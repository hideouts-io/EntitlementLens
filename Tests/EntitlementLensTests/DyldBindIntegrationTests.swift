import Foundation
import Testing
@testable import EntitlementLens

struct DyldBindIntegrationTests {
    @Test
    func nativeUniversalBindingsMatchAppleImportToolAndKeepWeakDefinitionsSeparate() throws {
        let root = try dyldFixtureRoot()
        defer { removeDyldFixture(root) }
        let url = try makeDyldFixture(root)
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        let bytes = try Data(contentsOf: url)
        for slice in inspection.architectures.records.map(\.slice) {
            let layout = try dyldFixtureLayout(bytes, slice: slice)
            #expect(layout.streams.allSatisfy { $0.dataSize > 0 })
            let collection = try collectDyldFixture(url, layout: layout)
            #expect(collection.state == .complete)
            let imports = collection.records.filter { $0.kind == .importedSymbol }
            let weak = collection.records.filter { $0.kind == .dyldBindingSymbol }
            #expect(weak.contains { $0.name == "_fixture_weak" })
            #expect(!imports.contains { $0.name == "_fixture_weak" })
            let native = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
                arguments: ["dyld_info", "-arch", slice.architecture, "-imports", url.path])
            #expect(Set(imports.map(\.name)) == Set(try nativeDyldImports(native.standardOutput)))
            if slice.architecture == "arm64" {
                #expect(imports.contains { $0.name == "_CFAbsoluteTimeGetCurrent" })
            } else {
                #expect(!imports.contains { $0.name == "_CFAbsoluteTimeGetCurrent" })
            }
            #expect(imports.contains { $0.name == "_CFRelease" })
            #expect(imports.contains { $0.name == "_CFStringCreateWithCString" })
            for reference in collection.records {
                #expect(reference.location.method == .dyldBindStream)
                #expect(reference.location.architecture == slice.architecture)
                #expect(reference.location.sliceOffset == slice.fileOffset)
                let fileOffset = try #require(reference.location.fileOffset)
                let byteCount = try #require(reference.location.byteCount)
                let offset = try #require(Int(exactly: fileOffset))
                let count = try #require(Int(exactly: byteCount))
                try #require(offset >= 0 && count > 1 && offset <= bytes.count && count <= bytes.count - offset)
                #expect(bytes[offset + count - 1] == 0)
                #expect(String(data: bytes[offset..<(offset + count - 1)], encoding: .utf8) == reference.name)
                let slot = try #require(reference.referenceLocation)
                #expect(slot.method == .dyldBindStream)
                #expect(slot.architecture == slice.architecture)
                #expect(slot.sliceOffset == slice.fileOffset)
                #expect(slot.byteCount == 8)
                let slotOffset = try #require(slot.fileOffset)
                #expect(slotOffset >= slice.fileOffset)
                #expect(slotOffset - slice.fileOffset <= slice.fileSize - 8)
            }
            #expect(inspection.apiReferences.records.filter {
                $0.location.sliceOffset == slice.fileOffset && $0.location.method == .dyldBindStream
            } == collection.records)
            let encoded = try JSONEncoder().encode(collection)
            #expect(try JSONDecoder().decode(StaticFeatureCollection<StaticAPIReference>.self, from: encoded) == collection)
        }
    }

    @Test
    func malformedAndThreadedStreamsRetainEarlierBindingsAndOtherArchitectures() throws {
        let root = try dyldFixtureRoot()
        defer { removeDyldFixture(root) }
        let originalURL = try makeDyldFixture(root)
        let original = try Data(contentsOf: originalURL)
        let slices = try MachOInspector.inspect(originalURL)
        let slice = try #require(slices.first { $0.architecture == "arm64" })
        let other = try #require(slices.first { $0.architecture == "x86_64" })
        let layout = try dyldFixtureLayout(original, slice: slice)
        let normal = try #require(layout.streams.first { $0.kind == .normal })
        let prefix = dyldOrdinaryProgram("_kept_bind", ordinal: 1, segment: 1).dropLast()
        let cases: [(name: String, program: Data, message: String)] = [
            ("unknown", Data(prefix) + Data([0xF0]), "unrecognized"),
            ("threaded", Data(prefix) + Data([0xD0, 0]), "threaded"),
            ("truncated-uleb", Data([0x20, 0x80]), "truncated"),
            ("overlong-uleb", Data([0x20]) + Data(repeating: 0x80, count: 10), "10-byte"),
            ("overflowing-uleb", Data([0x20]) + Data(repeating: 0x80, count: 9) + Data([2]), "64 bits"),
            ("overflowing-sleb", Data([0x60]) + Data(repeating: 0x80, count: 9) + Data([1]), "signed 64-bit"),
            ("bad-segment", Data([0x7F, 0]), "Segment index"),
            ("bad-type", Data([0x59]), "Binding type"),
            ("bad-ordinal", Data([0x1F]), "Dylib ordinal"),
            ("bad-special-ordinal", Data([0x3C]), "Dylib ordinal"),
            ("unterminated-symbol", Data([0x40]) + Data("_unterminated".utf8), "NUL terminator")
        ]
        for fixture in cases {
            let url = root.appendingPathComponent("\(fixture.name).universal")
            try dyldFixtureReplacingStream(original, layout: layout, kind: .normal, program: fixture.program).write(to: url)
            let altered = try Data(contentsOf: url)
            let newLayout = try dyldFixtureLayout(altered, slice: slice)
            let collection = try collectDyldFixture(url, layout: newLayout)
            #expect(collection.state == .partial)
            #expect(collection.reason?.contains(fixture.message) == true)
            #expect(collection.records.contains { $0.kind == .dyldBindingSymbol && $0.name == "_fixture_weak" })
            #expect(collection.records.contains { $0.name == "_CFRelease" })
            if fixture.name == "unknown" || fixture.name == "threaded" {
                #expect(collection.records.contains { $0.name == "_kept_bind" })
            }
            let inspection = try MachOInspector.inspectStaticFeatures(url)
            #expect(inspection.architectures.state == .complete)
            #expect(inspection.apiReferences.records.contains {
                $0.location.sliceOffset == other.fileOffset && $0.location.method == .dyldBindStream && $0.name == "_CFRelease"
            })
            #expect(inspection.apiReferences.records.contains {
                $0.location.sliceOffset == slice.fileOffset && $0.location.method == .symbolTable
            })
        }
        #expect(normal.dataSize > 0)
    }

    @Test
    func weakDefinitionMarkersSpecialLookupsAndLazySequenceResetsDoNotInventImports() throws {
        let root = try dyldFixtureRoot()
        defer { removeDyldFixture(root) }
        _ = try makeDyldFixture(root)
        let thinURL = root.appendingPathComponent("fixture.arm64.dylib")
        let original = try Data(contentsOf: thinURL)
        let slice = try #require(MachOInspector.inspect(thinURL).first)
        let layout = try dyldFixtureLayout(original, slice: slice)

        let markerURL = root.appendingPathComponent("definition-marker.dylib")
        let marker = Data([0x48]) + Data("_definition_marker".utf8) + Data([0, 0])
        try dyldFixtureReplacingStream(original, layout: layout, kind: .weak, program: marker).write(to: markerURL)
        let markerLayout = try dyldFixtureLayout(Data(contentsOf: markerURL), slice: slice)
        let marked = try collectDyldFixture(markerURL, layout: markerLayout)
        #expect(marked.state == .complete)
        #expect(!marked.records.contains { $0.name == "_definition_marker" })
        #expect(marked.records.contains { $0.kind == .importedSymbol && $0.name == "_CFRelease" })

        let selfURL = root.appendingPathComponent("self-lookup.dylib")
        try dyldFixtureReplacingStream(original, layout: layout, kind: .normal,
            program: dyldOrdinaryProgram("_self_reference", ordinal: 0, segment: 1)).write(to: selfURL)
        let selfLayout = try dyldFixtureLayout(Data(contentsOf: selfURL), slice: slice)
        let selfLookup = try collectDyldFixture(selfURL, layout: selfLayout)
        let selfReference = try #require(selfLookup.records.first { $0.name == "_self_reference" })
        #expect(selfReference.kind == .dyldBindingSymbol)

        let doneURL = root.appendingPathComponent("normal-done.dylib")
        let afterDone = dyldOrdinaryProgram("_before_done", ordinal: 1, segment: 1)
            + Data([0x40]) + Data("_after_done".utf8) + Data([0, 0x90])
        try dyldFixtureReplacingStream(original, layout: layout, kind: .normal, program: afterDone).write(to: doneURL)
        let doneLayout = try dyldFixtureLayout(Data(contentsOf: doneURL), slice: slice)
        let stopped = try collectDyldFixture(doneURL, layout: doneLayout)
        #expect(stopped.state == .complete)
        #expect(stopped.records.contains { $0.name == "_before_done" })
        #expect(!stopped.records.contains { $0.name == "_after_done" })

        // Apple's bounded ordinary walker also accepts a complete program ending at the declared stream size.
        let noDoneURL = root.appendingPathComponent("normal-no-done.dylib")
        let noDoneProgram = Data(dyldOrdinaryProgram("_at_stream_end", ordinal: 1, segment: 1).dropLast())
        try dyldFixtureReplacingStream(original, layout: layout, kind: .normal, program: noDoneProgram).write(to: noDoneURL)
        let noDoneLayout = try dyldFixtureLayout(Data(contentsOf: noDoneURL), slice: slice)
        let noDone = try collectDyldFixture(noDoneURL, layout: noDoneLayout)
        #expect(noDone.state == .complete)
        #expect(noDone.records.contains { $0.name == "_at_stream_end" })

        let lazyURL = root.appendingPathComponent("lazy-reset.dylib")
        let first = Data([0x71, 0, 0x11, 0x40]) + Data("_first_lazy".utf8) + Data([0, 0x90, 0])
        let secondWithoutSetup = Data([0x40]) + Data("_uninitialized_lazy".utf8) + Data([0, 0x90, 0])
        try dyldFixtureReplacingStream(original, layout: layout, kind: .lazy, program: first + secondWithoutSetup).write(to: lazyURL)
        let lazyLayout = try dyldFixtureLayout(Data(contentsOf: lazyURL), slice: slice)
        let lazy = try collectDyldFixture(lazyURL, layout: lazyLayout)
        #expect(lazy.state == .partial)
        #expect(lazy.records.contains { $0.name == "_first_lazy" })
        #expect(!lazy.records.contains { $0.name == "_uninitialized_lazy" })
        #expect(lazy.reason?.contains("requires a declared type, library ordinal, segment selection, and symbol name") == true)
    }

    @Test
    func bindsValidateVMArithmeticSignedAddendsAndBoundedRepetition() throws {
        let root = try dyldFixtureRoot()
        defer { removeDyldFixture(root) }
        _ = try makeDyldFixture(root)
        let thinURL = root.appendingPathComponent("fixture.arm64.dylib")
        let original = try Data(contentsOf: thinURL)
        let slice = try #require(MachOInspector.inspect(thinURL).first)
        let layout = try dyldFixtureLayout(original, slice: slice)
        let setup = Data([0x11, 0x40]) + Data("_checked_bind".utf8) + Data([0, 0x51, 0x71, 0])
        let wrappedOutside = setup + Data([0x80]) + dyldFixtureULEB(UInt64.max) + Data([0x90, 0])
        let badWidth = Data(setup.dropLast()) + dyldFixtureULEB(layout.segments[1].virtualSize - 4) + Data([0x90, 0])
        let repeatLimit = setup + Data([0xC0]) + dyldFixtureULEB(65_537) + Data([0, 0])
        let cases: [(name: String, program: Data, reason: String)] = [
            ("wrapped-target-outside-segment", wrappedOutside, "exceeds"),
            ("vm-width", Data(badWidth), "exceeds"),
            ("repeat-limit", repeatLimit, "remaining binding operations")
        ]
        for fixture in cases {
            let url = root.appendingPathComponent("\(fixture.name).dylib")
            try dyldFixtureReplacingStream(original, layout: layout, kind: .normal, program: fixture.program).write(to: url)
            let alteredLayout = try dyldFixtureLayout(Data(contentsOf: url), slice: slice)
            let collection = try collectDyldFixture(url, layout: alteredLayout)
            #expect(collection.state == .partial)
            #expect(collection.reason?.contains(fixture.reason) == true)
            #expect(!collection.records.contains { $0.name == "_checked_bind" })
            #expect(collection.records.contains { $0.name == "_CFRelease" })
        }
        let signedURL = root.appendingPathComponent("signed-addends.dylib")
        let maximumSigned = Data(repeating: 0xFF, count: 9) + Data([0])
        let minimumSigned = Data(repeating: 0x80, count: 9) + Data([0x7F])
        let signedProgram = setup + Data([0x60]) + maximumSigned + Data([0x60]) + minimumSigned + Data([0x90, 0])
        try dyldFixtureReplacingStream(original, layout: layout, kind: .normal, program: signedProgram).write(to: signedURL)
        let signedLayout = try dyldFixtureLayout(Data(contentsOf: signedURL), slice: slice)
        let signed = try collectDyldFixture(signedURL, layout: signedLayout)
        #expect(signed.state == .complete)
        #expect(signed.records.contains { $0.name == "_checked_bind" })
        #expect(signed.records.first { $0.name == "_checked_bind" }?.referenceLocation == nil)
        #expect(signed.limits.contains { $0.name == "dyld_bind_integer_bytes" && $0.value == 10 })
    }

    @Test
    func fileBackedSlotsRemainOptionalForVMOnlyBindingsAndInvalidDescriptorsAreExplicit() throws {
        let root = try dyldFixtureRoot()
        defer { removeDyldFixture(root) }
        _ = try makeDyldFixture(root)
        let thinURL = root.appendingPathComponent("fixture.arm64.dylib")
        let original = try Data(contentsOf: thinURL)
        let slice = try #require(MachOInspector.inspect(thinURL).first)
        let layout = try dyldFixtureLayout(original, slice: slice)
        let vmURL = root.appendingPathComponent("vm-only-target.dylib")
        try dyldFixtureReplacingStream(original, layout: layout, kind: .normal,
            program: dyldOrdinaryProgram("_vm_only_bind", ordinal: 1, segment: 1)).write(to: vmURL)
        let changed = try dyldFixtureLayout(Data(contentsOf: vmURL), slice: slice)
        let vmSegments = changed.segments.enumerated().map { index, segment in
            index == 1 ? MachODyldSegment(virtualSize: segment.virtualSize, fileOffset: segment.fileOffset, fileSize: 0) : segment
        }
        let vmLayout = DyldFixtureLayout(slice: slice, commandOffset: changed.commandOffset,
            minimumDataOffset: changed.minimumDataOffset, streams: changed.streams,
            segments: vmSegments, dylibCount: changed.dylibCount)
        let vm = try collectDyldFixture(vmURL, layout: vmLayout)
        #expect(vm.state == .complete)
        let reference = try #require(vm.records.first { $0.name == "_vm_only_bind" })
        #expect(reference.referenceLocation == nil)
        #expect(reference.location.fileOffset != nil)
        #expect(vm.limitations.contains { $0.contains("VM-only") })

        let textURL = root.appendingPathComponent("text-target.dylib")
        let textSetup = Data([0x11, 0x40]) + Data("_text_bind".utf8) + Data([0, 0x52, 0x71, 0, 0x90, 0])
        try dyldFixtureReplacingStream(original, layout: layout, kind: .normal, program: textSetup).write(to: textURL)
        let textLayout = try dyldFixtureLayout(Data(contentsOf: textURL), slice: slice)
        let text = try collectDyldFixture(textURL, layout: textLayout)
        #expect(text.state == .complete)
        let textReference = try #require(text.records.first { $0.name == "_text_bind" })
        #expect(textReference.referenceLocation == nil)

        let badRanges: [(segment: MachODyldSegment, reason: String)] = [
            (MachODyldSegment(virtualSize: 64, fileOffset: 0, fileSize: 65), "exceeding"),
            (MachODyldSegment(virtualSize: 64, fileOffset: UInt64.max - 16, fileSize: 64), "outside")
        ]
        for invalid in badRanges {
            let invalidSegments = changed.segments.enumerated().map { index, segment in index == 1 ? invalid.segment : segment }
            let invalidLayout = DyldFixtureLayout(slice: slice, commandOffset: changed.commandOffset,
                minimumDataOffset: changed.minimumDataOffset, streams: changed.streams,
                segments: invalidSegments, dylibCount: changed.dylibCount)
            let unavailable = try collectDyldFixture(vmURL, layout: invalidLayout)
            #expect(unavailable.state == .unavailable)
            #expect(unavailable.records.isEmpty)
            #expect(unavailable.reason?.contains(invalid.reason) == true)
        }
    }

    @Test
    func oversizedStreamRangesArePartialWhileOtherBindingStreamsRemainAvailable() throws {
        let root = try dyldFixtureRoot()
        defer { removeDyldFixture(root) }
        _ = try makeDyldFixture(root)
        let thinURL = root.appendingPathComponent("fixture.arm64.dylib")
        let original = try Data(contentsOf: thinURL)
        let slice = try #require(MachOInspector.inspect(thinURL).first)
        let layout = try dyldFixtureLayout(original, slice: slice)
        let newOffset = try #require(UInt32(exactly: original.count + 16))
        let newSize: UInt32 = 4 * 1_024 * 1_024 + 1
        let withOffset = try dyldFixtureReplacingUInt32(original, offset: layout.commandOffset + 16, value: newOffset)
        let modified = try dyldFixtureReplacingUInt32(withOffset, offset: layout.commandOffset + 20, value: newSize)
        let url = root.appendingPathComponent("oversized-stream.dylib")
        try modified.write(to: url)
        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: UInt64(newOffset) + UInt64(newSize))
        try handle.close()
        let newSlice = try #require(MachOInspector.inspect(url).first)
        let newLayout = try dyldFixtureLayout(modified, slice: newSlice)
        let collection = try collectDyldFixture(url, layout: newLayout)
        #expect(collection.state == .partial)
        #expect(collection.reason?.contains("4194305 stream bytes") == true)
        #expect(collection.records.contains { $0.name == "_CFRelease" })
        #expect(collection.records.contains { $0.name == "_fixture_weak" && $0.kind == .dyldBindingSymbol })

        let invalidSlice = MachOSlice(architecture: slice.architecture, fileOffset: UInt64.max - 16,
            fileSize: 64, uuid: nil, platform: nil, minimumOSVersion: nil, sdkVersion: nil,
            codeSignatureOffset: nil, codeSignatureSize: nil)
        let invalidLayout = DyldFixtureLayout(slice: invalidSlice, commandOffset: layout.commandOffset,
            minimumDataOffset: layout.minimumDataOffset, streams: layout.streams,
            segments: layout.segments, dylibCount: layout.dylibCount)
        let invalid = try collectDyldFixture(thinURL, layout: invalidLayout)
        #expect(invalid.state == .unavailable)
        #expect(invalid.records.isEmpty)
        #expect(invalid.reason?.contains("FAT architecture slice") == true)
    }
}

private struct DyldFixtureLayout {
    let slice: MachOSlice
    let commandOffset: Int
    let minimumDataOffset: UInt64
    let streams: [MachODyldBindStream]
    let segments: [MachODyldSegment]
    let dylibCount: UInt32
}

private enum DyldFixtureError: LocalizedError {
    case invalidRange(Int, Int, Int)
    case missingDyldInfo
    case missingStream(MachODyldBindKind)
    case excessiveProgram(Int, UInt32)
    case invalidNativeOutput

    var errorDescription: String? {
        switch self {
        case let .invalidRange(offset, count, available): "Dyld fixture field at \(offset) requires \(count) bytes in a \(available)-byte file."
        case .missingDyldInfo: "The dyld fixture has no LC_DYLD_INFO binding command."
        case let .missingStream(kind): "The dyld fixture has no \(kind.rawValue) binding stream."
        case let .excessiveProgram(count, available): "The replacement dyld program requires \(count) bytes; its fixture region has \(available)."
        case .invalidNativeOutput: "Apple dyld_info returned invalid UTF-8 or an empty import-name record for the controlled fixture."
        }
    }
}

private func dyldFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-dyld-bind-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeDyldFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Dyld binding fixture cleanup failed: \(error.localizedDescription)") }
}

private func makeDyldFixture(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("fixture.c")
    let text = """
    #include <CoreFoundation/CoreFoundation.h>
    #if defined(__arm64__)
    CFAbsoluteTime (*fixture_callback)(void) = CFAbsoluteTimeGetCurrent;
    #else
    CFStringRef (*fixture_callback)(CFAllocatorRef, const char*, CFStringEncoding) = CFStringCreateWithCString;
    #endif
    __attribute__((weak)) int fixture_weak(void) { return 1; }
    int (*weak_callback)(void) = fixture_weak;
    int fixture_invoke(void) {
    #if defined(__arm64__)
        CFStringRef value = CFStringCreateWithCString(NULL, "static evidence", kCFStringEncodingUTF8);
        CFAbsoluteTime now = fixture_callback();
    #else
        CFStringRef value = fixture_callback(NULL, "static evidence", kCFStringEncodingUTF8);
        CFAbsoluteTime now = 0;
    #endif
        CFRelease(value);
        return now < 0 || weak_callback() < 0;
    }
    """
    try Data(text.utf8).write(to: source)
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    let arm64 = root.appendingPathComponent("fixture.arm64.dylib")
    let x86 = root.appendingPathComponent("fixture.x86_64.dylib")
    let universal = root.appendingPathComponent("fixture.universal.dylib")
    for architecture in ["arm64", "x86_64"] {
        let output = architecture == "arm64" ? arm64 : x86
        _ = try runFixtureTool(executable: xcrun, arguments: [
            "clang", "-target", "\(architecture)-apple-macos14.0", "-dynamiclib", source.path,
            "-framework", "CoreFoundation", "-Wl,-no_fixup_chains", "-o", output.path
        ])
    }
    _ = try runFixtureTool(executable: xcrun, arguments: ["lipo", "-create", arm64.path, x86.path, "-output", universal.path])
    return universal
}

private func nativeDyldImports(_ bytes: Data) throws -> [String] {
    guard let text = String(data: bytes, encoding: .utf8) else { throw DyldFixtureError.invalidNativeOutput }
    var names: [String] = []
    for line in text.split(separator: "\n") {
        if let separator = line.range(of: "  (from ") {
            let name = line[..<separator.lowerBound].trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { throw DyldFixtureError.invalidNativeOutput }
            names.append(name)
        }
    }
    return names
}

private func dyldFixtureLayout(_ bytes: Data, slice: MachOSlice) throws -> DyldFixtureLayout {
    let start = try #require(Int(exactly: slice.fileOffset))
    let count = try dyldFixtureUInt32(bytes, offset: start + 16)
    let commandBytes = try dyldFixtureUInt32(bytes, offset: start + 20)
    var offset = start + 32
    var dyldInfoOffset: Int?
    var streams: [MachODyldBindStream] = []
    var segments: [MachODyldSegment] = []
    var dylibCount: UInt32 = 0
    for _ in 0..<count {
        let command = try dyldFixtureUInt32(bytes, offset: offset)
        let size = try dyldFixtureUInt32(bytes, offset: offset + 4)
        if command == 0x19, segments.count < 16 {
            segments.append(MachODyldSegment(virtualSize: try dyldFixtureUInt64(bytes, offset: offset + 32),
                fileOffset: try dyldFixtureUInt64(bytes, offset: offset + 40),
                fileSize: try dyldFixtureUInt64(bytes, offset: offset + 48)))
        }
        if [0x0C, 0x8000_0018, 0x8000_001F, 0x20, 0x8000_0023].contains(command) { dylibCount += 1 }
        if command == 0x22 || command == 0x8000_0022 {
            dyldInfoOffset = offset
            let fields: [(kind: MachODyldBindKind, offset: Int)] = [(.normal, 16), (.weak, 24), (.lazy, 32)]
            streams = try fields.map { field in
                MachODyldBindStream(kind: field.kind,
                    dataOffset: try dyldFixtureUInt32(bytes, offset: offset + field.offset),
                    dataSize: try dyldFixtureUInt32(bytes, offset: offset + field.offset + 4))
            }
        }
        offset += Int(size)
    }
    guard let dyldInfoOffset else { throw DyldFixtureError.missingDyldInfo }
    return DyldFixtureLayout(slice: slice, commandOffset: dyldInfoOffset,
        minimumDataOffset: 32 + UInt64(commandBytes), streams: streams, segments: segments, dylibCount: dylibCount)
}

private func collectDyldFixture(_ url: URL, layout: DyldFixtureLayout) throws -> StaticFeatureCollection<StaticAPIReference> {
    let handle = try FileHandle(forReadingFrom: url)
    defer {
        do { try handle.close() }
        catch { Issue.record("Dyld binding fixture read-handle cleanup failed: \(error.localizedDescription)") }
    }
    let size = try handle.seekToEnd()
    return try MachODyldBindCollector.collect(handle: handle, url: url, slice: layout.slice, containerSize: size,
        minimumDataOffset: layout.minimumDataOffset, streams: layout.streams, segments: layout.segments,
        pointerSize: 8, dylibCount: layout.dylibCount)
}

private func dyldFixtureReplacingStream(
    _ bytes: Data, layout: DyldFixtureLayout, kind: MachODyldBindKind, program: Data
) throws -> Data {
    guard let stream = layout.streams.first(where: { $0.kind == kind }) else { throw DyldFixtureError.missingStream(kind) }
    guard UInt64(program.count) <= UInt64(stream.dataSize) else { throw DyldFixtureError.excessiveProgram(program.count, stream.dataSize) }
    let absolute = try #require(Int(exactly: layout.slice.fileOffset + UInt64(stream.dataOffset)))
    try dyldFixtureRange(bytes, offset: absolute, count: Int(stream.dataSize))
    var result = bytes
    result.replaceSubrange(absolute..<(absolute + Int(stream.dataSize)), with: program + Data(repeating: 0, count: Int(stream.dataSize) - program.count))
    let field: Int
    switch kind {
    case .normal: field = 20
    case .weak: field = 28
    case .lazy: field = 36
    }
    let size = try #require(UInt32(exactly: program.count))
    return try dyldFixtureReplacingUInt32(result, offset: layout.commandOffset + field, value: size)
}

private func dyldOrdinaryProgram(_ name: String, ordinal: UInt8, segment: UInt8) -> Data {
    Data([0x10 | ordinal, 0x40]) + Data(name.utf8) + Data([0, 0x51, 0x70 | segment, 0, 0x90, 0])
}

private func dyldFixtureULEB(_ value: UInt64) -> Data {
    var remaining = value
    var bytes: [UInt8] = []
    repeat {
        let byte = UInt8(remaining & 0x7F)
        remaining >>= 7
        bytes.append(remaining == 0 ? byte : byte | 0x80)
    } while remaining != 0
    return Data(bytes)
}

private func dyldFixtureRange(_ bytes: Data, offset: Int, count: Int) throws {
    guard offset >= 0, count >= 0, offset <= bytes.count, count <= bytes.count - offset else {
        throw DyldFixtureError.invalidRange(offset, count, bytes.count)
    }
}

private func dyldFixtureUInt32(_ bytes: Data, offset: Int) throws -> UInt32 {
    try dyldFixtureRange(bytes, offset: offset, count: 4)
    return bytes[offset..<(offset + 4)].enumerated().reduce(0) { value, byte in
        value | UInt32(byte.element) << UInt32(byte.offset * 8)
    }
}

private func dyldFixtureUInt64(_ bytes: Data, offset: Int) throws -> UInt64 {
    try dyldFixtureRange(bytes, offset: offset, count: 8)
    return bytes[offset..<(offset + 8)].enumerated().reduce(0) { value, byte in
        value | UInt64(byte.element) << UInt64(byte.offset * 8)
    }
}

private func dyldFixtureReplacingUInt32(_ bytes: Data, offset: Int, value: UInt32) throws -> Data {
    try dyldFixtureRange(bytes, offset: offset, count: 4)
    var result = bytes
    for index in 0..<4 { result[offset + index] = UInt8(truncatingIfNeeded: value >> UInt32(index * 8)) }
    return result
}
