import Foundation
import Testing
@testable import EntitlementLens

struct ObjectiveCReferenceIntegrationTests {
    @Test
    func universalExecutableReferencesMatchNativeSectionsAndExactSourceBytes() throws {
        let root = try objectiveCFixtureRoot()
        defer { removeObjectiveCFixture(root) }
        let source = try objectiveCFixtureSource(root)
        let url = try compileObjectiveCFixture(root: root, sourceFiles: [source], linkerArguments: ["-Wl,-no_fixup_chains"])
        let bytes = try Data(contentsOf: url)
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        #expect(inspection.architectures.records.count == 2)
        for slice in inspection.architectures.records.map(\.slice) {
            let layout = try objectiveCFixtureLayout(bytes, slice: slice)
            let selectorSection = try #require(layout.sections.first { $0.sectionName == "__objc_selrefs" })
            let classSection = try #require(layout.sections.first { $0.sectionName == "__objc_classrefs" })
            #expect(selectorSection.virtualAddress >= 0x1_0000_0000)
            let native = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: [
                "dyld_info", "-arch", slice.architecture, "-opcodes", "-fixups",
                "-section", selectorSection.segmentName, selectorSection.sectionName,
                "-section", classSection.segmentName, classSection.sectionName, url.path
            ])
            let nativeText = try #require(String(data: native.standardOutput, encoding: .utf8))
            #expect(nativeText.contains("BIND_OPCODE_ADD_ADDR_ULEB(0xFFFFFFFFFFFFFFE8)"))
            let bindingCommand = try #require(layout.bindingCommandOffset)
            let bindingOffset = try objectiveCFixtureUInt32(bytes, offset: bindingCommand + 16)
            let bindingSize = try objectiveCFixtureUInt32(bytes, offset: bindingCommand + 20)
            let bindingStart = try #require(Int(exactly: slice.fileOffset + UInt64(bindingOffset)))
            try objectiveCFixtureRange(bytes, offset: bindingStart, count: Int(bindingSize))
            let bindingBytes = Data(bytes[bindingStart..<(bindingStart + Int(bindingSize))])
            #expect(bindingBytes.range(of: Data([0x80]) + objectiveCFixtureULEB(UInt64.max - 23)) != nil)
            let nativeSections = try nativeObjectiveCSectionRows(native.standardOutput)
            let nativeBindings = try nativeObjectiveCBindingRows(native.standardOutput)
            let selectors = try nativeSections.filter { $0.section == "__objc_selrefs" }.map { row in
                NativeObjectiveCReference(virtualAddress: row.virtualAddress, name: try nativeObjectiveCSelector(row.value))
            }
            let classes = try nativeSections.filter { $0.section == "__objc_classrefs" }.map { row in
                NativeObjectiveCReference(virtualAddress: row.virtualAddress, name: try nativeObjectiveCClass(row.value))
            }
            let records = inspection.apiReferences.records.filter { $0.location.sliceOffset == slice.fileOffset }
            let bindings = records.filter { $0.kind == .importedSymbol && $0.location.method == .dyldBindStream }
            #expect(Set(bindings.map(\.name)) == Set(nativeBindings.map(\.name)))
            for nativeBinding in nativeBindings {
                let binding = try #require(bindings.first { $0.name == nativeBinding.name })
                let segment = try #require(layout.segments.first { $0.name == nativeBinding.segmentName })
                try #require(nativeBinding.virtualAddress >= segment.virtualAddress)
                let relative = nativeBinding.virtualAddress - segment.virtualAddress
                try #require(relative <= segment.fileSize && 8 <= segment.fileSize - relative)
                #expect(binding.referenceLocation?.fileOffset == slice.fileOffset + segment.fileOffset + relative)
                #expect(binding.referenceLocation?.byteCount == 8)
            }
            let collectedSelectors = records.filter { $0.kind == .objectiveCSelector }
            let collectedClasses = records.filter { $0.kind == .objectiveCClass }
            #expect(Set(collectedSelectors.map(\.name)) == Set(selectors.map(\.name)))
            #expect(Set(collectedClasses.map(\.name)) == Set(classes.map(\.name)))
            let expectedSelector = slice.architecture == "arm64" ? "stringWithString:" : "arrayWithObject:"
            let expectedClass = slice.architecture == "arm64" ? "NSString" : "NSArray"
            #expect(Set(collectedSelectors.map(\.name)) == ["date", expectedSelector])
            #expect(Set(collectedClasses.map(\.name)) == ["NSDate", expectedClass])
            #expect(!collectedSelectors.contains { $0.name == "notAReferencedSelector:" })
            #expect(!collectedClasses.contains { $0.name == "NSProcessInfo" })
            let outside = try #require(records.first {
                $0.kind == .importedSymbol && $0.name == "_OBJC_CLASS_$_NSProcessInfo" && $0.location.method == .dyldBindStream
            })
            let outsideSlot = try #require(outside.referenceLocation?.fileOffset)
            let classStart = slice.fileOffset + classSection.fileOffset
            #expect(outsideSlot < classStart || outsideSlot >= classStart + classSection.byteCount)
            for item in selectors {
                let reference = try #require(collectedSelectors.first { $0.name == item.name })
                try verifyObjectiveCReferenceBytes(reference, bytes: bytes, url: url, slice: slice)
                let expectedOffset = try objectiveCNativeSlotOffset(item.virtualAddress, section: selectorSection, slice: slice)
                #expect(reference.referenceLocation?.fileOffset == expectedOffset)
            }
            for item in classes {
                let reference = try #require(collectedClasses.first { $0.name == item.name })
                try verifyObjectiveCReferenceBytes(reference, bytes: bytes, url: url, slice: slice)
                let expectedOffset = try objectiveCNativeSlotOffset(item.virtualAddress, section: classSection, slice: slice)
                #expect(reference.referenceLocation?.fileOffset == expectedOffset)
                let binding = try #require(records.first {
                    $0.kind == .importedSymbol && $0.name == "_OBJC_CLASS_$_" + item.name && $0.location.method == .dyldBindStream
                })
                #expect(reference.location.fileOffset == binding.location.fileOffset.map { $0 + UInt64("_OBJC_CLASS_$_".utf8.count) })
                // The linker's symbol order binds the later __data global before rewinding to these class slots.
                #expect(binding.referenceLocation?.fileOffset == expectedOffset)
                #expect(expectedOffset < outsideSlot)
            }
        }
        let encoded = try JSONEncoder().encode(inspection.apiReferences)
        #expect(try JSONDecoder().decode(StaticFeatureCollection<StaticAPIReference>.self, from: encoded) == inspection.apiReferences)
    }

    @Test
    func malformedReferenceSectionsAndNamesRetainOtherSlicesAndMethods() throws {
        let root = try objectiveCFixtureRoot()
        defer { removeObjectiveCFixture(root) }
        let source = try objectiveCFixtureSource(root)
        let originalURL = try compileObjectiveCFixture(root: root, sourceFiles: [source], linkerArguments: ["-Wl,-no_fixup_chains"])
        let original = try Data(contentsOf: originalURL)
        let inspection = try MachOInspector.inspectStaticFeatures(originalURL)
        let slice = try #require(inspection.architectures.records.first { $0.slice.architecture == "arm64" }?.slice)
        let other = try #require(inspection.architectures.records.first { $0.slice.architecture == "x86_64" }?.slice)
        let layout = try objectiveCFixtureLayout(original, slice: slice)
        let selectors = try #require(layout.sections.first { $0.sectionName == "__objc_selrefs" })
        let classes = try #require(layout.sections.first { $0.sectionName == "__objc_classrefs" })
        let methodNames = try #require(layout.sections.first { $0.sectionName == "__objc_methname" })
        let imageInfo = try #require(layout.sections.first { $0.sectionName == "__objc_imageinfo" })
        let date = try #require(inspection.apiReferences.records.first {
            $0.kind == .objectiveCSelector && $0.name == "date" && $0.location.sliceOffset == slice.fileOffset
        })
        let dateOffset = try #require(date.location.fileOffset)
        let dateIndex = try #require(Int(exactly: dateOffset))
        let slotOffset = try #require(Int(exactly: slice.fileOffset + selectors.fileOffset))
        let nameEnd = try #require(Int(exactly: slice.fileOffset + methodNames.fileOffset + methodNames.byteCount - 1))
        let imageFlagsOffset = try #require(Int(exactly: slice.fileOffset + imageInfo.fileOffset + 4))
        let imageFlags = try objectiveCFixtureUInt32(original, offset: imageFlagsOffset)
        let headerFlagsOffset = try #require(Int(exactly: slice.fileOffset + 24))
        let classSegment = try #require(layout.segments.first { $0.headerOffset == classes.segmentHeaderOffset })
        let unrelated = try #require(layout.segments.first { $0.name == "__LINKEDIT" })
        let aliasOffset = try objectiveCFixtureReplacingUInt64(original, offset: unrelated.headerOffset + 40, value: classSegment.fileOffset)
        let aliasRange = try objectiveCFixtureReplacingUInt64(aliasOffset, offset: unrelated.headerOffset + 48, value: classSegment.fileSize)
        let cases: [(name: String, bytes: Data)] = [
            ("section-outside-slice", try objectiveCFixtureReplacingUInt32(original, offset: selectors.headerOffset + 48, value: UInt32.max)),
            ("section-overlap", try objectiveCFixtureReplacingUInt64(original, offset: selectors.headerOffset + 40, value: selectors.byteCount + 8)),
            ("pointer-outside-image", try objectiveCFixtureReplacingUInt64(original, offset: slotOffset, value: UInt64.max)),
            ("pointer-to-wrong-section", try objectiveCFixtureReplacingUInt64(original, offset: slotOffset, value: classes.virtualAddress)),
            ("invalid-name-utf8", try objectiveCFixtureReplacingByte(original, offset: dateIndex, value: 0xFF)),
            ("unterminated-name", try objectiveCFixtureReplacingByte(original, offset: nameEnd, value: 0x41)),
            ("imageinfo-optimized", try objectiveCFixtureReplacingUInt32(original, offset: imageFlagsOffset, value: imageFlags | 0x80)),
            ("cache-image", try objectiveCFixtureReplacingUInt32(original, offset: headerFlagsOffset, value: layout.flags | 0x8000_0000)),
            ("authenticated-data", try objectiveCFixtureAuthenticatingDataSegment(original, section: selectors)),
            ("unrelated-segment-file-alias", aliasRange)
        ]
        for fixture in cases {
            let url = root.appendingPathComponent(fixture.name)
            try fixture.bytes.write(to: url)
            let altered = try MachOInspector.inspectStaticFeatures(url)
            #expect(altered.architectures.state == .complete)
            #expect(altered.apiReferences.state == .partial)
            #expect(altered.apiReferences.reason != nil)
            #expect(altered.apiReferences.records.contains {
                $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.sliceOffset == other.fileOffset
            })
            #expect(altered.apiReferences.records.contains {
                $0.kind == .objectiveCClass && $0.name == "NSDate" && $0.location.sliceOffset == other.fileOffset
            })
            #expect(altered.apiReferences.records.contains {
                $0.kind == .importedSymbol && $0.location.method == .symbolTable && $0.location.sliceOffset == slice.fileOffset
            })
            if fixture.name == "invalid-name-utf8" {
                #expect(!altered.apiReferences.records.contains {
                    $0.kind == .objectiveCSelector && $0.name == "date" && $0.location.sliceOffset == slice.fileOffset
                })
                #expect(altered.apiReferences.records.contains {
                    $0.kind == .objectiveCSelector && $0.name == "stringWithString:" && $0.location.sliceOffset == slice.fileOffset
                })
            }
            if ["imageinfo-optimized", "cache-image", "authenticated-data"].contains(fixture.name) {
                #expect(!altered.apiReferences.records.contains {
                    ($0.kind == .objectiveCClass || $0.kind == .objectiveCSelector) && $0.location.sliceOffset == slice.fileOffset
                })
                #expect(altered.apiReferences.reason?.localizedCaseInsensitiveContains("unsupported") == true)
            }
            if fixture.name == "unrelated-segment-file-alias" {
                #expect(!altered.apiReferences.records.contains {
                    ($0.kind == .objectiveCClass || $0.kind == .objectiveCSelector) && $0.location.sliceOffset == slice.fileOffset
                })
            }
        }
    }

    @Test
    func overlappingAndNonzeroAddendBindingsPreventRawSelectorPointerInterpretation() throws {
        let root = try objectiveCFixtureRoot()
        defer { removeObjectiveCFixture(root) }
        let source = try objectiveCFixtureSource(root)
        let originalURL = try compileObjectiveCFixture(root: root, sourceFiles: [source], linkerArguments: ["-Wl,-no_fixup_chains"])
        let original = try Data(contentsOf: originalURL)
        let slices = try MachOInspector.inspect(originalURL)
        let slice = try #require(slices.first { $0.architecture == "arm64" })
        let other = try #require(slices.first { $0.architecture == "x86_64" })
        let layout = try objectiveCFixtureLayout(original, slice: slice)
        let selectors = try #require(layout.sections.first { $0.sectionName == "__objc_selrefs" })
        let segmentOffset = selectors.virtualAddress - selectors.segmentVirtualAddress
        let slotOffset = try #require(Int(exactly: slice.fileOffset + selectors.fileOffset))
        let cases: [(name: String, addend: UInt8, offset: UInt64)] = [
            ("nonzero-addend", 1, segmentOffset), ("unaligned-overlap", 0, segmentOffset + 1)
        ]
        for fixture in cases {
            let program = Data([0x11, 0x40]) + Data("_objc_msgSend".utf8)
                + Data([0, 0x51, 0x60, fixture.addend, 0x70 | selectors.segmentIndex])
                + objectiveCFixtureULEB(fixture.offset) + Data([0x90, 0])
            let alteredBytes = try objectiveCFixtureReplacingNormalBindings(original, slice: slice, layout: layout, program: program)
            #expect(Data(alteredBytes[slotOffset..<(slotOffset + 8)]) == Data(original[slotOffset..<(slotOffset + 8)]))
            let url = root.appendingPathComponent("selector-slot-with-\(fixture.name)-binding")
            try alteredBytes.write(to: url)
            let inspection = try MachOInspector.inspectStaticFeatures(url)
            let binding = try #require(inspection.apiReferences.records.first {
                $0.location.method == .dyldBindStream && $0.name == "_objc_msgSend" && $0.location.sliceOffset == slice.fileOffset
            })
            #expect(binding.kind == .importedSymbol)
            if fixture.addend != 0 { #expect(binding.referenceLocation == nil) }
            else { #expect(binding.referenceLocation?.fileOffset == UInt64(slotOffset) + 1) }
            #expect(!inspection.apiReferences.records.contains {
                $0.kind == .objectiveCSelector && $0.location.sliceOffset == slice.fileOffset
            })
            #expect(inspection.apiReferences.state == .partial)
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.sliceOffset == other.fileOffset
            })
        }
    }

    @Test
    func legacyNativeArm64EFormatRetainsAttributableMetadataAndLiteralImports() throws {
        let root = try objectiveCFixtureRoot()
        defer { removeObjectiveCFixture(root) }
        let source = try objectiveCFixtureSource(root)
        let url = root.appendingPathComponent("fixture.arm64e")
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: [
            "clang", "-target", "arm64e-apple-macos11.0", source.path, "-framework", "Foundation", "-Wl,-fixup_chains", "-o", url.path
        ])
        // The linker records the arm64e ABI version in the CPU subtype; native dyld_info selects it without an arch filter.
        let native = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["dyld_info", "-fixup_chains", "-fixups", url.path])
        let nativeText = try #require(String(data: native.standardOutput, encoding: .utf8))
        #expect(nativeText.contains("pointer_format:  1 (DYLD_CHAINED_PTR_ARM64E)"))
        #expect(nativeText.contains("auth-bind"))
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        #expect(inspection.loadCommands.records.contains { $0.commandID == 0x8000_0034 })
        let metadata = inspection.apiReferences.records.filter { $0.kind == .objectiveCSelector || $0.kind == .objectiveCClass }
        #expect(metadata.count == 4)
        #expect(Set(metadata.filter { $0.kind == .objectiveCSelector }.map(\.name)) == ["date", "stringWithString:"])
        #expect(Set(metadata.filter { $0.kind == .objectiveCClass }.map(\.name)) == ["NSDate", "NSString"])
        #expect(!metadata.contains { $0.name == "notAReferencedSelector:" || $0.name == "NSProcessInfo" })
        let bytes = try Data(contentsOf: url)
        for slice in inspection.architectures.records.map(\.slice) {
            for reference in metadata.filter({ $0.location.sliceOffset == slice.fileOffset }) {
                try verifyObjectiveCReferenceBytes(reference, bytes: bytes, url: url, slice: slice)
            }
            #expect(inspection.apiReferences.records.contains {
                $0.name == "_OBJC_CLASS_$_NSDate" && $0.kind == .importedSymbol && $0.location.sliceOffset == slice.fileOffset
                    && $0.location.method == .chainedFixupImports
            })
        }
    }

    @Test
    func nativeSelectorTablesRespectRecordCapsAndRetainImports() throws {
        let root = try objectiveCFixtureRoot()
        defer { removeObjectiveCFixture(root) }
        let source = try objectiveCFixtureSource(root)
        let assembly = root.appendingPathComponent("many-selectors.s")
        // The linker coalesces duplicate selector references, so every retained slot needs a unique literal.
        let literals = (0..<4_097).map { "Lbounded_selector\($0):\n.asciz \"boundedSelector\($0):\"\n" }.joined()
        let pointers = (0..<4_097).map { ".quad Lbounded_selector\($0)\n" }.joined()
        let text = ".section __TEXT,__objc_methname,cstring_literals\n" + literals
            + ".section __DATA,__objc_selrefs,literal_pointers,no_dead_strip\n.p2align 3\n" + pointers
        try Data(text.utf8).write(to: assembly)
        let url = try compileObjectiveCFixture(root: root, sourceFiles: [source, assembly], linkerArguments: ["-Wl,-no_fixup_chains"])
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        #expect(inspection.apiReferences.state == .partial)
        #expect(inspection.apiReferences.reason?.contains("4096") == true)
        #expect(inspection.apiReferences.limits.contains { $0.name == "objc_reference_records_per_slice" && $0.value == 4_096 })
        for slice in inspection.architectures.records.map(\.slice) {
            let records = inspection.apiReferences.records.filter {
                ($0.kind == .objectiveCSelector || $0.kind == .objectiveCClass) && $0.location.sliceOffset == slice.fileOffset
            }
            #expect(records.count == 4_096)
            #expect(records.contains { $0.name.hasPrefix("boundedSelector") })
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .importedSymbol && $0.name == "_OBJC_CLASS_$_NSDate" && $0.location.sliceOffset == slice.fileOffset
            })
            #expect(records.allSatisfy { $0.referenceLocation != nil })
        }
    }

    @Test @MainActor
    func cancellationPropagatesBeforeObjectiveCMetadataReads() async throws {
        let root = try objectiveCFixtureRoot()
        defer { removeObjectiveCFixture(root) }
        let source = try objectiveCFixtureSource(root)
        let url = try compileObjectiveCFixture(root: root, sourceFiles: [source], linkerArguments: ["-Wl,-no_fixup_chains"])
        let bytes = try Data(contentsOf: url)
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        let slice = try #require(inspection.architectures.records.first?.slice)
        let layout = try objectiveCFixtureLayout(bytes, slice: slice)
        let handle = try FileHandle(forReadingFrom: url)
        defer {
            do { try handle.close() }
            catch { Issue.record("Objective-C cancellation fixture read-handle cleanup failed: \(error.localizedDescription)") }
        }
        let task = Task {
            try MachOObjectiveCReferenceCollector.collect(handle: handle, url: url, slice: slice,
                containerSize: UInt64(bytes.count), minimumDataOffset: layout.minimumDataOffset,
                sections: layout.sections.map(\.descriptor), byteOrder: .little, fileType: layout.fileType,
                machHeaderFlags: layout.flags, pointerSource: .ordinaryBindings(inspection.apiReferences))
        }
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Objective-C metadata collection completed after cancellation.")
        } catch is CancellationError { }
    }

    @Test
    func pipelineExportsSchemaThreeWithNameAndSlotLocationsAndRetainsReviewSamples() async throws {
        let root = try objectiveCFixtureRoot()
        defer { removeObjectiveCFixture(root) }
        let source = try objectiveCFixtureSource(root)
        let universal = try compileObjectiveCFixture(root: root, sourceFiles: [source], linkerArguments: ["-Wl,-no_fixup_chains"])
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let samples = repository.appendingPathComponent(".build/static-feature-validation")
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        let sample = samples.appendingPathComponent("objc-reference")
        try Data(contentsOf: universal).write(to: sample, options: [.atomic])
        let finding = try await collectObjectiveCFeatureFinding(sample)
        let features = try #require(finding.staticFeatures)
        #expect(features.schemaVersion == .v3)
        #expect(features.analyzedPath == sample.path)
        #expect(features.artifactSHA256 == finding.provenance.sha256)
        let references = features.apiReferences.records.filter { $0.kind == .objectiveCClass || $0.kind == .objectiveCSelector }
        #expect(references.count == 8)
        #expect(references.allSatisfy { $0.referenceLocation != nil })
        let json = try ResultExporter.data(for: [finding], format: .json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == [finding])
        let csv = try ResultExporter.data(for: [finding], format: .csv)
        let rows = try csvFixtureRecords(String(decoding: csv, as: UTF8.self))
        let header = try #require(rows.first)
        let versionColumn = try #require(header.firstIndex(of: "static_features_schema_version"))
        let featureColumn = try #require(header.firstIndex(of: "static_features_json"))
        let row = try #require(rows.dropFirst().first)
        #expect(row.count == header.count)
        #expect(row[versionColumn] == "3")
        let decoded = try JSONDecoder().decode(StaticFeatureSet.self, from: Data(row[featureColumn].utf8))
        #expect(decoded == features)
        let jsonURL = samples.appendingPathComponent("objc-reference.json")
        let csvURL = samples.appendingPathComponent("objc-reference.csv")
        try await writeExport(to: jsonURL) { json }
        try await writeExport(to: csvURL) { csv }
        #expect(try Data(contentsOf: jsonURL) == json)
        #expect(try Data(contentsOf: csvURL) == csv)
    }
}

private struct ObjectiveCFixtureSection {
    let headerOffset: Int
    let segmentHeaderOffset: Int
    let segmentIndex: UInt8
    let segmentVirtualAddress: UInt64
    let segmentName: String
    let sectionName: String
    let virtualAddress: UInt64
    let fileOffset: UInt64
    let byteCount: UInt64
    let flags: UInt32
    let alignmentExponent: UInt32
    let relocationCount: UInt32

    var descriptor: MachOObjectiveCSection {
        MachOObjectiveCSection(segmentName: segmentName, sectionName: sectionName,
            virtualAddress: virtualAddress, fileOffset: fileOffset, byteCount: byteCount,
            flags: flags, alignmentExponent: alignmentExponent, relocationCount: relocationCount)
    }
}

private struct ObjectiveCFixtureLayout {
    let fileType: UInt32
    let flags: UInt32
    let minimumDataOffset: UInt64
    let sections: [ObjectiveCFixtureSection]
    let segments: [ObjectiveCFixtureSegment]
    let bindingCommandOffset: Int?
}

private struct ObjectiveCFixtureSegment {
    let headerOffset: Int
    let name: String
    let virtualAddress: UInt64
    let fileOffset: UInt64
    let fileSize: UInt64
}

private struct NativeObjectiveCSectionRow {
    let section: String
    let virtualAddress: UInt64
    let value: String
}

private struct NativeObjectiveCReference {
    let virtualAddress: UInt64
    let name: String
}

private struct NativeObjectiveCBinding {
    let segmentName: String
    let virtualAddress: UInt64
    let name: String
}

private enum ObjectiveCFixtureError: LocalizedError {
    case invalidRange(Int, Int)
    case invalidHeader
    case invalidNativeOutput(String)

    var errorDescription: String? {
        switch self {
        case let .invalidRange(offset, count): "The Objective-C fixture field at \(offset) requires \(count) unavailable bytes."
        case .invalidHeader: "The Objective-C fixture must be a native little-endian 64-bit Mach-O image."
        case let .invalidNativeOutput(reason): "Apple dyld_info returned an unexpected controlled Objective-C fixture section: \(reason)"
        }
    }
}

private func objectiveCFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-objc-reference-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeObjectiveCFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Objective-C fixture cleanup failed: \(error.localizedDescription)") }
}

private func objectiveCFixtureSource(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("fixture.m")
    let text = """
    #import <Foundation/Foundation.h>
    extern Class fixture_nsprocess __asm("_OBJC_CLASS_$_NSProcessInfo");
    Class *fixture_external_class_address = &fixture_nsprocess;
    const char *fixture_only_raw_string = "notAReferencedSelector:";
    id fixture_objc(id value) {
    #if defined(__arm64__)
        return [NSString stringWithString:value];
    #else
        return [NSArray arrayWithObject:value];
    #endif
    }
    id fixture_date(void) { return [NSDate date]; }
    int main(void) { return 0; }
    """
    try Data(text.utf8).write(to: source)
    return source
}

private func compileObjectiveCFixture(root: URL, sourceFiles: [URL], linkerArguments: [String]) throws -> URL {
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    let architectures = ["arm64", "x86_64"]
    let thinFiles = architectures.map { root.appendingPathComponent("fixture.\($0)") }
    for (architecture, output) in zip(architectures, thinFiles) {
        _ = try runFixtureTool(executable: xcrun,
            arguments: ["clang", "-target", "\(architecture)-apple-macos14.0"] + sourceFiles.map(\.path)
                + ["-framework", "Foundation"] + linkerArguments + ["-o", output.path])
    }
    let universal = root.appendingPathComponent("fixture.universal")
    _ = try runFixtureTool(executable: xcrun,
        arguments: ["lipo", "-create"] + thinFiles.map(\.path) + ["-output", universal.path])
    return universal
}

private func objectiveCFixtureLayout(_ bytes: Data, slice: MachOSlice) throws -> ObjectiveCFixtureLayout {
    let start = try #require(Int(exactly: slice.fileOffset))
    guard try objectiveCFixtureUInt32(bytes, offset: start) == 0xFEED_FACF else { throw ObjectiveCFixtureError.invalidHeader }
    let count = try objectiveCFixtureUInt32(bytes, offset: start + 16)
    let commandBytes = try objectiveCFixtureUInt32(bytes, offset: start + 20)
    var offset = start + 32
    var sections: [ObjectiveCFixtureSection] = []
    var segments: [ObjectiveCFixtureSegment] = []
    var segmentIndex: UInt8 = 0
    var bindingCommandOffset: Int?
    for _ in 0..<count {
        let command = try objectiveCFixtureUInt32(bytes, offset: offset)
        let size = try objectiveCFixtureUInt32(bytes, offset: offset + 4)
        if command == 0x19 {
            let segmentVirtualAddress = try objectiveCFixtureUInt64(bytes, offset: offset + 24)
            segments.append(ObjectiveCFixtureSegment(headerOffset: offset,
                name: try objectiveCFixtureName(bytes, offset: offset + 8),
                virtualAddress: segmentVirtualAddress,
                fileOffset: try objectiveCFixtureUInt64(bytes, offset: offset + 40),
                fileSize: try objectiveCFixtureUInt64(bytes, offset: offset + 48)))
            let sectionCount = try objectiveCFixtureUInt32(bytes, offset: offset + 64)
            for index in 0..<sectionCount {
                let position = offset + 72 + Int(index) * 80
                let name = try objectiveCFixtureName(bytes, offset: position)
                if name.hasPrefix("__objc_") {
                    sections.append(ObjectiveCFixtureSection(headerOffset: position, segmentHeaderOffset: offset,
                        segmentIndex: segmentIndex, segmentVirtualAddress: segmentVirtualAddress,
                        segmentName: try objectiveCFixtureName(bytes, offset: position + 16), sectionName: name,
                        virtualAddress: try objectiveCFixtureUInt64(bytes, offset: position + 32),
                        fileOffset: UInt64(try objectiveCFixtureUInt32(bytes, offset: position + 48)),
                        byteCount: try objectiveCFixtureUInt64(bytes, offset: position + 40),
                        flags: try objectiveCFixtureUInt32(bytes, offset: position + 64),
                        alignmentExponent: try objectiveCFixtureUInt32(bytes, offset: position + 52),
                        relocationCount: try objectiveCFixtureUInt32(bytes, offset: position + 60)))
                }
            }
            segmentIndex += 1
        }
        if command == 0x22 || command == 0x8000_0022 { bindingCommandOffset = offset }
        offset += Int(size)
    }
    return ObjectiveCFixtureLayout(fileType: try objectiveCFixtureUInt32(bytes, offset: start + 12),
        flags: try objectiveCFixtureUInt32(bytes, offset: start + 24), minimumDataOffset: 32 + UInt64(commandBytes),
        sections: sections, segments: segments, bindingCommandOffset: bindingCommandOffset)
}

private func nativeObjectiveCSectionRows(_ data: Data) throws -> [NativeObjectiveCSectionRow] {
    guard let text = String(data: data, encoding: .utf8) else { throw ObjectiveCFixtureError.invalidNativeOutput("Invalid UTF-8.") }
    var section: String?
    var rows: [NativeObjectiveCSectionRow] = []
    for line in text.split(separator: "\n") {
        if line.hasPrefix("("), let comma = line.firstIndex(of: ","), let closing = line.firstIndex(of: ")") {
            section = String(line[line.index(after: comma)..<closing])
        } else if line.hasPrefix("0x"), let section {
            let fields = line.split(maxSplits: 1, whereSeparator: { $0.isWhitespace })
            guard fields.count == 2, let address = UInt64(fields[0].dropFirst(2), radix: 16) else {
                throw ObjectiveCFixtureError.invalidNativeOutput("Invalid address or name row.")
            }
            rows.append(NativeObjectiveCSectionRow(section: section, virtualAddress: address,
                value: fields[1].trimmingCharacters(in: .whitespaces)))
        }
    }
    guard !rows.isEmpty else { throw ObjectiveCFixtureError.invalidNativeOutput("No reference rows were printed.") }
    return rows
}

private func nativeObjectiveCBindingRows(_ data: Data) throws -> [NativeObjectiveCBinding] {
    guard let text = String(data: data, encoding: .utf8) else { throw ObjectiveCFixtureError.invalidNativeOutput("Invalid UTF-8.") }
    var bindings: [NativeObjectiveCBinding] = []
    for line in text.split(separator: "\n") {
        let fields = line.split(whereSeparator: { $0.isWhitespace })
        if fields.count == 5, fields[3] == "bind" {
            guard fields[2].hasPrefix("0x"), let address = UInt64(fields[2].dropFirst(2), radix: 16),
                let separator = fields[4].firstIndex(of: "/"), separator < fields[4].index(before: fields[4].endIndex) else {
                throw ObjectiveCFixtureError.invalidNativeOutput("Invalid binding address or library/symbol target.")
            }
            bindings.append(NativeObjectiveCBinding(segmentName: String(fields[0]), virtualAddress: address,
                name: String(fields[4][fields[4].index(after: separator)...])))
        }
    }
    guard !bindings.isEmpty else { throw ObjectiveCFixtureError.invalidNativeOutput("No binding rows were printed.") }
    return bindings
}

private func nativeObjectiveCSelector(_ value: String) throws -> String {
    guard value.count > 2, value.first == "\"", value.last == "\"" else {
        throw ObjectiveCFixtureError.invalidNativeOutput("A selector row lacks its quoted literal name.")
    }
    return String(value.dropFirst().dropLast())
}

private func nativeObjectiveCClass(_ value: String) throws -> String {
    let prefix = "_OBJC_CLASS_$_"
    guard value.hasPrefix(prefix), value.count > prefix.count else {
        throw ObjectiveCFixtureError.invalidNativeOutput("A class row lacks its declared Objective-C class symbol.")
    }
    return String(value.dropFirst(prefix.count))
}

private func objectiveCNativeSlotOffset(_ address: UInt64, section: ObjectiveCFixtureSection, slice: MachOSlice) throws -> UInt64 {
    guard address >= section.virtualAddress else {
        throw ObjectiveCFixtureError.invalidNativeOutput("A reference address precedes its declared section.")
    }
    let offset = address - section.virtualAddress
    guard offset.isMultiple(of: 8), offset <= section.byteCount, 8 <= section.byteCount - offset else {
        throw ObjectiveCFixtureError.invalidNativeOutput("A reference address is not an 8-byte slot in its declared section.")
    }
    return slice.fileOffset + section.fileOffset + offset
}

private func verifyObjectiveCReferenceBytes(_ reference: StaticAPIReference, bytes: Data, url: URL, slice: MachOSlice) throws {
    #expect(reference.location.method == .objectiveCMetadata)
    #expect(reference.location.sourcePath == url.path)
    #expect(reference.location.architecture == slice.architecture)
    #expect(reference.location.sliceOffset == slice.fileOffset)
    let nameOffset = try #require(reference.location.fileOffset)
    let nameCount = try #require(reference.location.byteCount)
    let nameIndex = try #require(Int(exactly: nameOffset))
    let nameLength = try #require(Int(exactly: nameCount))
    try #require(nameLength > 0)
    try objectiveCFixtureRange(bytes, offset: nameIndex, count: nameLength)
    #expect(nameLength == reference.name.utf8.count + 1)
    #expect(bytes[nameIndex + nameLength - 1] == 0)
    #expect(Data(bytes[nameIndex..<(nameIndex + nameLength - 1)]) == Data(reference.name.utf8))
    let slot = try #require(reference.referenceLocation)
    #expect(slot.method == .objectiveCMetadata)
    #expect(slot.sourcePath == url.path)
    #expect(slot.architecture == slice.architecture)
    #expect(slot.sliceOffset == slice.fileOffset)
    #expect(slot.byteCount == 8)
    let slotOffset = try #require(slot.fileOffset)
    #expect(slotOffset >= slice.fileOffset && slotOffset - slice.fileOffset <= slice.fileSize - 8)
}

private func collectObjectiveCFeatureFinding(_ url: URL) async throws -> ScanFinding {
    let configuration = ScanConfiguration(roots: [url], includeHidden: true, deepCarve: false,
        maximumWorkerCount: 1, queueCapacity: 4, maximumCarveBytes: 1_048_576, excludedPathPrefixes: [])
    var findings: [ScanFinding] = []
    var issues: [ScanIssue] = []
    var completed = false
    for await update in ScanCoordinator.updates(configuration: configuration) {
        switch update {
        case let .batch(batch):
            findings.append(contentsOf: batch.findings)
            issues.append(contentsOf: batch.issues.filter { $0.category != .skipped })
        case .completed: completed = true
        case .cancelled: Issue.record("Objective-C feature fixture collection was cancelled.")
        }
    }
    #expect(completed)
    #expect(issues.isEmpty)
    let selected = findings.filter { $0.path == url.path }
    #expect(selected.count == 1)
    return try #require(selected.first)
}

private func objectiveCFixtureRange(_ bytes: Data, offset: Int, count: Int) throws {
    guard offset >= 0, count >= 0, offset <= bytes.count, count <= bytes.count - offset else {
        throw ObjectiveCFixtureError.invalidRange(offset, count)
    }
}

private func objectiveCFixtureUInt32(_ bytes: Data, offset: Int) throws -> UInt32 {
    try objectiveCFixtureRange(bytes, offset: offset, count: 4)
    return bytes[offset..<(offset + 4)].enumerated().reduce(0) { value, byte in
        value | UInt32(byte.element) << UInt32(byte.offset * 8)
    }
}

private func objectiveCFixtureUInt64(_ bytes: Data, offset: Int) throws -> UInt64 {
    try objectiveCFixtureRange(bytes, offset: offset, count: 8)
    return bytes[offset..<(offset + 8)].enumerated().reduce(0) { value, byte in
        value | UInt64(byte.element) << UInt64(byte.offset * 8)
    }
}

private func objectiveCFixtureName(_ bytes: Data, offset: Int) throws -> String {
    try objectiveCFixtureRange(bytes, offset: offset, count: 16)
    let name = bytes[offset..<(offset + 16)].prefix { $0 != 0 }
    guard let value = String(data: Data(name), encoding: .utf8) else { throw ObjectiveCFixtureError.invalidHeader }
    return value
}

private func objectiveCFixtureReplacingUInt32(_ bytes: Data, offset: Int, value: UInt32) throws -> Data {
    try objectiveCFixtureRange(bytes, offset: offset, count: 4)
    var result = bytes
    for index in 0..<4 { result[offset + index] = UInt8(truncatingIfNeeded: value >> UInt32(index * 8)) }
    return result
}

private func objectiveCFixtureReplacingUInt64(_ bytes: Data, offset: Int, value: UInt64) throws -> Data {
    try objectiveCFixtureRange(bytes, offset: offset, count: 8)
    var result = bytes
    for index in 0..<8 { result[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64(index * 8)) }
    return result
}

private func objectiveCFixtureReplacingByte(_ bytes: Data, offset: Int, value: UInt8) throws -> Data {
    try objectiveCFixtureRange(bytes, offset: offset, count: 1)
    var result = bytes
    result[offset] = value
    return result
}

private func objectiveCFixtureReplacingNormalBindings(
    _ bytes: Data, slice: MachOSlice, layout: ObjectiveCFixtureLayout, program: Data
) throws -> Data {
    let command = try #require(layout.bindingCommandOffset)
    let dataOffset = try objectiveCFixtureUInt32(bytes, offset: command + 16)
    let dataSize = try objectiveCFixtureUInt32(bytes, offset: command + 20)
    try #require(UInt64(program.count) <= UInt64(dataSize))
    let absolute = try #require(Int(exactly: slice.fileOffset + UInt64(dataOffset)))
    try objectiveCFixtureRange(bytes, offset: absolute, count: Int(dataSize))
    var result = bytes
    result.replaceSubrange(absolute..<(absolute + Int(dataSize)),
        with: program + Data(repeating: 0, count: Int(dataSize) - program.count))
    let size = try #require(UInt32(exactly: program.count))
    return try objectiveCFixtureReplacingUInt32(result, offset: command + 20, value: size)
}

private func objectiveCFixtureAuthenticatingDataSegment(_ bytes: Data, section: ObjectiveCFixtureSection) throws -> Data {
    let name = Data("__AUTH".utf8) + Data(repeating: 0, count: 10)
    var result = bytes
    try objectiveCFixtureRange(result, offset: section.segmentHeaderOffset + 8, count: 16)
    result.replaceSubrange((section.segmentHeaderOffset + 8)..<(section.segmentHeaderOffset + 24), with: name)
    let count = try objectiveCFixtureUInt32(bytes, offset: section.segmentHeaderOffset + 64)
    for index in 0..<count {
        let field = section.segmentHeaderOffset + 72 + Int(index) * 80 + 16
        try objectiveCFixtureRange(result, offset: field, count: 16)
        result.replaceSubrange(field..<(field + 16), with: name)
    }
    return result
}

private func objectiveCFixtureULEB(_ value: UInt64) -> Data {
    var remaining = value
    var result: [UInt8] = []
    repeat {
        let byte = UInt8(remaining & 0x7F)
        remaining >>= 7
        result.append(remaining == 0 ? byte : byte | 0x80)
    } while remaining != 0
    return Data(result)
}
