import Foundation
import Testing
@testable import EntitlementLens

struct ChainedImportIntegrationTests {
    @Test
    func collectsRealUniversalImportsMatchingApplesStaticTool() throws {
        let root = try chainedFixtureRoot()
        defer { removeChainedFixture(root) }
        let url = try makeChainedFixture(root)
        let bytes = try Data(contentsOf: url)
        let slices = try MachOInspector.inspect(url)
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        #expect(Set(slices.map(\.architecture)) == ["arm64", "x86_64"])
        for slice in slices {
            let context = try chainedFixtureContext(url: url, bytes: bytes, slice: slice)
            let collection = try collectChainedFixture(context)
            #expect(collection.state == .partial)
            #expect(collection.records.map(\.name) == ["_CFAbsoluteTimeGetCurrent", "_CFRelease", "_CFStringCreateWithCString"])
            #expect(collection.records.allSatisfy { $0.kind == .importedSymbol })
            #expect(collection.records == inspection.apiReferences.records.filter {
                $0.location.sliceOffset == slice.fileOffset && $0.location.method == .chainedFixupImports
            })
            let thinURL = root.appendingPathComponent("fixture.\(slice.architecture)")
            let oracle = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
                arguments: ["dyld_info", "-imports", thinURL.path])
            let oracleText = try #require(String(data: oracle.standardOutput, encoding: .utf8))
            let oracleNames = oracleText.split(separator: "\n").compactMap { line -> String? in
                let fields = line.split(whereSeparator: { $0.isWhitespace })
                guard fields.count >= 2, fields[0].hasPrefix("0x") else { return nil }
                return String(fields[1])
            }
            #expect(collection.records.map(\.name) == oracleNames)
            try verifyChainedLocations(records: collection.records, bytes: bytes, context: context)
            let encoded = try JSONEncoder().encode(collection)
            #expect(try JSONDecoder().decode(StaticFeatureCollection<StaticAPIReference>.self, from: encoded) == collection)
        }
        #expect(inspection.apiReferences.limitations.contains { $0.contains("pointer-chain usage") })
    }

    @Test
    func supportsPackedAddendFormatsAndChecksImportAttribution() throws {
        let root = try chainedFixtureRoot()
        defer { removeChainedFixture(root) }
        _ = try makeChainedFixture(root)
        let original = try chainedThinContext(root)
        let native = try collectChainedFixture(original)
        let addendFormats: [UInt32] = [2, 3]
        for format in addendFormats {
            let payload = try chainedConvertedPayload(original, format: format)
            let url = root.appendingPathComponent("controlled-format-\(format).arm64")
            let context = try writeChainedPayload(payload, original: original, url: url)
            let collection = try collectChainedFixture(context)
            #expect(collection.state == .partial)
            #expect(collection.records.map(\.name) == native.records.map(\.name))
            #expect(collection.records.map(\.kind) == native.records.map(\.kind))
            try verifyChainedLocations(records: collection.records, bytes: Data(contentsOf: url), context: context)

            let importsOffset = Int(try chainedUInt32(payload, offset: 8))
            let packed = try chainedUInt32(payload, offset: importsOffset)
            let ordinalWidth = format == 3 ? UInt32(0xFFFF) : UInt32(0xFF)
            let lookups: [UInt32] = [0, ordinalWidth, ordinalWidth - 1, ordinalWidth - 2]
            for ordinal in lookups {
                let altered = try replacingChainedUInt32(payload, offset: importsOffset,
                    value: (packed & ~ordinalWidth) | ordinal)
                let lookupURL = root.appendingPathComponent("lookup-\(format)-\(ordinal).arm64")
                let lookup = try collectChainedFixture(writeChainedPayload(altered, original: original, url: lookupURL))
                #expect(lookup.records.count == native.records.count)
                #expect(lookup.records.first?.kind == .dyldBindingSymbol)
                #expect(lookup.records.dropFirst().allSatisfy { $0.kind == .importedSymbol })
            }
            let positiveTooLarge = try replacingChainedUInt32(payload, offset: importsOffset,
                value: (packed & ~ordinalWidth) | (original.dylibCount + 1))
            let invalidURL = root.appendingPathComponent("bad-ordinal-\(format).arm64")
            let invalid = try collectChainedFixture(writeChainedPayload(positiveTooLarge, original: original, url: invalidURL))
            #expect(invalid.state == .partial)
            #expect(invalid.records.map(\.name) == Array(native.records.dropFirst().map(\.name)))
            #expect(invalid.limitations.contains { $0.contains("Library ordinal") && $0.contains("declared dependencies") })
            let unknownSpecial = try replacingChainedUInt32(payload, offset: importsOffset,
                value: (packed & ~ordinalWidth) | (ordinalWidth - 14))
            let unknownURL = root.appendingPathComponent("unknown-special-\(format).arm64")
            let unknown = try collectChainedFixture(writeChainedPayload(unknownSpecial, original: original, url: unknownURL))
            #expect(unknown.records.count == native.records.count - 1)
            #expect(unknown.limitations.contains { $0.contains("Library ordinal -15") })
        }
        let format3 = try chainedConvertedPayload(original, format: 3)
        let importsOffset = Int(try chainedUInt32(format3, offset: 8))
        let packed = try chainedUInt32(format3, offset: importsOffset)
        let reserved = try replacingChainedUInt32(format3, offset: importsOffset, value: packed | (1 << 17))
        let reservedURL = root.appendingPathComponent("reserved-bit.arm64")
        let invalid = try collectChainedFixture(writeChainedPayload(reserved, original: original, url: reservedURL))
        #expect(invalid.state == .partial)
        #expect(invalid.records.count == native.records.count - 1)
        #expect(invalid.limitations.contains { $0.contains("reserved bits") })

        // Values below the negative-ordinal thresholds remain positive even when their top bit is set.
        let thresholdFormats: [UInt32] = [1, 3]
        for format in thresholdFormats {
            let payload = try chainedConvertedPayload(original, format: format)
            let position = Int(try chainedUInt32(payload, offset: 8))
            let value = try chainedUInt32(payload, offset: position)
            let ordinalMask: UInt32 = format == 3 ? 0xFFFF : 0xFF
            let encoded: UInt32 = format == 3 ? 0xFFF0 : 0xF0
            let altered = try replacingChainedUInt32(payload, offset: position, value: (value & ~ordinalMask) | encoded)
            let url = root.appendingPathComponent("positive-ordinal-threshold-\(format).arm64")
            let result = try collectChainedFixture(writeChainedPayload(altered, original: original, url: url))
            #expect(result.records.count == native.records.count - 1)
            #expect(result.limitations.contains { $0.contains("Library ordinal \(encoded)") })
        }
    }

    @Test
    func reportsFutureAndMalformedHeadersWithoutLosingTheOtherSlice() throws {
        let root = try chainedFixtureRoot()
        defer { removeChainedFixture(root) }
        let url = try makeChainedFixture(root)
        let bytes = try Data(contentsOf: url)
        let slices = try MachOInspector.inspect(url)
        let affected = try #require(slices.first)
        let other = try #require(slices.last)
        let context = try chainedFixtureContext(url: url, bytes: bytes, slice: affected)
        let headerOffset = Int(affected.fileOffset) + Int(context.descriptor.dataOffset)
        let importsOffset = try chainedUInt32(bytes, offset: headerOffset + 8)
        let mutations: [(label: String, offset: Int, value: UInt32, state: StaticCollectionState, reason: String)] = [
            ("future", headerOffset, 1, .unsupported, "fixups_version 1"),
            ("format", headerOffset + 20, 99, .unsupported, "imports_format 99"),
            ("compression", headerOffset + 24, 1, .unsupported, "symbols_format"),
            ("starts-header-overlap", headerOffset + 4, 0, .unavailable, "overlap"),
            ("starts-import-overlap", headerOffset + 8, 32, .unavailable, "overlap"),
            ("alternate-starts-order", headerOffset + 4, importsOffset + 4, .unsupported, "unsupported region ordering"),
            ("import-symbol-overlap", headerOffset + 12, importsOffset, .unavailable, "overlap"),
            ("symbols-beyond-payload", headerOffset + 12, context.descriptor.dataSize + 1, .unavailable, "exceeds"),
            ("count-limit", headerOffset + 16, UInt32.max, .partial, "collection limit"),
            ("short-header", context.commandOffset + 12, 27, .unavailable, "shorter"),
            ("cross-slice-payload", context.commandOffset + 8, UInt32(affected.fileSize - 8), .unavailable, "outside")
        ]
        for mutation in mutations {
            let alteredURL = root.appendingPathComponent("\(mutation.label).universal")
            let altered = try replacingChainedUInt32(bytes, offset: mutation.offset, value: mutation.value)
            try altered.write(to: alteredURL)
            let alteredContext = try chainedFixtureContext(url: alteredURL, bytes: altered, slice: affected)
            let result = try collectChainedFixture(alteredContext)
            #expect(result.state == mutation.state)
            #expect(result.records.isEmpty)
            #expect(result.reason?.contains(mutation.reason) == true)
            let merged = try MachOInspector.inspectStaticFeatures(alteredURL)
            #expect(merged.architectures.state == .complete)
            #expect(merged.apiReferences.state == .partial)
            #expect(merged.apiReferences.records.contains {
                $0.location.sliceOffset == other.fileOffset && $0.location.method == .chainedFixupImports
            })
            #expect(!merged.apiReferences.records.contains {
                $0.location.sliceOffset == affected.fileOffset && $0.location.method == .chainedFixupImports
            })
        }
        let bigEndian = ChainedFixtureContext(url: context.url, bytes: context.bytes, slice: context.slice,
            commandOffset: context.commandOffset, minimumDataOffset: context.minimumDataOffset,
            descriptor: MachOChainedImportDescriptor(dataOffset: context.descriptor.dataOffset,
                dataSize: context.descriptor.dataSize, byteOrder: .big), dylibCount: context.dylibCount)
        let endianResult = try collectChainedFixture(bigEndian)
        #expect(endianResult.state == .unsupported)
        #expect(endianResult.reason?.contains("big-endian") == true)
    }

    @Test
    func retainsValidEntriesAlongsideInvalidNamesAndTruncatedData() throws {
        let root = try chainedFixtureRoot()
        defer { removeChainedFixture(root) }
        _ = try makeChainedFixture(root)
        let context = try chainedThinContext(root)
        let native = try collectChainedFixture(context)
        let payload = try chainedConvertedPayload(context, format: 1)
        let importOffset = Int(try chainedUInt32(payload, offset: 8))
        let symbolsOffset = Int(try chainedUInt32(payload, offset: 12))
        let packed = try chainedUInt32(payload, offset: importOffset)
        let firstNameOffset = Int(packed >> 9)
        var invalidUTF8 = payload
        invalidUTF8[symbolsOffset + firstNameOffset] = 0xFF
        let utf8URL = root.appendingPathComponent("invalid-utf8.arm64")
        let utf8 = try collectChainedFixture(writeChainedPayload(invalidUTF8, original: context, url: utf8URL))
        #expect(utf8.records.map(\.name) == Array(native.records.dropFirst().map(\.name)))
        #expect(utf8.limitations.contains { $0.contains("not valid UTF-8") })

        let beyondPool = try replacingChainedUInt32(payload, offset: importOffset,
            value: UInt32(payload.count - symbolsOffset) << 9 | (packed & 0x1FF))
        let beyondURL = root.appendingPathComponent("outside-name.arm64")
        let beyond = try collectChainedFixture(writeChainedPayload(beyondPool, original: context, url: beyondURL))
        #expect(beyond.records.count == native.records.count - 1)
        #expect(beyond.limitations.contains { $0.contains("name_offset") && $0.contains("outside") })

        var emptyName = payload
        emptyName[symbolsOffset + firstNameOffset] = 0
        let emptyURL = root.appendingPathComponent("empty-name.arm64")
        let empty = try collectChainedFixture(writeChainedPayload(emptyName, original: context, url: emptyURL))
        #expect(empty.records.count == native.records.count - 1)
        #expect(empty.limitations.contains { $0.contains("empty name") })

        let lastNameOffset = try (0..<native.records.count).map { index in
            Int(try chainedUInt32(payload, offset: importOffset + index * 4) >> 9)
        }.max()
        let lastStart = symbolsOffset + (try #require(lastNameOffset))
        var unterminated = payload
        for position in lastStart..<unterminated.count { unterminated[position] = 0x41 }
        let unterminatedURL = root.appendingPathComponent("unterminated-name.arm64")
        let badTerminator = try collectChainedFixture(writeChainedPayload(unterminated, original: context, url: unterminatedURL))
        #expect(badTerminator.records.count == native.records.count - 1)
        #expect(badTerminator.limitations.contains { $0.contains("no NUL terminator") })

        let truncatedURL = root.appendingPathComponent("truncated-payload.arm64")
        try context.bytes.prefix(Int(context.descriptor.dataOffset) + 16).write(to: truncatedURL)
        let truncated = ChainedFixtureContext(url: truncatedURL, bytes: context.bytes, slice: context.slice,
            commandOffset: context.commandOffset, minimumDataOffset: context.minimumDataOffset,
            descriptor: context.descriptor, dylibCount: context.dylibCount)
        let truncatedResult = try collectChainedFixture(truncated)
        #expect(truncatedResult.state == .unavailable)
        #expect(truncatedResult.reason?.contains("truncated") == true)
    }

    @Test
    func boundsCollectionSizeAndRetainsSharedNamesAtOffsetZero() throws {
        let root = try chainedFixtureRoot()
        defer { removeChainedFixture(root) }
        _ = try makeChainedFixture(root)
        let context = try chainedThinContext(root)
        let nativePayload = try chainedConvertedPayload(context, format: 1)
        let importOffset = Int(try chainedUInt32(nativePayload, offset: 8))
        let prefix = Data(nativePayload.prefix(importOffset))
        let validOrdinal = try chainedUInt32(nativePayload, offset: importOffset) & 0xFF
        let sharedName = Data("_CFRelease\0".utf8)
        let repeatedCount: UInt32 = 16_385
        let encodedImport = [UInt8](chainedUInt32Bytes(validOrdinal))
        let repeatedRecords = Data((0..<repeatedCount).flatMap { _ in encodedImport })
        let repeatedPayload = try chainedPayloadFromParts(prefix: prefix, imports: repeatedRecords,
            importCount: repeatedCount, pool: sharedName)
        let repeatedURL = root.appendingPathComponent("reference-limit.arm64")
        let repeated = try collectChainedFixture(writeChainedPayload(repeatedPayload, original: context, url: repeatedURL))
        #expect(repeated.state == .partial)
        #expect(repeated.records.count == 16_384)
        #expect(repeated.records.allSatisfy { $0.name == "_CFRelease" && $0.kind == .importedSymbol })
        #expect(Set(repeated.records.compactMap(\.location.fileOffset)).count == 1)
        #expect(repeated.reason?.contains("reference limit") == true)
        #expect(repeated.limits.contains { $0.name == "chained_imported_references_per_slice" && $0.value == 16_384 })

        let originalSymbols = try MachOInspector.inspectStaticFeatures(context.url).apiReferences.records.filter {
            $0.location.method == .symbolTable
        }
        #expect(!originalSymbols.isEmpty)
        let aggregate = try MachOInspector.inspectStaticFeatures(repeatedURL).apiReferences
        #expect(aggregate.state == .partial)
        #expect(aggregate.records.count == 16_384)
        let retainedSymbols = Array(aggregate.records.prefix(originalSymbols.count))
        #expect(retainedSymbols.allSatisfy { $0.location.method == .symbolTable })
        #expect(retainedSymbols.map(\.name) == originalSymbols.map(\.name))
        #expect(retainedSymbols.map(\.location.fileOffset) == originalSymbols.map(\.location.fileOffset))
        let retainedChains = aggregate.records.filter { $0.location.method == .chainedFixupImports }
        #expect(retainedChains.count == 16_384 - originalSymbols.count)
        #expect(retainedChains == Array(repeated.records.prefix(retainedChains.count)))
        #expect(aggregate.reason?.contains("Combined API collection") == true)
        #expect(aggregate.reason?.contains("16384-record limit") == true)
        let exportedAggregate = try JSONDecoder().decode(StaticFeatureCollection<StaticAPIReference>.self,
            from: JSONEncoder().encode(aggregate))
        #expect(exportedAggregate == aggregate)
        #expect(exportedAggregate.limits.contains { $0.name == "api_reference_records_per_slice" && $0.value == 16_384 })

        let longName = Data(repeating: 0x41, count: 4_097) + Data([0])
        let pool = longName + sharedName
        let table = chainedUInt32Bytes(validOrdinal) + chainedUInt32Bytes(UInt32(longName.count) << 9 | validOrdinal)
        let longPayload = try chainedPayloadFromParts(prefix: prefix, imports: table, importCount: 2, pool: pool)
        let longURL = root.appendingPathComponent("name-limit.arm64")
        let long = try collectChainedFixture(writeChainedPayload(longPayload, original: context, url: longURL))
        #expect(long.records.map(\.name) == ["_CFRelease"])
        #expect(long.limitations.contains { $0.contains("4096-byte name limit") })
    }

    @Test @MainActor
    func propagatesCancellationBeforeChainedReads() async throws {
        let root = try chainedFixtureRoot()
        defer { removeChainedFixture(root) }
        _ = try makeChainedFixture(root)
        let context = try chainedThinContext(root)
        let task = Task { try collectChainedFixture(context) }
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Chained-fixup collection completed after cancellation.")
        } catch is CancellationError { }
    }
}

private struct ChainedFixtureContext {
    let url: URL
    let bytes: Data
    let slice: MachOSlice
    let commandOffset: Int
    let minimumDataOffset: UInt64
    let descriptor: MachOChainedImportDescriptor
    let dylibCount: UInt32
}

private enum ChainedFixtureError: LocalizedError {
    case invalidBytes(Int, Int)
    case missingCommand

    var errorDescription: String? {
        switch self {
        case let .invalidBytes(offset, length): "Chained-fixup fixture byte range at \(offset) for \(length) bytes is invalid."
        case .missingCommand: "The real linked fixture has no LC_DYLD_CHAINED_FIXUPS command."
        }
    }
}

private func chainedFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-chained-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeChainedFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Chained-fixup fixture cleanup failed: \(error.localizedDescription)") }
}

private func makeChainedFixture(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("fixture.c")
    try Data("""
        #include <CoreFoundation/CoreFoundation.h>
        int main(void) {
            CFStringRef value = CFStringCreateWithCString(NULL, "chained imports", kCFStringEncodingUTF8);
            CFRelease(value);
            return CFAbsoluteTimeGetCurrent() < 0;
        }
        """.utf8).write(to: source)
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    let arm = root.appendingPathComponent("fixture.arm64")
    let x86 = root.appendingPathComponent("fixture.x86_64")
    for architecture in ["arm64", "x86_64"] {
        let target = root.appendingPathComponent("fixture.\(architecture)")
        _ = try runFixtureTool(executable: xcrun,
            arguments: ["clang", "-target", "\(architecture)-apple-macos14.0", source.path,
                "-framework", "CoreFoundation", "-Wl,-fixup_chains", "-o", target.path])
    }
    let universal = root.appendingPathComponent("fixture.universal")
    _ = try runFixtureTool(executable: xcrun,
        arguments: ["lipo", "-create", arm.path, x86.path, "-output", universal.path])
    return universal
}

private func chainedThinContext(_ root: URL) throws -> ChainedFixtureContext {
    let url = root.appendingPathComponent("fixture.arm64")
    let bytes = try Data(contentsOf: url)
    let slice = try #require(MachOInspector.inspect(url).first)
    return try chainedFixtureContext(url: url, bytes: bytes, slice: slice)
}

private func chainedFixtureContext(url: URL, bytes: Data, slice: MachOSlice) throws -> ChainedFixtureContext {
    let base = try #require(Int(exactly: slice.fileOffset))
    #expect(try chainedUInt32(bytes, offset: base) == 0xFEED_FACF)
    let count = try chainedUInt32(bytes, offset: base + 16)
    let minimumDataOffset = UInt64(try chainedUInt32(bytes, offset: base + 20)) + 32
    var position = base + 32
    var commandOffset: Int?
    var dylibCount: UInt32 = 0
    for _ in 0..<count {
        let command = try chainedUInt32(bytes, offset: position)
        let size = try chainedUInt32(bytes, offset: position + 4)
        guard size >= 8, position <= bytes.count, Int(size) <= bytes.count - position else {
            throw ChainedFixtureError.invalidBytes(position, Int(size))
        }
        if command == 0x8000_0034 { commandOffset = position }
        if [UInt32(0x0C), 0x8000_0018, 0x8000_001F, 0x20, 0x8000_0023].contains(command) { dylibCount += 1 }
        position += Int(size)
    }
    guard let commandOffset else { throw ChainedFixtureError.missingCommand }
    return ChainedFixtureContext(url: url, bytes: bytes, slice: slice, commandOffset: commandOffset,
        minimumDataOffset: minimumDataOffset,
        descriptor: MachOChainedImportDescriptor(dataOffset: try chainedUInt32(bytes, offset: commandOffset + 8),
            dataSize: try chainedUInt32(bytes, offset: commandOffset + 12), byteOrder: .little), dylibCount: dylibCount)
}

private func collectChainedFixture(_ context: ChainedFixtureContext) throws -> StaticFeatureCollection<StaticAPIReference> {
    let handle = try FileHandle(forReadingFrom: context.url)
    defer {
        do { try handle.close() }
        catch { Issue.record("Chained-fixup fixture file close failed: \(error.localizedDescription)") }
    }
    return try MachOChainedImportCollector.collect(handle: handle, url: context.url, slice: context.slice,
        containerSize: UInt64(context.bytes.count), minimumDataOffset: context.minimumDataOffset,
        descriptor: context.descriptor, dylibCount: context.dylibCount)
}

private func verifyChainedLocations(records: [StaticAPIReference], bytes: Data, context: ChainedFixtureContext) throws {
    for record in records {
        let fileOffset = try #require(record.location.fileOffset)
        let byteCount = try #require(record.location.byteCount)
        let offset = try #require(Int(exactly: fileOffset))
        let count = try #require(Int(exactly: byteCount))
        #expect(record.location.sourcePath == context.url.path)
        #expect(record.location.architecture == context.slice.architecture)
        #expect(record.location.sliceOffset == context.slice.fileOffset)
        #expect(record.location.method == .chainedFixupImports)
        #expect(offset >= Int(context.slice.fileOffset) + Int(context.descriptor.dataOffset))
        guard offset <= bytes.count, count > 1, count <= bytes.count - offset else {
            throw ChainedFixtureError.invalidBytes(offset, count)
        }
        #expect(bytes[offset + count - 1] == 0)
        #expect(String(data: bytes[offset..<(offset + count - 1)], encoding: .utf8) == record.name)
    }
}

/// These controlled import-format copies preserve real linker-produced starts metadata and names.
/// Their relocated table is inspected only; signature integrity and runtime pointer validity are not asserted.
private func chainedConvertedPayload(_ context: ChainedFixtureContext, format: UInt32) throws -> Data {
    let base = Int(context.slice.fileOffset) + Int(context.descriptor.dataOffset)
    let payload = Data(context.bytes[base..<(base + Int(context.descriptor.dataSize))])
    #expect(try chainedUInt32(payload, offset: 20) == 1)
    let importsOffset = Int(try chainedUInt32(payload, offset: 8))
    let symbolsOffset = Int(try chainedUInt32(payload, offset: 12))
    let importCount = try chainedUInt32(payload, offset: 16)
    let table = try (0..<importCount).reduce(Data()) { bytes, index in
        let packed = try chainedUInt32(payload, offset: importsOffset + Int(index) * 4)
        if format == 3 {
            let ordinal = packed & 0xFF
            let widenedOrdinal = ordinal > 0xF0 ? UInt64(ordinal | 0xFF00) : UInt64(ordinal)
            let value = UInt64(packed >> 9) << 32 | UInt64((packed >> 8) & 1) << 16 | widenedOrdinal
            return bytes + chainedUInt64Bytes(value) + chainedUInt64Bytes(UInt64.max - 16)
        }
        if format == 2 { return bytes + chainedUInt32Bytes(packed) + chainedUInt32Bytes(UInt32.max - 16) }
        #expect(format == 1)
        return bytes + chainedUInt32Bytes(packed)
    }
    let prefix = try replacingChainedUInt32(Data(payload.prefix(importsOffset)), offset: 20, value: format)
    return try chainedPayloadFromParts(prefix: prefix, imports: table, importCount: importCount,
        pool: Data(payload[symbolsOffset..<payload.count]))
}

private func chainedPayloadFromParts(prefix: Data, imports: Data, importCount: UInt32, pool: Data) throws -> Data {
    let withCount = try replacingChainedUInt32(prefix, offset: 16, value: importCount)
    let withSymbols = try replacingChainedUInt32(withCount, offset: 12, value: UInt32(prefix.count + imports.count))
    return withSymbols + imports + pool
}

private func writeChainedPayload(_ payload: Data, original: ChainedFixtureContext, url: URL) throws -> ChainedFixtureContext {
    #expect(original.slice.fileOffset == 0)
    let padding = Data(repeating: 0, count: (8 - original.bytes.count % 8) % 8)
    let dataOffset = try #require(UInt32(exactly: original.bytes.count + padding.count))
    let dataSize = try #require(UInt32(exactly: payload.count))
    let withOffset = try replacingChainedUInt32(original.bytes, offset: original.commandOffset + 8, value: dataOffset)
    let withSize = try replacingChainedUInt32(withOffset, offset: original.commandOffset + 12, value: dataSize)
    let bytes = withSize + padding + payload
    try bytes.write(to: url)
    let slice = try #require(MachOInspector.inspect(url).first)
    return try chainedFixtureContext(url: url, bytes: bytes, slice: slice)
}

private func chainedUInt32(_ data: Data, offset: Int) throws -> UInt32 {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw ChainedFixtureError.invalidBytes(offset, 4)
    }
    return data[offset..<(offset + 4)].enumerated().reduce(0) { value, byte in
        value | UInt32(byte.element) << UInt32(byte.offset * 8)
    }
}

private func chainedUInt32Bytes(_ value: UInt32) -> Data {
    Data((0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32($0 * 8)) })
}

private func chainedUInt64Bytes(_ value: UInt64) -> Data {
    Data((0..<8).map { UInt8(truncatingIfNeeded: value >> UInt64($0 * 8)) })
}

private func replacingChainedUInt32(_ data: Data, offset: Int, value: UInt32) throws -> Data {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw ChainedFixtureError.invalidBytes(offset, 4)
    }
    var result = data
    result.replaceSubrange(offset..<(offset + 4), with: chainedUInt32Bytes(value))
    return result
}
