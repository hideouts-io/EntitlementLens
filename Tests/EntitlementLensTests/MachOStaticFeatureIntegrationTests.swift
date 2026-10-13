import Foundation
import Testing
@testable import EntitlementLens

struct MachOStaticFeatureIntegrationTests {
    @Test
    func exportsArchitectureBoundDependenciesAndImportedSymbols() throws {
        let root = try staticMachOFixtureRoot()
        defer { removeStaticMachOFixture(root) }
        let url = try makeStaticMachOFixture(root)
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        let legacySlices = try MachOInspector.inspect(url)
        #expect(inspection.architectures.state == .complete)
        #expect(inspection.architectures.records.map(\.slice) == legacySlices)
        #expect(Set(inspection.architectures.records.map(\.cpuType)) == [0x0100_000C, 0x0100_0007])
        #expect(inspection.loadCommands.state == .complete)
        #expect(inspection.linkedFrameworks.state == .complete)
        #expect(inspection.apiReferences.state == .partial)
        #expect(!inspection.apiReferences.limits.isEmpty)
        #expect(inspection.apiReferences.limitations.contains { $0.contains("chained-fixup") && $0.contains("Objective-C") })
        for slice in legacySlices {
            let commands = inspection.loadCommands.records.filter { $0.location.sliceOffset == slice.fileOffset }
            #expect(commands.contains { $0.name == "LC_SYMTAB" })
            #expect(commands.contains { $0.name == "LC_RPATH" && $0.runtimeSearchPath == "@loader_path/Frameworks" })
            #expect(commands.allSatisfy { $0.location.architecture == slice.architecture })
            let coreFoundation = try #require(inspection.linkedFrameworks.records.first {
                $0.location.sliceOffset == slice.fileOffset && $0.frameworkName == "CoreFoundation"
            })
            #expect(coreFoundation.kind == .load)
            #expect(coreFoundation.installName.contains("CoreFoundation.framework/"))
            let imports = inspection.apiReferences.records.filter { $0.location.sliceOffset == slice.fileOffset }
            #expect(imports.allSatisfy { $0.kind == .importedSymbol && $0.location.architecture == slice.architecture })
            if slice.architecture == "arm64" {
                #expect(imports.contains { $0.name == "_CFAbsoluteTimeGetCurrent" })
                #expect(!imports.contains { $0.name == "_CFStringCreateWithCString" })
            } else if slice.architecture == "x86_64" {
                #expect(imports.contains { $0.name == "_CFStringCreateWithCString" })
                #expect(imports.contains { $0.name == "_CFRelease" })
                #expect(!imports.contains { $0.name == "_CFAbsoluteTimeGetCurrent" })
            }
        }
        let bytes = try Data(contentsOf: url)
        for reference in inspection.apiReferences.records {
            let fileOffset = try #require(reference.location.fileOffset)
            let byteCount = try #require(reference.location.byteCount)
            let offset = try #require(Int(exactly: fileOffset))
            let count = try #require(Int(exactly: byteCount))
            #expect(offset >= 0 && count > 1 && offset <= bytes.count && count <= bytes.count - offset)
            #expect(bytes[offset + count - 1] == 0)
            #expect(String(data: bytes[offset..<(offset + count - 1)], encoding: .utf8) == reference.name)
        }
        #expect(try MachOInspector.inspectStaticFeatures(url) == inspection)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(inspection)
        #expect(try JSONDecoder().decode(MachOStaticInspection.self, from: encoded) == inspection)
    }

    @Test
    func preservesOtherFeaturesWhenOptionalCommandsAndSymbolTablesAreMalformed() throws {
        let root = try staticMachOFixtureRoot()
        defer { removeStaticMachOFixture(root) }
        let originalURL = try makeStaticMachOFixture(root)
        let original = try Data(contentsOf: originalURL)
        let slices = try MachOInspector.inspect(originalURL)
        let affected = try #require(slices.first)
        let other = try #require(slices.last)
        let dependency = try staticFixtureCommand(original, slice: affected, command: 0x0C)
        let symtab = try staticFixtureCommand(original, slice: affected, command: 0x02)
        let dependencySize = try staticFixtureUInt32(original, offset: dependency + 4)

        let badDependencyURL = root.appendingPathComponent("bad-dependency.universal")
        try staticFixtureReplacingUInt32(original, offset: dependency + 8, value: dependencySize).write(to: badDependencyURL)
        let badDependency = try MachOInspector.inspectStaticFeatures(badDependencyURL)
        #expect(badDependency.architectures.state == .complete)
        #expect(badDependency.loadCommands.state == .partial)
        #expect(badDependency.linkedFrameworks.state == .partial)
        #expect(badDependency.loadCommands.records.contains { $0.location.sliceOffset == affected.fileOffset && $0.decodingIssue != nil })
        #expect(badDependency.linkedFrameworks.records.contains { $0.location.sliceOffset == other.fileOffset })
        #expect(badDependency.apiReferences.records.contains { $0.location.sliceOffset == affected.fileOffset })

        let rpath = try staticFixtureCommand(original, slice: affected, command: 0x8000_001C)
        let rpathSize = try staticFixtureUInt32(original, offset: rpath + 4)
        let rpathStart = try staticFixtureUInt32(original, offset: rpath + 8)
        var unterminatedPath = original
        for offset in (rpath + Int(rpathStart))..<(rpath + Int(rpathSize)) { unterminatedPath[offset] = 0x41 }
        let badRpathURL = root.appendingPathComponent("unterminated-rpath.universal")
        try unterminatedPath.write(to: badRpathURL)
        let badRpath = try MachOInspector.inspectStaticFeatures(badRpathURL)
        #expect(badRpath.loadCommands.state == .partial)
        #expect(badRpath.loadCommands.reason?.contains("NUL terminator") == true)
        #expect(badRpath.linkedFrameworks.state == .complete)

        let nameOffset = try staticFixtureUInt32(original, offset: dependency + 8)
        var invalidUTF8 = original
        invalidUTF8[dependency + Int(nameOffset)] = 0xFF
        let badUTF8URL = root.appendingPathComponent("invalid-utf8-name.universal")
        try invalidUTF8.write(to: badUTF8URL)
        let badUTF8 = try MachOInspector.inspectStaticFeatures(badUTF8URL)
        #expect(badUTF8.loadCommands.state == .partial)
        #expect(badUTF8.loadCommands.reason?.contains("not valid UTF-8") == true)
        #expect(badUTF8.linkedFrameworks.state == .partial)
        #expect(badUTF8.linkedFrameworks.records.contains { $0.location.sliceOffset == other.fileOffset })

        let badSymbolsURL = root.appendingPathComponent("cross-slice-symbols.universal")
        let crossedOffset = try #require(UInt32(exactly: affected.fileSize - 8))
        try staticFixtureReplacingUInt32(original, offset: symtab + 8, value: crossedOffset).write(to: badSymbolsURL)
        let badSymbols = try MachOInspector.inspectStaticFeatures(badSymbolsURL)
        #expect(badSymbols.architectures.state == .complete)
        #expect(badSymbols.loadCommands.state == .complete)
        #expect(badSymbols.linkedFrameworks.state == .complete)
        #expect(badSymbols.apiReferences.state == .partial)
        #expect(badSymbols.apiReferences.reason?.contains("outside") == true)
        #expect(!badSymbols.apiReferences.records.contains {
            $0.location.sliceOffset == affected.fileOffset && $0.location.method == .symbolTable
        })
        #expect(badSymbols.apiReferences.records.contains {
            $0.location.sliceOffset == affected.fileOffset && $0.location.method != .symbolTable
        })
        #expect(badSymbols.apiReferences.records.contains { $0.location.sliceOffset == other.fileOffset })

        let symbolOffset = try staticFixtureUInt32(original, offset: symtab + 8)
        let symbolCount = try staticFixtureUInt32(original, offset: symtab + 12)
        let stringSize = try staticFixtureUInt32(original, offset: symtab + 20)
        let importedEntry = try staticFixtureImportedEntry(original, slice: affected, offset: symbolOffset, count: symbolCount)
        let badNameURL = root.appendingPathComponent("bad-symbol-name.universal")
        try staticFixtureReplacingUInt32(original, offset: importedEntry, value: stringSize).write(to: badNameURL)
        let badName = try MachOInspector.inspectStaticFeatures(badNameURL)
        #expect(badName.architectures.state == .complete)
        #expect(badName.apiReferences.state == .partial)
        #expect(badName.apiReferences.limitations.contains { $0.contains("String index") && $0.contains("outside") })
        #expect(badName.apiReferences.records.contains { $0.location.sliceOffset == affected.fileOffset })
        #expect(badName.apiReferences.records.contains { $0.location.sliceOffset == other.fileOffset })

        let malformedURL = root.appendingPathComponent("malformed-command.universal")
        try staticFixtureReplacingUInt32(original, offset: dependency + 4, value: 0).write(to: malformedURL)
        #expect(throws: MachOInspectionError.self) { _ = try MachOInspector.inspectStaticFeatures(malformedURL) }
    }

    @Test
    func retainsUnknownCommandsAndRecoversImportsWithoutSymbolTable() throws {
        let root = try staticMachOFixtureRoot()
        defer { removeStaticMachOFixture(root) }
        let originalURL = try makeStaticMachOFixture(root)
        let original = try Data(contentsOf: originalURL)
        let slice = try #require(MachOInspector.inspect(originalURL).first)
        let uuidOffset = try staticFixtureCommand(original, slice: slice, command: 0x1B)
        let unknownCommand: UInt32 = 0x7FFF_FE01
        let unknownURL = root.appendingPathComponent("unknown-command.universal")
        try staticFixtureReplacingUInt32(original, offset: uuidOffset, value: unknownCommand).write(to: unknownURL)
        let unknown = try MachOInspector.inspectStaticFeatures(unknownURL)
        let retained = try #require(unknown.loadCommands.records.first { $0.commandID == unknownCommand })
        #expect(retained.name == nil)
        #expect(retained.location.fileOffset == UInt64(uuidOffset))
        #expect(retained.commandSize == 24)
        #expect(unknown.architectures.records.first { $0.slice.fileOffset == slice.fileOffset }?.slice.uuid == nil)

        let thinURL = root.appendingPathComponent("fixture.arm64")
        let thin = try Data(contentsOf: thinURL)
        let thinSlice = try #require(MachOInspector.inspect(thinURL).first)
        let symtabOffset = try staticFixtureCommand(thin, slice: thinSlice, command: 0x02)
        let noSymbolURL = root.appendingPathComponent("no-symbol-command.arm64")
        try staticFixtureReplacingUInt32(thin, offset: symtabOffset, value: unknownCommand).write(to: noSymbolURL)
        let noSymbols = try MachOInspector.inspectStaticFeatures(noSymbolURL)
        #expect(noSymbols.apiReferences.state == .partial)
        #expect(noSymbols.apiReferences.records.allSatisfy { $0.location.method != .symbolTable })
        #expect(noSymbols.apiReferences.records.contains { $0.name == "_CFAbsoluteTimeGetCurrent" })
        #expect(noSymbols.apiReferences.reason?.contains("no LC_SYMTAB") == true)
        #expect(noSymbols.linkedFrameworks.state == .complete)

        let strippedURL = root.appendingPathComponent("stripped.arm64")
        try FileManager.default.copyItem(at: thinURL, to: strippedURL)
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/strip"), arguments: ["-x", strippedURL.path])
        let stripped = try MachOInspector.inspectStaticFeatures(strippedURL)
        #expect(stripped.apiReferences.state == .partial)
        #expect(stripped.apiReferences.limitations.contains { $0.contains("Stripping") })

        let nonMachOURL = root.appendingPathComponent("ordinary-data")
        try Data("ordinary data, no executable header\n".utf8).write(to: nonMachOURL)
        let nonMachO = try MachOInspector.inspectStaticFeatures(nonMachOURL)
        #expect(nonMachO.architectures.state == .notApplicable)
        #expect(nonMachO.loadCommands.state == .notApplicable)
        #expect(nonMachO.linkedFrameworks.state == .notApplicable)
        #expect(nonMachO.apiReferences.state == .notApplicable)
    }

    @Test @MainActor
    func cancelsBeforeReadingFeatureData() async throws {
        let root = try staticMachOFixtureRoot()
        defer { removeStaticMachOFixture(root) }
        let url = root.appendingPathComponent("ordinary-data")
        try Data("ordinary data\n".utf8).write(to: url)
        let task = Task { try MachOInspector.inspectStaticFeatures(url) }
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Mach-O feature inspection completed after task cancellation.")
        } catch is CancellationError { }
    }

    @Test
    func reportsSymbolCollectionLimitsBeforeReadingOversizedTables() throws {
        let root = try staticMachOFixtureRoot()
        defer { removeStaticMachOFixture(root) }
        _ = try makeStaticMachOFixture(root)
        let originalURL = root.appendingPathComponent("fixture.arm64")
        let original = try Data(contentsOf: originalURL)
        let slice = try #require(MachOInspector.inspect(originalURL).first)
        let command = try staticFixtureCommand(original, slice: slice, command: 0x02)
        let symbolOffset = try #require(UInt32(exactly: original.count + 16))
        let symbolCount: UInt32 = 250_001
        let stringOffset = symbolOffset + symbolCount * 16
        let fields: [(offset: Int, value: UInt32)] = [
            (command + 8, symbolOffset), (command + 12, symbolCount),
            (command + 16, stringOffset), (command + 20, 1)
        ]
        let altered = try fields.reduce(original) { data, field in
            try staticFixtureReplacingUInt32(data, offset: field.offset, value: field.value)
        }
        let oversizedURL = root.appendingPathComponent("oversized-symbol-table.arm64")
        try altered.write(to: oversizedURL)
        let handle = try FileHandle(forWritingTo: oversizedURL)
        try handle.truncate(atOffset: UInt64(stringOffset) + 1)
        try handle.close()
        let inspection = try MachOInspector.inspectStaticFeatures(oversizedURL)
        #expect(inspection.architectures.state == .complete)
        #expect(inspection.loadCommands.state == .complete)
        #expect(inspection.apiReferences.state == .partial)
        #expect(!inspection.apiReferences.records.contains { $0.location.method == .symbolTable })
        #expect(inspection.apiReferences.records.contains { $0.name == "_CFAbsoluteTimeGetCurrent" })
        #expect(inspection.apiReferences.reason?.contains("250001 symbol records") == true)
        #expect(inspection.apiReferences.limits.contains { $0.name == "symbol_records_per_slice" && $0.value == 250_000 })
    }
}

private enum MachOStaticFixtureError: LocalizedError {
    case invalidRange(Int, Int)
    case missingCommand(UInt32)
    case missingImportedSymbol

    var errorDescription: String? {
        switch self {
        case let .invalidRange(offset, count): "Static Mach-O fixture field at \(offset) is outside its \(count)-byte file."
        case let .missingCommand(command): "Static Mach-O fixture has no command 0x\(String(command, radix: 16))."
        case .missingImportedSymbol: "Static Mach-O fixture has no external undefined symbol."
        }
    }
}

private func staticMachOFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-static-MachO-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeStaticMachOFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Static Mach-O fixture cleanup failed: \(error.localizedDescription)") }
}

private func makeStaticMachOFixture(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("fixture.c")
    let sourceText = """
    #include <CoreFoundation/CoreFoundation.h>
    int main(void) {
    #if defined(__arm64__)
        return CFAbsoluteTimeGetCurrent() < 0;
    #else
        CFStringRef value = CFStringCreateWithCString(NULL, "static evidence", kCFStringEncodingUTF8);
        CFRelease(value);
        return 0;
    #endif
    }
    """
    try Data(sourceText.utf8).write(to: source)
    let arm64 = root.appendingPathComponent("fixture.arm64")
    let x86 = root.appendingPathComponent("fixture.x86_64")
    let universal = root.appendingPathComponent("fixture.universal")
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    for architecture in ["arm64", "x86_64"] {
        let output = architecture == "arm64" ? arm64 : x86
        _ = try runFixtureTool(executable: xcrun, arguments: [
            "clang", "-target", "\(architecture)-apple-macos14.0", source.path,
            "-framework", "CoreFoundation", "-Wl,-rpath,@loader_path/Frameworks", "-o", output.path
        ])
    }
    _ = try runFixtureTool(executable: xcrun, arguments: ["lipo", "-create", arm64.path, x86.path, "-output", universal.path])
    return universal
}

private func staticFixtureUInt32(_ data: Data, offset: Int) throws -> UInt32 {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw MachOStaticFixtureError.invalidRange(offset, data.count)
    }
    return data[offset..<(offset + 4)].enumerated().reduce(0) { value, byte in
        value | UInt32(byte.element) << UInt32(byte.offset * 8)
    }
}

private func staticFixtureReplacingUInt32(_ data: Data, offset: Int, value: UInt32) throws -> Data {
    _ = try staticFixtureUInt32(data, offset: offset)
    var result = data
    for index in 0..<4 { result[offset + index] = UInt8(truncatingIfNeeded: value >> UInt32(index * 8)) }
    return result
}

private func staticFixtureCommand(_ data: Data, slice: MachOSlice, command: UInt32) throws -> Int {
    let sliceStart = try #require(Int(exactly: slice.fileOffset))
    let count = try staticFixtureUInt32(data, offset: sliceStart + 16)
    var offset = sliceStart + 32
    for _ in 0..<count {
        let value = try staticFixtureUInt32(data, offset: offset)
        let size = try staticFixtureUInt32(data, offset: offset + 4)
        if value == command { return offset }
        offset += Int(size)
    }
    throw MachOStaticFixtureError.missingCommand(command)
}

private func staticFixtureImportedEntry(_ data: Data, slice: MachOSlice, offset: UInt32, count: UInt32) throws -> Int {
    let start = try #require(Int(exactly: slice.fileOffset + UInt64(offset)))
    for index in 0..<count {
        let entry = start + Int(index) * 16
        guard entry >= 0, entry <= data.count, 16 <= data.count - entry else {
            throw MachOStaticFixtureError.invalidRange(entry, data.count)
        }
        let type = data[entry + 4]
        if type & 0xE0 == 0, type & 0x0E == 0, type & 0x01 != 0,
            data[(entry + 8)..<(entry + 16)].allSatisfy({ $0 == 0 }) { return entry }
    }
    throw MachOStaticFixtureError.missingImportedSymbol
}
