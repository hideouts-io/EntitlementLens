import Foundation
import Testing
@testable import EntitlementLens

private struct MalformedMachOFile {
    let name: String
    let data: Data
}

private enum MachORangeFixtureError: LocalizedError {
    case invalidRange(Int, Int, Int)
    case missingLoadCommand(UInt32)
    case missingEntitlementSlot

    var errorDescription: String? {
        switch self {
        case let .invalidRange(offset, length, available):
            "Fixture field at \(offset) requires \(length) bytes in a \(available)-byte file."
        case let .missingLoadCommand(command):
            "Signed fixture has no load command 0x\(String(command, radix: 16))."
        case .missingEntitlementSlot:
            "Signed fixture has no XML entitlement slot."
        }
    }
}

struct MachORangeIntegrationTests {
    @Test
    func rejectsMalformedMachOContainersThroughCollection() async throws {
        let root = try makeRangeFixtureRoot()
        defer { removeRangeFixture(root) }
        let originalURL = try makeRangeSignedFixture(root)
        let original = try Data(contentsOf: originalURL)
        #expect(Array(original.prefix(4)) == [0xCA, 0xFE, 0xBA, 0xBE])
        let slices = try MachOInspector.inspect(originalURL)
        let slice = try #require(slices.first)
        #expect(slices.count == 2)
        let headerOffset = try #require(Int(exactly: slice.fileOffset))
        let signatureCommand = try fixtureLoadCommandOffset(original, slice: slice, command: 0x1D)
        let uuidCommand = try fixtureLoadCommandOffset(original, slice: slice, command: 0x1B)
        let signatureOffset = try #require(slice.codeSignatureOffset)
        let signatureSize = try #require(slice.codeSignatureSize)
        let relativeSignatureOffset = try #require(UInt32(exactly: signatureOffset - slice.fileOffset))
        let signatureSize32 = try #require(UInt32(exactly: signatureSize))
        let sliceSize32 = try #require(UInt32(exactly: slice.fileSize))
        let pastEOF = try #require(UInt32(exactly: original.count + 32))

        let duplicateCommand = try fixtureReplacingLittleUInt32(original, offset: uuidCommand, value: 0x1D)
        let duplicateOffset = try fixtureReplacingLittleUInt32(
            duplicateCommand, offset: uuidCommand + 8, value: relativeSignatureOffset
        )
        let duplicate = try fixtureReplacingLittleUInt32(
            duplicateOffset, offset: uuidCommand + 12, value: signatureSize32
        )
        let rangeCases: [MalformedMachOFile] = [
            MalformedMachOFile(name: "slice-past-eof", data: try fixtureReplacingBigUInt32(original, offset: 36, value: pastEOF)),
            MalformedMachOFile(name: "slice-too-short", data: try fixtureReplacingBigUInt32(original, offset: 20, value: 8)),
            MalformedMachOFile(name: "commands-cross-slice", data: try fixtureReplacingLittleUInt32(original, offset: headerOffset + 20, value: sliceSize32)),
            MalformedMachOFile(name: "signature-crosses-slice", data: try fixtureReplacingLittleUInt32(original, offset: signatureCommand + 8, value: sliceSize32 - 4)),
            MalformedMachOFile(name: "fat64-offset-overflows", data: try overflowingFat64Fixture(original))
        ]
        let commandCases: [MalformedMachOFile] = [
            MalformedMachOFile(name: "signature-command-too-short", data: try fixtureReplacingLittleUInt32(original, offset: signatureCommand + 4, value: 8)),
            MalformedMachOFile(name: "duplicate-signature-command", data: duplicate)
        ]
        for fixture in rangeCases {
            let url = root.appendingPathComponent(fixture.name)
            try fixture.data.write(to: url)
            #expect(throws: MachOByteRangeError.self) { _ = try MachOInspector.inspect(url) }
            let collected = await collectRangeFixture(url)
            #expect(collected.completed)
            #expect(collected.findings.isEmpty)
            #expect(collected.issues.contains { $0.category == .analysis && !$0.privilegedRetryEligible && $0.path == url.path })
        }
        for fixture in commandCases {
            let url = root.appendingPathComponent(fixture.name)
            try fixture.data.write(to: url)
            #expect(throws: MachOInspectionError.self) { _ = try MachOInspector.inspect(url) }
            let collected = await collectRangeFixture(url)
            #expect(collected.completed)
            #expect(collected.findings.isEmpty)
            #expect(collected.issues.contains { $0.category == .analysis && !$0.privilegedRetryEligible && $0.path == url.path })
        }
    }

    @Test
    func rejectsOversizedAndCallerSuppliedSignatureRanges() throws {
        let root = try makeRangeFixtureRoot()
        defer { removeRangeFixture(root) }
        _ = try makeRangeSignedFixture(root)
        let thinURL = root.appendingPathComponent("fixture.arm64")
        let original = try Data(contentsOf: thinURL)
        let originalSlice = try #require(MachOInspector.inspect(thinURL).first)
        let commandOffset = try fixtureLoadCommandOffset(original, slice: originalSlice, command: 0x1D)
        let signatureOffset = try #require(originalSlice.codeSignatureOffset)
        let oversizedLength: UInt32 = 32 * 1_024 * 1_024 + 1
        let oversizedURL = root.appendingPathComponent("oversized-signature")
        try fixtureReplacingLittleUInt32(original, offset: commandOffset + 12, value: oversizedLength).write(to: oversizedURL)
        let handle = try FileHandle(forWritingTo: oversizedURL)
        try handle.truncate(atOffset: signatureOffset + UInt64(oversizedLength))
        try handle.close()
        let oversizedSlices = try MachOInspector.inspect(oversizedURL)
        let oversized = CodeSignatureParser.inspect(oversizedURL, slices: oversizedSlices, architectureEntitlements: [])
        #expect(oversized.slots.isEmpty)
        #expect(oversized.warnings.count == 1)
        #expect(oversized.warnings.first?.contains("33554433") == true)
        #expect(oversized.warnings.first?.contains("33554432") == true)

        let beyondEOF = MachOSlice(
            architecture: originalSlice.architecture, fileOffset: originalSlice.fileOffset,
            fileSize: originalSlice.fileSize, uuid: originalSlice.uuid, platform: originalSlice.platform,
            minimumOSVersion: originalSlice.minimumOSVersion, sdkVersion: originalSlice.sdkVersion,
            codeSignatureOffset: originalSlice.fileSize - 4, codeSignatureSize: 12
        )
        let supplied = CodeSignatureParser.inspect(thinURL, slices: [beyondEOF], architectureEntitlements: [])
        #expect(supplied.slots.isEmpty)
        #expect(supplied.warnings.count == 1)
        #expect(supplied.warnings.first?.contains("code-signature region") == true)
    }

    @Test
    func rejectsSuperBlobRangesWithoutDiscardingOtherSlices() async throws {
        let root = try makeRangeFixtureRoot()
        defer { removeRangeFixture(root) }
        let originalURL = try makeRangeSignedFixture(root)
        let original = try Data(contentsOf: originalURL)
        let slices = try MachOInspector.inspect(originalURL)
        let slice = try #require(slices.first)
        let signatureFileOffset = try #require(slice.codeSignatureOffset)
        let signatureOffset = try #require(Int(exactly: signatureFileOffset))
        let declaredLength = try fixtureBigUInt32(original, offset: signatureOffset + 4)
        let xmlIndex = try fixtureXMLSlotIndex(original, signatureOffset: signatureOffset)
        let blobOffset = try fixtureBigUInt32(original, offset: xmlIndex + 4)
        let blobHeader = signatureOffset + Int(blobOffset)
        let architectureEntitlements = EntitlementExtractor.inspect(originalURL).architectureEntitlements
        let unrelatedNullURL = root.appendingPathComponent("null-unrelated-slot")
        try fixtureReplacingBigUInt32(original, offset: signatureOffset + 16, value: 0).write(to: unrelatedNullURL)
        let unrelatedNull = CodeSignatureParser.inspect(
            unrelatedNullURL, slices: slices, architectureEntitlements: architectureEntitlements
        )
        #expect(unrelatedNull.warnings.isEmpty)
        #expect(unrelatedNull.slots.contains { $0.architecture == slice.architecture && $0.format == .xml })
        let cases: [MalformedMachOFile] = [
            MalformedMachOFile(name: "duplicate-xml-entitlement-slot", data: try fixtureReplacingBigUInt32(original, offset: signatureOffset + 12, value: 5)),
            MalformedMachOFile(name: "duplicate-der-entitlement-slot", data: try fixtureReplacingBigUInt32(original, offset: signatureOffset + 12, value: 7)),
            MalformedMachOFile(name: "null-entitlement-slot", data: try fixtureReplacingBigUInt32(original, offset: xmlIndex + 4, value: 0)),
            MalformedMachOFile(name: "slot-inside-index", data: try fixtureReplacingBigUInt32(original, offset: xmlIndex + 4, value: 4)),
            MalformedMachOFile(name: "entitlement-blob-crosses-superblob", data: try fixtureReplacingBigUInt32(original, offset: blobHeader + 4, value: declaredLength + 1)),
            MalformedMachOFile(name: "non-entitlement-slot-crosses-superblob", data: try fixtureReplacingBigUInt32(original, offset: signatureOffset + 16, value: declaredLength - 4))
        ]
        for fixture in cases {
            let url = root.appendingPathComponent(fixture.name)
            try fixture.data.write(to: url)
            let inspection = CodeSignatureParser.inspect(url, slices: slices, architectureEntitlements: architectureEntitlements)
            #expect(!inspection.slots.contains { $0.architecture == slice.architecture })
            #expect(inspection.slots.contains { $0.architecture != slice.architecture })
            #expect(inspection.warnings.count == 1)
            #expect(inspection.warnings.first?.contains(slice.architecture) == true)
            #expect(inspection.warnings.first?.contains(url.path) == true)
            let collected = await collectRangeFixture(url)
            let finding = try #require(collected.findings.first)
            #expect(collected.completed)
            #expect(findingOutcome(finding) == .incomplete)
        }
    }
}

private func makeRangeFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-ranges-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeRangeFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Mach-O range fixture cleanup failed: \(error.localizedDescription)") }
}

private func makeRangeSignedFixture(_ root: URL) throws -> URL {
    let entitlements = Data("<plist version=\"1.0\"><dict><key>entitlementlens.range-fixture</key><true/></dict></plist>".utf8)
    return try makeSignedUniversalFixture(root: root, arm64Entitlements: entitlements, x86Entitlements: entitlements)
}

private func collectRangeFixture(_ url: URL) async -> (findings: [ScanFinding], issues: [ScanIssue], completed: Bool) {
    let configuration = ScanConfiguration(
        roots: [url], includeHidden: true, deepCarve: false, maximumWorkerCount: 1,
        queueCapacity: 4, maximumCarveBytes: 1_048_576, excludedPathPrefixes: []
    )
    var findings: [ScanFinding] = []
    var issues: [ScanIssue] = []
    var completed = false
    for await update in ScanCoordinator.updates(configuration: configuration) {
        switch update {
        case let .batch(batch):
            findings.append(contentsOf: batch.findings)
            issues.append(contentsOf: batch.issues)
        case .completed: completed = true
        case .cancelled: Issue.record("Malformed-file collection was unexpectedly cancelled.")
        }
    }
    return (findings, issues, completed)
}

private func fixtureBigUInt32(_ data: Data, offset: Int) throws -> UInt32 {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw MachORangeFixtureError.invalidRange(offset, 4, data.count)
    }
    return data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
}

private func fixtureLittleUInt32(_ data: Data, offset: Int) throws -> UInt32 {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw MachORangeFixtureError.invalidRange(offset, 4, data.count)
    }
    return data[offset..<(offset + 4)].enumerated().reduce(0) { value, item in
        value | (UInt32(item.element) << UInt32(item.offset * 8))
    }
}

private func fixtureReplacingBigUInt32(_ data: Data, offset: Int, value: UInt32) throws -> Data {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw MachORangeFixtureError.invalidRange(offset, 4, data.count)
    }
    var result = data
    result.replaceSubrange(offset..<(offset + 4), with: (0..<4).map { UInt8(truncatingIfNeeded: value >> ((3 - $0) * 8)) })
    return result
}

private func fixtureReplacingLittleUInt32(_ data: Data, offset: Int, value: UInt32) throws -> Data {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw MachORangeFixtureError.invalidRange(offset, 4, data.count)
    }
    var result = data
    result.replaceSubrange(offset..<(offset + 4), with: (0..<4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) })
    return result
}

private func overflowingFat64Fixture(_ original: Data) throws -> Data {
    guard original.count >= 16 else {
        throw MachORangeFixtureError.invalidRange(8, 8, original.count)
    }
    var result = Data([0xCA, 0xFE, 0xBA, 0xBF, 0, 0, 0, 1])
    result.append(original[8..<16])
    let offset = UInt64.max - 16
    result.append(contentsOf: (0..<8).map { UInt8(truncatingIfNeeded: offset >> ((7 - $0) * 8)) })
    result.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 14, 0, 0, 0, 0])
    return result
}

private func fixtureLoadCommandOffset(_ data: Data, slice: MachOSlice, command: UInt32) throws -> Int {
    let base = try #require(Int(exactly: slice.fileOffset))
    #expect(Array(data[base..<(base + 4)]) == [0xCF, 0xFA, 0xED, 0xFE])
    let count = try fixtureLittleUInt32(data, offset: base + 16)
    var offset = base + 32
    for _ in 0..<count {
        let type = try fixtureLittleUInt32(data, offset: offset)
        if type == command { return offset }
        let size = try fixtureLittleUInt32(data, offset: offset + 4)
        offset += Int(size)
    }
    throw MachORangeFixtureError.missingLoadCommand(command)
}

private func fixtureXMLSlotIndex(_ data: Data, signatureOffset: Int) throws -> Int {
    let count = try fixtureBigUInt32(data, offset: signatureOffset + 8)
    for index in 0..<Int(count) {
        let offset = signatureOffset + 12 + index * 8
        if try fixtureBigUInt32(data, offset: offset) == 5 { return offset }
    }
    throw MachORangeFixtureError.missingEntitlementSlot
}
