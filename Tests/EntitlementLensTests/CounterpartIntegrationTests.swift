import Foundation
import Testing
@testable import EntitlementLens

struct CounterpartIntegrationTests {
    @Test
    func signedUniversalChangesAndExportsRetainArchitectureAndTypedValues() throws {
        let root = try counterpartFixtureRoot()
        defer { removeCounterpartFixture(root) }
        let sourceRoot = root.appendingPathComponent("source")
        let installedRoot = root.appendingPathComponent("installed")
        try FileManager.default.createDirectory(at: sourceRoot, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: installedRoot, withIntermediateDirectories: false)
        let empty = Data("<plist version=\"1.0\"><dict/></plist>".utf8)
        let sourceURL = try makeSignedUniversalFixture(root: sourceRoot,
            arm64Entitlements: empty, x86Entitlements: sourceComparisonPlist())
        let installedURL = try makeSignedUniversalFixture(root: installedRoot,
            arm64Entitlements: empty, x86Entitlements: installedComparisonPlist())
        let finding = try counterpartFinding(source: sourceURL, installed: installedURL)
        let counterpart = try #require(finding.installedCounterpart)
        let report = try #require(counterpart.entitlementComparison)
        #expect(counterpart.relationship == .different)
        #expect(report.isComplete)
        #expect(report.hasDifferences)
        let arm = try comparisonScope(report, architecture: "arm64")
        #expect(arm.source.availability == .collected)
        #expect(arm.installed.availability == .collected)
        #expect(arm.entries.isEmpty)
        let x86 = try comparisonScope(report, architecture: "x86_64")
        #expect(x86.source.signatureStatus == .valid)
        #expect(x86.installed.signatureStatus == .valid)
        let boolean = try comparisonEntry(x86, key: "fixture.boolean")
        #expect(boolean.sourceValue == .boolean(true))
        #expect(boolean.installedValue == .integer(1))
        #expect(boolean.result == .changed)
        let number = try comparisonEntry(x86, key: "fixture.number")
        #expect(number.sourceValue == .integer(7))
        #expect(number.installedValue == .string("7"))
        #expect(number.result == .changed)
        #expect(try comparisonEntry(x86, key: "fixture.added").result == .added)
        #expect(try comparisonEntry(x86, key: "fixture.removed").result == .removed)
        #expect(try comparisonEntry(x86, key: "fixture.dictionary").result == .unchanged)
        #expect(try comparisonEntry(x86, key: "fixture.array").result == .changed)
        #expect(try comparisonEntry(x86, key: "fixture.long").installedValue == .string(counterpartLongValue))
        #expect(counterpart.entitlementKeys.contains("fixture.added"))
        try verifyCounterpartExports(finding)

        // These are actual exported records with the additive fields removed to represent the older schema.
        let legacyData = try legacyCounterpartExport(finding)
        let legacy = try #require(JSONDecoder().decode([ScanFinding].self, from: legacyData).first)
        #expect(legacy.installedCounterpart?.entitlementComparison == nil)
        let legacySigning = try #require(legacy.signing)
        #expect(legacySigning.entitlementCollectionState == nil)
        #expect(legacySigning.architectureEntitlements.allSatisfy { $0.collectionState == nil })
        let incomplete = try compareEntitlements(sourceSigning: legacySigning, sourceSlices: finding.provenance.machOSlices,
            installedSigning: EntitlementExtractor.inspect(installedURL), installedSlices: MachOInspector.inspect(installedURL))
        #expect(!incomplete.isComplete)
        #expect(incomplete.scopes.flatMap(\.entries).allSatisfy { $0.result == .unavailable })
    }

    @Test
    func missingUnreadableAndTamperedSlicesRemainDistinctFromEmptyDeclarations() throws {
        let root = try counterpartFixtureRoot()
        defer { removeCounterpartFixture(root) }
        let universal = try makeSignedUniversalFixture(root: root,
            arm64Entitlements: sourceComparisonPlist(), x86Entitlements: sourceComparisonPlist())
        let thin = root.appendingPathComponent("fixture.x86_64")
        let missingFinding = try counterpartFinding(source: universal, installed: thin)
        let missing = try #require(missingFinding.installedCounterpart?.entitlementComparison)
        let arm = try comparisonScope(missing, architecture: "arm64")
        #expect(arm.installed.availability == .architectureMissing)
        #expect(arm.entries.allSatisfy { $0.result == .architectureMissing && $0.installedValue == nil })
        #expect(missing.hasDifferences)
        #expect(missing.isComplete)
        #expect(try comparisonScope(missing, architecture: "x86_64").entries.allSatisfy { $0.result == .unchanged })
        try verifyCounterpartExports(missingFinding)

        let unsigned = root.appendingPathComponent("unsigned.universal")
        try FileManager.default.copyItem(at: universal, to: unsigned)
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/codesign"),
            arguments: ["--remove-signature", unsigned.path])
        let unsignedFinding = try counterpartFinding(source: universal, installed: unsigned)
        let unsignedReport = try #require(unsignedFinding.installedCounterpart?.entitlementComparison)
        #expect(unsignedReport.isComplete)
        #expect(unsignedReport.scopes.allSatisfy { $0.installed.signatureStatus == .unsigned })
        #expect(unsignedReport.scopes.flatMap(\.entries).allSatisfy { $0.result == .removed })

        let unreadable = root.appendingPathComponent("unreadable.universal")
        var damagedSignature = try Data(contentsOf: universal)
        for slice in try MachOInspector.inspect(universal) {
            let offset = try #require(slice.codeSignatureOffset.flatMap(Int.init(exactly:)))
            damagedSignature[offset] = 0
        }
        try damagedSignature.write(to: unreadable)
        let unavailableFinding = try counterpartFinding(source: universal, installed: unreadable)
        let unavailable = try #require(unavailableFinding.installedCounterpart?.entitlementComparison)
        #expect(!unavailable.isComplete)
        #expect(!unavailable.hasDifferences)
        #expect(unavailable.scopes.allSatisfy { $0.installed.availability == .unavailable })
        #expect(unavailable.scopes.flatMap(\.entries).allSatisfy { $0.result == .unavailable })
        #expect(unavailable.scopes.allSatisfy { !$0.installed.warnings.isEmpty })
        try verifyCounterpartExports(unavailableFinding)

        let tampered = root.appendingPathComponent("tampered.universal")
        var bytes = try Data(contentsOf: universal)
        let armSlice = try #require(MachOInspector.inspect(universal).first { $0.architecture == "arm64" })
        bytes[try #require(Int(exactly: armSlice.fileOffset)) + 28] ^= 1
        try bytes.write(to: tampered)
        let tamperedFinding = try counterpartFinding(source: universal, installed: tampered)
        let tamperedReport = try #require(tamperedFinding.installedCounterpart?.entitlementComparison)
        let tamperedArm = try comparisonScope(tamperedReport, architecture: "arm64")
        guard case .invalid = tamperedArm.installed.signatureStatus else {
            throw CounterpartFixtureError.expectedInvalidSignature
        }
        #expect(tamperedArm.installed.availability == .collected)
        #expect(tamperedArm.entries.allSatisfy { $0.result == .unchanged && $0.installedValue != nil })
        #expect(tamperedReport.isComplete)
        #expect(!tamperedReport.hasDifferences)
        #expect(tamperedFinding.installedCounterpart?.relationship == .different)
        try verifyCounterpartExports(tamperedFinding)
    }

    @Test
    func propertyListNumbersAndNestedCollectionsPreserveTypeAndOrdering() throws {
        // codesign rejects real-valued entitlement plists on this host; exercise the real plist decoder for this type boundary.
        let data = Data("""
        <plist version="1.0"><array><integer>1</integer><real>1.0</real><true/><string>1</string></array></plist>
        """.utf8)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        #expect(try PropertyListValueDecoder.decode(plist) == .array([.integer(1), .real(1), .boolean(true), .string("1")]))
        #expect(EntitlementValue.integer(1) != EntitlementValue.real(1))
    }
}

private enum CounterpartFixtureError: Error {
    case expectedInvalidSignature
}

private let counterpartLongValue = String(repeating: "Long value, \"quoted\"\n", count: 220)

private func sourceComparisonPlist() -> Data {
    Data("""
    <plist version="1.0"><dict>
    <key>fixture.boolean</key><true/>
    <key>fixture.number</key><integer>7</integer>
    <key>fixture.removed</key><string>source only</string>
    <key>fixture.dictionary</key><dict><key>z</key><array><true/><string>nested</string></array><key>a</key><integer>1</integer></dict>
    <key>fixture.array</key><array><string>first</string><string>second</string></array>
    <key>fixture.long</key><string>short</string>
    </dict></plist>
    """.utf8)
}

private func installedComparisonPlist() -> Data {
    Data("""
    <plist version="1.0"><dict>
    <key>fixture.long</key><string>\(counterpartLongValue)</string>
    <key>fixture.array</key><array><string>second</string><string>first</string></array>
    <key>fixture.dictionary</key><dict><key>a</key><integer>1</integer><key>z</key><array><true/><string>nested</string></array></dict>
    <key>fixture.added</key><string>installed only</string>
    <key>fixture.number</key><string>7</string>
    <key>fixture.boolean</key><integer>1</integer>
    </dict></plist>
    """.utf8)
}

private func counterpartFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-counterpart-test-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeCounterpartFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Counterpart fixture cleanup failed: \(error.localizedDescription)") }
}

private func counterpartFinding(source: URL, installed: URL) throws -> ScanFinding {
    let sourceSigning = EntitlementExtractor.inspect(source)
    let installedSigning = EntitlementExtractor.inspect(installed)
    let sourceProvenance = try ArtifactProvenanceCollector.collectCode(sourceURL: source, analyzedURL: source)
    let installedProvenance = try ArtifactProvenanceCollector.collectCode(sourceURL: installed, analyzedURL: installed)
    let comparison = try InstalledCounterpartComparator.compareEvidence(sourceProvenance: sourceProvenance,
        sourceSigning: sourceSigning, counterpartPath: installed.path,
        counterpartProvenance: installedProvenance, counterpartSigning: installedSigning)
    return ScanFinding(id: UUID(), path: source.path, kind: .machO, fileFormat: "Mach-O",
        fileSize: sourceProvenance.fileSize, signing: sourceSigning, provenance: sourceProvenance,
        installedCounterpart: comparison, runningBoardPolicies: [], embeddedObjects: [], warnings: sourceSigning.extractionWarnings)
}

private func comparisonScope(_ comparison: EntitlementComparison, architecture: String) throws -> EntitlementScopeComparison {
    try #require(comparison.scopes.first { $0.scope == .architecture(architecture) })
}

private func comparisonEntry(_ scope: EntitlementScopeComparison, key: String) throws -> EntitlementDifference {
    try #require(scope.entries.first { $0.key == key })
}

private func verifyCounterpartExports(_ finding: ScanFinding) throws {
    let report = try #require(finding.installedCounterpart?.entitlementComparison)
    let json = try ResultExporter.data(for: [finding], format: .json)
    #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == [finding])
    let records = try csvFixtureRecords(String(decoding: ResultExporter.data(for: [finding], format: .csv), as: UTF8.self))
    let header = try #require(records.first)
    let summaryColumn = try #require(header.firstIndex(of: "counterpart_entitlement_summary"))
    let comparisonColumn = try #require(header.firstIndex(of: "counterpart_entitlement_comparison_json"))
    #expect(records.count > 1)
    for (index, record) in records.dropFirst().enumerated() {
        #expect(record.count == header.count)
        #expect(record[summaryColumn] == report.summary)
        if index == 0 {
            #expect(try JSONDecoder().decode(EntitlementComparison.self, from: Data(record[comparisonColumn].utf8)) == report)
        } else {
            #expect(record[comparisonColumn].isEmpty)
        }
    }
}

private func legacyCounterpartExport(_ finding: ScanFinding) throws -> Data {
    let data = try ResultExporter.data(for: [finding], format: .json)
    // JSONSerialization is used only at the old-schema boundary, after validating every required container.
    let records = try #require(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
    var record = try #require(records.first)
    var counterpart = try #require(record["installedCounterpart"] as? [String: Any])
    counterpart.removeValue(forKey: "entitlementComparison")
    record["installedCounterpart"] = counterpart
    var signing = try #require(record["signing"] as? [String: Any])
    signing.removeValue(forKey: "entitlementCollectionState")
    let architectures = try #require(signing["architectureEntitlements"] as? [[String: Any]])
    signing["architectureEntitlements"] = architectures.map { architecture in
        var legacy = architecture
        legacy.removeValue(forKey: "collectionState")
        return legacy
    }
    record["signing"] = signing
    return try JSONSerialization.data(withJSONObject: [record], options: [.sortedKeys])
}
