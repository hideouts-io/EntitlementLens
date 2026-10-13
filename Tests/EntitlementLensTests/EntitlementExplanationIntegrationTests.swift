import Foundation
import Testing
@testable import EntitlementLens

@MainActor
struct EntitlementExplanationIntegrationTests {
    @Test
    func curatedSelectionRetainsSignedArchitectureDeclarationsAndExportBytes() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-explanations-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Explanation fixture cleanup failed: \(error.localizedDescription)") }
        }
        let executable = try makeSignedUniversalFixture(root: root,
            arm64Entitlements: explanationArm64Plist(), x86Entitlements: explanationX86Plist())
        let store = ScanStore()
        store.browserMode = .entitlements
        store.startScan(roots: [executable])
        try await waitForExplanationExplorer(store)
        #expect(store.lastError == nil)
        #expect(store.explorerQueryError == nil)
        let finding = try #require(store.findings.first)
        #expect(store.findings.count == 1)
        let retainedFindings = store.findings
        let jsonBefore = try ResultExporter.data(for: retainedFindings, format: .json)
        let csvBefore = try ResultExporter.data(for: retainedFindings, format: .csv)
        let catalog = try EntitlementExplanationCatalog.bundled()

        store.selectedEntitlementKey = "com.apple.security.app-sandbox"
        let sandboxDeclarations = store.selectedEntitlementDeclarations
        #expect(!sandboxDeclarations.isEmpty)
        #expect(sandboxDeclarations.allSatisfy { $0.value == .boolean(true) && $0.status == .valid })
        #expect(Set(explanationArchitectures(sandboxDeclarations)) == ["arm64", "x86_64"])
        guard case let .available(sandbox) = catalog.lookup(key: "com.apple.security.app-sandbox") else {
            Issue.record("The bundled catalog did not resolve the exact sandbox key.")
            return
        }
        #expect(store.selectedEntitlementExplanation == .available(sandbox))
        #expect(sandboxDeclarations.allSatisfy {
            entitlementExplanationObservation(value: $0.value, explanation: sandbox) == .booleanDeclaration(true)
        })

        store.selectedEntitlementKey = "com.apple.security.get-task-allow"
        let taskDeclarations = store.selectedEntitlementDeclarations
        guard case let .available(taskAllow) = catalog.lookup(key: "com.apple.security.get-task-allow") else {
            Issue.record("The bundled catalog did not resolve the exact get-task-allow key.")
            return
        }
        #expect(store.selectedEntitlementExplanation == .available(taskAllow))
        let arm64TaskDeclaration = try #require(taskDeclarations.first { $0.source == .architecture("arm64") })
        let x86TaskDeclaration = try #require(taskDeclarations.first { $0.source == .architecture("x86_64") })
        #expect(arm64TaskDeclaration.value == .boolean(false))
        #expect(x86TaskDeclaration.value == .string("false"))
        #expect(arm64TaskDeclaration.status == .valid)
        #expect(x86TaskDeclaration.status == .valid)
        #expect(entitlementExplanationObservation(value: arm64TaskDeclaration.value, explanation: taskAllow) == .booleanDeclaration(false))
        // This string is intentionally outside the documented Boolean shape, but remains real signed declaration evidence.
        #expect(entitlementExplanationObservation(value: x86TaskDeclaration.value, explanation: taskAllow) ==
            .shapeMismatch(expected: .boolean, observedType: "String"))

        let unknownKey = "com.apple.private.entitlementlens-curated.unknown"
        store.selectedEntitlementKey = unknownKey
        #expect(!store.selectedEntitlementDeclarations.isEmpty)
        #expect(store.selectedEntitlementDeclarations.allSatisfy { $0.key == unknownKey && $0.value == .boolean(false) })
        #expect(catalog.lookup(key: unknownKey) == .unavailable(key: unknownKey))
        #expect(store.selectedEntitlementExplanation == .unavailable(key: unknownKey))
        let caseDifferentKey = "com.apple.security.App-sandbox"
        store.selectedEntitlementKey = caseDifferentKey
        #expect(!store.selectedEntitlementDeclarations.isEmpty)
        #expect(store.selectedEntitlementDeclarations.allSatisfy { $0.key == caseDifferentKey && $0.value == .string("case differs") })
        #expect(catalog.lookup(key: caseDifferentKey) == .unavailable(key: caseDifferentKey))
        #expect(store.selectedEntitlementExplanation == .unavailable(key: caseDifferentKey))
        store.selectedEntitlementKey = nil
        #expect(store.selectedEntitlementDeclarations.isEmpty)
        #expect(store.selectedEntitlementExplanation == nil)

        store.selectedEntitlementKey = "com.apple.security.app-sandbox"
        #expect(store.selectedEntitlementExplanation == .available(sandbox))
        store.browserMode = .files
        try await waitForExplanationExplorer(store)
        #expect(store.selectedEntitlementExplanation == nil)
        store.browserMode = .entitlements
        try await waitForExplanationExplorer(store)
        #expect(store.selectedEntitlementExplanation == .available(sandbox))

        store.explorerKeyPattern = "com.apple.security.entitlementlens-curated.absent"
        try await waitForExplanationExplorer(store)
        #expect(store.explorerGroups.isEmpty)
        #expect(store.selectedEntitlementKey == nil)
        #expect(store.selectedEntitlementDeclarations.isEmpty)
        #expect(store.selectedEntitlementExplanation == nil)
        store.explorerKeyPattern = "com.apple.security.get-task-allow"
        store.explorerValueMode = .booleanFalse
        try await waitForExplanationExplorer(store)
        #expect(explanationArchitectures(store.selectedEntitlementDeclarations) == ["arm64"])
        store.explorerValueMode = .stringEquals
        store.explorerValueText = "false"
        try await waitForExplanationExplorer(store)
        #expect(explanationArchitectures(store.selectedEntitlementDeclarations) == ["x86_64"])

        #expect(store.findings == retainedFindings)
        #expect(try ResultExporter.data(for: store.findings, format: .json) == jsonBefore)
        #expect(try ResultExporter.data(for: store.findings, format: .csv) == csvBefore)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: jsonBefore) == retainedFindings)
        try verifyExplanationCSVPayload(csvBefore, finding: finding)
        let samples = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            .appendingPathComponent(".build/static-feature-validation", isDirectory: true)
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        try jsonBefore.write(to: samples.appendingPathComponent("curated-explanations.json"), options: .atomic)
        try csvBefore.write(to: samples.appendingPathComponent("curated-explanations.csv"), options: .atomic)
    }

    @Test
    func catalogRejectsAmbiguousKeysAndUnreviewedSourceLocations() throws {
        let bundled = try EntitlementExplanationCatalog.bundled()
        let record = try #require(bundled.records.first)
        #expect(throws: EntitlementExplanationCatalogError.duplicateKey(record.key)) {
            try EntitlementExplanationCatalog(schemaVersion: bundled.schemaVersion, revision: bundled.revision,
                reviewedOn: bundled.reviewedOn, records: [record, record])
        }
        let unreviewedURL = try #require(URL(string: "https://example.com/entitlement"))
        let unreviewed = EntitlementExplanation(key: record.key, title: record.title, summary: record.summary,
            valueShape: record.valueShape, contextLimits: record.contextLimits,
            sources: [EntitlementExplanationSource(title: "Unreviewed source", url: unreviewedURL)])
        #expect(throws: EntitlementExplanationCatalogError.invalidSourceURL(key: record.key, url: unreviewedURL.absoluteString)) {
            try EntitlementExplanationCatalog(schemaVersion: bundled.schemaVersion, revision: bundled.revision,
                reviewedOn: bundled.reviewedOn, records: [unreviewed])
        }
        #expect(throws: EntitlementExplanationCatalogError.invalidSchemaVersion(0)) {
            try EntitlementExplanationCatalog(schemaVersion: 0, revision: bundled.revision,
                reviewedOn: bundled.reviewedOn, records: [record])
        }
    }
}

@MainActor
private func waitForExplanationExplorer(_ store: ScanStore) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(30))
    while store.isScanning || store.isFiltering || store.isExploring {
        guard ContinuousClock.now < deadline else { throw ExplanationFixtureError.presentationTimeout }
        try await Task.sleep(for: .milliseconds(10))
    }
}

private func explanationArchitectures(_ declarations: [EntitlementDeclaration]) -> [String] {
    declarations.compactMap {
        if case let .architecture(name) = $0.source { return name }
        return nil
    }.sorted()
}

private func verifyExplanationCSVPayload(_ csv: Data, finding: ScanFinding) throws {
    let features = try #require(finding.staticFeatures)
    #expect(features.schemaVersion.rawValue == 3)
    let records = try csvFixtureRecords(String(decoding: csv, as: UTF8.self))
    let header = try #require(records.first)
    let versionColumn = try #require(header.firstIndex(of: "static_features_schema_version"))
    let payloadColumn = try #require(header.firstIndex(of: "static_features_json"))
    let rows = Array(records.dropFirst())
    #expect(!rows.isEmpty)
    try #require(rows.allSatisfy { $0.count == header.count })
    #expect(rows.allSatisfy { $0[versionColumn] == "3" })
    let payloadRows = rows.filter { !$0[payloadColumn].isEmpty }
    #expect(payloadRows.count == 1)
    let payload = try #require(payloadRows.first?[payloadColumn])
    #expect(try JSONDecoder().decode(StaticFeatureSet.self, from: Data(payload.utf8)) == features)
}

private func explanationArm64Plist() -> Data {
    Data("""
    <?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0"><dict>
    <key>com.apple.security.app-sandbox</key><true/>
    <key>com.apple.security.get-task-allow</key><false/>
    <key>com.apple.private.entitlementlens-curated.unknown</key><false/>
    <key>com.apple.security.App-sandbox</key><string>case differs</string>
    </dict></plist>
    """.utf8)
}

private func explanationX86Plist() -> Data {
    Data("""
    <?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0"><dict>
    <key>com.apple.security.app-sandbox</key><true/>
    <key>com.apple.security.get-task-allow</key><string>false</string>
    <key>com.apple.private.entitlementlens-curated.unknown</key><false/>
    <key>com.apple.security.App-sandbox</key><string>case differs</string>
    </dict></plist>
    """.utf8)
}

private enum ExplanationFixtureError: LocalizedError {
    case presentationTimeout

    var errorDescription: String? {
        "The explanation explorer did not finish updating within 30 seconds."
    }
}
