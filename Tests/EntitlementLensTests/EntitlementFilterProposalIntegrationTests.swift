import Foundation
import Testing
@testable import EntitlementLens

@MainActor
struct EntitlementFilterProposalIntegrationTests {
    @Test
    func constructedProposalsApplyEquivalentQueriesToRealSignedDeclarations() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-filter-proposals-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { removeFilterProposalFixture(root) }
        let executable = try makeSignedUniversalFixture(root: root,
            arm64Entitlements: filterProposalArm64Plist(), x86Entitlements: filterProposalX86Plist())
        let store = ScanStore()
        store.browserMode = .entitlements
        store.startScan(roots: [executable])
        try await waitForFilterProposalExplorer(store)
        #expect(store.lastError == nil)
        #expect(store.findings.count == 1)
        let findings = store.findings
        let issues = store.issues
        let json = try ResultExporter.data(for: findings, format: .json)
        let csv = try ResultExporter.data(for: findings, format: .csv)
        let declarations = try entitlementDeclarations(findings)
        let examples: [FilterProposalFixtureQuery] = [
            FilterProposalFixtureQuery(
                request: "Show entitlementlens.fixture.shared with Boolean false.",
                proposal: EntitlementFilterProposal(keyPattern: "entitlementlens.fixture.shared", keyMode: .exact,
                    valueMode: .booleanFalse, valueText: ""), predicate: .boolean(false)),
            FilterProposalFixtureQuery(
                request: "Show entitlementlens.fixture.shared with string value \"false\".",
                proposal: EntitlementFilterProposal(keyPattern: "entitlementlens.fixture.shared", keyMode: .exact,
                    valueMode: .stringEquals, valueText: "false"), predicate: .stringEquals("false")),
            FilterProposalFixtureQuery(
                request: "Show entitlementlens.fixture.number with integer value 7.",
                proposal: EntitlementFilterProposal(keyPattern: "entitlementlens.fixture.number", keyMode: .exact,
                    valueMode: .integerEquals, valueText: "7"), predicate: .integerEquals(7)),
            FilterProposalFixtureQuery(
                request: "Show entitlementlens.fixture.spaces with string value \" false \".",
                proposal: EntitlementFilterProposal(keyPattern: "entitlementlens.fixture.spaces", keyMode: .exact,
                    valueMode: .stringEquals, valueText: " false "), predicate: .stringEquals(" false ")),
            FilterProposalFixtureQuery(
                request: "Show entitlementlens.fixture.empty with string value \"\".",
                proposal: EntitlementFilterProposal(keyPattern: "entitlementlens.fixture.empty", keyMode: .exact,
                    valueMode: .stringEquals, valueText: ""), predicate: .stringEquals("")),
            FilterProposalFixtureQuery(
                request: "Show keys matching entitlementlens.fixture.* with any value.",
                proposal: EntitlementFilterProposal(keyPattern: "entitlementlens.fixture.*", keyMode: .glob,
                    valueMode: .any, valueText: ""), predicate: .any)
        ]
        for example in examples {
            store.filterRequestText = example.request
            let activeControls = store.currentFilterControls
            let selectedFindingID = store.selectedFindingID
            // These responses are constructed adapter inputs, not observed model inference.
            let ownership = try store.beginFilterProposalRequest()
            #expect(try store.completeFilterProposalRequest(ownership, translation: .proposal(example.proposal)))
            #expect(store.filterProposalState == .preview(example.proposal))
            #expect(store.currentFilterControls == activeControls)
            #expect(store.selectedFindingID == selectedFindingID)
            #expect(store.findings == findings)
            #expect(store.issues == issues)
            try store.applyFilterProposal(example.proposal)
            try await waitForFilterProposalExplorer(store)
            let expected = try entitlementKeyGroups(declarations, query: EntitlementExplorerQuery(
                keyPattern: example.proposal.keyPattern, keyMode: example.proposal.keyMode,
                valuePredicate: example.predicate))
            #expect(!expected.isEmpty)
            #expect(expected.flatMap(\.declarations).allSatisfy { $0.status == .valid })
            #expect(store.explorerGroups.map(\.key) == expected.map(\.key))
            #expect(store.explorerGroups.flatMap { $0.declarations.map(\.id) } == expected.flatMap { $0.declarations.map(\.id) })
            #expect(store.explorerGroups.flatMap { $0.declarations.map(\.collectionWarnings) } ==
                expected.flatMap { $0.declarations.map(\.collectionWarnings) })
            #expect(store.explorerGroups.flatMap { $0.declarations.map(\.source) } == expected.flatMap { $0.declarations.map(\.source) })
            #expect(store.findings == findings)
            #expect(store.issues == issues)
            #expect(try ResultExporter.data(for: store.findings, format: .json) == json)
            #expect(try ResultExporter.data(for: store.findings, format: .csv) == csv)
            if example.proposal.valueMode == .booleanFalse {
                #expect(filterProposalArchitectures(store.selectedEntitlementDeclarations) == ["arm64"])
            } else if example.proposal.valueMode == .stringEquals, example.proposal.valueText == "false" {
                #expect(filterProposalArchitectures(store.selectedEntitlementDeclarations) == ["x86_64"])
            }
        }
        #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == findings)
        try verifyFilterProposalCSVPayload(csv, findings: findings)
        let samples = URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
            .appendingPathComponent(".build/static-feature-validation", isDirectory: true)
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        try json.write(to: samples.appendingPathComponent("natural-language-filters.json"), options: .atomic)
        try csv.write(to: samples.appendingPathComponent("natural-language-filters.csv"), options: .atomic)
    }

    @Test
    func constructedLateResponsesCannotClaimNewRequestsEditsNavigationOrScans() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-filter-ownership-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { removeFilterProposalFixture(root) }
        let executable = try makeSignedUniversalFixture(root: root,
            arm64Entitlements: filterProposalArm64Plist(), x86Entitlements: filterProposalX86Plist())
        let store = ScanStore()
        store.browserMode = .entitlements
        store.startScan(roots: [executable])
        try await waitForFilterProposalExplorer(store)
        let findings = store.findings
        let json = try ResultExporter.data(for: findings, format: .json)
        let csv = try ResultExporter.data(for: findings, format: .csv)
        store.filterRequestText = "Show entitlementlens.fixture.shared with Boolean false."
        let proposal = EntitlementFilterProposal(keyPattern: "entitlementlens.fixture.shared", keyMode: .exact,
            valueMode: .booleanFalse, valueText: "")
        let first = try store.beginFilterProposalRequest()
        let second = try store.beginFilterProposalRequest()
        #expect(first.id != second.id)
        #expect(try !store.completeFilterProposalRequest(first, translation: .proposal(proposal)))
        #expect(!store.failFilterProposalRequest(first, failure: .generationFailed))
        #expect(store.filterProposalState == .generating)
        #expect(try store.completeFilterProposalRequest(second, translation: .proposal(proposal)))
        #expect(!store.failFilterProposalRequest(second, failure: .timedOut))
        #expect(store.filterProposalState == .preview(proposal))

        for edit in FilterProposalManualEdit.allCases {
            let pending = try store.beginFilterProposalRequest()
            switch edit {
            case .key: store.explorerKeyPattern = "entitlementlens.fixture.number"
            case .keyMode: store.explorerKeyMode = .glob
            case .valueMode: store.explorerValueMode = .stringEquals
            case .valueText: store.explorerValueText = "false"
            }
            #expect(store.filterProposalState == .idle)
            #expect(try !store.completeFilterProposalRequest(pending, translation: .proposal(proposal)))
        }
        let beforeTextEdit = try store.beginFilterProposalRequest()
        store.filterRequestText = "Show entitlementlens.fixture.number with integer value 7."
        #expect(try !store.completeFilterProposalRequest(beforeTextEdit, translation: .proposal(proposal)))
        store.filterRequestText = "Show entitlementlens.fixture.shared with Boolean false."
        let beforeNavigation = try store.beginFilterProposalRequest()
        store.browserMode = .files
        #expect(try !store.completeFilterProposalRequest(beforeNavigation, translation: .proposal(proposal)))
        store.browserMode = .entitlements
        try await waitForFilterProposalExplorer(store)

        let beforeCancellation = try store.beginFilterProposalRequest()
        store.cancelFilterProposal()
        #expect(store.filterProposalState == .cancelled)
        #expect(try !store.completeFilterProposalRequest(beforeCancellation, translation: .proposal(proposal)))
        let beforeDiscard = try store.beginFilterProposalRequest()
        #expect(try store.completeFilterProposalRequest(beforeDiscard, translation: .proposal(proposal)))
        store.discardFilterProposal()
        #expect(store.filterProposalState == .idle)
        #expect(try !store.completeFilterProposalRequest(beforeDiscard, translation: .proposal(proposal)))

        let timeoutOwnership = try store.beginFilterProposalRequest()
        // Constructed deadline delivery verifies the production handler, not real inference latency.
        #expect(store.failFilterProposalRequest(timeoutOwnership, failure: .timedOut))
        #expect(store.filterProposalState == .failed(.timedOut))
        #expect(try !store.completeFilterProposalRequest(timeoutOwnership, translation: .proposal(proposal)))
        #expect(store.findings == findings)
        #expect(try ResultExporter.data(for: store.findings, format: .json) == json)
        #expect(try ResultExporter.data(for: store.findings, format: .csv) == csv)

        let beforeRefresh = try store.beginFilterProposalRequest()
        store.refreshEntitlementExplorer()
        try await waitForFilterProposalExplorer(store)
        #expect(store.filterProposalState == .generating)
        #expect(try store.completeFilterProposalRequest(beforeRefresh, translation: .proposal(proposal)))
        let beforeScan = try store.beginFilterProposalRequest()
        store.startScan(roots: [executable])
        #expect(try !store.completeFilterProposalRequest(beforeScan, translation: .proposal(proposal)))
        #expect(store.filterProposalState == .idle)
        let duringReplacementScan = try store.beginFilterProposalRequest()
        #expect(store.isScanning)
        try await waitForFilterProposalExplorer(store)
        // Actual scan batches and completion refresh the matcher without retiring this request.
        #expect(store.filterProposalState == .generating)
        #expect(store.filterProposalOwnership == duringReplacementScan)
        #expect(try store.completeFilterProposalRequest(duringReplacementScan, translation: .proposal(proposal)))
        #expect(store.filterProposalState == .preview(proposal))
        #expect(store.findings.count == findings.count)
        store.discardFilterProposal()
    }

    @Test
    func identicalControlWritebacksRetainOwnershipAndByteDistinctUnicodeEditsRetireIt() async throws {
        let store = ScanStore()
        let composedKey = "entitlementlens.fixture.caf\u{00E9}"
        let decomposedKey = "entitlementlens.fixture.cafe\u{0301}"
        let composedValue = "caf\u{00E9}"
        let decomposedValue = "cafe\u{0301}"
        let request = "Show \"\(composedKey)\" with string value \"\(composedValue)\"."
        let changedRequest = "Show \"\(decomposedKey)\" with string value \"\(composedValue)\"."
        let proposal = EntitlementFilterProposal(keyPattern: composedKey, keyMode: .exact,
            valueMode: .stringEquals, valueText: composedValue)
        store.browserMode = .entitlements
        store.explorerKeyPattern = composedKey
        store.explorerValueMode = .stringEquals
        store.explorerValueText = composedValue
        store.filterRequestText = request
        let ownership = try store.beginFilterProposalRequest()

        // Native focus commits may write the same text and picker selections back to their bindings.
        writeBackIdenticalFilterProposalControls(store)
        try await waitForFilterProposalExplorer(store)
        #expect(store.filterProposalState == .generating)
        #expect(store.filterProposalOwnership == ownership)
        #expect(try store.completeFilterProposalRequest(ownership, translation: .proposal(proposal)))
        writeBackIdenticalFilterProposalControls(store)
        try await waitForFilterProposalExplorer(store)
        #expect(store.filterProposalState == .preview(proposal))
        #expect(store.filterProposalOwnership == ownership)
        try store.applyFilterProposal(proposal)
        try await waitForFilterProposalExplorer(store)
        #expect(store.currentFilterControls == proposal)
        #expect(store.filterProposalState == .idle)

        #expect(composedKey == decomposedKey)
        #expect(composedValue == decomposedValue)
        #expect(request == changedRequest)
        #expect(!composedKey.utf8.elementsEqual(decomposedKey.utf8))
        #expect(!composedValue.utf8.elementsEqual(decomposedValue.utf8))
        #expect(!request.utf8.elementsEqual(changedRequest.utf8))
        for field in FilterProposalUnicodeEdit.allCases {
            store.explorerKeyPattern = composedKey
            store.explorerValueText = composedValue
            store.filterRequestText = request
            let pending = try store.beginFilterProposalRequest()
            switch field {
            case .request: store.filterRequestText = changedRequest
            case .key: store.explorerKeyPattern = decomposedKey
            case .value: store.explorerValueText = decomposedValue
            }
            #expect(store.filterProposalState == .idle)
            #expect(store.filterProposalOwnership == nil)
            #expect(try !store.completeFilterProposalRequest(pending, translation: .proposal(proposal)))
        }
        try await waitForFilterProposalExplorer(store)
    }

    @Test
    func editedDraftFailuresRetainPreviewAndUnsupportedRequestsDoNotGenerate() async throws {
        let store = ScanStore()
        store.browserMode = .entitlements
        store.filterRequestText = "Show entitlementlens.fixture.number with integer value 7."
        let proposal = EntitlementFilterProposal(keyPattern: "entitlementlens.fixture.number", keyMode: .exact,
            valueMode: .integerEquals, valueText: "7")
        let ownership = try store.beginFilterProposalRequest()
        #expect(try store.completeFilterProposalRequest(ownership, translation: .proposal(proposal)))
        let controls = store.currentFilterControls
        let invalid = EntitlementFilterProposal(keyPattern: proposal.keyPattern, keyMode: proposal.keyMode,
            valueMode: .integerEquals, valueText: "9223372036854775808")
        do {
            try store.applyFilterProposal(invalid)
            Issue.record("An overflowing edited draft unexpectedly applied.")
        } catch {
            #expect(error.failure == .invalidProposal(.invalidInteger))
        }
        #expect(store.filterProposalState == .preview(proposal))
        #expect(store.currentFilterControls == controls)
        let userEdited = EntitlementFilterProposal(keyPattern: "com.apple.private.entitlementlens.literal", keyMode: .exact,
            valueMode: .stringEquals, valueText: " false ")
        try store.applyFilterProposal(userEdited)
        try await waitForFilterProposalExplorer(store)
        #expect(store.currentFilterControls == userEdited)
        #expect(store.filterProposalState == .idle)
        do {
            try store.applyFilterProposal(userEdited)
            Issue.record("A discarded ownership unexpectedly applied twice.")
        } catch {
            #expect(error.failure == .noOwnedProposal)
        }

        store.filterRequestText = "Show entitlementlens.fixture.number with integer value 7 and arm64 only."
        store.generateFilterProposal()
        #expect(store.filterProposalState == .failed(.invalidRequest(.unsupportedRequest)))
        #expect(store.filterGenerationTask == nil)
        #expect(store.currentFilterControls == userEdited)
        #expect(store.findings.isEmpty)

        store.filterRequestText = "Show entitlementlens.fixture.number with integer value 7."
        let ambiguous = try store.beginFilterProposalRequest()
        #expect(try store.completeFilterProposalRequest(ambiguous, translation: .ambiguous))
        #expect(store.filterProposalState == .ambiguous)
        #expect(store.currentFilterControls == userEdited)
        let unsupported = try store.beginFilterProposalRequest()
        #expect(try store.completeFilterProposalRequest(unsupported, translation: .unsupported))
        #expect(store.filterProposalState == .unsupported)
        #expect(store.currentFilterControls == userEdited)
    }
}

private struct FilterProposalFixtureQuery {
    let request: String
    let proposal: EntitlementFilterProposal
    let predicate: EntitlementValuePredicate
}

private enum FilterProposalManualEdit: CaseIterable {
    case key
    case keyMode
    case valueMode
    case valueText
}

private enum FilterProposalUnicodeEdit: CaseIterable {
    case request
    case key
    case value
}

@MainActor
private func writeBackIdenticalFilterProposalControls(_ store: ScanStore) {
    let controls = store.currentFilterControls
    let request = store.filterRequestText
    let browserMode = store.browserMode
    store.filterRequestText = request
    store.explorerKeyPattern = controls.keyPattern
    store.explorerKeyMode = controls.keyMode
    store.explorerValueMode = controls.valueMode
    store.explorerValueText = controls.valueText
    store.browserMode = browserMode
}

private func filterProposalArchitectures(_ declarations: [EntitlementDeclaration]) -> Set<String> {
    Set(declarations.compactMap {
        if case let .architecture(name) = $0.source { return name }
        return nil
    })
}

@MainActor
private func waitForFilterProposalExplorer(_ store: ScanStore) async throws {
    let deadline = ContinuousClock.now.advanced(by: .seconds(30))
    while store.isScanning || store.isFiltering || store.isExploring {
        guard ContinuousClock.now < deadline else { throw FilterProposalFixtureError.presentationTimeout }
        try await Task.sleep(for: .milliseconds(10))
    }
}

private func removeFilterProposalFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Filter proposal fixture cleanup failed: \(error.localizedDescription)") }
}

private func verifyFilterProposalCSVPayload(_ csv: Data, findings: [ScanFinding]) throws {
    let records = try csvFixtureRecords(String(decoding: csv, as: UTF8.self))
    let header = try #require(records.first)
    let versionColumn = try #require(header.firstIndex(of: "static_features_schema_version"))
    let payloadColumn = try #require(header.firstIndex(of: "static_features_json"))
    let rows = Array(records.dropFirst())
    try #require(rows.allSatisfy { $0.count == header.count })
    #expect(rows.allSatisfy { $0[versionColumn] == "3" })
    let payloads = try rows.filter { !$0[payloadColumn].isEmpty }.map {
        try JSONDecoder().decode(StaticFeatureSet.self, from: Data($0[payloadColumn].utf8))
    }
    #expect(payloads.count == findings.count)
    #expect(payloads == findings.compactMap(\.staticFeatures))
}

private func filterProposalArm64Plist() -> Data {
    Data("""
    <?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0"><dict>
    <key>entitlementlens.fixture.shared</key><false/>
    <key>entitlementlens.fixture.number</key><integer>7</integer>
    <key>entitlementlens.fixture.spaces</key><string> false </string>
    <key>entitlementlens.fixture.empty</key><string></string>
    </dict></plist>
    """.utf8)
}

private func filterProposalX86Plist() -> Data {
    Data("""
    <?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0"><dict>
    <key>entitlementlens.fixture.shared</key><string>false</string>
    <key>entitlementlens.fixture.number</key><string>7</string>
    <key>entitlementlens.fixture.spaces</key><string> false </string>
    <key>entitlementlens.fixture.empty</key><string></string>
    </dict></plist>
    """.utf8)
}

private enum FilterProposalFixtureError: LocalizedError {
    case presentationTimeout

    var errorDescription: String? {
        "The real signed fixture's proposal explorer did not settle within 30 seconds."
    }
}
