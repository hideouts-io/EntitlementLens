import Foundation
import Testing
@testable import EntitlementLens

@MainActor
struct ArchitectureIntegrationTests {
    @Test
    func signedArchitectureDeclarationsRemainSearchableCountedAndExported() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-architectures-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Signed fixture cleanup failed: \(error.localizedDescription)") }
        }
        let universal = try makeSignedUniversalFixture(root: root,
            arm64Entitlements: architectureFixturePlist(.arm64), x86Entitlements: architectureFixturePlist(.x86_64))
        let store = ScanStore()
        store.startScan(roots: [universal])
        try await waitForArchitecturePresentation(store)
        #expect(store.lastError == nil)
        #expect(store.findings.count == 1)
        let finding = try #require(store.findings.first)
        let signing = try #require(finding.signing)
        #expect(signing.status == .valid)
        #expect(signing.extractionWarnings.isEmpty)
        #expect(Set(signing.architectureEntitlements.map(\.architecture)) == ["arm64", "x86_64"])
        let groups = entitlementSourceGroups(signing)
        #expect(groups.count == 3)
        #expect(distinctEntitlementKeys(groups).count == 5)
        #expect(finding.entitlementCount == 5)
        #expect(finding.privateEntitlementCount == 2)
        #expect(store.count(for: .entitlements) == 1)
        #expect(store.count(for: .privateEntitlements) == 1)
        let index = try [indexFinding(finding)]
        for query in ["com.apple.private.entitlementlens-fixture.arm64", "com.apple.private.entitlementlens-fixture.x86-only",
            "arm64 value", "x86_64 value"] {
            #expect(try matchingFindings(index, filter: .entitlements, query: query, includeEmpty: false).count == 1)
            store.searchText = query
            try await waitForArchitecturePresentation(store)
            #expect(store.filteredFindings.map(\.id) == [finding.id])
        }
        for architecture in signing.architectureEntitlements {
            #expect(architecture.status == .valid)
            #expect(architecture.entitlements.count == 4)
            let plist = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/codesign"),
                arguments: ["--display", "--arch", architecture.architecture, "--xml", "--entitlements", "-", universal.path])
            let dictionary = try PropertyListSerialization.propertyList(from: plist.standardOutput, options: [], format: nil)
            #expect(try PropertyListValueDecoder.decode(dictionary) == .dictionary(
                Dictionary(uniqueKeysWithValues: architecture.entitlements.map { ($0.key, $0.value) })))
        }
        let csv = try parseEntitlementCSV(ResultExporter.data(for: [finding], format: .csv))
        #expect(csv.count == 12)
        for architecture in signing.architectureEntitlements {
            let rows = csv.filter { $0.source == "architecture_dictionary" && $0.architecture == architecture.architecture }
            #expect(rows.count == 4)
            for entry in architecture.entitlements {
                let row = try #require(rows.first { $0.key == entry.key })
                #expect(row.signatureIntegrity == architecture.status.title)
                #expect(row.cdHash == architecture.uniqueCDHash)
                #expect(row.value == entry.value.displayValue)
                #expect(try JSONDecoder().decode(EntitlementValue.self, from: Data(row.valueJSON.utf8)) == entry.value)
            }
        }
        let x86False = try #require(csv.first { $0.architecture == "x86_64"
            && $0.key == "com.apple.private.entitlementlens-fixture.x86-only" })
        #expect(try JSONDecoder().decode(EntitlementValue.self, from: Data(x86False.valueJSON.utf8)) == .boolean(false))
        #expect(!csv.contains { $0.architecture == "arm64" && $0.key == x86False.key })
        let arm64Shared = try #require(csv.first { $0.architecture == "arm64" && $0.key == "entitlementlens.fixture.shared" })
        let x86Shared = try #require(csv.first { $0.architecture == "x86_64" && $0.key == "entitlementlens.fixture.shared" })
        #expect(arm64Shared.value == "false")
        #expect(x86Shared.value == "false")
        #expect(try JSONDecoder().decode(EntitlementValue.self, from: Data(arm64Shared.valueJSON.utf8)) == .boolean(false))
        #expect(try JSONDecoder().decode(EntitlementValue.self, from: Data(x86Shared.valueJSON.utf8)) == .string("false"))
        let json = try ResultExporter.data(for: [finding], format: .json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == [finding])

        let slices = try MachOInspector.inspect(universal)
        let affectedSlice = try #require(slices.first { $0.architecture == "arm64" })
        let reservedOffset = try #require(Int(exactly: affectedSlice.fileOffset)) + 28
        let invalidURL = root.appendingPathComponent("fixture.invalid.universal")
        try FileManager.default.copyItem(at: universal, to: invalidURL)
        var damaged = try Data(contentsOf: invalidURL)
        try #require(reservedOffset < damaged.count)
        damaged[reservedOffset] ^= 1
        try damaged.write(to: invalidURL)
        store.startScan(roots: [invalidURL])
        store.selectedFilter = .privateEntitlements
        store.searchText = "com.apple.private.entitlementlens-fixture.arm64"
        try await waitForArchitecturePresentation(store)
        #expect(store.lastError == nil)
        let invalidFinding = try #require(store.findings.first)
        let invalidSigning = try #require(invalidFinding.signing)
        let invalidArchitecture = try #require(invalidSigning.architectureEntitlements.first { $0.architecture == "arm64" })
        guard case .invalid = invalidArchitecture.status else {
            throw ArchitectureFixtureError.expectedInvalidSignature(invalidArchitecture.status)
        }
        let originalArchitecture = try #require(signing.architectureEntitlements.first { $0.architecture == "arm64" })
        #expect(invalidArchitecture.entitlements == originalArchitecture.entitlements)
        let unchangedArchitecture = try #require(invalidSigning.architectureEntitlements.first { $0.architecture == "x86_64" })
        #expect(unchangedArchitecture.status == .valid)
        #expect(store.count(for: .privateEntitlements) == 1)
        #expect(store.filteredFindings.map(\.id) == [invalidFinding.id])
        let invalidIndex = try [indexFinding(invalidFinding)]
        #expect(try matchingFindings(invalidIndex, filter: .privateEntitlements,
            query: "arm64 value", includeEmpty: false).count == 1)
        let invalidCSV = try parseEntitlementCSV(ResultExporter.data(for: [invalidFinding], format: .csv))
        let invalidRows = invalidCSV.filter { $0.source == "architecture_dictionary" && $0.architecture == "arm64" }
        #expect(invalidRows.count == 4)
        for entry in invalidArchitecture.entitlements {
            let row = try #require(invalidRows.first { $0.key == entry.key })
            #expect(row.signatureIntegrity == invalidArchitecture.status.title)
            #expect(try JSONDecoder().decode(EntitlementValue.self, from: Data(row.valueJSON.utf8)) == entry.value)
        }
        let unchangedRows = invalidCSV.filter { $0.source == "architecture_dictionary" && $0.architecture == "x86_64" }
        #expect(unchangedRows.count == 4)
        #expect(unchangedRows.allSatisfy { $0.signatureIntegrity == SignatureStatus.valid.title })
    }

    @Test
    func emptyPrimaryDictionaryDoesNotHideOtherArchitectureDeclarations() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-empty-primary-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Empty-primary fixture cleanup failed: \(error.localizedDescription)") }
        }
        let empty = Data("<plist version=\"1.0\"><dict/></plist>".utf8)
        #if arch(arm64)
        let arm64 = empty
        let x86 = architectureFixturePlist(.x86_64)
        let populatedArchitecture = "x86_64"
        #else
        let arm64 = architectureFixturePlist(.arm64)
        let x86 = empty
        let populatedArchitecture = "arm64"
        #endif
        let universal = try makeSignedUniversalFixture(root: root, arm64Entitlements: arm64, x86Entitlements: x86)
        let store = ScanStore()
        store.startScan(roots: [universal])
        try await waitForArchitecturePresentation(store)
        #expect(store.lastError == nil)
        let finding = try #require(store.findings.first)
        let signing = try #require(finding.signing)
        #expect(signing.entitlements.isEmpty)
        #expect(finding.entitlementCount == 4)
        #expect(finding.privateEntitlementCount == 1)
        #expect(store.count(for: .entitlements) == 1)
        #expect(store.count(for: .privateEntitlements) == 1)
        #expect(try indexFinding(finding).visibleByDefault)
        store.selectedFilter = .privateEntitlements
        store.searchText = populatedArchitecture
        try await waitForArchitecturePresentation(store)
        #expect(store.filteredFindings.map(\.id) == [finding.id])
        let rows = try parseEntitlementCSV(ResultExporter.data(for: [finding], format: .csv))
        #expect(rows.count == 6)
        let markers = rows.filter { $0.key.isEmpty }
        #expect(markers.count == 2)
        #expect(markers.allSatisfy { $0.value.isEmpty && $0.valueJSON.isEmpty && $0.signatureIntegrity == SignatureStatus.valid.title })
        #expect(markers.allSatisfy { $0.sourceNotes == "No entries returned." })
        #expect(markers.contains { $0.source == "standard_dictionary" && $0.architecture.isEmpty })
        #expect(rows.filter { $0.architecture == populatedArchitecture }.count == 4)
        #expect(rows.allSatisfy { $0.collectionNotes.isEmpty == signing.extractionWarnings.isEmpty })
    }

    private func waitForArchitecturePresentation(_ store: ScanStore) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while store.isScanning || store.isFiltering {
            guard ContinuousClock.now < deadline else { throw ArchitectureFixtureError.presentationTimeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}

private enum FixtureArchitecture {
    case arm64
    case x86_64
}

private func architectureFixturePlist(_ architecture: FixtureArchitecture) -> Data {
    let name: String
    let privateKey: String
    let boolean: String
    let sharedValue: String
    switch architecture {
    case .arm64:
        name = "arm64"
        privateKey = "com.apple.private.entitlementlens-fixture.arm64"
        boolean = "true"
        sharedValue = "<false/>"
    case .x86_64:
        name = "x86_64"
        privateKey = "com.apple.private.entitlementlens-fixture.x86-only"
        boolean = "false"
        sharedValue = "<string>false</string>"
    }
    return Data("""
    <plist version="1.0"><dict>
    <key>com.apple.security.get-task-allow</key><\(boolean)/>
    <key>\(privateKey)</key><\(boolean)/>
    <key>entitlementlens.fixture.shared</key>\(sharedValue)
    <key>entitlementlens.fixture.array</key><array><string>\(name) value, "quoted"
    second line</string><string>shared</string></array>
    </dict></plist>
    """.utf8)
}

private struct EntitlementCSVRow {
    let source: String
    let architecture: String
    let signatureIntegrity: String
    let cdHash: String
    let key: String
    let value: String
    let valueJSON: String
    let sourceNotes: String
    let collectionNotes: String
}

private enum ArchitectureFixtureError: Error {
    case presentationTimeout
    case expectedInvalidSignature(SignatureStatus)
    case invalidCSVQuote(Int)
    case unterminatedCSVQuote
    case invalidCSVWidth(Int, Int)
    case missingCSVColumn(String)
}

private func parseEntitlementCSV(_ data: Data) throws -> [EntitlementCSVRow] {
    let records = try csvFixtureRecords(String(decoding: data, as: UTF8.self))
    let header = try #require(records.first)
    let columns = try ["entitlement_source", "entitlement_architecture", "source_signature_integrity", "source_cdhash",
        "entitlement_key", "entitlement_value", "entitlement_value_json", "source_notes", "collection_notes"].map { name in
        guard let index = header.firstIndex(of: name) else { throw ArchitectureFixtureError.missingCSVColumn(name) }
        return index
    }
    return try records.dropFirst().map { fields in
        guard fields.count == header.count else { throw ArchitectureFixtureError.invalidCSVWidth(fields.count, header.count) }
        return EntitlementCSVRow(source: fields[columns[0]], architecture: fields[columns[1]],
            signatureIntegrity: fields[columns[2]], cdHash: fields[columns[3]], key: fields[columns[4]],
            value: fields[columns[5]], valueJSON: fields[columns[6]], sourceNotes: fields[columns[7]],
            collectionNotes: fields[columns[8]])
    }
}

func csvFixtureRecords(_ value: String) throws -> [[String]] {
    let characters = Array(value)
    var records: [[String]] = []
    var fields: [String] = []
    var field = ""
    var quoted = false
    var closedQuote = false
    var index = 0
    while index < characters.count {
        let character = characters[index]
        if quoted {
            if character == "\"" {
                if index + 1 < characters.count, characters[index + 1] == "\"" {
                    field.append("\"")
                    index += 1
                } else {
                    quoted = false
                    closedQuote = true
                }
            } else {
                field.append(character)
            }
        } else if character == "," {
            fields.append(field)
            field = ""
            closedQuote = false
        } else if character == "\n" {
            fields.append(field)
            records.append(fields)
            fields = []
            field = ""
            closedQuote = false
        } else if character == "\"", field.isEmpty, !closedQuote {
            quoted = true
        } else {
            guard character != "\"", !closedQuote else { throw ArchitectureFixtureError.invalidCSVQuote(index) }
            field.append(character)
        }
        index += 1
    }
    guard !quoted else { throw ArchitectureFixtureError.unterminatedCSVQuote }
    if !fields.isEmpty || !field.isEmpty || closedQuote {
        fields.append(field)
        records.append(fields)
    }
    return records
}
