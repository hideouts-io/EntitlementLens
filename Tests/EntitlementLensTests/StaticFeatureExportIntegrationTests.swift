import Foundation
import Testing
@testable import EntitlementLens

struct StaticFeatureExportIntegrationTests {
    @Test
    func systemCollectionExportsVersionedEvidenceAndDecodesLegacyRecords() async throws {
        let system = URL(fileURLWithPath: "/usr/bin/true")
        let finding = try await collectSelectedStaticFeatureFinding(system)
        let features = try #require(finding.staticFeatures)
        #expect(features.schemaVersion == .v3)
        #expect(features.artifactSHA256 == finding.provenance.sha256)
        #expect(features.analyzedPath == finding.provenance.analyzedPath)
        #expect(features.architectures.records.map(\.slice) == finding.provenance.machOSlices)
        #expect(features.architectures.state == .complete)
        #expect(features.loadCommands.records.allSatisfy { $0.location.sourcePath == features.analyzedPath })
        #expect(features.apiReferences.records.allSatisfy { $0.location.sourcePath == features.analyzedPath })
        #expect(features.context.hostOperatingSystem == finding.provenance.hostOperatingSystem)
        #expect(finding.signing?.executionPolicy.status == .notAssessed)
        let json = try verifyStaticFeatureExports(finding)
        let records = try #require(JSONSerialization.jsonObject(with: json) as? [[String: Any]])
        var legacy = try #require(records.first)
        var unsupported = try #require(legacy["staticFeatures"] as? [String: Any])
        unsupported["schema_version"] = 4
        let unsupportedJSON = try JSONSerialization.data(withJSONObject: unsupported, options: [.sortedKeys])
        #expect(throws: DecodingError.self) { _ = try JSONDecoder().decode(StaticFeatureSet.self, from: unsupportedJSON) }
        legacy.removeValue(forKey: "staticFeatures")
        let legacyJSON = try JSONSerialization.data(withJSONObject: [legacy], options: [.sortedKeys])
        let legacyFinding = try #require(JSONDecoder().decode([ScanFinding].self, from: legacyJSON).first)
        #expect(legacyFinding.staticFeatures == nil)
        #expect(legacyFinding.signing == finding.signing)
        #expect(legacyFinding.provenance == finding.provenance)
        let legacyCSV = try csvFixtureRecords(String(decoding: ResultExporter.data(for: [legacyFinding], format: .csv), as: UTF8.self))
        let header = try #require(legacyCSV.first)
        let column = try #require(header.firstIndex(of: "static_features_json"))
        #expect(legacyCSV.dropFirst().allSatisfy { $0[column].isEmpty })

        // Keep a real local sample beside ignored build outputs for review of the export contract.
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let samples = repository.appendingPathComponent(".build/static-feature-validation")
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        try await writeExport(to: samples.appendingPathComponent("true.json")) { json }
        let csv = try ResultExporter.data(for: [finding], format: .csv)
        try await writeExport(to: samples.appendingPathComponent("true.csv")) { csv }
    }

    @Test
    func universalSourceFeaturesRetainTypedDeclarationsAndExcludeCounterpartEvidence() async throws {
        let root = try staticFeatureFixtureRoot()
        defer { removeStaticFeatureFixture(root) }
        let arm64 = Data("<plist version=\"1.0\"><dict><key>fixture.value</key><integer>7</integer></dict></plist>".utf8)
        let x86 = Data("<plist version=\"1.0\"><dict><key>fixture.value</key><string>seven</string></dict></plist>".utf8)
        let universal = try makeSignedUniversalFixture(root: root, arm64Entitlements: arm64, x86Entitlements: x86)
        let source = root.appendingPathComponent("usr/bin/ssh")
        try FileManager.default.createDirectory(at: source.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: universal, to: source)
        let finding = try await collectSelectedStaticFeatureFinding(source)
        let features = try #require(finding.staticFeatures)
        let armEvidence = try #require(features.entitlements.records.first { $0.source == .architecture("arm64") })
        let x86Evidence = try #require(features.entitlements.records.first { $0.source == .architecture("x86_64") })
        #expect(armEvidence.state == .complete)
        #expect(x86Evidence.state == .complete)
        #expect(armEvidence.values.first { $0.key == "fixture.value" }?.value == .integer(7))
        #expect(x86Evidence.values.first { $0.key == "fixture.value" }?.value == .string("seven"))
        #expect(armEvidence.location.sliceOffset != x86Evidence.location.sliceOffset)
        #expect(features.signer.records.allSatisfy { $0.mode == .adHoc })
        #expect(features.signer.records.allSatisfy { $0.signingIdentifier == "io.hideouts.EntitlementLens.IntegrationFixture" })
        #expect(features.embeddedCertificates.records.isEmpty)
        #expect(features.codeDirectoryData.records.count >= 2)
        #expect(features.codeDirectoryData.records.allSatisfy { $0.location.sourcePath == source.path })
        let comparison = try #require(finding.installedCounterpart)
        #expect(comparison.path == "/usr/bin/ssh")
        #expect(comparison.sha256 != features.artifactSHA256)
        _ = try verifyStaticFeatureExports(finding)
    }

    @Test
    func selectedPropertyListExportsTypedPersistenceWithoutInventingCodeEvidence() async throws {
        let root = try staticFeatureFixtureRoot()
        defer { removeStaticFeatureFixture(root) }
        let file = root.appendingPathComponent("declaration.plist")
        let bytes = Data("<plist version=\"1.0\"><dict><key>Label</key><string>io.hideouts.fixture</string><key>ProgramArguments</key><array><string>/not-opened/fixture</string><string>literal argument</string></array><key>RunAtLoad</key><true/></dict></plist>".utf8)
        try bytes.write(to: file)
        let finding = try await collectSelectedStaticFeatureFinding(file)
        let features = try #require(finding.staticFeatures)
        #expect(features.signer.state == .notApplicable)
        #expect(features.architectures.state == .notApplicable)
        #expect(features.apiReferences.state == .notApplicable)
        let persistence = features.persistenceCharacteristics
        #expect(!persistence.records.isEmpty)
        #expect(persistence.records.allSatisfy { $0.sourceSHA256 == finding.provenance.sha256 })
        #expect(persistence.records.contains { $0.declarationKey == "RunAtLoad" && $0.declarationValue == .boolean(true) })
        #expect(persistence.records.allSatisfy { $0.association == .selectedPropertyList })
        let json = try verifyStaticFeatureExports(finding)
        let exported = try #require(JSONSerialization.jsonObject(with: json) as? [[String: Any]])
        let exportedFinding = try #require(exported.first)
        let featureObject = try #require(exportedFinding["staticFeatures"] as? [String: Any])
        let legacyVersions: [StaticFeatureSchemaVersion] = [.v1, .v2]
        for version in legacyVersions {
            var legacyObject = featureObject
            legacyObject["schema_version"] = version.rawValue
            let legacyJSON = try JSONSerialization.data(withJSONObject: legacyObject, options: [.sortedKeys])
            let decodedLegacy = try JSONDecoder().decode(StaticFeatureSet.self, from: legacyJSON)
            #expect(decodedLegacy.schemaVersion == version)
            #expect(decodedLegacy.persistenceCharacteristics == persistence)
            #expect(decodedLegacy.persistenceCharacteristics.records.allSatisfy { $0.apiReference == nil })
        }
    }

    @Test
    func changedArtifactIsRejectedBeforeEvidenceCanBeRetained() throws {
        let root = try staticFeatureFixtureRoot()
        defer { removeStaticFeatureFixture(root) }
        let file = root.appendingPathComponent("artifact")
        try Data("before".utf8).write(to: file)
        let classified = try #require(try FileClassifier.classify(file))
        let identity = try ArtifactAnalysisIdentity.capture(classified)
        let provenance = try ArtifactProvenanceCollector.collectFile(file)
        try identity.verifyProvenance(provenance)
        try Data("after".utf8).write(to: file)
        #expect(throws: ArtifactAnalysisIdentityError.self) { try identity.verifyCurrentContents() }
        let changedProvenance = try ArtifactProvenanceCollector.collectFile(file)
        #expect(throws: ArtifactAnalysisIdentityError.self) { try identity.verifyProvenance(changedProvenance) }
    }

    @Test
    func bundleExecutableEscapesAreRejectedBeforeReadingExternalBytes() throws {
        let root = try staticFeatureFixtureRoot()
        defer { removeStaticFeatureFixture(root) }
        let bundle = root.appendingPathComponent("Escape.app")
        let executableDirectory = bundle.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at: executableDirectory, withIntermediateDirectories: true)
        let info: [String: String] = ["CFBundleIdentifier": "io.hideouts.escape-fixture", "CFBundleExecutable": "fixture", "CFBundlePackageType": "APPL"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            .write(to: bundle.appendingPathComponent("Contents/Info.plist"))
        let external = root.appendingPathComponent("external")
        try Data("uninspected external bytes".utf8).write(to: external)
        try FileManager.default.createSymbolicLink(at: executableDirectory.appendingPathComponent("fixture"), withDestinationURL: external)
        let classified = try #require(try FileClassifier.classify(bundle))
        #expect(throws: ArtifactAnalysisIdentityError.self) { _ = try ArtifactAnalysisIdentity.capture(classified) }
    }

    @Test
    func unsignedBundleStillExportsItsContainedExecutableAndDeclarations() async throws {
        let root = try staticFeatureFixtureRoot()
        defer { removeStaticFeatureFixture(root) }
        let declarations = Data("<plist version=\"1.0\"><dict/></plist>".utf8)
        let universal = try makeSignedUniversalFixture(root: root, arm64Entitlements: declarations, x86Entitlements: declarations)
        let bundle = root.appendingPathComponent("Unsigned.app")
        let executable = bundle.appendingPathComponent("Contents/MacOS/fixture")
        try FileManager.default.createDirectory(at: executable.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: universal, to: executable)
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/codesign"), arguments: ["--remove-signature", executable.path])
        let info: [String: String] = ["CFBundleIdentifier": "io.hideouts.unsigned-fixture", "CFBundleExecutable": "fixture", "CFBundlePackageType": "APPL"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            .write(to: bundle.appendingPathComponent("Contents/Info.plist"))
        let finding = try await collectSelectedStaticFeatureFinding(bundle)
        let features = try #require(finding.staticFeatures)
        #expect(finding.provenance.analyzedPath == executable.path)
        #expect(features.architectures.records.count == 2)
        #expect(features.signer.records.count == 2)
        #expect(features.signer.records.allSatisfy { $0.mode == .unsigned })
        #expect(features.embeddedCertificates.records.isEmpty)
        #expect(features.codeDirectoryData.records.isEmpty)
        _ = try verifyStaticFeatureExports(finding)
    }
}

private func verifyStaticFeatureExports(_ finding: ScanFinding) throws -> Data {
    let features = try #require(finding.staticFeatures)
    let json = try ResultExporter.data(for: [finding], format: .json)
    #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == [finding])
    #expect(try ResultExporter.data(for: [finding], format: .json) == json)
    let records = try csvFixtureRecords(String(decoding: ResultExporter.data(for: [finding], format: .csv), as: UTF8.self))
    let header = try #require(records.first)
    let versionColumn = try #require(header.firstIndex(of: "static_features_schema_version"))
    let featureColumn = try #require(header.firstIndex(of: "static_features_json"))
    #expect(versionColumn == header.count - 2)
    #expect(featureColumn == header.count - 1)
    for (index, record) in records.dropFirst().enumerated() {
        #expect(record.count == header.count)
        #expect(record[versionColumn] == String(features.schemaVersion.rawValue))
        if index == 0 {
            #expect(try JSONDecoder().decode(StaticFeatureSet.self, from: Data(record[featureColumn].utf8)) == features)
        } else {
            #expect(record[featureColumn].isEmpty)
        }
    }
    return json
}

private func collectSelectedStaticFeatureFinding(_ url: URL) async throws -> ScanFinding {
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
            issues.append(contentsOf: batch.issues.filter { $0.category != .skipped })
        case .completed: completed = true
        case .cancelled: Issue.record("Static-feature fixture collection was cancelled.")
        }
    }
    #expect(completed)
    #expect(issues.isEmpty)
    let selectedFindings = findings.filter { $0.path == url.path }
    #expect(selectedFindings.count == 1)
    return try #require(selectedFindings.first)
}

private func staticFeatureFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-static-export-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeStaticFeatureFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Static-feature export fixture cleanup failed: \(error.localizedDescription)") }
}
