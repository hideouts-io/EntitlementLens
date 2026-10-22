import Foundation
import Testing
@testable import EntitlementLens

struct ResearchCaseCandidateProjectorTests {
    @Test
    func controlledUniversalFixtureProducesScopedPublicCaseAndRejectsCoverageLoss() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-research-case-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Research case fixture cleanup failed: \(error.localizedDescription)") }
        }
        let x86 = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>com.apple.security.get-task-allow</key><false/>
          <key>io.hideouts.fixture-note</key><string>case differs</string>
        </dict></plist>
        """.utf8)
        let arm = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>com.apple.security.get-task-allow</key><true/>
          <key>io.hideouts.fixture-note</key><string>case differs</string>
        </dict></plist>
        """.utf8)
        let file = try makeSignedUniversalFixture(root: root, arm64Entitlements: arm, x86Entitlements: x86)
        let finding = try await collectResearchCaseFinding(file)
        let metadata = ResearchCaseCandidateMetadata(
            caseID: "controlled-universal-candidate", sampleKind: .controlledFixture,
            sourceReference: "ResearchCaseCandidateProjectorTests.controlledUniversalFixture",
            artifactLabel: "controlled-universal-fixture",
            // This syntax sentinel is not a claim about the uncommitted test fixture's source revision.
            sourceCommit: String(repeating: "a", count: 40)
        )
        let candidate = try ResearchCaseCandidateProjector.project(finding: finding, metadata: metadata)
        #expect(candidate.schemaVersion == 1)
        #expect(candidate.collector.featureSchemaVersion == finding.staticFeatures?.schemaVersion.rawValue)
        #expect(candidate.collector.hostMacOSVersion == finding.provenance.hostOperatingSystem.productVersion)
        #expect(candidate.collector.hostMacOSBuild == finding.provenance.hostOperatingSystem.buildVersion)
        #expect(candidate.collector.sourceCommit == metadata.sourceCommit)
        #expect(candidate.artifactSHA256 == finding.provenance.sha256)
        #expect(Set(candidate.architectures.map(\.name)) == ["arm64", "x86_64"])
        #expect(candidate.architectures.allSatisfy { $0.collectionState == .complete && $0.signatureIntegrity == .valid })
        let values = candidate.architectures.compactMap { architecture in
            architecture.declarations.first { $0.key == "com.apple.security.get-task-allow" }.map { (architecture.name, $0.value) }
        }
        #expect(values.count == 2)
        #expect(Set(values.map(\.1)) == [.boolean(false), .boolean(true)])
        let json = try ResearchCaseCandidateProjector.jsonData(for: candidate)
        let object = try #require(JSONSerialization.jsonObject(with: json) as? [String: Any])
        #expect(Set(object.keys) == ["schema_version", "case_id", "sample_kind", "source_reference", "artifact_label",
            "artifact_sha256", "collector", "signature_integrity", "entitlement_collection_state",
            "architectures", "evidence_scope", "runtime_authorization"])
        #expect(object["evidence_scope"] as? String == "static_signed_declarations")
        #expect(object["runtime_authorization"] as? String == "not_assessed")
        #expect(!String(decoding: json, as: UTF8.self).contains(root.path))
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let output = repository.appendingPathComponent(".build/research-candidate-validation")
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        try json.write(to: output.appendingPathComponent("controlled-universal-candidate.json"), options: [.atomic])

        let invalidCommit = ResearchCaseCandidateMetadata(caseID: metadata.caseID, sampleKind: metadata.sampleKind,
            sourceReference: metadata.sourceReference, artifactLabel: metadata.artifactLabel, sourceCommit: "a29639f")
        #expect(throws: ResearchCaseCandidateError.self) {
            _ = try ResearchCaseCandidateProjector.project(finding: finding, metadata: invalidCommit)
        }
        let warned = researchCaseFinding(finding, signing: finding.signing,
            warnings: ["Source analysis was incomplete."], features: finding.staticFeatures)
        #expect(throws: ResearchCaseCandidateError.self) {
            _ = try ResearchCaseCandidateProjector.project(finding: warned, metadata: metadata)
        }
        let features = try #require(finding.staticFeatures)
        let partialCollection = StaticFeatureCollection(
            state: StaticCollectionState.partial, reason: "Controlled incomplete collection.",
            records: features.entitlements.records, limitations: ["Some declarations were unavailable."], limits: []
        )
        let partialFeatures = researchCaseFeatures(features, entitlements: partialCollection)
        let partial = researchCaseFinding(finding, signing: finding.signing, warnings: [], features: partialFeatures)
        #expect(throws: ResearchCaseCandidateError.self) {
            _ = try ResearchCaseCandidateProjector.project(finding: partial, metadata: metadata)
        }
        let signing = try #require(finding.signing)
        let originalSlot = try #require(signing.entitlementSlots.first {
            $0.architecture == "arm64" && $0.format == .xml
        })
        let changedSlot = CodeSignatureEntitlementSlot(
            architecture: originalSlot.architecture, slotType: originalSlot.slotType, format: originalSlot.format,
            fileOffset: originalSlot.fileOffset, byteCount: originalSlot.byteCount, sha256: originalSlot.sha256,
            decodedEntitlements: originalSlot.decodedEntitlements.map { entry in
                EntitlementEntry(key: entry.key, value: entry.key == "com.apple.security.get-task-allow"
                    ? .boolean(false) : entry.value)
            }, decoderSource: originalSlot.decoderSource, warning: originalSlot.warning
        )
        let changedSigning = researchCaseSigning(signing,
            entitlementSlots: signing.entitlementSlots.map { $0 == originalSlot ? changedSlot : $0 })
        let changedRecords = features.entitlements.records.map { record in
            StaticEntitlementEvidence(source: record.source, state: record.state, reason: record.reason,
                signatureIntegrity: record.signatureIntegrity, nativeCDHash: record.nativeCDHash,
                values: record.values, slots: record.slots.map { $0 == originalSlot ? changedSlot : $0 },
                location: record.location)
        }
        let changedCollection = StaticFeatureCollection(state: features.entitlements.state,
            reason: features.entitlements.reason, records: changedRecords,
            limitations: features.entitlements.limitations, limits: features.entitlements.limits)
        let divergentSlot = researchCaseFinding(finding, signing: changedSigning, warnings: [],
            features: researchCaseFeatures(features, entitlements: changedCollection))
        #expect(throws: ResearchCaseCandidateError.self) {
            _ = try ResearchCaseCandidateProjector.project(finding: divergentSlot, metadata: metadata)
        }
        let unrecordedSlot = CodeSignatureEntitlementSlot(
            architecture: "unrecorded", slotType: originalSlot.slotType, format: originalSlot.format,
            fileOffset: originalSlot.fileOffset, byteCount: originalSlot.byteCount, sha256: originalSlot.sha256,
            decodedEntitlements: originalSlot.decodedEntitlements,
            decoderSource: originalSlot.decoderSource, warning: nil
        )
        let extraSigning = researchCaseSigning(signing,
            entitlementSlots: signing.entitlementSlots + [unrecordedSlot])
        let extraSlotFinding = researchCaseFinding(finding, signing: extraSigning, warnings: [], features: features)
        #expect(throws: ResearchCaseCandidateError.self) {
            _ = try ResearchCaseCandidateProjector.project(finding: extraSlotFinding, metadata: metadata)
        }
    }
}

private func collectResearchCaseFinding(_ url: URL) async throws -> ScanFinding {
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
        case .cancelled: Issue.record("Research case fixture collection was cancelled.")
        }
    }
    #expect(completed && issues.isEmpty)
    return try #require(findings.first { $0.path == url.path })
}

private func researchCaseFinding(
    _ finding: ScanFinding, signing: SigningDetails?, warnings: [String], features: StaticFeatureSet?
) -> ScanFinding {
    ScanFinding(id: finding.id, path: finding.path, kind: finding.kind, fileFormat: finding.fileFormat,
        fileSize: finding.fileSize, signing: signing, provenance: finding.provenance,
        installedCounterpart: finding.installedCounterpart, runningBoardPolicies: finding.runningBoardPolicies,
        embeddedObjects: finding.embeddedObjects, warnings: warnings, staticFeatures: features)
}

private func researchCaseSigning(
    _ signing: SigningDetails, entitlementSlots: [CodeSignatureEntitlementSlot]
) -> SigningDetails {
    SigningDetails(status: signing.status, resourceIntegrity: signing.resourceIntegrity,
        executionPolicy: signing.executionPolicy, identifier: signing.identifier,
        teamIdentifier: signing.teamIdentifier, format: signing.format, source: signing.source,
        mainExecutable: signing.mainExecutable, requirements: signing.requirements,
        signatureFlags: signing.signatureFlags, rawEntitlementsByteCount: signing.rawEntitlementsByteCount,
        uniqueCDHash: signing.uniqueCDHash, cdHashes: signing.cdHashes,
        platformIdentifier: signing.platformIdentifier, signingTime: signing.signingTime,
        timestamp: signing.timestamp, authorities: signing.authorities, entitlements: signing.entitlements,
        entitlementScope: signing.entitlementScope, runtimeAuthorization: signing.runtimeAuthorization,
        architectureEntitlements: signing.architectureEntitlements,
        entitlementSlots: entitlementSlots,
        extractionWarnings: signing.extractionWarnings,
        entitlementCollectionState: signing.entitlementCollectionState)
}

private func researchCaseFeatures(
    _ features: StaticFeatureSet, entitlements: StaticFeatureCollection<StaticEntitlementEvidence>
) -> StaticFeatureSet {
    StaticFeatureSet(schemaVersion: features.schemaVersion, analyzedPath: features.analyzedPath,
        artifactSHA256: features.artifactSHA256, context: features.context, signer: features.signer,
        embeddedCertificates: features.embeddedCertificates, entitlements: entitlements,
        architectures: features.architectures, loadCommands: features.loadCommands,
        linkedFrameworks: features.linkedFrameworks, apiReferences: features.apiReferences,
        persistenceCharacteristics: features.persistenceCharacteristics, codeDirectoryData: features.codeDirectoryData)
}
