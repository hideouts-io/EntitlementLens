import CryptoKit
import Darwin
import Foundation
import Testing
@testable import EntitlementLens

struct StaticResearchConsumerIntegrationTests {
    @Test
    func coverageRetainsEveryCollectionStateWithoutInventingZeroes() async throws {
        let root = try researchConsumerRoot()
        defer { removeResearchConsumerRoot(root) }
        let selected = root.appendingPathComponent("declaration.plist")
        try Data("<plist version=\"1.0\"><dict/></plist>".utf8).write(to: selected)
        let baseline = try await researchConsumerFinding(selected)
        let features = try #require(baseline.staticFeatures)
        let states: [StaticCollectionState] = [.complete, .partial, .unsupported, .unavailable, .notCollected, .notApplicable]
        // These typed collection-state mutations test consumer semantics, not native scanner outcomes.
        for state in states {
            let empty = researchConsumerFeatures(features, state: state, apiRecords: [], entitlementRecords: [])
            let finding = researchConsumerFinding(baseline, features: empty)
            let report = try researchConsumerReport([finding], root: root, sourceURLs: [])
            let artifact = try #require(report.artifacts.first)
            #expect(artifact.families.count == 9)
            #expect(artifact.staticFeatures == empty)
            #expect(artifact.provenance == baseline.provenance)
            #expect(artifact.sourceVerification.identityState == .notProvided)
            #expect(artifact.sourceVerification.apiByteState == .notPerformed)
            for family in artifact.families {
                #expect(family.collectionState == state)
                #expect(family.retainedRecordCount == 0)
                #expect(family.reason == "Controlled collection state.")
                #expect(family.limitations == ["Bounded fixture collection scope."])
                #expect(family.limits == [StaticCollectionLimit(name: "fixture_records", value: 4, unit: .records)])
                if state == .complete {
                    #expect(family.presence == .scopedAbsent)
                    #expect(family.observationCount == 0)
                    #expect(family.countInterpretation == .exactWithinScope)
                } else {
                    #expect(family.presence == .unknown)
                    #expect(family.observationCount == nil)
                    #expect(family.countInterpretation == .unknown)
                }
            }
            let reference = StaticAPIReference(name: "fixtureRawReference", kind: .rawStringReference,
                location: StaticEvidenceLocation(sourcePath: selected.path, architecture: nil, sliceOffset: nil,
                    fileOffset: nil, byteCount: nil, propertyListKey: nil, method: .rawString), referenceLocation: nil)
            let positive = researchConsumerFeatures(features, state: state, apiRecords: [reference], entitlementRecords: [])
            let positiveReport = try researchConsumerReport([researchConsumerFinding(baseline, features: positive)], root: root, sourceURLs: [])
            let positiveArtifact = try #require(positiveReport.artifacts.first)
            let api = try #require(positiveArtifact.families.first { $0.family == .apiReferences })
            #expect(api.presence == .observed)
            #expect(api.retainedRecordCount == 1 && api.observationCount == 1)
            #expect(api.countInterpretation == (state == .complete ? .exactWithinScope : .lowerBound))
        }
        let legacy = researchConsumerFinding(baseline, features: nil)
        let report = try researchConsumerReport([legacy], root: root, sourceURLs: [])
        let artifact = try #require(report.artifacts.first)
        #expect(artifact.staticFeatures == nil)
        #expect(artifact.families.count == 9)
        #expect(artifact.families.allSatisfy {
            $0.presence == .unknown && $0.collectionState == nil && $0.observationCount == nil
                && $0.countInterpretation == .unknown
        })
        #expect(artifact.entitlementScopes.isEmpty)
        #expect(artifact.provenance == legacy.provenance)
    }

    @Test
    func nestedEntitlementCoverageCountsDeclarationsAndPreservesScopedMissingness() async throws {
        let root = try researchConsumerRoot()
        defer { removeResearchConsumerRoot(root) }
        let selected = root.appendingPathComponent("scope.plist")
        try Data("<plist version=\"1.0\"><dict/></plist>".utf8).write(to: selected)
        let baseline = try await researchConsumerFinding(selected)
        let features = try #require(baseline.staticFeatures)
        let location = StaticEvidenceLocation(sourcePath: selected.path, architecture: nil, sliceOffset: nil,
            fileOffset: nil, byteCount: nil, propertyListKey: nil, method: .securityFramework)
        let empty = StaticEntitlementEvidence(source: .standardDictionary, state: .complete, reason: nil,
            signatureIntegrity: .unsigned, nativeCDHash: nil, values: [], slots: [], location: location)
        let missingLocation = StaticEvidenceLocation(sourcePath: selected.path, architecture: "arm64e", sliceOffset: nil,
            fileOffset: nil, byteCount: nil, propertyListKey: nil, method: .securityFramework)
        let missing = StaticEntitlementEvidence(source: .architecture("arm64e"), state: .unavailable,
            reason: "Controlled architecture dictionary unavailable.", signatureIntegrity: .unsigned,
            nativeCDHash: nil, values: [], slots: [], location: missingLocation)
        let complete = researchConsumerFeatures(features, state: .complete, apiRecords: [], entitlementRecords: [empty])
        let completeReport = try researchConsumerReport([researchConsumerFinding(baseline, features: complete)], root: root, sourceURLs: [])
        let completeArtifact = try #require(completeReport.artifacts.first)
        let family = try #require(completeArtifact.families.first { $0.family == .entitlements })
        #expect(family.retainedRecordCount == 1)
        #expect(family.presence == .scopedAbsent && family.observationCount == 0)
        let scope = try #require(completeArtifact.entitlementScopes.first)
        #expect(scope.source == empty.source && scope.location == empty.location)
        #expect(scope.presence == .scopedAbsent && scope.observationCount == 0)
        let incomplete = researchConsumerFeatures(features, state: .complete, apiRecords: [], entitlementRecords: [empty, missing])
        let incompleteReport = try researchConsumerReport([researchConsumerFinding(baseline, features: incomplete)], root: root, sourceURLs: [])
        let incompleteArtifact = try #require(incompleteReport.artifacts.first)
        let incompleteFamily = try #require(incompleteArtifact.families.first { $0.family == .entitlements })
        #expect(incompleteFamily.presence == .unknown && incompleteFamily.observationCount == nil)
        #expect(incompleteFamily.retainedRecordCount == 2)
        let unavailable = try #require(incompleteArtifact.entitlementScopes.first { $0.source == missing.source })
        #expect(unavailable.presence == .unknown && unavailable.state == .unavailable)
        #expect(unavailable.reason == missing.reason)
        let value = StaticEntitlementEvidence(source: .standardDictionary, state: .complete, reason: nil,
            signatureIntegrity: .unsigned, nativeCDHash: nil, values: [EntitlementEntry(key: "fixture.literal", value: .boolean(false))],
            slots: [], location: location)
        let positive = researchConsumerFeatures(features, state: .partial, apiRecords: [], entitlementRecords: [value, missing])
        let positiveReport = try researchConsumerReport([researchConsumerFinding(baseline, features: positive)], root: root, sourceURLs: [])
        let positiveArtifact = try #require(positiveReport.artifacts.first)
        let positiveFamily = try #require(positiveArtifact.families.first { $0.family == .entitlements })
        #expect(positiveFamily.presence == .observed && positiveFamily.observationCount == 1)
        #expect(positiveFamily.countInterpretation == .lowerBound && positiveFamily.retainedRecordCount == 2)
        let duplicateScope = researchConsumerFeatures(features, state: .complete, apiRecords: [], entitlementRecords: [empty, empty])
        #expect(throws: StaticResearchConsumerError.self) {
            _ = try researchConsumerReport([researchConsumerFinding(baseline, features: duplicateScope)], root: root, sourceURLs: [])
        }
        let duplicateKeys = StaticEntitlementEvidence(source: .standardDictionary, state: .complete, reason: nil,
            signatureIntegrity: .unsigned, nativeCDHash: nil,
            values: [EntitlementEntry(key: "fixture.literal", value: .boolean(false)), EntitlementEntry(key: "fixture.literal", value: .boolean(true))],
            slots: [], location: location)
        #expect(throws: StaticResearchConsumerError.self) {
            _ = try researchConsumerReport([researchConsumerFinding(baseline,
                features: researchConsumerFeatures(features, state: .complete, apiRecords: [], entitlementRecords: [duplicateKeys]))], root: root, sourceURLs: [])
        }
        let disagreement = StaticEntitlementEvidence(source: .architecture("arm64e"), state: .unavailable,
            reason: missing.reason, signatureIntegrity: .unsigned, nativeCDHash: nil, values: [], slots: [], location: location)
        #expect(throws: StaticResearchConsumerError.self) {
            _ = try researchConsumerReport([researchConsumerFinding(baseline,
                features: researchConsumerFeatures(features, state: .partial, apiRecords: [], entitlementRecords: [disagreement]))], root: root, sourceURLs: [])
        }
        let ghostLocation = StaticEvidenceLocation(sourcePath: selected.path, architecture: "ghost", sliceOffset: nil,
            fileOffset: nil, byteCount: nil, propertyListKey: nil, method: .securityFramework)
        let unmappedCompleteScope = StaticEntitlementEvidence(source: .architecture("ghost"), state: .complete,
            reason: nil, signatureIntegrity: .unsigned, nativeCDHash: nil, values: [], slots: [], location: ghostLocation)
        #expect(throws: StaticResearchConsumerError.self) {
            _ = try researchConsumerReport([researchConsumerFinding(baseline,
                features: researchConsumerFeatures(features, state: .complete, apiRecords: [], entitlementRecords: [unmappedCompleteScope]))],
                root: root, sourceURLs: [])
        }
    }

    @Test
    func nativeExportsVerifyRetainedNameBytesAndSlotsInDeterministicResearchReport() async throws {
        let root = try researchConsumerRoot()
        defer { removeResearchConsumerRoot(root) }
        let native = try researchConsumerNativeFixtures(root)
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let samples = repository.appendingPathComponent(".build/static-feature-validation")
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        let modern = samples.appendingPathComponent("research-modern-source")
        let legacy = samples.appendingPathComponent("research-legacy-arm64e-source")
        try Data(contentsOf: native.modern).write(to: modern, options: [.atomic])
        try Data(contentsOf: native.legacy).write(to: legacy, options: [.atomic])
        let system = URL(fileURLWithPath: "/usr/bin/true")
        let findings = [try await researchConsumerFinding(system), try await researchConsumerFinding(modern),
            try await researchConsumerFinding(legacy)]
        let modernFeatures = try #require(findings[1].staticFeatures)
        let legacyFeatures = try #require(findings[2].staticFeatures)
        #expect(modernFeatures.apiReferences.records.contains { $0.name == "SMAppService" && $0.kind == .objectiveCClass })
        #expect(legacyFeatures.apiReferences.records.contains { $0.name == "NSCalendar" && $0.kind == .objectiveCClass })
        let modernOracle = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["dyld_info", "-fixup_chains", native.modern.path])
        let legacyOracle = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["dyld_info", "-fixup_chains", native.legacy.path])
        #expect(String(decoding: modernOracle.standardOutput, as: UTF8.self).contains("DYLD_CHAINED_PTR_ARM64E_USERLAND24"))
        #expect(String(decoding: legacyOracle.standardOutput, as: UTF8.self).contains("DYLD_CHAINED_PTR_ARM64E)"))
        let export = samples.appendingPathComponent("research-inputs.json")
        let json = try ResultExporter.data(for: findings, format: .json)
        try json.write(to: export, options: [.atomic])
        let csv = try ResultExporter.data(for: findings, format: .csv)
        try csv.write(to: samples.appendingPathComponent("research-inputs.csv"), options: [.atomic])
        let report = try StaticResearchExportConsumer.inspect(exportURL: export, sourceURLs: [system, modern, legacy])
        #expect(report.artifacts.count == findings.count)
        #expect(report.exportSHA256 == researchConsumerDigest(json))
        #expect(report.reportVersion == 1)
        for (artifact, finding) in zip(report.artifacts, findings) {
            let features = try #require(finding.staticFeatures)
            #expect(artifact.findingID == finding.id && artifact.selectedPath == finding.path)
            #expect(artifact.provenance == finding.provenance && artifact.staticFeatures == features)
            #expect(artifact.sourceVerification.identityState == .matched)
            #expect(artifact.sourceVerification.actualSHA256 == features.artifactSHA256)
            #expect(artifact.sourceVerification.apiByteState == (features.apiReferences.records.isEmpty ? .notApplicable : .matched))
            #expect(artifact.sourceVerification.checkedAPINameCount == features.apiReferences.records.count)
            #expect(artifact.sourceVerification.checkedReferenceSlotCount == features.apiReferences.records.compactMap(\.referenceLocation).count)
            let bytes = try Data(contentsOf: URL(fileURLWithPath: finding.provenance.analyzedPath))
            for reference in features.apiReferences.records {
                let fileOffset = try #require(reference.location.fileOffset)
                let byteCount = try #require(reference.location.byteCount)
                let offset = try #require(Int(exactly: fileOffset))
                let count = try #require(Int(exactly: byteCount))
                #expect(bytes.subdata(in: offset..<offset + count) == Data(reference.name.utf8) + Data([0]))
                if let slot = reference.referenceLocation {
                    let slotFileOffset = try #require(slot.fileOffset)
                    let slotOffset = try #require(Int(exactly: slotFileOffset))
                    #expect(slot.byteCount == 8 && slotOffset + 8 <= bytes.count)
                    #expect(slot.sourcePath == reference.location.sourcePath && slot.architecture == reference.location.architecture
                        && slot.sliceOffset == reference.location.sliceOffset)
                }
            }
        }
        let reportJSON = try StaticResearchExportConsumer.data(for: report)
        #expect(try JSONDecoder().decode(StaticResearchReport.self, from: reportJSON) == report)
        #expect(try StaticResearchExportConsumer.data(for: report) == reportJSON)
        #expect(try StaticResearchExportConsumer.inspect(exportURL: export, sourceURLs: [system, modern, legacy]) == report)
        #expect(try ResultExporter.data(for: findings, format: .json) == json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == findings)
        let rows = try csvFixtureRecords(String(decoding: csv, as: UTF8.self))
        let header = try #require(rows.first)
        let pathColumn = try #require(header.firstIndex(of: "path"))
        let featureColumn = try #require(header.firstIndex(of: "static_features_json"))
        for finding in findings {
            let payloads = rows.dropFirst().filter { $0[pathColumn] == finding.path }.map { $0[featureColumn] }.filter { !$0.isEmpty }
            #expect(payloads.count == 1)
            let payload = try #require(payloads.first)
            #expect(try JSONDecoder().decode(StaticFeatureSet.self, from: Data(payload.utf8)) == finding.staticFeatures)
        }
        try reportJSON.write(to: samples.appendingPathComponent("research-coverage.json"), options: [.atomic])
    }

    @Test
    func sourceIdentityAndMalformedRetainedEvidenceHaveDistinctVerificationStates() async throws {
        let root = try researchConsumerRoot()
        defer { removeResearchConsumerRoot(root) }
        let native = try researchConsumerNativeFixtures(root)
        let finding = try await researchConsumerFinding(native.modern)
        let features = try #require(finding.staticFeatures)
        let originalBytes = try Data(contentsOf: native.modern)
        let withoutSource = try researchConsumerReport([finding], root: root, sourceURLs: [])
        let omitted = try #require(withoutSource.artifacts.first)
        #expect(omitted.sourceVerification.identityState == .notProvided && omitted.sourceVerification.apiByteState == .notPerformed)
        try Data("changed source artifact".utf8).write(to: native.modern)
        let changedReport = try researchConsumerReport([finding], root: root, sourceURLs: [native.modern])
        let changed = try #require(changedReport.artifacts.first)
        #expect(changed.sourceVerification.identityState == .mismatch && changed.sourceVerification.apiByteState == .notPerformed)
        #expect(changed.staticFeatures == features)
        try FileManager.default.removeItem(at: native.modern)
        let missingReport = try researchConsumerReport([finding], root: root, sourceURLs: [native.modern])
        let missing = try #require(missingReport.artifacts.first)
        #expect(missing.sourceVerification.identityState == .unavailable && missing.sourceVerification.apiByteState == .notPerformed)
        try originalBytes.write(to: native.modern)
        let original = try #require(features.apiReferences.records.first { $0.kind == .objectiveCClass && $0.name == "SMAppService" })
        let wrongName = StaticAPIReference(name: "WrongService", kind: original.kind, location: original.location,
            referenceLocation: original.referenceLocation)
        let invalidNameReport = try researchConsumerReport([researchConsumerFinding(finding,
            features: researchConsumerAPISet(features, schemaVersion: .v3, records: [wrongName]))], root: root, sourceURLs: [native.modern])
        let invalidName = try #require(invalidNameReport.artifacts.first)
        #expect(invalidName.sourceVerification.identityState == .matched && invalidName.sourceVerification.apiByteState == .mismatch)
        let slot = try #require(original.referenceLocation)
        let outOfRange = StaticEvidenceLocation(sourcePath: slot.sourcePath, architecture: slot.architecture,
            sliceOffset: slot.sliceOffset, fileOffset: UInt64(originalBytes.count), byteCount: 8, propertyListKey: nil, method: slot.method)
        let invalidSlot = StaticAPIReference(name: original.name, kind: original.kind, location: original.location, referenceLocation: outOfRange)
        #expect(throws: StaticResearchConsumerError.self) {
            _ = try researchConsumerReport([researchConsumerFinding(finding,
                features: researchConsumerAPISet(features, schemaVersion: .v3, records: [invalidSlot]))], root: root, sourceURLs: [native.modern])
        }
        let sliceOffset = try #require(slot.sliceOffset)
        let foreignSlice = StaticEvidenceLocation(sourcePath: slot.sourcePath, architecture: slot.architecture,
            sliceOffset: sliceOffset + 1, fileOffset: slot.fileOffset, byteCount: slot.byteCount, propertyListKey: nil, method: slot.method)
        let invalidSlice = StaticAPIReference(name: original.name, kind: original.kind, location: original.location, referenceLocation: foreignSlice)
        #expect(throws: StaticResearchConsumerError.self) {
            _ = try researchConsumerReport([researchConsumerFinding(finding,
                features: researchConsumerAPISet(features, schemaVersion: .v3, records: [invalidSlice]))], root: root, sourceURLs: [native.modern])
        }
        let absentSlot = StaticAPIReference(name: original.name, kind: original.kind, location: original.location, referenceLocation: nil)
        for version: StaticFeatureSchemaVersion in [.v1, .v2, .v3] {
            let absentSlotReport = try researchConsumerReport([researchConsumerFinding(finding,
                features: researchConsumerAPISet(features, schemaVersion: version, records: [absentSlot]))], root: root, sourceURLs: [native.modern])
            let incomplete = try #require(absentSlotReport.artifacts.first)
            #expect(incomplete.sourceVerification.identityState == .matched && incomplete.sourceVerification.apiByteState == .incomplete)
        }
        let foreignURL = root.appendingPathComponent("unselected-artifact")
        #expect(throws: Error.self) { _ = try researchConsumerReport([finding], root: root, sourceURLs: [foreignURL]) }
        #expect(throws: Error.self) { _ = try researchConsumerReport([finding], root: root, sourceURLs: [native.modern, native.modern]) }
    }

    @Test
    func samePathSnapshotsVerifyTheirOwnExpectedIdentity() async throws {
        let root = try researchConsumerRoot()
        defer { removeResearchConsumerRoot(root) }
        let selected = root.appendingPathComponent("snapshot.plist")
        try Data("<plist version=\"1.0\"><dict><key>Label</key><string>io.hideouts.old-snapshot</string></dict></plist>".utf8).write(to: selected)
        let earlier = try await researchConsumerFinding(selected)
        try Data("<plist version=\"1.0\"><dict><key>Label</key><string>io.hideouts.current-snapshot</string></dict></plist>".utf8).write(to: selected)
        let current = try await researchConsumerFinding(selected)
        #expect(earlier.provenance.analyzedPath == current.provenance.analyzedPath)
        #expect(earlier.provenance.sha256 != current.provenance.sha256)
        let report = try researchConsumerReport([earlier, current], root: root, sourceURLs: [selected])
        #expect(report.artifacts.count == 2)
        #expect(report.artifacts[0].sourceVerification.identityState == .mismatch)
        #expect(report.artifacts[1].sourceVerification.identityState == .matched)
        #expect(report.artifacts[0].sourceVerification.actualSHA256 == current.provenance.sha256)
        #expect(report.artifacts[1].sourceVerification.actualSHA256 == current.provenance.sha256)
        let reversed = try researchConsumerReport([current, earlier], root: root, sourceURLs: [selected])
        #expect(reversed.artifacts[0].sourceVerification.identityState == .matched)
        #expect(reversed.artifacts[1].sourceVerification.identityState == .mismatch)
    }

    @Test
    func consumerRejectsInvalidTypedExportsAndArtifactBoundsBeforeInterpretation() async throws {
        let root = try researchConsumerRoot()
        defer { removeResearchConsumerRoot(root) }
        let selected = root.appendingPathComponent("scope.plist")
        try Data("<plist version=\"1.0\"><dict/></plist>".utf8).write(to: selected)
        let finding = try await researchConsumerFinding(selected)
        let features = try #require(finding.staticFeatures)
        let export = root.appendingPathComponent("invalid-input.json")
        let json = try ResultExporter.data(for: [finding], format: .json)
        let text = String(decoding: json, as: UTF8.self)
        let schema = "\"schema_version\" : 3"
        let digest = "\"artifact_sha256\" : \"\(features.artifactSHA256)\""
        #expect(text.contains(schema) && text.contains(digest))
        let invalid = [Data("{}".utf8), Data("[0,]".utf8), Data([0xFF]),
            Data(text.replacingOccurrences(of: schema, with: "\"schema_version\" : 4").utf8),
            Data(text.replacingOccurrences(of: digest, with: "\"artifact_sha256\" : \"invalid-hash\"").utf8)]
        for bytes in invalid {
            try bytes.write(to: export)
            #expect(throws: Error.self) { _ = try StaticResearchExportConsumer.inspect(exportURL: export, sourceURLs: []) }
        }
        #expect(throws: Error.self) {
            _ = try researchConsumerReport(Array(repeating: finding, count: 257), root: root, sourceURLs: [])
        }
        let remote = try #require(URL(string: "https://example.invalid/source"))
        #expect(throws: Error.self) { _ = try researchConsumerReport([finding], root: root, sourceURLs: [remote]) }
        try json.write(to: export)
        let cancelled = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try StaticResearchExportConsumer.inspect(exportURL: export, sourceURLs: [])
        }
        do {
            _ = try await cancelled.value
            Issue.record("Cancelled research export consumption unexpectedly completed.")
        } catch is CancellationError { }
    }

    @Test
    func boundedReaderRejectsMalformedJSONAndUnsafeFilesystemInputs() throws {
        let root = try researchConsumerRoot()
        defer { removeResearchConsumerRoot(root) }
        let file = root.appendingPathComponent("input.json")
        try Data("[]".utf8).write(to: file)
        #expect(try StaticResearchFileReader.exportData(at: file) == Data("[]".utf8))
        #expect(try StaticResearchFileReader.sourceData(at: file, maximumBytes: 2) == Data("[]".utf8))
        #expect(throws: StaticResearchFileError.self) { _ = try StaticResearchFileReader.sourceData(at: file, maximumBytes: 1) }
        let link = root.appendingPathComponent("input-link.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        #expect(throws: StaticResearchFileError.self) { _ = try StaticResearchFileReader.exportData(at: link) }
        #expect(throws: StaticResearchFileError.self) { _ = try StaticResearchFileReader.sourceData(at: link) }
        #expect(throws: StaticResearchFileError.self) { _ = try StaticResearchFileReader.exportData(at: root) }
        let fifo = root.appendingPathComponent("input.fifo")
        #expect(mkfifo(fifo.path, 0o600) == 0)
        #expect(throws: StaticResearchFileError.self) { _ = try StaticResearchFileReader.exportData(at: fifo) }
        let remoteURL = try #require(URL(string: "https://example.invalid/input.json"))
        #expect(throws: StaticResearchFileError.self) { _ = try StaticResearchFileReader.exportData(at: remoteURL) }
        let oversized = root.appendingPathComponent("oversized.json")
        try Data().write(to: oversized)
        let handle = try FileHandle(forWritingTo: oversized)
        try handle.truncate(atOffset: UInt64(StaticResearchFileReader.maximumExportBytes + 1))
        try handle.close()
        #expect(throws: StaticResearchFileError.self) { _ = try StaticResearchFileReader.exportData(at: oversized) }
        let sourceHandle = try FileHandle(forWritingTo: oversized)
        try sourceHandle.truncate(atOffset: UInt64(StaticResearchFileReader.maximumSourceBytes + 1))
        try sourceHandle.close()
        #expect(throws: StaticResearchFileError.self) { _ = try StaticResearchFileReader.sourceData(at: oversized) }

        let invalid = ["", "[}", "[", "\"unterminated", "\"\\q\"", "\"\\uZZZZ\"", "\"line\nfeed\""]
        for input in invalid {
            #expect(throws: StaticResearchFileError.self) {
                try StaticResearchFileReader.validateJSONStructure(Data(input.utf8))
            }
        }
        let deepestSupported = String(repeating: "[", count: StaticResearchFileReader.maximumJSONDepth)
            + "0" + String(repeating: "]", count: StaticResearchFileReader.maximumJSONDepth)
        try StaticResearchFileReader.validateJSONStructure(Data(deepestSupported.utf8))
        let tooDeep = "[" + deepestSupported + "]"
        try expectResearchJSONLimit(Data(tooDeep.utf8), limit: .nestingDepth)
        let oversizedString = "\"" + String(repeating: "x", count: StaticResearchFileReader.maximumJSONStringBytes + 1) + "\""
        try expectResearchJSONLimit(Data(oversizedString.utf8), limit: .stringBytes)
        let tooManyNodes = "[" + Array(repeating: "0", count: StaticResearchFileReader.maximumJSONNodes).joined(separator: ",") + "]"
        try expectResearchJSONLimit(Data(tooManyNodes.utf8), limit: .valueNodes)
        #expect(throws: StaticResearchFileError.self) {
            try StaticResearchFileReader.validateJSONStructure(Data(repeating: 0x20, count: StaticResearchFileReader.maximumExportBytes + 1))
        }
    }

    @Test
    func cancellationStopsReaderBeforeReadingOrDecoding() async throws {
        let root = try researchConsumerRoot()
        defer { removeResearchConsumerRoot(root) }
        let file = root.appendingPathComponent("input.json")
        try Data("[]".utf8).write(to: file)
        let operation = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            _ = try StaticResearchFileReader.exportData(at: file)
            try StaticResearchFileReader.validateJSONStructure(Data("[]".utf8))
        }
        do {
            try await operation.value
            Issue.record("Cancelled research input collection unexpectedly completed.")
        } catch is CancellationError { }
    }
}

private func researchConsumerRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-research-consumer-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeResearchConsumerRoot(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Research consumer fixture cleanup failed: \(error.localizedDescription)") }
}

private func expectResearchJSONLimit(_ data: Data, limit: StaticResearchJSONLimit) throws {
    do {
        try StaticResearchFileReader.validateJSONStructure(data)
        Issue.record("Research JSON exceeding the \(limit.rawValue) bound unexpectedly passed preflight.")
    } catch let StaticResearchFileError.jsonLimitExceeded(actual, _) {
        #expect(actual == limit)
    }
}

private func researchConsumerReport(_ findings: [ScanFinding], root: URL, sourceURLs: [URL]) throws -> StaticResearchReport {
    let export = root.appendingPathComponent("input.json")
    try ResultExporter.data(for: findings, format: .json).write(to: export)
    return try StaticResearchExportConsumer.inspect(exportURL: export, sourceURLs: sourceURLs)
}

private func researchConsumerFeatures(_ features: StaticFeatureSet, state: StaticCollectionState,
                                      apiRecords: [StaticAPIReference], entitlementRecords: [StaticEntitlementEvidence]) -> StaticFeatureSet {
    StaticFeatureSet(schemaVersion: features.schemaVersion, analyzedPath: features.analyzedPath,
        artifactSHA256: features.artifactSHA256, context: features.context,
        signer: researchConsumerCollection(state: state, records: []),
        embeddedCertificates: researchConsumerCollection(state: state, records: []),
        entitlements: researchConsumerCollection(state: state, records: entitlementRecords),
        architectures: researchConsumerCollection(state: state, records: []),
        loadCommands: researchConsumerCollection(state: state, records: []),
        linkedFrameworks: researchConsumerCollection(state: state, records: []),
        apiReferences: researchConsumerCollection(state: state, records: apiRecords),
        persistenceCharacteristics: researchConsumerCollection(state: state, records: []),
        codeDirectoryData: researchConsumerCollection(state: state, records: []))
}

private func researchConsumerCollection<Record: Codable & Hashable & Sendable>(state: StaticCollectionState,
                                                                            records: [Record]) -> StaticFeatureCollection<Record> {
    StaticFeatureCollection(state: state, reason: "Controlled collection state.", records: records,
        limitations: ["Bounded fixture collection scope."],
        limits: [StaticCollectionLimit(name: "fixture_records", value: 4, unit: .records)])
}

private func researchConsumerFinding(_ finding: ScanFinding, features: StaticFeatureSet?) -> ScanFinding {
    ScanFinding(id: finding.id, path: finding.path, kind: finding.kind, fileFormat: finding.fileFormat,
        fileSize: finding.fileSize, signing: finding.signing, provenance: finding.provenance,
        installedCounterpart: finding.installedCounterpart, runningBoardPolicies: finding.runningBoardPolicies,
        embeddedObjects: finding.embeddedObjects, warnings: finding.warnings, staticFeatures: features)
}

private func researchConsumerFinding(_ url: URL) async throws -> ScanFinding {
    let configuration = ScanConfiguration(roots: [url], includeHidden: true, deepCarve: false, maximumWorkerCount: 1,
        queueCapacity: 4, maximumCarveBytes: 1_048_576, excludedPathPrefixes: [])
    var findings: [ScanFinding] = []
    var issues: [ScanIssue] = []
    var completed = false
    for await update in ScanCoordinator.updates(configuration: configuration) {
        switch update {
        case let .batch(batch):
            findings.append(contentsOf: batch.findings)
            issues.append(contentsOf: batch.issues.filter { $0.category != .skipped })
        case .completed: completed = true
        case .cancelled: Issue.record("Research consumer fixture collection was cancelled.")
        }
    }
    #expect(completed && issues.isEmpty)
    let selected = findings.filter { $0.path == url.path }
    #expect(selected.count == 1)
    return try #require(selected.first)
}

private func researchConsumerAPISet(_ features: StaticFeatureSet, schemaVersion: StaticFeatureSchemaVersion,
                                    records: [StaticAPIReference]) -> StaticFeatureSet {
    let persistence = features.persistenceCharacteristics
    let retainedPersistence = persistence.records.filter { characteristic in
        guard let api = characteristic.apiReference else { return true }
        return records.contains(api)
    }
    return StaticFeatureSet(schemaVersion: schemaVersion, analyzedPath: features.analyzedPath,
        artifactSHA256: features.artifactSHA256, context: features.context, signer: features.signer,
        embeddedCertificates: features.embeddedCertificates, entitlements: features.entitlements,
        architectures: features.architectures, loadCommands: features.loadCommands, linkedFrameworks: features.linkedFrameworks,
        apiReferences: StaticFeatureCollection(state: features.apiReferences.state, reason: features.apiReferences.reason,
            records: records, limitations: features.apiReferences.limitations, limits: features.apiReferences.limits),
        persistenceCharacteristics: StaticFeatureCollection(state: persistence.state, reason: persistence.reason,
            records: retainedPersistence, limitations: persistence.limitations, limits: persistence.limits),
        codeDirectoryData: features.codeDirectoryData)
}

private struct ResearchConsumerNativeFixtures {
    let modern: URL
    let legacy: URL
}

/// Native fixtures declare references only. They are compiled and read but never executed or registered.
private func researchConsumerNativeFixtures(_ root: URL) throws -> ResearchConsumerNativeFixtures {
    let source = root.appendingPathComponent("research-native.m")
    try Data("""
    #import <Foundation/Foundation.h>
    #import <ServiceManagement/ServiceManagement.h>
    API_AVAILABLE(macos(13.0)) id fixture_service(void) { return [SMAppService mainAppService]; }
    id fixture_date(void) { return [NSDate date]; }
    SEL fixture_selector(void) { return @selector(registerAndReturnError:); }
    Boolean (* volatile fixture_legacy)(CFStringRef, Boolean) = &SMLoginItemSetEnabled;
    int main(void) { return 0; }
    """.utf8).write(to: source)
    let authentication = root.appendingPathComponent("research-auth.s")
    try Data("""
    .section __TEXT,__objc_methname,cstring_literals
    Lresearch_selector:
    .asciz "researchAuthenticatedSelector:"
    .section __AUTH,__objc_selrefs,literal_pointers,no_dead_strip
    .p2align 3
    .quad Lresearch_selector@AUTH(da,4660,addr)
    .section __AUTH_CONST,__objc_classrefs,regular,no_dead_strip
    .p2align 3
    .quad _OBJC_CLASS_$_SMAppService@AUTH(db,22136,addr)
    .quad _OBJC_CLASS_$_NSCalendar@AUTH(ia,42)
    """.utf8).write(to: authentication)
    let modernArm = root.appendingPathComponent("research-modern.arm64e")
    let ordinary = root.appendingPathComponent("research-modern.x86_64")
    let legacy = root.appendingPathComponent("research-legacy.arm64e")
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    let compilations: [(target: String, inputs: [URL], linker: String, output: URL)] = [
        ("arm64e-apple-macos14.0", [source, authentication], "-fixup_chains", modernArm),
        ("x86_64-apple-macos14.0", [source], "-no_fixup_chains", ordinary),
        ("arm64e-apple-macos11.0", [source, authentication], "-fixup_chains", legacy)
    ]
    for compilation in compilations {
        _ = try runFixtureTool(executable: xcrun, arguments: ["clang", "-target", compilation.target] + compilation.inputs.map(\.path)
            + ["-framework", "Foundation", "-framework", "ServiceManagement", "-Wl," + compilation.linker, "-o", compilation.output.path])
    }
    let modern = root.appendingPathComponent("research-modern.universal")
    _ = try runFixtureTool(executable: xcrun, arguments: ["lipo", "-create", modernArm.path, ordinary.path, "-output", modern.path])
    return ResearchConsumerNativeFixtures(modern: modern, legacy: legacy)
}

private func researchConsumerDigest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
