import Foundation
import Testing
@testable import EntitlementLens

struct PersistenceAPIReferenceIntegrationTests {
    @Test
    func projectsExactSDKImportsWithOriginalArchitectureMethodAndLocation() throws {
        let root = try persistenceAPIFixtureRoot()
        defer { removePersistenceAPIFixture(root) }
        let fixture = try makePersistenceAPIFixture(root)
        let inspection = try MachOInspector.inspectStaticFeatures(fixture)
        let result = try PersistenceAPIReferenceCollector.collect(apiReferences: inspection.apiReferences, analyzedPath: fixture.path)
        let expectedNames: Set<String> = ["_SMLoginItemSetEnabled", "_SMJobBless", "_SMJobSubmit", "_SMJobRemove"]
        let expected = inspection.apiReferences.records.filter { $0.kind == .importedSymbol && expectedNames.contains($0.name) }
        #expect(!expected.isEmpty)
        #expect(Set(result.records.compactMap { $0.apiReference?.name }) == expectedNames)
        #expect(result.records.compactMap(\.apiReference) == expected)
        #expect(Set(result.records.compactMap { $0.location.architecture }) == ["arm64", "x86_64"])
        #expect(result.records.allSatisfy { $0.kind == .apiReference && $0.association == .selectedArtifact })
        #expect(result.records.allSatisfy {
            $0.declarationKey == nil && $0.declarationValue == nil && $0.declaredIdentifier == nil
                && $0.declaredExecutablePaths.isEmpty && $0.bundleProgramCandidatePath == nil && $0.sourceSHA256 == nil
        })
        for record in result.records {
            let original = try #require(record.apiReference)
            #expect(record.location == original.location)
        }
        #expect(result.state == inspection.apiReferences.state)
        #expect(result.reason == inspection.apiReferences.reason)
        #expect(try PersistenceAPIReferenceCollector.collect(apiReferences: inspection.apiReferences, analyzedPath: fixture.path) == result)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(result)
        #expect(try JSONDecoder().decode(StaticFeatureCollection<StaticPersistenceCharacteristic>.self, from: encoded) == result)
    }

    @Test
    func excludesRawAmbiguousDefinitionContextAndNearMatchReferences() throws {
        let root = try persistenceAPIFixtureRoot()
        defer { removePersistenceAPIFixture(root) }
        let fixture = try makePersistenceAPIFixture(root)
        let source = try MachOInspector.inspectStaticFeatures(fixture).apiReferences
        let original = try #require(source.records.first { $0.name == "_SMJobBless" && $0.kind == .importedSymbol })
        let raw = persistenceAPIVariant(original, name: original.name, kind: .rawStringReference, method: .rawString, sourcePath: fixture.path)
        let ambiguous = persistenceAPIVariant(original, name: original.name, kind: .dyldBindingSymbol, method: .dyldBindStream, sourcePath: fixture.path)
        let wrongMethod = persistenceAPIVariant(original, name: original.name, kind: .importedSymbol, method: .propertyList, sourcePath: fixture.path)
        let selector = persistenceAPIVariant(original, name: original.name, kind: .objectiveCSelector, method: .symbolTable, sourcePath: fixture.path)
        let suffix = persistenceAPIVariant(original, name: original.name + "$weak", kind: .importedSymbol, method: .symbolTable, sourcePath: fixture.path)
        let prefix = persistenceAPIVariant(original, name: original.name + "Extra", kind: .importedSymbol, method: .symbolTable, sourcePath: fixture.path)
        let genericProcess = persistenceAPIVariant(original, name: "_posix_spawn", kind: .importedSymbol, method: .symbolTable, sourcePath: fixture.path)
        let records = [raw, ambiguous, wrongMethod, selector, suffix, prefix, genericProcess, original]
        let input = persistenceAPIInput(source, records: records)
        let result = try PersistenceAPIReferenceCollector.collect(apiReferences: input, analyzedPath: fixture.path)
        #expect(result.records.compactMap(\.apiReference) == [original])
        #expect(result.state == source.state)
        let definedFixture = try makeDefinedPersistenceAPIFixture(root)
        let definedImports = try MachOInspector.inspectStaticFeatures(definedFixture).apiReferences
        #expect(!definedImports.records.contains { $0.name == "_SMJobBless" && $0.kind == .importedSymbol })
        #expect(try PersistenceAPIReferenceCollector.collect(apiReferences: definedImports, analyzedPath: definedFixture.path).records.isEmpty)
    }

    @Test
    func crossSourceReferencesFailBeforeFilteringAndAfterTheOutputBound() throws {
        let root = try persistenceAPIFixtureRoot()
        defer { removePersistenceAPIFixture(root) }
        let fixture = try makePersistenceAPIFixture(root)
        let source = try MachOInspector.inspectStaticFeatures(fixture).apiReferences
        let original = try #require(source.records.first { $0.name == "_SMJobBless" && $0.kind == .importedSymbol })
        let foreignPath = root.appendingPathComponent("uninspected-other-artifact").path
        let foreignImport = persistenceAPIVariant(original, name: original.name, kind: original.kind, method: original.location.method, sourcePath: foreignPath)
        #expect(throws: PersistenceAPIReferenceError.self) {
            _ = try PersistenceAPIReferenceCollector.collect(apiReferences: persistenceAPIInput(source, records: [foreignImport]), analyzedPath: fixture.path)
        }
        let foreignRaw = persistenceAPIVariant(original, name: original.name, kind: .rawStringReference, method: .rawString, sourcePath: foreignPath)
        #expect(throws: PersistenceAPIReferenceError.self) {
            _ = try PersistenceAPIReferenceCollector.collect(apiReferences: persistenceAPIInput(source, records: [foreignRaw]), analyzedPath: fixture.path)
        }
        let beyondBound = Array(repeating: original, count: 65) + [foreignRaw]
        #expect(throws: PersistenceAPIReferenceError.self) {
            _ = try PersistenceAPIReferenceCollector.collect(apiReferences: persistenceAPIInput(source, records: beyondBound), analyzedPath: fixture.path)
        }
    }

    @Test
    func secondaryLocationsRemainInOneArtifactSliceAndSurviveExport() async throws {
        let root = try persistenceAPIFixtureRoot()
        defer { removePersistenceAPIFixture(root) }
        let fixture = try makePersistenceAPIReferenceLocationFixture(root)
        let finding = try await collectPersistenceAPIFinding(fixture)
        let features = try #require(finding.staticFeatures)
        let source = features.apiReferences
        let original = try #require(source.records.first {
            $0.name == "_SMJobBless" && $0.kind == .importedSymbol && $0.location.method == .dyldBindStream
        })
        let secondary = try #require(original.referenceLocation)
        let architecture = try #require(original.location.architecture)
        let sliceOffset = try #require(original.location.sliceOffset)
        #expect(secondary.sourcePath == original.location.sourcePath)
        #expect(secondary.architecture == architecture)
        #expect(secondary.sliceOffset == sliceOffset)
        let legacy = persistenceAPISecondaryVariant(original, referenceLocation: nil)
        let valid = try PersistenceAPIReferenceCollector.collect(
            apiReferences: persistenceAPIInput(source, records: [original, legacy]), analyzedPath: fixture.path
        )
        #expect(valid.records.compactMap(\.apiReference) == [original, legacy])
        let encoded = try JSONEncoder().encode(valid)
        #expect(try JSONDecoder().decode(StaticFeatureCollection<StaticPersistenceCharacteristic>.self, from: encoded) == valid)
        let exported = try ResultExporter.data(for: [finding], format: .json)
        let decodedFindings = try JSONDecoder().decode([ScanFinding].self, from: exported)
        let decodedFinding = try #require(decodedFindings.first)
        let decodedFeatures = try #require(decodedFinding.staticFeatures)
        #expect(decodedFeatures.persistenceCharacteristics.records.compactMap(\.apiReference).contains(original))

        let foreignPath = root.appendingPathComponent("uninspected-other-artifact").path
        let foreign = persistenceAPISecondaryLocation(secondary, sourcePath: foreignPath, architecture: architecture, sliceOffset: sliceOffset)
        let otherArchitecture = persistenceAPISecondaryLocation(secondary, sourcePath: fixture.path, architecture: "x86_64", sliceOffset: sliceOffset)
        let otherSlice = persistenceAPISecondaryLocation(secondary, sourcePath: fixture.path, architecture: architecture, sliceOffset: sliceOffset ^ 1)
        let invalidLocations: [(location: StaticEvidenceLocation, error: PersistenceAPIReferenceError)] = [
            (foreign, .secondarySourceMismatch(referenceIndex: 0, expectedPath: fixture.path, actualPath: foreignPath)),
            (otherArchitecture, .secondarySliceMismatch(referenceIndex: 0, primary: original.location, secondary: otherArchitecture)),
            (otherSlice, .secondarySliceMismatch(referenceIndex: 0, primary: original.location, secondary: otherSlice))
        ]
        for invalid in invalidLocations {
            let imported = persistenceAPISecondaryVariant(original, referenceLocation: invalid.location)
            #expect(throws: invalid.error) {
                _ = try PersistenceAPIReferenceCollector.collect(apiReferences: persistenceAPIInput(source, records: [imported]), analyzedPath: fixture.path)
            }
            let raw = persistenceAPIVariant(imported, name: original.name, kind: .rawStringReference, method: .rawString, sourcePath: fixture.path)
            #expect(throws: PersistenceAPIReferenceError.self) {
                _ = try PersistenceAPIReferenceCollector.collect(apiReferences: persistenceAPIInput(source, records: [raw]), analyzedPath: fixture.path)
            }
            let beyondBound = Array(repeating: original, count: 65) + [raw]
            #expect(throws: PersistenceAPIReferenceError.self) {
                _ = try PersistenceAPIReferenceCollector.collect(apiReferences: persistenceAPIInput(source, records: beyondBound), analyzedPath: fixture.path)
            }
        }
    }

    @Test
    func retainsIncompleteCoverageAndReportsItsOwnRecordBound() throws {
        let root = try persistenceAPIFixtureRoot()
        defer { removePersistenceAPIFixture(root) }
        let fixture = try makePersistenceAPIFixture(root)
        let source = try MachOInspector.inspectStaticFeatures(fixture).apiReferences
        let original = try #require(source.records.first { $0.name == "_SMJobBless" && $0.kind == .importedSymbol })
        let incompleteStates: [StaticCollectionState] = [.partial, .unsupported, .unavailable, .notCollected, .notApplicable]
        for state in incompleteStates {
            let records = state == .partial ? [original] : []
            let input = StaticFeatureCollection(state: state, reason: "Retained source collection coverage.", records: records,
                                                limitations: source.limitations, limits: source.limits)
            let result = try PersistenceAPIReferenceCollector.collect(apiReferences: input, analyzedPath: fixture.path)
            #expect(result.state == state)
            #expect(result.reason == input.reason)
            #expect(result.limitations.starts(with: input.limitations))
            #expect(result.limits.starts(with: input.limits))
        }
        let completeInput = StaticFeatureCollection(state: StaticCollectionState.complete, reason: nil,
            records: Array(repeating: original, count: 65), limitations: source.limitations, limits: source.limits)
        let bounded = try PersistenceAPIReferenceCollector.collect(apiReferences: completeInput, analyzedPath: fixture.path)
        #expect(bounded.state == .partial)
        #expect(bounded.records.count == 64)
        #expect(bounded.records.compactMap(\.apiReference) == Array(repeating: original, count: 64))
        #expect(bounded.reason != nil)
        #expect(bounded.limits.contains { $0.name == "persistence_api_references" && $0.value == 64 && $0.unit == .records })
        let exactlyAtBound = StaticFeatureCollection(state: StaticCollectionState.complete, reason: nil,
            records: Array(repeating: original, count: 64), limitations: source.limitations, limits: source.limits)
        #expect(try PersistenceAPIReferenceCollector.collect(apiReferences: exactlyAtBound, analyzedPath: fixture.path).state == .complete)
    }

    @Test
    func pipelineExportsOriginalAPIRecordsInJSONAndOneCSVFeatureCell() async throws {
        let root = try persistenceAPIFixtureRoot()
        defer { removePersistenceAPIFixture(root) }
        let compiledFixture = try makePersistenceAPIFixture(root)
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let samples = repository.appendingPathComponent(".build/static-feature-validation")
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        let fixture = samples.appendingPathComponent("persistence-api-fixture")
        // Atomic byte copying keeps repeated sample generation confined to the task's retained fixture.
        try await writeExport(to: fixture) { try Data(contentsOf: compiledFixture) }
        let finding = try await collectPersistenceAPIFinding(fixture)
        let features = try #require(finding.staticFeatures)
        #expect(features.schemaVersion == .v3)
        let projected = try PersistenceAPIReferenceCollector.collect(apiReferences: features.apiReferences, analyzedPath: features.analyzedPath)
        #expect(!projected.records.isEmpty)
        #expect(features.persistenceCharacteristics.records.filter { $0.kind == .apiReference } == projected.records)
        #expect(features.persistenceCharacteristics.records.allSatisfy { $0.location.sourcePath == finding.provenance.analyzedPath })
        let json = try ResultExporter.data(for: [finding], format: .json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == [finding])
        let csvData = try ResultExporter.data(for: [finding], format: .csv)
        let csv = try csvFixtureRecords(String(decoding: csvData, as: UTF8.self))
        let header = try #require(csv.first)
        let featureColumn = try #require(header.firstIndex(of: "static_features_json"))
        let featureRows = csv.dropFirst().filter { !$0[featureColumn].isEmpty }
        #expect(featureRows.count == 1)
        let featureRow = try #require(featureRows.first)
        let decoded = try JSONDecoder().decode(StaticFeatureSet.self, from: Data(featureRow[featureColumn].utf8))
        #expect(decoded.schemaVersion == features.schemaVersion)
        #expect(decoded.persistenceCharacteristics == features.persistenceCharacteristics)
        #expect(decoded.persistenceCharacteristics.records.filter { $0.kind == .apiReference } == projected.records)
        try await writeExport(to: samples.appendingPathComponent("persistence-api.json")) { json }
        try await writeExport(to: samples.appendingPathComponent("persistence-api.csv")) { csvData }
    }

    @Test
    func cancelledProjectionPropagatesCancellation() async throws {
        let input = StaticFeatureCollection<StaticAPIReference>(state: .notCollected, reason: "No API collection was requested.", records: [], limitations: [], limits: [])
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try PersistenceAPIReferenceCollector.collect(apiReferences: input, analyzedPath: "/not-opened/fixture")
        }
        do {
            _ = try await task.value
            Issue.record("Cancelled persistence API projection unexpectedly completed.")
        } catch is CancellationError { }
    }

    @Test
    func bundlePipelineCapsCombinedRecordsAfterTheCompleteConfigurationPrefix() async throws {
        let root = try persistenceAPIFixtureRoot()
        defer { removePersistenceAPIFixture(root) }
        let compiledFixture = try makePersistenceAPIFixture(root)
        let bundle = root.appendingPathComponent("Bounded.app")
        let executable = bundle.appendingPathComponent("Contents/MacOS/fixture")
        let agents = bundle.appendingPathComponent("Contents/Library/LaunchAgents")
        try FileManager.default.createDirectory(at: executable.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: compiledFixture, to: executable)
        let info = """
        <plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.hideouts.persistence-api-bundle-fixture</string>
        <key>CFBundleExecutable</key><string>fixture</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>
        """
        try Data(info.utf8).write(to: bundle.appendingPathComponent("Contents/Info.plist"))
        for index in 0..<102 {
            let declaration = """
            <plist version="1.0"><dict><key>Label</key><string>fixture.agent.\(index)</string>
            <key>Program</key><string>/not-opened/fixture</string>
            <key>ProgramArguments</key><array><string>/not-opened/fixture</string><string>--fixture</string></array>
            <key>RunAtLoad</key><false/><key>KeepAlive</key><true/></dict></plist>
            """
            try Data(declaration.utf8).write(to: agents.appendingPathComponent(String(format: "%03d.plist", index)))
        }
        let configuration = try PersistenceStaticFeatureCollector.inspect(sourceURL: bundle, kind: .bundle, analyzedPath: executable.path)
        #expect(configuration.state == .complete)
        #expect(configuration.records.count == 510)
        let finding = try await collectPersistenceAPIFinding(bundle)
        let features = try #require(finding.staticFeatures)
        let api = try PersistenceAPIReferenceCollector.collect(apiReferences: features.apiReferences, analyzedPath: features.analyzedPath)
        #expect(api.records.count > 2)
        let combined = features.persistenceCharacteristics
        #expect(combined.records.count == 512)
        #expect(Array(combined.records.prefix(510)) == configuration.records)
        #expect(Array(combined.records.suffix(2)) == Array(api.records.prefix(2)))
        #expect(combined.state == .partial)
        #expect(combined.reason?.contains("Combined persistence collection") == true)
        #expect(combined.reason?.contains("512") == true)
        #expect(combined.limits.contains { $0.name == "combined_persistence_records" && $0.value == 512 && $0.unit == .records })
    }
}

private func persistenceAPIFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-persistence-API-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removePersistenceAPIFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Persistence API fixture cleanup failed: \(error.localizedDescription)") }
}

/// The fixture retains typed function addresses and is never executed or registered as a job.
private func makePersistenceAPIFixture(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("imports.c")
    let sourceText = """
    #include <ServiceManagement/ServiceManagement.h>
    Boolean (* volatile fixtureLoginItem)(CFStringRef, Boolean) = &SMLoginItemSetEnabled;
    Boolean (* volatile fixtureJobBless)(CFStringRef, CFStringRef, AuthorizationRef, CFErrorRef *) = &SMJobBless;
    Boolean (* volatile fixtureJobSubmit)(CFStringRef, CFDictionaryRef, AuthorizationRef, CFErrorRef *) = &SMJobSubmit;
    Boolean (* volatile fixtureJobRemove)(CFStringRef, CFStringRef, AuthorizationRef, Boolean, CFErrorRef *) = &SMJobRemove;
    int main(void) {
        return fixtureLoginItem == 0 || fixtureJobBless == 0 || fixtureJobSubmit == 0 || fixtureJobRemove == 0;
    }
    """
    try Data(sourceText.utf8).write(to: source)
    let arm64 = root.appendingPathComponent("imports.arm64")
    let x86 = root.appendingPathComponent("imports.x86_64")
    let universal = root.appendingPathComponent("imports.universal")
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    for architecture in ["arm64", "x86_64"] {
        let output = architecture == "arm64" ? arm64 : x86
        try compilePersistenceAPIFixture(source: source, output: output, architecture: architecture)
    }
    _ = try runFixtureTool(executable: xcrun, arguments: ["lipo", "-create", arm64.path, x86.path, "-output", universal.path])
    return universal
}

private func makeDefinedPersistenceAPIFixture(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("defined.c")
    let output = root.appendingPathComponent("defined.arm64")
    let sourceText = """
    #include <ServiceManagement/ServiceManagement.h>
    Boolean SMJobBless(CFStringRef domain, CFStringRef label, AuthorizationRef authorization, CFErrorRef *error) {
        return 0;
    }
    Boolean (* volatile fixtureDefinition)(CFStringRef, CFStringRef, AuthorizationRef, CFErrorRef *) = &SMJobBless;
    int main(void) { return fixtureDefinition == 0; }
    """
    try Data(sourceText.utf8).write(to: source)
    try compilePersistenceAPIFixture(source: source, output: output, architecture: "arm64")
    return output
}

/// Ordinary bindings retain an actual file-backed reference slot; the target is never executed.
private func makePersistenceAPIReferenceLocationFixture(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("reference-location.c")
    let output = root.appendingPathComponent("reference-location.arm64")
    let sourceText = """
    #include <ServiceManagement/ServiceManagement.h>
    Boolean (* volatile fixtureJobBless)(CFStringRef, CFStringRef, AuthorizationRef, CFErrorRef *) = &SMJobBless;
    int main(void) { return fixtureJobBless == 0; }
    """
    try Data(sourceText.utf8).write(to: source)
    _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: [
        "clang", "-target", "arm64-apple-macos14.0", "-O0", source.path,
        "-framework", "ServiceManagement", "-Wl,-no_fixup_chains", "-o", output.path
    ])
    return output
}

private func compilePersistenceAPIFixture(source: URL, output: URL, architecture: String) throws {
    _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: [
        "clang", "-target", "\(architecture)-apple-macos14.0", "-O0", source.path,
        "-framework", "ServiceManagement", "-o", output.path
    ])
}

private func persistenceAPIVariant(_ source: StaticAPIReference, name: String, kind: StaticAPIReferenceKind,
                                   method: StaticEvidenceMethod, sourcePath: String) -> StaticAPIReference {
    StaticAPIReference(name: name, kind: kind, location: StaticEvidenceLocation(
        sourcePath: sourcePath, architecture: source.location.architecture, sliceOffset: source.location.sliceOffset,
        fileOffset: source.location.fileOffset, byteCount: source.location.byteCount,
        propertyListKey: source.location.propertyListKey, method: method
    ), referenceLocation: source.referenceLocation)
}

private func persistenceAPIInput(_ source: StaticFeatureCollection<StaticAPIReference>, records: [StaticAPIReference]) -> StaticFeatureCollection<StaticAPIReference> {
    StaticFeatureCollection(state: source.state, reason: source.reason, records: records, limitations: source.limitations, limits: source.limits)
}

private func persistenceAPISecondaryVariant(_ source: StaticAPIReference, referenceLocation: StaticEvidenceLocation?) -> StaticAPIReference {
    StaticAPIReference(name: source.name, kind: source.kind, location: source.location, referenceLocation: referenceLocation)
}

private func persistenceAPISecondaryLocation(_ source: StaticEvidenceLocation, sourcePath: String,
                                           architecture: String?, sliceOffset: UInt64?) -> StaticEvidenceLocation {
    StaticEvidenceLocation(sourcePath: sourcePath, architecture: architecture, sliceOffset: sliceOffset,
        fileOffset: source.fileOffset, byteCount: source.byteCount, propertyListKey: source.propertyListKey, method: source.method)
}

private func collectPersistenceAPIFinding(_ url: URL) async throws -> ScanFinding {
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
        case .cancelled: Issue.record("Persistence API fixture scan was cancelled.")
        }
    }
    #expect(completed)
    #expect(issues.isEmpty)
    let selected = findings.filter { $0.path == url.path }
    #expect(selected.count == 1)
    return try #require(selected.first)
}
