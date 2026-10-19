import CryptoKit
import Foundation
import Testing
@testable import EntitlementLens

struct ModernServiceManagementIntegrationTests {
    @Test
    func nativeOrdinaryAndSupportedChainedClassesMatchExactOracleSlots() throws {
        let root = try modernServiceManagementRoot()
        defer { removeModernServiceManagementRoot(root) }
        let source = try modernServiceManagementSource(root)
        let authentication = try modernServiceManagementAuthenticationSource(root)
        let variants: [(name: String, target: String, linker: String, format: UInt16?, assembly: [URL])] = [
            ("ordinary", "arm64-apple-macos14.0", "-no_fixup_chains", nil, []),
            ("format2", "arm64-apple-macos11.0", "-fixup_chains", 2, []),
            ("format6", "arm64-apple-macos14.0", "-fixup_chains", 6, []),
            ("format12", "arm64e-apple-macos14.0", "-fixup_chains", 12, [authentication])
        ]
        for variant in variants {
            let fixture = root.appendingPathComponent(variant.name)
            try compileModernServiceManagement(sourceFiles: [source] + variant.assembly, target: variant.target,
                linker: variant.linker, output: fixture)
            let bytes = try Data(contentsOf: fixture)
            let inspection = try MachOInspector.inspectStaticFeatures(fixture)
            let slice = try #require(inspection.architectures.records.first?.slice)
            let layout = try modernServiceManagementLayout(bytes, slice: slice)
            let oracle = try modernServiceManagementOracle(fixture)
            if let format = variant.format { #expect(oracle.contains("pointer_format:  \(format) (")) }
            else { #expect(!inspection.loadCommands.records.contains { $0.commandID == 0x8000_0034 }) }
            let nativeSlots = try modernServiceManagementOracleSlots(oracle, layout: layout, slice: slice)
            let classes = inspection.apiReferences.records.filter { $0.kind == .objectiveCClass && $0.name == "SMAppService" }
            #expect(classes.count == (variant.format == 12 ? 2 : 1))
            #expect(Set(classes.compactMap { $0.referenceLocation?.fileOffset }) == Set(nativeSlots))
            #expect(inspection.apiReferences.records.contains { $0.kind == .objectiveCSelector && $0.name == "mainAppService" })
            #expect(inspection.apiReferences.records.contains { $0.kind == .objectiveCSelector && $0.name == "registerAndReturnError:" })
            #expect(inspection.apiReferences.records.contains { $0.kind == .importedSymbol && $0.name == "_OBJC_CLASS_$_SMAppService" })
            if variant.format == nil {
                // Hosted Xcode 26.4's dyld_info misattributes the second consecutive ordinary bind.
                // LLVM's independent bind table verifies the literal import without changing the fixture.
                let bindings = try modernServiceManagementOrdinaryBindOracle(fixture)
                let literalRows = bindings.split(separator: "\n").filter { line in
                    let fields = line.split(whereSeparator: \.isWhitespace)
                    return fields.count == 7 && fields[0] == "__DATA" && fields[1] == "__data"
                        && fields[3] == "pointer" && fields[4] == "0" && fields[5] == "ServiceManagement"
                        && fields[6] == "_OBJC_CLASS_$_SMAppService"
                }
                #expect(literalRows.count == 1, "Ordinary literal class-import bindings:\n\(bindings)")
                let literalRow = try #require(literalRows.first)
                let literalSlot = try modernServiceManagementOrdinaryLiteralSlot(literalRow, layout: layout, slice: slice)
                #expect(!nativeSlots.contains(literalSlot))
                #expect(Set(try modernServiceManagementOracleSlots(bindings, layout: layout, slice: slice)) == Set(nativeSlots))
            } else {
                #expect(oracle.split(separator: "\n").contains { $0.contains("__data") && $0.contains("_OBJC_CLASS_$_SMAppService") },
                    "Literal class-import storage for \(variant.name). Native fixture oracle:\n\(oracle)")
            }
            if variant.format == 12 {
                #expect(oracle.split(separator: "\n").contains {
                    $0.contains("__AUTH_CONST") && $0.contains("__objc_classrefs") && $0.contains("auth-bind")
                        && $0.contains("_OBJC_CLASS_$_SMAppService (div=0x1234 ad=1 key=DA)")
                })
            }
            for reference in classes {
                try verifyModernServiceManagementEvidence(reference, bytes: bytes, url: fixture, slice: slice)
                let importMethod: StaticEvidenceMethod = variant.format == nil ? .dyldBindStream : .chainedFixupImports
                #expect(inspection.apiReferences.records.contains {
                    $0.name == "_OBJC_CLASS_$_SMAppService" && $0.location.method == importMethod
                        && $0.location.fileOffset.map { $0 + UInt64("_OBJC_CLASS_$_".utf8.count) } == reference.location.fileOffset
                })
            }
            let projected = try PersistenceAPIReferenceCollector.collect(apiReferences: inspection.apiReferences, analyzedPath: fixture.path)
            #expect(projected.records.compactMap(\.apiReference).filter { $0.kind == .objectiveCClass } == classes)
            #expect(projected.records.contains { $0.apiReference?.name == "_SMLoginItemSetEnabled" })
            #expect(projected.records.allSatisfy {
                $0.kind == .apiReference && $0.association == .selectedArtifact && $0.declarationKey == nil
                    && $0.declarationValue == nil && $0.declaredIdentifier == nil && $0.declaredExecutablePaths.isEmpty
                    && $0.bundleProgramCandidatePath == nil && $0.sourceSHA256 == nil
                    && $0.apiReference?.location == $0.location
            })
            #expect(projected.state == inspection.apiReferences.state)
            #expect(projected.reason == inspection.apiReferences.reason)
        }
    }

    @Test
    func nativeSelectorsAndLiteralClassImportsWithoutClassSlotsDoNotProject() throws {
        let root = try modernServiceManagementRoot()
        defer { removeModernServiceManagementRoot(root) }
        let source = root.appendingPathComponent("decoys.m")
        let text = """
        #import <ServiceManagement/ServiceManagement.h>
        #import <Foundation/Foundation.h>
        extern Class fixture_sm_import __asm("_OBJC_CLASS_$_SMAppService");
        Class *fixture_sm_import_address __attribute__((section("__DATA,__data"))) = &fixture_sm_import;
        const char *fixture_raw_class = "SMAppService";
        const char *fixture_raw_import = "_OBJC_CLASS_$_SMAppService";
        SEL fixture_first_selector(void) { return @selector(mainAppService); }
        SEL fixture_second_selector(void) { return @selector(registerAndReturnError:); }
        Boolean (* volatile fixture_legacy)(CFStringRef, Boolean) = &SMLoginItemSetEnabled;
        int main(void) { return 0; }
        """
        try Data(text.utf8).write(to: source)
        let fixture = root.appendingPathComponent("decoys")
        try compileModernServiceManagement(sourceFiles: [source], target: "arm64-apple-macos14.0", linker: "-fixup_chains", output: fixture)
        let inspection = try MachOInspector.inspectStaticFeatures(fixture)
        #expect(inspection.apiReferences.records.contains { $0.name == "_OBJC_CLASS_$_SMAppService" && $0.kind == .importedSymbol })
        #expect(inspection.apiReferences.records.contains { $0.name == "mainAppService" && $0.kind == .objectiveCSelector })
        #expect(inspection.apiReferences.records.contains { $0.name == "registerAndReturnError:" && $0.kind == .objectiveCSelector })
        #expect(!inspection.apiReferences.records.contains { $0.name == "SMAppService" && $0.kind == .objectiveCClass })
        let oracle = try modernServiceManagementOracle(fixture)
        #expect(oracle.split(separator: "\n").contains { $0.contains("__data") && $0.contains("_OBJC_CLASS_$_SMAppService") })
        #expect(!oracle.split(separator: "\n").contains { $0.contains("__objc_classrefs") && $0.contains("_OBJC_CLASS_$_SMAppService") })
        let projected = try PersistenceAPIReferenceCollector.collect(apiReferences: inspection.apiReferences, analyzedPath: fixture.path)
        #expect(projected.records.allSatisfy { $0.apiReference?.name == "_SMLoginItemSetEnabled" })
        #expect(!projected.records.isEmpty)
    }

    @Test
    func incompleteChainedSliceKeepsOrdinaryModernReferencesAndLiteralImports() throws {
        let root = try modernServiceManagementRoot()
        defer { removeModernServiceManagementRoot(root) }
        let fixture = try modernServiceManagementUniversal(root)
        let bytes = try Data(contentsOf: fixture)
        let original = try MachOInspector.inspectStaticFeatures(fixture)
        let slice = try #require(original.architectures.records.first { $0.slice.architecture == "arm64e" }?.slice)
        let ordinarySlice = try #require(original.architectures.records.first { $0.slice.architecture == "x86_64" }?.slice)
        let ordinaryNames = original.apiReferences.records.filter { $0.location.sliceOffset == ordinarySlice.fileOffset }
        let info = try #require(try modernServiceManagementLayout(bytes, slice: slice).sections.first { $0.sectionName == "__objc_imageinfo" })
        let offset = try #require(Int(exactly: slice.fileOffset + info.fileOffset + 4))
        let flags = try modernServiceManagementUInt32(bytes, offset: offset)
        // This byte-mutated native fixture declares optimized image information. It is not native linker output.
        var changed = bytes
        let newFlags = flags | 0x80
        for index in 0..<4 { changed[offset + index] = UInt8(truncatingIfNeeded: newFlags >> (index * 8)) }
        let mutated = root.appendingPathComponent("mutated-optimized-arm64e")
        try changed.write(to: mutated)
        let inspection = try MachOInspector.inspectStaticFeatures(mutated)
        #expect(inspection.apiReferences.state == .partial)
        #expect(inspection.apiReferences.reason?.localizedCaseInsensitiveContains("unsupported") == true)
        #expect(!inspection.apiReferences.records.contains {
            $0.kind == .objectiveCClass && $0.name == "SMAppService" && $0.location.sliceOffset == slice.fileOffset
        })
        #expect(inspection.apiReferences.records.contains {
            $0.kind == .importedSymbol && $0.name == "_OBJC_CLASS_$_SMAppService"
                && $0.location.method == .chainedFixupImports && $0.location.sliceOffset == slice.fileOffset
        })
        #expect(inspection.apiReferences.records.filter { $0.location.sliceOffset == ordinarySlice.fileOffset }.map(\.name) == ordinaryNames.map(\.name))
        let projected = try PersistenceAPIReferenceCollector.collect(apiReferences: inspection.apiReferences, analyzedPath: mutated.path)
        let modern = projected.records.compactMap(\.apiReference).filter { $0.kind == .objectiveCClass }
        #expect(modern.count == 1)
        #expect(modern.first?.name == "SMAppService")
        #expect(modern.first?.location.architecture == "x86_64")
        #expect(projected.records.contains { $0.apiReference?.name == "_SMLoginItemSetEnabled" && $0.location.sliceOffset == slice.fileOffset })
        #expect(projected.state == .partial)
        #expect(projected.reason == inspection.apiReferences.reason)
    }

    @Test
    func malformedModernEvidenceAndExcludedSourcesFailBeforeSharedOutputLimit() async throws {
        let root = try modernServiceManagementRoot()
        defer { removeModernServiceManagementRoot(root) }
        let source = try modernServiceManagementSource(root)
        let fixture = root.appendingPathComponent("boundaries")
        try compileModernServiceManagement(sourceFiles: [source], target: "arm64-apple-macos14.0", linker: "-fixup_chains", output: fixture)
        let input = try MachOInspector.inspectStaticFeatures(fixture).apiReferences
        let original = try #require(input.records.first { $0.kind == .objectiveCClass && $0.name == "SMAppService" })
        let legacy = try #require(input.records.first { $0.kind == .importedSymbol && $0.name == "_SMLoginItemSetEnabled" })
        let primary = original.location
        let slot = try #require(original.referenceLocation)
        let primaryOffset = try #require(primary.fileOffset)
        let slotOffset = try #require(slot.fileOffset)
        let exclusions = [
            StaticAPIReference(name: original.name, kind: .rawStringReference, location: primary, referenceLocation: slot),
            StaticAPIReference(name: original.name, kind: .objectiveCSelector, location: primary, referenceLocation: slot),
            StaticAPIReference(name: original.name, kind: .dyldBindingSymbol, location: primary, referenceLocation: slot),
            StaticAPIReference(name: "SMAppServiceExtra", kind: .objectiveCClass, location: primary, referenceLocation: slot),
            StaticAPIReference(name: original.name, kind: .objectiveCClass,
                location: modernServiceManagementLocation(primary, architecture: primary.architecture, sliceOffset: primary.sliceOffset,
                    fileOffset: primary.fileOffset, byteCount: primary.byteCount, propertyListKey: nil, method: .symbolTable), referenceLocation: slot)
        ]
        #expect(try PersistenceAPIReferenceCollector.collect(apiReferences: modernServiceManagementInput(input, records: exclusions), analyzedPath: fixture.path).records.isEmpty)
        let invalidPrimaries = [
            modernServiceManagementLocation(primary, architecture: primary.architecture, sliceOffset: primary.sliceOffset, fileOffset: nil, byteCount: 13, propertyListKey: nil, method: .objectiveCMetadata),
            modernServiceManagementLocation(primary, architecture: primary.architecture, sliceOffset: primary.sliceOffset, fileOffset: primaryOffset, byteCount: 12, propertyListKey: nil, method: .objectiveCMetadata),
            modernServiceManagementLocation(primary, architecture: primary.architecture, sliceOffset: primary.sliceOffset, fileOffset: UInt64.max - 10, byteCount: 13, propertyListKey: nil, method: .objectiveCMetadata),
            modernServiceManagementLocation(primary, architecture: primary.architecture, sliceOffset: primary.sliceOffset, fileOffset: primaryOffset, byteCount: 13, propertyListKey: "unexpected", method: .objectiveCMetadata)
        ]
        let invalidSlots = [
            modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: slot.sliceOffset, fileOffset: nil, byteCount: 8, propertyListKey: nil, method: .objectiveCMetadata),
            modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: slot.sliceOffset, fileOffset: slotOffset, byteCount: 7, propertyListKey: nil, method: .objectiveCMetadata),
            modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: slot.sliceOffset, fileOffset: slotOffset + 1, byteCount: 8, propertyListKey: nil, method: .objectiveCMetadata),
            modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: slot.sliceOffset, fileOffset: UInt64.max - 7, byteCount: 8, propertyListKey: nil, method: .objectiveCMetadata),
            modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: slot.sliceOffset, fileOffset: slotOffset, byteCount: 8, propertyListKey: nil, method: .chainedFixupPointer),
            modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: slot.sliceOffset, fileOffset: slotOffset, byteCount: 8, propertyListKey: "unexpected", method: .objectiveCMetadata)
        ]
        var invalid = invalidPrimaries.map { StaticAPIReference(name: original.name, kind: .objectiveCClass, location: $0, referenceLocation: slot) }
            + invalidSlots.map { StaticAPIReference(name: original.name, kind: .objectiveCClass, location: primary, referenceLocation: $0) }
            + [StaticAPIReference(name: original.name, kind: .objectiveCClass, location: primary, referenceLocation: nil)]
        for architecture: String? in [nil, ""] {
            let name = modernServiceManagementLocation(primary, architecture: architecture, sliceOffset: primary.sliceOffset, fileOffset: primaryOffset, byteCount: 13, propertyListKey: nil, method: .objectiveCMetadata)
            let pointer = modernServiceManagementLocation(slot, architecture: architecture, sliceOffset: slot.sliceOffset, fileOffset: slotOffset, byteCount: 8, propertyListKey: nil, method: .objectiveCMetadata)
            invalid.append(StaticAPIReference(name: original.name, kind: .objectiveCClass, location: name, referenceLocation: pointer))
        }
        let missingSlicePrimary = modernServiceManagementLocation(primary, architecture: primary.architecture, sliceOffset: nil, fileOffset: primaryOffset, byteCount: 13, propertyListKey: nil, method: .objectiveCMetadata)
        let missingSliceSlot = modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: nil, fileOffset: slotOffset, byteCount: 8, propertyListKey: nil, method: .objectiveCMetadata)
        invalid.append(StaticAPIReference(name: original.name, kind: .objectiveCClass, location: missingSlicePrimary, referenceLocation: missingSliceSlot))
        let beforeSlice = modernServiceManagementLocation(primary, architecture: primary.architecture, sliceOffset: 1_024, fileOffset: 1_023, byteCount: 13, propertyListKey: nil, method: .objectiveCMetadata)
        let afterSlice = modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: 1_024, fileOffset: 2_048, byteCount: 8, propertyListKey: nil, method: .objectiveCMetadata)
        invalid.append(StaticAPIReference(name: original.name, kind: .objectiveCClass, location: beforeSlice, referenceLocation: afterSlice))
        let overlappingName = modernServiceManagementLocation(primary, architecture: primary.architecture, sliceOffset: 0, fileOffset: 4_096, byteCount: 13, propertyListKey: nil, method: .objectiveCMetadata)
        let overlappingSlot = modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: 0, fileOffset: 4_096, byteCount: 8, propertyListKey: nil, method: .objectiveCMetadata)
        invalid.append(StaticAPIReference(name: original.name, kind: .objectiveCClass, location: overlappingName, referenceLocation: overlappingSlot))
        // These are typed record mutations from a real parsed reference; they test projection boundary validation.
        for reference in invalid {
            try expectInvalidModernServiceManagement(input: modernServiceManagementInput(input, records: [reference]), index: 0, path: fixture.path)
            try expectInvalidModernServiceManagement(input: modernServiceManagementInput(input, records: Array(repeating: original, count: 65) + [reference]), index: 65, path: fixture.path)
        }
        let otherSlice = modernServiceManagementLocation(slot, architecture: slot.architecture, sliceOffset: 1, fileOffset: slotOffset, byteCount: 8, propertyListKey: nil, method: .objectiveCMetadata)
        let mismatched = StaticAPIReference(name: original.name, kind: .objectiveCClass, location: primary, referenceLocation: otherSlice)
        #expect(throws: PersistenceAPIReferenceError.secondarySliceMismatch(referenceIndex: 0, primary: primary, secondary: otherSlice)) {
            _ = try PersistenceAPIReferenceCollector.collect(apiReferences: modernServiceManagementInput(input, records: [mismatched]), analyzedPath: fixture.path)
        }
        let foreignPath = root.appendingPathComponent("uninspected-other-artifact").path
        let foreign = StaticEvidenceLocation(sourcePath: foreignPath, architecture: primary.architecture, sliceOffset: primary.sliceOffset,
            fileOffset: primary.fileOffset, byteCount: primary.byteCount, propertyListKey: nil, method: .rawString)
        let excludedForeign = StaticAPIReference(name: original.name, kind: .rawStringReference, location: foreign, referenceLocation: nil)
        #expect(throws: PersistenceAPIReferenceError.sourceMismatch(referenceIndex: 65, expectedPath: fixture.path, actualPath: foreignPath)) {
            _ = try PersistenceAPIReferenceCollector.collect(apiReferences: modernServiceManagementInput(input, records: Array(repeating: original, count: 65) + [excludedForeign]), analyzedPath: fixture.path)
        }
        let shared = StaticFeatureCollection(state: StaticCollectionState.complete, reason: nil,
            records: Array(repeating: original, count: 33) + Array(repeating: legacy, count: 33), limitations: input.limitations, limits: input.limits)
        let bounded = try PersistenceAPIReferenceCollector.collect(apiReferences: shared, analyzedPath: fixture.path)
        #expect(bounded.state == .partial)
        #expect(bounded.records.count == 64)
        #expect(bounded.records.compactMap(\.apiReference) == Array(shared.records.prefix(64)))
        #expect(bounded.limits.contains { $0.name == "persistence_api_references" && $0.value == 64 })
        let partial = StaticFeatureCollection(state: StaticCollectionState.partial, reason: "Retained partial source coverage.", records: [original], limitations: input.limitations, limits: input.limits)
        let partialProjection = try PersistenceAPIReferenceCollector.collect(apiReferences: partial, analyzedPath: fixture.path)
        #expect(partialProjection.state == .partial && partialProjection.reason == partial.reason)
        #expect(partialProjection.records.compactMap(\.apiReference) == [original])
        let cancelled = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try PersistenceAPIReferenceCollector.collect(apiReferences: input, analyzedPath: fixture.path)
        }
        do { _ = try await cancelled.value; Issue.record("Cancelled modern ServiceManagement projection unexpectedly completed.") }
        catch is CancellationError { }
    }

    @Test
    func scannerExportsModernAndLegacyReferencesInStableV3JSONAndOneCSVFeatureCell() async throws {
        let root = try modernServiceManagementRoot()
        defer { removeModernServiceManagementRoot(root) }
        let compiled = try modernServiceManagementUniversal(root)
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let samples = repository.appendingPathComponent(".build/static-feature-validation")
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        let fixture = samples.appendingPathComponent("modern-servicemanagement")
        try Data(contentsOf: compiled).write(to: fixture, options: [.atomic])
        let finding = try await modernServiceManagementFinding(fixture)
        let features = try #require(finding.staticFeatures)
        #expect(features.schemaVersion == .v3)
        #expect(features.artifactSHA256 == finding.provenance.sha256)
        let bytes = try Data(contentsOf: fixture)
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        #expect(features.artifactSHA256 == digest)
        let projected = try PersistenceAPIReferenceCollector.collect(apiReferences: features.apiReferences, analyzedPath: fixture.path)
        #expect(features.persistenceCharacteristics.records.filter { $0.kind == .apiReference } == projected.records)
        let modern = projected.records.compactMap(\.apiReference).filter { $0.kind == .objectiveCClass }
        #expect(modern.count == 3)
        #expect(Set(modern.compactMap { $0.location.architecture }) == ["arm64e", "x86_64"])
        for reference in modern {
            let slice = try #require(features.architectures.records.first { $0.slice.fileOffset == reference.location.sliceOffset }?.slice)
            try verifyModernServiceManagementEvidence(reference, bytes: bytes, url: fixture, slice: slice)
        }
        let json = try ResultExporter.data(for: [finding], format: .json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == [finding])
        #expect(try ResultExporter.data(for: [finding], format: .json) == json)
        let csv = try ResultExporter.data(for: [finding], format: .csv)
        #expect(try ResultExporter.data(for: [finding], format: .csv) == csv)
        let rows = try csvFixtureRecords(String(decoding: csv, as: UTF8.self))
        let header = try #require(rows.first)
        let versionColumn = try #require(header.firstIndex(of: "static_features_schema_version"))
        let featureColumn = try #require(header.firstIndex(of: "static_features_json"))
        let populated = rows.dropFirst().filter { !$0[featureColumn].isEmpty }
        #expect(populated.count == 1)
        let row = try #require(populated.first)
        #expect(row.count == header.count && row[versionColumn] == "3")
        #expect(try JSONDecoder().decode(StaticFeatureSet.self, from: Data(row[featureColumn].utf8)) == features)
        let jsonURL = samples.appendingPathComponent("modern-servicemanagement.json")
        let csvURL = samples.appendingPathComponent("modern-servicemanagement.csv")
        try await writeExport(to: jsonURL) { json }
        try await writeExport(to: csvURL) { csv }
        #expect(try Data(contentsOf: jsonURL) == json)
        #expect(try Data(contentsOf: csvURL) == csv)
    }
}

private enum ModernServiceManagementFixtureError: LocalizedError {
    case range(Int, Int)
    case oracle(String)

    var errorDescription: String? {
        switch self {
        case let .range(offset, count): "Modern ServiceManagement fixture field at \(offset) requires \(count) unavailable bytes."
        case let .oracle(reason): "Apple dyld_info returned unexpected ServiceManagement fixture output: \(reason)"
        }
    }
}

private func modernServiceManagementRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-modern-ServiceManagement-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeModernServiceManagementRoot(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Modern ServiceManagement fixture cleanup failed: \(error.localizedDescription)") }
}

/// SDK-declared references are compiled but never executed; no service is registered or enabled.
private func modernServiceManagementSource(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("fixture.m")
    let text = """
    #import <ServiceManagement/ServiceManagement.h>
    #import <Foundation/Foundation.h>
    extern Class fixture_sm_import __asm("_OBJC_CLASS_$_SMAppService");
    Class *fixture_sm_import_address __attribute__((section("__DATA,__data"))) = &fixture_sm_import;
    const char *fixture_raw_class = "SMAppService";
    const char *fixture_raw_import = "_OBJC_CLASS_$_SMAppService";
    SEL fixture_standalone_selector(void) { return @selector(registerAndReturnError:); }
    API_AVAILABLE(macos(13.0)) id fixture_service(void) { return [SMAppService mainAppService]; }
    Boolean (* volatile fixture_legacy)(CFStringRef, Boolean) = &SMLoginItemSetEnabled;
    int main(void) { return 0; }
    """
    try Data(text.utf8).write(to: source)
    return source
}

private func modernServiceManagementAuthenticationSource(_ root: URL) throws -> URL {
    let assembly = root.appendingPathComponent("authenticated.s")
    let text = """
    .section __AUTH_CONST,__objc_classrefs,regular,no_dead_strip
    .p2align 3
    .quad _OBJC_CLASS_$_SMAppService@AUTH(da,4660,addr)
    """
    try Data(text.utf8).write(to: assembly)
    return assembly
}

private func compileModernServiceManagement(sourceFiles: [URL], target: String, linker: String, output: URL) throws {
    _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: ["clang", "-target", target]
        + sourceFiles.map(\.path) + ["-framework", "Foundation", "-framework", "ServiceManagement", "-Wl," + linker, "-o", output.path])
}

private func modernServiceManagementUniversal(_ root: URL) throws -> URL {
    let source = try modernServiceManagementSource(root)
    let authentication = try modernServiceManagementAuthenticationSource(root)
    let arm64e = root.appendingPathComponent("fixture.arm64e")
    let x86 = root.appendingPathComponent("fixture.x86_64")
    try compileModernServiceManagement(sourceFiles: [source, authentication], target: "arm64e-apple-macos14.0", linker: "-fixup_chains", output: arm64e)
    try compileModernServiceManagement(sourceFiles: [source], target: "x86_64-apple-macos14.0", linker: "-no_fixup_chains", output: x86)
    let universal = root.appendingPathComponent("fixture.universal")
    _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: ["lipo", "-create", arm64e.path, x86.path, "-output", universal.path])
    return universal
}

private func modernServiceManagementLayout(_ bytes: Data, slice: MachOSlice) throws -> MachOObjectiveCLayout {
    let start = try #require(Int(exactly: slice.fileOffset))
    let count = try modernServiceManagementUInt32(bytes, offset: start + 16)
    let commandBytes = try modernServiceManagementUInt32(bytes, offset: start + 20)
    try modernServiceManagementRange(bytes, offset: start + 32, count: Int(commandBytes))
    return try MachOObjectiveCLayoutParser.parse(commands: Data(bytes[(start + 32)..<(start + 32 + Int(commandBytes))]),
        commandCount: count, slice: slice, headerSize: 32, is64Bit: true, byteOrder: .little)
}

private func modernServiceManagementOracle(_ url: URL) throws -> String {
    let output = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: ["dyld_info", "-fixup_chains", "-fixups", url.path])
    return try #require(String(data: output.standardOutput, encoding: .utf8))
}

private func modernServiceManagementOrdinaryBindOracle(_ url: URL) throws -> String {
    let output = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: ["llvm-objdump", "--macho", "--bind", url.path])
    return try #require(String(data: output.standardOutput, encoding: .utf8))
}

private func modernServiceManagementOracleSlots(_ oracle: String, layout: MachOObjectiveCLayout, slice: MachOSlice) throws -> [UInt64] {
    try oracle.split(separator: "\n").filter { $0.contains("__objc_classrefs") && $0.contains("_OBJC_CLASS_$_SMAppService") }.map { line in
        let fields = line.split(whereSeparator: \.isWhitespace)
        guard fields.count >= 5, fields[2].hasPrefix("0x"), let address = UInt64(fields[2].dropFirst(2), radix: 16) else {
            throw ModernServiceManagementFixtureError.oracle("A class-reference row lacks its virtual address: \(line)")
        }
        let matches = layout.sections.filter {
            $0.segmentName == fields[0] && $0.sectionName == fields[1] && address >= $0.virtualAddress
                && address - $0.virtualAddress < $0.byteCount
        }
        guard matches.count == 1, let section = matches.first, 8 <= section.byteCount - (address - section.virtualAddress) else {
            throw ModernServiceManagementFixtureError.oracle("A class-reference address has no unique eight-byte section mapping: \(line)")
        }
        return slice.fileOffset + section.fileOffset + address - section.virtualAddress
    }
}

/// LLVM supplies the __data section attribution; the layout retains its enclosing file-backed segment.
private func modernServiceManagementOrdinaryLiteralSlot(_ line: Substring, layout: MachOObjectiveCLayout, slice: MachOSlice) throws -> UInt64 {
    let fields = line.split(whereSeparator: \.isWhitespace)
    guard fields.count == 7, fields[2].hasPrefix("0x"), let address = UInt64(fields[2].dropFirst(2), radix: 16) else {
        throw ModernServiceManagementFixtureError.oracle("A literal-import row lacks its virtual address: \(line)")
    }
    let matches = layout.segments.filter {
        $0.name == fields[0] && address >= $0.virtualAddress && $0.fileSize >= 8 && $0.virtualSize >= 8
            && address - $0.virtualAddress <= $0.fileSize - 8 && address - $0.virtualAddress <= $0.virtualSize - 8
    }
    guard matches.count == 1, let segment = matches.first else {
        throw ModernServiceManagementFixtureError.oracle("A literal-import address has no unique eight-byte segment mapping: \(line)")
    }
    return slice.fileOffset + segment.fileOffset + address - segment.virtualAddress
}

private func verifyModernServiceManagementEvidence(_ reference: StaticAPIReference, bytes: Data, url: URL, slice: MachOSlice) throws {
    #expect(reference.kind == .objectiveCClass && reference.name == "SMAppService")
    let name = reference.location
    #expect(name.method == .objectiveCMetadata && name.sourcePath == url.path)
    #expect(name.architecture == slice.architecture && name.sliceOffset == slice.fileOffset)
    let nameOffset = try #require(name.fileOffset)
    let nameCount = try #require(name.byteCount)
    let nameIndex = try #require(Int(exactly: nameOffset))
    let nameLength = try #require(Int(exactly: nameCount))
    try modernServiceManagementRange(bytes, offset: nameIndex, count: nameLength)
    #expect(nameCount == 13)
    #expect(Data(bytes[nameIndex..<(nameIndex + nameLength)]) == Data("SMAppService\0".utf8))
    let slot = try #require(reference.referenceLocation)
    #expect(slot.method == .objectiveCMetadata && slot.sourcePath == url.path)
    #expect(slot.architecture == slice.architecture && slot.sliceOffset == slice.fileOffset)
    #expect(slot.byteCount == 8)
    let slotOffset = try #require(slot.fileOffset)
    #expect(slotOffset >= slice.fileOffset && slotOffset - slice.fileOffset <= slice.fileSize - 8)
    #expect((slotOffset - slice.fileOffset) % 8 == 0)
    let slotIndex = try #require(Int(exactly: slotOffset))
    try modernServiceManagementRange(bytes, offset: slotIndex, count: 8)
}

private func modernServiceManagementInput(_ source: StaticFeatureCollection<StaticAPIReference>, records: [StaticAPIReference]) -> StaticFeatureCollection<StaticAPIReference> {
    StaticFeatureCollection(state: source.state, reason: source.reason, records: records, limitations: source.limitations, limits: source.limits)
}

private func modernServiceManagementLocation(_ source: StaticEvidenceLocation, architecture: String?, sliceOffset: UInt64?,
    fileOffset: UInt64?, byteCount: UInt64?, propertyListKey: String?, method: StaticEvidenceMethod) -> StaticEvidenceLocation {
    StaticEvidenceLocation(sourcePath: source.sourcePath, architecture: architecture, sliceOffset: sliceOffset,
        fileOffset: fileOffset, byteCount: byteCount, propertyListKey: propertyListKey, method: method)
}

private func expectInvalidModernServiceManagement(input: StaticFeatureCollection<StaticAPIReference>, index: Int, path: String) throws {
    do {
        _ = try PersistenceAPIReferenceCollector.collect(apiReferences: input, analyzedPath: path)
        Issue.record("Malformed SMAppService metadata unexpectedly projected.")
    } catch let PersistenceAPIReferenceError.invalidClassReference(actualIndex, reason) {
        #expect(actualIndex == index)
        #expect(!reason.isEmpty)
    }
}

private func modernServiceManagementFinding(_ url: URL) async throws -> ScanFinding {
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
        case .cancelled: Issue.record("Modern ServiceManagement fixture scan was cancelled.")
        }
    }
    #expect(completed && issues.isEmpty)
    let selected = findings.filter { $0.path == url.path }
    #expect(selected.count == 1)
    return try #require(selected.first)
}

private func modernServiceManagementRange(_ bytes: Data, offset: Int, count: Int) throws {
    guard offset >= 0, count >= 0, offset <= bytes.count, count <= bytes.count - offset else {
        throw ModernServiceManagementFixtureError.range(offset, count)
    }
}

private func modernServiceManagementUInt32(_ bytes: Data, offset: Int) throws -> UInt32 {
    try modernServiceManagementRange(bytes, offset: offset, count: 4)
    return (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[offset + $1]) << ($1 * 8) }
}
