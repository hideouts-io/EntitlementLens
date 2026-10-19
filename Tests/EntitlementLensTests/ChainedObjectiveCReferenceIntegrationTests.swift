import Foundation
import Testing
@testable import EntitlementLens

struct ChainedObjectiveCReferenceIntegrationTests {
    @Test
    func nativeUniversalPointerFormatsMatchApplesFixupsAndMetadataSections() throws {
        let root = try chainedObjectiveCFixtureRoot()
        defer { removeChainedObjectiveCFixture(root) }
        let versions: [(deployment: String, pointerFormat: UInt16)] = [("11.0", 2), ("14.0", 6)]
        for version in versions {
            let fixtureRoot = root.appendingPathComponent(version.deployment)
            try FileManager.default.createDirectory(at: fixtureRoot, withIntermediateDirectories: false)
            let source = try chainedObjectiveCFixtureSource(fixtureRoot)
            let url = try compileChainedObjectiveCFixture(root: fixtureRoot, sourceFiles: [source], deployment: version.deployment)
            let bytes = try Data(contentsOf: url)
            let inspection = try MachOInspector.inspectStaticFeatures(url)
            #expect(Set(inspection.architectures.records.map { $0.slice.architecture }) == ["arm64", "x86_64"])
            for slice in inspection.architectures.records.map(\.slice) {
                let input = try chainedObjectiveCInput(url: url, bytes: bytes, slice: slice)
                let pointers = try collectChainedObjectiveCFixturePointers(input, containerSize: UInt64(bytes.count))
                #expect(pointers.state == .complete)
                #expect(pointers.records.count == 7)
                #expect(pointers.records.allSatisfy { $0.location.method == .chainedFixupPointer })
                let selectors = try #require(input.layout.sections.first { $0.sectionName == "__objc_selrefs" })
                let classes = try #require(input.layout.sections.first { $0.sectionName == "__objc_classrefs" })
                let oracle = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: [
                    "dyld_info", "-arch", slice.architecture, "-fixup_chains", "-fixups",
                    "-section", selectors.segmentName, selectors.sectionName,
                    "-section", classes.segmentName, classes.sectionName, url.path
                ])
                let oracleText = try #require(String(data: oracle.standardOutput, encoding: .utf8))
                #expect(oracleText.contains("pointer_format:  \(version.pointerFormat) ("))
                let nativeFixups = try nativeChainedObjectiveCFixups(oracle.standardOutput)
                #expect(nativeFixups.count == pointers.records.count)
                for fixup in nativeFixups {
                    let fileOffset = try chainedObjectiveCNativeFileOffset(fixup.virtualAddress, layout: input.layout, slice: slice)
                    let pointer = try #require(pointers.records.first { $0.location.fileOffset == fileOffset })
                    #expect(pointer.location.sourcePath == url.path)
                    #expect(pointer.location.architecture == slice.architecture)
                    #expect(pointer.location.sliceOffset == slice.fileOffset)
                    #expect(pointer.location.byteCount == 8)
                    switch (fixup.value, pointer.value) {
                    case let (.rebase(nativeAddress), .rebase(collectedAddress)):
                        #expect(nativeAddress == collectedAddress)
                    case let (.bind(nativeName), .bind(reference, addend)):
                        #expect(nativeName == reference.name)
                        #expect(addend == 0)
                        #expect(reference.location.method == .chainedFixupImports)
                        #expect(reference.referenceLocation == nil)
                    default:
                        Issue.record("A native chained fixup does not match its collected pointer kind.")
                    }
                }
                let rows = try nativeChainedObjectiveCSectionRows(oracle.standardOutput)
                let records = inspection.apiReferences.records.filter { $0.location.sliceOffset == slice.fileOffset }
                let metadata = records.filter { $0.kind == .objectiveCClass || $0.kind == .objectiveCSelector }
                #expect(metadata.count == 4)
                let expectedSelector = slice.architecture == "arm64" ? "stringWithString:" : "arrayWithObject:"
                let expectedClass = slice.architecture == "arm64" ? "NSString" : "NSArray"
                #expect(Set(metadata.filter { $0.kind == .objectiveCSelector }.map(\.name)) == ["date", expectedSelector])
                #expect(Set(metadata.filter { $0.kind == .objectiveCClass }.map(\.name)) == ["NSDate", expectedClass])
                #expect(!metadata.contains { $0.name == "notAReferencedSelector:" || $0.name == "NSProcessInfo" })
                for row in rows {
                    let kind: StaticAPIReferenceKind = row.section == "__objc_selrefs" ? .objectiveCSelector : .objectiveCClass
                    let reference = try #require(metadata.first { $0.kind == kind && $0.name == row.name })
                    try verifyChainedObjectiveCNameAndSlot(reference, bytes: bytes, url: url, slice: slice)
                    let expectedOffset = try chainedObjectiveCNativeFileOffset(row.virtualAddress, layout: input.layout, slice: slice)
                    #expect(reference.referenceLocation?.fileOffset == expectedOffset)
                    if kind == .objectiveCClass {
                        let declared = try #require(records.first {
                            $0.location.method == .chainedFixupImports && $0.name == "_OBJC_CLASS_$_" + row.name
                        })
                        #expect(reference.location.fileOffset == declared.location.fileOffset.map { $0 + UInt64("_OBJC_CLASS_$_".utf8.count) })
                    }
                }
                #expect(records.filter { $0.location.method == .chainedFixupImports }.allSatisfy { $0.referenceLocation == nil })
                let encoded = try JSONEncoder().encode(pointers)
                #expect(try JSONDecoder().decode(StaticFeatureCollection<MachOChainedPointer>.self, from: encoded) == pointers)
            }
        }
    }

    @Test
    func nativeInlineAndSignedTableAddendsDoNotInventClassReferences() throws {
        let root = try chainedObjectiveCFixtureRoot()
        defer { removeChainedObjectiveCFixture(root) }
        let variants: [(format: UInt32, extra: String)] = [
            (2, ".quad _OBJC_CLASS_$_NSProcessInfo + 4096\n"),
            (3, ".quad _OBJC_CLASS_$_NSDecimalNumber + 4294967296\n")
        ]
        for variant in variants {
            let fixtureRoot = root.appendingPathComponent("imports-\(variant.format)")
            try FileManager.default.createDirectory(at: fixtureRoot, withIntermediateDirectories: false)
            let source = try chainedObjectiveCFixtureSource(fixtureRoot)
            let assembly = fixtureRoot.appendingPathComponent("addends.s")
            let text = ".section __DATA,__objc_classrefs,regular,no_dead_strip\n.p2align 3\n"
                + ".quad _OBJC_CLASS_$_NSCalendar + 1\n.quad _OBJC_CLASS_$_NSSet - 1\n"
                + ".section __DATA,__data,regular,no_dead_strip\n.p2align 3\n" + variant.extra
            try Data(text.utf8).write(to: assembly)
            let url = try compileChainedObjectiveCFixture(root: fixtureRoot, sourceFiles: [source, assembly], deployment: "14.0")
            let bytes = try Data(contentsOf: url)
            let inspection = try MachOInspector.inspectStaticFeatures(url)
            #expect(inspection.apiReferences.state == .partial)
            for slice in inspection.architectures.records.map(\.slice) {
                let input = try chainedObjectiveCInput(url: url, bytes: bytes, slice: slice)
                let payloadOffset = try chainedObjectiveCPayloadOffset(input)
                #expect(try chainedObjectiveCUInt32(bytes, offset: payloadOffset + 20) == variant.format)
                let pointers = try collectChainedObjectiveCFixturePointers(input, containerSize: UInt64(bytes.count))
                #expect(pointers.state == .complete)
                let bound = pointers.records.compactMap { pointer -> (String, Int64)? in
                    guard case let .bind(reference, addend) = pointer.value else { return nil }
                    return (reference.name, addend)
                }
                #expect(bound.contains { $0.0 == "_OBJC_CLASS_$_NSCalendar" && $0.1 == 1 })
                #expect(bound.contains { $0.0 == "_OBJC_CLASS_$_NSSet" && $0.1 == -1 })
                let expectedName = variant.format == 2 ? "_OBJC_CLASS_$_NSProcessInfo" : "_OBJC_CLASS_$_NSDecimalNumber"
                let expectedAddend: Int64 = variant.format == 2 ? 4_096 : 4_294_967_296
                #expect(bound.contains { $0.0 == expectedName && $0.1 == expectedAddend })
                let oracle = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
                    arguments: ["dyld_info", "-arch", slice.architecture, "-fixups", url.path])
                let nativeText = try #require(String(data: oracle.standardOutput, encoding: .utf8))
                #expect(nativeText.contains("_OBJC_CLASS_$_NSCalendar + 0x1"))
                #expect(nativeText.contains("_OBJC_CLASS_$_NSSet + 0xFFFFFFFFFFFFFFFF"))
                #expect(nativeText.contains(variant.format == 2 ? "_OBJC_CLASS_$_NSProcessInfo + 0x1000" : "_OBJC_CLASS_$_NSDecimalNumber + 0x100000000"))
                let records = inspection.apiReferences.records.filter { $0.location.sliceOffset == slice.fileOffset }
                let classes = records.filter { $0.kind == .objectiveCClass }
                let expectedClass = slice.architecture == "arm64" ? "NSString" : "NSArray"
                #expect(Set(classes.map(\.name)) == ["NSDate", expectedClass])
                #expect(!classes.contains { ["NSCalendar", "NSSet", "NSProcessInfo", "NSDecimalNumber"].contains($0.name) })
                #expect(records.contains { $0.kind == .objectiveCSelector && $0.name == "date" })
                #expect(records.contains { $0.location.method == .chainedFixupImports && $0.name == "_OBJC_CLASS_$_NSCalendar" })
                #expect(records.contains { $0.location.method == .chainedFixupImports && $0.name == "_OBJC_CLASS_$_NSSet" })
            }
        }
    }

    @Test
    func malformedChainsAndUnmappedSlotsRetainOtherSlicesAndLiteralImports() throws {
        let root = try chainedObjectiveCFixtureRoot()
        defer { removeChainedObjectiveCFixture(root) }
        let source = try chainedObjectiveCFixtureSource(root)
        let originalURL = try compileChainedObjectiveCFixture(root: root, sourceFiles: [source], deployment: "14.0")
        let original = try Data(contentsOf: originalURL)
        let slices = try MachOInspector.inspect(originalURL)
        let slice = try #require(slices.first { $0.architecture == "arm64" })
        let other = try #require(slices.first { $0.architecture == "x86_64" })
        let input = try chainedObjectiveCInput(url: originalURL, bytes: original, slice: slice)
        let selectors = try #require(input.layout.sections.first { $0.sectionName == "__objc_selrefs" })
        let classes = try #require(input.layout.sections.first { $0.sectionName == "__objc_classrefs" })
        let payloadOffset = try chainedObjectiveCPayloadOffset(input)
        let starts = try chainedObjectiveCUInt32(original, offset: payloadOffset + 4)
        let startsOffset = payloadOffset + Int(starts)
        let dataSegmentIndex = try #require(input.layout.segments.firstIndex { $0.name == selectors.segmentName })
        let segmentInfoRelative = try chainedObjectiveCUInt32(original, offset: startsOffset + 4 + dataSegmentIndex * 4)
        let segmentInfo = startsOffset + Int(segmentInfoRelative)
        let pageSize = try chainedObjectiveCUInt16(original, offset: segmentInfo + 4)
        let segmentOffset = try chainedObjectiveCUInt64(original, offset: segmentInfo + 8)
        let selectorOffset = try #require(Int(exactly: slice.fileOffset + selectors.fileOffset))
        let classOffset = try #require(Int(exactly: slice.fileOffset + classes.fileOffset))
        let selectorWord = try chainedObjectiveCUInt64(original, offset: selectorOffset)
        let classWord = try chainedObjectiveCUInt64(original, offset: classOffset)
        let importCount = try chainedObjectiveCUInt32(original, offset: payloadOffset + 16)
        let nextMask: UInt64 = 0xFFF << 51
        let cases: [(label: String, bytes: Data)] = [
            ("unknown-format", try replacingChainedObjectiveCInteger(original, offset: segmentInfo + 6, value: 99, width: 2)),
            ("segment-vm-offset", try replacingChainedObjectiveCInteger(original, offset: segmentInfo + 8, value: segmentOffset + 8, width: 8)),
            ("page-start-outside-page", try replacingChainedObjectiveCInteger(original, offset: segmentInfo + 22, value: UInt64(pageSize - 4), width: 2)),
            ("unsupported-multiple-starts", try replacingChainedObjectiveCInteger(original, offset: segmentInfo + 22, value: 0x8000, width: 2)),
            ("next-crosses-page", try replacingChainedObjectiveCInteger(original, offset: selectorOffset, value: (selectorWord & ~nextMask) | nextMask, width: 8)),
            ("rebase-reserved-bits", try replacingChainedObjectiveCInteger(original, offset: selectorOffset, value: selectorWord | (1 << 44), width: 8)),
            ("bind-reserved-bits", try replacingChainedObjectiveCInteger(original, offset: classOffset, value: classWord | (1 << 32), width: 8)),
            ("import-index-outside-table", try replacingChainedObjectiveCInteger(original, offset: classOffset, value: (classWord & ~0xFF_FFFF) | UInt64(importCount), width: 8)),
            ("metadata-page-has-no-chain", try replacingChainedObjectiveCInteger(original, offset: segmentInfo + 22, value: 0xFFFF, width: 2)),
            ("cross-slice-payload", try replacingChainedObjectiveCInteger(original, offset: input.commandOffset + 8, value: slice.fileSize - 8, width: 4))
        ]
        for fixture in cases {
            let url = root.appendingPathComponent(fixture.label)
            try fixture.bytes.write(to: url)
            let inspection = try MachOInspector.inspectStaticFeatures(url)
            #expect(inspection.apiReferences.state == .partial)
            #expect(inspection.apiReferences.reason != nil)
            let affectedMetadata = inspection.apiReferences.records.filter {
                ($0.kind == .objectiveCClass || $0.kind == .objectiveCSelector) && $0.location.sliceOffset == slice.fileOffset
            }
            #expect(affectedMetadata.isEmpty)
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.sliceOffset == other.fileOffset
            })
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .objectiveCClass && $0.name == "NSDate" && $0.location.sliceOffset == other.fileOffset
            })
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .importedSymbol && $0.name == "_OBJC_CLASS_$_NSDate" && $0.location.method == .symbolTable
                    && $0.location.sliceOffset == slice.fileOffset
            })
            if fixture.label != "cross-slice-payload" {
                #expect(inspection.apiReferences.records.contains {
                    $0.name == "_OBJC_CLASS_$_NSDate" && $0.location.method == .chainedFixupImports
                        && $0.location.sliceOffset == slice.fileOffset
                })
            }
        }

        // A tagged rebase must retain its high byte instead of silently becoming a local selector pointer.
        let taggedBytes = try replacingChainedObjectiveCInteger(original, offset: selectorOffset,
            value: selectorWord | (0x12 << 36), width: 8)
        let taggedURL = root.appendingPathComponent("tagged-selector-rebase")
        try taggedBytes.write(to: taggedURL)
        let taggedInput = try chainedObjectiveCInput(url: taggedURL, bytes: taggedBytes, slice: slice)
        let pointers = try collectChainedObjectiveCFixturePointers(taggedInput, containerSize: UInt64(taggedBytes.count))
        #expect(pointers.state == .unavailable)
        #expect(pointers.records.isEmpty)
        #expect(pointers.reason?.localizedCaseInsensitiveContains("virtual range") == true)
        let taggedInspection = try MachOInspector.inspectStaticFeatures(taggedURL)
        #expect(taggedInspection.apiReferences.state == .partial)
        #expect(!taggedInspection.apiReferences.records.contains {
            $0.kind == .objectiveCSelector && $0.referenceLocation?.fileOffset == UInt64(selectorOffset)
        })
        #expect(taggedInspection.apiReferences.records.contains {
            $0.kind == .objectiveCClass && $0.name == "NSDate" && $0.location.sliceOffset == other.fileOffset
        })
    }

    @Test
    func nativeChainedSelectorTablesRespectMetadataCapsAcrossMultiplePages() throws {
        let root = try chainedObjectiveCFixtureRoot()
        defer { removeChainedObjectiveCFixture(root) }
        let source = try chainedObjectiveCFixtureSource(root)
        let assembly = root.appendingPathComponent("many-selectors.s")
        let literals = (0..<4_097).map { "Lchained_selector\($0):\n.asciz \"chainedBoundedSelector\($0):\"\n" }.joined()
        let pointers = (0..<4_097).map { ".quad Lchained_selector\($0)\n" }.joined()
        let text = ".section __TEXT,__objc_methname,cstring_literals\n" + literals
            + ".section __DATA,__objc_selrefs,literal_pointers,no_dead_strip\n.p2align 3\n" + pointers
        try Data(text.utf8).write(to: assembly)
        let url = try compileChainedObjectiveCFixture(root: root, sourceFiles: [source, assembly], deployment: "14.0")
        let bytes = try Data(contentsOf: url)
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        #expect(inspection.apiReferences.state == .partial)
        #expect(inspection.apiReferences.reason?.contains("4096") == true)
        #expect(inspection.apiReferences.limits.contains { $0.name == "objc_reference_records_per_slice" && $0.value == 4_096 })
        for slice in inspection.architectures.records.map(\.slice) {
            let input = try chainedObjectiveCInput(url: url, bytes: bytes, slice: slice)
            let collection = try collectChainedObjectiveCFixturePointers(input, containerSize: UInt64(bytes.count))
            #expect(collection.state == .complete)
            #expect(collection.records.count > 4_096)
            let references = inspection.apiReferences.records.filter {
                ($0.kind == .objectiveCClass || $0.kind == .objectiveCSelector) && $0.location.sliceOffset == slice.fileOffset
            }
            #expect(references.count == 4_096)
            #expect(references.allSatisfy { $0.referenceLocation != nil })
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .importedSymbol && $0.name == "_OBJC_CLASS_$_NSDate" && $0.location.sliceOffset == slice.fileOffset
            })
            let oracle = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
                arguments: ["dyld_info", "-arch", slice.architecture, "-section", "__DATA", "__objc_selrefs", url.path])
            let rows = try nativeChainedObjectiveCSectionRows(oracle.standardOutput)
            #expect(rows.count == 4_099)
        }
    }

    @Test
    func nativePointerRecordLimitSuppressesMetadataUntilEveryChainCanBeValidated() throws {
        let root = try chainedObjectiveCFixtureRoot()
        defer { removeChainedObjectiveCFixture(root) }
        let source = try chainedObjectiveCFixtureSource(root)
        let assembly = root.appendingPathComponent("pointer-limit.s")
        let text = """
        .section __TEXT,__cstring,cstring_literals
        Lchain_cap_target:
        .asciz "Bounded chain target"
        .section __DATA,__data,regular,no_dead_strip
        .p2align 3
        .rept 65537
        .quad Lchain_cap_target
        .endr
        """
        try Data(text.utf8).write(to: assembly)
        let url = try compileChainedObjectiveCFixture(root: root, sourceFiles: [source, assembly], deployment: "14.0")
        let bytes = try Data(contentsOf: url)
        let inspection = try MachOInspector.inspectStaticFeatures(url)
        #expect(inspection.apiReferences.state == .partial)
        #expect(!inspection.apiReferences.records.contains { $0.kind == .objectiveCClass || $0.kind == .objectiveCSelector })
        #expect(inspection.apiReferences.reason?.contains("65536") == true)
        for slice in inspection.architectures.records.map(\.slice) {
            let input = try chainedObjectiveCInput(url: url, bytes: bytes, slice: slice)
            let pointers = try collectChainedObjectiveCFixturePointers(input, containerSize: UInt64(bytes.count))
            #expect(pointers.state == .partial)
            #expect(pointers.records.count == 65_536)
            #expect(pointers.reason?.contains("65536") == true)
            #expect(pointers.limits.contains { $0.name == "chained_pointer_records_per_slice" && $0.value == 65_536 })
            #expect(inspection.apiReferences.records.contains {
                $0.name == "_OBJC_CLASS_$_NSDate" && $0.location.method == .chainedFixupImports
                    && $0.location.sliceOffset == slice.fileOffset
            })
        }
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
            arguments: ["dyld_info", "-validate_only", url.path])
    }

    @Test
    func chainedPointerReadFailureIsUnavailableAfterValidImportInspection() throws {
        let root = try chainedObjectiveCFixtureRoot()
        defer { removeChainedObjectiveCFixture(root) }
        let source = try chainedObjectiveCFixtureSource(root)
        let url = try compileChainedObjectiveCFixture(root: root, sourceFiles: [source], deployment: "14.0")
        let bytes = try Data(contentsOf: url)
        let slices = try MachOInspector.inspect(url)
        let slice = try #require(slices.first)
        let input = try chainedObjectiveCInput(url: url, bytes: bytes, slice: slice)
        let importHandle = try FileHandle(forReadingFrom: url)
        defer {
            do { try importHandle.close() }
            catch { Issue.record("Read-failure fixture import handle close failed: \(error.localizedDescription)") }
        }
        let imports = try MachOChainedImportCollector.inspect(handle: importHandle, url: url, slice: slice,
            containerSize: UInt64(bytes.count), minimumDataOffset: input.minimumDataOffset,
            descriptor: input.descriptor, dylibCount: input.dylibCount)
        #expect(imports.entries.state == .complete)
        let handle = try FileHandle(forReadingFrom: url)
        try handle.close()
        let pointers = try MachOChainedPointerCollector.collect(handle: handle, url: url, slice: slice,
            containerSize: UInt64(bytes.count), minimumDataOffset: input.minimumDataOffset,
            descriptor: input.descriptor, segments: input.layout.segments, imports: imports.entries)
        #expect(pointers.state == .unavailable)
        #expect(pointers.records.isEmpty)
        #expect(pointers.reason != nil)
    }

    @Test @MainActor
    func chainedPointerCollectionHonorsCancellationBeforeReadingTheNativeArtifact() async throws {
        let root = try chainedObjectiveCFixtureRoot()
        defer { removeChainedObjectiveCFixture(root) }
        let source = try chainedObjectiveCFixtureSource(root)
        let url = try compileChainedObjectiveCFixture(root: root, sourceFiles: [source], deployment: "14.0")
        let bytes = try Data(contentsOf: url)
        let slices = try MachOInspector.inspect(url)
        let slice = try #require(slices.first)
        let input = try chainedObjectiveCInput(url: url, bytes: bytes, slice: slice)
        let handle = try FileHandle(forReadingFrom: url)
        defer {
            do { try handle.close() }
            catch { Issue.record("Cancelled chained fixture handle close failed: \(error.localizedDescription)") }
        }
        let imports = try MachOChainedImportCollector.inspect(handle: handle, url: url, slice: slice,
            containerSize: UInt64(bytes.count), minimumDataOffset: input.minimumDataOffset,
            descriptor: input.descriptor, dylibCount: input.dylibCount)
        let task = Task { @MainActor in
            try MachOChainedPointerCollector.collect(handle: handle, url: url, slice: slice,
                containerSize: UInt64(bytes.count), minimumDataOffset: input.minimumDataOffset,
                descriptor: input.descriptor, segments: input.layout.segments, imports: imports.entries)
        }
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Chained pointer collection completed after cancellation.")
        } catch is CancellationError { }
    }

    @Test
    func scannerExportsChainedMetadataWithExactSourceIdentityAndRetainsReviewSamples() async throws {
        let root = try chainedObjectiveCFixtureRoot()
        defer { removeChainedObjectiveCFixture(root) }
        let source = try chainedObjectiveCFixtureSource(root)
        let universal = try compileChainedObjectiveCFixture(root: root, sourceFiles: [source], deployment: "14.0")
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let samples = repository.appendingPathComponent(".build/static-feature-validation")
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        let sample = samples.appendingPathComponent("chained-objc-reference")
        try Data(contentsOf: universal).write(to: sample, options: [.atomic])
        let finding = try await collectChainedObjectiveCFeatureFinding(sample)
        let features = try #require(finding.staticFeatures)
        #expect(features.schemaVersion == .v3)
        #expect(features.analyzedPath == sample.path)
        #expect(features.artifactSHA256 == finding.provenance.sha256)
        let references = features.apiReferences.records.filter { $0.kind == .objectiveCClass || $0.kind == .objectiveCSelector }
        #expect(references.count == 8)
        let sampleBytes = try Data(contentsOf: sample)
        for reference in references {
            let slice = try #require(features.architectures.records.first { $0.slice.fileOffset == reference.location.sliceOffset }?.slice)
            try verifyChainedObjectiveCNameAndSlot(reference, bytes: sampleBytes, url: sample, slice: slice)
        }
        let json = try ResultExporter.data(for: [finding], format: .json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == [finding])
        #expect(try ResultExporter.data(for: [finding], format: .json) == json)
        let csv = try ResultExporter.data(for: [finding], format: .csv)
        let rows = try csvFixtureRecords(String(decoding: csv, as: UTF8.self))
        let header = try #require(rows.first)
        let versionColumn = try #require(header.firstIndex(of: "static_features_schema_version"))
        let featureColumn = try #require(header.firstIndex(of: "static_features_json"))
        let populated = rows.dropFirst().filter { !$0[featureColumn].isEmpty }
        #expect(populated.count == 1)
        let row = try #require(populated.first)
        #expect(row.count == header.count)
        #expect(row[versionColumn] == "3")
        #expect(try JSONDecoder().decode(StaticFeatureSet.self, from: Data(row[featureColumn].utf8)) == features)
        let jsonURL = samples.appendingPathComponent("chained-objc-reference.json")
        let csvURL = samples.appendingPathComponent("chained-objc-reference.csv")
        try await writeExport(to: jsonURL) { json }
        try await writeExport(to: csvURL) { csv }
        #expect(try Data(contentsOf: jsonURL) == json)
        #expect(try Data(contentsOf: csvURL) == csv)
    }
}

private struct ChainedObjectiveCFixtureInput: Sendable {
    let url: URL
    let slice: MachOSlice
    let minimumDataOffset: UInt64
    let layout: MachOObjectiveCLayout
    let descriptor: MachOChainedImportDescriptor
    let commandOffset: Int
    let dylibCount: UInt32
}

private enum NativeChainedObjectiveCValue {
    case rebase(UInt64)
    case bind(String)
}

private struct NativeChainedObjectiveCFixup {
    let virtualAddress: UInt64
    let value: NativeChainedObjectiveCValue
}

private struct NativeChainedObjectiveCSectionRow {
    let section: String
    let virtualAddress: UInt64
    let name: String
}

private enum ChainedObjectiveCFixtureError: LocalizedError {
    case range(Int, Int)
    case nativeOutput(String)
    case missingFixups
    case ambiguousAddress(UInt64)

    var errorDescription: String? {
        switch self {
        case let .range(offset, count): "Chained Objective-C fixture field at \(offset) requires \(count) unavailable bytes."
        case let .nativeOutput(reason): "Apple dyld_info returned unexpected chained Objective-C fixture output: \(reason)"
        case .missingFixups: "The controlled native fixture has no LC_DYLD_CHAINED_FIXUPS descriptor."
        case let .ambiguousAddress(address): "The native fixup address \(address) does not map uniquely into a file-backed fixture segment."
        }
    }
}

private func chainedObjectiveCFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-chained-objc-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeChainedObjectiveCFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Chained Objective-C fixture cleanup failed: \(error.localizedDescription)") }
}

private func chainedObjectiveCFixtureSource(_ root: URL) throws -> URL {
    let source = root.appendingPathComponent("fixture.m")
    let text = """
    #import <Foundation/Foundation.h>
    extern Class fixture_nsprocess __asm("_OBJC_CLASS_$_NSProcessInfo");
    Class *fixture_external_class_address = &fixture_nsprocess;
    const char *fixture_only_raw_string = "notAReferencedSelector:";
    id fixture_objc(id value) {
    #if defined(__arm64__)
        return [NSString stringWithString:value];
    #else
        return [NSArray arrayWithObject:value];
    #endif
    }
    id fixture_date(void) { return [NSDate date]; }
    int main(void) { return 0; }
    """
    try Data(text.utf8).write(to: source)
    return source
}

private func compileChainedObjectiveCFixture(root: URL, sourceFiles: [URL], deployment: String) throws -> URL {
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    let architectures = ["arm64", "x86_64"]
    let thinFiles = architectures.map { root.appendingPathComponent("fixture.\($0)") }
    for (architecture, output) in zip(architectures, thinFiles) {
        _ = try runFixtureTool(executable: xcrun, arguments: ["clang", "-target", "\(architecture)-apple-macos\(deployment)"]
            + sourceFiles.map(\.path) + ["-framework", "Foundation", "-Wl,-fixup_chains", "-o", output.path])
    }
    let universal = root.appendingPathComponent("fixture.universal")
    _ = try runFixtureTool(executable: xcrun, arguments: ["lipo", "-create"] + thinFiles.map(\.path) + ["-output", universal.path])
    return universal
}

private func chainedObjectiveCInput(url: URL, bytes: Data, slice: MachOSlice) throws -> ChainedObjectiveCFixtureInput {
    let start = try #require(Int(exactly: slice.fileOffset))
    let commandCount = try chainedObjectiveCUInt32(bytes, offset: start + 16)
    let commandBytes = try chainedObjectiveCUInt32(bytes, offset: start + 20)
    try chainedObjectiveCFixtureRange(bytes, offset: start + 32, count: Int(commandBytes))
    let commands = Data(bytes[(start + 32)..<(start + 32 + Int(commandBytes))])
    let layout = try MachOObjectiveCLayoutParser.parse(commands: commands, commandCount: commandCount,
        slice: slice, headerSize: 32, is64Bit: true, byteOrder: .little)
    var offset = start + 32
    var descriptor: MachOChainedImportDescriptor?
    var descriptorOffset: Int?
    var dylibCount: UInt32 = 0
    let dylibCommands: Set<UInt32> = [0x0C, 0x18, 0x1F, 0x20, 0x23]
    for _ in 0..<commandCount {
        let command = try chainedObjectiveCUInt32(bytes, offset: offset)
        let size = try chainedObjectiveCUInt32(bytes, offset: offset + 4)
        if command == 0x8000_0034 {
            descriptor = MachOChainedImportDescriptor(dataOffset: try chainedObjectiveCUInt32(bytes, offset: offset + 8),
                dataSize: try chainedObjectiveCUInt32(bytes, offset: offset + 12), byteOrder: .little)
            descriptorOffset = offset
        }
        if dylibCommands.contains(command & 0x7FFF_FFFF) { dylibCount += 1 }
        offset += Int(size)
    }
    guard let descriptor, let descriptorOffset else { throw ChainedObjectiveCFixtureError.missingFixups }
    return ChainedObjectiveCFixtureInput(url: url, slice: slice, minimumDataOffset: 32 + UInt64(commandBytes),
        layout: layout, descriptor: descriptor, commandOffset: descriptorOffset, dylibCount: dylibCount)
}

private func chainedObjectiveCPayloadOffset(_ input: ChainedObjectiveCFixtureInput) throws -> Int {
    try #require(Int(exactly: input.slice.fileOffset + UInt64(input.descriptor.dataOffset)))
}

private func collectChainedObjectiveCFixturePointers(_ input: ChainedObjectiveCFixtureInput,
    containerSize: UInt64) throws -> StaticFeatureCollection<MachOChainedPointer> {
    let handle = try FileHandle(forReadingFrom: input.url)
    defer {
        do { try handle.close() }
        catch { Issue.record("Chained Objective-C fixture handle close failed: \(error.localizedDescription)") }
    }
    let imports = try MachOChainedImportCollector.inspect(handle: handle, url: input.url, slice: input.slice,
        containerSize: containerSize, minimumDataOffset: input.minimumDataOffset,
        descriptor: input.descriptor, dylibCount: input.dylibCount)
    return try MachOChainedPointerCollector.collect(handle: handle, url: input.url, slice: input.slice,
        containerSize: containerSize, minimumDataOffset: input.minimumDataOffset,
        descriptor: input.descriptor, segments: input.layout.segments, imports: imports.entries)
}

private func nativeChainedObjectiveCFixups(_ data: Data) throws -> [NativeChainedObjectiveCFixup] {
    guard let text = String(data: data, encoding: .utf8) else { throw ChainedObjectiveCFixtureError.nativeOutput("Invalid UTF-8.") }
    var records: [NativeChainedObjectiveCFixup] = []
    for line in text.split(separator: "\n") {
        let fields = line.split(whereSeparator: { $0.isWhitespace })
        guard fields.count == 5, fields[0].hasPrefix("__"), fields[2].hasPrefix("0x") else { continue }
        guard let address = UInt64(fields[2].dropFirst(2), radix: 16) else {
            throw ChainedObjectiveCFixtureError.nativeOutput("Invalid fixup address.")
        }
        let value: NativeChainedObjectiveCValue
        if fields[3] == "rebase", fields[4].hasPrefix("0x"), let target = UInt64(fields[4].dropFirst(2), radix: 16) {
            value = .rebase(target)
        } else if fields[3] == "bind", let separator = fields[4].firstIndex(of: "/") {
            value = .bind(String(fields[4][fields[4].index(after: separator)...]))
        } else {
            throw ChainedObjectiveCFixtureError.nativeOutput("Unexpected fixup type or target.")
        }
        records.append(NativeChainedObjectiveCFixup(virtualAddress: address, value: value))
    }
    guard !records.isEmpty else { throw ChainedObjectiveCFixtureError.nativeOutput("No fixups were printed.") }
    return records
}

private func nativeChainedObjectiveCSectionRows(_ data: Data) throws -> [NativeChainedObjectiveCSectionRow] {
    guard let text = String(data: data, encoding: .utf8) else { throw ChainedObjectiveCFixtureError.nativeOutput("Invalid UTF-8.") }
    var section: String?
    var records: [NativeChainedObjectiveCSectionRow] = []
    for line in text.split(separator: "\n") {
        if line.hasPrefix("("), let comma = line.firstIndex(of: ","), let closing = line.firstIndex(of: ")") {
            section = String(line[line.index(after: comma)..<closing])
        } else if line.hasPrefix("0x"), let section {
            let fields = line.split(maxSplits: 1, whereSeparator: { $0.isWhitespace })
            guard fields.count == 2, let address = UInt64(fields[0].dropFirst(2), radix: 16) else {
                throw ChainedObjectiveCFixtureError.nativeOutput("Invalid metadata address or name row.")
            }
            let value = fields[1].trimmingCharacters(in: .whitespaces)
            let name: String
            if section == "__objc_selrefs", value.count > 2, value.first == "\"", value.last == "\"" {
                name = String(value.dropFirst().dropLast())
            } else if section == "__objc_classrefs", value.hasPrefix("_OBJC_CLASS_$_"), value.count > "_OBJC_CLASS_$_".count {
                name = String(value.dropFirst("_OBJC_CLASS_$_".count))
            } else {
                throw ChainedObjectiveCFixtureError.nativeOutput("Unexpected selector or class reference row.")
            }
            records.append(NativeChainedObjectiveCSectionRow(section: section, virtualAddress: address, name: name))
        }
    }
    guard !records.isEmpty else { throw ChainedObjectiveCFixtureError.nativeOutput("No metadata section rows were printed.") }
    return records
}

private func chainedObjectiveCNativeFileOffset(_ address: UInt64, layout: MachOObjectiveCLayout, slice: MachOSlice) throws -> UInt64 {
    let segments = layout.segments.filter {
        address >= $0.virtualAddress && address - $0.virtualAddress <= $0.fileSize
            && 8 <= $0.fileSize - (address - $0.virtualAddress)
    }
    guard segments.count == 1, let segment = segments.first else { throw ChainedObjectiveCFixtureError.ambiguousAddress(address) }
    return slice.fileOffset + segment.fileOffset + address - segment.virtualAddress
}

private func verifyChainedObjectiveCNameAndSlot(_ reference: StaticAPIReference, bytes: Data, url: URL, slice: MachOSlice) throws {
    #expect(reference.location.method == .objectiveCMetadata)
    #expect(reference.location.sourcePath == url.path)
    #expect(reference.location.architecture == slice.architecture)
    #expect(reference.location.sliceOffset == slice.fileOffset)
    let nameOffset = try #require(reference.location.fileOffset)
    let nameCount = try #require(reference.location.byteCount)
    let nameIndex = try #require(Int(exactly: nameOffset))
    let nameLength = try #require(Int(exactly: nameCount))
    try #require(nameLength > 0)
    try chainedObjectiveCFixtureRange(bytes, offset: nameIndex, count: nameLength)
    #expect(nameLength == reference.name.utf8.count + 1)
    #expect(bytes[nameIndex + nameLength - 1] == 0)
    #expect(Data(bytes[nameIndex..<(nameIndex + nameLength - 1)]) == Data(reference.name.utf8))
    let slot = try #require(reference.referenceLocation)
    #expect(slot.method == .objectiveCMetadata)
    #expect(slot.sourcePath == url.path)
    #expect(slot.architecture == slice.architecture)
    #expect(slot.sliceOffset == slice.fileOffset)
    #expect(slot.byteCount == 8)
    let slotOffset = try #require(slot.fileOffset)
    #expect(slotOffset >= slice.fileOffset && slotOffset - slice.fileOffset <= slice.fileSize - 8)
}

private func collectChainedObjectiveCFeatureFinding(_ url: URL) async throws -> ScanFinding {
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
        case .cancelled: Issue.record("Chained Objective-C feature fixture collection was cancelled.")
        }
    }
    #expect(completed)
    #expect(issues.isEmpty)
    let selected = findings.filter { $0.path == url.path }
    #expect(selected.count == 1)
    return try #require(selected.first)
}

private func chainedObjectiveCFixtureRange(_ bytes: Data, offset: Int, count: Int) throws {
    guard offset >= 0, count >= 0, offset <= bytes.count, count <= bytes.count - offset else {
        throw ChainedObjectiveCFixtureError.range(offset, count)
    }
}

private func chainedObjectiveCUInt16(_ bytes: Data, offset: Int) throws -> UInt16 {
    try chainedObjectiveCFixtureRange(bytes, offset: offset, count: 2)
    return UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
}

private func chainedObjectiveCUInt32(_ bytes: Data, offset: Int) throws -> UInt32 {
    try chainedObjectiveCFixtureRange(bytes, offset: offset, count: 4)
    return (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[offset + $1]) << ($1 * 8) }
}

private func chainedObjectiveCUInt64(_ bytes: Data, offset: Int) throws -> UInt64 {
    try chainedObjectiveCFixtureRange(bytes, offset: offset, count: 8)
    return (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[offset + $1]) << ($1 * 8) }
}

private func replacingChainedObjectiveCInteger(_ bytes: Data, offset: Int, value: UInt64, width: Int) throws -> Data {
    try chainedObjectiveCFixtureRange(bytes, offset: offset, count: width)
    var result = bytes
    for index in 0..<width { result[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
    return result
}
