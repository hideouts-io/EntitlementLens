import CryptoKit
import Foundation
import Testing
@testable import EntitlementLens

struct LegacyArm64EObjectiveCReferenceIntegrationTests {
    @Test
    func nativeLegacyAuthenticatedAndUnauthenticatedReferencesMatchApplesFixups() throws {
        let root = try legacyArm64EFixtureRoot()
        defer { removeLegacyArm64EFixture(root) }
        let fixture = try makeLegacyArm64EFixture(root: root, assemblySources: [])
        let bytes = try Data(contentsOf: fixture.universal)
        let inspection = try MachOInspector.inspectStaticFeatures(fixture.universal)
        #expect(Set(inspection.architectures.records.map { $0.slice.architecture }) == ["arm64e", "x86_64"])
        for slice in inspection.architectures.records.map(\.slice) {
            let input = try legacyArm64EInput(url: fixture.universal, bytes: bytes, slice: slice)
            if slice.architecture == "x86_64" {
                #expect(input.descriptor == nil)
                #expect(inspection.apiReferences.records.contains {
                    $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.sliceOffset == slice.fileOffset
                })
                continue
            }
            let authenticatedSelectors = try #require(input.layout.sections.first {
                $0.segmentName == "__AUTH" && $0.sectionName == "__objc_selrefs"
            })
            #expect(authenticatedSelectors.flags & 0xFF == 0)
            let pointers = try collectLegacyArm64EPointers(input, containerSize: UInt64(bytes.count))
            #expect(pointers.state == .complete)
            #expect(pointers.records.count == 11)
            #expect(pointers.records.allSatisfy { $0.format == .arm64e && $0.location.method == .chainedFixupPointer })
            let oracle = try legacyArm64EOracle(fixture.arm64e)
            #expect(oracle.text.contains("pointer_format:  1 (DYLD_CHAINED_PTR_ARM64E)"))
            #expect(oracle.fixups.count == pointers.records.count)
            for fixup in oracle.fixups {
                let offset = try legacyArm64EFileOffset(fixup.virtualAddress, layout: input.layout, slice: slice)
                let pointer = try #require(pointers.records.first { $0.location.fileOffset == offset })
                #expect(pointer.location.sourcePath == fixture.universal.path)
                #expect(pointer.location.architecture == slice.architecture)
                #expect(pointer.location.sliceOffset == slice.fileOffset)
                #expect(pointer.location.byteCount == 8)
                #expect(pointer.authentication == fixup.authentication)
                switch (fixup.value, pointer.value) {
                case let (.rebase(nativeAddress), .rebase(address)): #expect(address == nativeAddress)
                case let (.bind(name), .bind(reference, addend)):
                    #expect(name == reference.name)
                    #expect(addend == 0)
                    #expect(reference.location.method == .chainedFixupImports)
                    #expect(reference.referenceLocation == nil)
                default: Issue.record("The collected arm64e pointer does not match the native fixup kind.")
                }
            }
            #expect(Set(pointers.records.compactMap { $0.authentication?.key }) == [.instructionA, .instructionB, .dataA, .dataB])
            #expect(pointers.records.contains { $0.authentication?.diversity == 0x1234 && $0.authentication?.addressDiversity == true })
            #expect(pointers.records.contains { $0.authentication?.diversity == 65_535 && $0.authentication?.addressDiversity == false })
            let rows = inspection.apiReferences.records.filter {
                $0.location.sliceOffset == slice.fileOffset && ($0.kind == .objectiveCClass || $0.kind == .objectiveCSelector)
            }
            #expect(rows.count == 8)
            #expect(Set(rows.filter { $0.kind == .objectiveCSelector }.map(\.name)) == ["date", "stringWithString:", "nativeAuthenticatedSelector:"])
            #expect(Set(rows.filter { $0.kind == .objectiveCClass }.map(\.name)) == ["NSDate", "NSString", "NSCalendar", "NSSet", "NSDecimalNumber"])
            #expect(!rows.contains { $0.name == "NSProcessInfo" || $0.name == "notAReferencedSelector:" })
            for reference in rows {
                try verifyLegacyArm64ENameAndSlot(reference, bytes: bytes, url: fixture.universal, slice: slice)
                let slot = try #require(reference.referenceLocation?.fileOffset)
                let fixup = try #require(try oracle.fixups.first {
                    try legacyArm64EFileOffset($0.virtualAddress, layout: input.layout, slice: slice) == slot
                })
                if reference.kind == .objectiveCClass {
                    #expect(fixup.value == .bind("_OBJC_CLASS_$_" + reference.name))
                    let pointer = try #require(pointers.records.first { $0.location.fileOffset == slot })
                    guard case let .bind(declaration, _) = pointer.value else {
                        Issue.record("An exported class reference has no attributable chained import.")
                        continue
                    }
                    let declarationOffset = try #require(declaration.location.fileOffset)
                    #expect(reference.location.fileOffset == declarationOffset + UInt64("_OBJC_CLASS_$_".utf8.count))
                } else {
                    let nameOffset = try #require(reference.location.fileOffset)
                    let nameAddress = try legacyArm64EVirtualAddress(nameOffset, layout: input.layout, slice: slice)
                    #expect(fixup.value == .rebase(nameAddress))
                }
            }
            let encoded = try JSONEncoder().encode(pointers)
            #expect(try JSONDecoder().decode(StaticFeatureCollection<MachOChainedPointer>.self, from: encoded) == pointers)
        }
    }

    @Test
    func nativePositiveInlineAndSignedTableAddendsWithMutatedNegativeFields() throws {
        let root = try legacyArm64EFixtureRoot()
        defer { removeLegacyArm64EFixture(root) }
        let variants: [(importFormat: UInt32, extra: String)] = [
            (2, ".quad _OBJC_CLASS_$_NSUUID + 262144\n"),
            (3, ".quad _OBJC_CLASS_$_NSUUID + 4294967296\n")
        ]
        for variant in variants {
            let variantRoot = root.appendingPathComponent("addends-\(variant.importFormat)")
            try FileManager.default.createDirectory(at: variantRoot, withIntermediateDirectories: false)
            let assembly = variantRoot.appendingPathComponent("addends.s")
            let text = """
            .section __DATA,__objc_classrefs,regular,no_dead_strip
            .p2align 3
            .quad _OBJC_CLASS_$_NSLocale + 1
            .quad _OBJC_CLASS_$_NSTimeZone + 1
            .quad _OBJC_CLASS_$_NSIndexSet + 262143
            .quad _OBJC_CLASS_$_NSMutableSet + 262144
            .section __AUTH_CONST,__objc_classrefs,regular,no_dead_strip
            .p2align 3
            .quad (_OBJC_CLASS_$_NSCountedSet + 1)@AUTH(da,23,addr)
            .quad (_OBJC_CLASS_$_NSOrderedSet - 1)@AUTH(db,29)
            .section __DATA,__data,regular,no_dead_strip
            .p2align 3
            """ + "\n" + variant.extra
            try Data(text.utf8).write(to: assembly)
            let fixture = try makeLegacyArm64EFixture(root: variantRoot, assemblySources: [assembly])
            let bytes = try Data(contentsOf: fixture.universal)
            let inspection = try MachOInspector.inspectStaticFeatures(fixture.universal)
            let slice = try #require(inspection.architectures.records.first { $0.slice.architecture == "arm64e" }?.slice)
            let input = try legacyArm64EInput(url: fixture.universal, bytes: bytes, slice: slice)
            let payload = try legacyArm64EPayloadOffset(input)
            #expect(try legacyArm64EUInt32(bytes, offset: payload + 20) == variant.importFormat)
            let pointers = try collectLegacyArm64EPointers(input, containerSize: UInt64(bytes.count))
            #expect(pointers.state == .complete)
            let addends: [(String, Int64)] = [("NSLocale", 1), ("NSTimeZone", 1), ("NSIndexSet", 262_143),
                ("NSMutableSet", 262_144), ("NSCountedSet", 1), ("NSOrderedSet", -1), ("NSUUID", variant.importFormat == 2 ? 262_144 : 4_294_967_296)]
            for (name, expected) in addends {
                #expect(pointers.records.contains {
                    if case let .bind(reference, addend) = $0.value { return reference.name == "_OBJC_CLASS_$_" + name && addend == expected }
                    return false
                })
                #expect(!inspection.apiReferences.records.contains { $0.kind == .objectiveCClass && $0.name == name })
                #expect(inspection.apiReferences.records.contains {
                    $0.name == "_OBJC_CLASS_$_" + name && $0.location.method == .chainedFixupImports && $0.location.sliceOffset == slice.fileOffset
                })
            }
            let negative = try #require(pointers.records.first {
                if case let .bind(reference, _) = $0.value { return reference.name == "_OBJC_CLASS_$_NSTimeZone" }
                return false
            })
            let negativeFileOffset = try #require(negative.location.fileOffset)
            let negativeOffset = try #require(Int(exactly: negativeFileOffset))
            let negativeWord = try legacyArm64EUInt64(bytes, offset: negativeOffset)
            #expect((negativeWord >> 32) & 0x7FFFF == 1)
            let oracle = try legacyArm64EOracle(fixture.arm64e)
            #expect(oracle.text.contains("_OBJC_CLASS_$_NSLocale + 0x1"))
            #expect(oracle.text.contains("_OBJC_CLASS_$_NSIndexSet + 0x3FFFF"))
            #expect(oracle.text.contains("_OBJC_CLASS_$_NSCountedSet + 0x1 (div=0x0017 ad=1 key=DA)"))
            #expect(oracle.text.contains("_OBJC_CLASS_$_NSOrderedSet + 0xFFFFFFFFFFFFFFFF (div=0x001D ad=0 key=DB)"))
            // The installed linker rejects negative inline addends for format 1. This byte mutation
            // exercises its SDK-declared signed 19-bit field without claiming native linker output.
            let inlineMask: UInt64 = 0x7FFFF << 32
            let minusOneWord = (negativeWord & ~inlineMask) | (0x7FFFF << 32)
            let minusOneBytes = try replacingLegacyArm64EInteger(bytes, offset: negativeOffset, value: minusOneWord, width: 8)
            let minusOneURL = variantRoot.appendingPathComponent("mutated-negative-inline-addend")
            try minusOneBytes.write(to: minusOneURL)
            let minusOneInput = try legacyArm64EInput(url: minusOneURL, bytes: minusOneBytes, slice: slice)
            let minusOnePointers = try collectLegacyArm64EPointers(minusOneInput, containerSize: UInt64(minusOneBytes.count))
            #expect(minusOnePointers.state == .complete)
            #expect(minusOnePointers.records.contains {
                if case let .bind(reference, addend) = $0.value { return reference.name == "_OBJC_CLASS_$_NSTimeZone" && addend == -1 }
                return false
            })
            let minusOneOracle = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
                arguments: ["dyld_info", "-fixups", minusOneURL.path])
            let minusOneText = try #require(String(data: minusOneOracle.standardOutput, encoding: .utf8))
            // dyld_info prints the raw unsigned field; Apple MachOLayout.cpp sign-extends bit 18.
            #expect(minusOneText.contains("_OBJC_CLASS_$_NSTimeZone + 0x7FFFF"))
            #expect(inspection.apiReferences.state == .partial)
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .objectiveCSelector && $0.name == "nativeAuthenticatedSelector:" && $0.location.sliceOffset == slice.fileOffset
            })
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.architecture == "x86_64"
            })

            // This byte-mutated native fixture converts one authenticated bind into an unauthenticated bind.
            // Its signed inline -1 cancels the real import-table +1; it tests arithmetic, not linker output.
            let counted = try #require(pointers.records.first {
                if case let .bind(reference, _) = $0.value { return reference.name == "_OBJC_CLASS_$_NSCountedSet" }
                return false
            })
            let countedFileOffset = try #require(counted.location.fileOffset)
            let countedOffset = try #require(Int(exactly: countedFileOffset))
            let countedWord = try legacyArm64EUInt64(bytes, offset: countedOffset)
            let nextMask: UInt64 = 0x7FF << 51
            let cancelledWord = (countedWord & (nextMask | 0xFFFF)) | (1 << 62) | (0x7FFFF << 32)
            let cancelledBytes = try replacingLegacyArm64EInteger(bytes, offset: countedOffset, value: cancelledWord, width: 8)
            let cancelledURL = variantRoot.appendingPathComponent("mutated-cancelled-addend")
            try cancelledBytes.write(to: cancelledURL)
            let cancelledInput = try legacyArm64EInput(url: cancelledURL, bytes: cancelledBytes, slice: slice)
            let cancelledPointers = try collectLegacyArm64EPointers(cancelledInput, containerSize: UInt64(cancelledBytes.count))
            #expect(cancelledPointers.state == .complete)
            #expect(cancelledPointers.records.contains {
                if case let .bind(reference, addend) = $0.value { return reference.name == "_OBJC_CLASS_$_NSCountedSet" && addend == 0 && $0.authentication == nil }
                return false
            })
            let cancelled = try MachOInspector.inspectStaticFeatures(cancelledURL)
            let classReference = try #require(cancelled.apiReferences.records.first {
                $0.kind == .objectiveCClass && $0.name == "NSCountedSet" && $0.location.sliceOffset == slice.fileOffset
            })
            #expect(classReference.referenceLocation?.fileOffset == UInt64(countedOffset))
            try verifyLegacyArm64ENameAndSlot(classReference, bytes: cancelledBytes, url: cancelledURL, slice: slice)

            // This mutation of a real zero-table-addend slot exercises the signed inline minimum.
            // It is decoder coverage, not native linker output.
            let minimumWord = (negativeWord & ~inlineMask) | (0x40000 << 32)
            let minimumBytes = try replacingLegacyArm64EInteger(bytes, offset: negativeOffset, value: minimumWord, width: 8)
            let minimumURL = variantRoot.appendingPathComponent("mutated-minimum-inline-addend")
            try minimumBytes.write(to: minimumURL)
            let minimumInput = try legacyArm64EInput(url: minimumURL, bytes: minimumBytes, slice: slice)
            let minimumPointers = try collectLegacyArm64EPointers(minimumInput, containerSize: UInt64(minimumBytes.count))
            #expect(minimumPointers.state == .complete)
            #expect(minimumPointers.records.contains {
                if case let .bind(reference, addend) = $0.value { return reference.name == "_OBJC_CLASS_$_NSTimeZone" && addend == -262_144 }
                return false
            })

            if variant.importFormat == 3 {
                // Mutate the actual NSLocale import3 entry: its native inline +1 must overflow Int64.max.
                let locale = try #require(pointers.records.first {
                    if case let .bind(reference, _) = $0.value { return reference.name == "_OBJC_CLASS_$_NSLocale" }
                    return false
                })
                let localeFileOffset = try #require(locale.location.fileOffset)
                let localeOffset = try #require(Int(exactly: localeFileOffset))
                let localeWord = try legacyArm64EUInt64(bytes, offset: localeOffset)
                #expect((localeWord >> 32) & 0x7FFFF == 1)
                let ordinal = localeWord & 0xFFFF
                let importsStart = payload + Int(try legacyArm64EUInt32(bytes, offset: payload + 8))
                let importAddendOffset = importsStart + Int(ordinal) * 16 + 8
                let overflowBytes = try replacingLegacyArm64EInteger(bytes, offset: importAddendOffset, value: UInt64(Int64.max), width: 8)
                let overflowURL = variantRoot.appendingPathComponent("mutated-combined-addend-overflow")
                try overflowBytes.write(to: overflowURL)
                let overflowInput = try legacyArm64EInput(url: overflowURL, bytes: overflowBytes, slice: slice)
                let overflowPointers = try collectLegacyArm64EPointers(overflowInput, containerSize: UInt64(overflowBytes.count))
                #expect(overflowPointers.state == .unavailable)
                #expect(overflowPointers.records.isEmpty)
                #expect(overflowPointers.reason?.localizedCaseInsensitiveContains("overflow") == true)
                let overflow = try MachOInspector.inspectStaticFeatures(overflowURL)
                #expect(overflow.apiReferences.state == .partial)
                #expect(!overflow.apiReferences.records.contains {
                    ($0.kind == .objectiveCSelector || $0.kind == .objectiveCClass) && $0.location.sliceOffset == slice.fileOffset
                })
                #expect(overflow.apiReferences.records.contains {
                    $0.name == "_OBJC_CLASS_$_NSLocale" && $0.location.method == .chainedFixupImports && $0.location.sliceOffset == slice.fileOffset
                })
                #expect(overflow.apiReferences.records.contains {
                    $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.architecture == "x86_64"
                })
            }
        }
    }

    @Test
    func byteMutatedLegacyBoundariesRetainOrdinarySliceAndLiteralImports() throws {
        let root = try legacyArm64EFixtureRoot()
        defer { removeLegacyArm64EFixture(root) }
        let fixture = try makeLegacyArm64EFixture(root: root, assemblySources: [])
        let original = try Data(contentsOf: fixture.universal)
        let slices = try MachOInspector.inspect(fixture.universal)
        let slice = try #require(slices.first { $0.architecture == "arm64e" })
        let other = try #require(slices.first { $0.architecture == "x86_64" })
        let input = try legacyArm64EInput(url: fixture.universal, bytes: original, slice: slice)
        let classes = try #require(input.layout.sections.first { $0.sectionName == "__objc_classrefs" && $0.segmentName == "__AUTH_CONST" })
        let ordinaryClasses = try #require(input.layout.sections.first { $0.sectionName == "__objc_classrefs" && $0.segmentName == "__DATA" })
        let selectors = try #require(input.layout.sections.first { $0.sectionName == "__objc_selrefs" && $0.segmentName == "__AUTH" })
        let ordinarySelectors = try #require(input.layout.sections.first { $0.sectionName == "__objc_selrefs" && $0.segmentName == "__DATA" })
        let authClassOffset = try #require(Int(exactly: slice.fileOffset + classes.fileOffset))
        let classOffset = try #require(Int(exactly: slice.fileOffset + ordinaryClasses.fileOffset))
        let selectorOffset = try #require(Int(exactly: slice.fileOffset + selectors.fileOffset))
        let plainSelectorOffset = try #require(Int(exactly: slice.fileOffset + ordinarySelectors.fileOffset))
        let authClassWord = try legacyArm64EUInt64(original, offset: authClassOffset)
        let secondAuthClassOffset = authClassOffset + 8
        let secondAuthClassWord = try legacyArm64EUInt64(original, offset: secondAuthClassOffset)
        let classWord = try legacyArm64EUInt64(original, offset: classOffset)
        let selectorWord = try legacyArm64EUInt64(original, offset: selectorOffset)
        let plainSelectorWord = try legacyArm64EUInt64(original, offset: plainSelectorOffset)
        let payload = try legacyArm64EPayloadOffset(input)
        let importCount = try legacyArm64EUInt32(original, offset: payload + 16)
        let starts = payload + Int(try legacyArm64EUInt32(original, offset: payload + 4))
        let segmentIndex = try #require(input.layout.segments.firstIndex { $0.name == "__AUTH" })
        let segmentInfo = starts + Int(try legacyArm64EUInt32(original, offset: starts + 4 + segmentIndex * 4))
        let pageSize = try legacyArm64EUInt16(original, offset: segmentInfo + 4)
        // The second auth class slot is at page offset eight; next=2047 advances beyond this 16 KiB page.
        #expect((classes.fileOffset + 8) % UInt64(pageSize) == 8)
        let nextMask: UInt64 = 0x7FF << 51
        let targetMask: UInt64 = (1 << 43) - 1
        let authSelectorFlagsOffset = try legacyArm64ESectionFlagsOffset(bytes: original, slice: slice,
            segmentName: "__AUTH", sectionName: "__objc_selrefs")
        let ordinarySelectorFlagsOffset = try legacyArm64ESectionFlagsOffset(bytes: original, slice: slice,
            segmentName: "__DATA", sectionName: "__objc_selrefs")
        let ordinarySelectorFlags = try legacyArm64EUInt32(original, offset: ordinarySelectorFlagsOffset)
        let cases: [(String, Data)] = [
            ("auth-selector-literal-type", try replacingLegacyArm64EInteger(original, offset: authSelectorFlagsOffset, value: 5, width: 4)),
            ("ordinary-selector-regular-type", try replacingLegacyArm64EInteger(original, offset: ordinarySelectorFlagsOffset, value: UInt64(ordinarySelectorFlags & ~0xFF), width: 4)),
            ("auth-selector-instruction-attribute", try replacingLegacyArm64EInteger(original, offset: authSelectorFlagsOffset, value: 0x8000_0000, width: 4)),
            ("auth-bind-zero-field", try replacingLegacyArm64EInteger(original, offset: authClassOffset, value: authClassWord | (1 << 16), width: 8)),
            ("unauth-bind-zero-field", try replacingLegacyArm64EInteger(original, offset: classOffset, value: classWord | (1 << 31), width: 8)),
            ("auth-bind-invalid-ordinal", try replacingLegacyArm64EInteger(original, offset: authClassOffset, value: (authClassWord & ~0xFFFF) | UInt64(importCount), width: 8)),
            ("unauth-bind-invalid-ordinal", try replacingLegacyArm64EInteger(original, offset: classOffset, value: (classWord & ~0xFFFF) | UInt64(importCount), width: 8)),
            ("auth-rebase-unmapped-target", try replacingLegacyArm64EInteger(original, offset: selectorOffset, value: (selectorWord & ~0xFFFF_FFFF) | 0xFFFF_FFFF, width: 8)),
            ("unauth-rebase-unmapped-target", try replacingLegacyArm64EInteger(original, offset: plainSelectorOffset, value: (plainSelectorWord & ~targetMask) | targetMask, width: 8)),
            ("unauth-rebase-high-byte", try replacingLegacyArm64EInteger(original, offset: plainSelectorOffset, value: plainSelectorWord | (0x12 << 43), width: 8)),
            ("next-stride-crosses-page", try replacingLegacyArm64EInteger(original, offset: secondAuthClassOffset, value: (secondAuthClassWord & ~nextMask) | nextMask, width: 8)),
            ("page-start-not-stride-aligned", try replacingLegacyArm64EInteger(original, offset: segmentInfo + 22, value: 4, width: 2)),
            ("page-start-outside-page", try replacingLegacyArm64EInteger(original, offset: segmentInfo + 22, value: UInt64(pageSize), width: 2)),
            ("multiple-starts-unsupported", try replacingLegacyArm64EInteger(original, offset: segmentInfo + 22, value: 0x8000, width: 2)),
            ("userland16-unsupported", try replacingLegacyArm64EInteger(original, offset: segmentInfo + 6, value: 9, width: 2)),
            ("non-arm64e-header", try replacingLegacyArm64EInteger(original, offset: Int(slice.fileOffset) + 8, value: 0, width: 4))
        ]
        for (name, bytes) in cases {
            let url = root.appendingPathComponent("mutated-" + name)
            try bytes.write(to: url)
            let inspection = try MachOInspector.inspectStaticFeatures(url)
            let mutationComment = Comment(rawValue: "Mutated native fixture: " + name)
            #expect(inspection.apiReferences.state == .partial, mutationComment)
            #expect(inspection.apiReferences.reason != nil, mutationComment)
            #expect(!inspection.apiReferences.records.contains {
                ($0.kind == .objectiveCClass || $0.kind == .objectiveCSelector) && $0.location.sliceOffset == slice.fileOffset
            }, mutationComment)
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.sliceOffset == other.fileOffset
            }, mutationComment)
            #expect(inspection.apiReferences.records.contains {
                $0.kind == .objectiveCClass && $0.name == "NSDate" && $0.location.sliceOffset == other.fileOffset
            }, mutationComment)
            #expect(inspection.apiReferences.records.contains {
                $0.name == "_OBJC_CLASS_$_NSCalendar" && $0.location.method == .chainedFixupImports && $0.location.sliceOffset == slice.fileOffset
            }, mutationComment)
        }

        // A subtype-only mutation exercises the additional SDK-recognized arm64e header variant without runtime claims.
        let subtypeBytes = try replacingLegacyArm64EInteger(original, offset: Int(slice.fileOffset) + 8, value: 0x8100_000C, width: 4)
        let subtypeURL = root.appendingPathComponent("mutated-arm64e-x1-header")
        try subtypeBytes.write(to: subtypeURL)
        let subtype = try MachOInspector.inspectStaticFeatures(subtypeURL)
        #expect(subtype.architectures.records.contains { $0.slice.architecture == "arm64e.x1" })
        #expect(subtype.apiReferences.records.contains {
            $0.kind == .objectiveCSelector && $0.name == "nativeAuthenticatedSelector:" && $0.location.architecture == "arm64e.x1"
        })
    }

    @Test
    func nativeAuthenticatedSelectorPagesRespectMetadataLimits() throws {
        let root = try legacyArm64EFixtureRoot()
        defer { removeLegacyArm64EFixture(root) }
        let assembly = root.appendingPathComponent("many-auth-selectors.s")
        let names = (0..<4_097).map { "Larm64e_selector\($0):\n.asciz \"boundedAuthenticatedSelector\($0):\"\n" }.joined()
        let slots = (0..<4_097).map { ".quad Larm64e_selector\($0)@AUTH(da,\($0),addr)\n" }.joined()
        try Data((".section __TEXT,__objc_methname,cstring_literals\n" + names
            + ".section __AUTH,__objc_selrefs,literal_pointers,no_dead_strip\n.p2align 3\n" + slots).utf8).write(to: assembly)
        let fixture = try makeLegacyArm64EFixture(root: root, assemblySources: [assembly])
        let bytes = try Data(contentsOf: fixture.universal)
        let inspection = try MachOInspector.inspectStaticFeatures(fixture.universal)
        let slice = try #require(inspection.architectures.records.first { $0.slice.architecture == "arm64e" }?.slice)
        let input = try legacyArm64EInput(url: fixture.universal, bytes: bytes, slice: slice)
        let pointers = try collectLegacyArm64EPointers(input, containerSize: UInt64(bytes.count))
        #expect(pointers.state == .complete)
        #expect(pointers.records.filter { $0.authentication?.key == .dataA }.count == 4_098)
        #expect(inspection.apiReferences.state == .partial)
        #expect(inspection.apiReferences.reason?.contains("4096") == true)
        #expect(inspection.apiReferences.records.filter {
            ($0.kind == .objectiveCClass || $0.kind == .objectiveCSelector) && $0.location.sliceOffset == slice.fileOffset
        }.count == 4_096)
        #expect(inspection.apiReferences.records.contains {
            $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.architecture == "x86_64"
        })
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: ["dyld_info", "-validate_only", fixture.arm64e.path])
    }

    @Test
    func nativeLegacyPointerRecordLimitRetainsIndependentImportsAndOrdinarySlice() throws {
        let root = try legacyArm64EFixtureRoot()
        defer { removeLegacyArm64EFixture(root) }
        let assembly = root.appendingPathComponent("many-pointers.s")
        let text = """
        .section __TEXT,__cstring,cstring_literals
        Llegacy_cap_target:
        .asciz "Bounded legacy chain target"
        .section __DATA,__data,regular,no_dead_strip
        .p2align 3
        .rept 65537
        .quad Llegacy_cap_target
        .endr
        """
        try Data(text.utf8).write(to: assembly)
        let fixture = try makeLegacyArm64EFixture(root: root, assemblySources: [assembly])
        let bytes = try Data(contentsOf: fixture.universal)
        let inspection = try MachOInspector.inspectStaticFeatures(fixture.universal)
        let slice = try #require(inspection.architectures.records.first { $0.slice.architecture == "arm64e" }?.slice)
        let input = try legacyArm64EInput(url: fixture.universal, bytes: bytes, slice: slice)
        let pointers = try collectLegacyArm64EPointers(input, containerSize: UInt64(bytes.count))
        #expect(pointers.state == .partial)
        #expect(pointers.records.count == 65_536)
        #expect(pointers.reason?.contains("65536") == true)
        #expect(pointers.limits.contains { $0.name == "chained_pointer_records_per_slice" && $0.value == 65_536 })
        #expect(inspection.apiReferences.state == .partial)
        #expect(!inspection.apiReferences.records.contains {
            ($0.kind == .objectiveCClass || $0.kind == .objectiveCSelector) && $0.location.sliceOffset == slice.fileOffset
        })
        #expect(inspection.apiReferences.records.contains {
            $0.name == "_OBJC_CLASS_$_NSCalendar" && $0.location.method == .chainedFixupImports && $0.location.sliceOffset == slice.fileOffset
        })
        #expect(inspection.apiReferences.records.contains {
            $0.kind == .objectiveCSelector && $0.name == "arrayWithObject:" && $0.location.architecture == "x86_64"
        })
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: ["dyld_info", "-validate_only", fixture.arm64e.path])
    }

    @Test
    func legacyPointersRequireEveryOriginalImportAndActualDependencyOrdinal() throws {
        let root = try legacyArm64EFixtureRoot()
        defer { removeLegacyArm64EFixture(root) }
        let fixture = try makeLegacyArm64EFixture(root: root, assemblySources: [])
        let bytes = try Data(contentsOf: fixture.universal)
        let slices = try MachOInspector.inspect(fixture.universal)
        let slice = try #require(slices.first { $0.architecture == "arm64e" })
        let input = try legacyArm64EInput(url: fixture.universal, bytes: bytes, slice: slice)
        let descriptor = try #require(input.descriptor)
        let handle = try FileHandle(forReadingFrom: fixture.universal)
        defer {
            do { try handle.close() }
            catch { Issue.record("Legacy import-coverage fixture handle close failed: \(error.localizedDescription)") }
        }
        let imports = try MachOChainedImportCollector.inspect(handle: handle, url: fixture.universal, slice: slice,
            containerSize: UInt64(bytes.count), minimumDataOffset: input.minimumDataOffset,
            descriptor: descriptor, dylibCount: input.dylibCount)
        #expect(imports.entries.state == .complete)
        let truncated = StaticFeatureCollection(state: StaticCollectionState.complete, reason: nil,
            records: Array(imports.entries.records.dropLast()), limitations: imports.entries.limitations, limits: imports.entries.limits)
        let incomplete = try MachOChainedPointerCollector.collect(handle: handle, url: fixture.universal, slice: slice,
            containerSize: UInt64(bytes.count), minimumDataOffset: input.minimumDataOffset,
            descriptor: descriptor, segments: input.layout.segments, imports: truncated)
        #expect(incomplete.state == .unavailable)
        #expect(incomplete.records.isEmpty)

        // Mutate the native import ordinal and supply an exaggerated caller count. Pointer collection
        // must rederive the true dependency count from load commands instead of trusting that input.
        let payload = try legacyArm64EPayloadOffset(input)
        #expect(try legacyArm64EUInt32(bytes, offset: payload + 20) == 1)
        let importsOffset = payload + Int(try legacyArm64EUInt32(bytes, offset: payload + 8))
        let packed = try legacyArm64EUInt32(bytes, offset: importsOffset)
        let mutatedBytes = try replacingLegacyArm64EInteger(bytes, offset: importsOffset,
            value: UInt64((packed & ~0xFF) | (input.dylibCount + 1)), width: 4)
        let mutatedURL = root.appendingPathComponent("mutated-import-dependency-ordinal")
        try mutatedBytes.write(to: mutatedURL)
        let mutatedHandle = try FileHandle(forReadingFrom: mutatedURL)
        defer {
            do { try mutatedHandle.close() }
            catch { Issue.record("Mutated legacy import fixture handle close failed: \(error.localizedDescription)") }
        }
        let exaggerated = try MachOChainedImportCollector.inspect(handle: mutatedHandle, url: mutatedURL, slice: slice,
            containerSize: UInt64(mutatedBytes.count), minimumDataOffset: input.minimumDataOffset,
            descriptor: descriptor, dylibCount: UInt32.max)
        #expect(exaggerated.entries.state == .complete)
        let rejected = try MachOChainedPointerCollector.collect(handle: mutatedHandle, url: mutatedURL, slice: slice,
            containerSize: UInt64(mutatedBytes.count), minimumDataOffset: input.minimumDataOffset,
            descriptor: descriptor, segments: input.layout.segments, imports: exaggerated.entries)
        #expect(rejected.state == .unavailable)
        #expect(rejected.records.isEmpty)
        #expect(rejected.reason?.localizedCaseInsensitiveContains("ordinal") == true)
        let inspection = try MachOInspector.inspectStaticFeatures(mutatedURL)
        #expect(inspection.apiReferences.state == .partial)
        #expect(!inspection.apiReferences.records.contains {
            ($0.kind == .objectiveCSelector || $0.kind == .objectiveCClass) && $0.location.sliceOffset == slice.fileOffset
        })
        #expect(inspection.apiReferences.records.contains {
            $0.kind == .objectiveCClass && $0.name == "NSDate" && $0.location.architecture == "x86_64"
        })
    }

    @Test @MainActor
    func legacyPointerCollectionHonorsCancellationBeforeReadingTheArtifact() async throws {
        let root = try legacyArm64EFixtureRoot()
        defer { removeLegacyArm64EFixture(root) }
        let fixture = try makeLegacyArm64EFixture(root: root, assemblySources: [])
        let bytes = try Data(contentsOf: fixture.universal)
        let slices = try MachOInspector.inspect(fixture.universal)
        let slice = try #require(slices.first { $0.architecture == "arm64e" })
        let input = try legacyArm64EInput(url: fixture.universal, bytes: bytes, slice: slice)
        let descriptor = try #require(input.descriptor)
        let handle = try FileHandle(forReadingFrom: fixture.universal)
        defer {
            do { try handle.close() }
            catch { Issue.record("Cancelled legacy arm64e fixture handle close failed: \(error.localizedDescription)") }
        }
        let imports = try MachOChainedImportCollector.inspect(handle: handle, url: fixture.universal, slice: slice,
            containerSize: UInt64(bytes.count), minimumDataOffset: input.minimumDataOffset,
            descriptor: descriptor, dylibCount: input.dylibCount)
        #expect(imports.entries.state == .complete)
        let task = Task { @MainActor in
            try MachOChainedPointerCollector.collect(handle: handle, url: fixture.universal, slice: slice,
                containerSize: UInt64(bytes.count), minimumDataOffset: input.minimumDataOffset,
                descriptor: descriptor, segments: input.layout.segments, imports: imports.entries)
        }
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Legacy arm64e pointer collection completed after cancellation.")
        } catch is CancellationError { }
    }

    @Test
    func scannerExportsNativeLegacyArm64EEvidenceWithStableV3JSONAndCSV() async throws {
        let root = try legacyArm64EFixtureRoot()
        defer { removeLegacyArm64EFixture(root) }
        let fixture = try makeLegacyArm64EFixture(root: root, assemblySources: [])
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let samples = repository.appendingPathComponent(".build/static-feature-validation")
        try FileManager.default.createDirectory(at: samples, withIntermediateDirectories: true)
        let sample = samples.appendingPathComponent("legacy-arm64e-objc-reference")
        try Data(contentsOf: fixture.universal).write(to: sample, options: [.atomic])
        let finding = try await collectLegacyArm64EFinding(sample)
        let features = try #require(finding.staticFeatures)
        #expect(features.schemaVersion == .v3)
        #expect(features.analyzedPath == sample.path)
        #expect(features.artifactSHA256 == finding.provenance.sha256)
        let references = features.apiReferences.records.filter { $0.kind == .objectiveCClass || $0.kind == .objectiveCSelector }
        #expect(references.count == 12)
        let sampleBytes = try Data(contentsOf: sample)
        let digest = SHA256.hash(data: sampleBytes).map { String(format: "%02x", $0) }.joined()
        #expect(features.artifactSHA256 == digest)
        for reference in references {
            let slice = try #require(features.architectures.records.first { $0.slice.fileOffset == reference.location.sliceOffset }?.slice)
            try verifyLegacyArm64ENameAndSlot(reference, bytes: sampleBytes, url: sample, slice: slice)
        }
        let firstReference = try #require(references.first)
        let legacy = LegacyArm64EAPIReference(name: firstReference.name, kind: firstReference.kind, location: firstReference.location)
        let legacyBytes = try JSONEncoder().encode(legacy)
        let decodedLegacy = try JSONDecoder().decode(StaticAPIReference.self, from: legacyBytes)
        #expect(decodedLegacy.name == firstReference.name && decodedLegacy.kind == firstReference.kind)
        #expect(decodedLegacy.location == firstReference.location && decodedLegacy.referenceLocation == nil)
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
        #expect(row.count == header.count)
        #expect(row[versionColumn] == "3")
        #expect(try JSONDecoder().decode(StaticFeatureSet.self, from: Data(row[featureColumn].utf8)) == features)
        let jsonURL = samples.appendingPathComponent("legacy-arm64e-objc-reference.json")
        let csvURL = samples.appendingPathComponent("legacy-arm64e-objc-reference.csv")
        try await writeExport(to: jsonURL) { json }
        try await writeExport(to: csvURL) { csv }
        #expect(try Data(contentsOf: jsonURL) == json)
        #expect(try Data(contentsOf: csvURL) == csv)
    }
}

private struct LegacyArm64EAPIReference: Encodable {
    let name: String
    let kind: StaticAPIReferenceKind
    let location: StaticEvidenceLocation
}

private struct LegacyArm64EFixture {
    let universal: URL
    let arm64e: URL
}

private struct LegacyArm64EFixtureInput {
    let url: URL
    let slice: MachOSlice
    let minimumDataOffset: UInt64
    let layout: MachOObjectiveCLayout
    let descriptor: MachOChainedImportDescriptor?
    let dylibCount: UInt32
}

private enum NativeLegacyArm64EValue: Equatable {
    case rebase(UInt64)
    case bind(String)
}

private struct NativeLegacyArm64EFixup {
    let virtualAddress: UInt64
    let value: NativeLegacyArm64EValue
    let authentication: MachOChainedAuthentication?
}

private struct LegacyArm64EOracle {
    let text: String
    let fixups: [NativeLegacyArm64EFixup]
}

private enum LegacyArm64EFixtureError: LocalizedError {
    case range(Int, Int)
    case nativeOutput(String)
    case missingFixups
    case ambiguousAddress(UInt64)

    var errorDescription: String? {
        switch self {
        case let .range(offset, count): "Arm64e fixture field at \(offset) requires \(count) unavailable bytes."
        case let .nativeOutput(reason): "Apple dyld_info returned unexpected arm64e fixture output: \(reason)"
        case .missingFixups: "The controlled arm64e fixture has no LC_DYLD_CHAINED_FIXUPS descriptor."
        case let .ambiguousAddress(address): "The arm64e fixture address \(address) has no unique file-backed segment mapping."
        }
    }
}

private func legacyArm64EFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-legacy-arm64e-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeLegacyArm64EFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Arm64e fixture cleanup failed: \(error.localizedDescription)") }
}

private func makeLegacyArm64EFixture(root: URL, assemblySources: [URL]) throws -> LegacyArm64EFixture {
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
    let authenticationSource = root.appendingPathComponent("authenticated.s")
    let assembly = """
    .section __TEXT,__objc_methname,cstring_literals
    Lfixture_auth_selector:
    .asciz "nativeAuthenticatedSelector:"
    .section __AUTH,__objc_selrefs,literal_pointers,no_dead_strip
    .p2align 3
    .quad Lfixture_auth_selector@AUTH(da,4660,addr)
    .section __AUTH_CONST,__objc_classrefs,regular,no_dead_strip
    .p2align 3
    .quad _OBJC_CLASS_$_NSCalendar@AUTH(db,22136,addr)
    .quad _OBJC_CLASS_$_NSSet@AUTH(ia,42)
    .quad _OBJC_CLASS_$_NSDecimalNumber@AUTH(ib,65535)
    """
    try Data(assembly.utf8).write(to: authenticationSource)
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    let arm64e = root.appendingPathComponent("fixture.arm64e")
    let x86 = root.appendingPathComponent("fixture.x86_64")
    _ = try runFixtureTool(executable: xcrun, arguments: ["clang", "-target", "arm64e-apple-macos11.0", source.path, authenticationSource.path]
        + assemblySources.map(\.path) + ["-framework", "Foundation", "-Wl,-fixup_chains", "-o", arm64e.path])
    _ = try runFixtureTool(executable: xcrun, arguments: ["clang", "-target", "x86_64-apple-macos14.0", source.path,
        "-framework", "Foundation", "-Wl,-no_fixup_chains", "-o", x86.path])
    let universal = root.appendingPathComponent("fixture.universal")
    _ = try runFixtureTool(executable: xcrun, arguments: ["lipo", "-create", arm64e.path, x86.path, "-output", universal.path])
    return LegacyArm64EFixture(universal: universal, arm64e: arm64e)
}

private func legacyArm64EInput(url: URL, bytes: Data, slice: MachOSlice) throws -> LegacyArm64EFixtureInput {
    let start = try #require(Int(exactly: slice.fileOffset))
    let commandCount = try legacyArm64EUInt32(bytes, offset: start + 16)
    let commandBytes = try legacyArm64EUInt32(bytes, offset: start + 20)
    try legacyArm64EFixtureRange(bytes, offset: start + 32, count: Int(commandBytes))
    let commands = Data(bytes[(start + 32)..<(start + 32 + Int(commandBytes))])
    let layout = try MachOObjectiveCLayoutParser.parse(commands: commands, commandCount: commandCount,
        slice: slice, headerSize: 32, is64Bit: true, byteOrder: .little)
    var offset = start + 32
    var descriptor: MachOChainedImportDescriptor?
    var dylibCount: UInt32 = 0
    let dylibCommands: Set<UInt32> = [0x0C, 0x18, 0x1F, 0x20, 0x23]
    for _ in 0..<commandCount {
        let command = try legacyArm64EUInt32(bytes, offset: offset)
        let size = try legacyArm64EUInt32(bytes, offset: offset + 4)
        if command == 0x8000_0034 {
            descriptor = MachOChainedImportDescriptor(dataOffset: try legacyArm64EUInt32(bytes, offset: offset + 8),
                dataSize: try legacyArm64EUInt32(bytes, offset: offset + 12), byteOrder: .little)
        }
        if dylibCommands.contains(command & 0x7FFF_FFFF) { dylibCount += 1 }
        offset += Int(size)
    }
    return LegacyArm64EFixtureInput(url: url, slice: slice, minimumDataOffset: 32 + UInt64(commandBytes),
        layout: layout, descriptor: descriptor, dylibCount: dylibCount)
}

private func legacyArm64ESectionFlagsOffset(bytes: Data, slice: MachOSlice, segmentName: String, sectionName: String) throws -> Int {
    let start = try #require(Int(exactly: slice.fileOffset))
    let commandCount = try legacyArm64EUInt32(bytes, offset: start + 16)
    var cursor = start + 32
    var matches: [Int] = []
    for _ in 0..<commandCount {
        let command = try legacyArm64EUInt32(bytes, offset: cursor)
        let commandSize = try legacyArm64EUInt32(bytes, offset: cursor + 4)
        try legacyArm64EFixtureRange(bytes, offset: cursor, count: Int(commandSize))
        if command == 0x19 {
            let sectionCount = try legacyArm64EUInt32(bytes, offset: cursor + 64)
            for index in 0..<sectionCount {
                let header = cursor + 72 + Int(index) * 80
                try legacyArm64EFixtureRange(bytes, offset: header, count: 80)
                let nameBytes = bytes[header..<(header + 16)].prefix { $0 != 0 }
                let segmentBytes = bytes[(header + 16)..<(header + 32)].prefix { $0 != 0 }
                guard let name = String(data: Data(nameBytes), encoding: .utf8),
                    let segment = String(data: Data(segmentBytes), encoding: .utf8) else {
                    throw LegacyArm64EFixtureError.nativeOutput("A native section header has invalid UTF-8 names.")
                }
                if name == sectionName && segment == segmentName { matches.append(header + 64) }
            }
        }
        cursor += Int(commandSize)
    }
    guard matches.count == 1, let offset = matches.first else {
        throw LegacyArm64EFixtureError.nativeOutput("The requested section flags have no unique native header.")
    }
    return offset
}

private func legacyArm64EPayloadOffset(_ input: LegacyArm64EFixtureInput) throws -> Int {
    guard let descriptor = input.descriptor else { throw LegacyArm64EFixtureError.missingFixups }
    return try #require(Int(exactly: input.slice.fileOffset + UInt64(descriptor.dataOffset)))
}

private func collectLegacyArm64EPointers(_ input: LegacyArm64EFixtureInput, containerSize: UInt64) throws -> StaticFeatureCollection<MachOChainedPointer> {
    guard let descriptor = input.descriptor else { throw LegacyArm64EFixtureError.missingFixups }
    let handle = try FileHandle(forReadingFrom: input.url)
    defer {
        do { try handle.close() }
        catch { Issue.record("Arm64e fixture handle close failed: \(error.localizedDescription)") }
    }
    let imports = try MachOChainedImportCollector.inspect(handle: handle, url: input.url, slice: input.slice,
        containerSize: containerSize, minimumDataOffset: input.minimumDataOffset, descriptor: descriptor, dylibCount: input.dylibCount)
    return try MachOChainedPointerCollector.collect(handle: handle, url: input.url, slice: input.slice,
        containerSize: containerSize, minimumDataOffset: input.minimumDataOffset, descriptor: descriptor,
        segments: input.layout.segments, imports: imports.entries)
}

private func legacyArm64EOracle(_ url: URL) throws -> LegacyArm64EOracle {
    let output = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"), arguments: ["dyld_info", "-fixup_chains", "-fixups", url.path])
    guard let text = String(data: output.standardOutput, encoding: .utf8) else { throw LegacyArm64EFixtureError.nativeOutput("Invalid UTF-8.") }
    var records: [NativeLegacyArm64EFixup] = []
    for line in text.split(separator: "\n") {
        let fields = line.split(whereSeparator: { $0.isWhitespace })
        guard fields.count >= 5, fields[0].hasPrefix("__"), fields[2].hasPrefix("0x") else { continue }
        guard let address = UInt64(fields[2].dropFirst(2), radix: 16) else { throw LegacyArm64EFixtureError.nativeOutput("Invalid fixup address.") }
        let value: NativeLegacyArm64EValue
        if ["rebase", "auth-rebase"].contains(fields[3]), fields[4].hasPrefix("0x"), let target = UInt64(fields[4].dropFirst(2), radix: 16) {
            value = .rebase(target)
        } else if ["bind", "auth-bind"].contains(fields[3]), let separator = fields[4].firstIndex(of: "/") {
            value = .bind(String(fields[4][fields[4].index(after: separator)...]))
        } else { throw LegacyArm64EFixtureError.nativeOutput("Unexpected fixup kind or target.") }
        let authentication: MachOChainedAuthentication?
        if fields[3].hasPrefix("auth-") {
            guard let diversityField = fields.first(where: { $0.hasPrefix("(div=0x") }),
                let diversity = UInt16(diversityField.dropFirst(7), radix: 16),
                let addressField = fields.first(where: { $0.hasPrefix("ad=") }), ["ad=0", "ad=1"].contains(addressField),
                let keyField = fields.first(where: { $0.hasPrefix("key=") }) else {
                throw LegacyArm64EFixtureError.nativeOutput("Missing authentication fields.")
            }
            let key: MachOChainedAuthenticationKey
            switch keyField {
            case "key=IA)": key = .instructionA
            case "key=IB)": key = .instructionB
            case "key=DA)": key = .dataA
            case "key=DB)": key = .dataB
            default: throw LegacyArm64EFixtureError.nativeOutput("Invalid authentication key.")
            }
            authentication = MachOChainedAuthentication(diversity: diversity, addressDiversity: addressField == "ad=1", key: key)
        } else { authentication = nil }
        records.append(NativeLegacyArm64EFixup(virtualAddress: address, value: value, authentication: authentication))
    }
    guard !records.isEmpty else { throw LegacyArm64EFixtureError.nativeOutput("No native fixups were printed.") }
    return LegacyArm64EOracle(text: text, fixups: records)
}

private func legacyArm64EFileOffset(_ address: UInt64, layout: MachOObjectiveCLayout, slice: MachOSlice) throws -> UInt64 {
    let segments = layout.segments.filter {
        address >= $0.virtualAddress && address - $0.virtualAddress <= $0.fileSize
            && 8 <= $0.fileSize - (address - $0.virtualAddress)
    }
    guard segments.count == 1, let segment = segments.first else { throw LegacyArm64EFixtureError.ambiguousAddress(address) }
    return slice.fileOffset + segment.fileOffset + address - segment.virtualAddress
}

private func legacyArm64EVirtualAddress(_ fileOffset: UInt64, layout: MachOObjectiveCLayout, slice: MachOSlice) throws -> UInt64 {
    guard fileOffset >= slice.fileOffset else { throw LegacyArm64EFixtureError.ambiguousAddress(fileOffset) }
    let relative = fileOffset - slice.fileOffset
    let segments = layout.segments.filter { relative >= $0.fileOffset && relative - $0.fileOffset < $0.fileSize }
    guard segments.count == 1, let segment = segments.first else { throw LegacyArm64EFixtureError.ambiguousAddress(fileOffset) }
    return segment.virtualAddress + relative - segment.fileOffset
}

private func verifyLegacyArm64ENameAndSlot(_ reference: StaticAPIReference, bytes: Data, url: URL, slice: MachOSlice) throws {
    #expect(reference.location.method == .objectiveCMetadata)
    #expect(reference.location.sourcePath == url.path)
    #expect(reference.location.architecture == slice.architecture)
    #expect(reference.location.sliceOffset == slice.fileOffset)
    let nameOffset = try #require(reference.location.fileOffset)
    let nameCount = try #require(reference.location.byteCount)
    let nameIndex = try #require(Int(exactly: nameOffset))
    let nameLength = try #require(Int(exactly: nameCount))
    try #require(nameLength > 0)
    try legacyArm64EFixtureRange(bytes, offset: nameIndex, count: nameLength)
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

private func collectLegacyArm64EFinding(_ url: URL) async throws -> ScanFinding {
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
        case .cancelled: Issue.record("Arm64e feature fixture collection was cancelled.")
        }
    }
    #expect(completed)
    #expect(issues.isEmpty)
    let selected = findings.filter { $0.path == url.path }
    #expect(selected.count == 1)
    return try #require(selected.first)
}

private func legacyArm64EFixtureRange(_ bytes: Data, offset: Int, count: Int) throws {
    guard offset >= 0, count >= 0, offset <= bytes.count, count <= bytes.count - offset else { throw LegacyArm64EFixtureError.range(offset, count) }
}

private func legacyArm64EUInt16(_ bytes: Data, offset: Int) throws -> UInt16 {
    try legacyArm64EFixtureRange(bytes, offset: offset, count: 2)
    return UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
}

private func legacyArm64EUInt32(_ bytes: Data, offset: Int) throws -> UInt32 {
    try legacyArm64EFixtureRange(bytes, offset: offset, count: 4)
    return (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[offset + $1]) << ($1 * 8) }
}

private func legacyArm64EUInt64(_ bytes: Data, offset: Int) throws -> UInt64 {
    try legacyArm64EFixtureRange(bytes, offset: offset, count: 8)
    return (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[offset + $1]) << ($1 * 8) }
}

private func replacingLegacyArm64EInteger(_ bytes: Data, offset: Int, value: UInt64, width: Int) throws -> Data {
    try legacyArm64EFixtureRange(bytes, offset: offset, count: width)
    var result = bytes
    for index in 0..<width { result[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
    return result
}
