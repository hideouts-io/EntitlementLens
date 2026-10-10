import Foundation

enum MachOObjectiveCReferenceError: LocalizedError {
    case unsupported(String, String)
    case invalid(String, UInt64, String)
    case limitExceeded(String, String, UInt64, UInt64)
    case incompletePointerSource(String, StaticCollectionState, String)

    var collectionState: StaticCollectionState {
        switch self {
        case .unsupported: .unsupported
        case .invalid: .unavailable
        case .limitExceeded: .partial
        case let .incompletePointerSource(_, state, _): state
        }
    }

    var errorDescription: String? {
        switch self {
        case let .unsupported(path, reason): "Objective-C reference collection in \(path) is unsupported: \(reason)"
        case let .invalid(path, offset, reason): "Objective-C reference evidence in \(path) is invalid at file offset \(offset): \(reason)"
        case let .limitExceeded(path, name, declared, limit):
            "Objective-C reference collection in \(path) requires \(declared) \(name); the collection limit is \(limit)."
        case let .incompletePointerSource(path, state, reason):
            "Objective-C pointer coverage in \(path) is \(state.rawValue): \(reason) Metadata names require complete validated pointer coverage."
        }
    }
}

/// Collects static metadata references without registering selectors, loading images, or resolving runtime classes.
enum MachOObjectiveCReferenceCollector {
    private static let maximumReferenceCount: UInt64 = 4_096
    private static let maximumSourceSlots: UInt64 = 65_536
    private static let maximumNameBytes: UInt64 = 4_096
    private static let maximumLiteralBytes: UInt64 = 16 * 1_024 * 1_024
    private static let maximumDiagnosticCount = 32
    private static let classSymbolPrefix = "_OBJC_CLASS_$_"

    static let limits: [StaticCollectionLimit] = [
        StaticCollectionLimit(name: "objc_reference_records_per_slice", value: maximumReferenceCount, unit: .records),
        StaticCollectionLimit(name: "objc_reference_slots_per_slice", value: maximumSourceSlots, unit: .records),
        StaticCollectionLimit(name: "objc_reference_name_bytes", value: maximumNameBytes, unit: .bytes),
        StaticCollectionLimit(name: "objc_method_name_pool_bytes_per_slice", value: maximumLiteralBytes, unit: .bytes),
        StaticCollectionLimit(name: "objc_reference_diagnostics_per_slice", value: UInt64(maximumDiagnosticCount), unit: .records)
    ]

    static let limitations: [String] = [
        "Only 64-bit little-endian linked Mach-O selector and externally bound class-reference sections are collected, using ordinary bindings or validated chained-pointer formats 2, 6, arm64e format 1, and arm64e userland24 format 12. Other authenticated formats, shared-cache, and optimized metadata are unsupported.",
        "Selectors are exact strings reached from __objc_selrefs into file-backed __TEXT,__objc_methname. Unreferenced method strings and selector-looking raw strings are not emitted.",
        "Class names are exact suffixes of _OBJC_CLASS_$_ symbols from unique positive-import bindings with zero combined addend at __objc_classrefs slots. Local, unbound, special-lookup, and ambiguous class slots are not named.",
        "Every ordinary binding name must have a validated, aligned eight-byte file-backed pointer slot before metadata attribution. A complete name collection with nonzero-addend, nonpointer, unaligned, or VM-only bindings is insufficient; Objective-C metadata collection is unsupported for that slice.",
        "Chained metadata requires complete pointer coverage and aligned eight-byte fixup slots. Selector slots must contain a decoded local rebase; class slots must contain a decoded external bind. Missing fixups and nonzero class addends remain incomplete evidence; encoded words are never interpreted as raw addresses.",
        "__AUTH and __AUTH_CONST reference sections require complete format-1 or format-12 pointer coverage. Authentication fields describe on-disk fixup declarations; no pointer authentication is performed or established.",
        "Primary locations identify literal name bytes, including the NUL terminator; reference_location identifies the referring eight-byte metadata slot. Repeated metadata references remain separate records in section/slot order.",
        "References do not establish calls, class availability, receiver-selector relationships, or runtime behavior. Class definitions, superclass metadata, protocols, categories, dynamic lookups, and method-list layouts are outside this collection."
    ]

    private struct LiteralPool {
        let section: MachOObjectiveCSection
        let bytes: Data
    }

    private enum ReferenceSlots {
        case ordinaryBindings([UInt64: [StaticAPIReference]])
        case chainedFixups([UInt64: MachOChainedPointer])
    }

    static func collect(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        sections: [MachOObjectiveCSection],
        byteOrder: MachOByteOrder,
        fileType: UInt32,
        machHeaderFlags: UInt32,
        pointerSource: MachOObjectiveCPointerSource
    ) throws -> StaticFeatureCollection<StaticAPIReference> {
        try Task.checkCancellation()
        let references = sections.filter {
            ["__objc_selrefs", "__objc_classrefs"].contains($0.sectionName) && $0.byteCount > 0
        }
        guard !references.isEmpty else {
            return StaticFeatureCollection(state: .notApplicable, reason: "No supported Objective-C reference sections are present.",
                records: [], limitations: limitations, limits: limits)
        }
        do {
            guard byteOrder == .little, [UInt32(2), 6, 8].contains(fileType) else {
                throw MachOObjectiveCReferenceError.unsupported(url.path,
                    "Only little-endian MH_EXECUTE, MH_DYLIB, and MH_BUNDLE metadata with a supported pointer source is collected.")
            }
            guard machHeaderFlags & 0x8000_0000 == 0 else {
                throw MachOObjectiveCReferenceError.unsupported(url.path, "MH_DYLIB_IN_CACHE requires shared-cache pointer decoding.")
            }
            _ = try MachOByteRange(offset: slice.fileOffset, length: slice.fileSize,
                containerLength: containerSize, path: url.path, context: .fatSlice)
            for section in sections {
                try validate(section: section, slice: slice, minimumDataOffset: minimumDataOffset, path: url.path)
            }
            try validateImageInfo(handle: handle, url: url, slice: slice, containerSize: containerSize, sections: sections)
            let bySlot = try referenceSlots(pointerSource, slice: slice, path: url.path)
            try validateReferenceSegments(references, pointers: bySlot, path: url.path)
            let pools = try readLiteralPools(handle: handle, url: url, slice: slice,
                containerSize: containerSize, sections: sections)
            return try collectSlots(handle: handle, url: url, slice: slice, containerSize: containerSize,
                references: references, pools: pools, pointers: bySlot)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as MachOObjectiveCReferenceError {
            return failure(error.localizedDescription, state: error.collectionState)
        } catch let error as MachOByteRangeError {
            return failure(error.localizedDescription, state: .unavailable)
        } catch let error as MachOInspectionError {
            return failure(error.localizedDescription, state: .unavailable)
        } catch let error as CocoaError {
            return failure(error.localizedDescription, state: .unavailable)
        } catch let error as POSIXError {
            return failure(error.localizedDescription, state: .unavailable)
        }
    }

    private static func validateReferenceSegments(
        _ references: [MachOObjectiveCSection], pointers: ReferenceSlots, path: String
    ) throws {
        let supportsAuthenticationSections: Bool
        switch pointers {
        case .ordinaryBindings:
            supportsAuthenticationSections = false
        case let .chainedFixups(slots):
            supportsAuthenticationSections = !slots.isEmpty
                && slots.values.allSatisfy { $0.format == .arm64e || $0.format == .arm64eUserland24 }
        }
        for section in references {
            if ["__DATA", "__DATA_CONST", "__DATA_DIRTY"].contains(section.segmentName) { continue }
            guard supportsAuthenticationSections, ["__AUTH", "__AUTH_CONST"].contains(section.segmentName) else {
                throw MachOObjectiveCReferenceError.unsupported(path,
                    "Reference sections outside conventional data segments require validated format-1 or format-12 pointers in __AUTH or __AUTH_CONST; other segment layouts are not collected.")
            }
        }
    }

    private static func referenceSlots(
        _ source: MachOObjectiveCPointerSource, slice: MachOSlice, path: String
    ) throws -> ReferenceSlots {
        switch source {
        case let .ordinaryBindings(bindings):
            guard bindings.state == .complete else {
                throw MachOObjectiveCReferenceError.unsupported(path,
                    "Ordinary binding evidence is incomplete (\(bindings.state.rawValue)): \(bindings.reason ?? "not all binding operations were established").")
            }
            return .ordinaryBindings(try bindingSlots(bindings, slice: slice, path: path))
        case let .chainedFixups(pointers):
            guard pointers.state == .complete else {
                throw MachOObjectiveCReferenceError.incompletePointerSource(path, pointers.state,
                    pointers.reason ?? "Not every declared chained pointer was established.")
            }
            return .chainedFixups(try chainedSlots(pointers.records, slice: slice, path: path))
        case let .unavailable(reason):
            throw MachOObjectiveCReferenceError.unsupported(path, "The pointer source is unavailable: \(reason)")
        }
    }

    private static func validate(
        section: MachOObjectiveCSection, slice: MachOSlice, minimumDataOffset: UInt64, path: String
    ) throws {
        let range = try MachOByteRange(offset: section.fileOffset, length: section.byteCount,
            containerLength: slice.fileSize, path: path, context: .fileRead)
        let end = section.virtualAddress.addingReportingOverflow(section.byteCount)
        guard !end.overflow, range.offset >= minimumDataOffset, section.alignmentExponent < 64 else {
            throw MachOObjectiveCReferenceError.invalid(path, slice.fileOffset + range.offset,
                "The selected section's virtual extent, alignment, or file-backed header boundary is invalid.")
        }
        guard section.relocationCount == 0 else {
            throw MachOObjectiveCReferenceError.unsupported(path, "Section relocations are not resolved for Objective-C metadata.")
        }
        if ["__objc_selrefs", "__objc_classrefs"].contains(section.sectionName) {
            let expected: UInt32 = section.sectionName == "__objc_selrefs"
                && !["__AUTH", "__AUTH_CONST"].contains(section.segmentName) ? 5 : 0
            guard section.flags & 0xFF == expected, section.byteCount % 8 == 0,
                section.fileOffset % 8 == 0, section.virtualAddress % 8 == 0 else {
                throw MachOObjectiveCReferenceError.invalid(path, slice.fileOffset + range.offset,
                    "An Objective-C reference section must contain aligned eight-byte entries of its declared pointer-section type.")
            }
        }
    }

    private static func validateImageInfo(
        handle: FileHandle, url: URL, slice: MachOSlice, containerSize: UInt64, sections: [MachOObjectiveCSection]
    ) throws {
        let descriptors = sections.filter { $0.sectionName == "__objc_imageinfo" }
        guard descriptors.count == 1, let section = descriptors.first else {
            throw MachOObjectiveCReferenceError.unsupported(url.path,
                "Exactly one __objc_imageinfo descriptor is required to establish the supported image-info ABI.")
        }
        guard section.byteCount == 8, section.flags & 0xFF == 0 else {
            throw MachOObjectiveCReferenceError.invalid(url.path, slice.fileOffset + section.fileOffset,
                "__objc_imageinfo must contain one regular eight-byte version/flags record.")
        }
        let bytes = try read(handle: handle, offset: slice.fileOffset + section.fileOffset,
            length: 8, containerSize: containerSize, path: url.path)
        let version = uint32(bytes, offset: 0)
        let flags = uint32(bytes, offset: 4)
        guard version == 0, flags & 0x88 == 0 else {
            throw MachOObjectiveCReferenceError.unsupported(url.path,
                "Image-info version \(version) and flags 0x\(String(flags, radix: 16)) do not establish unoptimized version-zero metadata.")
        }
    }

    private static func bindingSlots(
        _ collection: StaticFeatureCollection<StaticAPIReference>, slice: MachOSlice, path: String
    ) throws -> [UInt64: [StaticAPIReference]] {
        var result: [UInt64: [StaticAPIReference]] = [:]
        for record in collection.records {
            try Task.checkCancellation()
            guard matches(record.location, slice: slice, path: path), record.location.method == .dyldBindStream else {
                throw MachOObjectiveCReferenceError.invalid(path, slice.fileOffset,
                    "Ordinary binding evidence belongs to a different source, architecture, slice, or collection method.")
            }
            guard let primaryOffset = record.location.fileOffset, let primaryCount = record.location.byteCount,
                primaryCount == UInt64(record.name.utf8.count) + 1 else {
                throw MachOObjectiveCReferenceError.invalid(path, slice.fileOffset,
                    "A binding name lacks its exact file-backed string extent.")
            }
            try validateEvidenceRange(offset: primaryOffset, count: primaryCount, slice: slice, path: path)
            guard let slot = record.referenceLocation else {
                throw MachOObjectiveCReferenceError.unsupported(path,
                    "Ordinary binding slot attribution is incomplete: a binding does not establish a zero-addend, full-width file-backed pointer slot. Selector and class names cannot be attributed safely.")
            }
            guard matches(slot, slice: slice, path: path), slot.method == .dyldBindStream,
                let offset = slot.fileOffset, slot.byteCount == 8 else {
                throw MachOObjectiveCReferenceError.invalid(path, slice.fileOffset,
                    "A binding slot lacks matching source identity or an eight-byte pointer extent.")
            }
            try validateEvidenceRange(offset: offset, count: 8, slice: slice, path: path)
            guard (offset - slice.fileOffset) % 8 == 0 else {
                throw MachOObjectiveCReferenceError.unsupported(path,
                    "An ordinary eight-byte binding target is unaligned relative to the slice and could overlap an Objective-C metadata slot without matching its start. Metadata slot attribution is unsupported.")
            }
            result[offset, default: []].append(record)
        }
        return result
    }

    private static func validateEvidenceRange(offset: UInt64, count: UInt64, slice: MachOSlice, path: String) throws {
        guard offset >= slice.fileOffset else {
            throw MachOObjectiveCReferenceError.invalid(path, offset, "Binding evidence precedes its declared slice.")
        }
        _ = try MachOByteRange(offset: offset - slice.fileOffset, length: count,
            containerLength: slice.fileSize, path: path, context: .fileRead)
    }

    private static func chainedSlots(
        _ records: [MachOChainedPointer], slice: MachOSlice, path: String
    ) throws -> [UInt64: MachOChainedPointer] {
        guard UInt64(records.count) <= maximumSourceSlots else {
            throw MachOObjectiveCReferenceError.limitExceeded(path, "chained pointer slots",
                UInt64(records.count), maximumSourceSlots)
        }
        var result: [UInt64: MachOChainedPointer] = [:]
        guard Set(records.map(\.format)).count <= 1 else {
            throw MachOObjectiveCReferenceError.invalid(path, slice.fileOffset,
                "Chained pointers declare different formats within one image.")
        }
        for pointer in records {
            try Task.checkCancellation()
            let slot = pointer.location
            guard matches(slot, slice: slice, path: path), slot.method == .chainedFixupPointer,
                let offset = slot.fileOffset, slot.byteCount == 8 else {
                throw MachOObjectiveCReferenceError.invalid(path, slice.fileOffset,
                    "A chained pointer slot lacks matching source identity or an eight-byte file extent.")
            }
            try validateEvidenceRange(offset: offset, count: 8, slice: slice, path: path)
            guard pointer.authentication == nil || pointer.format == .arm64e || pointer.format == .arm64eUserland24 else {
                throw MachOObjectiveCReferenceError.invalid(path, offset,
                    "Authentication descriptors require arm64e pointer format 1 or arm64e userland24 pointer format 12.")
            }
            guard (offset - slice.fileOffset) % 8 == 0 else {
                throw MachOObjectiveCReferenceError.unsupported(path,
                    "An unaligned chained pointer could overlap a metadata slot without matching its start.")
            }
            guard result[offset] == nil else {
                throw MachOObjectiveCReferenceError.invalid(path, offset,
                    "Multiple chained pointers claim the same file-backed metadata slot.")
            }
            if case let .bind(reference, _) = pointer.value {
                guard matches(reference.location, slice: slice, path: path),
                    reference.location.method == .chainedFixupImports, reference.referenceLocation == nil,
                    reference.kind == .importedSymbol || reference.kind == .dyldBindingSymbol,
                    let nameOffset = reference.location.fileOffset, let nameCount = reference.location.byteCount,
                    nameCount == UInt64(reference.name.utf8.count) + 1 else {
                    throw MachOObjectiveCReferenceError.invalid(path, offset,
                        "A chained binding lacks its validated import-table name and source identity.")
                }
                try validateEvidenceRange(offset: nameOffset, count: nameCount, slice: slice, path: path)
            }
            result[offset] = pointer
        }
        return result
    }

    private static func matches(_ location: StaticEvidenceLocation, slice: MachOSlice, path: String) -> Bool {
        location.sourcePath == path && location.architecture == slice.architecture && location.sliceOffset == slice.fileOffset
    }

    private static func readLiteralPools(
        handle: FileHandle, url: URL, slice: MachOSlice, containerSize: UInt64, sections: [MachOObjectiveCSection]
    ) throws -> [LiteralPool] {
        let descriptors = sections.filter { $0.segmentName == "__TEXT" && $0.sectionName == "__objc_methname" }
        var byteCount: UInt64 = 0
        for section in descriptors {
            guard section.flags & 0xFF == 2 else {
                throw MachOObjectiveCReferenceError.unsupported(url.path,
                    "__TEXT,__objc_methname does not declare a C-string literal section.")
            }
            guard section.byteCount <= maximumLiteralBytes - byteCount else {
                throw MachOObjectiveCReferenceError.limitExceeded(url.path, "method-name pool bytes",
                    section.byteCount, maximumLiteralBytes)
            }
            byteCount += section.byteCount
        }
        return try descriptors.map { section in
            LiteralPool(section: section, bytes: try read(handle: handle,
                offset: slice.fileOffset + section.fileOffset, length: section.byteCount,
                containerSize: containerSize, path: url.path))
        }
    }

    private static func collectSlots(
        handle: FileHandle, url: URL, slice: MachOSlice, containerSize: UInt64,
        references: [MachOObjectiveCSection], pools: [LiteralPool], pointers: ReferenceSlots
    ) throws -> StaticFeatureCollection<StaticAPIReference> {
        var records: [StaticAPIReference] = []
        var diagnostics: [String] = []
        var failureCount: UInt64 = 0
        var examinedSlots: UInt64 = 0
        var reachedLimit: String?
        referenceSections: for section in references {
            for index in 0..<(section.byteCount / 8) {
                try Task.checkCancellation()
                guard UInt64(records.count) < maximumReferenceCount else {
                    reachedLimit = "objc_reference_records_per_slice limit of \(maximumReferenceCount) retained records"
                    break referenceSections
                }
                guard examinedSlots < maximumSourceSlots else {
                    reachedLimit = "objc_reference_slots_per_slice limit of \(maximumSourceSlots) examined slots"
                    break referenceSections
                }
                examinedSlots += 1
                let offset = slice.fileOffset + section.fileOffset + index * 8
                do {
                    let bytes = try read(handle: handle, offset: offset, length: 8, containerSize: containerSize, path: url.path)
                    let slot = location(url: url, slice: slice, offset: offset, count: 8)
                    let record = try reference(section: section, bytes: bytes, slot: slot,
                        pointers: pointers, pools: pools, url: url, slice: slice)
                    records.append(record)
                } catch let error as MachOObjectiveCReferenceError {
                    failureCount += 1
                    if diagnostics.count < maximumDiagnosticCount { diagnostics.append(error.localizedDescription) }
                } catch let error as MachOInspectionError {
                    failureCount += 1
                    if diagnostics.count < maximumDiagnosticCount { diagnostics.append(error.localizedDescription) }
                    break referenceSections
                } catch let error as CocoaError {
                    failureCount += 1
                    if diagnostics.count < maximumDiagnosticCount { diagnostics.append(error.localizedDescription) }
                    break referenceSections
                } catch let error as POSIXError {
                    failureCount += 1
                    if diagnostics.count < maximumDiagnosticCount { diagnostics.append(error.localizedDescription) }
                    break referenceSections
                }
            }
        }
        try Task.checkCancellation()
        var issues = limitations + diagnostics
        if failureCount > UInt64(diagnostics.count) {
            issues.append("\(failureCount - UInt64(diagnostics.count)) additional Objective-C slot diagnostics exceeded the diagnostic limit.")
        }
        if let reachedLimit {
            issues.append("The \(reachedLimit) was reached; subsequent Objective-C slots were not collected.")
        }
        let reason: String?
        if let reachedLimit {
            reason = "Objective-C collection for \(slice.architecture) at slice offset \(slice.fileOffset) reached the \(reachedLimit)."
        } else if failureCount > 0 {
            reason = "\(failureCount) Objective-C metadata slots in \(slice.architecture) at slice offset \(slice.fileOffset) could not be named; valid references were retained."
        } else { reason = nil }
        return StaticFeatureCollection(state: reachedLimit != nil || failureCount > 0 ? .partial : .complete,
            reason: reason, records: records, limitations: issues, limits: limits)
    }

    private static func reference(
        section: MachOObjectiveCSection, bytes: Data, slot: StaticEvidenceLocation,
        pointers: ReferenceSlots, pools: [LiteralPool], url: URL, slice: MachOSlice
    ) throws -> StaticAPIReference {
        guard let offset = slot.fileOffset else {
            throw MachOObjectiveCReferenceError.invalid(url.path, slice.fileOffset,
                "The metadata reference slot has no file-backed location.")
        }
        switch pointers {
        case let .ordinaryBindings(bindings):
            return section.sectionName == "__objc_selrefs"
                ? try selectorReference(pointer: uint64(bytes), slot: slot, pools: pools,
                    bindings: bindings[offset] ?? [], url: url, slice: slice)
                : try classReference(slot: slot, bindings: bindings[offset] ?? [], url: url, slice: slice)
        case let .chainedFixups(pointers):
            guard let pointer = pointers[offset] else {
                throw MachOObjectiveCReferenceError.invalid(url.path, offset,
                    "The encoded metadata slot was not reached by a validated chained fixup.")
            }
            switch pointer.value {
            case let .rebase(target):
                guard section.sectionName == "__objc_selrefs" else {
                    throw MachOObjectiveCReferenceError.unsupported(url.path,
                        "The class-reference slot contains a local rebase; local class layouts are not collected.")
                }
                return try selectorReference(pointer: target, slot: slot, pools: pools,
                    bindings: [], url: url, slice: slice)
            case let .bind(reference, addend):
                guard section.sectionName == "__objc_classrefs", addend == 0 else {
                    throw MachOObjectiveCReferenceError.unsupported(url.path,
                        "A selector binding or class binding with nonzero combined addend does not establish the supported metadata reference.")
                }
                return try classReference(slot: slot, bindings: [reference], url: url, slice: slice)
            }
        }
    }

    private static func selectorReference(
        pointer: UInt64, slot: StaticEvidenceLocation, pools: [LiteralPool],
        bindings: [StaticAPIReference], url: URL, slice: MachOSlice
    ) throws -> StaticAPIReference {
        guard bindings.isEmpty else {
            throw MachOObjectiveCReferenceError.unsupported(url.path,
                "A selector-reference slot has a binding operation; its raw word is not established as a local selector pointer.")
        }
        let candidates = pools.filter {
            pointer >= $0.section.virtualAddress && pointer - $0.section.virtualAddress < $0.section.byteCount
        }
        guard candidates.count == 1, let pool = candidates.first else {
            throw MachOObjectiveCReferenceError.invalid(url.path, slot.fileOffset ?? slice.fileOffset,
                "The selector pointer does not map uniquely into file-backed __TEXT,__objc_methname bytes.")
        }
        let delta = pointer - pool.section.virtualAddress
        let start = Int(delta)
        let count = min(pool.bytes.count - start, Int(maximumNameBytes) + 1)
        let bytes = pool.bytes[start..<(start + count)]
        guard let terminator = bytes.firstIndex(of: 0), terminator > start,
            let name = String(data: pool.bytes[start..<terminator], encoding: .utf8) else {
            throw MachOObjectiveCReferenceError.invalid(url.path, slice.fileOffset + pool.section.fileOffset + delta,
                "The selector name is empty, invalid UTF-8, or lacks a NUL terminator within the method-name section and 4096-byte name limit.")
        }
        return StaticAPIReference(name: name, kind: .objectiveCSelector,
            location: location(url: url, slice: slice, offset: slice.fileOffset + pool.section.fileOffset + delta,
                count: UInt64(name.utf8.count) + 1), referenceLocation: slot)
    }

    private static func classReference(
        slot: StaticEvidenceLocation, bindings: [StaticAPIReference], url: URL, slice: MachOSlice
    ) throws -> StaticAPIReference {
        guard bindings.count == 1, let binding = bindings.first, binding.kind == .importedSymbol,
            binding.name.hasPrefix(classSymbolPrefix) else {
            throw MachOObjectiveCReferenceError.unsupported(url.path,
                "The class-reference slot is local, unbound, ambiguous, or lacks a unique external _OBJC_CLASS_$_ pointer binding.")
        }
        let name = String(binding.name.dropFirst(classSymbolPrefix.count))
        guard !name.isEmpty, UInt64(name.utf8.count) <= maximumNameBytes,
            let primaryOffset = binding.location.fileOffset else {
            throw MachOObjectiveCReferenceError.invalid(url.path, slot.fileOffset ?? slice.fileOffset,
                "The external Objective-C class name is empty or exceeds the 4096-byte name limit.")
        }
        return StaticAPIReference(name: name, kind: .objectiveCClass,
            location: location(url: url, slice: slice, offset: primaryOffset + UInt64(classSymbolPrefix.utf8.count),
                count: UInt64(name.utf8.count) + 1), referenceLocation: slot)
    }

    private static func location(url: URL, slice: MachOSlice, offset: UInt64, count: UInt64) -> StaticEvidenceLocation {
        StaticEvidenceLocation(sourcePath: url.path, architecture: slice.architecture, sliceOffset: slice.fileOffset,
            fileOffset: offset, byteCount: count, propertyListKey: nil, method: .objectiveCMetadata)
    }

    private static func uint32(_ data: Data, offset: Int) -> UInt32 {
        data[offset..<(offset + 4)].enumerated().reduce(0) { value, byte in
            value | UInt32(byte.element) << UInt32(byte.offset * 8)
        }
    }

    private static func uint64(_ data: Data) -> UInt64 {
        data.enumerated().reduce(0) { value, byte in value | UInt64(byte.element) << UInt64(byte.offset * 8) }
    }

    private static func read(handle: FileHandle, offset: UInt64, length: UInt64, containerSize: UInt64, path: String) throws -> Data {
        try Task.checkCancellation()
        _ = try MachOByteRange(offset: offset, length: length, containerLength: containerSize, path: path, context: .fileRead)
        if length == 0 { return Data() }
        try handle.seek(toOffset: offset)
        guard let bytes = try handle.read(upToCount: Int(length)), bytes.count == Int(length) else {
            throw MachOInspectionError.truncated(path, offset)
        }
        return bytes
    }

    private static func failure(_ reason: String, state: StaticCollectionState) -> StaticFeatureCollection<StaticAPIReference> {
        StaticFeatureCollection(state: state, reason: reason, records: [], limitations: limitations, limits: limits)
    }
}
