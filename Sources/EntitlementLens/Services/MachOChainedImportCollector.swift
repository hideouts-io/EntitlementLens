import Foundation

enum MachOChainedImportError: LocalizedError {
    case unsupportedByteOrder(String)
    case unsupportedVersion(String, UInt32)
    case unsupportedFormat(String, String, UInt32)
    case unsupportedOrdering(String, UInt32, UInt32, UInt32)
    case invalidTable(String, String)
    case invalidImport(String, UInt32, String)
    case limitExceeded(String, String, UInt64, UInt64)

    var errorDescription: String? {
        switch self {
        case let .unsupportedByteOrder(path):
            "LC_DYLD_CHAINED_FIXUPS imports in \(path) require little-endian Mach-O data; big-endian collection is unsupported."
        case let .unsupportedVersion(path, version):
            "LC_DYLD_CHAINED_FIXUPS in \(path) declares fixups_version \(version); only version zero is supported."
        case let .unsupportedFormat(path, field, value):
            "LC_DYLD_CHAINED_FIXUPS in \(path) declares unsupported \(field) \(value)."
        case let .unsupportedOrdering(path, starts, imports, symbols):
            "LC_DYLD_CHAINED_FIXUPS in \(path) has unsupported region ordering (starts_offset \(starts), imports_offset \(imports), symbols_offset \(symbols)); collection requires starts metadata before the import table and symbol pool."
        case let .invalidTable(path, reason):
            "The LC_DYLD_CHAINED_FIXUPS import table in \(path) is invalid: \(reason)"
        case let .invalidImport(path, index, reason):
            "Chained-fixup import \(index) in \(path) is invalid: \(reason)"
        case let .limitExceeded(path, name, declared, limit):
            "Chained-fixup import collection in \(path) requires \(declared) \(name); the collection limit is \(limit)."
        }
    }
}

/// Collects import-table declarations using the SDK's fixup-chains.h layouts.
/// Pointer chains and their import ordinal references are not traversed or validated.
enum MachOChainedImportCollector {
    private static let headerBytes: UInt64 = 28
    private static let maximumPayloadBytes: UInt64 = 32 * 1_024 * 1_024
    private static let maximumStringPoolBytes: UInt64 = 16 * 1_024 * 1_024
    private static let maximumImportCount: UInt64 = 250_000
    private static let maximumReferenceCount: UInt64 = 16_384
    private static let maximumSymbolNameBytes: UInt64 = 4_096
    private static let maximumDiagnosticCount = 32

    static let limits: [StaticCollectionLimit] = [
        StaticCollectionLimit(name: "chained_fixup_payload_bytes_per_slice", value: maximumPayloadBytes, unit: .bytes),
        StaticCollectionLimit(name: "chained_import_records_per_slice", value: maximumImportCount, unit: .records),
        StaticCollectionLimit(name: "chained_symbol_pool_bytes_per_slice", value: maximumStringPoolBytes, unit: .bytes),
        StaticCollectionLimit(name: "chained_imported_references_per_slice", value: maximumReferenceCount, unit: .records),
        StaticCollectionLimit(name: "chained_symbol_name_bytes", value: maximumSymbolNameBytes, unit: .bytes),
        StaticCollectionLimit(name: "chained_import_diagnostics_per_slice", value: UInt64(maximumDiagnosticCount), unit: .records)
    ]

    static let limitations: [String] = [
        "Only little-endian version-zero chained-fixup import tables in formats 1, 2, and 3 with uncompressed symbol pools and starts-before-imports-before-names region ordering are collected.",
        "Records are import-table declarations in table order. Duplicate names and shared string offsets are retained; no pointer-chain usage or API calls are inferred.",
        "starts_offset is range-bounded separately from the header, import table, and names; segment-start metadata and pointer chains are not decoded or validated.",
        "Positive library ordinals are checked against declared dependencies. SELF and recognized special lookups use dyld_binding_symbol because external ownership is not established; ordinals, weak-import flags, and addends are not exported.",
        "Dynamic lookups, Objective-C metadata, and raw strings beyond declared import-table names are not collected."
    ]

    enum ImportFormat: UInt32 {
        case plain = 1
        case addend = 2
        case addend64 = 3

        var recordBytes: UInt64 {
            switch self {
            case .plain: 4
            case .addend: 8
            case .addend64: 16
            }
        }
    }

    struct Header {
        let startsOffset: UInt32
        let importsOffset: UInt32
        let symbolsOffset: UInt32
        let importCount: UInt32
        let format: ImportFormat
    }

    private struct Import {
        let nameOffset: UInt32
        let kind: StaticAPIReferenceKind
        let addend: Int64
    }

    /// Shared validated layout for import names and bounded pointer-chain traversal.
    struct Layout {
        let payloadRange: MachOByteRange
        let payloadFileOffset: UInt64
        let header: Header
        let importsRange: MachOByteRange
        let stringsRange: MachOByteRange
    }

    static func collect(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        descriptor: MachOChainedImportDescriptor,
        dylibCount: UInt32
    ) throws -> StaticFeatureCollection<StaticAPIReference> {
        try inspect(handle: handle, url: url, slice: slice, containerSize: containerSize,
            minimumDataOffset: minimumDataOffset, descriptor: descriptor, dylibCount: dylibCount).references
    }

    /// Entry completeness describes the entire import table, independently of legacy table-only API coverage.
    static func inspect(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        descriptor: MachOChainedImportDescriptor,
        dylibCount: UInt32
    ) throws -> MachOChainedImportInspection {
        try Task.checkCancellation()
        do {
            return try readInspection(handle: handle, url: url, slice: slice, containerSize: containerSize,
                minimumDataOffset: minimumDataOffset, descriptor: descriptor, dylibCount: dylibCount)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as MachOChainedImportError {
            let state: StaticCollectionState
            switch error {
            case .unsupportedByteOrder, .unsupportedVersion, .unsupportedFormat, .unsupportedOrdering: state = .unsupported
            case .limitExceeded: state = .partial
            case .invalidTable, .invalidImport: state = .unavailable
            }
            return failedInspection(slice: slice, reason: error.localizedDescription, state: state)
        } catch let error as MachOByteRangeError {
            return failedInspection(slice: slice, reason: error.localizedDescription, state: .unavailable)
        } catch let error as MachOInspectionError {
            return failedInspection(slice: slice, reason: error.localizedDescription, state: .unavailable)
        } catch let error as CocoaError {
            return failedInspection(slice: slice, reason: error.localizedDescription, state: .unavailable)
        } catch let error as POSIXError {
            return failedInspection(slice: slice, reason: error.localizedDescription, state: .unavailable)
        }
    }

    static func readLayout(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        descriptor: MachOChainedImportDescriptor
    ) throws -> Layout {
        try Task.checkCancellation()
        guard descriptor.byteOrder == .little else {
            throw MachOChainedImportError.unsupportedByteOrder(url.path)
        }
        _ = try MachOByteRange(offset: slice.fileOffset, length: slice.fileSize, containerLength: containerSize,
            path: url.path, context: .fatSlice)
        let payloadRange = try MachOByteRange(offset: UInt64(descriptor.dataOffset), length: UInt64(descriptor.dataSize),
            containerLength: slice.fileSize, path: url.path, context: .fileRead)
        guard payloadRange.offset >= minimumDataOffset else {
            throw MachOChainedImportError.invalidTable(url.path, "The payload overlaps the Mach-O header or load commands.")
        }
        guard payloadRange.length >= headerBytes else {
            throw MachOChainedImportError.invalidTable(url.path, "The payload is shorter than the 28-byte fixups header.")
        }
        guard payloadRange.length <= maximumPayloadBytes else {
            throw MachOChainedImportError.limitExceeded(url.path, "payload bytes", payloadRange.length, maximumPayloadBytes)
        }
        let payloadFileOffset = slice.fileOffset + payloadRange.offset
        let headerData = try read(handle: handle, offset: payloadFileOffset, length: headerBytes,
            containerSize: containerSize, path: url.path)
        let header = try decodeHeader(headerData, path: url.path)
        guard UInt64(header.importCount) <= maximumImportCount else {
            throw MachOChainedImportError.limitExceeded(url.path, "import records", UInt64(header.importCount), maximumImportCount)
        }
        let importsRange = try MachOByteRange(offset: UInt64(header.importsOffset),
            length: UInt64(header.importCount) * header.format.recordBytes,
            containerLength: payloadRange.length, path: url.path, context: .fileRead)
        guard UInt64(header.symbolsOffset) <= payloadRange.length else {
            throw MachOChainedImportError.invalidTable(url.path, "symbols_offset exceeds the chained-fixup payload.")
        }
        let stringsRange = try MachOByteRange(offset: UInt64(header.symbolsOffset),
            length: payloadRange.length - UInt64(header.symbolsOffset),
            containerLength: payloadRange.length, path: url.path, context: .fileRead)
        let startsHeaderRange = try MachOByteRange(offset: UInt64(header.startsOffset), length: 4,
            containerLength: payloadRange.length, path: url.path, context: .fileRead)
        guard startsHeaderRange.offset >= headerBytes, importsRange.offset >= headerBytes,
            stringsRange.offset >= headerBytes else {
            throw MachOChainedImportError.invalidTable(url.path,
                "starts_offset, the import table, or the symbol pool overlap the fixed header.")
        }
        guard importsRange.end <= stringsRange.offset else {
            throw MachOChainedImportError.invalidTable(url.path, "The import table overlaps the symbol pool.")
        }
        guard startsHeaderRange.offset <= importsRange.offset else {
            throw MachOChainedImportError.unsupportedOrdering(url.path, header.startsOffset,
                header.importsOffset, header.symbolsOffset)
        }
        guard startsHeaderRange.end <= importsRange.offset else {
            throw MachOChainedImportError.invalidTable(url.path, "The starts metadata header overlaps the import table.")
        }
        guard stringsRange.length <= maximumStringPoolBytes else {
            throw MachOChainedImportError.limitExceeded(url.path, "symbol-pool bytes", stringsRange.length, maximumStringPoolBytes)
        }
        guard header.importCount == 0 || stringsRange.length > 0 else {
            throw MachOChainedImportError.invalidTable(url.path, "A nonempty import table has an empty symbol pool.")
        }
        return Layout(payloadRange: payloadRange, payloadFileOffset: payloadFileOffset, header: header,
            importsRange: importsRange, stringsRange: stringsRange)
    }

    private static func readInspection(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        descriptor: MachOChainedImportDescriptor,
        dylibCount: UInt32
    ) throws -> MachOChainedImportInspection {
        let layout = try readLayout(handle: handle, url: url, slice: slice, containerSize: containerSize,
            minimumDataOffset: minimumDataOffset, descriptor: descriptor)
        let header = layout.header
        let payloadFileOffset = layout.payloadFileOffset
        let importsRange = layout.importsRange
        let stringsRange = layout.stringsRange
        let imports = try read(handle: handle, offset: payloadFileOffset + importsRange.offset, length: importsRange.length,
            containerSize: containerSize, path: url.path)
        let strings = try read(handle: handle, offset: payloadFileOffset + stringsRange.offset, length: stringsRange.length,
            containerSize: containerSize, path: url.path)
        var records: [StaticAPIReference] = []
        var entries: [MachOChainedImportEntry] = []
        var diagnostics: [String] = []
        var invalidCount: UInt32 = 0
        var referenceLimitReached = false
        for index in 0..<header.importCount {
            try Task.checkCancellation()
            guard UInt64(records.count) < maximumReferenceCount else {
                referenceLimitReached = true
                break
            }
            do {
                let item = try decodeImport(data: imports, index: index, format: header.format, dylibCount: dylibCount, path: url.path)
                let name = try symbolName(strings: strings, offset: item.nameOffset, index: index, path: url.path)
                let reference = StaticAPIReference(name: name, kind: item.kind,
                    location: StaticEvidenceLocation(sourcePath: url.path, architecture: slice.architecture,
                        sliceOffset: slice.fileOffset, fileOffset: payloadFileOffset + stringsRange.offset + UInt64(item.nameOffset),
                        byteCount: UInt64(name.utf8.count) + 1, propertyListKey: nil, method: .chainedFixupImports), referenceLocation: nil)
                records.append(reference)
                entries.append(MachOChainedImportEntry(index: index, addend: item.addend, reference: reference))
            } catch let error as MachOChainedImportError {
                invalidCount += 1
                if diagnostics.count < maximumDiagnosticCount { diagnostics.append(error.localizedDescription) }
            }
        }
        try Task.checkCancellation()
        var collectionLimitations = limitations + diagnostics
        if invalidCount > UInt32(diagnostics.count) {
            collectionLimitations.append("\(invalidCount - UInt32(diagnostics.count)) additional invalid import entries exceeded the diagnostic limit.")
        }
        if referenceLimitReached {
            collectionLimitations.append("The chained-import reference limit was reached; subsequent entries were not collected.")
        }
        let reason: String
        if referenceLimitReached {
            reason = "The \(slice.architecture) slice at file offset \(slice.fileOffset) reached the \(maximumReferenceCount)-reference limit."
        } else if invalidCount > 0 {
            reason = "The \(slice.architecture) slice at file offset \(slice.fileOffset) contains \(invalidCount) invalid chained import entries; valid declarations were retained."
        } else {
            reason = "Chained-fixup import-table names for \(slice.architecture) at file offset \(slice.fileOffset) were collected; pointer-chain use and other API-reference formats were not established."
        }
        let references = StaticFeatureCollection(state: invalidCount > 0 && records.isEmpty ? .unavailable : .partial,
            reason: reason, records: records, limitations: collectionLimitations, limits: limits)
        let entryState: StaticCollectionState = invalidCount == 0 && !referenceLimitReached ? .complete :
            (entries.isEmpty && invalidCount > 0 ? .unavailable : .partial)
        let entryReason = entryState == .complete ?
            "All \(header.importCount) chained import entries for \(slice.architecture) at file offset \(slice.fileOffset) were validated in original index order, including signed table addends." : reason
        return MachOChainedImportInspection(references: references,
            entries: StaticFeatureCollection(state: entryState, reason: entryReason, records: entries,
                limitations: collectionLimitations, limits: limits))
    }

    private static func decodeHeader(_ data: Data, path: String) throws -> Header {
        let version = uint32(data, offset: 0)
        guard version == 0 else { throw MachOChainedImportError.unsupportedVersion(path, version) }
        let formatValue = uint32(data, offset: 20)
        guard let format = ImportFormat(rawValue: formatValue) else {
            throw MachOChainedImportError.unsupportedFormat(path, "imports_format", formatValue)
        }
        let symbolsFormat = uint32(data, offset: 24)
        guard symbolsFormat == 0 else {
            throw MachOChainedImportError.unsupportedFormat(path,
                "symbols_format (compressed or unknown symbol pools are not decoded)", symbolsFormat)
        }
        return Header(startsOffset: uint32(data, offset: 4), importsOffset: uint32(data, offset: 8),
            symbolsOffset: uint32(data, offset: 12), importCount: uint32(data, offset: 16), format: format)
    }

    /// Revalidates complete entry inputs against the same bounded bytes before slot ordinals can use them.
    static func validateEntries(
        _ entries: [MachOChainedImportEntry],
        layout: Layout,
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        dylibCount: UInt32
    ) throws {
        try Task.checkCancellation()
        guard entries.count == Int(layout.header.importCount), UInt64(entries.count) <= maximumReferenceCount else {
            throw MachOChainedImportError.invalidTable(url.path,
                "The complete entry collection must retain every declared import index within the reference limit.")
        }
        let imports = try read(handle: handle, offset: layout.payloadFileOffset + layout.importsRange.offset,
            length: layout.importsRange.length, containerSize: containerSize, path: url.path)
        let strings = try read(handle: handle, offset: layout.payloadFileOffset + layout.stringsRange.offset,
            length: layout.stringsRange.length, containerSize: containerSize, path: url.path)
        for (position, entry) in entries.enumerated() {
            try Task.checkCancellation()
            let index = UInt32(position)
            guard entry.index == index else {
                throw MachOChainedImportError.invalidImport(url.path, index,
                    "Original import indexes are missing, duplicated, or out of table order.")
            }
            let item = try decodeImport(data: imports, index: index, format: layout.header.format,
                dylibCount: dylibCount, path: url.path)
            let name = try symbolName(strings: strings, offset: item.nameOffset, index: index, path: url.path)
            let expectedLocation = StaticEvidenceLocation(sourcePath: url.path, architecture: slice.architecture,
                sliceOffset: slice.fileOffset,
                fileOffset: layout.payloadFileOffset + layout.stringsRange.offset + UInt64(item.nameOffset),
                byteCount: UInt64(name.utf8.count) + 1, propertyListKey: nil, method: .chainedFixupImports)
            guard entry.addend == item.addend, entry.reference.name == name, entry.reference.kind == item.kind,
                entry.reference.location == expectedLocation, entry.reference.referenceLocation == nil else {
                throw MachOChainedImportError.invalidImport(url.path, index,
                    "The supplied entry addend, name, kind, or byte provenance does not match its original table bytes.")
            }
        }
    }

    private static func decodeImport(
        data: Data, index: UInt32, format: ImportFormat, dylibCount: UInt32, path: String
    ) throws -> Import {
        let position = Int(UInt64(index) * format.recordBytes)
        let nameOffset: UInt32
        let ordinal: Int64
        let addend: Int64
        switch format {
        case .plain, .addend:
            let packed = uint32(data, offset: position)
            let encodedOrdinal = Int64(packed & 0xFF)
            ordinal = encodedOrdinal > 0xF0 ? encodedOrdinal - 0x100 : encodedOrdinal
            nameOffset = packed >> 9
            addend = format == .addend ? Int64(Int32(bitPattern: uint32(data, offset: position + 4))) : 0
        case .addend64:
            let packed = uint64(data, offset: position)
            guard (packed >> 17) & 0x7FFF == 0 else {
                throw MachOChainedImportError.invalidImport(path, index, "DYLD_CHAINED_IMPORT_ADDEND64 reserved bits are nonzero.")
            }
            let encodedOrdinal = Int64(packed & 0xFFFF)
            ordinal = encodedOrdinal > 0xFFF0 ? encodedOrdinal - 0x1_0000 : encodedOrdinal
            nameOffset = UInt32(packed >> 32)
            addend = Int64(bitPattern: uint64(data, offset: position + 8))
        }
        guard ordinal >= -3, ordinal <= Int64(dylibCount) else {
            throw MachOChainedImportError.invalidImport(path, index,
                "Library ordinal \(ordinal) is not one of the \(dylibCount) declared dependencies or a recognized special lookup.")
        }
        return Import(nameOffset: nameOffset, kind: ordinal > 0 ? .importedSymbol : .dyldBindingSymbol, addend: addend)
    }

    private static func symbolName(strings: Data, offset: UInt32, index: UInt32, path: String) throws -> String {
        guard UInt64(offset) < UInt64(strings.count) else {
            throw MachOChainedImportError.invalidImport(path, index,
                "name_offset \(offset) is outside the \(strings.count)-byte symbol pool.")
        }
        let start = Int(offset)
        let count = min(strings.count - start, Int(maximumSymbolNameBytes) + 1)
        let region = strings[start..<(start + count)]
        guard let terminator = region.firstIndex(of: 0) else {
            throw MachOChainedImportError.invalidImport(path, index,
                "The name has no NUL terminator within its symbol pool and \(maximumSymbolNameBytes)-byte name limit.")
        }
        guard terminator > start else {
            throw MachOChainedImportError.invalidImport(path, index, "name_offset points to an empty name.")
        }
        guard let name = String(data: strings[start..<terminator], encoding: .utf8) else {
            throw MachOChainedImportError.invalidImport(path, index,
                "The name is not valid UTF-8; replacement characters were not substituted.")
        }
        return name
    }

    private static func uint32(_ data: Data, offset: Int) -> UInt32 {
        data[offset..<(offset + 4)].enumerated().reduce(0) { value, byte in
            value | UInt32(byte.element) << UInt32(byte.offset * 8)
        }
    }

    private static func uint64(_ data: Data, offset: Int) -> UInt64 {
        data[offset..<(offset + 8)].enumerated().reduce(0) { value, byte in
            value | UInt64(byte.element) << UInt64(byte.offset * 8)
        }
    }

    private static func read(
        handle: FileHandle, offset: UInt64, length: UInt64, containerSize: UInt64, path: String
    ) throws -> Data {
        try Task.checkCancellation()
        _ = try MachOByteRange(offset: offset, length: length, containerLength: containerSize,
            path: path, context: .fileRead)
        if length == 0 { return Data() }
        try handle.seek(toOffset: offset)
        guard let data = try handle.read(upToCount: Int(length)), data.count == Int(length) else {
            throw MachOInspectionError.truncated(path, offset)
        }
        return data
    }

    private static func failedInspection(
        slice: MachOSlice, reason: String, state: StaticCollectionState
    ) -> MachOChainedImportInspection {
        let scopedReason = "\(slice.architecture) at file offset \(slice.fileOffset): \(reason)"
        return MachOChainedImportInspection(
            references: StaticFeatureCollection(state: state, reason: scopedReason,
                records: [], limitations: limitations, limits: limits),
            entries: StaticFeatureCollection(state: state, reason: scopedReason,
                records: [], limitations: limitations, limits: limits))
    }
}
