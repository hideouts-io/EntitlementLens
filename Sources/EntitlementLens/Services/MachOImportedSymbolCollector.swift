import Foundation

enum MachOImportedSymbolError: LocalizedError {
    case invalidTable(String, String)
    case limitExceeded(String, String, UInt64, UInt64)
    case invalidSymbol(String, UInt32, String)

    var errorDescription: String? {
        switch self {
        case let .invalidTable(path, reason):
            "The LC_SYMTAB data in \(path) is invalid: \(reason)"
        case let .limitExceeded(path, name, declared, limit):
            "LC_SYMTAB collection in \(path) requires \(declared) \(name); the collection limit is \(limit)."
        case let .invalidSymbol(path, index, reason):
            "LC_SYMTAB symbol \(index) in \(path) is invalid: \(reason)"
        }
    }
}

/// Collects external N_UNDF entries with zero n_value; common definitions and debug entries are excluded.
enum MachOImportedSymbolCollector {
    private static let maximumSymbolCount: UInt64 = 250_000
    private static let maximumStringTableBytes: UInt64 = 16 * 1_024 * 1_024
    private static let maximumReferenceCount: UInt64 = 16_384
    private static let maximumSymbolNameBytes: UInt64 = 4_096
    private static let maximumDiagnosticCount: Int = 32

    static var limits: [StaticCollectionLimit] {
        [
            StaticCollectionLimit(name: "symbol_records_per_slice", value: maximumSymbolCount, unit: .records),
            StaticCollectionLimit(name: "string_table_bytes_per_slice", value: maximumStringTableBytes, unit: .bytes),
            StaticCollectionLimit(name: "imported_references_per_slice", value: maximumReferenceCount, unit: .records),
            StaticCollectionLimit(name: "symbol_name_bytes", value: maximumSymbolNameBytes, unit: .bytes),
            StaticCollectionLimit(name: "symbol_diagnostics_per_slice", value: UInt64(maximumDiagnosticCount), unit: .records)
        ]
    }

    static let limitations: [String] = [
        "Only named external undefined LC_SYMTAB symbols with zero n_value are collected; symbol names retain their original spelling.",
        "This symbol-table method does not decode dyld binding or chained-fixup structures; separate collectors report those methods. Prebound undefined symbols, Objective-C class or selector metadata, and raw string references remain unsupported. Stripping can remove symbol-table references.",
        "A parsed reference does not establish that an API was called. No platform ownership is inferred from a symbol name."
    ]

    static func collect(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        table: MachOSymbolTableDescriptor
    ) throws -> StaticFeatureCollection<StaticAPIReference> {
        try Task.checkCancellation()
        do {
            return try readReferences(
                handle: handle, url: url, slice: slice, containerSize: containerSize,
                minimumDataOffset: minimumDataOffset, table: table
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as MachOImportedSymbolError {
            let state: StaticCollectionState
            if case .limitExceeded = error { state = .partial }
            else { state = .unavailable }
            return failedCollection(slice: slice, reason: error.localizedDescription, state: state)
        } catch let error as MachOByteRangeError {
            return failedCollection(slice: slice, reason: error.localizedDescription, state: .unavailable)
        } catch let error as MachOInspectionError {
            return failedCollection(slice: slice, reason: error.localizedDescription, state: .unavailable)
        } catch let error as CocoaError {
            return failedCollection(slice: slice, reason: error.localizedDescription, state: .unavailable)
        } catch let error as POSIXError {
            return failedCollection(slice: slice, reason: error.localizedDescription, state: .unavailable)
        }
    }

    private static func readReferences(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        table: MachOSymbolTableDescriptor
    ) throws -> StaticFeatureCollection<StaticAPIReference> {
        let symbolBytes = UInt64(table.symbolCount) * table.recordFormat.byteCount
        let symbolsRange = try MachOByteRange(
            offset: UInt64(table.symbolOffset), length: symbolBytes,
            containerLength: slice.fileSize, path: url.path, context: .fileRead
        )
        let stringsRange = try MachOByteRange(
            offset: UInt64(table.stringOffset), length: UInt64(table.stringSize),
            containerLength: slice.fileSize, path: url.path, context: .fileRead
        )
        guard (symbolsRange.length == 0 || symbolsRange.offset >= minimumDataOffset),
            (stringsRange.length == 0 || stringsRange.offset >= minimumDataOffset) else {
            throw MachOImportedSymbolError.invalidTable(url.path, "A symbol or string table overlaps the Mach-O header or load commands.")
        }
        guard symbolsRange.length == 0 || stringsRange.length == 0
            || symbolsRange.end <= stringsRange.offset || stringsRange.end <= symbolsRange.offset else {
            throw MachOImportedSymbolError.invalidTable(url.path, "The symbol and string tables overlap.")
        }
        guard UInt64(table.symbolCount) <= maximumSymbolCount else {
            throw MachOImportedSymbolError.limitExceeded(url.path, "symbol records", UInt64(table.symbolCount), maximumSymbolCount)
        }
        guard UInt64(table.stringSize) <= maximumStringTableBytes else {
            throw MachOImportedSymbolError.limitExceeded(url.path, "string-table bytes", UInt64(table.stringSize), maximumStringTableBytes)
        }
        guard table.symbolCount > 0 else {
            return StaticFeatureCollection(
                state: .unsupported,
                reason: "The \(slice.architecture) slice at file offset \(slice.fileOffset) has an empty LC_SYMTAB; this method supplies no names.",
                records: [], limitations: limitations, limits: limits
            )
        }
        guard table.stringSize > 0 else {
            throw MachOImportedSymbolError.invalidTable(url.path, "A nonempty symbol table has an empty string table.")
        }
        let symbols = try read(
            handle: handle, offset: slice.fileOffset + symbolsRange.offset,
            count: Int(symbolsRange.length), containerSize: containerSize, path: url.path
        )
        let strings = try read(
            handle: handle, offset: slice.fileOffset + stringsRange.offset,
            count: Int(stringsRange.length), containerSize: containerSize, path: url.path
        )
        var records: [StaticAPIReference] = []
        var diagnostics: [String] = []
        var invalidSymbolCount: UInt32 = 0
        var nullNameCount: UInt32 = 0
        var referenceLimitReached = false
        let recordByteCount = Int(table.recordFormat.byteCount)
        for index in 0..<table.symbolCount {
            try Task.checkCancellation()
            let offset = Int(index) * recordByteCount
            let type = symbols[offset + 4]
            guard type & 0xE0 == 0, type & 0x0E == 0, type & 0x01 != 0 else { continue }
            let valueBytes = symbols[(offset + 8)..<(offset + recordByteCount)]
            guard valueBytes.allSatisfy({ $0 == 0 }) else { continue }
            do {
                guard symbols[offset + 5] == 0 else {
                    throw MachOImportedSymbolError.invalidSymbol(url.path, index, "An undefined symbol declares a nonzero section ordinal.")
                }
                let stringIndex = uint32(symbols, offset: offset, order: table.byteOrder)
                guard stringIndex != 0 else {
                    nullNameCount += 1
                    continue
                }
                let name = try symbolName(strings: strings, offset: stringIndex, index: index, path: url.path)
                guard UInt64(records.count) < maximumReferenceCount else {
                    referenceLimitReached = true
                    break
                }
                records.append(StaticAPIReference(
                    name: name, kind: .importedSymbol,
                    location: StaticEvidenceLocation(
                        sourcePath: url.path, architecture: slice.architecture, sliceOffset: slice.fileOffset,
                        fileOffset: slice.fileOffset + stringsRange.offset + UInt64(stringIndex),
                        byteCount: UInt64(name.utf8.count) + 1, propertyListKey: nil, method: .symbolTable
                    ), referenceLocation: nil
                ))
            } catch let error as MachOImportedSymbolError {
                invalidSymbolCount += 1
                if diagnostics.count < maximumDiagnosticCount { diagnostics.append(error.localizedDescription) }
            }
        }
        var collectionLimitations = limitations + diagnostics
        if invalidSymbolCount > UInt32(diagnostics.count) {
            collectionLimitations.append("\(invalidSymbolCount - UInt32(diagnostics.count)) additional invalid symbol records exceeded the diagnostic limit.")
        }
        if nullNameCount > 0 {
            collectionLimitations.append("\(nullNameCount) external undefined symbols declare the null string index and have no exportable name.")
        }
        if referenceLimitReached {
            collectionLimitations.append("The imported-reference record limit was reached for this slice; subsequent symbols were not collected.")
        }
        let reason: String
        if referenceLimitReached {
            reason = "The \(slice.architecture) slice at file offset \(slice.fileOffset) reached the \(maximumReferenceCount)-reference limit."
        } else if invalidSymbolCount > 0 {
            reason = "The \(slice.architecture) slice at file offset \(slice.fileOffset) contains \(invalidSymbolCount) invalid symbol records; valid imported-symbol evidence was retained."
        } else {
            reason = "LC_SYMTAB reference collection for \(slice.architecture) at file offset \(slice.fileOffset) covers named external undefined symbols only."
        }
        return StaticFeatureCollection(
            state: .partial, reason: reason, records: records,
            limitations: collectionLimitations, limits: limits
        )
    }

    private static func symbolName(strings: Data, offset: UInt32, index: UInt32, path: String) throws -> String {
        guard UInt64(offset) < UInt64(strings.count) else {
            throw MachOImportedSymbolError.invalidSymbol(path, index, "String index \(offset) is outside the \(strings.count)-byte string table.")
        }
        let start = Int(offset)
        let available = strings.count - start
        let boundedCount = min(available, Int(maximumSymbolNameBytes) + 1)
        let boundedBytes = strings[start..<(start + boundedCount)]
        guard let terminator = boundedBytes.firstIndex(of: 0) else {
            throw MachOImportedSymbolError.invalidSymbol(path, index, "The name is not NUL terminated within its string table and \(maximumSymbolNameBytes)-byte name limit.")
        }
        guard terminator > start else {
            throw MachOImportedSymbolError.invalidSymbol(path, index, "A nonzero string index points to an empty name.")
        }
        guard let name = String(data: strings[start..<terminator], encoding: .utf8) else {
            throw MachOImportedSymbolError.invalidSymbol(path, index, "The name is not valid UTF-8; replacement characters were not substituted.")
        }
        return name
    }

    private static func uint32(_ data: Data, offset: Int, order: MachOByteOrder) -> UInt32 {
        let bytes = data[offset..<(offset + 4)]
        switch order {
        case .little:
            return bytes.enumerated().reduce(0) { value, item in
                value | (UInt32(item.element) << UInt32(item.offset * 8))
            }
        case .big:
            return bytes.reduce(0) { ($0 << 8) | UInt32($1) }
        }
    }

    private static func read(handle: FileHandle, offset: UInt64, count: Int, containerSize: UInt64, path: String) throws -> Data {
        try Task.checkCancellation()
        _ = try MachOByteRange(
            offset: offset, length: UInt64(count), containerLength: containerSize,
            path: path, context: .fileRead
        )
        try handle.seek(toOffset: offset)
        let data = try handle.read(upToCount: count) ?? Data()
        guard data.count == count else { throw MachOInspectionError.truncated(path, offset + UInt64(data.count)) }
        return data
    }

    private static func failedCollection(
        slice: MachOSlice, reason: String, state: StaticCollectionState
    ) -> StaticFeatureCollection<StaticAPIReference> {
        StaticFeatureCollection(
            state: state, reason: "\(slice.architecture) at file offset \(slice.fileOffset): \(reason)",
            records: [], limitations: limitations, limits: limits
        )
    }
}
