import Foundation

enum MachOChainedPointerError: LocalizedError {
    case unsupported(String, String)
    case invalid(String, UInt64, String)
    case incompleteImports(String, StaticCollectionState, String?)
    case limitExceeded(String, String, UInt64, UInt64)

    var collectionState: StaticCollectionState {
        switch self {
        case .unsupported: .unsupported
        case .invalid: .unavailable
        case let .incompleteImports(_, state, _): state == .partial ? .partial :
            (state == .unsupported ? .unsupported : .unavailable)
        case .limitExceeded: .partial
        }
    }

    var errorDescription: String? {
        switch self {
        case let .unsupported(path, reason): "Chained-pointer collection in \(path) is unsupported: \(reason)"
        case let .invalid(path, offset, reason):
            "Chained-pointer metadata in \(path) is invalid at file offset \(offset): \(reason)"
        case let .incompleteImports(path, state, reason):
            "Chained-pointer collection in \(path) requires every original import entry; its entry collection is \(state.rawValue). \(reason ?? "Inspect the complete, unchanged import table before resolving pointer ordinals.")"
        case let .limitExceeded(path, name, declared, limit):
            "Chained-pointer collection in \(path) requires \(declared) \(name); the collection limit is \(limit)."
        }
    }
}

/// Decodes on-disk fixup declarations; it never applies fixups, authenticates pointers, or loads an image.
enum MachOChainedPointerCollector {
    private static let maximumSegmentCount: UInt64 = 128
    private static let maximumLoadCommandCount: UInt64 = 4_096
    private static let maximumLoadCommandBytes: UInt64 = 16 * 1_024 * 1_024
    private static let maximumPageCount: UInt64 = 65_536
    private static let maximumPointerCount: UInt64 = 65_536
    private static let maximumPageReadBytes: UInt64 = 64 * 1_024 * 1_024
    private static let pointerBytes: UInt64 = 8
    private static let segmentHeaderBytes: UInt64 = 22

    static let limits: [StaticCollectionLimit] = MachOChainedImportCollector.limits + [
        StaticCollectionLimit(name: "chained_pointer_segments_per_slice", value: maximumSegmentCount, unit: .records),
        StaticCollectionLimit(name: "chained_pointer_load_commands_per_slice", value: maximumLoadCommandCount, unit: .records),
        StaticCollectionLimit(name: "chained_pointer_load_command_bytes_per_slice", value: maximumLoadCommandBytes, unit: .bytes),
        StaticCollectionLimit(name: "chained_pointer_pages_per_slice", value: maximumPageCount, unit: .records),
        StaticCollectionLimit(name: "chained_pointer_records_per_slice", value: maximumPointerCount, unit: .records),
        StaticCollectionLimit(name: "chained_pointer_page_read_bytes_per_slice", value: maximumPageReadBytes, unit: .bytes)
    ]

    static let limitations: [String] = [
        "Only version-zero, little-endian 64-bit linked images with DYLD_CHAINED_PTR_ARM64E (1), DYLD_CHAINED_PTR_64 (2), DYLD_CHAINED_PTR_64_OFFSET (6), or DYLD_CHAINED_PTR_ARM64E_USERLAND24 (12), 4096- or 16384-byte pages, and one chain start per page are decoded.",
        "All declared import entries must be validated and retained in original index order. Bind addends combine signed table addends with unsigned eight-bit inline addends for formats 2/6 or signed nineteen-bit unauthenticated inline addends for formats 1/12, without overflow. Authenticated binds have no inline addend.",
        "Starts tables, subrecord extents, segment mappings, page bounds, reserved bits, import ordinals, and increasing nonoverlapping eight-byte slots are validated before complete coverage is reported.",
        "Formats 1/12 require an ARM64 header with CPU subtype ARM64E (2) or ARM64E_X1 (12), after masking capability bits; their slots and chain strides must be eight-byte aligned. Format 1 uses sixteen-bit bind ordinals, absolute unauthenticated rebase targets, and image-relative authenticated targets; format 12 uses twenty-four-bit ordinals and image-relative targets. Authentication keys, diversity, and address-diversity bits are retained only as static declarations, without generating or verifying a PAC.",
        "Other arm64e formats, shared-cache, kernel, 32-bit, unknown pointer formats, multi-start pages, and nonconventional segment mappings remain explicitly unsupported; pointer encodings are never stripped or retried as raw addresses.",
        "Decoded records establish static fixup declarations only. They do not establish external symbol availability, runtime values, API calls, or execution."
    ]

    private struct SegmentStarts {
        let segment: MachOImageSegment
        let format: MachOChainedPointerFormat
        let pageSize: UInt64
        let pageStarts: [UInt16]
    }

    private struct ImageMapping {
        let preferredBase: UInt64
        let dylibCount: UInt32
        let cpuType: UInt32
        let cpuSubtype: UInt32
    }

    private struct DecodedPointer {
        let value: MachOChainedPointerValue
        let authentication: MachOChainedAuthentication?
    }

    static func collect(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        descriptor: MachOChainedImportDescriptor,
        segments: [MachOImageSegment],
        imports: StaticFeatureCollection<MachOChainedImportEntry>
    ) throws -> StaticFeatureCollection<MachOChainedPointer> {
        try Task.checkCancellation()
        do {
            guard imports.state == .complete else {
                throw MachOChainedPointerError.incompleteImports(url.path, imports.state, imports.reason)
            }
            let layout = try MachOChainedImportCollector.readLayout(handle: handle, url: url, slice: slice,
                containerSize: containerSize, minimumDataOffset: minimumDataOffset, descriptor: descriptor)
            let mapping = try validateSegments(handle: handle, url: url, slice: slice,
                containerSize: containerSize, minimumDataOffset: minimumDataOffset, segments: segments,
                payloadRange: layout.payloadRange)
            try MachOChainedImportCollector.validateEntries(imports.records, layout: layout,
                handle: handle, url: url, slice: slice, containerSize: containerSize, dylibCount: mapping.dylibCount)
            let starts = try readStarts(handle: handle, url: url, slice: slice, containerSize: containerSize,
                layout: layout, segments: segments, mapping: mapping)
            return try readPointers(handle: handle, url: url, slice: slice, containerSize: containerSize,
                minimumDataOffset: minimumDataOffset, starts: starts, imports: imports.records,
                segments: segments, preferredBase: mapping.preferredBase)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as MachOChainedPointerError {
            return collection(slice: slice, state: error.collectionState, reason: error.localizedDescription, records: [])
        } catch let error as MachOChainedImportError {
            let state: StaticCollectionState
            switch error {
            case .unsupportedByteOrder, .unsupportedVersion, .unsupportedFormat, .unsupportedOrdering: state = .unsupported
            case .limitExceeded: state = .partial
            case .invalidTable, .invalidImport: state = .unavailable
            }
            return collection(slice: slice, state: state, reason: error.localizedDescription, records: [])
        } catch let error as MachOByteRangeError {
            return collection(slice: slice, state: .unavailable, reason: error.localizedDescription, records: [])
        } catch let error as MachOInspectionError {
            return collection(slice: slice, state: .unavailable, reason: error.localizedDescription, records: [])
        } catch let error as CocoaError {
            return collection(slice: slice, state: .unavailable, reason: error.localizedDescription, records: [])
        } catch let error as POSIXError {
            return collection(slice: slice, state: .unavailable, reason: error.localizedDescription, records: [])
        }
    }

    private static func validateSegments(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        segments: [MachOImageSegment],
        payloadRange: MachOByteRange
    ) throws -> ImageMapping {
        guard !segments.isEmpty else {
            throw MachOChainedPointerError.invalid(url.path, slice.fileOffset, "No image segment descriptors were provided.")
        }
        guard UInt64(segments.count) <= maximumSegmentCount else {
            throw MachOChainedPointerError.limitExceeded(url.path, "segment descriptors", UInt64(segments.count), maximumSegmentCount)
        }
        _ = try MachOByteRange(offset: 0, length: 32, containerLength: slice.fileSize,
            path: url.path, context: .thinHeader)
        let header = try read(handle: handle, offset: slice.fileOffset, length: 32,
            containerSize: containerSize, path: url.path)
        guard uint32(header, offset: 0) == 0xFEED_FACF else {
            throw MachOChainedPointerError.unsupported(url.path, "The slice does not have a little-endian 64-bit Mach-O header.")
        }
        guard [UInt32(2), 6, 8].contains(uint32(header, offset: 12)) else {
            throw MachOChainedPointerError.unsupported(url.path, "Only MH_EXECUTE, MH_DYLIB, and MH_BUNDLE fixups are decoded.")
        }
        guard uint32(header, offset: 24) & 0x8000_0000 == 0 else {
            throw MachOChainedPointerError.unsupported(url.path, "MH_DYLIB_IN_CACHE requires shared-cache fixup metadata.")
        }
        let commandBytes = UInt64(uint32(header, offset: 20))
        let commandCount = uint32(header, offset: 16)
        guard UInt64(commandCount) <= maximumLoadCommandCount else {
            throw MachOChainedPointerError.limitExceeded(url.path, "load commands", UInt64(commandCount), maximumLoadCommandCount)
        }
        guard commandBytes <= maximumLoadCommandBytes else {
            throw MachOChainedPointerError.limitExceeded(url.path, "load-command bytes", commandBytes, maximumLoadCommandBytes)
        }
        guard minimumDataOffset == commandBytes + 32, minimumDataOffset <= slice.fileSize else {
            throw MachOChainedPointerError.invalid(url.path, slice.fileOffset,
                "The minimum data offset does not match this slice's header and load-command extent.")
        }
        let commands = try read(handle: handle, offset: slice.fileOffset + 32, length: commandBytes,
            containerSize: containerSize, path: url.path)
        let dylibCount = try validateLoadCommands(commands, commandCount: commandCount, segments: segments,
            payloadRange: payloadRange, slice: slice, path: url.path)
        var fileRanges: [MachOByteRange] = []
        var virtualRanges: [MachOByteRange] = []
        for segment in segments {
            try Task.checkCancellation()
            let range = try MachOByteRange(offset: segment.fileOffset, length: segment.fileSize,
                containerLength: slice.fileSize, path: url.path, context: .fileRead)
            guard segment.fileSize <= segment.virtualSize else {
                throw MachOChainedPointerError.invalid(url.path, slice.fileOffset + segment.fileOffset,
                    "A segment's file size exceeds its virtual size.")
            }
            guard segment.flags & 0x09 == 0 else {
                throw MachOChainedPointerError.unsupported(url.path, "SG_HIGHVM and protected segment mappings are not decoded.")
            }
            let virtualRange = try MachOByteRange(offset: segment.virtualAddress, length: segment.virtualSize,
                containerLength: UInt64.max, path: url.path, context: .fileRead)
            if range.length > 0 {
                guard !fileRanges.contains(where: { overlaps($0, range) }) else {
                    throw MachOChainedPointerError.invalid(url.path, slice.fileOffset + range.offset,
                        "Segment file ranges overlap; a pointer slot would not have a unique mapping.")
                }
                fileRanges.append(range)
            }
            if virtualRange.length > 0 {
                guard !virtualRanges.contains(where: { overlaps($0, virtualRange) }) else {
                    throw MachOChainedPointerError.invalid(url.path, slice.fileOffset + segment.fileOffset,
                        "Segment virtual ranges overlap; a pointer target would not have a unique mapping.")
                }
                virtualRanges.append(virtualRange)
            }
        }
        let headerSegments = segments.filter {
            $0.name == "__TEXT" && $0.fileOffset == 0 && $0.fileSize >= minimumDataOffset
        }
        guard headerSegments.count == 1 else {
            throw MachOChainedPointerError.invalid(url.path, slice.fileOffset,
                "Exactly one file-backed __TEXT segment must contain the header and establish its preferred virtual base.")
        }
        let linkeditSegments = segments.filter {
            $0.name == "__LINKEDIT" && payloadRange.offset >= $0.fileOffset &&
                payloadRange.end <= $0.fileOffset + $0.fileSize
        }
        guard linkeditSegments.count == 1 else {
            throw MachOChainedPointerError.invalid(url.path, slice.fileOffset + payloadRange.offset,
                "The chained-fixup payload is not wholly contained in a unique __LINKEDIT segment.")
        }
        return ImageMapping(preferredBase: headerSegments[0].virtualAddress, dylibCount: dylibCount,
            cpuType: uint32(header, offset: 4), cpuSubtype: uint32(header, offset: 8))
    }

    private static func validateLoadCommands(
        _ commands: Data,
        commandCount: UInt32,
        segments: [MachOImageSegment],
        payloadRange: MachOByteRange,
        slice: MachOSlice,
        path: String
    ) throws -> UInt32 {
        var cursor: UInt64 = 0
        var segmentIndex = 0
        var fixupCount = 0
        var dylibCount: UInt32 = 0
        for _ in 0..<commandCount {
            try Task.checkCancellation()
            _ = try MachOByteRange(offset: cursor, length: 8, containerLength: UInt64(commands.count),
                path: path, context: .loadCommands)
            let position = Int(cursor)
            let identifier = uint32(commands, offset: position)
            let size = UInt64(uint32(commands, offset: position + 4))
            guard size >= 8, size % 8 == 0 else {
                throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                    "A load command is shorter than eight bytes or not aligned to eight bytes.")
            }
            let range = try MachOByteRange(offset: cursor, length: size, containerLength: UInt64(commands.count),
                path: path, context: .loadCommands)
            if identifier == 0x19 {
                guard size >= 72, segmentIndex < segments.count else {
                    throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                        "A 64-bit segment command is truncated or has no corresponding supplied descriptor.")
                }
                let sectionCount = UInt64(uint32(commands, offset: position + 64))
                guard sectionCount * 80 + 72 == size else {
                    throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                        "A 64-bit segment command's size does not match its section array.")
                }
                let nameBytes = commands[(position + 8)..<(position + 24)].prefix { $0 != 0 }
                guard let name = String(data: nameBytes, encoding: .utf8) else {
                    throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                        "A segment name is not valid UTF-8.")
                }
                let segment = segments[segmentIndex]
                guard name == segment.name,
                    uint64(commands, offset: position + 24) == segment.virtualAddress,
                    uint64(commands, offset: position + 32) == segment.virtualSize,
                    uint64(commands, offset: position + 40) == segment.fileOffset,
                    uint64(commands, offset: position + 48) == segment.fileSize,
                    uint32(commands, offset: position + 68) == segment.flags else {
                    throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                        "A supplied segment descriptor differs from its original load-command bytes or order.")
                }
                segmentIndex += 1
            } else if identifier == 0x01 {
                throw MachOChainedPointerError.unsupported(path,
                    "A 32-bit LC_SEGMENT command does not establish a conventional 64-bit image mapping.")
            } else if identifier == 0x8000_0034 {
                guard size == 16,
                    UInt64(uint32(commands, offset: position + 8)) == payloadRange.offset,
                    UInt64(uint32(commands, offset: position + 12)) == payloadRange.length else {
                    throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                        "The supplied fixup payload differs from its LC_DYLD_CHAINED_FIXUPS command.")
                }
                fixupCount += 1
            } else if [UInt32(0x0C), 0x8000_0018, 0x8000_001F, 0x20, 0x8000_0023].contains(identifier) {
                guard size >= 24 else {
                    throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                        "A dependency declaration is shorter than its dylib_command header.")
                }
                dylibCount += 1
            } else if identifier == 0x21 || identifier == 0x2C {
                guard size >= 20 else {
                    throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                        "The encryption-info command is truncated.")
                }
                guard uint32(commands, offset: position + 16) == 0 else {
                    throw MachOChainedPointerError.unsupported(path,
                        "Encrypted image metadata does not establish readable ordinary pointer chains.")
                }
            }
            cursor = range.end
        }
        guard cursor == UInt64(commands.count), segmentIndex == segments.count, fixupCount == 1 else {
            throw MachOChainedPointerError.invalid(path, slice.fileOffset + 32 + cursor,
                "The complete load-command area must match every supplied segment and exactly one fixup payload command.")
        }
        return dylibCount
    }

    private static func readStarts(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        layout: MachOChainedImportCollector.Layout,
        segments: [MachOImageSegment],
        mapping: ImageMapping
    ) throws -> [SegmentStarts] {
        let startOffset = UInt64(layout.header.startsOffset)
        let bytes = try read(handle: handle, offset: layout.payloadFileOffset + startOffset,
            length: layout.importsRange.offset - startOffset, containerSize: containerSize, path: url.path)
        let segmentCount = UInt64(uint32(bytes, offset: 0))
        guard segmentCount == UInt64(segments.count) else {
            throw MachOChainedPointerError.invalid(url.path, layout.payloadFileOffset + startOffset,
                "The starts segment count does not match all segment descriptors in load-command order.")
        }
        let tableRange = try MachOByteRange(offset: 0, length: 4 + segmentCount * 4,
            containerLength: UInt64(bytes.count), path: url.path, context: .fileRead)
        var subrecordRanges: [MachOByteRange] = []
        var starts: [SegmentStarts] = []
        var totalPages: UInt64 = 0
        var imageFormat: MachOChainedPointerFormat?
        for (index, segment) in segments.enumerated() {
            try Task.checkCancellation()
            let offset = UInt64(uint32(bytes, offset: 4 + index * 4))
            if offset == 0 { continue }
            guard offset >= tableRange.end else {
                throw MachOChainedPointerError.invalid(url.path, layout.payloadFileOffset + startOffset + offset,
                    "A segment-start subrecord overlaps the starts table.")
            }
            _ = try MachOByteRange(offset: offset, length: segmentHeaderBytes, containerLength: UInt64(bytes.count),
                path: url.path, context: .fileRead)
            let position = Int(offset)
            let size = UInt64(uint32(bytes, offset: position))
            let range = try MachOByteRange(offset: offset, length: size, containerLength: UInt64(bytes.count),
                path: url.path, context: .fileRead)
            guard size >= segmentHeaderBytes, !subrecordRanges.contains(where: { overlaps($0, range) }) else {
                throw MachOChainedPointerError.invalid(url.path, layout.payloadFileOffset + startOffset + offset,
                    "Segment-start subrecords are shorter than their headers or overlap each other.")
            }
            subrecordRanges.append(range)
            let pageSize = UInt64(uint16(bytes, offset: position + 4))
            guard [UInt64(4_096), 16_384].contains(pageSize) else {
                throw MachOChainedPointerError.unsupported(url.path, "page_size \(pageSize) is not 4096 or 16384.")
            }
            let formatValue = uint16(bytes, offset: position + 6)
            guard let format = MachOChainedPointerFormat(rawValue: formatValue) else {
                throw MachOChainedPointerError.unsupported(url.path,
                    "pointer_format \(formatValue) is not DYLD_CHAINED_PTR_ARM64E (1), DYLD_CHAINED_PTR_64 (2), DYLD_CHAINED_PTR_64_OFFSET (6), or DYLD_CHAINED_PTR_ARM64E_USERLAND24 (12).")
            }
            if format == .arm64e || format == .arm64eUserland24 {
                guard mapping.cpuType == 0x0100_000C,
                    [UInt32(2), 12].contains(mapping.cpuSubtype & 0x00FF_FFFF) else {
                    throw MachOChainedPointerError.unsupported(url.path,
                        "Arm64e pointer formats 1/12 require an ARM64 CPU header with recognized ARM64E or ARM64E_X1 subtype after capability masking.")
                }
            }
            guard imageFormat == nil || imageFormat == format else {
                throw MachOChainedPointerError.invalid(url.path, layout.payloadFileOffset + startOffset + offset,
                    "Segment-start subrecords declare different pointer formats within one image.")
            }
            imageFormat = format
            let segmentOffset = uint64(bytes, offset: position + 8)
            guard segment.virtualAddress >= mapping.preferredBase,
                segmentOffset == segment.virtualAddress - mapping.preferredBase,
                segment.fileSize > 0, segment.name != "__LINKEDIT", segment.name != "__PAGEZERO" else {
                throw MachOChainedPointerError.invalid(url.path, layout.payloadFileOffset + startOffset + offset,
                    "segment_offset does not match its file-backed segment in load-command order.")
            }
            guard uint32(bytes, offset: position + 16) == 0 else {
                throw MachOChainedPointerError.unsupported(url.path, "A nonzero max_valid_pointer requires 32-bit fixup semantics.")
            }
            let pageCount = UInt64(uint16(bytes, offset: position + 20))
            totalPages += pageCount
            guard totalPages <= maximumPageCount else {
                throw MachOChainedPointerError.limitExceeded(url.path, "declared pages", totalPages, maximumPageCount)
            }
            let usedBytes = segmentHeaderBytes + pageCount * 2
            guard usedBytes <= size else {
                throw MachOChainedPointerError.invalid(url.path, layout.payloadFileOffset + startOffset + offset,
                    "The page_start array exceeds its segment-start subrecord.")
            }
            guard size - usedBytes <= 7, bytes[(position + Int(usedBytes))..<(position + Int(size))].allSatisfy({ $0 == 0 }) else {
                throw MachOChainedPointerError.unsupported(url.path,
                    "Additional chain-start entries or nonzero trailing subrecord data require unsupported multi-start metadata.")
            }
            guard pageCount == 0 || (pageCount - 1) * pageSize < segment.virtualSize else {
                throw MachOChainedPointerError.invalid(url.path, layout.payloadFileOffset + startOffset + offset,
                    "The declared pages extend beyond their segment's virtual range.")
            }
            var pageStarts: [UInt16] = []
            for page in 0..<pageCount {
                try Task.checkCancellation()
                let start = uint16(bytes, offset: position + Int(segmentHeaderBytes + page * 2))
                if start != 0xFFFF {
                    guard start & 0x8000 == 0 else {
                        throw MachOChainedPointerError.unsupported(url.path,
                            "DYLD_CHAINED_PTR_START_MULTI page \(page) in segment \(index) requires multiple chain starts.")
                    }
                    let alignment = chainStride(format: format)
                    guard UInt64(start) + pointerBytes <= pageSize, UInt64(start) % alignment == 0 else {
                        throw MachOChainedPointerError.invalid(url.path, layout.payloadFileOffset + startOffset + offset,
                            "A page start is not \(alignment)-byte aligned or cannot contain an eight-byte pointer within its page.")
                    }
                }
                pageStarts.append(start)
            }
            starts.append(SegmentStarts(segment: segment, format: format, pageSize: pageSize, pageStarts: pageStarts))
        }
        return starts
    }

    private static func readPointers(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        starts: [SegmentStarts],
        imports: [MachOChainedImportEntry],
        segments: [MachOImageSegment],
        preferredBase: UInt64
    ) throws -> StaticFeatureCollection<MachOChainedPointer> {
        var records: [MachOChainedPointer] = []
        var lastSlotEnd: UInt64 = 0
        var readBytes: UInt64 = 0
        for item in starts {
            for (page, start) in item.pageStarts.enumerated() {
                try Task.checkCancellation()
                if start == 0xFFFF { continue }
                let pageOffset = UInt64(page) * item.pageSize
                guard pageOffset < item.segment.fileSize else {
                    throw MachOChainedPointerError.invalid(url.path, slice.fileOffset + item.segment.fileOffset,
                        "A nonempty chain page is outside its segment's file-backed extent.")
                }
                let byteCount = min(item.pageSize, item.segment.fileSize - pageOffset)
                guard byteCount <= maximumPageReadBytes - readBytes else {
                    return collection(slice: slice, state: .partial,
                        reason: "The \(maximumPageReadBytes)-byte pointer-page read limit was reached before every chain was traversed.", records: records)
                }
                readBytes += byteCount
                let pageFileOffset = slice.fileOffset + item.segment.fileOffset + pageOffset
                let bytes = try read(handle: handle, offset: pageFileOffset, length: byteCount,
                    containerSize: containerSize, path: url.path)
                var position = UInt64(start)
                while true {
                    try Task.checkCancellation()
                    guard UInt64(records.count) < maximumPointerCount else {
                        return collection(slice: slice, state: .partial,
                            reason: "The \(maximumPointerCount)-pointer record limit was reached before every chain was traversed.", records: records)
                    }
                    let slot = try MachOByteRange(offset: position, length: pointerBytes, containerLength: UInt64(bytes.count),
                        path: url.path, context: .fileRead)
                    let fileOffset = pageFileOffset + slot.offset
                    let stride = chainStride(format: item.format)
                    guard fileOffset - slice.fileOffset >= minimumDataOffset, fileOffset % stride == 0,
                        fileOffset >= lastSlotEnd else {
                        throw MachOChainedPointerError.invalid(url.path, fileOffset,
                            "Pointer slots overlap, do not increase in segment/page order, are unaligned, or overlap the Mach-O header and load commands.")
                    }
                    if item.format == .arm64e || item.format == .arm64eUserland24 {
                        let virtualAddress = item.segment.virtualAddress + pageOffset + slot.offset
                        guard virtualAddress % pointerBytes == 0 else {
                            throw MachOChainedPointerError.invalid(url.path, fileOffset,
                                "An arm64e pointer slot does not map to an eight-byte-aligned virtual address.")
                        }
                    }
                    let word = uint64(bytes, offset: Int(slot.offset))
                    let decoded = try decodePointer(word, format: item.format, imports: imports,
                        segments: segments, preferredBase: preferredBase, path: url.path, fileOffset: fileOffset)
                    let location = StaticEvidenceLocation(sourcePath: url.path, architecture: slice.architecture,
                        sliceOffset: slice.fileOffset, fileOffset: fileOffset, byteCount: pointerBytes,
                        propertyListKey: nil, method: .chainedFixupPointer)
                    records.append(MachOChainedPointer(location: location, value: decoded.value,
                        format: item.format, authentication: decoded.authentication))
                    lastSlotEnd = fileOffset + pointerBytes
                    let next = chainNext(word, format: item.format)
                    if next == 0 { break }
                    let distance = next * stride
                    guard distance >= pointerBytes, distance <= item.pageSize - slot.end else {
                        throw MachOChainedPointerError.invalid(url.path, fileOffset,
                            "The \(stride)-byte chain stride overlaps the current pointer or leaves its page.")
                    }
                    position += distance
                }
            }
        }
        try Task.checkCancellation()
        return collection(slice: slice, state: .complete,
            reason: "All declared supported chained pointers were validated in segment/page/slot order.", records: records)
    }

    private static func decodePointer(
        _ word: UInt64,
        format: MachOChainedPointerFormat,
        imports: [MachOChainedImportEntry],
        segments: [MachOImageSegment],
        preferredBase: UInt64,
        path: String,
        fileOffset: UInt64
    ) throws -> DecodedPointer {
        switch format {
        case .address64, .offset64:
            let value = try decode64Pointer(word, format: format, imports: imports, segments: segments,
                preferredBase: preferredBase, path: path, fileOffset: fileOffset)
            return DecodedPointer(value: value, authentication: nil)
        case .arm64e, .arm64eUserland24:
            return try decodeArm64EPointer(word, format: format, imports: imports, segments: segments,
                preferredBase: preferredBase, path: path, fileOffset: fileOffset)
        }
    }

    private static func decode64Pointer(
        _ word: UInt64,
        format: MachOChainedPointerFormat,
        imports: [MachOChainedImportEntry],
        segments: [MachOImageSegment],
        preferredBase: UInt64,
        path: String,
        fileOffset: UInt64
    ) throws -> MachOChainedPointerValue {
        if word >> 63 == 1 {
            guard (word >> 32) & 0x7_FFFF == 0 else {
                throw MachOChainedPointerError.invalid(path, fileOffset, "A bind pointer has nonzero reserved bits.")
            }
            let ordinal = word & 0xFF_FFFF
            guard ordinal < UInt64(imports.count) else {
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "Bind ordinal \(ordinal) is outside the complete \(imports.count)-entry import table.")
            }
            let entry = imports[Int(ordinal)]
            let inlineAddend = Int64((word >> 24) & 0xFF)
            let (addend, overflow) = entry.addend.addingReportingOverflow(inlineAddend)
            guard !overflow else {
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "The signed table addend and unsigned inline addend overflow Int64.")
            }
            return .bind(reference: entry.reference, addend: addend)
        }
        guard (word >> 44) & 0x7F == 0 else {
            throw MachOChainedPointerError.invalid(path, fileOffset, "A rebase pointer has nonzero reserved bits.")
        }
        let target = word & 0xF_FFFF_FFFF
        let highBits = ((word >> 36) & 0xFF) << 56
        let virtualAddress: UInt64
        switch format {
        case .address64:
            virtualAddress = highBits | target
        case .offset64:
            let (address, overflow) = preferredBase.addingReportingOverflow(highBits | target)
            guard !overflow else {
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "The DYLD_CHAINED_PTR_64_OFFSET rebase target overflows its header-derived preferred base.")
            }
            virtualAddress = address
        case .arm64e, .arm64eUserland24:
            throw MachOChainedPointerError.invalid(path, fileOffset,
                "An arm64e pointer requires the format-specific decoder.")
        }
        try validateTarget(virtualAddress, segments: segments, path: path, fileOffset: fileOffset)
        return .rebase(targetVirtualAddress: virtualAddress)
    }

    private static func validateTarget(
        _ virtualAddress: UInt64,
        segments: [MachOImageSegment],
        path: String,
        fileOffset: UInt64
    ) throws {
        guard segments.filter({
            $0.name != "__PAGEZERO" && virtualAddress >= $0.virtualAddress &&
                virtualAddress - $0.virtualAddress < $0.virtualSize
        }).count == 1 else {
            throw MachOChainedPointerError.invalid(path, fileOffset,
                "The decoded rebase target overflows or is not contained in a unique image virtual range.")
        }
    }

    /// Formats 1/12 share authentication declarations; only format 1's unauthenticated targets are absolute.
    private static func decodeArm64EPointer(
        _ word: UInt64,
        format: MachOChainedPointerFormat,
        imports: [MachOChainedImportEntry],
        segments: [MachOImageSegment],
        preferredBase: UInt64,
        path: String,
        fileOffset: UInt64
    ) throws -> DecodedPointer {
        let authentication: MachOChainedAuthentication?
        if word >> 63 == 1 {
            let keyValue = UInt8((word >> 49) & 0x03)
            guard let key = MachOChainedAuthenticationKey(rawValue: keyValue) else {
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "The authenticated pointer key does not identify a recognized static authentication key.")
            }
            authentication = MachOChainedAuthentication(diversity: UInt16((word >> 32) & 0xFFFF),
                addressDiversity: (word >> 48) & 1 == 1, key: key)
        } else {
            authentication = nil
        }
        if (word >> 62) & 1 == 1 {
            let ordinalBits: UInt64
            switch format {
            case .arm64e: ordinalBits = 16
            case .arm64eUserland24: ordinalBits = 24
            case .address64, .offset64:
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "A generic 64-bit pointer requires the format-specific decoder.")
            }
            let ordinalMask = (UInt64(1) << ordinalBits) - 1
            let reservedMask = (UInt64(1) << (32 - ordinalBits)) - 1
            guard (word >> ordinalBits) & reservedMask == 0 else {
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "An arm64e \(ordinalBits)-bit bind pointer has nonzero reserved zero bits.")
            }
            let ordinal = word & ordinalMask
            guard ordinal < UInt64(imports.count) else {
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "Bind ordinal \(ordinal) is outside the complete \(imports.count)-entry import table.")
            }
            let entry = imports[Int(ordinal)]
            let inlineAddend: Int64
            if authentication == nil {
                let encodedAddend = (word >> 32) & 0x7_FFFF
                inlineAddend = encodedAddend & 0x4_0000 == 0 ?
                    Int64(encodedAddend) : Int64(encodedAddend) - 0x8_0000
            } else {
                inlineAddend = 0
            }
            let (addend, overflow) = entry.addend.addingReportingOverflow(inlineAddend)
            guard !overflow else {
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "The signed table addend and signed nineteen-bit arm64e inline addend overflow Int64.")
            }
            return DecodedPointer(value: .bind(reference: entry.reference, addend: addend),
                authentication: authentication)
        }
        let encodedTarget: UInt64
        if authentication == nil {
            encodedTarget = (word & 0x7FF_FFFF_FFFF) | (((word >> 43) & 0xFF) << 56)
        } else {
            encodedTarget = word & 0xFFFF_FFFF
        }
        let virtualAddress: UInt64
        if format == .arm64e && authentication == nil {
            virtualAddress = encodedTarget
        } else {
            let (address, overflow) = preferredBase.addingReportingOverflow(encodedTarget)
            guard !overflow else {
                throw MachOChainedPointerError.invalid(path, fileOffset,
                    "The arm64e format-\(format.rawValue) rebase target overflows its header-derived preferred base.")
            }
            virtualAddress = address
        }
        try validateTarget(virtualAddress, segments: segments, path: path, fileOffset: fileOffset)
        return DecodedPointer(value: .rebase(targetVirtualAddress: virtualAddress),
            authentication: authentication)
    }

    private static func chainStride(format: MachOChainedPointerFormat) -> UInt64 {
        switch format {
        case .address64, .offset64: 4
        case .arm64e, .arm64eUserland24: 8
        }
    }

    private static func chainNext(_ word: UInt64, format: MachOChainedPointerFormat) -> UInt64 {
        switch format {
        case .address64, .offset64: (word >> 51) & 0xFFF
        case .arm64e, .arm64eUserland24: (word >> 51) & 0x7FF
        }
    }

    private static func collection(
        slice: MachOSlice,
        state: StaticCollectionState,
        reason: String,
        records: [MachOChainedPointer]
    ) -> StaticFeatureCollection<MachOChainedPointer> {
        StaticFeatureCollection(state: state,
            reason: "\(slice.architecture) at file offset \(slice.fileOffset): \(reason)",
            records: records, limitations: limitations, limits: limits)
    }

    private static func overlaps(_ first: MachOByteRange, _ second: MachOByteRange) -> Bool {
        first.offset < second.end && second.offset < first.end
    }

    private static func uint16(_ data: Data, offset: Int) -> UInt16 {
        data[offset..<(offset + 2)].enumerated().reduce(0) { value, byte in
            value | UInt16(byte.element) << UInt16(byte.offset * 8)
        }
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
        handle: FileHandle,
        offset: UInt64,
        length: UInt64,
        containerSize: UInt64,
        path: String
    ) throws -> Data {
        try Task.checkCancellation()
        _ = try MachOByteRange(offset: offset, length: length, containerLength: containerSize,
            path: path, context: .fileRead)
        if length == 0 { return Data() }
        try handle.seek(toOffset: offset)
        guard let bytes = try handle.read(upToCount: Int(length)), bytes.count == Int(length) else {
            throw MachOInspectionError.truncated(path, offset)
        }
        return bytes
    }
}
