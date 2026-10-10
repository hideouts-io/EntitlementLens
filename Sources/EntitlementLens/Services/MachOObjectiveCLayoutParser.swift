import Foundation

enum MachOObjectiveCLayoutError: LocalizedError {
    case unsupported(String, String)
    case invalid(String, UInt64, String)
    case limitExceeded(String, String, UInt64, UInt64)

    var collectionState: StaticCollectionState {
        switch self {
        case .unsupported: .unsupported
        case .invalid: .unavailable
        case .limitExceeded: .partial
        }
    }

    var errorDescription: String? {
        switch self {
        case let .unsupported(scope, reason):
            "Objective-C metadata layout for \(scope) is unsupported: \(reason)"
        case let .invalid(scope, offset, reason):
            "Objective-C metadata layout for \(scope) is invalid at file offset \(offset): \(reason)"
        case let .limitExceeded(scope, name, declared, limit):
            "Objective-C metadata layout for \(scope) declares \(declared) \(name); the collection limit is \(limit)."
        }
    }
}

/// Reads section descriptors only; it never loads an image or resolves Objective-C runtime objects.
enum MachOObjectiveCLayoutParser {
    private static let maximumCommandCount: UInt64 = 4_096
    private static let maximumSegmentCount: UInt64 = 128
    private static let maximumSectionCount: UInt64 = 4_096

    static let limits: [StaticCollectionLimit] = [
        StaticCollectionLimit(name: "objc_layout_load_commands_per_slice", value: maximumCommandCount, unit: .records),
        StaticCollectionLimit(name: "objc_layout_segments_per_slice", value: maximumSegmentCount, unit: .records),
        StaticCollectionLimit(name: "objc_layout_section_headers_per_slice", value: maximumSectionCount, unit: .records)
    ]

    static let limitations: [String] = [
        "Objective-C section layout collection supports only 64-bit little-endian Mach-O descriptors.",
        "Only selector references, class references, image information, and __TEXT,__objc_methname strings are selected; class definitions, superclass references, method lists, protocols, categories, and raw strings are not collected.",
        "All 64-bit segment extents must be bounded and nonoverlapping in file and virtual address space before a metadata reference can be attributed to a unique slot.",
        "Authenticated data sections are selected for separate format-1 or format-12 pointer validation; layout collection does not decode or authenticate their pointer words."
    ]

    static func parse(
        commands: Data,
        commandCount: UInt32,
        slice: MachOSlice,
        headerSize: UInt64,
        is64Bit: Bool,
        byteOrder: MachOByteOrder
    ) throws -> MachOObjectiveCLayout {
        try Task.checkCancellation()
        let scope = "\(slice.architecture) slice at offset \(slice.fileOffset)"
        guard slice.fileSize <= UInt64.max - slice.fileOffset else {
            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset,
                "The slice's absolute byte extent overflows a 64-bit file offset.")
        }
        guard is64Bit, byteOrder == .little else {
            throw MachOObjectiveCLayoutError.unsupported(scope, "Only 64-bit little-endian section headers are supported.")
        }
        guard headerSize == 32 else {
            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset, "A 64-bit Mach-O header must occupy 32 bytes.")
        }
        guard UInt64(commandCount) <= maximumCommandCount else {
            throw MachOObjectiveCLayoutError.limitExceeded(scope, "load commands", UInt64(commandCount), maximumCommandCount)
        }
        let commandRange = try MachOByteRange(offset: headerSize, length: UInt64(commands.count),
            containerLength: slice.fileSize, path: scope, context: .loadCommands)
        var sections: [MachOObjectiveCSection] = []
        var segments: [MachOImageSegment] = []
        var encryptedRanges: [MachOByteRange] = []
        var cursor: UInt64 = 0
        var segmentCount: UInt64 = 0
        var sectionCount: UInt64 = 0
        for _ in 0..<commandCount {
            try Task.checkCancellation()
            let command = try uint32(commands, offset: cursor, scope: scope)
            let size = UInt64(try uint32(commands, offset: cursor + 4, scope: scope))
            guard size >= 8, size % 8 == 0 else {
                throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + cursor,
                    "A load command must be at least eight bytes and aligned to eight bytes.")
            }
            let range = try MachOByteRange(offset: cursor, length: size, containerLength: UInt64(commands.count),
                path: scope, context: .loadCommands)
            if command == 0x19 {
                segmentCount += 1
                guard segmentCount <= maximumSegmentCount else {
                    throw MachOObjectiveCLayoutError.limitExceeded(scope, "segments", segmentCount, maximumSegmentCount)
                }
                guard size >= 72 else {
                    throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + cursor,
                        "LC_SEGMENT_64 is shorter than its 72-byte header.")
                }
                let count = UInt64(try uint32(commands, offset: cursor + 64, scope: scope))
                guard count <= maximumSectionCount - sectionCount else {
                    throw MachOObjectiveCLayoutError.limitExceeded(scope, "section headers", sectionCount + count, maximumSectionCount)
                }
                guard 72 + count * 80 == size else {
                    throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + cursor,
                        "LC_SEGMENT_64 size does not equal its header plus the declared 80-byte section headers.")
                }
                sectionCount += count
                let segment = try decodeSegment(commands, offset: cursor, scope: scope)
                try validate(segment: segment, slice: slice, scope: scope)
                for other in segments {
                    guard !overlaps(segment, other) else {
                        throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + cursor,
                            "Segments overlap in file-backed or virtual ranges; metadata slot attribution requires a unique VM-to-file mapping.")
                    }
                }
                segments.append(segment)
                for index in 0..<count {
                    try Task.checkCancellation()
                    let position = cursor + 72 + index * 80
                    let sectionName = try fixedName(commands, offset: position, scope: scope)
                    guard selects(segmentName: segment.name, sectionName: sectionName) else { continue }
                    let declaredSegment = try fixedName(commands, offset: position + 16, scope: scope)
                    guard declaredSegment == segment.name else {
                        throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + position,
                            "The selected section's segment name differs from its containing segment.")
                    }
                    let section = MachOObjectiveCSection(segmentName: segment.name, sectionName: sectionName,
                        virtualAddress: try uint64(commands, offset: position + 32, scope: scope),
                        fileOffset: UInt64(try uint32(commands, offset: position + 48, scope: scope)),
                        byteCount: try uint64(commands, offset: position + 40, scope: scope),
                        flags: try uint32(commands, offset: position + 64, scope: scope),
                        alignmentExponent: try uint32(commands, offset: position + 52, scope: scope),
                        relocationCount: try uint32(commands, offset: position + 60, scope: scope))
                    try validate(section: section, segment: segment, slice: slice,
                        minimumFileOffset: commandRange.end, scope: scope)
                    for other in sections {
                        guard !overlaps(section, other) else {
                            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + section.fileOffset,
                                "Selected Objective-C sections overlap in virtual or file-backed ranges.")
                        }
                    }
                    sections.append(section)
                }
            } else if command == 0x01 {
                throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + cursor,
                    "A 64-bit slice contains a 32-bit LC_SEGMENT descriptor.")
            } else if command == 0x21 || command == 0x2C {
                guard size == 24 else {
                    throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + cursor,
                        "An encryption descriptor must occupy its eight-byte-aligned 24-byte load-command extent.")
                }
                let encryptedOffset = UInt64(try uint32(commands, offset: cursor + 8, scope: scope))
                let encryptedSize = UInt64(try uint32(commands, offset: cursor + 12, scope: scope))
                let encryptionIdentifier = try uint32(commands, offset: cursor + 16, scope: scope)
                guard try uint32(commands, offset: cursor + 20, scope: scope) == 0 else {
                    throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + cursor,
                        "The encryption descriptor's reserved padding is nonzero.")
                }
                if encryptionIdentifier != 0 {
                    encryptedRanges.append(try MachOByteRange(offset: encryptedOffset, length: encryptedSize,
                        containerLength: slice.fileSize, path: scope, context: .fileRead))
                }
            }
            cursor = range.end
        }
        guard cursor == UInt64(commands.count) else {
            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + headerSize + cursor,
                "The declared load-command count does not consume the load-command area exactly.")
        }
        for section in sections where section.byteCount > 0 {
            try Task.checkCancellation()
            for range in encryptedRanges where range.length > 0 {
                if section.fileOffset < range.end && range.offset < section.fileOffset + section.byteCount {
                    throw MachOObjectiveCLayoutError.unsupported(scope,
                        "Selected Objective-C metadata overlaps an encrypted byte range; encrypted bytes are not interpreted as metadata.")
                }
            }
        }
        return MachOObjectiveCLayout(sections: sections, segments: segments)
    }

    private static func decodeSegment(_ commands: Data, offset: UInt64, scope: String) throws -> MachOImageSegment {
        MachOImageSegment(name: try fixedName(commands, offset: offset + 8, scope: scope),
            virtualAddress: try uint64(commands, offset: offset + 24, scope: scope),
            virtualSize: try uint64(commands, offset: offset + 32, scope: scope),
            fileOffset: try uint64(commands, offset: offset + 40, scope: scope),
            fileSize: try uint64(commands, offset: offset + 48, scope: scope),
            flags: try uint32(commands, offset: offset + 68, scope: scope))
    }

    private static func selects(segmentName: String, sectionName: String) -> Bool {
        if segmentName == "__TEXT" { return sectionName == "__objc_methname" }
        guard segmentName.hasPrefix("__DATA") || segmentName.hasPrefix("__AUTH") else { return false }
        return ["__objc_selrefs", "__objc_classrefs", "__objc_imageinfo"].contains(sectionName)
    }

    private static func validate(segment: MachOImageSegment, slice: MachOSlice, scope: String) throws {
        _ = try MachOByteRange(offset: segment.fileOffset, length: segment.fileSize,
            containerLength: slice.fileSize, path: scope, context: .fileRead)
        guard segment.fileSize <= segment.virtualSize,
            segment.virtualSize <= UInt64.max - segment.virtualAddress else {
            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + segment.fileOffset,
                "A segment's file-backed extent exceeds its virtual size or its virtual range overflows a 64-bit address.")
        }
    }

    private static func validate(
        section: MachOObjectiveCSection, segment: MachOImageSegment, slice: MachOSlice, minimumFileOffset: UInt64, scope: String
    ) throws {
        guard segment.flags & 0x09 == 0 else {
            throw MachOObjectiveCLayoutError.unsupported(scope,
                "Selected metadata is in a high-VM or protected segment; ordinary file-to-VM mapping is not established.")
        }
        _ = try MachOByteRange(offset: segment.fileOffset, length: segment.fileSize,
            containerLength: slice.fileSize, path: scope, context: .fileRead)
        let range = try MachOByteRange(offset: section.fileOffset, length: section.byteCount,
            containerLength: slice.fileSize, path: scope, context: .fileRead)
        let vmEnd = segment.virtualAddress.addingReportingOverflow(segment.virtualSize)
        let sectionEnd = section.virtualAddress.addingReportingOverflow(section.byteCount)
        guard segment.fileSize <= segment.virtualSize, !vmEnd.overflow, !sectionEnd.overflow,
            section.virtualAddress >= segment.virtualAddress,
            sectionEnd.partialValue <= vmEnd.partialValue else {
            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + section.fileOffset,
                "The selected section's virtual range is not contained in its segment.")
        }
        let delta = section.virtualAddress - segment.virtualAddress
        guard delta <= segment.fileSize, section.byteCount <= segment.fileSize - delta,
            section.fileOffset == segment.fileOffset + delta, range.offset >= minimumFileOffset else {
            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + range.offset,
                "The selected section is not mapped consistently inside its segment's file-backed range or overlaps the header.")
        }
        guard section.alignmentExponent < 64 else {
            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + range.offset,
                "The selected section's alignment exponent cannot be represented by a 64-bit address.")
        }
        let alignment = UInt64(1) << section.alignmentExponent
        guard section.fileOffset % alignment == 0, section.virtualAddress % alignment == 0 else {
            throw MachOObjectiveCLayoutError.invalid(scope, slice.fileOffset + range.offset,
                "The selected section's file and virtual addresses do not satisfy its declared alignment.")
        }
        guard section.relocationCount == 0 else {
            throw MachOObjectiveCLayoutError.unsupported(scope,
                "\(section.segmentName),\(section.sectionName) has section relocations; relocation-based metadata is not collected.")
        }
        let expectedType: UInt32
        switch section.sectionName {
        case "__objc_selrefs": expectedType = ["__AUTH", "__AUTH_CONST"].contains(section.segmentName) ? 0 : 5
        case "__objc_methname": expectedType = 2
        default: expectedType = 0
        }
        guard section.flags & 0xFF == expectedType, section.flags & 0x8200_0700 == 0 else {
            throw MachOObjectiveCLayoutError.unsupported(scope,
                "\(section.segmentName),\(section.sectionName) has an unsupported section type or instruction, debug, or relocation attributes.")
        }
    }

    private static func overlaps(_ first: MachOImageSegment, _ second: MachOImageSegment) -> Bool {
        let fileOverlap = first.fileSize > 0 && second.fileSize > 0
            && first.fileOffset < second.fileOffset + second.fileSize
            && second.fileOffset < first.fileOffset + first.fileSize
        let virtualOverlap = first.virtualSize > 0 && second.virtualSize > 0
            && first.virtualAddress < second.virtualAddress + second.virtualSize
            && second.virtualAddress < first.virtualAddress + first.virtualSize
        return fileOverlap || virtualOverlap
    }

    private static func overlaps(_ first: MachOObjectiveCSection, _ second: MachOObjectiveCSection) -> Bool {
        guard first.byteCount > 0, second.byteCount > 0 else { return false }
        return (first.fileOffset < second.fileOffset + second.byteCount && second.fileOffset < first.fileOffset + first.byteCount)
            || (first.virtualAddress < second.virtualAddress + second.byteCount && second.virtualAddress < first.virtualAddress + first.byteCount)
    }

    private static func fixedName(_ data: Data, offset: UInt64, scope: String) throws -> String {
        _ = try MachOByteRange(offset: offset, length: 16, containerLength: UInt64(data.count),
            path: scope, context: .loadCommands)
        let bytes = data[Int(offset)..<Int(offset + 16)]
        let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
        guard let name = String(data: bytes[..<end], encoding: .utf8) else {
            throw MachOObjectiveCLayoutError.invalid(scope, offset, "A selected descriptor name is not valid UTF-8.")
        }
        return name
    }

    private static func uint32(_ data: Data, offset: UInt64, scope: String) throws -> UInt32 {
        _ = try MachOByteRange(offset: offset, length: 4, containerLength: UInt64(data.count),
            path: scope, context: .loadCommands)
        return data[Int(offset)..<Int(offset + 4)].enumerated().reduce(0) { value, byte in
            value | UInt32(byte.element) << UInt32(byte.offset * 8)
        }
    }

    private static func uint64(_ data: Data, offset: UInt64, scope: String) throws -> UInt64 {
        _ = try MachOByteRange(offset: offset, length: 8, containerLength: UInt64(data.count),
            path: scope, context: .loadCommands)
        return data[Int(offset)..<Int(offset + 8)].enumerated().reduce(0) { value, byte in
            value | UInt64(byte.element) << UInt64(byte.offset * 8)
        }
    }
}
