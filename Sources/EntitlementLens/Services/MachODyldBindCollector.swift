import Foundation

enum MachODyldBindError: LocalizedError {
    case invalidDescriptors(String, String)
    case invalidStream(String, MachODyldBindKind, UInt64, String)
    case invalidOpcode(String, MachODyldBindKind, UInt64, UInt8, String)
    case invalidLEB128(String, MachODyldBindKind, UInt64, String)
    case unsupportedThreaded(String, MachODyldBindKind, UInt64)
    case limitExceeded(String, MachODyldBindKind, String, UInt64, UInt64)

    var errorDescription: String? {
        switch self {
        case let .invalidDescriptors(path, reason):
            "Cannot collect dyld binding streams in \(path): \(reason)"
        case let .invalidStream(path, kind, offset, reason):
            "The \(kind.rawValue) dyld binding stream in \(path) is invalid at file offset \(offset): \(reason)"
        case let .invalidOpcode(path, kind, offset, opcode, reason):
            "The \(kind.rawValue) dyld binding opcode 0x\(String(opcode, radix: 16)) in \(path) is invalid at file offset \(offset): \(reason)"
        case let .invalidLEB128(path, kind, offset, reason):
            "The \(kind.rawValue) dyld binding integer in \(path) is invalid at file offset \(offset): \(reason)"
        case let .unsupportedThreaded(path, kind, offset):
            "The \(kind.rawValue) dyld binding stream in \(path) uses unsupported threaded binding at file offset \(offset); subsequent opcodes in this stream were not collected."
        case let .limitExceeded(path, kind, name, requested, limit):
            "The \(kind.rawValue) dyld binding stream in \(path) requires \(requested) \(name); its collection limit is \(limit)."
        }
    }
}

/// Parses declared ordinary binding programs without loading code or following pointer chains.
enum MachODyldBindCollector {
    private static let maximumStreamBytes: UInt64 = 4 * 1_024 * 1_024
    private static let maximumOpcodeCount: UInt64 = 250_000
    private static let maximumBindingCount: UInt64 = 65_536
    private static let maximumReferenceCount: UInt64 = 16_384
    private static let maximumNameBytes: UInt64 = 4_096

    static var limits: [StaticCollectionLimit] {
        [
            StaticCollectionLimit(name: "dyld_bind_streams_per_slice", value: 3, unit: .records),
            StaticCollectionLimit(name: "dyld_bind_segment_descriptors", value: 16, unit: .records),
            StaticCollectionLimit(name: "dyld_bind_bytes_per_stream", value: maximumStreamBytes, unit: .bytes),
            StaticCollectionLimit(name: "dyld_bind_opcodes_per_stream", value: maximumOpcodeCount, unit: .records),
            StaticCollectionLimit(name: "dyld_bind_operations_per_stream", value: maximumBindingCount, unit: .records),
            StaticCollectionLimit(name: "dyld_bind_references_per_stream", value: maximumReferenceCount, unit: .records),
            StaticCollectionLimit(name: "dyld_bind_symbol_name_bytes", value: maximumNameBytes, unit: .bytes),
            StaticCollectionLimit(name: "dyld_bind_integer_bytes", value: 10, unit: .bytes)
        ]
    }

    static let limitations: [String] = [
        "Only ordinary normal, weak, and lazy LC_DYLD_INFO binding programs are decoded. Threaded binding, rebase streams, and export tries are not decoded by this method.",
        "Names are emitted only for parsed binding operations. Weak coalescing and special-ordinal lookups use dyld_binding_symbol because external ownership is not established; definition-only markers emit no record.",
        "VM bounds and bind widths are checked using declared segment sizes. Segment protections, text-relocation policy, and __LINKEDIT exclusion are not validated by this collector.",
        "Bind-address state uses the ABI's modulo-2^64 transitions, including large ULEB128 values used by linkers to rewind. Every emitted binding still requires its full width within the selected VM segment.",
        "reference_location identifies only pointer-type, zero-addend binding slots whose full width is within the selected segment's file-backed range. Text bindings, nonzero addends, and valid VM-only targets retain their name evidence with a nil reference_location.",
        "Normal and weak programs stop at DONE; lazy DONE resets the state for the next independently addressable sequence. Unconsumed bytes after non-lazy DONE are not interpreted as bindings.",
        "References retain literal spelling and source offsets. Declared targets and optional weak imports do not establish API calls, runtime availability, platform ownership, or persistence enablement."
    ]

    private enum BindType {
        case pointer
        case textAbsolute32
        case textRelative32

        func byteCount(pointerSize: UInt64) -> UInt64 {
            switch self {
            case .pointer: pointerSize
            case .textAbsolute32, .textRelative32: 4
            }
        }
    }

    private struct SymbolName {
        let value: String
        let fileOffset: UInt64
        let byteCount: UInt64
    }

    private struct BindState {
        var type: BindType?
        var ordinal: Int64?
        var segmentIndex: UInt8?
        var segmentOffset: UInt64
        var symbol: SymbolName?
        var addend: Int64
    }

    private struct StreamContext {
        let path: String
        let slice: MachOSlice
        let stream: MachODyldBindStream
        let segments: [MachODyldSegment]
        let pointerSize: UInt64
        let dylibCount: UInt32

        var fileOffset: UInt64 { slice.fileOffset + UInt64(stream.dataOffset) }
    }

    private struct UnsignedInteger {
        let value: UInt64
        let nextOffset: Int
    }

    private struct SignedInteger {
        let value: Int64
        let nextOffset: Int
    }

    private struct ParsedSymbol {
        let symbol: SymbolName
        let nextOffset: Int
    }

    static func collect(
        handle: FileHandle,
        url: URL,
        slice: MachOSlice,
        containerSize: UInt64,
        minimumDataOffset: UInt64,
        streams: [MachODyldBindStream],
        segments: [MachODyldSegment],
        pointerSize: UInt64,
        dylibCount: UInt32
    ) throws -> StaticFeatureCollection<StaticAPIReference> {
        try Task.checkCancellation()
        do {
            _ = try MachOByteRange(offset: slice.fileOffset, length: slice.fileSize,
                containerLength: containerSize, path: url.path, context: .fatSlice)
        } catch let error as MachOByteRangeError {
            return failed(error.localizedDescription, state: .unavailable)
        }
        guard pointerSize == 4 || pointerSize == 8 else {
            throw MachODyldBindError.invalidDescriptors(url.path, "The pointer size must be 4 or 8 bytes, but is \(pointerSize).")
        }
        guard streams.count <= 3, Set(streams.map { $0.kind.rawValue }).count == streams.count else {
            throw MachODyldBindError.invalidDescriptors(url.path, "At most one normal, weak, and lazy stream descriptor is permitted.")
        }
        guard segments.count <= 16 else {
            throw MachODyldBindError.invalidDescriptors(url.path, "A binding opcode can address only segment indexes 0 through 15.")
        }
        for (index, segment) in segments.enumerated() {
            try Task.checkCancellation()
            guard segment.fileSize <= segment.virtualSize else {
                return failed(MachODyldBindError.invalidDescriptors(url.path,
                    "Segment \(index) declares \(segment.fileSize) file-backed bytes exceeding its \(segment.virtualSize)-byte VM size.").localizedDescription,
                    state: .unavailable)
            }
            do {
                _ = try MachOByteRange(offset: segment.fileOffset, length: segment.fileSize,
                    containerLength: slice.fileSize, path: url.path, context: .fileRead)
            } catch let error as MachOByteRangeError {
                return failed("Segment \(index) file range: \(error.localizedDescription)", state: .unavailable)
            }
        }
        guard !streams.isEmpty else {
            return StaticFeatureCollection(
                state: .notApplicable, reason: "No ordinary dyld binding stream descriptors were supplied.",
                records: [], limitations: limitations, limits: limits
            )
        }
        var collections: [StaticFeatureCollection<StaticAPIReference>] = []
        for stream in streams {
            try Task.checkCancellation()
            let context = StreamContext(
                path: url.path, slice: slice, stream: stream, segments: segments,
                pointerSize: pointerSize, dylibCount: dylibCount
            )
            do {
                let range = try MachOByteRange(
                    offset: UInt64(stream.dataOffset), length: UInt64(stream.dataSize),
                    containerLength: slice.fileSize, path: url.path, context: .fileRead
                )
                guard range.length == 0 || range.offset >= minimumDataOffset else {
                    throw MachODyldBindError.invalidStream(url.path, stream.kind, context.fileOffset, "The stream overlaps the Mach-O header or load commands.")
                }
                guard range.length <= maximumStreamBytes else {
                    throw MachODyldBindError.limitExceeded(url.path, stream.kind, "stream bytes", range.length, maximumStreamBytes)
                }
                for other in streams where other.kind != stream.kind && other.dataSize > 0 && stream.dataSize > 0 {
                    let otherStart = UInt64(other.dataOffset)
                    // Invalid sibling ranges receive their own failure result and cannot poison a valid stream.
                    guard otherStart >= minimumDataOffset, otherStart <= slice.fileSize,
                        UInt64(other.dataSize) <= slice.fileSize - otherStart else { continue }
                    let otherEnd = otherStart + UInt64(other.dataSize)
                    guard range.end <= otherStart || otherEnd <= range.offset else {
                        throw MachODyldBindError.invalidStream(url.path, stream.kind, context.fileOffset, "The stream overlaps the \(other.kind.rawValue) binding stream.")
                    }
                }
                let data = try read(handle: handle, context: context, containerSize: containerSize)
                collections.append(try parse(data: data, context: context))
            } catch is CancellationError {
                throw CancellationError()
            } catch let error as MachODyldBindError {
                collections.append(failed(error.localizedDescription, state: failureState(error, records: [])))
            } catch let error as MachOByteRangeError {
                collections.append(failed("\(stream.kind.rawValue) stream: \(error.localizedDescription)", state: .unavailable))
            } catch let error as CocoaError {
                collections.append(failed("Could not read the \(stream.kind.rawValue) stream at file offset \(context.fileOffset): \(error.localizedDescription)", state: .unavailable))
            } catch let error as POSIXError {
                collections.append(failed("Could not read the \(stream.kind.rawValue) stream at file offset \(context.fileOffset): \(error.localizedDescription)", state: .unavailable))
            }
        }
        let state: StaticCollectionState
        if collections.allSatisfy({ $0.state == .complete }) { state = .complete }
        else if collections.allSatisfy({ $0.state == .unavailable }) { state = .unavailable }
        else if collections.allSatisfy({ $0.state == .unsupported }) { state = .unsupported }
        else { state = .partial }
        let reasons = collections.compactMap(\.reason)
        return StaticFeatureCollection(
            state: state, reason: reasons.isEmpty ? nil : reasons.joined(separator: " "),
            records: collections.flatMap(\.records), limitations: limitations, limits: limits
        )
    }

    private static func parse(data: Data, context: StreamContext) throws -> StaticFeatureCollection<StaticAPIReference> {
        var state = initialState(context.stream.kind)
        var cursor = 0
        var opcodeCount: UInt64 = 0
        var bindingCount: UInt64 = 0
        var records: [StaticAPIReference] = []
        var terminated = data.isEmpty
        do {
            while cursor < data.count {
                try Task.checkCancellation()
                guard opcodeCount < maximumOpcodeCount else {
                    throw MachODyldBindError.limitExceeded(context.path, context.stream.kind, "opcodes", opcodeCount + 1, maximumOpcodeCount)
                }
                opcodeCount += 1
                let opcodeOffset = cursor
                let byte = data[cursor]
                cursor += 1
                let opcode = byte & 0xF0
                let immediate = byte & 0x0F
                let absoluteOffset = context.fileOffset + UInt64(opcodeOffset)
                if context.stream.kind == .lazy && ![0x00, 0x10, 0x20, 0x30, 0x40, 0x60, 0x70, 0x90, 0xD0].contains(opcode) {
                    throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "This opcode is not valid in an ordinary lazy binding sequence.")
                }
                switch opcode {
                case 0x00:
                    terminated = true
                    if context.stream.kind == .lazy {
                        state = initialState(.lazy)
                    } else {
                        cursor = data.count
                    }
                case 0x10, 0x20, 0x30:
                    guard context.stream.kind != .weak else {
                        throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "Weak coalescing streams do not set a dylib ordinal.")
                    }
                    let ordinal: Int64
                    if opcode == 0x20 {
                        let integer = try unsignedInteger(data: data, offset: cursor, context: context)
                        cursor = integer.nextOffset
                        guard integer.value <= UInt64(context.dylibCount) else {
                            throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "Dylib ordinal \(integer.value) exceeds the \(context.dylibCount) declared dependencies.")
                        }
                        ordinal = Int64(integer.value)
                    } else if opcode == 0x30 {
                        ordinal = immediate == 0 ? 0 : Int64(immediate) - 16
                    } else { ordinal = Int64(immediate) }
                    guard ordinal >= -3, ordinal <= Int64(context.dylibCount) else {
                        throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "Dylib ordinal \(ordinal) is not a declared dependency or recognized special lookup.")
                    }
                    state.ordinal = ordinal
                    terminated = false
                case 0x40:
                    guard immediate & ~UInt8(0x09) == 0, context.stream.kind == .weak || immediate & 0x08 == 0 else {
                        throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "The symbol flags are unrecognized or contain a weak-stream definition marker in another stream kind.")
                    }
                    let parsed = try symbol(data: data, offset: cursor, context: context)
                    state.symbol = parsed.symbol
                    cursor = parsed.nextOffset
                    terminated = false
                case 0x50:
                    switch immediate {
                    case 1: state.type = .pointer
                    case 2: state.type = .textAbsolute32
                    case 3: state.type = .textRelative32
                    default:
                        throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "Binding type \(immediate) is not supported.")
                    }
                    terminated = false
                case 0x60:
                    let integer = try signedInteger(data: data, offset: cursor, context: context)
                    cursor = integer.nextOffset
                    state.addend = integer.value
                    terminated = false
                case 0x70:
                    let integer = try unsignedInteger(data: data, offset: cursor, context: context)
                    cursor = integer.nextOffset
                    guard Int(immediate) < context.segments.count else {
                        throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "Segment index \(immediate) exceeds the \(context.segments.count) addressable segment descriptors.")
                    }
                    state.segmentIndex = immediate
                    state.segmentOffset = integer.value
                    terminated = false
                case 0x80:
                    guard state.segmentIndex != nil else {
                        throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "An address update has no preceding segment selection.")
                    }
                    let integer = try unsignedInteger(data: data, offset: cursor, context: context)
                    cursor = integer.nextOffset
                    // dyld's uint64_t state permits large encoded deltas to rewind between symbol groups.
                    state.segmentOffset = state.segmentOffset &+ integer.value
                    terminated = false
                case 0x90, 0xA0, 0xB0, 0xC0:
                    let count: UInt64
                    let skip: UInt64
                    if opcode == 0xC0 {
                        let repetitions = try unsignedInteger(data: data, offset: cursor, context: context)
                        let distance = try unsignedInteger(data: data, offset: repetitions.nextOffset, context: context)
                        cursor = distance.nextOffset
                        count = repetitions.value
                        skip = distance.value
                    } else if opcode == 0xA0 {
                        let integer = try unsignedInteger(data: data, offset: cursor, context: context)
                        cursor = integer.nextOffset
                        count = 1
                        skip = integer.value
                    } else {
                        count = 1
                        skip = opcode == 0xB0 ? UInt64(immediate) * context.pointerSize : 0
                    }
                    guard count <= maximumBindingCount - bindingCount else {
                        throw MachODyldBindError.limitExceeded(context.path, context.stream.kind, "remaining binding operations", count, maximumBindingCount - bindingCount)
                    }
                    let advance = context.pointerSize &+ skip
                    for _ in 0..<count {
                        try Task.checkCancellation()
                        let record = try reference(state: state, context: context, offset: absoluteOffset, opcode: byte)
                        let nextAddress = state.segmentOffset &+ advance
                        guard UInt64(records.count) < maximumReferenceCount else {
                            throw MachODyldBindError.limitExceeded(context.path, context.stream.kind, "reference records", UInt64(records.count) + 1, maximumReferenceCount)
                        }
                        records.append(record)
                        bindingCount += 1
                        state.segmentOffset = nextAddress
                    }
                    terminated = false
                case 0xD0:
                    throw MachODyldBindError.unsupportedThreaded(context.path, context.stream.kind, absoluteOffset)
                default:
                    throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, absoluteOffset, byte, "The opcode is unrecognized; subsequent bytes in this stream were not decoded.")
                }
            }
            guard context.stream.kind != .lazy || terminated else {
                throw MachODyldBindError.invalidStream(context.path, context.stream.kind, context.fileOffset + UInt64(cursor), "The independently addressable lazy sequence ended without a DONE terminator; already parsed bindings were retained.")
            }
        } catch let error as MachODyldBindError {
            return StaticFeatureCollection(
                state: failureState(error, records: records), reason: error.localizedDescription,
                records: records, limitations: limitations, limits: limits
            )
        }
        return StaticFeatureCollection(state: .complete, reason: nil, records: records, limitations: limitations, limits: limits)
    }

    private static func initialState(_ kind: MachODyldBindKind) -> BindState {
        BindState(
            type: kind == .normal ? nil : .pointer,
            ordinal: kind == .weak ? -3 : nil,
            segmentIndex: nil, segmentOffset: 0, symbol: nil, addend: 0
        )
    }

    private static func reference(
        state: BindState, context: StreamContext, offset: UInt64, opcode: UInt8
    ) throws -> StaticAPIReference {
        guard let type = state.type, let ordinal = state.ordinal, let segment = state.segmentIndex, let symbol = state.symbol else {
            throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, offset, opcode, "A binding requires a declared type, library ordinal, segment selection, and symbol name.")
        }
        let descriptor = context.segments[Int(segment)]
        let size = descriptor.virtualSize
        let width = type.byteCount(pointerSize: context.pointerSize)
        guard state.segmentOffset <= size, width <= size - state.segmentOffset else {
            throw MachODyldBindError.invalidOpcode(context.path, context.stream.kind, offset, opcode, "A \(width)-byte binding at VM segment offset \(state.segmentOffset) exceeds the \(size)-byte segment.")
        }
        let referenceLocation: StaticEvidenceLocation?
        if case .pointer = type, state.addend == 0,
            state.segmentOffset <= descriptor.fileSize, width <= descriptor.fileSize - state.segmentOffset {
            referenceLocation = StaticEvidenceLocation(
                sourcePath: context.path, architecture: context.slice.architecture, sliceOffset: context.slice.fileOffset,
                fileOffset: context.slice.fileOffset + descriptor.fileOffset + state.segmentOffset,
                byteCount: width, propertyListKey: nil, method: .dyldBindStream
            )
        } else { referenceLocation = nil }
        return StaticAPIReference(
            name: symbol.value,
            kind: context.stream.kind != .weak && ordinal > 0 ? .importedSymbol : .dyldBindingSymbol,
            location: StaticEvidenceLocation(
                sourcePath: context.path, architecture: context.slice.architecture, sliceOffset: context.slice.fileOffset,
                fileOffset: symbol.fileOffset, byteCount: symbol.byteCount, propertyListKey: nil, method: .dyldBindStream
            ), referenceLocation: referenceLocation
        )
    }

    private static func unsignedInteger(data: Data, offset: Int, context: StreamContext) throws -> UnsignedInteger {
        var value: UInt64 = 0
        var cursor = offset
        for index in 0..<10 {
            guard cursor < data.count else {
                throw MachODyldBindError.invalidLEB128(context.path, context.stream.kind, context.fileOffset + UInt64(offset), "The ULEB128 value is truncated.")
            }
            let byte = data[cursor]
            cursor += 1
            let payload = byte & 0x7F
            guard index < 9 || payload <= 1 else {
                throw MachODyldBindError.invalidLEB128(context.path, context.stream.kind, context.fileOffset + UInt64(offset), "The ULEB128 value exceeds 64 bits.")
            }
            value |= UInt64(payload) << UInt64(index * 7)
            if byte & 0x80 == 0 { return UnsignedInteger(value: value, nextOffset: cursor) }
        }
        throw MachODyldBindError.invalidLEB128(context.path, context.stream.kind, context.fileOffset + UInt64(offset), "The ULEB128 value exceeds its 10-byte encoding limit.")
    }

    private static func signedInteger(data: Data, offset: Int, context: StreamContext) throws -> SignedInteger {
        var value: UInt64 = 0
        var cursor = offset
        for index in 0..<10 {
            guard cursor < data.count else {
                throw MachODyldBindError.invalidLEB128(context.path, context.stream.kind, context.fileOffset + UInt64(offset), "The SLEB128 value is truncated.")
            }
            let byte = data[cursor]
            cursor += 1
            let payload = byte & 0x7F
            guard index < 9 || payload == 0 || payload == 0x7F else {
                throw MachODyldBindError.invalidLEB128(context.path, context.stream.kind, context.fileOffset + UInt64(offset), "The SLEB128 value exceeds signed 64-bit range.")
            }
            let shift = index * 7
            value |= UInt64(index == 9 ? payload & 1 : payload) << UInt64(shift)
            if byte & 0x80 == 0 {
                if index < 9 && byte & 0x40 != 0 { value |= UInt64.max << UInt64(shift + 7) }
                return SignedInteger(value: Int64(bitPattern: value), nextOffset: cursor)
            }
        }
        throw MachODyldBindError.invalidLEB128(context.path, context.stream.kind, context.fileOffset + UInt64(offset), "The SLEB128 value exceeds its 10-byte encoding limit.")
    }

    private static func symbol(data: Data, offset: Int, context: StreamContext) throws -> ParsedSymbol {
        let end = offset + min(data.count - offset, Int(maximumNameBytes) + 1)
        var cursor = offset
        while cursor < end {
            try Task.checkCancellation()
            if data[cursor] == 0 {
                guard cursor > offset, let name = String(data: data[offset..<cursor], encoding: .utf8) else {
                    throw MachODyldBindError.invalidStream(context.path, context.stream.kind, context.fileOffset + UInt64(offset), "The symbol name is empty or not valid UTF-8; replacement characters were not substituted.")
                }
                return ParsedSymbol(
                    symbol: SymbolName(value: name, fileOffset: context.fileOffset + UInt64(offset), byteCount: UInt64(cursor - offset) + 1),
                    nextOffset: cursor + 1
                )
            }
            cursor += 1
        }
        throw MachODyldBindError.invalidStream(context.path, context.stream.kind, context.fileOffset + UInt64(offset), "The symbol name lacks a NUL terminator within its stream and \(maximumNameBytes)-byte name limit.")
    }

    private static func read(handle: FileHandle, context: StreamContext, containerSize: UInt64) throws -> Data {
        try Task.checkCancellation()
        _ = try MachOByteRange(
            offset: context.fileOffset, length: UInt64(context.stream.dataSize),
            containerLength: containerSize, path: context.path, context: .fileRead
        )
        try handle.seek(toOffset: context.fileOffset)
        let data = try handle.read(upToCount: Int(context.stream.dataSize)) ?? Data()
        guard data.count == Int(context.stream.dataSize) else {
            throw MachODyldBindError.invalidStream(context.path, context.stream.kind, context.fileOffset + UInt64(data.count), "The declared stream data is truncated.")
        }
        return data
    }

    private static func failureState(_ error: MachODyldBindError, records: [StaticAPIReference]) -> StaticCollectionState {
        if !records.isEmpty { return .partial }
        switch error {
        case .unsupportedThreaded: return .unsupported
        case .limitExceeded: return .partial
        default: return .unavailable
        }
    }

    private static func failed(_ reason: String, state: StaticCollectionState) -> StaticFeatureCollection<StaticAPIReference> {
        StaticFeatureCollection(state: state, reason: reason, records: [], limitations: limitations, limits: limits)
    }
}
