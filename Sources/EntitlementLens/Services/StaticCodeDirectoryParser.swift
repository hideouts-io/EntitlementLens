import CryptoKit
import Foundation

/// Layout and hash conventions follow the SDK's kern/cs_blobs.h and Apple's CodeDirectory.
/// Structural validation and digest computation do not verify the code pages or CMS signature.
enum StaticCodeDirectoryParser {
    private static let maximumSignatureBytes: UInt64 = 32 * 1_024 * 1_024
    private static let maximumSlots = 4_096
    private static let maximumStringBytes = 65_536
    private static let maximumScatterRecords = 4_096

    static let limits: [StaticCollectionLimit] = [
        StaticCollectionLimit(name: "signature_region_bytes", value: maximumSignatureBytes, unit: .bytes),
        StaticCollectionLimit(name: "super_blob_slots", value: UInt64(maximumSlots), unit: .records),
        StaticCollectionLimit(name: "code_directory_string_bytes", value: UInt64(maximumStringBytes), unit: .bytes),
        StaticCollectionLimit(name: "scatter_vector_records", value: UInt64(maximumScatterRecords), unit: .records)
    ]

    private struct SignatureBlob {
        let slotType: UInt32
        let magic: UInt32
        let range: MachOByteRange
    }

    private struct DirectoryFailure {
        let reason: String
        let state: StaticCollectionState
    }

    private struct ParsedSignature {
        let records: [StaticCodeDirectory]
        let failures: [DirectoryFailure]
    }

    static func inspect(
        analyzedURL: URL, slices: [MachOSlice], signers: [StaticSigner]
    ) throws -> StaticFeatureCollection<StaticCodeDirectory> {
        guard !slices.isEmpty else {
            return StaticFeatureCollection(state: .notCollected,
                reason: "No parsed Mach-O slices were supplied; embedded CodeDirectory collection did not run.",
                records: [], limitations: [], limits: limits)
        }
        var records: [StaticCodeDirectory] = []
        var failures: [DirectoryFailure] = []
        for slice in slices {
            try Task.checkCancellation()
            guard slice.codeSignatureOffset != nil || slice.codeSignatureSize != nil else { continue }
            do {
                let data = try readSignature(analyzedURL: analyzedURL, slice: slice)
                let nativeHashes = signers.first { $0.location.sliceOffset == slice.fileOffset }?.nativeCDHashes ?? []
                let parsed = try parseSignature(data: data, path: analyzedURL.path, slice: slice, nativeHashes: nativeHashes)
                records.append(contentsOf: parsed.records)
                failures.append(contentsOf: parsed.failures)
            } catch is CancellationError {
                throw CancellationError()
            } catch let error as StaticCodeDirectoryParsingError {
                failures.append(directoryFailure(error: error, slice: slice))
            } catch let error as CodeSignatureParsingError {
                failures.append(DirectoryFailure(reason: "\(slice.architecture) at slice offset \(slice.fileOffset): \(error.localizedDescription)", state: .unavailable))
            } catch let error as MachOByteRangeError {
                failures.append(DirectoryFailure(reason: "\(slice.architecture) at slice offset \(slice.fileOffset): \(error.localizedDescription)", state: .unavailable))
            } catch let error as NSError where error.domain == NSCocoaErrorDomain || error.domain == NSPOSIXErrorDomain {
                failures.append(DirectoryFailure(reason: "\(slice.architecture) at slice offset \(slice.fileOffset): \(error.localizedDescription)", state: .unavailable))
            }
        }
        let warnings = records.flatMap(\.warnings)
        let limitations = [
            "Parsed offsets, fields, and computed CodeDirectory digests do not establish signature integrity, certificate trust, or execution policy."
        ] + failures.map(\.reason) + warnings
        let state: StaticCollectionState
        if !failures.isEmpty {
            state = records.isEmpty ? (failures.allSatisfy { $0.state == .unsupported } ? .unsupported : .unavailable) : .partial
        } else if !warnings.isEmpty {
            state = records.allSatisfy { $0.computedHash == nil } ? .unsupported : .partial
        } else {
            state = .complete
        }
        return StaticFeatureCollection(state: state,
            reason: failures.first?.reason ?? warnings.first, records: records, limitations: limitations, limits: limits)
    }

    private static func readSignature(analyzedURL: URL, slice: MachOSlice) throws -> Data {
        guard let offset = slice.codeSignatureOffset, let size = slice.codeSignatureSize else {
            throw CodeSignatureParsingError.incompleteSignatureLocation(slice.architecture)
        }
        guard size <= maximumSignatureBytes else {
            throw CodeSignatureParsingError.excessiveSize(size, maximumSignatureBytes)
        }
        let handle = try FileHandle(forReadingFrom: analyzedURL)
        let data: Data
        do {
            data = try readSignatureBytes(handle: handle, analyzedURL: analyzedURL, slice: slice, offset: offset, size: size)
        } catch {
            let primaryError = error
            do { try handle.close() }
            catch {
                throw StaticCodeDirectoryParsingError.readAndCloseFailed(primaryError as NSError, error as NSError)
            }
            throw primaryError
        }
        try handle.close()
        return data
    }

    private static func readSignatureBytes(
        handle: FileHandle, analyzedURL: URL, slice: MachOSlice, offset: UInt64, size: UInt64
    ) throws -> Data {
        let fileSize = try handle.seekToEnd()
        _ = try MachOByteRange(offset: slice.fileOffset, length: slice.fileSize, containerLength: fileSize,
            path: analyzedURL.path, context: .fatSlice)
        guard offset >= slice.fileOffset else {
            throw CodeSignatureParsingError.signatureBeforeSlice(offset, slice.fileOffset)
        }
        _ = try MachOByteRange(offset: offset - slice.fileOffset, length: size, containerLength: slice.fileSize,
            path: analyzedURL.path, context: .codeSignature)
        _ = try MachOByteRange(offset: offset, length: size, containerLength: fileSize,
            path: analyzedURL.path, context: .codeSignature)
        try Task.checkCancellation()
        try handle.seek(toOffset: offset)
        guard let data = try handle.read(upToCount: Int(size)), data.count == Int(size) else {
            throw CodeSignatureParsingError.truncated("CodeDirectory signature region")
        }
        return data
    }

    private static func parseSignature(
        data: Data, path: String, slice: MachOSlice, nativeHashes: [StaticNativeCodeDirectoryHash]
    ) throws -> ParsedSignature {
        guard try uint32(data, at: 0) == 0xFADE_0CC0 else {
            throw CodeSignatureParsingError.invalidMagic(try uint32(data, at: 0))
        }
        let length = Int(try uint32(data, at: 4))
        let count = Int(try uint32(data, at: 8))
        guard length >= 12, length <= data.count else {
            throw CodeSignatureParsingError.invalidLength(length, data.count)
        }
        guard count <= maximumSlots, count <= (length - 12) / 8 else {
            throw CodeSignatureParsingError.invalidSlotCount(count)
        }
        let index = try MachOByteRange(offset: 12, length: UInt64(count) * 8, containerLength: UInt64(length),
            path: path, context: .superBlobIndex)
        var blobs: [SignatureBlob] = []
        var slotTypes: Set<UInt32> = []
        for position in 0..<count {
            try Task.checkCancellation()
            let type = try uint32(data, at: 12 + position * 8)
            let offset = try uint32(data, at: 16 + position * 8)
            if offset == 0 {
                guard type != 0, !(0x1000..<0x1005).contains(type) else {
                    throw StaticCodeDirectoryParsingError.invalidField("CodeDirectory slot \(type)", "has a null blob offset")
                }
                continue
            }
            guard slotTypes.insert(type).inserted else {
                throw StaticCodeDirectoryParsingError.duplicateSlot(type)
            }
            guard UInt64(offset) >= index.end else {
                throw CodeSignatureParsingError.invalidSlotOffset(Int(offset), Int(index.end))
            }
            _ = try MachOByteRange(offset: UInt64(offset), length: 8, containerLength: UInt64(length),
                path: path, context: .signatureSlotHeader)
            let magic = try uint32(data, at: Int(offset))
            let blobLength = try uint32(data, at: Int(offset) + 4)
            guard blobLength >= 8 else {
                throw CodeSignatureParsingError.invalidLength(Int(blobLength), length - Int(offset))
            }
            let range = try MachOByteRange(offset: UInt64(offset), length: UInt64(blobLength),
                containerLength: UInt64(length), path: path, context: .signatureSlot)
            blobs.append(SignatureBlob(slotType: type, magic: magic, range: range))
        }
        let ordered = blobs.sorted { $0.range.offset < $1.range.offset }
        for position in 1..<max(1, ordered.count) {
            guard ordered[position - 1].range.end <= ordered[position].range.offset else {
                throw StaticCodeDirectoryParsingError.overlappingSlot(ordered[position].slotType)
            }
        }
        guard blobs.contains(where: { $0.slotType == 0 }) else {
            throw StaticCodeDirectoryParsingError.missingPrimary
        }
        var records: [StaticCodeDirectory] = []
        var failures: [DirectoryFailure] = []
        for blob in blobs where blob.slotType == 0 || (0x1000..<0x1005).contains(blob.slotType) {
            try Task.checkCancellation()
            do {
                guard blob.magic == 0xFADE_0C02 else {
                    throw CodeSignatureParsingError.invalidMagic(blob.magic)
                }
                let bytes = Data(data[Int(blob.range.offset)..<Int(blob.range.end)])
                records.append(try parseDirectory(data: bytes, blob: blob, path: path,
                    slice: slice, nativeHashes: nativeHashes))
            } catch let error as StaticCodeDirectoryParsingError {
                let failure = directoryFailure(error: error, slice: slice)
                failures.append(DirectoryFailure(reason: "Slot \(blob.slotType): \(failure.reason)", state: failure.state))
            } catch let error as CodeSignatureParsingError {
                failures.append(DirectoryFailure(reason: "Slot \(blob.slotType) in \(slice.architecture): \(error.localizedDescription)", state: .unavailable))
            } catch let error as MachOByteRangeError {
                failures.append(DirectoryFailure(reason: "Slot \(blob.slotType) in \(slice.architecture): \(error.localizedDescription)", state: .unavailable))
            }
        }
        return ParsedSignature(records: records, failures: failures)
    }

    private static func directoryFailure(error: StaticCodeDirectoryParsingError, slice: MachOSlice) -> DirectoryFailure {
        let state: StaticCollectionState
        if case .unsupportedVersion = error { state = .unsupported }
        else { state = .unavailable }
        return DirectoryFailure(reason: "\(slice.architecture) at slice offset \(slice.fileOffset): \(error.localizedDescription)", state: state)
    }

    private static func parseDirectory(
        data: Data, blob: SignatureBlob, path: String, slice: MachOSlice,
        nativeHashes: [StaticNativeCodeDirectoryHash]
    ) throws -> StaticCodeDirectory {
        let version = try uint32(data, at: 8)
        guard version >= 0x20001, version <= 0x20600 else {
            throw StaticCodeDirectoryParsingError.unsupportedVersion(version)
        }
        let headerLength = directoryHeaderLength(version)
        guard data.count >= headerLength else {
            throw CodeSignatureParsingError.truncated("CodeDirectory version 0x\(String(version, radix: 16)) header")
        }
        let flags = try uint32(data, at: 12)
        let hashOffset = try uint32(data, at: 16)
        let identifierOffset = try uint32(data, at: 20)
        let specialCount = try uint32(data, at: 24)
        let codeCount = try uint32(data, at: 28)
        let codeLimit = try uint32(data, at: 32)
        let hashSize = data[36]
        let hashType = data[37]
        let platform = data[38]
        let exponent = data[39]
        guard try uint32(data, at: 40) == 0 else {
            throw StaticCodeDirectoryParsingError.invalidField("spare2", "must be zero")
        }
        guard hashSize > 0 else {
            throw StaticCodeDirectoryParsingError.invalidField("hashSize", "must be positive")
        }
        let specialBytes = UInt64(specialCount) * UInt64(hashSize)
        guard UInt64(hashOffset) >= specialBytes else {
            throw StaticCodeDirectoryParsingError.invalidField("hashOffset", "precedes its special hash slots")
        }
        let hashStart = UInt64(hashOffset) - specialBytes
        try validateDynamicRange(offset: hashStart,
            length: (UInt64(specialCount) + UInt64(codeCount)) * UInt64(hashSize),
            headerLength: headerLength, data: data, path: path)
        let identifier = try directoryString(data: data, offset: identifierOffset,
            headerLength: headerLength, field: "identifier")
        let scatterOffset = version >= 0x20100 ? try uint32(data, at: 44) : nil
        let teamOffset = version >= 0x20200 ? try uint32(data, at: 48) : nil
        let team: String?
        if let teamOffset, teamOffset != 0 {
            team = try directoryString(data: data, offset: teamOffset, headerLength: headerLength, field: "team identifier")
        } else { team = nil }
        let limit64 = version >= 0x20300 ? try uint64(data, at: 56) : nil
        if version >= 0x20300, try uint32(data, at: 52) != 0 {
            throw StaticCodeDirectoryParsingError.invalidField("spare3", "must be zero")
        }
        let effectiveLimit = limit64.flatMap { $0 == 0 ? nil : $0 } ?? UInt64(codeLimit)
        guard effectiveLimit <= slice.fileSize else {
            throw StaticCodeDirectoryParsingError.invalidField("codeLimit", "exceeds the Mach-O slice length")
        }
        guard exponent < 64 else {
            throw StaticCodeDirectoryParsingError.invalidField("pageSize", "has an exponent exceeding a 64-bit page size")
        }
        let pageBytes: UInt64? = exponent == 0 ? nil : UInt64(1) << exponent
        let expectedCodeCount: UInt64
        if exponent == 0 {
            expectedCodeCount = effectiveLimit == 0 ? 0 : 1
        } else {
            guard effectiveLimit > 0 else {
                throw StaticCodeDirectoryParsingError.invalidField("codeLimit", "paged signatures require nonempty coverage")
            }
            expectedCodeCount = ((effectiveLimit - 1) >> exponent) + 1
        }
        guard scatterOffset.map({ $0 != 0 }) == true || expectedCodeCount == UInt64(codeCount) else {
            throw StaticCodeDirectoryParsingError.invalidField("nCodeSlots", "does not match codeLimit and pageSize")
        }
        let preEncryptOffset = version >= 0x20500 ? try uint32(data, at: 92) : nil
        if let preEncryptOffset, preEncryptOffset != 0 {
            try validateDynamicRange(offset: UInt64(preEncryptOffset), length: UInt64(codeCount) * UInt64(hashSize),
                headerLength: headerLength, data: data, path: path)
        }
        if let scatterOffset, scatterOffset != 0 {
            try validateScatter(data: data, offset: scatterOffset, codeCount: codeCount,
                sliceSize: slice.fileSize, headerLength: headerLength, path: path)
        }
        if version >= 0x20600 {
            let linkageOffset = try uint32(data, at: 100)
            let linkageLength = try uint32(data, at: 104)
            if linkageOffset != 0 || linkageLength != 0 {
                try validateDynamicRange(offset: UInt64(linkageOffset), length: UInt64(linkageLength),
                    headerLength: headerLength, data: data, path: path)
            }
        }
        let computed = try directoryHash(data: data, hashType: hashType, hashSize: hashSize)
        var warnings: [String] = []
        if computed == nil {
            warnings.append("CodeDirectory hash type \(hashType) is unsupported; no computed digest or CDHash was substituted.")
        }
        if scatterOffset.map({ $0 != 0 }) == true {
            warnings.append("Scatter-vector offsets and slot indices were bounded; sparse page-coverage semantics are unsupported and were not inferred from the dense page count.")
        }
        let matchedNativeHash = nativeHashes.first {
            $0.hashType == UInt32(hashType) && $0.value == computed?.cdHash
        }?.value
        if computed != nil, nativeHashes.contains(where: { $0.hashType == UInt32(hashType) }), matchedNativeHash == nil {
            warnings.append("No Security.framework CDHash for this hash type matched the computed CodeDirectory CDHash; native data was not assigned to this slot.")
        }
        guard let signatureOffset = slice.codeSignatureOffset else {
            throw CodeSignatureParsingError.incompleteSignatureLocation(slice.architecture)
        }
        return StaticCodeDirectory(
            location: StaticEvidenceLocation(sourcePath: path, architecture: slice.architecture,
                sliceOffset: slice.fileOffset, fileOffset: signatureOffset + blob.range.offset,
                byteCount: UInt64(data.count), propertyListKey: nil, method: .codeDirectory),
            slotType: blob.slotType, kind: blob.slotType == 0 ? .primary : .alternate,
            length: UInt32(data.count), version: version, versionSupported: true, flags: flags,
            signingIdentifier: identifier, teamIdentifier: team, hashType: hashType, hashSize: hashSize,
            hashOffset: hashOffset, identifierOffset: identifierOffset, teamOffset: teamOffset,
            scatterOffset: scatterOffset, preEncryptOffset: preEncryptOffset,
            specialSlotCount: specialCount, codeSlotCount: codeCount, pageSizeExponent: exponent,
            pageSizeBytes: pageBytes, platform: platform, codeLimit: codeLimit, codeLimit64: limit64,
            effectiveCodeLimit: effectiveLimit, computedHash: computed,
            nativeCDHash: matchedNativeHash, warnings: warnings)
    }

    private static func directoryHeaderLength(_ version: UInt32) -> Int {
        if version >= 0x20600 { return 108 }
        if version >= 0x20500 { return 96 }
        if version >= 0x20400 { return 88 }
        if version >= 0x20300 { return 64 }
        if version >= 0x20200 { return 52 }
        if version >= 0x20100 { return 48 }
        return 44
    }

    private static func validateDynamicRange(
        offset: UInt64, length: UInt64, headerLength: Int, data: Data, path: String
    ) throws {
        guard offset >= UInt64(headerLength) else {
            throw StaticCodeDirectoryParsingError.invalidField("dynamic offset", "points into the CodeDirectory header")
        }
        _ = try MachOByteRange(offset: offset, length: length, containerLength: UInt64(data.count),
            path: path, context: .signatureSlot)
    }

    private static func directoryString(
        data: Data, offset: UInt32, headerLength: Int, field: String
    ) throws -> String {
        guard Int(offset) >= headerLength, Int(offset) < data.count else {
            throw StaticCodeDirectoryParsingError.invalidField(field, "offset points outside the dynamic string area")
        }
        let available = min(data.count - Int(offset), maximumStringBytes)
        let region = data[Int(offset)..<(Int(offset) + available)]
        guard let terminator = region.firstIndex(of: 0) else {
            throw StaticCodeDirectoryParsingError.invalidField(field, "has no terminator within the bounded string area")
        }
        guard let string = String(data: data[Int(offset)..<terminator], encoding: .utf8) else {
            throw StaticCodeDirectoryParsingError.invalidField(field, "is not valid UTF-8")
        }
        return string
    }

    private static func validateScatter(
        data: Data, offset: UInt32, codeCount: UInt32, sliceSize: UInt64, headerLength: Int, path: String
    ) throws {
        var pages: UInt64 = 0
        for index in 0..<maximumScatterRecords {
            try Task.checkCancellation()
            let position = UInt64(offset) + UInt64(index) * 24
            try validateDynamicRange(offset: position, length: 24, headerLength: headerLength, data: data, path: path)
            let count = try uint32(data, at: Int(position))
            if count == 0 { return }
            let base = try uint32(data, at: Int(position) + 4)
            let target = try uint64(data, at: Int(position) + 8)
            let spare = try uint64(data, at: Int(position) + 16)
            pages += UInt64(count)
            guard pages <= UInt64(codeCount), UInt64(base) + UInt64(count) <= UInt64(codeCount),
                target < sliceSize, spare == 0 else {
                throw StaticCodeDirectoryParsingError.invalidField("scatter vector", "references invalid code slots or file offsets")
            }
        }
        throw StaticCodeDirectoryParsingError.invalidField("scatter vector", "exceeds the bounded record limit without a terminator")
    }

    private static func directoryHash(
        data: Data, hashType: UInt8, hashSize: UInt8
    ) throws -> StaticComputedCodeDirectoryHash? {
        let algorithm: StaticCodeDirectoryHashAlgorithm
        let bytes: Data
        let expectedSize: UInt8
        switch hashType {
        case 1:
            algorithm = .sha1
            bytes = Data(Insecure.SHA1.hash(data: data))
            expectedSize = 20
        case 2:
            algorithm = .sha256
            bytes = Data(SHA256.hash(data: data))
            expectedSize = 32
        case 3:
            algorithm = .sha256Truncated
            bytes = Data(SHA256.hash(data: data).prefix(20))
            expectedSize = 20
        case 4:
            algorithm = .sha384
            bytes = Data(SHA384.hash(data: data))
            expectedSize = 48
        default: return nil
        }
        guard hashSize == expectedSize else {
            throw StaticCodeDirectoryParsingError.invalidField("hashSize", "does not match hash type \(hashType)")
        }
        return StaticComputedCodeDirectoryHash(algorithm: algorithm,
            digest: hex(bytes), cdHash: hex(Data(bytes.prefix(20))))
    }

    private static func uint32(_ data: Data, at offset: Int) throws -> UInt32 {
        guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
            throw CodeSignatureParsingError.truncated("CodeDirectory 32-bit field at \(offset)")
        }
        return data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
    }

    private static func uint64(_ data: Data, at offset: Int) throws -> UInt64 {
        guard offset >= 0, offset <= data.count, 8 <= data.count - offset else {
            throw CodeSignatureParsingError.truncated("CodeDirectory 64-bit field at \(offset)")
        }
        return data[offset..<(offset + 8)].reduce(0) { ($0 << 8) | UInt64($1) }
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

enum StaticCodeDirectoryParsingError: LocalizedError {
    case duplicateSlot(UInt32)
    case overlappingSlot(UInt32)
    case missingPrimary
    case unsupportedVersion(UInt32)
    case invalidField(String, String)
    case readAndCloseFailed(NSError, NSError)

    var errorDescription: String? {
        switch self {
        case let .duplicateSlot(type): "Code-signature SuperBlob repeats slot type \(type)."
        case let .overlappingSlot(type): "Code-signature SuperBlob slot \(type) overlaps another blob."
        case .missingPrimary: "The embedded signature has no primary CodeDirectory slot."
        case let .unsupportedVersion(version): "CodeDirectory version 0x\(String(version, radix: 16)) is outside the supported 0x20001 through 0x20600 layouts."
        case let .invalidField(field, detail): "CodeDirectory field \(field) \(detail)."
        case let .readAndCloseFailed(primary, close): "CodeDirectory collection failed: \(primary.localizedDescription). Closing its file also failed: \(close.localizedDescription)."
        }
    }
}
