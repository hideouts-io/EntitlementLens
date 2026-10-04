import CryptoKit
import Foundation

struct CodeSignatureInspection: Sendable {
    let slots: [CodeSignatureEntitlementSlot]
    let warnings: [String]
}

enum CodeSignatureParser {
    private static let embeddedSignatureMagic: UInt32 = 0xFADE_0CC0
    private static let xmlEntitlementsMagic: UInt32 = 0xFADE_7171
    private static let derEntitlementsMagic: UInt32 = 0xFADE_7172
    private static let xmlEntitlementsSlot: UInt32 = 5
    private static let derEntitlementsSlot: UInt32 = 7
    private static let maximumCodeSignatureBytes: UInt64 = 32 * 1_024 * 1_024

    private struct EntitlementSlotRecord {
        let type: UInt32
        let magic: UInt32
        let range: MachOByteRange
    }

    static func inspect(
        _ url: URL,
        slices: [MachOSlice],
        architectureEntitlements: [ArchitectureEntitlements]
    ) -> CodeSignatureInspection {
        var slots: [CodeSignatureEntitlementSlot] = []
        var warnings: [String] = []
        guard slices.contains(where: { $0.codeSignatureOffset != nil || $0.codeSignatureSize != nil }) else {
            return CodeSignatureInspection(slots: slots, warnings: warnings)
        }
        let handle: FileHandle
        do {
            handle = try FileHandle(forReadingFrom: url)
        } catch {
            return CodeSignatureInspection(
                slots: [], warnings: ["Could not open code-signature data in \(url.path): \(error.localizedDescription)"]
            )
        }
        do {
            let fileSize = try handle.seekToEnd()
            for slice in slices {
                if slice.codeSignatureOffset == nil, slice.codeSignatureSize == nil {
                    continue
                }
                do {
                    guard let offset = slice.codeSignatureOffset, let size = slice.codeSignatureSize else {
                        throw CodeSignatureParsingError.incompleteSignatureLocation(slice.architecture)
                    }
                    _ = try MachOByteRange(
                        offset: slice.fileOffset, length: slice.fileSize, containerLength: fileSize,
                        path: url.path, context: .fatSlice
                    )
                    guard offset >= slice.fileOffset else {
                        throw CodeSignatureParsingError.signatureBeforeSlice(offset, slice.fileOffset)
                    }
                    _ = try MachOByteRange(
                        offset: offset - slice.fileOffset, length: size, containerLength: slice.fileSize,
                        path: url.path, context: .codeSignature
                    )
                    let data = try read(handle: handle, offset: offset, size: size, fileSize: fileSize, path: url.path)
                    let architectureEntries = architectureEntitlements
                        .first { $0.architecture == slice.architecture }?
                        .entitlements ?? []
                    slots.append(contentsOf: try parseSuperBlob(
                        data,
                        fileOffset: offset,
                        path: url.path,
                        architecture: slice.architecture,
                        architectureEntitlements: architectureEntries
                    ))
                } catch {
                    warnings.append("Code-signature parsing failed for \(slice.architecture) in \(url.path): \(error.localizedDescription)")
                }
            }
        } catch {
            warnings.append("Could not determine the code-signature file size in \(url.path): \(error.localizedDescription)")
        }
        do {
            try handle.close()
        } catch {
            warnings.append("Could not close the code-signature file \(url.path): \(error.localizedDescription)")
        }
        return CodeSignatureInspection(slots: slots, warnings: warnings)
    }

    private static func parseSuperBlob(
        _ data: Data,
        fileOffset: UInt64,
        path: String,
        architecture: String,
        architectureEntitlements: [EntitlementEntry]
    ) throws -> [CodeSignatureEntitlementSlot] {
        guard data.count >= 12 else {
            throw CodeSignatureParsingError.truncated("SuperBlob header")
        }
        guard try uint32(data, at: 0) == embeddedSignatureMagic else {
            throw CodeSignatureParsingError.invalidMagic(try uint32(data, at: 0))
        }
        let declaredLength = integer(try uint32(data, at: 4))
        let count = integer(try uint32(data, at: 8))
        guard declaredLength >= 12, declaredLength <= data.count else {
            throw CodeSignatureParsingError.invalidLength(declaredLength, data.count)
        }
        guard count <= 4_096, count <= (declaredLength - 12) / 8 else {
            throw CodeSignatureParsingError.invalidSlotCount(count)
        }
        let indexRange = try MachOByteRange(
            offset: 12, length: UInt64(count) * 8, containerLength: UInt64(declaredLength),
            path: path, context: .superBlobIndex
        )

        var records: [EntitlementSlotRecord] = []
        for index in 0..<count {
            let indexOffset = 12 + index * 8
            let slotType = try uint32(data, at: indexOffset)
            let blobOffset = integer(try uint32(data, at: indexOffset + 4))
            if blobOffset == 0 {
                guard slotType != xmlEntitlementsSlot, slotType != derEntitlementsSlot else {
                    throw CodeSignatureParsingError.nullEntitlementSlot(slotType)
                }
                continue
            }
            guard UInt64(blobOffset) >= indexRange.end else {
                throw CodeSignatureParsingError.invalidSlotOffset(blobOffset, Int(indexRange.end))
            }
            _ = try MachOByteRange(
                offset: UInt64(blobOffset), length: 8, containerLength: UInt64(declaredLength),
                path: path, context: .signatureSlotHeader
            )
            let magic = try uint32(data, at: blobOffset)
            let blobLength = integer(try uint32(data, at: blobOffset + 4))
            guard blobLength >= 8 else {
                throw CodeSignatureParsingError.invalidLength(blobLength, declaredLength - blobOffset)
            }
            let blobRange = try MachOByteRange(
                offset: UInt64(blobOffset), length: UInt64(blobLength), containerLength: UInt64(declaredLength),
                path: path, context: .signatureSlot
            )
            guard slotType == xmlEntitlementsSlot || slotType == derEntitlementsSlot else {
                continue
            }
            guard !records.contains(where: { $0.type == slotType }) else {
                throw CodeSignatureParsingError.duplicateEntitlementSlot(slotType)
            }
            guard !records.contains(where: { $0.range.offset < blobRange.end && blobRange.offset < $0.range.end }) else {
                throw CodeSignatureParsingError.overlappingEntitlementSlot(slotType)
            }
            records.append(EntitlementSlotRecord(type: slotType, magic: magic, range: blobRange))
        }

        var results: [CodeSignatureEntitlementSlot] = []
        for record in records {
            let blob = Data(data[Int(record.range.offset)..<Int(record.range.end)])
            let payload = Data(blob.dropFirst(8))
            let absoluteOffset = fileOffset + record.range.offset
            if record.type == xmlEntitlementsSlot {
                guard record.magic == xmlEntitlementsMagic else {
                    throw CodeSignatureParsingError.invalidMagic(record.magic)
                }
                let decoded = try decodeXML(payload)
                results.append(CodeSignatureEntitlementSlot(
                    architecture: architecture,
                    slotType: record.type,
                    format: .xml,
                    fileOffset: absoluteOffset,
                    byteCount: Int(record.range.length),
                    sha256: sha256(blob),
                    decodedEntitlements: decoded,
                    decoderSource: "Mach-O SuperBlob XML slot",
                    warning: nil
                ))
            } else {
                guard record.magic == derEntitlementsMagic else {
                    throw CodeSignatureParsingError.invalidMagic(record.magic)
                }
                results.append(CodeSignatureEntitlementSlot(
                    architecture: architecture,
                    slotType: record.type,
                    format: .der,
                    fileOffset: absoluteOffset,
                    byteCount: Int(record.range.length),
                    sha256: sha256(blob),
                    decodedEntitlements: architectureEntitlements,
                    decoderSource: "Bounded Mach-O DER slot; semantic dictionary from Security.framework kSecCodeInfoEntitlementsDict",
                    warning: architectureEntitlements.isEmpty
                        ? "The DER slot was structurally bounded and hashed, but Security.framework returned no decoded entitlement dictionary for this architecture."
                        : nil
                ))
            }
        }
        return results
    }

    private static func decodeXML(_ data: Data) throws -> [EntitlementEntry] {
        let object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = object as? [String: Any] else {
            throw CodeSignatureParsingError.nonDictionaryXML
        }
        return try dictionary
            .map { EntitlementEntry(key: $0.key, value: try PropertyListValueDecoder.decode($0.value)) }
            .sorted { $0.key < $1.key }
    }

    private static func read(
        handle: FileHandle,
        offset: UInt64,
        size: UInt64,
        fileSize: UInt64,
        path: String
    ) throws -> Data {
        guard size <= maximumCodeSignatureBytes else {
            throw CodeSignatureParsingError.excessiveSize(size, maximumCodeSignatureBytes)
        }
        _ = try MachOByteRange(
            offset: offset, length: size, containerLength: fileSize,
            path: path, context: .codeSignature
        )
        try handle.seek(toOffset: offset)
        let data = try handle.read(upToCount: Int(size)) ?? Data()
        guard data.count == Int(size) else {
            throw CodeSignatureParsingError.truncated("code-signature region")
        }
        return data
    }

    private static func uint32(_ data: Data, at offset: Int) throws -> UInt32 {
        guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
            throw CodeSignatureParsingError.truncated("32-bit field at \(offset)")
        }
        return data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
    }

    private static func integer(_ value: UInt32) -> Int {
        return Int(value)
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

enum CodeSignatureParsingError: LocalizedError {
    case truncated(String)
    case invalidMagic(UInt32)
    case invalidLength(Int, Int)
    case invalidSlotCount(Int)
    case invalidSlotOffset(Int, Int)
    case excessiveSize(UInt64, UInt64)
    case incompleteSignatureLocation(String)
    case signatureBeforeSlice(UInt64, UInt64)
    case duplicateEntitlementSlot(UInt32)
    case overlappingEntitlementSlot(UInt32)
    case nullEntitlementSlot(UInt32)
    case nonDictionaryXML

    var errorDescription: String? {
        switch self {
        case let .truncated(field): "The \(field) is truncated."
        case let .invalidMagic(value): "Unexpected code-signature magic 0x\(String(value, radix: 16, uppercase: true))."
        case let .invalidLength(length, available): "A code-signature blob declares \(length) bytes but only \(available) are available."
        case let .invalidSlotCount(count): "The code-signature SuperBlob declares an invalid slot count of \(count)."
        case let .invalidSlotOffset(offset, indexEnd): "A code-signature slot points to offset \(offset), before the SuperBlob index ends at \(indexEnd)."
        case let .excessiveSize(size, maximum): "The code-signature region declares \(size) bytes, exceeding the application's \(maximum)-byte inspection limit."
        case let .incompleteSignatureLocation(architecture): "The \(architecture) slice supplies only one of the code-signature offset and size."
        case let .signatureBeforeSlice(offset, sliceOffset): "The code signature starts at file offset \(offset), before its slice starts at \(sliceOffset)."
        case let .duplicateEntitlementSlot(type): "The code-signature SuperBlob contains more than one entitlement slot of type \(type)."
        case let .overlappingEntitlementSlot(type): "Entitlement slot \(type) overlaps another entitlement slot in the code-signature SuperBlob."
        case let .nullEntitlementSlot(type): "Entitlement slot \(type) has a null offset and supplies no entitlement blob."
        case .nonDictionaryXML: "The XML entitlement slot did not contain a dictionary."
        }
    }
}
