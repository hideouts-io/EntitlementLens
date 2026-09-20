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

    static func inspect(
        _ url: URL,
        slices: [MachOSlice],
        architectureEntitlements: [ArchitectureEntitlements]
    ) -> CodeSignatureInspection {
        var slots: [CodeSignatureEntitlementSlot] = []
        var warnings: [String] = []
        for slice in slices {
            guard let offset = slice.codeSignatureOffset, let size = slice.codeSignatureSize else {
                continue
            }
            do {
                let data = try read(url: url, offset: offset, size: size)
                let architectureEntries = architectureEntitlements
                    .first { $0.architecture == slice.architecture }?
                    .entitlements ?? []
                slots.append(contentsOf: try parseSuperBlob(
                    data,
                    fileOffset: offset,
                    architecture: slice.architecture,
                    architectureEntitlements: architectureEntries
                ))
            } catch {
                warnings.append("Code-signature parsing failed for \(slice.architecture) at offset \(offset): \(error.localizedDescription)")
            }
        }
        return CodeSignatureInspection(slots: slots, warnings: warnings)
    }

    private static func parseSuperBlob(
        _ data: Data,
        fileOffset: UInt64,
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
        guard count <= 4_096, 12 + count * 8 <= declaredLength else {
            throw CodeSignatureParsingError.invalidSlotCount(count)
        }

        var results: [CodeSignatureEntitlementSlot] = []
        for index in 0..<count {
            let indexOffset = 12 + index * 8
            let slotType = try uint32(data, at: indexOffset)
            guard slotType == xmlEntitlementsSlot || slotType == derEntitlementsSlot else {
                continue
            }
            let blobOffset = integer(try uint32(data, at: indexOffset + 4))
            guard blobOffset + 8 <= declaredLength else {
                throw CodeSignatureParsingError.invalidSlotOffset(blobOffset)
            }
            let magic = try uint32(data, at: blobOffset)
            let blobLength = integer(try uint32(data, at: blobOffset + 4))
            guard blobLength >= 8, blobOffset + blobLength <= declaredLength else {
                throw CodeSignatureParsingError.invalidLength(blobLength, declaredLength - blobOffset)
            }
            let blob = Data(data[blobOffset..<(blobOffset + blobLength)])
            let payload = Data(blob.dropFirst(8))
            let absoluteOffset = fileOffset + UInt64(blobOffset)
            if slotType == xmlEntitlementsSlot {
                guard magic == xmlEntitlementsMagic else {
                    throw CodeSignatureParsingError.invalidMagic(magic)
                }
                let decoded = try decodeXML(payload)
                results.append(CodeSignatureEntitlementSlot(
                    architecture: architecture,
                    slotType: slotType,
                    format: .xml,
                    fileOffset: absoluteOffset,
                    byteCount: blobLength,
                    sha256: sha256(blob),
                    decodedEntitlements: decoded,
                    decoderSource: "Mach-O SuperBlob XML slot",
                    warning: nil
                ))
            } else {
                guard magic == derEntitlementsMagic else {
                    throw CodeSignatureParsingError.invalidMagic(magic)
                }
                results.append(CodeSignatureEntitlementSlot(
                    architecture: architecture,
                    slotType: slotType,
                    format: .der,
                    fileOffset: absoluteOffset,
                    byteCount: blobLength,
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

    private static func read(url: URL, offset: UInt64, size: UInt64) throws -> Data {
        guard size <= UInt64(Int.max) else {
            throw CodeSignatureParsingError.excessiveSize(size)
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer {
            do {
                try handle.close()
            } catch {
                // A close error cannot invalidate bytes already read successfully.
            }
        }
        try handle.seek(toOffset: offset)
        let data = try handle.read(upToCount: Int(size)) ?? Data()
        guard data.count == Int(size) else {
            throw CodeSignatureParsingError.truncated("code-signature region")
        }
        return data
    }

    private static func uint32(_ data: Data, at offset: Int) throws -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else {
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
    case invalidSlotOffset(Int)
    case excessiveSize(UInt64)
    case nonDictionaryXML

    var errorDescription: String? {
        switch self {
        case let .truncated(field): "The \(field) is truncated."
        case let .invalidMagic(value): "Unexpected code-signature magic 0x\(String(value, radix: 16, uppercase: true))."
        case let .invalidLength(length, available): "A code-signature blob declares \(length) bytes but only \(available) are available."
        case let .invalidSlotCount(count): "The code-signature SuperBlob declares an invalid slot count of \(count)."
        case let .invalidSlotOffset(offset): "A code-signature slot points outside the SuperBlob at offset \(offset)."
        case let .excessiveSize(size): "The code-signature region is too large to inspect: \(size) bytes."
        case .nonDictionaryXML: "The XML entitlement slot did not contain a dictionary."
        }
    }
}
