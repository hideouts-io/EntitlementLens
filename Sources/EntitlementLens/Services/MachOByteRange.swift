import Foundation

enum MachOByteRangeContext: String, Sendable {
    case fileRead = "file read"
    case fatTable = "FAT architecture table"
    case fatSlice = "FAT architecture slice"
    case thinHeader = "thin Mach-O header"
    case loadCommands = "Mach-O load-command area"
    case codeSignature = "code-signature region"
    case superBlobIndex = "code-signature SuperBlob index"
    case signatureSlotHeader = "code-signature slot header"
    case signatureSlot = "code-signature slot"
}

struct MachOByteRange: Sendable {
    let offset: UInt64
    let length: UInt64

    init(
        offset: UInt64,
        length: UInt64,
        containerLength: UInt64,
        path: String,
        context: MachOByteRangeContext
    ) throws {
        guard offset <= containerLength, length <= containerLength - offset else {
            throw MachOByteRangeError.outsideContainer(
                path: path,
                context: context,
                offset: offset,
                length: length,
                containerLength: containerLength
            )
        }
        self.offset = offset
        self.length = length
    }

    var end: UInt64 { offset + length }
}

enum MachOByteRangeError: LocalizedError {
    case outsideContainer(
        path: String,
        context: MachOByteRangeContext,
        offset: UInt64,
        length: UInt64,
        containerLength: UInt64
    )

    var errorDescription: String? {
        switch self {
        case let .outsideContainer(path, context, offset, length, containerLength):
            "The \(context.rawValue) in \(path) declares offset \(offset) and length \(length) outside its \(containerLength)-byte container."
        }
    }
}
