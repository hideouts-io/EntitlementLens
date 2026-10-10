import Foundation

enum MachODyldBindKind: String, Sendable {
    case normal
    case weak
    case lazy
}

/// Offsets are relative to the enclosing Mach-O slice, as stored in dyld_info_command.
struct MachODyldBindStream: Sendable {
    let kind: MachODyldBindKind
    let dataOffset: UInt32
    let dataSize: UInt32
}

/// VM bounds validate bindings; slice-relative file ranges locate file-backed reference slots.
struct MachODyldSegment: Sendable {
    let virtualSize: UInt64
    let fileOffset: UInt64
    let fileSize: UInt64
}

struct MachOChainedImportDescriptor: Sendable {
    let dataOffset: UInt32
    let dataSize: UInt32
    let byteOrder: MachOByteOrder
}
