import Foundation

/// Unslid segment addresses and slice-relative file ranges define a unique image mapping.
struct MachOImageSegment: Sendable {
    let name: String
    let virtualAddress: UInt64
    let virtualSize: UInt64
    let fileOffset: UInt64
    let fileSize: UInt64
    let flags: UInt32
}

/// Import ordinals index the original table, including entries with repeated names.
struct MachOChainedImportEntry: Codable, Hashable, Sendable {
    let index: UInt32
    let addend: Int64
    let reference: StaticAPIReference
}

/// Table completeness is separate from the narrower exported import-name collection.
struct MachOChainedImportInspection: Sendable {
    let references: StaticFeatureCollection<StaticAPIReference>
    let entries: StaticFeatureCollection<MachOChainedImportEntry>
}

enum MachOChainedPointerValue: Codable, Hashable, Sendable {
    case rebase(targetVirtualAddress: UInt64)
    case bind(reference: StaticAPIReference, addend: Int64)
}

enum MachOChainedPointerFormat: UInt16, Codable, Hashable, Sendable {
    case arm64e = 1
    case address64 = 2
    case offset64 = 6
    case arm64eUserland24 = 12
}

enum MachOChainedAuthenticationKey: UInt8, Codable, Hashable, Sendable {
    case instructionA = 0
    case instructionB = 1
    case dataA = 2
    case dataB = 3
}

/// These on-disk fields describe requested authentication; no PAC is generated or verified.
struct MachOChainedAuthentication: Codable, Hashable, Sendable {
    let diversity: UInt16
    let addressDiversity: Bool
    let key: MachOChainedAuthenticationKey
}

/// A decoded file-backed fixup describes static metadata, without applying it to an image.
struct MachOChainedPointer: Codable, Hashable, Sendable {
    let location: StaticEvidenceLocation
    let value: MachOChainedPointerValue
    let format: MachOChainedPointerFormat
    let authentication: MachOChainedAuthentication?
}
