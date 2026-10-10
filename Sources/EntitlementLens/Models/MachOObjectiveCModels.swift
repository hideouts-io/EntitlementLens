import Foundation

/// File-backed section locations are relative to the slice; virtual addresses remain unslid.
struct MachOObjectiveCSection: Sendable {
    let segmentName: String
    let sectionName: String
    let virtualAddress: UInt64
    let fileOffset: UInt64
    let byteCount: UInt64
    let flags: UInt32
    let alignmentExponent: UInt32
    let relocationCount: UInt32
}

struct MachOObjectiveCLayout: Sendable {
    let sections: [MachOObjectiveCSection]
    let segments: [MachOImageSegment]
}

/// Encoded or incompletely collected fixups must never be treated as ordinary pointers.
enum MachOObjectiveCPointerSource: Sendable {
    case ordinaryBindings(StaticFeatureCollection<StaticAPIReference>)
    case chainedFixups(StaticFeatureCollection<MachOChainedPointer>)
    case unavailable(String)
}
