import Foundation

/// Collection completeness within the named method and limits; never a behavioral verdict.
enum StaticCollectionState: String, Codable, Hashable, Sendable {
    case complete
    case partial
    case notCollected = "not_collected"
    case unsupported
    case unavailable
    case notApplicable = "not_applicable"
}

enum StaticEvidenceMethod: String, Codable, Hashable, Sendable {
    case securityFramework = "security_framework"
    case machOHeader = "mach_o_header"
    case loadCommand = "load_command"
    case symbolTable = "symbol_table"
    case dyldBindStream = "dyld_bind_stream"
    case chainedFixupImports = "chained_fixup_imports"
    case chainedFixupPointer = "chained_fixup_pointer"
    case objectiveCMetadata = "objective_c_metadata"
    case codeDirectory = "code_directory"
    case propertyList = "property_list"
    case bundleLayout = "bundle_layout"
    case rawString = "raw_string"
}

/// Offsets are absolute file offsets. Slice offsets disambiguate same-name architectures.
struct StaticEvidenceLocation: Codable, Hashable, Sendable {
    let sourcePath: String
    let architecture: String?
    let sliceOffset: UInt64?
    let fileOffset: UInt64?
    let byteCount: UInt64?
    let propertyListKey: String?
    let method: StaticEvidenceMethod

    enum CodingKeys: String, CodingKey {
        case architecture, method
        case sourcePath = "source_path"
        case sliceOffset = "slice_offset"
        case fileOffset = "file_offset"
        case byteCount = "byte_count"
        case propertyListKey = "property_list_key"
    }
}

enum StaticLimitUnit: String, Codable, Hashable, Sendable {
    case bytes
    case records
    case depth
}

struct StaticCollectionLimit: Codable, Hashable, Sendable {
    let name: String
    let value: UInt64
    let unit: StaticLimitUnit
}

/// Empty records establish absence only when collection is complete within its stated scope.
struct StaticFeatureCollection<Record: Codable & Hashable & Sendable>: Codable, Hashable, Sendable {
    let state: StaticCollectionState
    let reason: String?
    let records: [Record]
    let limitations: [String]
    let limits: [StaticCollectionLimit]
}
