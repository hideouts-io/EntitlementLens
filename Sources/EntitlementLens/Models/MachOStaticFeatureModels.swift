import Foundation

struct MachOStaticInspection: Codable, Hashable, Sendable {
    let architectures: StaticFeatureCollection<StaticArchitecture>
    let loadCommands: StaticFeatureCollection<StaticLoadCommand>
    let linkedFrameworks: StaticFeatureCollection<StaticLinkedDependency>
    let apiReferences: StaticFeatureCollection<StaticAPIReference>
}

/// CPU values retain their complete header bits; slice identity includes its absolute file offset.
struct StaticArchitecture: Codable, Hashable, Sendable {
    let slice: MachOSlice
    let cpuType: UInt32
    let cpuSubtype: UInt32
    let location: StaticEvidenceLocation
}

/// The original command ID is retained even when its name or payload is unsupported.
struct StaticLoadCommand: Codable, Hashable, Sendable {
    let commandID: UInt32
    let name: String?
    let commandSize: UInt32
    let location: StaticEvidenceLocation
    let dylib: StaticDylibDeclaration?
    let runtimeSearchPath: String?
    let decodingIssue: String?
}

struct StaticDylibDeclaration: Codable, Hashable, Sendable {
    let installName: String
    let timestamp: UInt32
    let currentVersion: String
    let compatibilityVersion: String
}

enum StaticDependencyKind: String, Codable, Hashable, Sendable {
    case load
    case weakLoad = "weak_load"
    case reexport
    case lazyLoad = "lazy_load"
    case upwardLoad = "upward_load"
}

/// Declared dependencies and path-derived framework names do not establish runtime loading.
struct StaticLinkedDependency: Codable, Hashable, Sendable {
    let installName: String
    let frameworkName: String?
    let kind: StaticDependencyKind
    let currentVersion: String
    let compatibilityVersion: String
    let location: StaticEvidenceLocation
}

enum StaticAPIReferenceKind: String, Codable, Hashable, Sendable {
    case importedSymbol = "imported_symbol"
    case dyldBindingSymbol = "dyld_binding_symbol"
    case objectiveCClass = "objective_c_class"
    case objectiveCSelector = "objective_c_selector"
    case rawStringReference = "raw_string_reference"
}

/// Names preserve their parsed spelling, including leading underscores; references are not calls.
struct StaticAPIReference: Codable, Hashable, Sendable {
    let name: String
    let kind: StaticAPIReferenceKind
    let location: StaticEvidenceLocation
    /// File-backed binding or metadata slot referring to the named evidence, when established.
    let referenceLocation: StaticEvidenceLocation?

    enum CodingKeys: String, CodingKey {
        case name, kind, location
        case referenceLocation = "reference_location"
    }
}

enum MachOByteOrder: Sendable {
    case little
    case big
}

enum MachOSymbolRecordFormat: Sendable {
    case nlist32
    case nlist64

    var byteCount: UInt64 {
        switch self {
        case .nlist32: 12
        case .nlist64: 16
        }
    }
}

struct MachOSymbolTableDescriptor: Sendable {
    let symbolOffset: UInt32
    let symbolCount: UInt32
    let stringOffset: UInt32
    let stringSize: UInt32
    let byteOrder: MachOByteOrder
    let recordFormat: MachOSymbolRecordFormat
}
