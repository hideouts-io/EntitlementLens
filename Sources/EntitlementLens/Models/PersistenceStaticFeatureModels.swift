import Foundation

enum StaticPersistenceKind: String, Codable, Hashable, Sendable {
    case launchdDeclaration = "launchd_declaration"
    case privilegedHelperDeclaration = "privileged_helper_declaration"
    case loginItemBundle = "login_item_bundle"
    case loginItemExecutableDeclaration = "login_item_executable_declaration"
    case apiReference = "api_reference"
    case rawStringReference = "raw_string_reference"
}

enum StaticPersistenceAssociation: String, Codable, Hashable, Sendable {
    case selectedArtifact = "selected_artifact"
    case selectedPropertyList = "selected_property_list"
    case bundleContained = "bundle_contained"
    case explicitBundleDeclaration = "explicit_bundle_declaration"
}

/// Declarations, layouts, and named API references do not establish registration or execution.
struct StaticPersistenceCharacteristic: Codable, Hashable, Sendable {
    let kind: StaticPersistenceKind
    let declarationKey: String?
    let declarationValue: EntitlementValue?
    let declaredIdentifier: String?
    /// Original declared strings; paths outside the bundle are never followed or inspected.
    let declaredExecutablePaths: [String]
    let association: StaticPersistenceAssociation
    /// Lexically resolved only for a validated BundleProgram, without establishing that it exists.
    let bundleProgramCandidatePath: String?
    /// Hash of the exact configuration bytes read, absent for a layout-only observation.
    let sourceSHA256: String?
    /// Exact parsed imports or attributed class references, separate from configuration and layout observations.
    let apiReference: StaticAPIReference?
    let location: StaticEvidenceLocation
}
