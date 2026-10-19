import Foundation

enum StaticFeatureSchemaVersion: UInt16, Codable, Hashable, Sendable {
    case v1 = 1
    case v2 = 2
    case v3 = 3
}

struct StaticCollectionContext: Codable, Hashable, Sendable {
    let collector: String
    let appVersion: String?
    let appBuild: String?
    let collectedAt: Date
    let hostOperatingSystem: SourceOperatingSystem

    enum CodingKeys: String, CodingKey {
        case collector
        case appVersion = "app_version"
        case appBuild = "app_build"
        case collectedAt = "collected_at"
        case hostOperatingSystem = "host_operating_system"
    }
}

/// Typed entitlement dictionaries and slot evidence retain their original collection scope.
struct StaticEntitlementEvidence: Codable, Hashable, Sendable {
    let source: EntitlementSource
    let state: StaticCollectionState
    let reason: String?
    let signatureIntegrity: SignatureStatus
    let nativeCDHash: String?
    let values: [EntitlementEntry]
    let slots: [CodeSignatureEntitlementSlot]
    let location: StaticEvidenceLocation
}

/// An additive record block; legacy findings without this block have unrecorded collection.
struct StaticFeatureSet: Codable, Hashable, Sendable {
    let schemaVersion: StaticFeatureSchemaVersion
    let analyzedPath: String
    let artifactSHA256: String
    let context: StaticCollectionContext
    let signer: StaticFeatureCollection<StaticSigner>
    let embeddedCertificates: StaticFeatureCollection<StaticCertificate>
    let entitlements: StaticFeatureCollection<StaticEntitlementEvidence>
    let architectures: StaticFeatureCollection<StaticArchitecture>
    let loadCommands: StaticFeatureCollection<StaticLoadCommand>
    let linkedFrameworks: StaticFeatureCollection<StaticLinkedDependency>
    let apiReferences: StaticFeatureCollection<StaticAPIReference>
    let persistenceCharacteristics: StaticFeatureCollection<StaticPersistenceCharacteristic>
    let codeDirectoryData: StaticFeatureCollection<StaticCodeDirectory>

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case analyzedPath = "analyzed_path"
        case artifactSHA256 = "artifact_sha256"
        case context, signer, entitlements, architectures
        case embeddedCertificates = "embedded_certificates"
        case loadCommands = "load_commands"
        case linkedFrameworks = "linked_frameworks"
        case apiReferences = "api_references"
        case persistenceCharacteristics = "persistence_characteristics"
        case codeDirectoryData = "code_directory_data"
    }
}
