import Foundation

enum StaticResearchPresence: String, Codable, Hashable, Sendable {
    case observed
    case scopedAbsent
    case unknown
}

enum StaticResearchCountInterpretation: String, Codable, Hashable, Sendable {
    case exactWithinScope
    case lowerBound
    case unknown
}

enum StaticResearchFamily: String, Codable, CaseIterable, Hashable, Sendable {
    case signer, embeddedCertificates, entitlements, architectures, loadCommands
    case linkedFrameworks, apiReferences, persistenceCharacteristics, codeDirectoryData
}

/// Retained record counts describe storage, while optional observation counts describe collected evidence.
struct StaticResearchFamilyCoverage: Codable, Hashable, Sendable {
    let family: StaticResearchFamily
    let presence: StaticResearchPresence
    let retainedRecordCount: Int
    let observationCount: Int?
    let countInterpretation: StaticResearchCountInterpretation
    let collectionState: StaticCollectionState?
    let reason: String?
    let limitations: [String]
    let limits: [StaticCollectionLimit]
}

/// Entitlement observations count dictionary entries, independently of dictionary and signature-slot counts.
struct StaticResearchEntitlementCoverage: Codable, Hashable, Sendable {
    let source: EntitlementSource
    let location: StaticEvidenceLocation
    let state: StaticCollectionState
    let reason: String?
    let presence: StaticResearchPresence
    let retainedRecordCount: Int
    let observationCount: Int?
    let countInterpretation: StaticResearchCountInterpretation
    let slotCount: Int
}

enum StaticResearchIdentityState: String, Codable, Hashable, Sendable {
    case notProvided, unavailable, mismatch, matched
}

enum StaticResearchAPIByteState: String, Codable, Hashable, Sendable {
    case notPerformed, notApplicable, incomplete, mismatch, matched
}

/// A matching hash establishes byte identity only. Slot checks establish readable bounds, not attribution.
struct StaticResearchSourceVerification: Codable, Hashable, Sendable {
    let identityState: StaticResearchIdentityState
    let apiByteState: StaticResearchAPIByteState
    let actualSHA256: String?
    let checkedAPINameCount: Int
    let checkedReferenceSlotCount: Int
    let reason: String?
}

/// Original feature records and provenance remain intact alongside the derived coverage interpretation.
struct StaticResearchArtifact: Codable, Hashable, Sendable {
    let findingID: UUID
    let selectedPath: String
    let provenance: ArtifactProvenance
    let staticFeatures: StaticFeatureSet?
    let families: [StaticResearchFamilyCoverage]
    let entitlementScopes: [StaticResearchEntitlementCoverage]
    let sourceVerification: StaticResearchSourceVerification
}

/// This local report has its own version; it does not change the app's static-feature export schema.
struct StaticResearchReport: Codable, Hashable, Sendable {
    let reportVersion: UInt16
    let exportPath: String
    let exportSHA256: String
    let limits: [StaticCollectionLimit]
    let limitations: [String]
    let artifacts: [StaticResearchArtifact]
}
