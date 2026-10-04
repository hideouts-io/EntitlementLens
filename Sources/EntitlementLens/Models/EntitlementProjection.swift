import Foundation

enum EntitlementSource: Hashable, Sendable {
    case standardDictionary
    case architecture(String)
}

struct EntitlementSourceGroup: Hashable, Sendable {
    let source: EntitlementSource
    let status: SignatureStatus
    let uniqueCDHash: String?
    let entitlements: [EntitlementEntry]
    let warnings: [String]
}

/// The standard dictionary is unscoped; architecture groups retain their original attribution.
func entitlementSourceGroups(_ signing: SigningDetails) -> [EntitlementSourceGroup] {
    let standard = EntitlementSourceGroup(
        source: .standardDictionary,
        status: signing.status,
        uniqueCDHash: signing.uniqueCDHash,
        entitlements: signing.entitlements,
        warnings: []
    )
    let architectures = signing.architectureEntitlements.sorted { $0.architecture < $1.architecture }.map {
        EntitlementSourceGroup(
            source: .architecture($0.architecture),
            status: $0.status,
            uniqueCDHash: $0.uniqueCDHash,
            entitlements: $0.entitlements,
            warnings: $0.warnings
        )
    }
    // Primary extraction warnings include other sources and remain on SigningDetails/ScanFinding.
    return [standard] + architectures
}

/// A declaration repeated in several source dictionaries counts as one key per finding.
func distinctEntitlementKeys(_ groups: [EntitlementSourceGroup]) -> Set<String> {
    Set(groups.flatMap { $0.entitlements.map(\.key) })
}

func distinctPrivateEntitlementKeys(_ groups: [EntitlementSourceGroup]) -> Set<String> {
    Set(groups.flatMap { $0.entitlements.filter(\.isPrivate).map(\.key) })
}
