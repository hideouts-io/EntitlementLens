import Foundation

enum StaticResearchCoverage {
    static func families(for features: StaticFeatureSet?) -> [StaticResearchFamilyCoverage] {
        guard let features else {
            return StaticResearchFamily.allCases.map {
                StaticResearchFamilyCoverage(
                    family: $0, presence: .unknown, retainedRecordCount: 0, observationCount: nil,
                    countInterpretation: .unknown, collectionState: nil,
                    reason: "Static-feature collection was not recorded in this legacy finding.",
                    limitations: [], limits: []
                )
            }
        }
        let entitlementCount = features.entitlements.records.reduce(0) { $0 + $1.values.count }
        let entitlementsComplete = features.entitlements.state == .complete
            && features.entitlements.records.allSatisfy { $0.state == .complete }
        return [
            family(.signer, collection: features.signer),
            family(.embeddedCertificates, collection: features.embeddedCertificates),
            coverage(
                family: .entitlements, retainedCount: features.entitlements.records.count,
                observationCount: entitlementCount, complete: entitlementsComplete,
                state: features.entitlements.state, reason: features.entitlements.reason,
                limitations: features.entitlements.limitations, limits: features.entitlements.limits
            ),
            family(.architectures, collection: features.architectures),
            family(.loadCommands, collection: features.loadCommands),
            family(.linkedFrameworks, collection: features.linkedFrameworks),
            family(.apiReferences, collection: features.apiReferences),
            family(.persistenceCharacteristics, collection: features.persistenceCharacteristics),
            family(.codeDirectoryData, collection: features.codeDirectoryData)
        ]
    }

    static func entitlementScopes(for features: StaticFeatureSet?) -> [StaticResearchEntitlementCoverage] {
        (features?.entitlements.records ?? []).map { evidence in
            let complete = evidence.state == .complete
            let count = evidence.values.count
            return StaticResearchEntitlementCoverage(
                source: evidence.source, location: evidence.location, state: evidence.state,
                reason: evidence.reason, presence: presence(count: count, complete: complete),
                retainedRecordCount: count, observationCount: count > 0 || complete ? count : nil,
                countInterpretation: interpretation(count: count, complete: complete),
                slotCount: evidence.slots.count
            )
        }
    }

    private static func family<Record: Codable & Hashable & Sendable>(
        _ family: StaticResearchFamily, collection: StaticFeatureCollection<Record>
    ) -> StaticResearchFamilyCoverage {
        coverage(
            family: family, retainedCount: collection.records.count, observationCount: collection.records.count,
            complete: collection.state == .complete, state: collection.state, reason: collection.reason,
            limitations: collection.limitations, limits: collection.limits
        )
    }

    private static func coverage(
        family: StaticResearchFamily, retainedCount: Int, observationCount: Int, complete: Bool,
        state: StaticCollectionState, reason: String?, limitations: [String], limits: [StaticCollectionLimit]
    ) -> StaticResearchFamilyCoverage {
        StaticResearchFamilyCoverage(
            family: family, presence: presence(count: observationCount, complete: complete),
            retainedRecordCount: retainedCount,
            observationCount: observationCount > 0 || complete ? observationCount : nil,
            countInterpretation: interpretation(count: observationCount, complete: complete),
            collectionState: state, reason: reason, limitations: limitations, limits: limits
        )
    }

    private static func presence(count: Int, complete: Bool) -> StaticResearchPresence {
        if count > 0 { return .observed }
        return complete ? .scopedAbsent : .unknown
    }

    private static func interpretation(count: Int, complete: Bool) -> StaticResearchCountInterpretation {
        if complete { return .exactWithinScope }
        return count > 0 ? .lowerBound : .unknown
    }
}
