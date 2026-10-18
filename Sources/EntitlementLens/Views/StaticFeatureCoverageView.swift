import SwiftUI

struct StaticFeatureCoverageView: View {
    let features: StaticFeatureSet?
    @State private var isExpanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            VStack(alignment: .leading, spacing: 12) {
                Text("These are static observations within each collector's stated scope. An empty completed collection supports only scoped absence; an incomplete or unrecorded collection remains unknown.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                ForEach(StaticResearchCoverage.families(for: features), id: \.family) { coverage in
                    familyRow(coverage)
                    if coverage.family != .codeDirectoryData {
                        Divider()
                    }
                }
            }
            .padding(.top, 10)
        } label: {
            Label("Static feature collection", systemImage: "square.stack.3d.up")
                .font(.headline)
        }
        .accessibilityIdentifier("detail.static-features")
        .padding(12)
        .background(.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
    }

    private func familyRow(_ coverage: StaticResearchFamilyCoverage) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text(title(for: coverage.family))
                    .fontWeight(.medium)
                Spacer()
                Text(stateTitle(coverage.collectionState))
                    .foregroundStyle(coverage.collectionState == .complete ? Color.secondary : Color.orange)
            }
            Text(presenceTitle(coverage))
                .font(.caption)
                .foregroundStyle(.secondary)
            if let reason = coverage.reason, !reason.isEmpty {
                Text("Collection note: \(reason)")
                    .font(.caption)
            }
            ForEach(coverage.limitations, id: \.self) { limitation in
                Text("Limit: \(limitation)")
                    .font(.caption)
            }
            ForEach(coverage.limits, id: \.name) { limit in
                Text("\(limit.name): \(limit.value.formatted()) \(limit.unit.rawValue)")
                    .font(.caption)
            }
            if coverage.family == .entitlements {
                ForEach(StaticResearchCoverage.entitlementScopes(for: features), id: \.source) { scope in
                    VStack(alignment: .leading, spacing: 2) {
                        Text("\(scope.source.title): \(stateTitle(scope.state)); \(presenceTitle(scope.presence))")
                        if let reason = scope.reason, !reason.isEmpty {
                            Text("Collection note: \(reason)")
                        }
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityIdentifier("detail.static-family.\(coverage.family.rawValue)")
    }

    private func title(for family: StaticResearchFamily) -> String {
        switch family {
        case .signer: "Signer"
        case .embeddedCertificates: "Embedded certificates"
        case .entitlements: "Signed entitlements"
        case .architectures: "Architectures"
        case .loadCommands: "Load commands"
        case .linkedFrameworks: "Linked frameworks"
        case .apiReferences: "API references"
        case .persistenceCharacteristics: "Persistence characteristics"
        case .codeDirectoryData: "CodeDirectory data"
        }
    }

    private func stateTitle(_ state: StaticCollectionState?) -> String {
        guard let state else { return "Unrecorded" }
        return state.rawValue.replacingOccurrences(of: "_", with: " ").capitalized
    }

    private func presenceTitle(_ coverage: StaticResearchFamilyCoverage) -> String {
        switch coverage.presence {
        case .observed:
            let count = coverage.observationCount ?? coverage.retainedRecordCount
            let qualifier = coverage.countInterpretation == .lowerBound ? "at least " : ""
            return "Observed \(qualifier)\(count.formatted()) within the collected scope."
        case .scopedAbsent:
            return "No records found within the completed collection scope."
        case .unknown:
            return "Presence unknown; collection did not establish absence."
        }
    }

    private func presenceTitle(_ presence: StaticResearchPresence) -> String {
        switch presence {
        case .observed: "observed"
        case .scopedAbsent: "no entries within completed scope"
        case .unknown: "presence unknown"
        }
    }
}
