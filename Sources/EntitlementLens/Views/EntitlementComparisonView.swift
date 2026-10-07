import SwiftUI

struct EntitlementComparisonView: View {
    let comparison: EntitlementComparison

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Declared entitlement comparison").font(.headline)
            Text(comparison.summary).textSelection(.enabled)
                .accessibilityIdentifier("counterpart.entitlement-summary")
            Text("Source is the baseline. Changes describe Installed relative to Source. Counts include each scope; the standard dictionary is unscoped.")
                .font(.caption).foregroundStyle(.secondary)
            if !comparison.isComplete {
                Label("Incomplete evidence: unavailable declarations are not treated as absent.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("counterpart.incomplete")
            }
            ForEach(comparison.warnings, id: \.self) { warning in
                PagedTextView(text: warning)
            }
            PagedEvidenceView(items: comparison.scopes) { scope in
                CounterpartScopeView(comparison: scope)
            }
        }
        .accessibilityIdentifier("counterpart.entitlements")
    }
}

private struct CounterpartScopeView: View {
    let comparison: EntitlementScopeComparison

    private var scopeIdentifier: String {
        switch comparison.scope {
        case .standardDictionary: "standard"
        case let .architecture(name): name
        }
    }

    var body: some View {
        GroupBox(comparison.scope.title) {
            VStack(alignment: .leading, spacing: 10) {
                Text(comparison.summary).font(.callout).textSelection(.enabled)
                evidence(comparison.source, label: "Source")
                evidence(comparison.installed, label: "Installed")
                if !comparison.entries.isEmpty {
                    DisclosureGroup("Declarations (\(comparison.entries.count))") {
                        PagedEvidenceView(items: comparison.entries) { entry in
                            DisclosureGroup {
                                value(entry.sourceValue, evidence: comparison.source, label: "Source")
                                value(entry.installedValue, evidence: comparison.installed, label: "Installed")
                            } label: {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(entry.key).font(.body.monospaced()).textSelection(.enabled)
                                    Text(entry.result.title).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            .accessibilityIdentifier("counterpart.entry.\(scopeIdentifier).\(entry.key)")
                        }
                    }
                    .accessibilityIdentifier("counterpart.scope.\(scopeIdentifier)")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 5)
        }
    }

    private func evidence(_ evidence: EntitlementComparisonEvidence, label: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(label): \(evidence.availability.title) · Signature: \(evidence.signatureStatus?.title ?? "Not collected")")
                .font(.caption).textSelection(.enabled)
            if let detail = evidence.signatureStatus?.detail { PagedTextView(text: detail) }
            if let cdHash = evidence.uniqueCDHash { PagedTextView(text: "CDHash \(cdHash)") }
            ForEach(evidence.warnings, id: \.self) { warning in
                PagedTextView(text: warning)
            }
        }
    }

    private func value(_ value: EntitlementValue?, evidence: EntitlementComparisonEvidence, label: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            if let value {
                Text("\(label) · \(value.typeTitle)").font(.subheadline.bold())
                EntitlementValueView(value: value)
            } else {
                Text("\(label): \(evidence.availability == .collected ? "No declaration for this key" : evidence.availability.title)")
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
    }
}
