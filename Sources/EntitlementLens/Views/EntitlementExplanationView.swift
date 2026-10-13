import SwiftUI

/// Bundled reference text is separate from each architecture-qualified observed declaration.
struct EntitlementExplanationView: View {
    let lookup: EntitlementExplanationLookup
    let catalogRevision: String
    let reviewedOn: String

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Label("Curated reference", systemImage: "book.closed")
                .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            switch lookup {
            case let .available(explanation):
                Text(explanation.title).font(.headline)
                    .accessibilityIdentifier("explorer.explanation.title")
                Text(explanation.summary).font(.callout).textSelection(.enabled)
                    .accessibilityIdentifier("explorer.explanation.meaning")
                Text("Documented value shape: \(explanation.valueShape.title)")
                    .font(.caption)
                ForEach(explanation.contextLimits.indices, id: \.self) { index in
                    Text(explanation.contextLimits[index]).font(.caption).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("explorer.explanation.context.\(index)")
                }
                Text("An observed value is a static declaration. Signature integrity, policy decisions, and runtime authorization are assessed separately.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(explanation.sources, id: \.url) { source in
                    Link(source.title, destination: source.url)
                        .font(.caption)
                        .accessibilityIdentifier("explorer.explanation.source.\(source.url.path)")
                }
            case .unavailable:
                Text("No curated explanation available")
                    .font(.callout)
                    .accessibilityIdentifier("explorer.explanation.unavailable")
                Text("This key has no reviewed entry in the bundled catalog. Its original value and source declarations remain below.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("Catalog \(catalogRevision) · Sources reviewed \(reviewedOn)")
                .font(.caption2).foregroundStyle(.secondary)
                .accessibilityIdentifier("explorer.explanation.revision")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 7))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("explorer.explanation")
    }
}
