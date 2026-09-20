import SwiftUI
import OSLog

struct EmbeddedEvidenceView: View {
    let objects: [EmbeddedObject]
    @State private var expandedID: UUID?
    @State private var selectedAt = ContinuousClock.now
    private let logger = Logger(subsystem: "io.hideouts.EntitlementLens", category: "DetailPerformance")

    var body: some View {
        GroupBox("Supporting Raw Evidence (\(objects.count))") {
            PagedEvidenceView(items: objects) { object in
                VStack(alignment: .leading, spacing: 8) {
                    Button {
                        selectedAt = .now
                        expandedID = expandedID == object.id ? nil : object.id
                    } label: {
                        Label("\(object.format.title) • offset 0x\(String(object.offset, radix: 16))",
                              systemImage: expandedID == object.id ? "chevron.down" : "chevron.right")
                    }
                    .buttonStyle(.plain)
                    .accessibilityValue(expandedID == object.id ? "Expanded" : "Collapsed")
                    .accessibilityIdentifier("embedded.object.\(object.id)")
                    if expandedID == object.id {
                        VStack(alignment: .leading, spacing: 8) {
                            PagedTextView(text: object.summary)
                            Text("Confidence \(object.confidence)% • \(object.length) bytes")
                            Text("Raw matches are supporting evidence, not proof of signed entitlements or runtime use.")
                                .foregroundStyle(.secondary)
                            EmbeddedKeysView(keys: object.entitlementKeys)
                            PagedEvidenceView(items: object.stringMatches) { match in
                                VStack(alignment: .leading) {
                                    Text("Offset 0x\(String(match.offset, radix: 16))").font(.caption)
                                    PagedTextView(text: match.value)
                                }
                            }
                        }
                        .onAppear {
                            let elapsed = selectedAt.duration(to: .now)
                            let milliseconds = Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds) / 1e15
                            logger.info("event=embedded_detail_appeared elapsed_ms=\(milliseconds) keys=\(object.entitlementKeys.count) strings=\(object.stringMatches.count)")
                        }
                    }
                }
            }
        }
    }
}

private struct EmbeddedKeysView: View {
    let keys: [String]
    @State private var page = 0

    var body: some View {
        VStack(alignment: .leading) {
            ForEach((page * 20)..<min(keys.count, (page + 1) * 20), id: \.self) { index in
                PagedTextView(text: keys[index])
            }
            if keys.count > 20 {
                HStack {
                    Button("Previous keys") { page -= 1 }.disabled(page == 0)
                        .accessibilityIdentifier("evidence.previous-keys")
                    Text("\(keys.count) keys • page \(page + 1)").font(.caption)
                    Button("Next keys") { page += 1 }.disabled((page + 1) * 20 >= keys.count)
                        .accessibilityIdentifier("evidence.next-keys")
                }
            }
        }
    }
}
