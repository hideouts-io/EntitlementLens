import SwiftUI

struct ArchitectureEntitlementsView: View {
    let architectures: [ArchitectureEntitlements]
    let slots: [CodeSignatureEntitlementSlot]

    var body: some View {
        if !architectures.isEmpty {
            GroupBox("Per-Architecture Entitlements") {
                VStack(spacing: 0) {
                    ForEach(architectures) { architecture in
                        VStack(alignment: .leading, spacing: 7) {
                            HStack {
                                Label(architecture.architecture, systemImage: "cpu")
                                    .font(.headline)
                                Spacer()
                                Text(architecture.status.title)
                                    .foregroundStyle(.secondary)
                            }
                            Text(architecture.uniqueCDHash.map { "CDHash \($0)" } ?? "CDHash not reported")
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                            EntitlementEntriesView(entries: architecture.entitlements)
                            ForEach(architecture.warnings, id: \.self) { warning in
                                Label(warning, systemImage: "exclamationmark.triangle")
                                    .foregroundStyle(.orange)
                            }
                        }
                        .padding(.vertical, 9)
                        if architecture.id != architectures.last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
        if !slots.isEmpty {
            GroupBox("Mach-O Entitlement Slots") {
                VStack(spacing: 0) {
                    ForEach(slots) { slot in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Label(slot.format.title, systemImage: "seal")
                                    .font(.headline)
                                Spacer()
                                Text(slot.architecture)
                                    .foregroundStyle(.secondary)
                            }
                            Text("Slot \(slot.slotType) • offset 0x\(String(slot.fileOffset, radix: 16).uppercased()) • \(slot.byteCount) bytes")
                                .font(.caption.monospaced())
                            Text("SHA-256 \(slot.sha256)")
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                            Text(slot.decoderSource)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            if let warning = slot.warning {
                                Label(warning, systemImage: "exclamationmark.triangle")
                                    .foregroundStyle(.orange)
                            }
                        }
                        .padding(.vertical, 9)
                        if slot.id != slots.last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
    }
}
