import SwiftUI

struct ArtifactEvidenceView: View {
    let provenance: ArtifactProvenance
    let installedCounterpart: InstalledCounterpartComparison?

    var body: some View {
        provenanceSection
        if !provenance.machOSlices.isEmpty {
            machOSlicesSection
        }
        if let installedCounterpart {
            counterpartSection(installedCounterpart)
        }
    }

    private var provenanceSection: some View {
        GroupBox("Evidence Provenance") {
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 9) {
                metadataRow("Analyzed path", provenance.analyzedPath)
                metadataRow("SHA-256", provenance.sha256)
                metadataRow("Analyzed size", ByteCountFormatter.string(fromByteCount: provenance.fileSize, countStyle: .file))
                metadataRow("Created", dateValue(provenance.createdAt))
                metadataRow("Modified", dateValue(provenance.modifiedAt))
                metadataRow("Owner", "UID \(provenance.ownerUserID), GID \(provenance.ownerGroupID)")
                metadataRow("POSIX mode", String(format: "%04o", provenance.posixMode))
                metadataRow("Filesystem identity", "device \(provenance.deviceID), inode \(provenance.inode)")
                metadataRow("Filesystem flags", String(format: "0x%08X", provenance.fileSystemFlags))
                metadataRow("Volume", volumeValue)
                metadataRow("Quarantine", provenance.quarantineValue ?? "Not present")
                metadataRow("Source OS", provenance.sourceOperatingSystem?.displayValue ?? "Not discoverable from the selected tree")
                metadataRow("Host OS", provenance.hostOperatingSystem.displayValue)
            }
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var machOSlicesSection: some View {
        GroupBox("Mach-O Build Provenance") {
            VStack(spacing: 0) {
                ForEach(provenance.machOSlices) { slice in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Label(slice.architecture, systemImage: "cpu")
                                .font(.headline)
                            Spacer()
                            Text(slice.platform ?? "Platform not reported")
                                .foregroundStyle(.secondary)
                        }
                        Text("Minimum OS \(slice.minimumOSVersion ?? "not reported") • SDK \(slice.sdkVersion ?? "not reported")")
                            .foregroundStyle(.secondary)
                        Text("UUID \(slice.uuid ?? "not reported")")
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                        Text("File range 0x\(String(slice.fileOffset, radix: 16).uppercased()) + \(slice.fileSize.formatted()) bytes")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 9)
                    if slice.id != provenance.machOSlices.last?.id {
                        Divider()
                    }
                }
            }
        }
    }

    private func counterpartSection(_ counterpart: InstalledCounterpartComparison) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: counterpart.relationship == .identical ? "equal.circle.fill" : "arrow.triangle.branch")
                        .foregroundStyle(counterpart.relationship == .identical ? .green : .orange)
                    Text(counterpart.relationship.title)
                        .font(.headline)
                }
                Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 9) {
                    metadataRow("Installed path", counterpart.path)
                    metadataRow("Analyzed path", counterpart.analyzedPath)
                    metadataRow("Installed SHA-256", counterpart.sha256)
                    metadataRow("Installed signature", counterpart.signatureStatus.title)
                    metadataRow("Installed unique CDHash", counterpart.uniqueCDHash ?? "Not reported")
                    metadataRow("Installed platform ID", counterpart.platformIdentifier.map(String.init) ?? "Not reported")
                    metadataRow("Installed source OS", counterpart.sourceOperatingSystem?.displayValue ?? "Not discoverable")
                }
                if counterpart.differences.isEmpty {
                    Text("No differences were found in the compared hashes, signing metadata, build targets, or entitlements.")
                        .foregroundStyle(.secondary)
                } else {
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(counterpart.differences, id: \.self) { difference in
                            Label(difference, systemImage: "exclamationmark.triangle")
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label("Installed Counterpart", systemImage: "arrow.left.arrow.right.square")
        }
    }

    private var volumeValue: String {
        let name = provenance.volumeName ?? "Unknown volume"
        guard let uuid = provenance.volumeUUID else {
            return name
        }
        return "\(name) (\(uuid))"
    }

    private func dateValue(_ date: Date?) -> String {
        guard let date else {
            return "Not reported"
        }
        return date.formatted(date: .abbreviated, time: .standard)
    }

    private func metadataRow(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value)
                .textSelection(.enabled)
                .gridColumnAlignment(.leading)
        }
    }
}
