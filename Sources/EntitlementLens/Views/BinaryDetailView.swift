import SwiftUI

struct BinaryDetailView: View {
    let finding: ScanFinding?
    let highlightedKey: String?
    let detailAppeared: (UUID) -> Void

    var body: some View {
        if let finding {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 18) {
                    header(finding)
                    capabilityNotice
                    Text(findingOutcome(finding).rawValue)
                        .font(.headline)
                    ArtifactEvidenceView(
                        provenance: finding.provenance,
                        installedCounterpart: finding.installedCounterpart
                    )
                    if let signing = finding.signing {
                        entitlements(signing.entitlements)
                        ArchitectureEntitlementsView(
                            architectures: signing.architectureEntitlements,
                            slots: signing.entitlementSlots,
                            highlightedKey: highlightedKey
                        )
                        signingMetadata(signing)
                    }
                    if !finding.runningBoardPolicies.isEmpty {
                        RunningBoardPolicyView(policies: finding.runningBoardPolicies)
                    }
                    if !finding.embeddedObjects.isEmpty {
                        EmbeddedEvidenceView(objects: finding.embeddedObjects)
                    }
                    if !finding.warnings.isEmpty {
                        warnings(finding.warnings)
                    }
                }
                .padding(22)
                .frame(maxWidth: 820, alignment: .leading)
            }
            .navigationTitle(finding.name)
            .accessibilityIdentifier("detail.scroll")
            .onAppear { detailAppeared(finding.id) }
            .id(finding.id)
        } else {
            ContentUnavailableView("Select a Result", systemImage: "sidebar.right", description: Text("Signature details and extracted evidence appear here."))
        }
    }

    private func header(_ finding: ScanFinding) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: finding.kind.systemImage)
                    .font(.system(size: 30))
                    .foregroundStyle(.tint)
                    .frame(width: 44, height: 44)
                    .background(.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 11))
                VStack(alignment: .leading, spacing: 3) {
                    Text(finding.name)
                        .font(.title2.weight(.semibold))
                        .textSelection(.enabled)
                    Text(finding.path)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer()
            }
            HStack(spacing: 8) {
                metadataPill(finding.kind.title, image: finding.kind.systemImage)
                metadataPill(finding.fileFormat, image: "doc.text.magnifyingglass")
                if let size = finding.fileSize {
                    metadataPill(ByteCountFormatter.string(fromByteCount: size, countStyle: .file), image: "internaldrive")
                }
            }
        }
    }

    private var capabilityNotice: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "info.circle.fill")
                .foregroundStyle(.blue)
            Text("Signed entitlements are declarations, not proof of runtime authorization or use. Embedded keys and strings are supporting raw evidence, not signed entitlements.")
                .font(.callout)
        }
        .padding(12)
        .background(.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
    }

    private func entitlements(_ entries: [EntitlementEntry]) -> some View {
        GroupBox {
            if entries.isEmpty {
                Text("No entitlements returned in the standard dictionary. Check per-architecture evidence and coverage notes before concluding that declarations are absent.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 6)
            } else {
                EntitlementEntriesView(entries: entries, highlightedKey: highlightedKey)
            }
        } label: {
            Label("Standard entitlement dictionary (\(entries.count))", systemImage: "checkmark.seal.fill")
                .accessibilityIdentifier("detail.standard-entitlement-dictionary")
        }
    }

    private func signingMetadata(_ signing: SigningDetails) -> some View {
        GroupBox("Code Signature") {
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 9) {
                metadataRow("Signature integrity", signing.status.title)
                metadataRow("Signed resources", signing.resourceIntegrity.title)
                metadataRow("Execution policy", signing.executionPolicy.status.title)
                metadataRow("Entitlement scope", signing.entitlementScope.title)
                metadataRow("Runtime authorization", signing.runtimeAuthorization.status.title)
                metadataRow("Identifier", signing.identifier ?? "Not present")
                metadataRow("Team", signing.teamIdentifier ?? "Not present")
                metadataRow("Format", signing.format ?? "Not reported")
                metadataRow("Source", signing.source ?? "Not reported")
                metadataRow("Main executable", signing.mainExecutable ?? "Not reported")
                metadataRow("Platform identifier", signing.platformIdentifier.map(String.init) ?? "Not reported")
                metadataRow("Unique CDHash", signing.uniqueCDHash ?? "Not reported")
                metadataRow("CDHashes", signing.cdHashes.isEmpty ? "Not reported" : signing.cdHashes.joined(separator: "\n"))
                metadataRow("Flags", signing.signatureFlags.map { String(format: "0x%08X", $0) } ?? "Not reported")
                metadataRow("Raw entitlement blob", signing.rawEntitlementsByteCount.map { "\($0) bytes" } ?? "Not present")
                metadataRow("Signing time", dateValue(signing.signingTime))
                metadataRow("Secure timestamp", dateValue(signing.timestamp))
                if let detail = signing.status.detail {
                    metadataRow("Signature detail", detail)
                }
                if let detail = signing.resourceIntegrity.detail {
                    metadataRow("Resource detail", detail)
                }
                metadataRow("Execution-policy detail", signing.executionPolicy.detail)
                metadataRow("Runtime-authorization detail", signing.runtimeAuthorization.detail)
                if !signing.authorities.isEmpty {
                    metadataRow("Authorities", signing.authorities.joined(separator: " → "))
                }
                if let requirements = signing.requirements {
                    metadataRow("Requirements", requirements)
                }
            }
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func warnings(_ warnings: [String]) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(warnings, id: \.self) { warning in
                    Label(warning, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text("Coverage Notes")
        }
    }

    private func metadataPill(_ title: String, image: String) -> some View {
        Label(title, systemImage: image)
            .font(.caption)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(.secondary.opacity(0.1), in: Capsule())
    }

    private func metadataRow(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            PagedTextView(text: value)
                .gridColumnAlignment(.leading)
        }
    }

    private func dateValue(_ date: Date?) -> String {
        guard let date else {
            return "Not reported"
        }
        return date.formatted(date: .abbreviated, time: .standard)
    }
}
