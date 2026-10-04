import AppKit
import SwiftUI

struct ResultsView: View {
    @Bindable var store: ScanStore

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Toggle("Show empty/skipped items", isOn: $store.showsEmptyItems)
                    .toggleStyle(.button)
                    .accessibilityIdentifier("results.show-empty-skipped")
                if store.isFiltering { ProgressView().controlSize(.small) }
                Spacer()
            }
            .padding(.horizontal)
            Text("\(store.filteredFindings.count) shown • \(store.findings.count) retained • \(store.hiddenEmptyCount) empty. Warnings remain visible.")
                .font(.caption).foregroundStyle(.secondary)
            if store.scanWasCancelled {
                Label("Scan stopped. Retained results are partial; unvisited items were not assessed.", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
                    .accessibilityIdentifier("results.cancelled-coverage")
            }
            if store.showsEmptyItems {
                Button("View skipped / failed / permission-limited items (\(store.issues.count))") {
                    store.showsIssues = true
                }
                .accessibilityIdentifier("results.show-coverage")
            }
            if store.filteredFindings.isEmpty {
                ContentUnavailableView {
                    if store.scannedRoots.isEmpty && !store.isScanning && !store.isFiltering && store.searchText.isEmpty {
                        Label {
                            Text(emptyTitle)
                        } icon: {
                            Image(nsImage: NSApp.applicationIconImage)
                                .resizable()
                                .scaledToFit()
                                .frame(width: 96, height: 96)
                                .accessibilityHidden(true)
                        }
                        .accessibilityIdentifier("results.welcome")
                    } else {
                        Label(emptyTitle, systemImage: store.isScanning ? "waveform.path.ecg" : "checkmark.seal")
                    }
                } description: {
                    Text(emptyDescription)
                } actions: {
                    if !store.isScanning && store.findings.isEmpty {
                        Button("Choose Folder…") {
                            store.chooseFolderAndScan()
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
            } else {
                Table(store.filteredFindings, selection: $store.selectedFindingID) {
                    TableColumn("File") { finding in
                        HStack(spacing: 9) {
                            Image(systemName: finding.kind.systemImage)
                                .foregroundStyle(.secondary)
                                .frame(width: 18)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(finding.name)
                                    .lineLimit(1)
                                    .accessibilityIdentifier("result.file.\(finding.id)")
                                Text(finding.path)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                    }
                    .width(min: 230, ideal: 320)

                    TableColumn("Signing") { finding in
                        SignatureStatusLabel(signing: finding.signing)
                    }
                    .width(90)

                    TableColumn("Entitlements") { finding in
                        Text(finding.entitlementCount, format: .number)
                            .monospacedDigit()
                            .accessibilityIdentifier("result.entitlement-count.\(finding.id)")
                    }
                    .width(85)
                    TableColumn("Collection") { finding in
                        Text(store.outcome(for: finding).rawValue)
                    }
                    .width(min: 130, ideal: 165)
                }
                .contextMenu(forSelectionType: UUID.self) { selectedIDs in
                    if let selectedID = selectedIDs.first, let finding = store.finding(id: selectedID) {
                        Button("Reveal in Finder") {
                            store.revealInFinder(finding)
                        }
                        Button("Open in TextEdit") {
                            store.openInTextEdit(finding)
                        }
                        Divider()
                        Button("Copy Path") {
                            store.copyPath(finding)
                        }
                        Button("Copy All Data Found") {
                            store.copyAllData(finding)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .navigationTitle(store.selectedFilter.title)
        .searchable(text: $store.searchText, placement: .toolbar, prompt: "Key, value, team, or path")
    }

    private var emptyTitle: String {
        if store.isFiltering { return "Filtering…" }
        if store.isScanning { return "Scanning…" }
        if !store.findings.isEmpty { return "No Visible Results" }
        if !store.searchText.isEmpty { return "No Matches" }
        return "Inspect Signed Code"
    }

    private var emptyDescription: String {
        if !store.findings.isEmpty { return "Change the filter or show empty/skipped items. All collected records remain available for export." }
        if store.isScanning { return "Results appear as files are classified and analyzed." }
        if !store.searchText.isEmpty { return "Try a broader entitlement key, team ID, or path." }
        return "Choose a directory, or start with one of the curated scopes in the sidebar."
    }
}

private struct SignatureStatusLabel: View {
    let signing: SigningDetails?

    var body: some View {
        HStack(spacing: 5) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
            Text(signing?.status.title ?? "N/A")
                .lineLimit(1)
        }
        .foregroundStyle(.secondary)
    }

    private var color: Color {
        guard let signing else {
            return .secondary
        }
        if signing.resourceIntegrity.isProblem {
            return .red
        }
        switch signing.status {
        case .valid: return .green
        case .unsigned: return .secondary
        case .invalid: return .red
        case .unavailable: return .orange
        }
    }
}
