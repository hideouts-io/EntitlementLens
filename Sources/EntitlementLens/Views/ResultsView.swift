import AppKit
import SwiftUI

struct ResultsView: View {
    @Bindable var store: ScanStore
    @State private var showsScanSetup = false

    var body: some View {
        VStack(spacing: 8) {
            if isWelcomeState {
                welcomeView
            } else {
                HStack {
                    Toggle("Show empty/skipped items", isOn: $store.showsEmptyItems)
                        .toggleStyle(.button)
                        .accessibilityIdentifier("results.show-empty-skipped")
                    if store.isFiltering { ProgressView().controlSize(.small) }
                    Spacer()
                }
                .padding(.horizontal)
                if !store.scannedRoots.isEmpty {
                    scanSummary
                }
                Text("\(store.filteredFindings.count) shown • \(store.findings.count) retained • \(store.hiddenEmptyCount) empty. Warnings remain visible.")
                    .font(.caption).foregroundStyle(.secondary)
                if store.scanWasCancelled {
                    Label("Scan stopped. Retained results are partial; unvisited items were not assessed.", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                        .accessibilityIdentifier("results.cancelled-coverage")
                }
                if store.filteredFindings.isEmpty {
                    ContentUnavailableView {
                        Label(emptyTitle, systemImage: store.isScanning ? "waveform.path.ecg" : "checkmark.seal")
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
                        TableColumn("Research") { finding in
                            Toggle("Include in research submission", isOn: Binding(
                                get: { store.researchSelectedFindingIDs.contains(finding.id) },
                                set: { isSelected in
                                    var selectedIDs = store.researchSelectedFindingIDs
                                    if isSelected {
                                        selectedIDs.insert(finding.id)
                                    } else {
                                        selectedIDs.remove(finding.id)
                                    }
                                    store.researchSelectedFindingIDs = selectedIDs
                                }
                            ))
                            .labelsHidden()
                            .toggleStyle(.checkbox)
                            .accessibilityLabel("Include \(finding.name) in research submission")
                            .accessibilityIdentifier("research.select.\(finding.id)")
                        }
                        .width(75)
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
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .navigationTitle(store.selectedFilter.title)
        .searchable(text: $store.searchText, placement: .toolbar, prompt: "Key, value, team, or path")
    }

    private var isWelcomeState: Bool {
        store.scannedRoots.isEmpty && !store.isScanning && !store.isFiltering && store.searchText.isEmpty && store.findings.isEmpty
    }

    private var welcomeView: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 14) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 72, height: 72)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Inspect What Signed Code Declares")
                            .font(.title2.weight(.semibold))
                        Text("Examine macOS apps and binaries without running them.")
                            .foregroundStyle(.secondary)
                    }
                }
                GroupBox("What you can learn") {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("Signed entitlements and code-signature integrity, including differences between architectures.", systemImage: "checkmark.seal")
                        Label("Embedded property lists and strings as supporting evidence when Deep carve is on.", systemImage: "doc.text.magnifyingglass")
                        Label("Which items were skipped, failed, or limited by permissions in scan coverage.", systemImage: "list.bullet.clipboard")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 4)
                }
                Text("A signed entitlement is a declaration. Static inspection cannot show that a capability was granted or used at runtime; embedded strings are not signed entitlements.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Button("Scan a Folder…") {
                    store.chooseFolderAndScan()
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("results.welcome.scan-folder")
                Text("Start with a focused folder. Broader Applications, System, and Entire Mac scans are available in the sidebar.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: 560, alignment: .leading)
            .padding(24)
            .frame(maxWidth: .infinity)
        }
        .accessibilityIdentifier("results.welcome")
    }

    private var scanSummary: some View {
        let classifiedCount = store.statistics.machO + store.statistics.bundles + store.statistics.propertyLists + store.statistics.rawFiles
        let rootPaths = store.scannedRoots.map(\.path).joined(separator: "\n")
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Scan summary")
                    .font(.subheadline.weight(.semibold))
                    .accessibilityIdentifier("results.scan-summary")
                Spacer()
                Text(scanStatus)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(store.scanWasCancelled || !store.issues.isEmpty ? Color.orange : Color.secondary)
                    .accessibilityIdentifier("results.scan-status")
            }
            Text("\(store.statistics.discovered.formatted()) discovered • \(classifiedCount.formatted()) classified • \(store.findings.count.formatted()) analyzed/retained • \(store.issues.count.formatted()) coverage issues")
                .font(.caption)
            Text(store.scannedRoots.count == 1 ? "Root: \(store.scannedRoots[0].path)" : "Roots: \(store.scannedRoots.count.formatted()) locations")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .help(rootPaths)
            DisclosureGroup("Scope and options", isExpanded: $showsScanSetup) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Roots: \(rootPaths)")
                        .textSelection(.enabled)
                    Text("Hidden files: \(store.scannedIncludeHidden ? "included" : "excluded") • Deep carve: \(store.scannedDeepCarve ? "on" : "off")")
                    Text(store.scannedExcludedPaths.isEmpty ? "Excluded paths: none" : "Excluded paths: \(store.scannedExcludedPaths.joined(separator: ", "))")
                        .textSelection(.enabled)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            .font(.caption)
            Button("Coverage details (\(store.issues.count))…") {
                store.showsIssues = true
            }
            .font(.caption)
            .accessibilityIdentifier("results.show-coverage")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal)
    }

    private var scanStatus: String {
        if store.isScanning { return "In progress" }
        if store.scanWasCancelled { return "Stopped — partial" }
        if !store.issues.isEmpty { return "Completed with coverage gaps" }
        return "Completed"
    }

    private var emptyTitle: String {
        if store.isFiltering { return "Filtering…" }
        if store.isScanning { return "Scanning…" }
        if !store.findings.isEmpty { return "No Visible Results" }
        if !store.searchText.isEmpty { return "No Matches" }
        return "No Results"
    }

    private var emptyDescription: String {
        if !store.findings.isEmpty { return "Change the filter or show empty/skipped items. All collected records remain available for export." }
        if store.isScanning { return "Results appear as files are classified and analyzed." }
        if !store.searchText.isEmpty { return "Try a broader entitlement key, team ID, or path." }
        return "Choose another folder or review scan coverage for collection limits."
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
