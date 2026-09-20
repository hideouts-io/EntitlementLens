import PrivilegedProtocol
import SwiftUI

struct ScanIssuesView: View {
    @Bindable var store: ScanStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                accessGuidance
                Divider()
                if !store.privilegedRecords.isEmpty {
                    privilegedResults
                    Divider()
                }
                Table(store.issues) {
                    TableColumn("Collection") { issue in
                        Text(issue.collectionLabel)
                    }
                    .width(140)
                    TableColumn("Category") { issue in
                        Label(issue.category.title, systemImage: issue.category.systemImage)
                            .lineLimit(1)
                    }
                    .width(min: 135, ideal: 155)

                    TableColumn("Operation") { issue in
                        Text(issue.operation.title)
                            .lineLimit(1)
                    }
                    .width(min: 105, ideal: 125)

                    TableColumn("Path") { issue in
                        Text(issue.path)
                            .textSelection(.enabled)
                    }
                    .width(min: 220, ideal: 330)

                    TableColumn("Reason") { issue in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(issue.message)
                            Text("\(issue.errorDomain) \(issue.errorCode) • \(issue.recoverySuggestion)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .textSelection(.enabled)
                    }
                    .width(min: 300, ideal: 420)
                }
            }
            .navigationTitle("Skipped Items and Collection Limits")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Export Coverage…") { store.exportCoverage() }
                        .disabled(store.isExporting)
                        .accessibilityIdentifier("coverage.export")
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier("coverage.done")
                }
            }
        }
        .frame(minWidth: 980, minHeight: 520)
        .onAppear {
            store.refreshPrivilegedHelperState()
        }
    }

    private var accessGuidance: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "lock.doc.fill")
                .font(.title2)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 5) {
                Text(issueSummary)
                    .font(.headline)
                Text("Full Disk Access can authorize protected user-data locations. It is separate from administrator or root access, and neither bypasses System Integrity Protection. Changes require a new scan.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 16)
            VStack(alignment: .trailing, spacing: 8) {
                Button("Open Full Disk Access…") {
                    store.openFullDiskAccessSettings()
                }
                helperAction
                Text("Helper: \(store.privilegedHelperState.title)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if !store.privilegedRecords.isEmpty {
                    Text("\(store.privilegedRecords.count) privileged records returned")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.green)
                }
            }
        }
        .padding(16)
    }

    private var issueSummary: String {
        let privacyCount = store.issues.filter { $0.category == .privacyProtection }.count
        let posixCount = store.issues.filter { $0.category == .posixPermissions }.count
        return "\(store.issues.count) issues • \(privacyCount) privacy • \(posixCount) POSIX"
    }

    private var privilegedResults: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Privileged Read-Only Results", systemImage: "person.badge.key.fill")
                .font(.headline)
            Table(store.privilegedRecords) {
                TableColumn("Path") { record in
                    Text(record.path)
                        .textSelection(.enabled)
                }
                TableColumn("Owner") { record in
                    Text(ownerText(record))
                        .monospacedDigit()
                }
                .width(90)
                TableColumn("Mode") { record in
                    Text(record.posixMode.map { String(format: "%04o", $0) } ?? "—")
                        .font(.system(.body, design: .monospaced))
                }
                .width(60)
                TableColumn("Signing ID") { record in
                    Text(record.identifier ?? record.errorMessage ?? "Not signed")
                        .textSelection(.enabled)
                }
                TableColumn("Entitlements") { record in
                    Text(record.entitlementCount.map(String.init) ?? "—")
                        .monospacedDigit()
                }
                .width(85)
            }
            .frame(height: 150)
        }
        .padding(12)
    }

    private func ownerText(_ record: PrivilegedInspectionRecord) -> String {
        guard let userID = record.ownerUserID, let groupID = record.ownerGroupID else {
            return "—"
        }
        return "\(userID):\(groupID)"
    }

    @ViewBuilder
    private var helperAction: some View {
        switch store.privilegedHelperState {
        case .adHocSignature, .notFound:
            Button("Enable Read-Only Helper…") {
                store.enablePrivilegedHelper()
            }
            .disabled(true)
        case .notRegistered:
            Button("Enable Read-Only Helper…") {
                store.enablePrivilegedHelper()
            }
        case .requiresApproval:
            Button("Approve in Login Items…") {
                store.openLoginItemsSettings()
            }
        case .enabled:
            Button(store.isRunningPrivilegedRetry ? "Inspecting…" : "Retry Eligible Paths as Root") {
                store.runPrivilegedRetry()
            }
            .disabled(store.isRunningPrivilegedRetry || eligibleIssueCount == 0)
        }
    }

    private var eligibleIssueCount: Int {
        store.issues.filter(\.privilegedRetryEligible).count
    }
}
