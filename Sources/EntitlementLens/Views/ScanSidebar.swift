import SwiftUI

struct ScanSidebar: View {
    @Bindable var store: ScanStore

    var body: some View {
        List {
            Section("Results") {
                ForEach(ResultFilter.allCases) { filter in
                    Button {
                        store.browserMode = .files
                        store.selectedFilter = filter
                    } label: {
                        HStack {
                            Label(filter.title, systemImage: filter.systemImage)
                            Spacer()
                            Text(store.count(for: filter), format: .number)
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(store.browserMode == .files && store.selectedFilter == filter ? Color.accentColor : Color.primary)
                    .fontWeight(store.browserMode == .files && store.selectedFilter == filter ? .semibold : .regular)
                }
            }

            Section("Quick Scans") {
                scanButton("Applications", image: "app.badge", action: store.scanApplications)
                scanButton("System", image: "gearshape.2", action: store.scanSystem)
                scanButton("Entire Mac", image: "desktopcomputer", action: store.scanEntireMac)
            }

            Section("Options") {
                Toggle("Include hidden files", isOn: $store.includeHidden)
                Toggle("Deep carve", isOn: $store.deepCarve)
                    .accessibilityIdentifier("scan.deep-carve")
                TextField("Excluded paths (; separated)", text: $store.excludedPathsText, axis: .vertical)
                    .lineLimit(2...4)
                    .accessibilityIdentifier("scan.excluded-paths")
                Text("Deep carve parses embedded plists and performs a strings-like keyword scan. Symbolic links are never followed.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Section("Coverage") {
                HStack {
                    Label("\(store.statistics.discovered.formatted()) discovered", systemImage: "doc.on.doc")
                    Spacer()
                    if store.isScanning {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                .font(.caption)

                Button {
                    store.showsIssues = true
                } label: {
                    Label("\(store.statistics.issues.formatted()) skipped / issues", systemImage: "lock.trianglebadge.exclamationmark")
                }
                .buttonStyle(.plain)
                .font(.caption)
                .foregroundStyle(store.issues.isEmpty ? Color.secondary : Color.orange)
                .disabled(store.issues.isEmpty)
            }
        }
        .listStyle(.sidebar)
    }

    private func scanButton(_ title: String, image: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Label(title, systemImage: image)
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(store.isScanning)
    }
}
