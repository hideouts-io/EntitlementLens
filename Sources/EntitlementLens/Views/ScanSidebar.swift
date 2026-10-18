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
                scanButton(
                    "Applications", subtitle: "Apps in /Applications\nand /System/Applications",
                    image: "app.badge", identifier: "scan.quick.applications", action: store.scanApplications
                )
                scanButton(
                    "System", subtitle: "Selected services, frameworks, and tools",
                    image: "gearshape.2", identifier: "scan.quick.system", action: store.scanSystem
                )
                scanButton(
                    "Entire Mac", subtitle: "Common app, system, library, and user roots",
                    image: "desktopcomputer", identifier: "scan.quick.entire-mac", action: store.scanEntireMac
                )
            }

            Section("Options") {
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Include hidden files", isOn: $store.includeHidden)
                        .accessibilityIdentifier("scan.include-hidden")
                    Text("Include dotfiles and other hidden items in the chosen scope.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Deep carve", isOn: $store.deepCarve)
                        .accessibilityIdentifier("scan.deep-carve")
                    Text("Slower scan of embedded plists and strings. These are supporting evidence, not signed entitlements.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(4)
                        .fixedSize(horizontal: false, vertical: true)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text("Excluded paths")
                        .font(.subheadline)
                    TextField("Absolute paths; separate with ; or a new line", text: $store.excludedPathsText, axis: .vertical)
                        .lineLimit(2...4)
                        .accessibilityLabel("Excluded paths")
                        .accessibilityIdentifier("scan.excluded-paths")
                    Text("These paths are skipped. Keep the default macOS maintenance-volume exclusions unless they are in scope.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(4)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("Symbolic links are never followed. Broad scans may encounter protected locations; review coverage afterward.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(4)
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

    private func scanButton(_ title: String, subtitle: String, image: String, identifier: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 9) {
                Image(systemName: image)
                    .frame(width: 17)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(store.isScanning)
        .accessibilityIdentifier(identifier)
    }
}
