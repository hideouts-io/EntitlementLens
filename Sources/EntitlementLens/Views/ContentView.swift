import SwiftUI

struct ContentView: View {
    @Bindable var store: ScanStore

    var body: some View {
        NavigationSplitView {
            ScanSidebar(store: store)
                .navigationSplitViewColumnWidth(min: 210, ideal: 240, max: 300)
        } content: {
            Group {
                switch store.browserMode {
                case .files: ResultsView(store: store)
                case .entitlements: EntitlementExplorerView(store: store)
                }
            }
                .navigationSplitViewColumnWidth(min: 390, ideal: 470)
        } detail: {
            BinaryDetailView(
                finding: store.selectedFinding,
                highlightedKey: store.browserMode == .entitlements ? store.selectedEntitlementKey : nil,
                detailAppeared: store.detailAppeared
            )
        }
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Browse", selection: $store.browserMode) {
                    Text("Files").tag(EntitlementBrowserMode.files)
                        .accessibilityIdentifier("browser.mode.files")
                    Text("By Entitlement").tag(EntitlementBrowserMode.entitlements)
                        .accessibilityIdentifier("browser.mode.entitlements")
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("browser.mode")
            }
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    store.chooseFolderAndScan()
                } label: {
                    Label("Scan Folder", systemImage: "folder.badge.plus")
                }
                .accessibilityIdentifier("scan.choose-folder")

                if store.isScanning {
                    Button(role: .cancel) {
                        store.cancelScan()
                    } label: {
                        Label("Stop", systemImage: "stop.fill")
                    }
                }

                Menu {
                    Button("JSON…") { store.exportResults(format: .json) }
                    Button("CSV…") { store.exportResults(format: .csv) }
                    Button("Coverage JSON…") { store.exportCoverage() }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .disabled(store.isExporting || (store.findings.isEmpty && store.issues.isEmpty))
                if store.isExporting {
                    ProgressView("Exporting…")
                        .controlSize(.small)
                        .accessibilityIdentifier("export.progress")
                }
            }
        }
        .sheet(isPresented: $store.showsIssues) {
            ScanIssuesView(store: store)
        }
    }
}
