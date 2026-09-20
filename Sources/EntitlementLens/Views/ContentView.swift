import SwiftUI

struct ContentView: View {
    @Bindable var store: ScanStore

    var body: some View {
        NavigationSplitView {
            ScanSidebar(store: store)
                .navigationSplitViewColumnWidth(min: 210, ideal: 240, max: 300)
        } content: {
            ResultsView(store: store)
                .navigationSplitViewColumnWidth(min: 390, ideal: 470)
        } detail: {
            BinaryDetailView(finding: store.selectedFinding, detailAppeared: store.detailAppeared)
        }
        .toolbar {
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
