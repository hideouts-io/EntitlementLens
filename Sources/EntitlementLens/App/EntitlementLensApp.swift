import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct EntitlementLensApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var store = ScanStore()

    var body: some Scene {
        WindowGroup {
            ContentView(store: store)
                .frame(minWidth: 1_050, minHeight: 680)
                .alert("EntitlementLens", isPresented: errorBinding) {
                    Button("OK") {
                        store.lastError = nil
                    }
                    .accessibilityIdentifier("scan.error-dismiss")
                } message: {
                    Text(store.lastError ?? "Unknown error")
                        .accessibilityIdentifier("scan.error-message")
                }
        }
        .defaultSize(width: 1_320, height: 820)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Scan File/App…") {
                    store.chooseFileAppAndScan()
                }
                .keyboardShortcut("o", modifiers: [.command, .option])
                .accessibilityIdentifier("scan.file-app-command")
                .disabled(store.isScanning)
                Button("Scan Folder…") {
                    store.chooseFolderAndScan()
                }
                .keyboardShortcut("o", modifiers: [.command])
                Button("Open Saved Candidate…") {
                    store.chooseSavedCandidate()
                }
                .keyboardShortcut("o", modifiers: [.command, .shift])
                .accessibilityIdentifier("research.open-saved-command")
                .disabled(!store.canOpenSavedCandidate)
            }
            CommandMenu("Scan") {
                Button("Applications") { store.scanApplications() }
                Button("System") { store.scanSystem() }
                Button("Entire Mac") { store.scanEntireMac() }
                Divider()
                Button("Stop") { store.cancelScan() }
                    .keyboardShortcut(".", modifiers: [.command])
                    .disabled(!store.isScanning)
            }
            CommandMenu("Export") {
                Button("Export JSON…") { store.exportResults(format: .json) }
                    .accessibilityIdentifier("export.command.json")
                Button("Export CSV…") { store.exportResults(format: .csv) }
                    .accessibilityIdentifier("export.command.csv")
            }
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(
            get: { store.lastError != nil },
            set: { isPresented in
                if !isPresented {
                    store.lastError = nil
                }
            }
        )
    }
}
