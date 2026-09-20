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
                } message: {
                    Text(store.lastError ?? "Unknown error")
                }
        }
        .defaultSize(width: 1_320, height: 820)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Scan Folder…") {
                    store.chooseFolderAndScan()
                }
                .keyboardShortcut("o", modifiers: [.command])
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
                Button("Export CSV…") { store.exportResults(format: .csv) }
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
