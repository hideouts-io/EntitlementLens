import Foundation
import Testing
@testable import EntitlementLens

@MainActor
struct ScanStoreIntegrationTests {
    @Test
    func largeScanKeepsLatestSearchAndSelectionWithoutDroppingRecords() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-stress-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Fixture cleanup failed: \(error.localizedDescription)") }
        }
        let data = try PropertyListSerialization.data(fromPropertyList: ["com.apple.security.example": true], format: .xml, options: 0)
        for index in 0..<1_000 {
            try data.write(to: root.appendingPathComponent("record-\(index).plist"))
        }
        let store = ScanStore()
        let started = ContinuousClock.now
        store.startScan(roots: [root])
        try await waitForPresentation(store)
        #expect(store.lastError == nil)
        #expect(store.findings.count == 1_000)
        #expect(store.filteredFindings.count == 1_000)
        let scanDuration = started.duration(to: .now)

        let searchStarted = ContinuousClock.now
        for query in ["record-1", "no-such-item", "record-99", "record-999.plist"] {
            store.searchText = query
        }
        try await waitForPresentation(store)
        #expect(store.filteredFindings.map(\.name) == ["record-999.plist"])
        #expect(store.selectedFinding?.name == "record-999.plist")
        #expect(store.findings.count == 1_000)
        let searchDuration = searchStarted.duration(to: .now)

        store.searchText = ""
        store.selectedFilter = .entitlements
        store.selectedFilter = .embeddedObjects
        try await waitForPresentation(store)
        #expect(store.filteredFindings.count == 1_000)
        for finding in store.filteredFindings.prefix(100) {
            store.selectedFindingID = finding.id
            #expect(store.selectedFinding?.id == finding.id)
        }
        let retained = store.findings
        let exportURL = root.appendingPathComponent("results.json")
        try await writeExport(to: exportURL) {
            #expect(!Thread.isMainThread)
            return try ResultExporter.data(for: retained, format: .json)
        }
        let exported = try Data(contentsOf: exportURL)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: exported).count == 1_000)
        print("PERFORMANCE records=1000 scan_seconds=\(seconds(scanDuration)) latest_search_seconds=\(seconds(searchDuration))")

        store.startScan(roots: [root])
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        while store.findings.isEmpty && store.isScanning {
            guard ContinuousClock.now < deadline else { throw PresentationTimeout.didNotSettle }
            try await Task.sleep(for: .milliseconds(1))
        }
        #expect(store.isScanning)
        store.cancelScan()
        let retainedAtStop = store.findings.map(\.id)
        try await Task.sleep(for: .milliseconds(100))
        #expect(store.scanWasCancelled)
        #expect(!retainedAtStop.isEmpty)
        #expect(store.findings.map(\.id) == retainedAtStop)
        #expect(!store.isScanning)
    }

    @Test
    func exportFailurePreservesExistingFile() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-export-\(UUID()).json")
        let original = Data("original".utf8)
        try original.write(to: url)
        defer {
            do { try FileManager.default.removeItem(at: url) }
            catch { Issue.record("Fixture cleanup failed: \(error.localizedDescription)") }
        }
        do {
            try await writeExport(to: url) { throw ExportTestError.encodingFailed }
            Issue.record("Export unexpectedly succeeded")
        } catch ExportTestError.encodingFailed {
            #expect(try Data(contentsOf: url) == original)
        }
    }

    @Test
    func replacingScanDiscardsOldWork() async throws {
        let store = ScanStore()
        store.startScan(roots: [URL(fileURLWithPath: "/usr/bin")])
        store.searchText = "old-query"
        store.startScan(roots: [URL(fileURLWithPath: "/usr/bin/true")])
        store.searchText = ""
        store.showsEmptyItems = true
        try await waitForPresentation(store)
        #expect(store.lastError == nil)
        #expect(store.findings.map(\.path) == ["/usr/bin/true"])
        #expect(store.filteredFindings.count == 1)
        #expect(store.selectedFinding?.path == "/usr/bin/true")
    }

    private func waitForPresentation(_ store: ScanStore) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while store.isScanning || store.isFiltering {
            guard ContinuousClock.now < deadline else { throw PresentationTimeout.didNotSettle }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    private func seconds(_ duration: Duration) -> Double {
        Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
    }
}

private enum PresentationTimeout: Error {
    case didNotSettle
}

private enum ExportTestError: Error {
    case encodingFailed
}
