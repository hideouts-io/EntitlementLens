import Darwin
import Foundation
import Testing
@testable import EntitlementLens

@MainActor
struct ScanFileIntakeIntegrationTests {
    @Test
    func selectedMachOScansOnlyThatFileAndPreservesSibling() async throws {
        let root = try intakeFixtureRoot()
        defer { removeIntakeFixture(root) }
        let selected = root.appendingPathComponent("selected-tool")
        let sibling = root.appendingPathComponent("sibling.plist")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: selected)
        try intakePropertyList().write(to: sibling)
        let siblingBytes = try Data(contentsOf: sibling)

        let store = ScanStore()
        store.showsEmptyItems = true
        store.startFileAppScan(at: selected)
        try await waitForIntakeScan(store)

        #expect(store.lastError == nil)
        #expect(store.scannedRoots == [selected])
        #expect(store.statistics.discovered == 1)
        #expect(store.findings.map(\.path) == [selected.path])
        #expect(store.findings.first?.kind == .machO)
        #expect(try Data(contentsOf: sibling) == siblingBytes)
    }

    @Test
    func selectedPropertyListScansOnlyThatFile() async throws {
        let root = try intakeFixtureRoot()
        defer { removeIntakeFixture(root) }
        let selected = root.appendingPathComponent("selected.plist")
        let sibling = root.appendingPathComponent("sibling.plist")
        try intakePropertyList().write(to: selected)
        try intakePropertyList().write(to: sibling)

        let store = ScanStore()
        store.showsEmptyItems = true
        store.startFileAppScan(at: selected)
        try await waitForIntakeScan(store)

        #expect(store.lastError == nil)
        #expect(store.scannedRoots == [selected])
        #expect(store.statistics.discovered == 1)
        #expect(store.findings.map(\.path) == [selected.path])
        #expect(store.findings.first?.kind == .propertyList)
    }

    @Test
    func selectedAppScansWithinBundleWithoutVisitingSibling() async throws {
        let root = try intakeFixtureRoot()
        defer { removeIntakeFixture(root) }
        let app = root.appendingPathComponent("Selected.app", isDirectory: true)
        let executable = app.appendingPathComponent("Contents/MacOS/Selected")
        try FileManager.default.createDirectory(at: executable.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: executable)
        try writeIntakeAppInfo(at: app, executableName: "Selected")
        let sibling = root.appendingPathComponent("sibling.plist")
        try intakePropertyList().write(to: sibling)
        let siblingBytes = try Data(contentsOf: sibling)

        let store = ScanStore()
        store.showsEmptyItems = true
        store.startFileAppScan(at: app)
        try await waitForIntakeScan(store)

        #expect(store.lastError == nil)
        #expect(store.scannedRoots == [app])
        #expect(store.findings.contains { isWithinIntakeRoot($0.path, root: app) && $0.kind == .bundle })
        #expect(store.findings.allSatisfy { isWithinIntakeRoot($0.path, root: app) })
        #expect(store.issues.allSatisfy { isWithinIntakeRoot($0.path, root: app)
            || $0.path == "/System/Library/LifecyclePolicy/DomainAttributes" })
        #expect(try Data(contentsOf: sibling) == siblingBytes)
    }

    @Test
    func versionedFrameworkWithContainedExecutableSymlinksScansWithinSelectedRoot() async throws {
        let root = try intakeFixtureRoot()
        defer { removeIntakeFixture(root) }
        let framework = root.appendingPathComponent("Fixture.framework", isDirectory: true)
        let version = framework.appendingPathComponent("Versions/A", isDirectory: true)
        let resources = version.appendingPathComponent("Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"),
            to: version.appendingPathComponent("Fixture"))
        try intakeBundleInfo(executableName: "Fixture", packageType: "FMWK")
            .write(to: resources.appendingPathComponent("Info.plist"))
        try FileManager.default.createSymbolicLink(atPath: framework.appendingPathComponent("Versions/Current").path,
            withDestinationPath: "A")
        try FileManager.default.createSymbolicLink(atPath: framework.appendingPathComponent("Fixture").path,
            withDestinationPath: "Versions/Current/Fixture")
        try FileManager.default.createSymbolicLink(atPath: framework.appendingPathComponent("Resources").path,
            withDestinationPath: "Versions/Current/Resources")
        let sibling = root.appendingPathComponent("sibling.plist")
        try intakePropertyList().write(to: sibling)

        #expect(try ScanFileIntake.validatedRoot(at: framework) == framework.standardizedFileURL)
        let store = ScanStore()
        store.showsEmptyItems = true
        store.startFileAppScan(at: framework)
        try await waitForIntakeScan(store)

        #expect(store.lastError == nil)
        #expect(store.scannedRoots == [framework])
        #expect(store.findings.contains { isWithinIntakeRoot($0.path, root: framework) && $0.kind == .bundle })
        #expect(store.findings.allSatisfy { isWithinIntakeRoot($0.path, root: framework) })
        #expect(store.issues.allSatisfy { isWithinIntakeRoot($0.path, root: framework)
            || $0.path == "/System/Library/LifecyclePolicy/DomainAttributes" })
        #expect(!store.findings.contains { isWithinIntakeRoot($0.path, root: sibling) })
    }

    @Test
    func invalidSelectionsReportErrorsWithoutReplacingPriorScan() async throws {
        let root = try intakeFixtureRoot()
        defer { removeIntakeFixture(root) }
        let store = ScanStore()
        store.showsEmptyItems = true
        store.startFileAppScan(at: URL(fileURLWithPath: "/usr/bin/true"))
        try await waitForIntakeScan(store)
        #expect(store.lastError == nil)
        #expect(store.findings.count == 1)
        let priorRoots = store.scannedRoots
        let priorFindingIDs = store.findings.map(\.id)
        let priorDiscovered = store.statistics.discovered

        store.excludedPathsText = "relative/path"
        assertRejected(URL(fileURLWithPath: "/usr/bin/true"), contains: "not an absolute path", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
        #expect(store.lastError?.contains("Enter exclusions beginning with /.") == true)
        store.excludedPathsText = ""

        let remote = try #require(URL(string: "https://example.invalid/tool"))
        assertRejected(remote, contains: "requires a local file", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
        let remoteFileURL = try #require(URL(string: "file://remote.example/tmp/tool"))
        assertRejected(remoteFileURL, contains: "requires a local file", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
        let link = root.appendingPathComponent("tool-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: URL(fileURLWithPath: "/usr/bin/true"))
        assertRejected(link, contains: "symbolic link", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
        let fifo = root.appendingPathComponent("pipe")
        try #require(mkfifo(fifo.path, 0o600) == 0)
        assertRejected(fifo, contains: "cannot inspect", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
        assertRejected(root.appendingPathComponent("missing"), contains: "errno \(ENOENT)", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
        let raw = root.appendingPathComponent("unsupported.txt")
        try Data("ordinary text".utf8).write(to: raw)
        store.deepCarve = true
        assertRejected(raw, contains: "cannot inspect", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
        assertRejected(root, contains: "cannot inspect", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)

        let malformedApp = root.appendingPathComponent("Malformed.app", isDirectory: true)
        try FileManager.default.createDirectory(at: malformedApp, withIntermediateDirectories: false)
        assertRejected(malformedApp, contains: "Could not resolve the executable", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)

        let external = root.appendingPathComponent("external-tool")
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: external)
        let escapeApp = root.appendingPathComponent("Escape.app", isDirectory: true)
        let escapeExecutable = escapeApp.appendingPathComponent("Contents/MacOS/Escape")
        try FileManager.default.createDirectory(at: escapeExecutable.deletingLastPathComponent(), withIntermediateDirectories: true)
        try writeIntakeAppInfo(at: escapeApp, executableName: "Escape")
        try FileManager.default.createSymbolicLink(at: escapeExecutable, withDestinationURL: external)
        assertRejected(escapeApp, contains: "resolves outside the selected bundle", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
    }

    @Test
    func unreadableSelectionReportsPermissionErrorAndPreservesPriorScan() async throws {
        let root = try intakeFixtureRoot()
        defer { removeIntakeFixture(root) }
        let store = ScanStore()
        store.startFileAppScan(at: URL(fileURLWithPath: "/usr/bin/true"))
        try await waitForIntakeScan(store)
        #expect(store.lastError == nil)
        #expect(store.findings.count == 1)
        let priorRoots = store.scannedRoots
        let priorFindingIDs = store.findings.map(\.id)
        let priorDiscovered = store.statistics.discovered

        #expect(geteuid() != 0, "Permission-denial verification requires a non-root test process.")
        let unreadable = root.appendingPathComponent("unreadable.plist")
        try intakePropertyList().write(to: unreadable)
        try #require(chmod(unreadable.path, 0) == 0)
        defer {
            if chmod(unreadable.path, 0o600) != 0 {
                Issue.record("Restoring unreadable intake fixture permissions failed: errno \(errno).")
            }
        }
        assertRejected(unreadable, contains: "errno \(EACCES)", store: store,
            priorRoots: priorRoots, priorFindingIDs: priorFindingIDs, priorDiscovered: priorDiscovered)
    }

    private func assertRejected(_ url: URL, contains detail: String, store: ScanStore,
                                priorRoots: [URL], priorFindingIDs: [UUID], priorDiscovered: Int) {
        store.lastError = nil
        store.startFileAppScan(at: url)
        #expect(store.lastError?.contains(detail) == true)
        #expect(store.scannedRoots == priorRoots)
        #expect(store.findings.map(\.id) == priorFindingIDs)
        #expect(store.statistics.discovered == priorDiscovered)
        #expect(!store.isScanning)
    }

    private func waitForIntakeScan(_ store: ScanStore) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while store.isScanning || store.isFiltering {
            guard ContinuousClock.now < deadline else { throw IntakePresentationTimeout.didNotSettle }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}

private func isWithinIntakeRoot(_ path: String, root: URL) -> Bool {
    let selected = root.resolvingSymlinksInPath().standardizedFileURL.path
    let observed = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL.path
    return observed == selected || observed.hasPrefix(selected + "/")
}

private enum IntakePresentationTimeout: Error {
    case didNotSettle
}

private func intakeFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-file-intake-\(UUID())", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeIntakeFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("File-intake fixture cleanup failed: \(error.localizedDescription)") }
}

private func intakePropertyList() throws -> Data {
    try PropertyListSerialization.data(fromPropertyList: ["com.apple.security.example": true], format: .xml, options: 0)
}

private func writeIntakeAppInfo(at bundle: URL, executableName: String) throws {
    try intakeBundleInfo(executableName: executableName, packageType: "APPL")
        .write(to: bundle.appendingPathComponent("Contents/Info.plist"))
}

private func intakeBundleInfo(executableName: String, packageType: String) throws -> Data {
    let info = [
        "CFBundleIdentifier": "io.hideouts.EntitlementLens.FileIntakeFixture",
        "CFBundleExecutable": executableName,
        "CFBundlePackageType": packageType,
        "CFBundleVersion": "1"
    ]
    return try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
}
