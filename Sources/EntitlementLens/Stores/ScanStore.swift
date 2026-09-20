import AppKit
import Foundation
import Observation
import OSLog
import PrivilegedProtocol
import UniformTypeIdentifiers

@MainActor
@Observable
final class ScanStore {
    var findings: [ScanFinding] = []
    var issues: [ScanIssue] = []
    var statistics = ScanStatistics()
    var selectedFindingID: UUID? {
        didSet { if selectedFindingID != oldValue { selectionStarted = .now } }
    }
    var selectedFilter: ResultFilter = .all {
        didSet { refreshVisibleFindings() }
    }
    var searchText = "" {
        didSet { scheduleSearch() }
    }
    var showsEmptyItems = false {
        didSet { refreshVisibleFindings() }
    }
    private(set) var filteredFindings: [ScanFinding] = []
    private(set) var hiddenEmptyCount = 0
    private(set) var isFiltering = false
    private(set) var isExporting = false
    var includeHidden = true
    var deepCarve = false
    var excludedPathsText = "/System/Volumes/VM; /System/Volumes/Preboot; /System/Volumes/Update"
    var isScanning = false
    private(set) var scanWasCancelled = false
    var scannedRoots: [URL] = []
    var lastError: String?
    var showsIssues = false
    var privilegedHelperState = PrivilegedHelperController.state()
    var privilegedRecords: [PrivilegedInspectionRecord] = []
    var isRunningPrivilegedRetry = false

    @ObservationIgnored
    private var scanTask: Task<Void, Never>?
    @ObservationIgnored
    private var findingByID: [UUID: ScanFinding] = [:]
    @ObservationIgnored
    private var presentationIndex: [IndexedFinding] = []
    @ObservationIgnored
    private var outcomeByID: [UUID: FindingOutcome] = [:]
    @ObservationIgnored
    private var filterTask: Task<Void, Never>?
    @ObservationIgnored
    private var searchTask: Task<Void, Never>?
    @ObservationIgnored
    private var filterRequest = UUID()
    @ObservationIgnored
    private var scanID = UUID()
    @ObservationIgnored
    private var selectionStarted = ContinuousClock.now
    @ObservationIgnored
    private let logger = Logger(subsystem: "io.hideouts.EntitlementLens", category: "DetailPerformance")
    private var filterCounts: [ResultFilter: Int] = [:]

    var selectedFinding: ScanFinding? {
        guard let selectedFindingID else {
            return filteredFindings.first
        }
        return findingByID[selectedFindingID]
    }

    func finding(id: UUID) -> ScanFinding? {
        findingByID[id]
    }

    func count(for filter: ResultFilter) -> Int {
        filterCounts[filter] ?? 0
    }

    func outcome(for finding: ScanFinding) -> FindingOutcome {
        outcomeByID[finding.id] ?? findingOutcome(finding)
    }

    func detailAppeared(id: UUID) {
        guard id == selectedFindingID else { return }
        let elapsed = selectionStarted.duration(to: .now)
        let milliseconds = Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds) / 1e15
        logger.info("event=result_detail_appeared elapsed_ms=\(milliseconds)")
    }

    private func refreshVisibleFindings() {
        searchTask?.cancel()
        filterTask?.cancel()
        let request = UUID()
        filterRequest = request
        let index = presentationIndex
        let filter = selectedFilter
        let query = searchText
        let includeEmpty = showsEmptyItems
        isFiltering = true
        filterTask = Task {
            let worker = Task.detached(priority: .userInitiated) {
                return try matchingFindings(index, filter: filter, query: query, includeEmpty: includeEmpty)
            }
            do {
                let result = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                guard filterRequest == request else { return }
                filteredFindings = result
                if !result.contains(where: { $0.id == selectedFindingID }) {
                    selectedFindingID = result.first?.id
                }
                isFiltering = false
            } catch is CancellationError {
                // A newer search/filter or scan owns the presentation now.
            } catch {
                guard filterRequest == request else { return }
                isFiltering = false
                lastError = "Result filtering failed: \(error.localizedDescription)"
            }
        }
    }

    private func scheduleSearch() {
        searchTask?.cancel()
        filterTask?.cancel()
        filterRequest = UUID()
        isFiltering = true
        searchTask = Task {
            do {
                try await Task.sleep(for: .milliseconds(120))
                refreshVisibleFindings()
            } catch is CancellationError {
                // New input supersedes this debounce interval.
            } catch {
                isFiltering = false
                lastError = "Search scheduling failed: \(error.localizedDescription)"
            }
        }
    }

    func chooseFolderAndScan() {
        let panel = NSOpenPanel()
        panel.title = "Choose a folder to inspect"
        panel.prompt = "Scan Folder"
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = false
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        startScan(roots: [url])
    }

    func scanApplications() {
        startScan(roots: existingURLs([
            "/Applications",
            "/System/Applications"
        ]))
    }

    func scanSystem() {
        startScan(roots: existingURLs([
            "/System/Library/CoreServices",
            "/System/Library/Frameworks",
            "/System/Library/PrivateFrameworks",
            "/usr/bin",
            "/usr/libexec",
            "/bin",
            "/sbin"
        ]))
    }

    func scanEntireMac() {
        startScan(roots: existingURLs([
            "/Applications",
            "/System/Applications",
            "/System/Library/CoreServices",
            "/System/Library/Frameworks",
            "/System/Library/PrivateFrameworks",
            "/Library",
            "/usr/bin",
            "/usr/libexec",
            "/usr/lib",
            "/bin",
            "/sbin",
            "/private",
            "/Users"
        ]))
    }

    func cancelScan() {
        guard isScanning else { return }
        scanWasCancelled = true
        scanTask?.cancel()
        scanTask = nil
        isScanning = false
    }

    func exportResults(format: ExportFormat) {
        guard !isExporting else { return }
        let panel = NSSavePanel()
        panel.title = "Export Scan Results"
        panel.nameFieldStringValue = "EntitlementLens-results.\(format.fileExtension)"
        if format == .json {
            panel.allowedContentTypes = [.json]
        } else {
            panel.allowedContentTypes = [.commaSeparatedText]
        }
        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        let snapshot = findings
        isExporting = true
        Task {
            defer { isExporting = false }
            do {
                try await writeExport(to: url) {
                    try ResultExporter.data(for: snapshot, format: format)
                }
            } catch {
                lastError = "Export to \(url.path) failed: \(error.localizedDescription)"
            }
        }
    }

    func exportCoverage() {
        guard !isExporting else { return }
        let panel = NSSavePanel()
        panel.title = "Export Skipped Items and Collection Limits"
        panel.nameFieldStringValue = "EntitlementLens-coverage.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let snapshot = issues
        isExporting = true
        Task {
            defer { isExporting = false }
            do {
                try await writeExport(to: url) {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
                    return try encoder.encode(snapshot)
                }
            } catch {
                lastError = "Coverage export to \(url.path) failed: \(error.localizedDescription)"
            }
        }
    }

    func revealInFinder(_ finding: ScanFinding) {
        performResultAction("Reveal in Finder") {
            try ResultItemActions.revealInFinder(finding)
        }
    }

    func openInTextEdit(_ finding: ScanFinding) {
        Task { @MainActor in
            do {
                try await ResultItemActions.openInTextEdit(finding)
            } catch {
                lastError = "Open in TextEdit failed: \(error.localizedDescription)"
            }
        }
    }

    func copyPath(_ finding: ScanFinding) {
        performResultAction("Copy path") {
            try ResultItemActions.copyPath(finding)
        }
    }

    func copyAllData(_ finding: ScanFinding) {
        performResultAction("Copy all data") {
            try ResultItemActions.copyAllData(finding)
        }
    }

    func openFullDiskAccessSettings() {
        do {
            try PrivacySettingsService.openFullDiskAccess()
        } catch {
            lastError = "Open Full Disk Access failed: \(error.localizedDescription)"
        }
    }

    func enablePrivilegedHelper() {
        do {
            try PrivilegedHelperController.register()
            privilegedHelperState = PrivilegedHelperController.state()
        } catch {
            lastError = "Enable privileged helper failed: \(error.localizedDescription)"
            privilegedHelperState = PrivilegedHelperController.state()
        }
    }

    func refreshPrivilegedHelperState() {
        privilegedHelperState = PrivilegedHelperController.state()
    }

    func openLoginItemsSettings() {
        PrivilegedHelperController.openLoginItemsSettings()
    }

    func runPrivilegedRetry() {
        let eligiblePaths = issues
            .filter(\.privilegedRetryEligible)
            .map(\.path)
        guard !eligiblePaths.isEmpty else {
            lastError = PrivilegedHelperError.noEligiblePaths.localizedDescription
            return
        }
        isRunningPrivilegedRetry = true
        Task { @MainActor in
            defer { isRunningPrivilegedRetry = false }
            do {
                privilegedRecords = try await PrivilegedHelperController.inspect(paths: eligiblePaths)
            } catch {
                lastError = "Privileged retry failed: \(error.localizedDescription)"
            }
        }
    }

    func startScan(roots: [URL]) {
        guard !roots.isEmpty else {
            lastError = "No readable scan roots are available."
            return
        }
        scanTask?.cancel()
        findings = []
        findingByID = [:]
        filterTask?.cancel()
        searchTask?.cancel()
        filterRequest = UUID()
        scanID = UUID()
        let currentScanID = scanID
        presentationIndex = []
        outcomeByID = [:]
        filteredFindings = []
        hiddenEmptyCount = 0
        isFiltering = false
        filterCounts = [:]
        issues = []
        privilegedRecords = []
        statistics = ScanStatistics()
        selectedFindingID = nil
        scannedRoots = roots
        lastError = nil
        isScanning = true
        scanWasCancelled = false

        let exclusions: [URL]
        do {
            exclusions = try parsedExclusions(excludedPathsText)
        } catch {
            isScanning = false
            lastError = error.localizedDescription
            return
        }
        let configuration = ScanConfiguration(
            roots: roots,
            includeHidden: includeHidden,
            deepCarve: deepCarve,
            maximumWorkerCount: 12,
            queueCapacity: 512,
            maximumCarveBytes: 32 * 1_024 * 1_024,
            excludedPathPrefixes: exclusions
        )
        scanTask = Task {
            for await update in ScanCoordinator.updates(configuration: configuration) {
                guard !Task.isCancelled, scanID == currentScanID else { return }
                await receive(update)
            }
        }
    }

    private func receive(_ update: ScanUpdate) async {
        switch update {
        case let .batch(batch):
            let worker = Task.detached(priority: .utility) {
                try batch.findings.map(indexFinding)
            }
            let indexed: [IndexedFinding]
            do {
                indexed = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
            } catch is CancellationError {
                return
            } catch {
                lastError = "Result indexing failed: \(error.localizedDescription)"
                cancelScan()
                return
            }
            statistics.discovered += batch.discovered
            statistics.machO += batch.machO
            statistics.bundles += batch.bundles
            statistics.propertyLists += batch.propertyLists
            statistics.rawFiles += batch.rawFiles
            statistics.findings += batch.findings.count
            statistics.issues += batch.issues.count
            findings.append(contentsOf: batch.findings)
            presentationIndex.append(contentsOf: indexed)
            for item in indexed {
                let finding = item.finding
                findingByID[finding.id] = finding
                outcomeByID[finding.id] = item.outcome
                if !item.visibleByDefault { hiddenEmptyCount += 1 }
                for filter in item.filters {
                    filterCounts[filter, default: 0] += 1
                }
            }
            issues.append(contentsOf: batch.issues)
            if !indexed.isEmpty { refreshVisibleFindings() }
        case .completed:
            isScanning = false
            scanTask = nil
        case .cancelled:
            scanWasCancelled = true
            isScanning = false
            scanTask = nil
        }
    }

    private func performResultAction(_ name: String, action: () throws -> Void) {
        do {
            try action()
        } catch {
            lastError = "\(name) failed: \(error.localizedDescription)"
        }
    }

    private func parsedExclusions(_ value: String) throws -> [URL] {
        try value
            .split(whereSeparator: { $0 == ";" || $0 == "\n" })
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .map { path in
                guard path.hasPrefix("/") else {
                    throw ScanConfigurationError.nonAbsoluteExclusion(path)
                }
                return URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
            }
    }

    private func existingURLs(_ paths: [String]) -> [URL] {
        paths.compactMap { path in
            FileManager.default.fileExists(atPath: path) ? URL(fileURLWithPath: path) : nil
        }
    }
}

enum ScanConfigurationError: LocalizedError {
    case nonAbsoluteExclusion(String)

    var errorDescription: String? {
        switch self {
        case let .nonAbsoluteExclusion(path):
            "The exclusion '\(path)' is not an absolute path. Enter exclusions beginning with /."
        }
    }
}
