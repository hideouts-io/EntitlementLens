import Foundation

actor ScanWorkChannel {
    private struct PendingSender {
        let url: URL
        let continuation: CheckedContinuation<Void, Never>
    }

    private let capacity: Int
    private var buffered: [URL] = []
    private var nextIndex = 0
    private var waiters: [CheckedContinuation<URL?, Never>] = []
    private var pendingSenders: [PendingSender] = []
    private var isFinished = false

    init(capacity: Int) {
        self.capacity = max(capacity, 1)
    }

    func send(_ url: URL) async {
        guard !isFinished, !Task.isCancelled else {
            return
        }
        if !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            waiter.resume(returning: url)
            return
        }
        if bufferedCount < capacity {
            buffered.append(url)
            return
        }
        await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                pendingSenders.append(PendingSender(url: url, continuation: continuation))
            }
        } onCancel: {
            // Cancellation belongs to the scan, so release every blocked producer/consumer.
            Task { await self.finish() }
        }
    }

    func finish() {
        isFinished = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending {
            waiter.resume(returning: nil)
        }
        let senders = pendingSenders
        pendingSenders.removeAll()
        for sender in senders {
            sender.continuation.resume()
        }
    }

    func next() async -> URL? {
        guard !Task.isCancelled else { return nil }
        if nextIndex < buffered.count {
            let url = buffered[nextIndex]
            nextIndex += 1
            admitPendingSender()
            if nextIndex > 2_048 {
                buffered.removeFirst(nextIndex)
                nextIndex = 0
            }
            return url
        }
        if isFinished {
            return nil
        }
        if !pendingSenders.isEmpty {
            let sender = pendingSenders.removeFirst()
            sender.continuation.resume()
            return sender.url
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                waiters.append(continuation)
            }
        } onCancel: {
            Task { await self.finish() }
        }
    }

    private var bufferedCount: Int {
        buffered.count - nextIndex
    }

    private func admitPendingSender() {
        guard !pendingSenders.isEmpty else {
            return
        }
        let sender = pendingSenders.removeFirst()
        buffered.append(sender.url)
        sender.continuation.resume()
    }
}

private enum ScanTuning {
    static func adaptiveWorkerCount(maximum: Int) -> Int {
        let processorCount = ProcessInfo.processInfo.activeProcessorCount
        let normalCount = min(maximum, max(2, processorCount - 1))
        if ProcessInfo.processInfo.isLowPowerModeEnabled {
            return max(1, normalCount / 2)
        }
        switch ProcessInfo.processInfo.thermalState {
        case .serious, .critical:
            return max(1, normalCount / 2)
        case .nominal, .fair:
            return normalCount
        @unknown default:
            return max(1, normalCount / 2)
        }
    }
}

private actor ScanUpdateBatcher {
    private let continuation: AsyncStream<ScanUpdate>.Continuation
    private var discovered = 0
    private var machO = 0
    private var bundles = 0
    private var propertyLists = 0
    private var rawFiles = 0
    private var findings: [ScanFinding] = []
    private var issues: [ScanIssue] = []

    init(continuation: AsyncStream<ScanUpdate>.Continuation) {
        self.continuation = continuation
    }

    func recordDiscovered() {
        discovered += 1
        flushIfNeeded()
    }

    func recordClassified(_ kind: FileKind) {
        switch kind {
        case .machO: machO += 1
        case .bundle: bundles += 1
        case .propertyList: propertyLists += 1
        case .other: rawFiles += 1
        }
        flushIfNeeded()
    }

    func recordFinding(_ finding: ScanFinding) {
        findings.append(finding)
        flushIfNeeded()
    }

    func recordIssue(_ issue: ScanIssue) {
        issues.append(issue)
        flushIfNeeded()
    }

    func flush() {
        guard discovered > 0 || classifiedCount > 0 || !findings.isEmpty || !issues.isEmpty else {
            return
        }
        continuation.yield(.batch(ScanUpdateBatch(
            discovered: discovered,
            machO: machO,
            bundles: bundles,
            propertyLists: propertyLists,
            rawFiles: rawFiles,
            findings: findings,
            issues: issues
        )))
        discovered = 0
        machO = 0
        bundles = 0
        propertyLists = 0
        rawFiles = 0
        findings.removeAll(keepingCapacity: true)
        issues.removeAll(keepingCapacity: true)
    }

    private var classifiedCount: Int {
        machO + bundles + propertyLists + rawFiles
    }

    private func flushIfNeeded() {
        if discovered >= 250 || classifiedCount >= 250 || findings.count >= 20 || issues.count >= 20 {
            flush()
        }
    }
}

enum ScanCoordinator {
    static func updates(configuration: ScanConfiguration) -> AsyncStream<ScanUpdate> {
        AsyncStream { continuation in
            let scanTask = Task.detached {
                let channel = ScanWorkChannel(capacity: configuration.queueCapacity)
                let batcher = ScanUpdateBatcher(continuation: continuation)
                let runningBoardCatalog = RunningBoardDecoder.loadCurrentCatalog()
                for warning in runningBoardCatalog.warnings {
                    await batcher.recordIssue(AccessIssueClassifier.analysisIssue(
                        path: "/System/Library/LifecyclePolicy/DomainAttributes",
                        operation: .analyzeFile,
                        message: warning
                    ))
                }
                await withTaskGroup(of: Void.self) { group in
                    group.addTask {
                        await DirectoryEnumerator.enumerate(configuration: configuration) { event in
                            guard !Task.isCancelled else {
                                return
                            }
                            switch event {
                            case let .url(url):
                                await batcher.recordDiscovered()
                                await channel.send(url)
                            case let .issue(issue):
                                await batcher.recordIssue(issue)
                            }
                        }
                        await channel.finish()
                    }

                    let workerCount = ScanTuning.adaptiveWorkerCount(maximum: configuration.maximumWorkerCount)
                    for _ in 0..<workerCount {
                        group.addTask {
                            while !Task.isCancelled, let url = await channel.next() {
                                let classified: ClassifiedFile
                                do {
                                    guard let result = try FileClassifier.classify(url) else {
                                        continue
                                    }
                                    classified = result
                                } catch {
                                    await batcher.recordIssue(AccessIssueClassifier.classify(
                                        error: error,
                                        path: url.path,
                                        operation: .classifyFile
                                    ))
                                    continue
                                }
                                await batcher.recordClassified(classified.kind)
                                if classified.kind == .other && !configuration.deepCarve {
                                    await batcher.recordIssue(AccessIssueClassifier.skipped(
                                        path: url.path, operation: .analyzeFile,
                                        reason: "Raw-file analysis skipped because Deep carve is disabled."
                                    ))
                                    continue
                                }
                                if !configuration.deepCarve && (classified.kind == .machO || classified.kind == .bundle) {
                                    await batcher.recordIssue(AccessIssueClassifier.skipped(
                                        path: url.path, operation: .analyzeFile,
                                        reason: "Supporting raw-evidence carving skipped because Deep carve is disabled; code-signature inspection still runs."
                                    ))
                                }
                                do {
                                    if let finding = try analyze(
                                        classified,
                                        configuration: configuration,
                                        runningBoardCatalog: runningBoardCatalog
                                    ) {
                                        await batcher.recordFinding(finding)
                                    }
                                } catch is CancellationError {
                                    return
                                } catch {
                                    await batcher.recordIssue(AccessIssueClassifier.classify(
                                        error: error,
                                        path: url.path,
                                        operation: .analyzeFile
                                    ))
                                }
                            }
                        }
                    }
                    await group.waitForAll()
                }
                await batcher.flush()
                continuation.yield(Task.isCancelled ? .cancelled : .completed)
                continuation.finish()
            }
            continuation.onTermination = { _ in
                scanTask.cancel()
            }
        }
    }

    private static func analyze(
        _ file: ClassifiedFile,
        configuration: ScanConfiguration,
        runningBoardCatalog: RunningBoardCatalog
    ) throws -> ScanFinding? {
        switch file.kind {
        case .machO, .bundle:
            let signing = EntitlementExtractor.inspect(file.url)
            let carveURL = signing.mainExecutable.map(URL.init(fileURLWithPath:)) ?? file.url
            let provenance = try ArtifactProvenanceCollector.collectCode(
                sourceURL: file.url,
                analyzedURL: carveURL
            )
            let rawScan = configuration.deepCarve
                ? try RawEvidenceScanner.inspect(
                    carveURL,
                    kind: .machO,
                    maximumBytes: configuration.maximumCarveBytes
                )
                : RawEvidenceScan(objects: [], warnings: [])
            let extractionWarnings = signing.extractionWarnings
            let comparisonResult = installedCounterpartComparison(
                sourceURL: file.url,
                provenance: provenance,
                signing: signing
            )
            return ScanFinding(
                id: UUID(),
                path: file.url.path,
                kind: file.kind,
                fileFormat: file.format,
                fileSize: file.fileSize,
                signing: signing,
                provenance: provenance,
                installedCounterpart: comparisonResult.comparison,
                runningBoardPolicies: [],
                embeddedObjects: rawScan.objects,
                warnings: extractionWarnings + rawScan.warnings + comparisonResult.warnings
            )
        case .propertyList:
            let rawScan = try RawEvidenceScanner.inspect(
                file.url,
                kind: .propertyList,
                maximumBytes: configuration.maximumCarveBytes
            )
            let provenance = try ArtifactProvenanceCollector.collectFile(file.url)
            let runningBoardPolicies = try RunningBoardDecoder.inspect(
                file.url,
                sourceFileHash: provenance.sha256,
                sourceOSBuild: provenance.sourceOperatingSystem?.buildVersion ?? "unknown",
                catalog: runningBoardCatalog
            )
            return ScanFinding(
                id: UUID(),
                path: file.url.path,
                kind: file.kind,
                fileFormat: file.format,
                fileSize: file.fileSize,
                signing: nil,
                provenance: provenance,
                installedCounterpart: nil,
                runningBoardPolicies: runningBoardPolicies,
                embeddedObjects: rawScan.objects,
                warnings: rawScan.warnings
            )
        case .other:
            guard configuration.deepCarve else {
                return nil
            }
            let rawScan = try RawEvidenceScanner.inspect(
                file.url,
                kind: .other,
                maximumBytes: configuration.maximumCarveBytes
            )
            let provenance = try ArtifactProvenanceCollector.collectFile(file.url)
            return ScanFinding(
                id: UUID(),
                path: file.url.path,
                kind: file.kind,
                fileFormat: file.format,
                fileSize: file.fileSize,
                signing: nil,
                provenance: provenance,
                installedCounterpart: nil,
                runningBoardPolicies: [],
                embeddedObjects: rawScan.objects,
                warnings: rawScan.warnings
            )
        }
    }

    private static func installedCounterpartComparison(
        sourceURL: URL,
        provenance: ArtifactProvenance,
        signing: SigningDetails
    ) -> (comparison: InstalledCounterpartComparison?, warnings: [String]) {
        do {
            let comparison = try InstalledCounterpartComparator.compare(
                sourceURL: sourceURL,
                sourceProvenance: provenance,
                sourceSigning: signing
            )
            return (comparison, [])
        } catch {
            return (nil, ["Installed counterpart comparison failed: \(error.localizedDescription)"])
        }
    }
}
