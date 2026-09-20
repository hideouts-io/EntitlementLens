import Foundation
import Testing
@testable import EntitlementLens

struct PresentationIntegrationTests {
    @Test
    func recognizesSuccessfullyCollectedCodeWithoutEntitlements() async throws {
        let collected = await collect(URL(fileURLWithPath: "/usr/bin/true"), deepCarve: false, exclusions: [])
        let finding = try #require(collected.findings.first)
        #expect(finding.signing?.status == .valid)
        #expect(findingOutcome(finding) == .noEntitlements)
        let index = try [indexFinding(finding)]
        #expect(try matchingFindings(index, filter: .all, query: "", includeEmpty: false).isEmpty)
        #expect(try matchingFindings(index, filter: .all, query: "", includeEmpty: true).count == 1)
    }

    @Test
    func preservesEmbeddedOffsetsAcrossRollingBufferBoundaries() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".raw")
        let markerOffset = 1_048_574
        let plist = Data("<plist version=\"1.0\"><dict><key>com.apple.security.example</key><true/></dict></plist>".utf8)
        var data = Data(repeating: 0, count: markerOffset)
        data.append(plist)
        data.append(Data(repeating: 0, count: 1_048_576))
        try data.write(to: url)
        defer { removeFixture(url) }
        let scan = try RawEvidenceScanner.inspect(url, kind: .other, maximumBytes: data.count)
        let object = try #require(scan.objects.first { $0.format == .xmlPropertyList })
        #expect(object.offset == markerOffset)
        #expect(object.length == plist.count)
        #expect(object.entitlementKeys == ["com.apple.security.example"])
    }

    @Test
    func stringCarvingKeepsDelimitedMatchesSeparate() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".raw")
        let first = "com.apple.security.first"
        let second = "com.apple.security.second"
        try Data((first + "\0ignored\0" + second + "\0").utf8).write(to: url)
        defer { removeFixture(url) }
        let scan = try RawEvidenceScanner.inspect(url, kind: .other, maximumBytes: 1_024)
        let matches = scan.objects.flatMap(\.stringMatches)
        #expect(matches.map(\.value) == [first, second])
        #expect(matches.map(\.offset) == [0, first.utf8.count + 9])
    }

    @Test
    func retainsEmptyResultsAndRecordsSkippedRawAnalysis() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".raw")
        try Data("ordinary data without matching keys".utf8).write(to: url)
        defer { removeFixture(url) }
        let collected = await collect(url, deepCarve: true, exclusions: [])
        let finding = try #require(collected.findings.first)
        let index = try [indexFinding(finding)]
        #expect(index.first?.outcome == .noData)
        #expect(try matchingFindings(index, filter: .all, query: "", includeEmpty: false).isEmpty)
        #expect(try matchingFindings(index, filter: .all, query: "", includeEmpty: true).count == 1)
        let exported = try ResultExporter.data(for: collected.findings, format: .json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: exported) == collected.findings)

        let skipped = await collect(url, deepCarve: false, exclusions: [])
        #expect(skipped.findings.isEmpty)
        #expect(skipped.issues.contains { $0.path == url.path && $0.category == .skipped })
        let excluded = await collect(url, deepCarve: true, exclusions: [url])
        #expect(excluded.issues.contains { $0.path == url.path && $0.category == .skipped })
    }

    @Test
    func largeEmbeddedEvidenceRemainsSearchableAndExportable() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".plist")
        let dictionary = Dictionary(uniqueKeysWithValues: (0..<400).map {
            ("com.apple.security.test\($0)", String(repeating: "value", count: 25))
        })
        try PropertyListSerialization.data(fromPropertyList: dictionary, format: .xml, options: 0).write(to: url)
        defer { removeFixture(url) }
        let collected = await collect(url, deepCarve: true, exclusions: [])
        let finding = try #require(collected.findings.first)
        #expect(finding.embeddedObjects.contains { $0.entitlementKeys.count == 400 })
        let index = try [indexFinding(finding)]
        #expect(try matchingFindings(index, filter: .embeddedObjects, query: "test399", includeEmpty: false).count == 1)
        let exported = try ResultExporter.data(for: collected.findings, format: .json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: exported) == collected.findings)
    }

    @Test
    func cancelledFilterDoesNotReturnStaleResults() async throws {
        let worker = Task.detached {
            withUnsafeCurrentTask { $0?.cancel() }
            return try matchingFindings([], filter: .all, query: "", includeEmpty: false)
        }
        do {
            _ = try await worker.value
            Issue.record("Cancelled filtering returned a result")
        } catch is CancellationError {
            // Cancellation must propagate to the presentation task.
        }
    }

    private func collect(_ url: URL, deepCarve: Bool, exclusions: [URL]) async -> (findings: [ScanFinding], issues: [ScanIssue]) {
        let configuration = ScanConfiguration(roots: [url], includeHidden: true, deepCarve: deepCarve,
            maximumWorkerCount: 2, queueCapacity: 8, maximumCarveBytes: 1_048_576, excludedPathPrefixes: exclusions)
        var findings: [ScanFinding] = []
        var issues: [ScanIssue] = []
        for await update in ScanCoordinator.updates(configuration: configuration) {
            if case let .batch(batch) = update {
                findings.append(contentsOf: batch.findings)
                issues.append(contentsOf: batch.issues)
            }
        }
        return (findings, issues)
    }

    private func removeFixture(_ url: URL) {
        do { try FileManager.default.removeItem(at: url) }
        catch { Issue.record("Could not remove fixture: \(error.localizedDescription)") }
    }
}
