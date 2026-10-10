import Foundation
import Testing
@testable import EntitlementLens

struct SystemIntegrationTests {
    @Test
    func classifiesSystemBinaryAsMachO() throws {
        let url = URL(fileURLWithPath: "/usr/bin/ssh")
        #expect(try FileClassifier.looksLikeMachO(url))
        #expect(try FileClassifier.classify(url)?.kind == .machO)
    }

    @Test
    func readsSigningInformationFromSystemBinary() {
        let result = EntitlementExtractor.inspect(URL(fileURLWithPath: "/usr/bin/ssh"))
        #expect(result.identifier != nil)
        #expect(result.status == .valid)
    }

    @Test
    func separatesSignatureIntegrityFromExecutionPolicy() {
        let result = EntitlementExtractor.inspect(URL(fileURLWithPath: "/usr/bin/ssh"))

        #expect(result.status == .valid)
        #expect(result.executionPolicy.status == .notAssessed)
        #expect(result.uniqueCDHash != nil)
        #expect(!result.cdHashes.isEmpty)
        #expect(result.platformIdentifier != nil)
        let isNotApplicable: Bool
        if case .notApplicable = result.resourceIntegrity {
            isNotApplicable = true
        } else {
            isNotApplicable = false
        }
        #expect(isNotApplicable)
    }

    @Test
    func collectsMachOBuildAndFilesystemProvenance() throws {
        let url = URL(fileURLWithPath: "/usr/bin/ssh")
        let result = try ArtifactProvenanceCollector.collectCode(sourceURL: url, analyzedURL: url)

        #expect(result.sha256.count == 64)
        #expect(result.fileSize > 0)
        #expect(!result.machOSlices.isEmpty)
        #expect(result.machOSlices.allSatisfy { !$0.architecture.isEmpty })
        #expect(result.machOSlices.contains { $0.minimumOSVersion != nil })
        #expect(!result.hostOperatingSystem.buildVersion.isEmpty)
    }

    @Test
    func comparesExtractedSystemPathWithInstalledCounterpart() throws {
        let fileManager = FileManager.default
        let temporaryRoot = fileManager.temporaryDirectory
            .appendingPathComponent("EntitlementLensTests-\(UUID().uuidString)", isDirectory: true)
        let extractedURL = temporaryRoot.appendingPathComponent("usr/bin/ssh", isDirectory: false)
        try fileManager.createDirectory(
            at: extractedURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try fileManager.copyItem(at: URL(fileURLWithPath: "/usr/bin/ssh"), to: extractedURL)
        defer {
            do {
                try fileManager.removeItem(at: temporaryRoot)
            } catch {
                Issue.record("Could not remove integration-test fixture: \(error.localizedDescription)")
            }
        }

        let sourceSigning = EntitlementExtractor.inspect(extractedURL)
        let sourceProvenance = try ArtifactProvenanceCollector.collectCode(
            sourceURL: extractedURL,
            analyzedURL: extractedURL
        )
        let comparison = try InstalledCounterpartComparator.compare(
            sourceURL: extractedURL,
            sourceProvenance: sourceProvenance,
            sourceSigning: sourceSigning
        )

        #expect(comparison?.path == "/usr/bin/ssh")
        #expect(comparison?.relationship == .identical)
        #expect(comparison?.differences.isEmpty == true)
        let entitlements = try #require(comparison?.entitlementComparison)
        #expect(entitlements.isComplete)
        #expect(!entitlements.hasDifferences)
        #expect(entitlements.scopes.count == sourceProvenance.machOSlices.count + 1)
        #expect(entitlements.scopes.flatMap(\.entries).allSatisfy { $0.result == .unchanged })
        #expect(comparison?.entitlementKeys == distinctEntitlementKeys(entitlementSourceGroups(sourceSigning)).sorted())
    }

    @Test
    func scansSystemBinaryThroughCompletePipeline() async {
        let configuration = ScanConfiguration(
            roots: [URL(fileURLWithPath: "/usr/bin/ssh")],
            includeHidden: true,
            deepCarve: false,
            maximumWorkerCount: 2,
            queueCapacity: 8,
            maximumCarveBytes: 4 * 1_024 * 1_024,
            excludedPathPrefixes: []
        )
        var findings: [ScanFinding] = []
        var completed = false
        for await update in ScanCoordinator.updates(configuration: configuration) {
            switch update {
            case let .batch(batch):
                findings.append(contentsOf: batch.findings)
            case .completed:
                completed = true
            case .cancelled:
                Issue.record("The one-file integration scan was unexpectedly cancelled.")
            }
        }

        #expect(completed)
        #expect(findings.count == 1)
        #expect(findings.first?.signing?.status == .valid)
        #expect(findings.first?.provenance.sha256.count == 64)
        #expect(findings.first?.signing?.entitlements.contains { $0.key == "keychain-access-groups" } == true)
    }

    @Test
    func findsStringsLikeSupportingEvidenceInSystemBinary() throws {
        let result = try RawEvidenceScanner.inspect(
            URL(fileURLWithPath: "/usr/bin/ssh"),
            kind: .machO,
            maximumBytes: 4 * 1_024 * 1_024
        )
        let matches = result.objects.flatMap(\.stringMatches)
        #expect(matches.contains { $0.value.contains("keychain-access-groups") })
    }

    @Test
    func classifiesWrappedPermissionErrorsForPrivilegedRetry() {
        let underlying = NSError(domain: NSPOSIXErrorDomain, code: Int(EACCES))
        let wrapped = NSError(
            domain: NSCocoaErrorDomain,
            code: NSFileReadNoPermissionError,
            userInfo: [NSUnderlyingErrorKey: underlying]
        )
        let issue = AccessIssueClassifier.classify(
            error: wrapped,
            path: "/private/example",
            operation: .classifyFile
        )

        #expect(issue.category == .posixPermissions)
        #expect(issue.privilegedRetryEligible)
        #expect(issue.errorDomain == NSCocoaErrorDomain)
    }

    @Test
    func doesNotTreatOperationNotPermittedAsRootBypassable() {
        let error = NSError(domain: NSPOSIXErrorDomain, code: Int(EPERM))
        let issue = AccessIssueClassifier.classify(
            error: error,
            path: "/Users/example/Library/Messages",
            operation: .enumerateDirectory
        )

        #expect(issue.category == .privacyProtection)
        #expect(!issue.privilegedRetryEligible)
    }
}
