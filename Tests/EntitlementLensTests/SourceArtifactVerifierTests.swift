import CryptoKit
import Darwin
import Foundation
import Testing
@testable import EntitlementLens

struct SourceArtifactVerifierTests {
    @Test
    func verifiesExactAndChangedBytesWithoutModifyingCandidateOrArtifact() throws {
        let fixture = try sourceArtifactFixture()
        defer { removeSourceArtifactFixture(fixture.root) }
        let candidateBytes = try Data(contentsOf: fixture.candidateURL)
        let candidateDate = try fixture.candidateURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
        let original = try Data(contentsOf: fixture.sourceURL)
        let originalDate = try fixture.sourceURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
        #expect(fixture.candidate.metadata.artifactSHA256 == sourceArtifactDigest(original))
        let matched = try SourceArtifactVerifier.verify(at: fixture.sourceURL, candidate: fixture.candidate)
        #expect(matched.matchesRecordedDigest)
        #expect(matched.observedSHA256 == sourceArtifactDigest(original))
        #expect(matched.bytes == original.count)
        #expect(try Data(contentsOf: fixture.sourceURL) == original)
        #expect(try fixture.sourceURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate == originalDate)

        var changed = original
        changed[changed.startIndex] ^= 1
        try changed.write(to: fixture.sourceURL)
        let changedDate = try fixture.sourceURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
        let mismatched = try SourceArtifactVerifier.verify(at: fixture.sourceURL, candidate: fixture.candidate)
        #expect(!mismatched.matchesRecordedDigest)
        #expect(mismatched.observedSHA256 == sourceArtifactDigest(changed))
        #expect(mismatched.bytes == original.count)
        #expect(try Data(contentsOf: fixture.sourceURL) == changed)
        #expect(try fixture.sourceURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate == changedDate)
        #expect(try Data(contentsOf: fixture.candidateURL) == candidateBytes)
        #expect(try fixture.candidateURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate == candidateDate)
        #expect(fixture.candidate.data == candidateBytes)
    }

    @Test
    func rejectsCandidatePathAndHardLinkAlias() throws {
        let fixture = try sourceArtifactFixture()
        defer { removeSourceArtifactFixture(fixture.root) }
        let alias = fixture.root.appendingPathComponent("candidate-hard-link.json")
        try FileManager.default.linkItem(at: fixture.candidateURL, to: alias)
        for url in [fixture.candidateURL, alias] {
            do {
                _ = try SourceArtifactVerifier.verify(at: url, candidate: fixture.candidate)
                Issue.record("The saved candidate was accepted as its own source artifact.")
            } catch SourceArtifactVerificationError.candidateSelected { }
        }
        let snapshot = try StaticResearchFileReader.sourceSnapshot(at: alias,
            maximumBytes: SavedResearchCandidateLoader.maximumBytes)
        #expect(snapshot.identity == fixture.candidate.fileIdentity)
        #expect(snapshot.data == fixture.candidate.data)
    }

    @Test
    func rejectsSymlinkFIFODirectoryMissingRemoteAndOversizedSources() throws {
        let fixture = try sourceArtifactFixture()
        defer { removeSourceArtifactFixture(fixture.root) }
        let symlink = fixture.root.appendingPathComponent("source-link")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: fixture.sourceURL)
        let fifo = fixture.root.appendingPathComponent("source-fifo")
        #expect(mkfifo(fifo.path, 0o600) == 0)
        let oversized = fixture.root.appendingPathComponent("oversized-source")
        try Data().write(to: oversized)
        let handle = try FileHandle(forWritingTo: oversized)
        try handle.truncate(atOffset: UInt64(StaticResearchFileReader.maximumSourceBytes + 1))
        try handle.close()
        let missing = fixture.root.appendingPathComponent("missing-source")
        let remote = try #require(URL(string: "https://example.invalid/source"))
        for url in [symlink, fifo, fixture.root, missing, remote] {
            #expect(throws: StaticResearchFileError.self) {
                _ = try SourceArtifactVerifier.verify(at: url, candidate: fixture.candidate)
            }
        }
        do {
            _ = try SourceArtifactVerifier.verify(at: oversized, candidate: fixture.candidate)
            Issue.record("An oversized source artifact was accepted.")
        } catch StaticResearchFileError.limitExceeded(_, let maximumBytes) {
            #expect(maximumBytes == StaticResearchFileReader.maximumSourceBytes)
        }
    }

    @Test
    func rejectsUnreadableSourceRatherThanReportingDigestMismatch() throws {
        let fixture = try sourceArtifactFixture()
        defer { removeSourceArtifactFixture(fixture.root) }
        #expect(geteuid() != 0, "Permission-denial verification requires a non-root test process.")
        #expect(chmod(fixture.sourceURL.path, 0) == 0)
        defer {
            if chmod(fixture.sourceURL.path, 0o600) != 0 {
                Issue.record("Restoring source fixture permissions failed: errno \(errno).")
            }
        }
        do {
            _ = try SourceArtifactVerifier.verify(at: fixture.sourceURL, candidate: fixture.candidate)
            Issue.record("An unreadable source artifact was accepted.")
        } catch StaticResearchFileError.filesystem(let operation, _, let code) {
            #expect(operation == "open")
            #expect(code == EACCES)
        }
    }

    @Test
    func cancellationDoesNotProduceACompletedVerification() async throws {
        let fixture = try sourceArtifactFixture()
        defer { removeSourceArtifactFixture(fixture.root) }
        let operation = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try SourceArtifactVerifier.verify(at: fixture.sourceURL, candidate: fixture.candidate)
        }
        do {
            _ = try await operation.value
            Issue.record("Cancelled source verification unexpectedly completed.")
        } catch is CancellationError { }
    }
}

private struct SourceArtifactFixture {
    let root: URL
    let sourceURL: URL
    let candidateURL: URL
    let candidate: SavedResearchCandidate
}

private func sourceArtifactFixture() throws -> SourceArtifactFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-source-artifact-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    let source = root.appendingPathComponent("controlled-source")
    let bytes = Data("Controlled source artifact bytes".utf8)
    try bytes.write(to: source)
    let candidateURL = root.appendingPathComponent("candidate.json")
    let candidate = Data("""
    {"schema_version":1,"case_id":"source-artifact-fixture","sample_kind":"controlled_fixture","source_reference":"Controlled source verification fixture","artifact_label":"controlled-source","artifact_sha256":"\(sourceArtifactDigest(bytes))","collector":{"name":"EntitlementLens","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","feature_schema_version":3,"collected_at_utc":"2026-10-23T10:00:00Z","host_macos_version":"27.2","host_macos_build":"26B5112a"},"signature_integrity":"unsigned","entitlement_collection_state":"complete","architectures":[{"name":"arm64","collection_state":"complete","signature_integrity":"unsigned","declarations":[]}],"evidence_scope":"static_signed_declarations","runtime_authorization":"not_assessed"}
    """.utf8)
    try candidate.write(to: candidateURL)
    return SourceArtifactFixture(root: root, sourceURL: source, candidateURL: candidateURL,
        candidate: try SavedResearchCandidateLoader.load(at: candidateURL))
}

private func sourceArtifactDigest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func removeSourceArtifactFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Source artifact fixture cleanup failed: \(error.localizedDescription)") }
}
