import CryptoKit
import Foundation

struct SourceArtifactVerification: Sendable {
    let observedSHA256: String
    let bytes: Int
    let matchesRecordedDigest: Bool
}

enum SourceArtifactVerificationError: LocalizedError {
    case candidateSelected

    var errorDescription: String? {
        switch self {
        case .candidateSelected:
            "The selected file is the saved candidate JSON or a hard-link alias of it. Choose the original source artifact whose digest the candidate records."
        }
    }
}

/// Compares one explicitly selected immutable artifact snapshot; it never inspects paths retained in JSON.
/// A matching digest establishes byte identity only, not origin, signature validity, or runtime authorization.
enum SourceArtifactVerifier {
    static func verify(at url: URL, candidate: SavedResearchCandidate) throws -> SourceArtifactVerification {
        try Task.checkCancellation()
        guard !url.isFileURL || url.standardizedFileURL != candidate.sourceURL else {
            throw SourceArtifactVerificationError.candidateSelected
        }
        let snapshot = try StaticResearchFileReader.sourceSnapshot(
            at: url, maximumBytes: StaticResearchFileReader.maximumSourceBytes
        )
        guard snapshot.identity != candidate.fileIdentity else {
            throw SourceArtifactVerificationError.candidateSelected
        }
        try Task.checkCancellation()
        let digest = SHA256.hash(data: snapshot.data).map { String(format: "%02x", $0) }.joined()
        try Task.checkCancellation()
        return SourceArtifactVerification(observedSHA256: digest, bytes: snapshot.data.count,
            matchesRecordedDigest: digest == candidate.metadata.artifactSHA256)
    }
}
