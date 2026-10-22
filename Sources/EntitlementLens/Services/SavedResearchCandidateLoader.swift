import CryptoKit
import Foundation

struct SavedResearchCandidate: Sendable {
    let data: Data
    let text: String
    let sha256: String
    let metadata: ResearchCaseReviewMetadata
}

enum SavedResearchCandidateError: LocalizedError {
    case invalidUTF8

    var errorDescription: String? {
        switch self {
        case .invalidUTF8:
            "The saved candidate is not valid UTF-8 JSON. Choose an intact case-v1 JSON file."
        }
    }
}

/// Opens one explicitly selected regular file as an immutable snapshot. Embedded paths never authorize reads.
enum SavedResearchCandidateLoader {
    static let maximumBytes = ResearchCaseSchemaValidator.maximumBytes

    static func load(at url: URL) throws -> SavedResearchCandidate {
        let data = try StaticResearchFileReader.sourceData(at: url, maximumBytes: maximumBytes)
        guard let text = String(data: data, encoding: .utf8) else {
            throw SavedResearchCandidateError.invalidUTF8
        }
        let metadata = try ResearchCaseSchemaValidator.validate(data)
        try Task.checkCancellation()
        return SavedResearchCandidate(
            data: data, text: text,
            sha256: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
            metadata: metadata
        )
    }
}
