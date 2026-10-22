import Foundation
import Testing
@testable import EntitlementLens

struct SavedResearchCandidateLoaderTests {
    @Test
    func rejectsOversizedNonregularSymlinkAndInvalidUTF8Inputs() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-saved-candidate-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Saved candidate fixture cleanup failed: \(error.localizedDescription)") }
        }

        let oversized = root.appendingPathComponent("oversized.json")
        try Data(count: SavedResearchCandidateLoader.maximumBytes + 1).write(to: oversized)
        do {
            _ = try SavedResearchCandidateLoader.load(at: oversized)
            Issue.record("An oversized candidate was accepted.")
        } catch StaticResearchFileError.limitExceeded(_, let maximumBytes) {
            #expect(maximumBytes == SavedResearchCandidateLoader.maximumBytes)
        }

        #expect(throws: StaticResearchFileError.self) {
            _ = try SavedResearchCandidateLoader.load(at: root)
        }
        let invalidUTF8 = root.appendingPathComponent("invalid-utf8.json")
        try Data([0x7B, 0xFF, 0x7D]).write(to: invalidUTF8)
        #expect(throws: SavedResearchCandidateError.self) {
            _ = try SavedResearchCandidateLoader.load(at: invalidUTF8)
        }
        let symlink = root.appendingPathComponent("symlink.json")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: invalidUTF8)
        #expect(throws: StaticResearchFileError.self) {
            _ = try SavedResearchCandidateLoader.load(at: symlink)
        }
    }
}
