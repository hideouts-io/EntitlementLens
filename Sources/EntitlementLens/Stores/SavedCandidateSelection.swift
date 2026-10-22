import AppKit
import Foundation
import UniformTypeIdentifiers

struct SavedCandidateSelection: Identifiable {
    let id: UUID
    let url: URL
}

extension ScanStore {
    var canOpenSavedCandidate: Bool {
        savedCandidateSelection == nil && !showsResearchSubmission && !showsIssues
    }

    func chooseSavedCandidate() {
        let panel = NSOpenPanel()
        panel.title = "Open Saved Candidate"
        panel.prompt = "Open Candidate"
        panel.message = "Choose a local case-v1 JSON file up to 8 MiB for read-only review."
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = false
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        savedCandidateSelection = SavedCandidateSelection(id: UUID(), url: url)
    }
}
