import SwiftUI

private enum SavedCandidateReviewState {
    case opening
    case loaded(SavedResearchCandidate)
    case failed(String)
}

struct SavedCandidateReviewView: View {
    let selection: SavedCandidateSelection
    @Environment(\.dismiss) private var dismiss
    @State private var state: SavedCandidateReviewState = .opening

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text(selection.url.lastPathComponent)
                        .font(.headline)
                        .textSelection(.enabled)
                    Text("Read-only review of the selected file. Case-v1 validation checks its structure and values. You can compare a source artifact’s bytes below; origin, signature, and runtime claims are not reverified.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    switch state {
                    case .opening:
                        ProgressView("Opening saved candidate…")
                            .accessibilityIdentifier("research.review-progress")
                    case let .loaded(candidate):
                        review(candidate)
                    case let .failed(message):
                        Label(message, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                            .textSelection(.enabled)
                            .accessibilityIdentifier("research.review-error")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
            }
            .navigationTitle("Saved Candidate Review")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier("research.review-done")
                }
            }
        }
        .frame(minWidth: 720, minHeight: 580)
        .task(id: selection.id) { await openCandidate() }
    }

    private func review(_ candidate: SavedResearchCandidate) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Validated against case-v1", systemImage: "checkmark.circle")
                .foregroundStyle(.green)
                .accessibilityIdentifier("research.review-valid")
            LabeledContent("Case ID") {
                Text(candidate.metadata.caseID)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("research.review-case-id")
            }
            LabeledContent("Artifact", value: candidate.metadata.artifactLabel)
            LabeledContent("Collector source commit", value: candidate.metadata.sourceCommit)
            LabeledContent("File bytes") {
                Text(String(candidate.data.count))
                    .accessibilityIdentifier("research.review-byte-count")
            }
            LabeledContent("Candidate file SHA-256") {
                Text(candidate.sha256)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .accessibilityIdentifier("research.review-sha256")
            }
            SourceArtifactVerificationView(candidate: candidate)
            Text("Original JSON")
                .font(.headline)
            Text(candidate.text)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                .accessibilityIdentifier("research.review-json")
        }
    }

    @MainActor
    private func openCandidate() async {
        state = .opening
        let url = selection.url
        let worker = Task.detached(priority: .userInitiated) {
            try SavedResearchCandidateLoader.load(at: url)
        }
        do {
            let candidate = try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                worker.cancel()
            }
            try Task.checkCancellation()
            state = .loaded(candidate)
        } catch is CancellationError {
            // Dismissing the review cancels its file read and validation.
        } catch {
            guard !Task.isCancelled else { return }
            state = .failed("Opening the saved candidate failed: \(error.localizedDescription)")
        }
    }
}
