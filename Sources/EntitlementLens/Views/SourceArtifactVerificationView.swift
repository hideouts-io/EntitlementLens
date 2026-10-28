import AppKit
import SwiftUI

private struct SourceArtifactSelection: Identifiable, Sendable {
    let id: UUID
    let url: URL
}

private enum SourceArtifactReviewState {
    case unverified
    case verifying
    case verified(SourceArtifactVerification, filename: String)
    case failed(String, filename: String)

    var code: String {
        switch self {
        case .unverified: "unverified"
        case .verifying: "verifying"
        case let .verified(result, _): result.matchesRecordedDigest ? "matched" : "mismatch"
        case .failed: "unavailable"
        }
    }

    var message: String {
        switch self {
        case .unverified: "Source artifact has not been verified."
        case .verifying: "Reading the selected source artifact…"
        case let .verified(result, _):
            result.matchesRecordedDigest
                ? "Source bytes match the candidate’s recorded artifact SHA-256."
                : "Source bytes do not match the candidate’s recorded artifact SHA-256."
        case .failed: "Source artifact verification is unavailable."
        }
    }
}

/// Compares only the explicitly selected local file, retaining the candidate's original bytes.
struct SourceArtifactVerificationView: View {
    let candidate: SavedResearchCandidate
    @State private var selection: SourceArtifactSelection?
    @State private var state: SourceArtifactReviewState = .unverified

    var body: some View {
        GroupBox("Source Artifact") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Select the original artifact, up to 64 MiB. Verification only reads its bytes; it does not execute the file or change the candidate or artifact.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                LabeledContent("Recorded artifact SHA-256") {
                    digest(candidate.metadata.artifactSHA256)
                        .accessibilityIdentifier("research.source-expected-sha256")
                }
                Button("Verify Source Artifact…", action: chooseSource)
                    .accessibilityIdentifier("research.verify-source")
                Text(state.message)
                    .accessibilityIdentifier("research.source-status")
                    .accessibilityValue(state.code)
                switch state {
                case .unverified:
                    EmptyView()
                case .verifying:
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityIdentifier("research.source-progress")
                case let .verified(result, filename):
                    selectedFile(filename)
                    LabeledContent("Observed source SHA-256") {
                        digest(result.observedSHA256)
                            .accessibilityIdentifier("research.source-observed-sha256")
                    }
                    LabeledContent("Source bytes") {
                        Text(String(result.bytes))
                            .accessibilityIdentifier("research.source-byte-count")
                    }
                case let .failed(message, filename):
                    selectedFile(filename)
                    Label(message, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("research.source-error")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
        .task(id: selection?.id) {
            if let selection { await verify(selection) }
        }
    }

    private func digest(_ value: String) -> some View {
        Text(value)
            .font(.system(.caption, design: .monospaced))
            .textSelection(.enabled)
    }

    private func selectedFile(_ filename: String) -> some View {
        LabeledContent("Selected source") {
            Text(filename)
                .textSelection(.enabled)
                .accessibilityIdentifier("research.source-filename")
        }
    }

    @MainActor
    private func chooseSource() {
        // Invalidate the prior request before the modal picker can deliver nested events.
        selection = nil
        state = .unverified
        let panel = NSOpenPanel()
        panel.title = "Verify Source Artifact"
        panel.prompt = "Verify Artifact"
        panel.message = "Choose the original local source artifact, up to 64 MiB. The file will only be read to compare its SHA-256."
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.resolvesAliases = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        state = .verifying
        selection = SourceArtifactSelection(id: UUID(), url: url)
    }

    @MainActor
    private func verify(_ request: SourceArtifactSelection) async {
        let candidate = candidate
        let worker = Task.detached(priority: .userInitiated) {
            try SourceArtifactVerifier.verify(at: request.url, candidate: candidate)
        }
        do {
            let result = try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                worker.cancel()
            }
            try Task.checkCancellation()
            guard selection?.id == request.id else { return }
            state = .verified(result, filename: request.url.lastPathComponent)
        } catch is CancellationError {
            // Dismissal or a new selection cancels this file read.
        } catch {
            guard !Task.isCancelled, selection?.id == request.id else { return }
            state = .failed("Verifying the source artifact failed: \(error.localizedDescription)", filename: request.url.lastPathComponent)
        }
    }
}
