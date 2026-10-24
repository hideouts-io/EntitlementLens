import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct ResearchSubmissionView: View {
    @Bindable var store: ScanStore
    @Environment(\.dismiss) private var dismiss

    @State private var selectedFindingID: UUID?
    @State private var caseID = ""
    @State private var sampleKind: ResearchCaseSampleKind?
    @State private var sourceReference = ""
    @State private var artifactLabel = ""
    @State private var previewData: Data?
    @State private var previewText = ""
    @State private var previewError: String?
    @State private var savedPath: String?
    @State private var isSaving = false

    init(store: ScanStore) {
        self.store = store
        _selectedFindingID = State(initialValue: store.findings.first {
            store.researchSelectedFindingIDs.contains($0.id)
        }?.id)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    introduction
                    if let previewData {
                        preview(previewData)
                    } else {
                        form
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
            }
            .navigationTitle("Prepare Research Submission")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier("research.done")
                }
            }
        }
        .frame(minWidth: 720, minHeight: 580)
        .onChange(of: selectedFindingID) { _, _ in
            resetForNextFinding()
        }
    }

    private var selectedFindings: [ScanFinding] {
        store.findings.filter { store.researchSelectedFindingIDs.contains($0.id) }
    }

    private var selectedFinding: ScanFinding? {
        selectedFindings.first { $0.id == selectedFindingID }
    }

    private var collectorSourceCommit: String? {
        selectedFinding?.staticFeatures?.context.collectorBuild?.exactSourceCommit
    }

    private var collectorBuildState: CollectorBuildState {
        if collectorSourceCommit != nil { return .clean }
        return selectedFinding?.staticFeatures?.context.collectorBuild?.state == .dirty ? .dirty : .unknown
    }

    private var provenanceError: String {
        switch collectorBuildState {
        case .dirty:
            "This finding was collected by a build with uncommitted source changes. Build from a clean committed checkout, then run a new scan before preparing a candidate."
        case .unknown, .clean:
            "This finding has no exact collector build revision. Use an app packaged from a clean committed checkout, then run a new scan before preparing a candidate."
        }
    }

    private var introduction: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Create one local case for one explicitly checked result. If you checked several, prepare and review each case separately.")
                .font(.callout)
            Text("Public case schema v1 contains static signed declarations and collection state. It cannot carry a full scan, carved content, or every feature family. The app rejects a finding when omitting its evidence would make the case misleading.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if store.scanWasCancelled {
                Label("This scan was stopped. Its retained results are partial; start a completed focused scan before preparing a case.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("research.scan-partial")
            } else if !store.issues.isEmpty {
                Label("This scan has \(store.issues.count) skipped or limited items. Review coverage alongside any candidate.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("research.scan-issues")
            }
            if let contributionURL = URL(string: "https://github.com/hideouts-io/EntitlementLens-Research/blob/main/CONTRIBUTING.md") {
                Link("Read the public dataset contribution guide", destination: contributionURL)
                    .accessibilityIdentifier("research.contribution-guide")
            }
            Text("Saving here does not upload, commit, or publish. Review the exact JSON and make a separate human-reviewed Git change when ready.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 12) {
            if selectedFindings.count > 1 {
                Picker("Selected finding", selection: $selectedFindingID) {
                    ForEach(selectedFindings) { finding in
                        Text(finding.path).tag(finding.id as UUID?)
                    }
                }
                .accessibilityIdentifier("research.finding")
            } else if let selectedFinding {
                LabeledContent("Selected finding", value: selectedFinding.path)
            }

            TextField("Case ID", text: $caseID, prompt: Text("lowercase-words-with-hyphens"))
                .accessibilityIdentifier("research.case-id")
            Picker("Sample source", selection: $sampleKind) {
                Text("Choose source type").tag(nil as ResearchCaseSampleKind?)
                Text("Controlled fixture").tag(ResearchCaseSampleKind.controlledFixture as ResearchCaseSampleKind?)
                Text("System binary").tag(ResearchCaseSampleKind.systemBinary as ResearchCaseSampleKind?)
                Text("Reviewed scan").tag(ResearchCaseSampleKind.reviewedScan as ResearchCaseSampleKind?)
            }
            .accessibilityIdentifier("research.sample-kind")
            TextField("Source reference", text: $sourceReference, prompt: Text("Reviewable source or fixture reference"))
                .accessibilityIdentifier("research.source-reference")
            TextField("Artifact label", text: $artifactLabel, prompt: Text("Public label without a path or person name"))
                .accessibilityIdentifier("research.artifact-label")
            LabeledContent("Collector build") {
                Text(collectorBuildState.rawValue)
                    .accessibilityIdentifier("research.build-state")
            }
            LabeledContent("Collector source commit") {
                Text(collectorSourceCommit ?? "Unavailable")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .accessibilityIdentifier("research.source-commit")
            }
            Text("Build identity was recorded when the app was packaged and retained with this finding. It does not establish artifact origin, trust, or runtime use.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if collectorSourceCommit == nil {
                Label(provenanceError, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("research.build-provenance-error")
            }

            if let previewError {
                Label(previewError, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("research.preview-error")
            }
            Button("Preview Every Included Field") { preparePreview() }
                .buttonStyle(.borderedProminent)
                .disabled(selectedFinding == nil || store.isScanning || store.scanWasCancelled || collectorSourceCommit == nil)
                .accessibilityIdentifier("research.preview")
        }
        .frame(maxWidth: 620, alignment: .leading)
    }

    private func preview(_ data: Data) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Review every field before saving")
                .font(.headline)
            Text("Only the JSON below will be saved. Check labels and entitlement values for personal information, credentials, and sharing rights. Its SHA-256 identifies observed bytes; it does not prove origin or runtime use.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(previewText)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
                .accessibilityIdentifier("research.preview-json")
            if let savedPath {
                Label("Saved locally: \(savedPath)", systemImage: "checkmark.circle")
                    .foregroundStyle(.green)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("research.saved")
            }
            if let previewError {
                Label(previewError, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("research.save-error")
            }
            HStack {
                Button("Edit Details") {
                    previewData = nil
                    previewError = nil
                    savedPath = nil
                }
                .accessibilityIdentifier("research.edit")
                Button(isSaving ? "Saving…" : "Save Local Candidate…") {
                    saveCandidate(data)
                }
                .buttonStyle(.borderedProminent)
                .disabled(isSaving)
                .accessibilityIdentifier("research.save")
            }
        }
    }

    private func preparePreview() {
        previewError = nil
        savedPath = nil
        guard let finding = selectedFinding, let sampleKind else {
            previewError = "Choose one checked finding and its sample source."
            return
        }
        guard collectorSourceCommit != nil else {
            previewError = provenanceError
            return
        }
        let metadata = ResearchCaseCandidateMetadata(
            caseID: caseID, sampleKind: sampleKind, sourceReference: sourceReference,
            artifactLabel: artifactLabel
        )
        do {
            let candidate = try ResearchCaseCandidateProjector.project(finding: finding, metadata: metadata)
            let data = try ResearchCaseCandidateProjector.jsonData(for: candidate)
            guard let text = String(data: data, encoding: .utf8) else {
                previewError = "The candidate JSON could not be displayed as UTF-8. No file was saved."
                return
            }
            previewText = text
            previewData = data
        } catch {
            previewError = error.localizedDescription
        }
    }

    @MainActor
    private func saveCandidate(_ data: Data) {
        let panel = NSSavePanel()
        panel.title = "Save Local Research Candidate"
        panel.nameFieldStringValue = "\(caseID).json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        isSaving = true
        previewError = nil
        Task { @MainActor in
            defer { isSaving = false }
            do {
                try await writeExport(to: url) { data }
                savedPath = url.path
            } catch {
                previewError = "Saving the local candidate failed: \(error.localizedDescription)"
            }
        }
    }

    private func resetForNextFinding() {
        caseID = ""
        sampleKind = nil
        sourceReference = ""
        artifactLabel = ""
        previewData = nil
        previewText = ""
        previewError = nil
        savedPath = nil
    }
}
