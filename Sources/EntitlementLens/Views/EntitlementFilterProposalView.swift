import SwiftUI

/// Model proposals remain drafts until the user applies validated manual filter controls.
struct EntitlementFilterProposalView: View {
    @Bindable var store: ScanStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Describe a filter", systemImage: "sparkles").font(.headline)
                Spacer()
                Button("Close") { dismiss() }
                    .accessibilityIdentifier("explorer.proposal.close")
            }
            Text("Use Show, Find, or List with one literal key, or ‘keys matching’ with a pattern. Add one typed value if needed. Extra conditions and informal key names cannot be applied.")
                .font(.callout)
            Text("Example: Show com.apple.security.get-task-allow with Boolean true.")
                .font(.caption).textSelection(.enabled)
            Text("Quote non-dotted or unusual keys as JSON, for example: Show \"keychain-access-groups\". For exact strings, use string value followed by a JSON quoted string. Empty strings and whitespace stay distinct.")
                .font(.caption).foregroundStyle(.secondary)
            TextField("Describe one supported filter", text: $store.filterRequestText, axis: .vertical)
                .lineLimit(3...5)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("explorer.proposal.request")
            HStack {
                Button("Propose Filter") { store.generateFilterProposal() }
                    .disabled(store.filterModelAvailability != .available || isGenerating)
                    .accessibilityIdentifier("explorer.proposal.generate")
                if isGenerating {
                    ProgressView().controlSize(.small)
                        .accessibilityIdentifier("explorer.proposal.progress")
                    Button("Cancel") { store.cancelFilterProposal() }
                        .accessibilityIdentifier("explorer.proposal.cancel")
                }
                Spacer()
                Button("Check Availability") { store.refreshFilterModelAvailability() }
                    .accessibilityIdentifier("explorer.proposal.availability-refresh")
            }
            Text(store.filterModelAvailability.message)
                .font(.caption).foregroundStyle(.secondary)
                .accessibilityIdentifier("explorer.proposal.availability")
            proposalContent
            Text("Only your request and the supported filter vocabulary go to the on-device model. Proposals may differ between requests; matching the accepted typed filter is deterministic. Inspection evidence and exports stay independent.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(20)
        .frame(width: 590)
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("explorer.proposal.panel")
        .onAppear { store.refreshFilterModelAvailability() }
        .onDisappear { store.discardFilterProposal() }
    }

    private var isGenerating: Bool {
        if case .generating = store.filterProposalState { return true }
        return false
    }

    @ViewBuilder
    private var proposalContent: some View {
        switch store.filterProposalState {
        case .idle: EmptyView()
        case .generating:
            Text("Preparing an Apple Intelligence proposal…").font(.caption)
        case let .preview(proposal):
            EntitlementFilterProposalEditor(proposal: proposal, store: store, dismiss: dismiss)
                .id(proposal)
        case .ambiguous:
            proposalNotice("Apple Intelligence returned an ambiguous response. Your active filter is unchanged. Review the literal key and value type, or use the manual filter controls.")
        case .unsupported:
            proposalNotice("The request cannot be expressed as one supported filter. No filter controls were changed.")
        case .cancelled:
            proposalNotice("Proposal generation was cancelled. Your active filter is unchanged.")
        case let .failed(failure):
            proposalNotice(failure.localizedDescription)
        }
    }

    private func proposalNotice(_ message: String) -> some View {
        Label(message, systemImage: "info.circle")
            .font(.callout).textSelection(.enabled)
            .accessibilityIdentifier("explorer.proposal.status")
    }
}

private struct EntitlementFilterProposalEditor: View {
    let proposal: EntitlementFilterProposal
    @Bindable var store: ScanStore
    let dismiss: DismissAction
    @State private var keyPattern: String
    @State private var keyMode: EntitlementKeyMatchMode
    @State private var valueMode: EntitlementValueMatchMode
    @State private var valueText: String
    @State private var validationMessage: String?

    init(proposal: EntitlementFilterProposal, store: ScanStore, dismiss: DismissAction) {
        self.proposal = proposal
        self.store = store
        self.dismiss = dismiss
        _keyPattern = State(initialValue: proposal.keyPattern)
        _keyMode = State(initialValue: proposal.keyMode)
        _valueMode = State(initialValue: proposal.valueMode)
        _valueText = State(initialValue: proposal.valueText)
        _validationMessage = State(initialValue: nil)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Divider()
            Text("Apple Intelligence proposal").font(.headline)
            Text("Review or edit the exact controls below. Apply changes only this filter; it makes no capability or safety judgment.")
                .font(.caption).foregroundStyle(.secondary)
            TextField("Key or pattern", text: $keyPattern)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("explorer.proposal.draft-key")
            Picker("Key match", selection: $keyMode) {
                ForEach(EntitlementKeyMatchMode.allCases) { mode in
                    Text(mode.title).tag(mode)
                        .accessibilityIdentifier("explorer.proposal.draft-key-mode.\(mode.rawValue)")
                }
            }
            .accessibilityIdentifier("explorer.proposal.draft-key-mode")
            Picker("Value type", selection: $valueMode) {
                ForEach(EntitlementValueMatchMode.allCases) { mode in
                    Text(mode.title).tag(mode)
                        .accessibilityIdentifier("explorer.proposal.draft-value-mode.\(mode.rawValue)")
                }
            }
            .accessibilityIdentifier("explorer.proposal.draft-value-mode")
            switch valueMode {
            case .stringEquals, .integerEquals, .realEquals:
                TextField("Exact value", text: $valueText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("explorer.proposal.draft-value")
                Text("Exact value: \(String(reflecting: valueText))")
                    .font(.caption.monospaced()).lineLimit(3).textSelection(.enabled)
                    .help(String(reflecting: valueText))
                    .accessibilityIdentifier("explorer.proposal.exact-value")
            case .any, .booleanTrue, .booleanFalse: EmptyView()
            }
            if let validationMessage {
                Text(validationMessage).font(.caption).foregroundStyle(.red)
                    .accessibilityIdentifier("explorer.proposal.draft-error")
            }
            HStack {
                Button("Apply") { applyDraft() }
                    .accessibilityIdentifier("explorer.proposal.apply")
                Button("Discard") { store.discardFilterProposal() }
                    .accessibilityIdentifier("explorer.proposal.discard")
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("explorer.proposal.preview")
    }

    private func applyDraft() {
        let text: String
        switch valueMode {
        case .any, .booleanTrue, .booleanFalse: text = ""
        case .stringEquals, .integerEquals, .realEquals: text = valueText
        }
        let draft = EntitlementFilterProposal(keyPattern: keyPattern, keyMode: keyMode,
            valueMode: valueMode, valueText: text)
        do {
            try store.applyFilterProposal(draft)
            dismiss()
        } catch {
            validationMessage = error.localizedDescription
        }
    }
}
