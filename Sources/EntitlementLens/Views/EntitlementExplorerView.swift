import SwiftUI

struct EntitlementExplorerView: View {
    @Bindable var store: ScanStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            queryControls
                .padding(.horizontal)
            coverageNotice
                .padding(.horizontal)
            if let error = store.explorerQueryError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.red)
                    .padding(.horizontal)
                    .accessibilityIdentifier("explorer.query-error")
            }
            if store.explorerGroups.isEmpty {
                ContentUnavailableView(store.isExploring ? "Preparing Declarations…" : "No Matching Declarations", systemImage: "key", description: Text(
                    store.findings.isEmpty
                        ? "Scan a folder to browse keys from signed entitlement dictionaries."
                        : "Change the key or value filter. This view covers retained signed dictionaries; skipped or unvisited items may contain other declarations."
                ))
            } else {
                VSplitView {
                    keyTable
                        .frame(minHeight: 120, idealHeight: 210)
                    declarations
                        .frame(minHeight: 180)
                }
            }
        }
        .padding(.top, 10)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .navigationTitle("By Entitlement")
    }

    private var queryControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                TextField("All entitlement keys", text: $store.explorerKeyPattern)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("explorer.key-pattern")
                Picker("Key match", selection: $store.explorerKeyMode) {
                    ForEach(EntitlementKeyMatchMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                            .accessibilityIdentifier("explorer.key-mode.\(mode.rawValue)")
                    }
                }
                .labelsHidden()
                .accessibilityIdentifier("explorer.key-mode")
            }
            HStack {
                Picker("Value", selection: $store.explorerValueMode) {
                    ForEach(EntitlementValueMatchMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                            .accessibilityIdentifier("explorer.value-mode.\(mode.rawValue)")
                    }
                }
                .accessibilityIdentifier("explorer.value-mode")
                switch store.explorerValueMode {
                case .stringEquals, .integerEquals, .realEquals:
                    TextField("Exact value", text: $store.explorerValueText)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("explorer.value-text")
                case .any, .booleanTrue, .booleanFalse: EmptyView()
                }
                Spacer(minLength: 0)
                if store.isExploring {
                    ProgressView().controlSize(.small)
                        .accessibilityIdentifier("explorer.progress")
                }
            }
            Text("Case-sensitive keys. Blank shows all; patterns use * for any characters and ? for one. Values match their exact type.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var coverageNotice: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("\(store.explorerGroups.count.formatted()) keys · \(store.findings.count.formatted()) retained records · \(store.issues.count.formatted()) coverage issues")
                .font(.caption).foregroundStyle(.secondary)
            if store.isScanning {
                Label("Scan in progress. Declarations appear as files are analyzed.", systemImage: "waveform.path.ecg")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if store.scanWasCancelled {
                Label("Scan stopped. Retained results are partial; unvisited items were not assessed.", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
                    .accessibilityIdentifier("explorer.cancelled-coverage")
            }
        }
    }

    private var keyTable: some View {
        Table(store.explorerGroups, selection: $store.selectedEntitlementKey) {
            TableColumn("Entitlement key") { group in
                Text(group.key).font(.caption.monospaced())
                    .lineLimit(1).help(group.key)
                    .accessibilityIdentifier("explorer.key.\(group.key)")
            }
            .width(min: 240, ideal: 320)
            TableColumn("Executables") { group in
                Text(group.executableCount, format: .number).monospacedDigit()
                    .accessibilityIdentifier("explorer.count.\(group.key)")
            }
            .width(85)
        }
        .accessibilityIdentifier("explorer.keys")
    }

    private var declarations: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let group = store.explorerGroups.first(where: { $0.key == store.selectedEntitlementKey }) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(group.key).font(.headline.monospaced()).textSelection(.enabled)
                    Text("\(group.executableCount.formatted()) executables · \(group.declarations.count.formatted()) source declarations · \(group.aliasCount.formatted()) paths")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("Counts use analyzed file identity and hash. Path aliases and signature sources remain separate below.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .padding(.horizontal)
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(group.declarations) { declaration in
                            declarationRow(declaration)
                        }
                    }
                    .padding(.horizontal)
                }
            } else {
                ContentUnavailableView("Select an Entitlement", systemImage: "key", description: Text("Matching executables and architecture declarations appear here."))
            }
        }
        .padding(.vertical, 10)
    }

    private func declarationRow(_ declaration: EntitlementDeclaration) -> some View {
        Button {
            store.selectedFindingID = declaration.findingID
        } label: {
            VStack(alignment: .leading, spacing: 5) {
                Text(URL(fileURLWithPath: declaration.path).lastPathComponent)
                    .font(.headline)
                Text(declaration.path).font(.caption).foregroundStyle(.secondary)
                    .lineLimit(2)
                    .help(declaration.path)
                Text(declaration.sourceTitle).font(.caption.weight(.semibold))
                Text("\(declaration.valueTypeTitle): \(entitlementValuePreview(declaration.value))")
                    .font(.caption.monospaced()).lineLimit(3)
                Text("Source signature: \(declaration.status.title) · \(declaration.collectionOutcome.rawValue)")
                    .font(.caption).foregroundStyle(signatureColor(declaration.status))
                if let hash = declaration.uniqueCDHash {
                    Text("CDHash \(hash)").font(.caption2.monospaced()).foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                if let team = declaration.teamIdentifier {
                    Text("Signing record team: \(team)").font(.caption).foregroundStyle(.secondary)
                }
                if !declaration.sourceWarnings.isEmpty || !declaration.collectionWarnings.isEmpty {
                    Label("Coverage notes available in details", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(10)
            .background(store.selectedFindingID == declaration.findingID ? Color.accentColor.opacity(0.1) : Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 7))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("explorer.declaration.\(declaration.findingID).\(declaration.id.sourceOrdinal).\(declaration.key)")
    }

    private func signatureColor(_ status: SignatureStatus) -> Color {
        switch status {
        case .valid: .secondary
        case .invalid: .red
        case .unsigned: .secondary
        case .unavailable: .orange
        }
    }
}

/// Previews stay bounded; selecting a declaration opens the complete, paged value in the detail column.
private func entitlementValuePreview(_ value: EntitlementValue) -> String {
    switch value {
    case let .string(text):
        let end = text.index(text.startIndex, offsetBy: 120, limitedBy: text.endIndex) ?? text.endIndex
        return String(reflecting: String(text[..<end])) + (end == text.endIndex ? "" : " …")
    case let .data(text):
        let end = text.index(text.startIndex, offsetBy: 120, limitedBy: text.endIndex) ?? text.endIndex
        return "Base64: \(text[..<end])" + (end == text.endIndex ? "" : " …")
    case let .array(values): return "\(values.count.formatted()) items; inspect details for full values"
    case let .dictionary(values): return "\(values.count.formatted()) entries; inspect details for full values"
    default: return value.displayValue
    }
}
