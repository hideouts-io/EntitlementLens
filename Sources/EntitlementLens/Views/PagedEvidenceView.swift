import SwiftUI

/// Bounded pages prevent a disclosure from constructing every child view at once.
struct PagedEvidenceView<Item: Identifiable, Row: View>: View {
    let items: [Item]
    let row: (Item) -> Row
    @State private var page = 0
    private let pageSize = 20

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(items.dropFirst(page * pageSize).prefix(pageSize)) { item in
                row(item)
            }
            if items.count > pageSize {
                HStack {
                    Button("Previous") { page -= 1 }.disabled(page == 0)
                        .accessibilityIdentifier("evidence.previous-page")
                    Text("Page \(page + 1) of \((items.count + pageSize - 1) / pageSize)")
                        .font(.caption).monospacedDigit()
                    Button("Next") { page += 1 }.disabled((page + 1) * pageSize >= items.count)
                        .accessibilityIdentifier("evidence.next-page")
                }
            }
        }
    }
}

/// Full text remains in the model/export; only a small character window is laid out.
struct PagedTextView: View {
    let text: String
    @State private var start: String.Index?
    @State private var history: [String.Index] = []

    var body: some View {
        let beginning = start ?? text.startIndex
        let end = text.index(beginning, offsetBy: 2_048, limitedBy: text.endIndex) ?? text.endIndex
        VStack(alignment: .leading, spacing: 6) {
            Text(String(text[beginning..<end]))
                .font(.caption.monospaced()).textSelection(.enabled)
            if beginning != text.startIndex || end != text.endIndex {
                HStack {
                    Button("Previous text") { start = history.removeLast() }.disabled(history.isEmpty)
                        .accessibilityIdentifier("evidence.previous-text")
                    Text("Text page \(history.count + 1)").font(.caption)
                    Button("Next text") { history.append(beginning); start = end }.disabled(end == text.endIndex)
                        .accessibilityIdentifier("evidence.next-text")
                }
                Text("Paged display only. Copy All Data Found or JSON export retains the complete value.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct EntitlementEntriesView: View {
    let entries: [EntitlementEntry]
    @State private var expandedKey: String?

    var body: some View {
        PagedEvidenceView(items: entries) { entry in
            DisclosureGroup(isExpanded: Binding(
                get: { expandedKey == entry.key },
                set: { expandedKey = $0 ? entry.key : nil }
            )) {
                if expandedKey == entry.key { EntitlementValueView(value: entry.value) }
            } label: {
                Text(entry.key).font(.body.monospaced()).textSelection(.enabled)
            }
        }
    }
}

struct EntitlementValueView: View {
    let value: EntitlementValue
    @State private var children: [EntitlementEntry]?
    @State private var failure: String?

    var body: some View {
        Group {
            switch value {
            case .array, .dictionary:
                if let children {
                    if children.isEmpty { Text("Empty collection").foregroundStyle(.secondary) }
                    else { EntitlementEntriesView(entries: children) }
                } else if let failure { Text(failure).foregroundStyle(.red) }
                else { ProgressView("Preparing values…") }
            case let .string(text): PagedTextView(text: text)
            case let .data(text):
                Text("Base64 data").foregroundStyle(.secondary)
                PagedTextView(text: text)
            default: PagedTextView(text: value.displayValue)
            }
        }
        .task {
            guard children == nil else { return }
            switch value {
            case .array, .dictionary: break
            default: return
            }
            let worker = Task.detached(priority: .userInitiated) { () throws -> [EntitlementEntry] in
                try Task.checkCancellation()
                switch value {
                case let .array(values):
                    return try values.enumerated().map { index, value in
                        try Task.checkCancellation()
                        return EntitlementEntry(key: "[\(index)]", value: value)
                    }
                case let .dictionary(values):
                    return try values.sorted { $0.key < $1.key }.map { key, child in
                        try Task.checkCancellation()
                        return EntitlementEntry(key: key, value: child)
                    }
                default: return []
                }
            }
            do {
                let result = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                children = result
            } catch is CancellationError {
                // Leaving a disclosure cancels its view-owned preparation.
            } catch { failure = "Value preparation failed: \(error.localizedDescription)" }
        }
    }
}
