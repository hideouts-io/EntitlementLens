import Foundation

extension ScanStore {
    var selectedEntitlementDeclarations: [EntitlementDeclaration] {
        explorerGroups.first { $0.key == selectedEntitlementKey }?.declarations ?? []
    }

    func selectExplorerFinding() {
        guard browserMode == .entitlements else { return }
        let declarations = selectedEntitlementDeclarations
        if !declarations.contains(where: { $0.findingID == selectedFindingID }) {
            selectedFindingID = declarations.first?.findingID
        }
    }

    func cancelEntitlementExplorer() {
        explorerTask?.cancel()
        explorerRequest = UUID()
        isExploring = false
    }

    /// Each batch is indexed once; queries group an immutable declaration snapshot off the main actor.
    func refreshEntitlementExplorer() {
        cancelEntitlementExplorer()
        guard browserMode == .entitlements else { return }
        let query: EntitlementExplorerQuery
        do {
            query = EntitlementExplorerQuery(
                keyPattern: explorerKeyPattern,
                keyMode: explorerKeyMode,
                valuePredicate: try entitlementValuePredicate(mode: explorerValueMode, text: explorerValueText)
            )
        } catch {
            explorerQueryError = error.localizedDescription
            explorerGroups = []
            selectedEntitlementKey = nil
            return
        }
        let request = explorerRequest
        let declarations = entitlementDeclarationIndex
        explorerQueryError = nil
        isExploring = true
        explorerTask = Task {
            let worker = Task.detached(priority: .userInitiated) {
                try entitlementKeyGroups(declarations, query: query)
            }
            do {
                let groups = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
                try Task.checkCancellation()
                guard explorerRequest == request, browserMode == .entitlements else { return }
                explorerGroups = groups
                if !groups.contains(where: { $0.key == selectedEntitlementKey }) {
                    selectedEntitlementKey = groups.first?.key
                }
                selectExplorerFinding()
                isExploring = false
            } catch is CancellationError {
                // A newer query, browser mode, or scan owns the explorer presentation.
            } catch {
                guard explorerRequest == request, browserMode == .entitlements else { return }
                explorerQueryError = "Entitlement query failed: \(error.localizedDescription)"
                explorerGroups = []
                selectedEntitlementKey = nil
                isExploring = false
            }
        }
    }
}
