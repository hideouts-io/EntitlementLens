import Foundation

extension ScanStore {
    var currentFilterControls: EntitlementFilterProposal {
        EntitlementFilterProposal(keyPattern: explorerKeyPattern, keyMode: explorerKeyMode,
            valueMode: explorerValueMode, valueText: explorerValueText)
    }

    func refreshFilterModelAvailability() {
        filterModelAvailability = entitlementFilterAvailability()
    }

    /// Manual edits, navigation and new scans retire both running generation and its preview.
    func invalidateFilterProposal() {
        filterGenerationTask?.cancel()
        filterDeadlineTask?.cancel()
        filterGenerationTask = nil
        filterDeadlineTask = nil
        filterProposalOwnership = nil
        filterProposalState = .idle
    }

    /// This seam validates request vocabulary without invoking a model or reading findings.
    func beginFilterProposalRequest() throws(EntitlementFilterGenerationError) -> EntitlementFilterRequestOwnership {
        invalidateFilterProposal()
        guard browserMode == .entitlements else {
            throw EntitlementFilterGenerationError(failure: .inactiveExplorer, underlying: nil)
        }
        do {
            _ = try entitlementFilterRequest(filterRequestText)
        } catch {
            throw EntitlementFilterGenerationError(failure: .invalidRequest(error), underlying: error)
        }
        let ownership = EntitlementFilterRequestOwnership(id: UUID(), requestText: filterRequestText,
            manualControls: currentFilterControls)
        filterProposalOwnership = ownership
        filterProposalState = .generating
        return ownership
    }

    /// False means a newer request or presentation change already retired this response.
    @discardableResult
    func completeFilterProposalRequest(
        _ ownership: EntitlementFilterRequestOwnership,
        translation: EntitlementFilterTranslation
    ) throws(EntitlementFilterGenerationError) -> Bool {
        guard filterProposalState == .generating, ownsFilterProposalRequest(ownership) else { return false }
        let validated: EntitlementFilterTranslation
        do {
            validated = try validatedEntitlementFilterTranslation(translation, request: ownership.requestText)
        } catch {
            throw EntitlementFilterGenerationError(failure: .invalidProposal(error), underlying: error)
        }
        finishFilterProposalTasks()
        switch validated {
        case let .proposal(proposal): filterProposalState = .preview(proposal)
        case .ambiguous: filterProposalState = .ambiguous
        case .unsupported: filterProposalState = .unsupported
        }
        return true
    }

    /// Failure publication observes the same ownership check as successful completion.
    @discardableResult
    func failFilterProposalRequest(
        _ ownership: EntitlementFilterRequestOwnership,
        failure: EntitlementFilterGenerationFailure
    ) -> Bool {
        guard filterProposalState == .generating, ownsFilterProposalRequest(ownership) else { return false }
        filterGenerationTask?.cancel()
        finishFilterProposalTasks()
        filterProposalOwnership = nil
        filterProposalState = failure == .cancelled ? .cancelled : .failed(failure)
        return true
    }

    /// Only an explicit action starts generation; the deadline releases presentation promptly.
    func generateFilterProposal() {
        let ownership: EntitlementFilterRequestOwnership
        do {
            ownership = try beginFilterProposalRequest()
        } catch {
            filterProposalState = .failed(error.failure)
            return
        }
        refreshFilterModelAvailability()
        guard filterModelAvailability == .available else {
            failFilterProposalRequest(ownership, failure: .unavailable(filterModelAvailability))
            return
        }
        filterDeadlineTask = Task {
            do {
                try await Task.sleep(for: .seconds(EntitlementFilterLimits.generationSeconds))
                try Task.checkCancellation()
                failFilterProposalRequest(ownership, failure: .timedOut)
            } catch is CancellationError {
                // Completion or a newer owner retired this deadline.
            } catch {
                failFilterProposalRequest(ownership, failure: .generationFailed)
            }
        }
        filterGenerationTask = Task {
            do {
                let translation = try await generateEntitlementFilter(request: ownership.requestText)
                try Task.checkCancellation()
                try completeFilterProposalRequest(ownership, translation: translation)
            } catch let error as EntitlementFilterGenerationError {
                failFilterProposalRequest(ownership, failure: error.failure)
            } catch is CancellationError {
                failFilterProposalRequest(ownership, failure: .cancelled)
            } catch {
                failFilterProposalRequest(ownership, failure: .generationFailed)
            }
        }
    }

    func cancelFilterProposal() {
        invalidateFilterProposal()
        filterProposalState = .cancelled
    }

    func discardFilterProposal() {
        invalidateFilterProposal()
    }

    /// User edits are structurally validated; the accepted query still uses the existing matcher.
    func applyFilterProposal(_ proposal: EntitlementFilterProposal) throws(EntitlementFilterGenerationError) {
        guard case .preview = filterProposalState,
              let ownership = filterProposalOwnership,
              ownsFilterProposalRequest(ownership) else {
            throw EntitlementFilterGenerationError(failure: .noOwnedProposal, underlying: nil)
        }
        do {
            _ = try validatedEntitlementFilterProposal(proposal)
        } catch {
            throw EntitlementFilterGenerationError(failure: .invalidProposal(error), underlying: error)
        }
        invalidateFilterProposal()
        explorerKeyPattern = proposal.keyPattern
        explorerKeyMode = proposal.keyMode
        explorerValueMode = proposal.valueMode
        explorerValueText = proposal.valueText
    }

    private func ownsFilterProposalRequest(_ ownership: EntitlementFilterRequestOwnership) -> Bool {
        filterProposalOwnership == ownership && browserMode == .entitlements &&
            filterRequestText == ownership.requestText && currentFilterControls == ownership.manualControls
    }

    private func finishFilterProposalTasks() {
        filterDeadlineTask?.cancel()
        filterDeadlineTask = nil
        filterGenerationTask = nil
    }
}
