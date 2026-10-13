import Foundation

/// Proposal lifecycle belongs to presentation, never to findings or exported evidence.
enum EntitlementFilterProposalState: Equatable, Sendable {
    case idle
    case generating
    case preview(EntitlementFilterProposal)
    case ambiguous
    case unsupported
    case cancelled
    case failed(EntitlementFilterGenerationFailure)
}

/// Exact input and control snapshots prevent a response from claiming newer presentation state.
struct EntitlementFilterRequestOwnership: Hashable, Sendable {
    let id: UUID
    let requestText: String
    let manualControls: EntitlementFilterProposal
}
