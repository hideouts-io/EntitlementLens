import Foundation

/// Presentation-only controls proposed by translation; inspection evidence never contains this model.
struct EntitlementFilterProposal: Hashable, Sendable {
    let keyPattern: String
    let keyMode: EntitlementKeyMatchMode
    let valueMode: EntitlementValueMatchMode
    let valueText: String
}

enum EntitlementFilterTranslation: Sendable {
    case proposal(EntitlementFilterProposal)
    case ambiguous
    case unsupported
}

/// Byte limits bound parsing and exact literals; model limits bound generation work independently.
enum EntitlementFilterLimits {
    static let requestBytes = 2_048
    static let keyBytes = 512
    static let valueBytes = 2_048
    static let responseTokens = 1_024
    static let generationSeconds = 30
}

enum EntitlementFilterProposalError: Error, LocalizedError, Equatable, Sendable {
    case requestTooLong
    case unsupportedRequest
    case invalidQuotedLiteral
    case emptyKey
    case keyTooLong
    case valueTooLong
    case unexpectedValue
    case invalidInteger
    case invalidReal
    case proposalMismatch

    var errorDescription: String? {
        switch self {
        case .requestTooLong:
            "The filter request exceeds \(EntitlementFilterLimits.requestBytes) UTF-8 bytes. Shorten the request before generating a proposal."
        case .unsupportedRequest:
            "Use Show, Find, or List with one literal key or keys matching one pattern, optionally followed by one explicitly typed value. Quote non-dotted or unusual keys as JSON, for example: Show \"keychain-access-groups\". Extra conditions are unsupported; informal names need literal spelling."
        case .invalidQuotedLiteral:
            "A quoted filter literal is invalid. Use a complete JSON-style quoted string with valid escapes."
        case .emptyKey:
            "An empty key would select all keys in the existing matcher. Supply a nonempty literal key or an explicit glob such as *."
        case .keyTooLong:
            "The proposed key or pattern exceeds \(EntitlementFilterLimits.keyBytes) UTF-8 bytes. Use a shorter literal or pattern."
        case .valueTooLong:
            "The proposed value exceeds \(EntitlementFilterLimits.valueBytes) UTF-8 bytes. Use the manual controls for a longer value."
        case .unexpectedValue:
            "Any-value and Boolean proposals must have an empty value-text field. Discard the invalid proposal and try again."
        case .invalidInteger:
            "An integer proposal must contain a signed decimal Int64 without whitespace and within Int64 bounds."
        case .invalidReal:
            "A real proposal must contain a finite decimal or scientific-notation value without whitespace. Infinity, NaN, and overflow are unsupported."
        case .proposalMismatch:
            "The proposal does not preserve the request's literal key, value, or match modes. Discard it or use the manual controls."
        }
    }
}
