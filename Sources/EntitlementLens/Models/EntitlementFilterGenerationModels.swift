import Foundation

/// On-device generation readiness is independent of scanning, manual filtering and exports.
enum EntitlementFilterAvailability: Equatable, Sendable {
    case available
    case unsupportedOS
    case unsupportedSDK
    case deviceNotEligible
    case appleIntelligenceDisabled
    case modelNotReady
    case unknownUnavailable

    var message: String {
        switch self {
        case .available:
            "Apple Intelligence is ready to propose a filter. Review the exact query before applying it."
        case .unsupportedOS:
            "Apple Intelligence filtering requires macOS 26 or later. Use the manual key and value controls on this version of macOS."
        case .unsupportedSDK:
            "This build does not include Foundation Models support. Use the manual filters or a build made with a supported macOS SDK."
        case .deviceNotEligible:
            "This Mac is not eligible for the on-device Apple Intelligence model. Use the manual key and value controls."
        case .appleIntelligenceDisabled:
            "Apple Intelligence is disabled in System Settings. You can enable it yourself or continue using the manual filters."
        case .modelNotReady:
            "The on-device model is not ready. Check Apple Intelligence in System Settings and try again when it is available; manual filters remain usable."
        case .unknownUnavailable:
            "The on-device model is unavailable for another system reason. Check Apple Intelligence in System Settings or use the manual filters."
        }
    }
}

enum EntitlementFilterGenerationFailure: LocalizedError, Equatable, Sendable {
    case unavailable(EntitlementFilterAvailability)
    case invalidRequest(EntitlementFilterProposalError)
    case invalidProposal(EntitlementFilterProposalError)
    case inactiveExplorer
    case noOwnedProposal
    case cancelled
    case timedOut
    case refused
    case guardrail
    case contextLimit
    case rateLimited
    case unsupportedLanguage
    case invalidResponse
    case concurrentRequest
    case generationFailed

    var errorDescription: String? {
        switch self {
        case let .unavailable(availability):
            availability.message
        case let .invalidRequest(error), let .invalidProposal(error):
            error.localizedDescription
        case .inactiveExplorer:
            "Open By Entitlement before generating or applying an Apple Intelligence filter proposal."
        case .noOwnedProposal:
            "There is no current validated proposal to apply. Generate a new proposal and review its exact key and typed value."
        case .cancelled:
            "Filter generation was cancelled. The active manual query has not changed."
        case .timedOut:
            "Filter generation exceeded the 30-second limit. Shorten the request or use the manual filters."
        case .refused:
            "The on-device model refused this request. Describe one supported key and typed value condition, or use the manual filters."
        case .guardrail:
            "The on-device model's guardrails stopped this request. Describe one supported filter condition, or use the manual filters."
        case .contextLimit:
            "This request exceeded the on-device model's context limit. Shorten it to one key and typed value condition."
        case .rateLimited:
            "The on-device model limited this request. Try again later or use the manual filters."
        case .unsupportedLanguage:
            "The on-device model does not support this request's language or locale. Try a supported language or use the manual filters."
        case .invalidResponse:
            "The on-device model could not produce a valid filter response. Rephrase one supported condition or use the manual filters."
        case .concurrentRequest:
            "The on-device model reported an overlapping request. Wait for the current generation to finish or cancel it before trying again."
        case .generationFailed:
            "The on-device model failed to generate a filter. Try again later or use the manual filters."
        }
    }
}

/// Retains the provider cause for authorized diagnostics without exposing its prompt or generated contents.
struct EntitlementFilterGenerationError: LocalizedError, Sendable {
    let failure: EntitlementFilterGenerationFailure
    let underlying: (any Error)?

    init(failure: EntitlementFilterGenerationFailure, underlying: (any Error)?) {
        self.failure = failure
        self.underlying = underlying
    }

    var errorDescription: String? {
        failure.errorDescription
    }
}
