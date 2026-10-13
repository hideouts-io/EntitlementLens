import Foundation

/// Curated reference material is independent of observed entitlement values and export evidence.
struct EntitlementExplanation: Hashable, Sendable {
    let key: String
    let title: String
    let summary: String
    let valueShape: EntitlementExplanationValueShape
    let contextLimits: [String]
    let sources: [EntitlementExplanationSource]
}

struct EntitlementExplanationSource: Hashable, Sendable {
    let title: String
    let url: URL
}

/// The first reviewed catalog covers Boolean keys only; other shapes require their own reviewed records.
enum EntitlementExplanationValueShape: Hashable, Sendable {
    case boolean

    var title: String {
        switch self {
        case .boolean: "Boolean"
        }
    }
}

enum EntitlementExplanationLookup: Hashable, Sendable {
    case available(EntitlementExplanation)
    case unavailable(key: String)
}

/// Describes a retained declaration's shape without coercing its value or inferring authorization.
enum EntitlementExplanationObservation: Hashable, Sendable {
    case booleanDeclaration(Bool)
    case shapeMismatch(expected: EntitlementExplanationValueShape, observedType: String)

    var message: String {
        switch self {
        case let .booleanDeclaration(value):
            "The observed declaration is Boolean \(value ? "true" : "false"). This value alone does not establish runtime authorization or use."
        case let .shapeMismatch(expected, observedType):
            "Apple documents a \(expected.title) value; the retained declaration is \(observedType). The original value is preserved without conversion. This shape difference is not a signing or runtime verdict."
        }
    }
}

func entitlementExplanationObservation(
    value: EntitlementValue,
    explanation: EntitlementExplanation
) -> EntitlementExplanationObservation {
    switch explanation.valueShape {
    case .boolean:
        if case let .boolean(declared) = value {
            return .booleanDeclaration(declared)
        }
        return .shapeMismatch(expected: .boolean, observedType: value.typeTitle)
    }
}

enum EntitlementExplanationTextField: String, Hashable, Sendable {
    case title
    case summary
    case contextLimit
    case sourceTitle
}

enum EntitlementExplanationCatalogError: LocalizedError, Hashable, Sendable {
    case invalidSchemaVersion(Int)
    case invalidRevision
    case invalidReviewDate(String)
    case emptyRecords
    case invalidKey(String)
    case duplicateKey(String)
    case invalidText(key: String, field: EntitlementExplanationTextField)
    case missingContextLimits(key: String)
    case missingSources(key: String)
    case invalidSourceURL(key: String, url: String)
    case duplicateSourceURL(key: String, url: String)

    var errorDescription: String? {
        switch self {
        case let .invalidSchemaVersion(version):
            "Curated entitlement catalog schema \(version) is unsupported. Use catalog schema 1."
        case .invalidRevision:
            "The curated entitlement catalog revision must be a nonempty identifier of at most 64 ASCII letters, digits, periods, underscores or hyphens."
        case let .invalidReviewDate(date):
            "Curated entitlement catalog review date '\(date)' must be a valid Gregorian date in YYYY-MM-DD form."
        case .emptyRecords:
            "The curated entitlement catalog contains no reviewed records."
        case let .invalidKey(key):
            "Curated entitlement key '\(key)' must be an exact com.apple key with nonempty ASCII components and at most 256 bytes."
        case let .duplicateKey(key):
            "The curated entitlement catalog contains duplicate exact key '\(key)'. Keep one reviewed record per key."
        case let .invalidText(key, field):
            "Curated entitlement '\(key)' has invalid \(field.rawValue) text. Use nonempty, bounded text without control characters."
        case let .missingContextLimits(key):
            "Curated entitlement '\(key)' needs at least one documented platform or context limit."
        case let .missingSources(key):
            "Curated entitlement '\(key)' needs at least one Apple primary documentation source."
        case let .invalidSourceURL(key, url):
            "Curated entitlement '\(key)' has invalid source URL '\(url)'. Use a bounded HTTPS Apple Developer documentation URL without credentials, query parameters or fragments."
        case let .duplicateSourceURL(key, url):
            "Curated entitlement '\(key)' repeats source URL '\(url)'. Keep each source once."
        }
    }
}
