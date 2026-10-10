import Foundation

enum EntitlementBrowserMode: String, CaseIterable, Identifiable, Sendable {
    case files
    case entitlements

    var id: String { rawValue }

    var title: String {
        switch self {
        case .files: "Files"
        case .entitlements: "Entitlements"
        }
    }
}

enum EntitlementKeyMatchMode: String, CaseIterable, Identifiable, Sendable {
    case exact
    case glob

    var id: String { rawValue }

    var title: String {
        switch self {
        case .exact: "Exact key"
        case .glob: "Key pattern"
        }
    }
}

enum EntitlementValueMatchMode: String, CaseIterable, Identifiable, Sendable {
    case any
    case booleanTrue
    case booleanFalse
    case stringEquals
    case integerEquals
    case realEquals

    var id: String { rawValue }

    var title: String {
        switch self {
        case .any: "Any value"
        case .booleanTrue: "Boolean true"
        case .booleanFalse: "Boolean false"
        case .stringEquals: "String equals"
        case .integerEquals: "Integer equals"
        case .realEquals: "Real equals"
        }
    }
}

enum EntitlementValuePredicate: Hashable, Sendable {
    case any
    case boolean(Bool)
    case stringEquals(String)
    case integerEquals(Int64)
    case realEquals(Double)
}

struct EntitlementExplorerQuery: Sendable {
    let keyPattern: String
    let keyMode: EntitlementKeyMatchMode
    let valuePredicate: EntitlementValuePredicate
}

enum EntitlementExplorerQueryError: LocalizedError {
    case invalidInteger(String)
    case invalidReal(String)

    var errorDescription: String? {
        switch self {
        case let .invalidInteger(text):
            "Integer filter value '\(text)' must be a whole number from \(Int64.min) through \(Int64.max). Enter a signed decimal integer without surrounding whitespace."
        case let .invalidReal(text):
            "Real filter value '\(text)' must be a finite number. Enter a decimal value such as 1.5; infinity and NaN cannot be used."
        }
    }
}

/// String comparisons retain every character, including an empty string; numeric inputs must parse in their declared type.
func entitlementValuePredicate(mode: EntitlementValueMatchMode, text: String) throws -> EntitlementValuePredicate {
    switch mode {
    case .any: return .any
    case .booleanTrue: return .boolean(true)
    case .booleanFalse: return .boolean(false)
    case .stringEquals: return .stringEquals(text)
    case .integerEquals:
        guard let value = Int64(text) else {
            throw EntitlementExplorerQueryError.invalidInteger(text)
        }
        return .integerEquals(value)
    case .realEquals:
        guard let value = Double(text), value.isFinite else {
            throw EntitlementExplorerQueryError.invalidReal(text)
        }
        return .realEquals(value)
    }
}

/// Filesystem identity belongs to the analyzed executable; a changed digest identifies a different observed artifact.
struct EntitlementExecutableIdentity: Hashable, Sendable {
    let deviceID: UInt64
    let inode: UInt64
    let sha256: String
}

struct EntitlementDeclarationID: Hashable, Sendable {
    let findingID: UUID
    let source: EntitlementSource
    let sourceOrdinal: Int
    let key: String
}

struct EntitlementDeclaration: Identifiable, Sendable {
    let id: EntitlementDeclarationID
    let findingID: UUID
    let path: String
    let analyzedPath: String
    let executableIdentity: EntitlementExecutableIdentity
    let source: EntitlementSource
    let key: String
    let value: EntitlementValue
    let status: SignatureStatus
    let uniqueCDHash: String?
    let teamIdentifier: String?
    let collectionOutcome: FindingOutcome
    let sourceWarnings: [String]
    let collectionWarnings: [String]

    var sourceTitle: String {
        source.title
    }

    var valueTypeTitle: String {
        value.typeTitle
    }
}

struct EntitlementKeyGroup: Identifiable, Sendable {
    let key: String
    let declarations: [EntitlementDeclaration]
    let executableCount: Int
    let aliasCount: Int

    var id: String { key }
}
