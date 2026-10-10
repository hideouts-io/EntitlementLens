import Foundation

/// Collection success is independent of signature integrity, including an invalid but readable signature.
enum EntitlementCollectionState: Codable, Hashable, Sendable {
    case complete
    case unavailable(reason: String)
}

enum EntitlementComparisonAvailability: String, Codable, Hashable, Sendable {
    case collected
    case unavailable
    case architectureMissing

    var title: String {
        switch self {
        case .collected: "Collected"
        case .unavailable: "Unavailable"
        case .architectureMissing: "Architecture absent"
        }
    }
}

struct EntitlementComparisonEvidence: Codable, Hashable, Sendable {
    let availability: EntitlementComparisonAvailability
    let signatureStatus: SignatureStatus?
    let uniqueCDHash: String?
    let warnings: [String]
}

enum EntitlementDifferenceKind: String, Codable, Hashable, Sendable {
    case added
    case removed
    case changed
    case unchanged
    case unavailable
    case architectureMissing

    var title: String {
        switch self {
        case .added: "Added in Installed"
        case .removed: "Absent from Installed"
        case .changed: "Value changed"
        case .unchanged: "Unchanged"
        case .unavailable: "Comparison unavailable"
        case .architectureMissing: "Architecture absent"
        }
    }
}

struct EntitlementDifference: Codable, Hashable, Identifiable, Sendable {
    let key: String
    let sourceValue: EntitlementValue?
    let installedValue: EntitlementValue?
    let result: EntitlementDifferenceKind

    var id: String { key }
}

struct EntitlementScopeComparison: Codable, Hashable, Identifiable, Sendable {
    let scope: EntitlementSource
    let source: EntitlementComparisonEvidence
    let installed: EntitlementComparisonEvidence
    let entries: [EntitlementDifference]

    var id: EntitlementSource { scope }
    var isIncomplete: Bool { source.availability == .unavailable || installed.availability == .unavailable }
    var hasMissingArchitecture: Bool {
        source.availability == .architectureMissing || installed.availability == .architectureMissing
    }

    var summary: String {
        if isIncomplete { return "Comparison incomplete: entitlement evidence is unavailable on at least one side." }
        if hasMissingArchitecture { return "This architecture is absent from one artifact; its declarations are not classified as added or removed." }
        if entries.isEmpty { return "Both sides were inspected successfully and returned no declared entitlements in this scope." }
        return entitlementDifferenceSummary(entries)
    }
}

struct EntitlementComparison: Codable, Hashable, Sendable {
    let scopes: [EntitlementScopeComparison]
    let warnings: [String]

    var isComplete: Bool { !scopes.isEmpty && scopes.allSatisfy { !$0.isIncomplete } }
    var hasDifferences: Bool {
        scopes.contains { scope in
            scope.hasMissingArchitecture || scope.entries.contains { [.added, .removed, .changed].contains($0.result) }
        }
    }

    var summary: String {
        let changes = entitlementDifferenceSummary(scopes.flatMap(\.entries))
        let missing = scopes.filter(\.hasMissingArchitecture).count
        let unavailable = scopes.filter(\.isIncomplete).count
        return "\(changes) · \(missing) architecture differences · \(unavailable) unavailable scopes"
    }
}

private func entitlementDifferenceSummary(_ entries: [EntitlementDifference]) -> String {
    let added = entries.filter { $0.result == .added }.count
    let removed = entries.filter { $0.result == .removed }.count
    let changed = entries.filter { $0.result == .changed }.count
    let unchanged = entries.filter { $0.result == .unchanged }.count
    return "\(added) added · \(removed) removed · \(changed) changed · \(unchanged) unchanged"
}
