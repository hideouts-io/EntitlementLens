import Foundation

enum EntitlementComparisonError: LocalizedError {
    case missingArchitectureInventory(String)
    case duplicateScope(String, String)
    case duplicateKey(String, String)
    case conflictingArchitecture(String, String)

    var errorDescription: String? {
        switch self {
        case let .missingArchitectureInventory(side):
            "Cannot compare \(side): no parsed Mach-O architecture inventory is available."
        case let .duplicateScope(side, scope):
            "Cannot compare \(side): more than one record identifies \(scope)."
        case let .duplicateKey(scope, key):
            "Cannot compare \(scope): entitlement key '\(key)' occurs more than once."
        case let .conflictingArchitecture(side, architecture):
            "Cannot compare \(side): collected architecture '\(architecture)' is absent from its parsed Mach-O inventory."
        }
    }
}

/// The source artifact is the baseline. Missing slices never become added/removed declarations.
func compareEntitlements(
    sourceSigning: SigningDetails,
    sourceSlices: [MachOSlice],
    installedSigning: SigningDetails,
    installedSlices: [MachOSlice]
) throws -> EntitlementComparison {
    let sourceGroups = try comparisonGroups(signing: sourceSigning, slices: sourceSlices, side: "Source")
    let installedGroups = try comparisonGroups(signing: installedSigning, slices: installedSlices, side: "Installed")
    let architectures = Set(sourceSlices.map(\.architecture) + installedSlices.map(\.architecture)).sorted()
    let scopes: [EntitlementSource] = [.standardDictionary] + architectures.map { .architecture($0) }
    let comparisons = try scopes.map { scope in
        let sourceGroup = sourceGroups[scope]
        let installedGroup = installedGroups[scope]
        let source = comparisonEvidence(group: sourceGroup, scope: scope, slices: sourceSlices)
        let installed = comparisonEvidence(group: installedGroup, scope: scope, slices: installedSlices)
        let sourceEntries = try comparisonEntries(sourceGroup, scope: "Source \(scope.title)")
        let installedEntries = try comparisonEntries(installedGroup, scope: "Installed \(scope.title)")
        let entries = Set(sourceEntries.keys).union(installedEntries.keys).sorted().map { key in
            EntitlementDifference(key: key, sourceValue: sourceEntries[key], installedValue: installedEntries[key],
                result: differenceKind(source: source, installed: installed,
                    sourceValue: sourceEntries[key], installedValue: installedEntries[key]))
        }
        return EntitlementScopeComparison(scope: scope, source: source, installed: installed, entries: entries)
    }
    return EntitlementComparison(scopes: comparisons, warnings: Array(Set(
        sourceSigning.extractionWarnings.map { "Source: \($0)" }
            + installedSigning.extractionWarnings.map { "Installed: \($0)" }
    )).sorted())
}

private func comparisonGroups(
    signing: SigningDetails, slices: [MachOSlice], side: String
) throws -> [EntitlementSource: EntitlementSourceGroup] {
    guard !slices.isEmpty else { throw EntitlementComparisonError.missingArchitectureInventory(side) }
    let sliceGroups = Dictionary(grouping: slices, by: \.architecture)
    if let duplicate = sliceGroups.sorted(by: { $0.key < $1.key }).first(where: { $0.value.count > 1 }) {
        throw EntitlementComparisonError.duplicateScope(side, duplicate.key)
    }
    let collected = entitlementSourceGroups(signing)
    let groups = Dictionary(grouping: collected, by: \.source)
    var result: [EntitlementSource: EntitlementSourceGroup] = [:]
    for group in collected {
        guard groups[group.source]?.count == 1 else {
            throw EntitlementComparisonError.duplicateScope(side, group.source.title)
        }
        if case let .architecture(architecture) = group.source, sliceGroups[architecture] == nil {
            throw EntitlementComparisonError.conflictingArchitecture(side, architecture)
        }
        result[group.source] = group
    }
    return result
}

private func comparisonEvidence(
    group: EntitlementSourceGroup?, scope: EntitlementSource, slices: [MachOSlice]
) -> EntitlementComparisonEvidence {
    guard let group else {
        if case let .architecture(architecture) = scope, !slices.contains(where: { $0.architecture == architecture }) {
            return EntitlementComparisonEvidence(availability: .architectureMissing, signatureStatus: nil,
                uniqueCDHash: nil, warnings: ["The parsed Mach-O inventory does not contain \(architecture)."])
        }
        return EntitlementComparisonEvidence(availability: .unavailable, signatureStatus: nil,
            uniqueCDHash: nil, warnings: ["The architecture exists, but its entitlement collection was not returned."])
    }
    let reason: String?
    if case let .unavailable(code, message) = group.status {
        reason = "Signing information unavailable: OSStatus \(code): \(message)"
    } else {
        switch group.collectionState {
        case .complete: reason = nil
        case let .unavailable(message): reason = message
        case nil: reason = "Collection completeness was not recorded in this evidence."
        }
    }
    return EntitlementComparisonEvidence(availability: reason == nil ? .collected : .unavailable,
        signatureStatus: group.status, uniqueCDHash: group.uniqueCDHash,
        warnings: Array(Set(group.warnings + (reason.map { [$0] } ?? []))).sorted())
}

private func comparisonEntries(_ group: EntitlementSourceGroup?, scope: String) throws -> [String: EntitlementValue] {
    var result: [String: EntitlementValue] = [:]
    for entry in group?.entitlements ?? [] {
        guard result[entry.key] == nil else { throw EntitlementComparisonError.duplicateKey(scope, entry.key) }
        result[entry.key] = entry.value
    }
    return result
}

private func differenceKind(
    source: EntitlementComparisonEvidence, installed: EntitlementComparisonEvidence,
    sourceValue: EntitlementValue?, installedValue: EntitlementValue?
) -> EntitlementDifferenceKind {
    if source.availability == .unavailable || installed.availability == .unavailable { return .unavailable }
    if source.availability == .architectureMissing || installed.availability == .architectureMissing { return .architectureMissing }
    switch (sourceValue, installedValue) {
    case (nil, .some): return .added
    case (.some, nil): return .removed
    case let (.some(left), .some(right)): return left == right ? .unchanged : .changed
    case (nil, nil): return .unchanged
    }
}
