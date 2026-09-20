import Foundation

enum FindingOutcome: String, Sendable {
    case evidence = "Evidence found"
    case noEntitlements = "No entitlements found"
    case noData = "No data returned"
    case incomplete = "Incomplete collection"
}

struct IndexedFinding: Sendable {
    let finding: ScanFinding
    let searchText: String
    let filters: Set<ResultFilter>
    let outcome: FindingOutcome
    let visibleByDefault: Bool
}

func findingOutcome(_ finding: ScanFinding) -> FindingOutcome {
    if !finding.warnings.isEmpty { return .incomplete }
    if let signing = finding.signing {
        if case .unavailable = signing.status { return .incomplete }
        if !signing.extractionWarnings.isEmpty || signing.architectureEntitlements.contains(where: {
            if case .unavailable = $0.status { return true }
            return !$0.warnings.isEmpty
        }) || signing.entitlementSlots.contains(where: { $0.warning != nil }) { return .incomplete }
        if !signing.entitlements.isEmpty || signing.architectureEntitlements.contains(where: { !$0.entitlements.isEmpty }) {
            return .evidence
        }
        // Undecoded slots are evidence, not proof of an empty entitlement dictionary.
        if !signing.entitlementSlots.isEmpty { return .incomplete }
        if finding.embeddedObjects.isEmpty && finding.runningBoardPolicies.isEmpty { return .noEntitlements }
    }
    return finding.embeddedObjects.isEmpty && finding.runningBoardPolicies.isEmpty ? .noData : .evidence
}

func indexFinding(_ finding: ScanFinding) throws -> IndexedFinding {
    try Task.checkCancellation()
    var filters: Set<ResultFilter> = [.all]
    if finding.entitlementCount > 0 { filters.insert(.entitlements) }
    if finding.privateEntitlementCount > 0 { filters.insert(.privateEntitlements) }
    if !finding.embeddedObjects.isEmpty { filters.insert(.embeddedObjects) }
    if !finding.runningBoardPolicies.isEmpty { filters.insert(.runningBoard) }
    if finding.hasSigningProblem { filters.insert(.signingProblems) }
    let outcome = findingOutcome(finding)
    var terms = [finding.path, finding.provenance.analyzedPath, finding.provenance.sha256,
                 finding.signing?.identifier ?? "", finding.signing?.teamIdentifier ?? "",
                 finding.signing?.uniqueCDHash ?? "", finding.installedCounterpart?.path ?? "",
                 finding.installedCounterpart?.sha256 ?? "", outcome.rawValue]
    for entry in finding.signing?.entitlements ?? [] {
        try Task.checkCancellation()
        terms.append(entry.key)
        terms.append(entry.value.displayValue)
    }
    for object in finding.embeddedObjects {
        try Task.checkCancellation()
        terms.append(contentsOf: object.entitlementKeys)
        terms.append(contentsOf: object.stringMatches.map(\.value))
    }
    for policy in finding.runningBoardPolicies {
        terms.append(contentsOf: [policy.domain, policy.policy, policy.originatorEntitlement ?? ""])
        terms.append(contentsOf: policy.runningReasons.flatMap { [$0.rawValue, $0.decodedLabel ?? ""] })
    }
    return IndexedFinding(finding: finding, searchText: terms.joined(separator: "\n").lowercased(),
                          filters: filters, outcome: outcome,
                          visibleByDefault: outcome == .evidence || outcome == .incomplete || finding.hasSigningProblem)
}

func matchingFindings(_ index: [IndexedFinding], filter: ResultFilter, query: String, includeEmpty: Bool) throws -> [ScanFinding] {
    try Task.checkCancellation()
    let normalized = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    var results: [ScanFinding] = []
    for item in index {
        try Task.checkCancellation()
        if item.filters.contains(filter) && (includeEmpty || item.visibleByDefault)
            && (normalized.isEmpty || item.searchText.contains(normalized)) {
            results.append(item.finding)
        }
    }
    return results
}
