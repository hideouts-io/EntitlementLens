import Foundation

/// Projects signed dictionaries only, preserving finding aliases, source integrity and collection limits.
func entitlementDeclarations(_ findings: [ScanFinding]) throws -> [EntitlementDeclaration] {
    try Task.checkCancellation()
    var declarations: [EntitlementDeclaration] = []
    for finding in findings {
        try Task.checkCancellation()
        guard let signing = finding.signing else { continue }
        let identity = EntitlementExecutableIdentity(
            deviceID: finding.provenance.deviceID,
            inode: finding.provenance.inode,
            sha256: finding.provenance.sha256
        )
        let outcome = findingOutcome(finding)
        let collectionWarnings = try entitlementCollectionWarnings(finding: finding, signing: signing)
        for (sourceOrdinal, group) in entitlementSourceGroups(signing).enumerated() {
            try Task.checkCancellation()
            for entry in group.entitlements {
                try Task.checkCancellation()
                declarations.append(EntitlementDeclaration(
                    id: EntitlementDeclarationID(
                        findingID: finding.id, source: group.source, sourceOrdinal: sourceOrdinal, key: entry.key
                    ),
                    findingID: finding.id,
                    path: finding.path,
                    analyzedPath: finding.provenance.analyzedPath,
                    executableIdentity: identity,
                    source: group.source,
                    key: entry.key,
                    value: entry.value,
                    status: group.status,
                    uniqueCDHash: group.uniqueCDHash,
                    teamIdentifier: signing.teamIdentifier,
                    collectionOutcome: outcome,
                    sourceWarnings: group.warnings,
                    collectionWarnings: collectionWarnings
                ))
            }
        }
    }
    return try declarations.sorted(by: entitlementDeclarationPrecedes)
}

/// Exact keys are case sensitive. Glob patterns match the entire key: * matches zero or more characters, ? matches one, and all other characters are literal.
/// Key and value conditions apply to the same declaration; executable and alias counts use only the returned observations.
func entitlementKeyGroups(
    _ declarations: [EntitlementDeclaration],
    query: EntitlementExplorerQuery
) throws -> [EntitlementKeyGroup] {
    try Task.checkCancellation()
    if case let .realEquals(value) = query.valuePredicate, !value.isFinite {
        throw EntitlementExplorerQueryError.invalidReal(String(value))
    }
    let pattern: [Character] = Array(query.keyPattern)
    var grouped: [String: [EntitlementDeclaration]] = [:]
    for declaration in declarations {
        try Task.checkCancellation()
        if entitlementValueMatches(declaration.value, predicate: query.valuePredicate) {
            grouped[declaration.key, default: []].append(declaration)
        }
    }
    var groups: [EntitlementKeyGroup] = []
    let groupedRows: [(key: String, value: [EntitlementDeclaration])] = try grouped.sorted {
        try Task.checkCancellation()
        return $0.key < $1.key
    }
    for (key, rows) in groupedRows {
        try Task.checkCancellation()
        let keyMatches: Bool
        if query.keyPattern.isEmpty {
            keyMatches = true
        } else {
            switch query.keyMode {
            case .exact: keyMatches = key == query.keyPattern
            case .glob: keyMatches = try entitlementGlobMatches(key, pattern: pattern)
            }
        }
        if keyMatches {
            var executables: Set<EntitlementExecutableIdentity> = []
            var aliases: Set<String> = []
            for row in rows {
                try Task.checkCancellation()
                executables.insert(row.executableIdentity)
                aliases.insert(row.path)
            }
            groups.append(EntitlementKeyGroup(
                key: key,
                declarations: try rows.sorted(by: entitlementDeclarationPrecedes),
                executableCount: executables.count,
                aliasCount: aliases.count
            ))
        }
    }
    try Task.checkCancellation()
    return groups
}

private func entitlementCollectionWarnings(finding: ScanFinding, signing: SigningDetails) throws -> [String] {
    var warnings: [String] = []
    var seen: Set<String> = []
    for warning in finding.warnings + signing.extractionWarnings {
        try Task.checkCancellation()
        if seen.insert(warning).inserted { warnings.append(warning) }
    }
    return warnings
}

private func entitlementValueMatches(_ value: EntitlementValue, predicate: EntitlementValuePredicate) -> Bool {
    switch (value, predicate) {
    case (_, .any): true
    case let (.boolean(value), .boolean(expected)): value == expected
    case let (.string(value), .stringEquals(expected)): value == expected
    case let (.integer(value), .integerEquals(expected)): value == expected
    case let (.real(value), .realEquals(expected)): value == expected
    default: false
    }
}

private func entitlementGlobMatches(_ key: String, pattern: [Character]) throws -> Bool {
    try Task.checkCancellation()
    let characters: [Character] = Array(key)
    var keyOffset = 0
    var patternOffset = 0
    var starOffset: Int?
    var starMatchOffset = 0
    while keyOffset < characters.count {
        try Task.checkCancellation()
        if patternOffset < pattern.count, pattern[patternOffset] == "*" {
            starOffset = patternOffset
            starMatchOffset = keyOffset
            patternOffset += 1
        } else if patternOffset < pattern.count,
                  pattern[patternOffset] == "?" || pattern[patternOffset] == characters[keyOffset] {
            keyOffset += 1
            patternOffset += 1
        } else if let starOffset {
            starMatchOffset += 1
            keyOffset = starMatchOffset
            patternOffset = starOffset + 1
        } else {
            return false
        }
    }
    while patternOffset < pattern.count, pattern[patternOffset] == "*" {
        try Task.checkCancellation()
        patternOffset += 1
    }
    return patternOffset == pattern.count
}

private func entitlementDeclarationPrecedes(_ left: EntitlementDeclaration, _ right: EntitlementDeclaration) throws -> Bool {
    try Task.checkCancellation()
    if left.key != right.key { return left.key < right.key }
    if left.path != right.path { return left.path < right.path }
    if left.analyzedPath != right.analyzedPath { return left.analyzedPath < right.analyzedPath }
    switch (left.source, right.source) {
    case (.standardDictionary, .architecture): return true
    case (.architecture, .standardDictionary): return false
    case let (.architecture(leftArchitecture), .architecture(rightArchitecture)):
        if leftArchitecture != rightArchitecture { return leftArchitecture < rightArchitecture }
    case (.standardDictionary, .standardDictionary): break
    }
    if left.findingID != right.findingID { return left.findingID.uuidString < right.findingID.uuidString }
    return left.id.sourceOrdinal < right.id.sourceOrdinal
}
