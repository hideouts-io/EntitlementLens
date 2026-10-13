import Foundation

/// Consumes a restricted complete request, so an unsupported clause cannot become an ignored suffix.
/// Grammar words are ASCII case insensitive; unquoted exact keys contain dotted ASCII components.
/// Nondotted keys, arbitrary literal spellings, and string values use JSON quotes. One terminal period is punctuation;
/// quote keys or patterns whose literal spelling ends in a period. No aliases are inferred.
func entitlementFilterRequest(_ request: String) throws(EntitlementFilterProposalError) -> EntitlementFilterProposal {
    try validateEntitlementFilterRequestSize(request)
    let tokens = try entitlementFilterRequestTokens(request)
    guard let command = tokens.first?.word,
          ["show", "find", "list"].contains(command.lowercased()) else { throw .unsupportedRequest }
    var offset = 1
    let keyMode: EntitlementKeyMatchMode
    if tokens.count > offset + 1,
       tokens[offset].isWord("keys"), tokens[offset + 1].isWord("matching") {
        keyMode = .glob
        offset += 2
    } else {
        keyMode = .exact
    }
    guard offset < tokens.count else { throw .unsupportedRequest }
    let key = try entitlementFilterRequestKey(tokens[offset], mode: keyMode)
    offset += 1
    var valueMode: EntitlementValueMatchMode = .any
    var valueText = ""
    if offset < tokens.count, tokens[offset].isWord("with") {
        offset += 1
        guard offset + 1 < tokens.count else { throw .unsupportedRequest }
        if tokens[offset].isWord("any"), tokens[offset + 1].isWord("value") {
            offset += 2
        } else if tokens[offset].isWord("boolean") {
            if tokens[offset + 1].isWord("true") { valueMode = .booleanTrue }
            else if tokens[offset + 1].isWord("false") { valueMode = .booleanFalse }
            else { throw .unsupportedRequest }
            offset += 2
        } else {
            guard tokens[offset + 1].isWord("value"), offset + 2 < tokens.count else { throw .unsupportedRequest }
            if tokens[offset].isWord("string"), case let .literal(text) = tokens[offset + 2] {
                valueMode = .stringEquals
                valueText = text
            } else if tokens[offset].isWord("integer"), let text = tokens[offset + 2].word {
                valueMode = .integerEquals
                valueText = text
            } else if tokens[offset].isWord("real"), let text = tokens[offset + 2].word {
                valueMode = .realEquals
                valueText = text
            } else { throw .unsupportedRequest }
            offset += 3
        }
    }
    if offset < tokens.count, case .period = tokens[offset] { offset += 1 }
    guard offset == tokens.count else { throw .unsupportedRequest }
    let proposal = EntitlementFilterProposal(keyPattern: key, keyMode: keyMode, valueMode: valueMode, valueText: valueText)
    _ = try validatedEntitlementFilterProposal(proposal)
    return proposal
}

/// Validates presentation controls without repairing generated text or changing manual query semantics.
func validatedEntitlementFilterProposal(
    _ proposal: EntitlementFilterProposal
) throws(EntitlementFilterProposalError) -> EntitlementExplorerQuery {
    guard !proposal.keyPattern.isEmpty else { throw .emptyKey }
    guard proposal.keyPattern.utf8.count <= EntitlementFilterLimits.keyBytes else { throw .keyTooLong }
    guard proposal.valueText.utf8.count <= EntitlementFilterLimits.valueBytes else { throw .valueTooLong }
    let predicate: EntitlementValuePredicate
    switch proposal.valueMode {
    case .any:
        guard proposal.valueText.isEmpty else { throw .unexpectedValue }
        predicate = .any
    case .booleanTrue, .booleanFalse:
        guard proposal.valueText.isEmpty else { throw .unexpectedValue }
        predicate = .boolean(proposal.valueMode == .booleanTrue)
    case .stringEquals:
        predicate = .stringEquals(proposal.valueText)
    case .integerEquals:
        guard entitlementFilterIntegerSyntax(Array(proposal.valueText.utf8)),
              let value = Int64(proposal.valueText) else { throw .invalidInteger }
        predicate = .integerEquals(value)
    case .realEquals:
        guard entitlementFilterRealSyntax(Array(proposal.valueText.utf8)),
              let value = Double(proposal.valueText), value.isFinite else { throw .invalidReal }
        predicate = .realEquals(value)
    }
    return EntitlementExplorerQuery(keyPattern: proposal.keyPattern, keyMode: proposal.keyMode, valuePredicate: predicate)
}

/// Guided shape validity is insufficient: proposals must agree with the complete eligible request.
func validatedEntitlementFilterTranslation(
    _ translation: EntitlementFilterTranslation,
    request: String
) throws(EntitlementFilterProposalError) -> EntitlementFilterTranslation {
    try validateEntitlementFilterRequestSize(request)
    switch translation {
    case let .proposal(proposal):
        let expected = try entitlementFilterRequest(request)
        _ = try validatedEntitlementFilterProposal(proposal)
        guard proposal.keyMode == expected.keyMode, proposal.valueMode == expected.valueMode,
              proposal.keyPattern.utf8.elementsEqual(expected.keyPattern.utf8),
              proposal.valueText.utf8.elementsEqual(expected.valueText.utf8) else { throw .proposalMismatch }
        return .proposal(proposal)
    case .ambiguous:
        return .ambiguous
    case .unsupported:
        return .unsupported
    }
}

private enum EntitlementFilterRequestToken {
    case word(String)
    case literal(String)
    case period

    var word: String? {
        if case let .word(text) = self { return text }
        return nil
    }

    func isWord(_ expected: String) -> Bool {
        word?.lowercased() == expected
    }
}

private func validateEntitlementFilterRequestSize(_ request: String) throws(EntitlementFilterProposalError) {
    guard request.utf8.count <= EntitlementFilterLimits.requestBytes else { throw .requestTooLong }
}

private func entitlementFilterRequestTokens(
    _ request: String
) throws(EntitlementFilterProposalError) -> [EntitlementFilterRequestToken] {
    let bytes = Array(request.utf8)
    var tokens: [EntitlementFilterRequestToken] = []
    var offset = 0
    while offset < bytes.count {
        if entitlementFilterRequestWhitespace(bytes[offset]) { offset += 1; continue }
        let start = offset
        if bytes[offset] == 34 {
            offset += 1
            var closed = false
            while offset < bytes.count {
                if bytes[offset] == 92 { offset += 2 }
                else if bytes[offset] == 34 { offset += 1; closed = true; break }
                else { offset += 1 }
            }
            guard closed, offset <= bytes.count else { throw .invalidQuotedLiteral }
            let text: String
            do { text = try JSONDecoder().decode(String.self, from: Data(bytes[start..<offset])) }
            catch { throw .invalidQuotedLiteral }
            tokens.append(.literal(text))
        } else {
            while offset < bytes.count, !entitlementFilterRequestWhitespace(bytes[offset]) { offset += 1 }
            let tokenBytes = bytes[start..<offset]
            if offset == bytes.count || bytes[offset...].allSatisfy(entitlementFilterRequestWhitespace),
               tokenBytes.last == 46 {
                let word = String(decoding: tokenBytes.dropLast(), as: UTF8.self)
                if !word.isEmpty { tokens.append(.word(word)) }
                tokens.append(.period)
            } else {
                tokens.append(.word(String(decoding: tokenBytes, as: UTF8.self)))
            }
        }
    }
    return tokens
}

private func entitlementFilterRequestKey(
    _ token: EntitlementFilterRequestToken,
    mode: EntitlementKeyMatchMode
) throws(EntitlementFilterProposalError) -> String {
    if case let .literal(text) = token { return text }
    guard let text = token.word, !text.isEmpty else { throw .unsupportedRequest }
    let bytes = Array(text.utf8)
    guard bytes.allSatisfy({ byte in
        (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57)
            || byte == 45 || byte == 95 || byte == 46 || (mode == .glob && (byte == 42 || byte == 63))
    }) else { throw .unsupportedRequest }
    if mode == .exact {
        let components = text.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count > 1, components.allSatisfy({ !$0.isEmpty }) else { throw .unsupportedRequest }
    }
    return text
}

private func entitlementFilterRequestWhitespace(_ byte: UInt8) -> Bool {
    byte == 32 || byte == 9 || byte == 10 || byte == 13
}

private func entitlementFilterIntegerSyntax(_ bytes: [UInt8]) -> Bool {
    guard !bytes.isEmpty else { return false }
    let start = bytes[0] == 43 || bytes[0] == 45 ? 1 : 0
    return start < bytes.count && bytes[start...].allSatisfy(entitlementFilterDecimalDigit)
}

private func entitlementFilterRealSyntax(_ bytes: [UInt8]) -> Bool {
    guard !bytes.isEmpty else { return false }
    var offset = bytes[0] == 43 || bytes[0] == 45 ? 1 : 0
    let integerStart = offset
    while offset < bytes.count, entitlementFilterDecimalDigit(bytes[offset]) { offset += 1 }
    let integerDigits = offset - integerStart
    var fractionalDigits = 0
    if offset < bytes.count, bytes[offset] == 46 {
        offset += 1
        let fractionalStart = offset
        while offset < bytes.count, entitlementFilterDecimalDigit(bytes[offset]) { offset += 1 }
        fractionalDigits = offset - fractionalStart
        guard fractionalDigits > 0 else { return false }
    }
    guard integerDigits + fractionalDigits > 0 else { return false }
    if offset < bytes.count, bytes[offset] == 69 || bytes[offset] == 101 {
        offset += 1
        if offset < bytes.count, bytes[offset] == 43 || bytes[offset] == 45 { offset += 1 }
        let exponentStart = offset
        while offset < bytes.count, entitlementFilterDecimalDigit(bytes[offset]) { offset += 1 }
        guard offset > exponentStart else { return false }
    }
    return offset == bytes.count
}

private func entitlementFilterDecimalDigit(_ byte: UInt8) -> Bool {
    byte >= 48 && byte <= 57
}
