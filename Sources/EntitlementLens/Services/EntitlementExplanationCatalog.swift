import Foundation

/// Validated, immutable local references. Catalog revisioning does not change static-feature schema v3.
struct EntitlementExplanationCatalog: Sendable {
    let schemaVersion: Int
    let revision: String
    let reviewedOn: String
    let records: [EntitlementExplanation]
    private let recordsByKey: [String: EntitlementExplanation]

    init(
        schemaVersion: Int,
        revision: String,
        reviewedOn: String,
        records: [EntitlementExplanation]
    ) throws(EntitlementExplanationCatalogError) {
        guard schemaVersion == 1 else {
            throw .invalidSchemaVersion(schemaVersion)
        }
        guard !revision.isEmpty, revision.utf8.count <= 64,
              revision.utf8.allSatisfy(entitlementExplanationIdentifierByte) else {
            throw .invalidRevision
        }
        guard entitlementExplanationReviewDateIsValid(reviewedOn) else {
            throw .invalidReviewDate(reviewedOn)
        }
        guard !records.isEmpty else { throw .emptyRecords }
        var indexed: [String: EntitlementExplanation] = [:]
        for record in records {
            try validateEntitlementExplanation(record)
            guard indexed[record.key] == nil else { throw .duplicateKey(record.key) }
            indexed[record.key] = record
        }
        self.schemaVersion = schemaVersion
        self.revision = revision
        self.reviewedOn = reviewedOn
        self.records = records.sorted { $0.key < $1.key }
        self.recordsByKey = indexed
    }

    /// Matching is exact and case sensitive; unknown keys receive no prefix or alias inference.
    func lookup(key: String) -> EntitlementExplanationLookup {
        if let record = recordsByKey[key] {
            return .available(record)
        }
        return .unavailable(key: key)
    }

    static func bundled() throws(EntitlementExplanationCatalogError) -> EntitlementExplanationCatalog {
        try EntitlementExplanationCatalog(
            schemaVersion: 1,
            revision: "2026-10-11.1",
            reviewedOn: "2026-10-11",
            records: [
                EntitlementExplanation(
                    key: "com.apple.security.app-sandbox",
                    title: "App Sandbox",
                    summary: "A true value declares App Sandbox configuration for a macOS executable, which constrains access to system and user resources.",
                    valueShape: .boolean,
                    contextLimits: [
                        "macOS App Sandbox configuration is applied per executable target. Resource-specific sandbox entitlements describe additional declarations."
                    ],
                    sources: [
                        try appleEntitlementDocumentationSource(
                            key: "com.apple.security.app-sandbox", title: "Apple entitlement reference",
                            path: "bundleresources/entitlements/com.apple.security.app-sandbox"
                        ),
                        try appleEntitlementDocumentationSource(
                            key: "com.apple.security.app-sandbox", title: "Protecting user data with App Sandbox",
                            path: "security/protecting-user-data-with-app-sandbox"
                        )
                    ]
                ),
                try booleanExplanation(
                    key: "com.apple.security.network.client",
                    title: "Outgoing network connections",
                    summary: "A true value requests outgoing network connections from a sandboxed macOS app, including connections to a server on the same machine.",
                    contextLimits: [
                        "For TCP, the client and server entitlements govern connection initiation; either kind of established connection can send and receive data.",
                        "For UDP, these declarations also govern data flow. Apple describes client-only configuration as permitting sending, while UDP apps usually need both network entitlements."
                    ]
                ),
                try booleanExplanation(
                    key: "com.apple.security.network.server",
                    title: "Incoming network connections",
                    summary: "A true value requests listening for incoming network connections in a sandboxed macOS app.",
                    contextLimits: [
                        "For TCP, client and server entitlements govern connection initiation rather than the direction of subsequent data.",
                        "For UDP, Apple describes server-only configuration as permitting receiving rather than sending. UDP apps usually need both network entitlements."
                    ]
                ),
                try booleanExplanation(
                    key: "com.apple.security.files.user-selected.read-only",
                    title: "Read user-selected files",
                    summary: "A true value requests read-only sandbox access to files the user selects through an Open or Save dialog.",
                    contextLimits: [
                        "This macOS App Sandbox declaration concerns user-selected files; it is not a declaration of unrestricted file access."
                    ]
                ),
                try booleanExplanation(
                    key: "com.apple.security.files.user-selected.read-write",
                    title: "Read and write user-selected files",
                    summary: "A true value requests read and write sandbox access to files the user selects through an Open or Save dialog.",
                    contextLimits: [
                        "This macOS App Sandbox declaration concerns user-selected files; it does not identify which files were selected or accessed."
                    ]
                ),
                EntitlementExplanation(
                    key: "com.apple.security.get-task-allow",
                    title: "Allow debugger attachment",
                    summary: "A true value declares the target-side macOS debugging allowance for a debugger to attach during development.",
                    valueShape: .boolean,
                    contextLimits: [
                        "Apple documents development and plug-in debugging uses, and standard Xcode distribution workflows that remove this declaration. Its separate notarization guidance excludes a true value.",
                        "This target-side allowance is distinct from com.apple.security.cs.debugger on the debugging tool. Static inspection does not establish that any debugger attached."
                    ],
                    sources: [
                        try appleEntitlementDocumentationSource(
                            key: "com.apple.security.get-task-allow",
                            title: "Creating distribution-signed code for macOS",
                            path: "xcode/creating-distribution-signed-code-for-the-mac"
                        ),
                        try appleEntitlementDocumentationSource(
                            key: "com.apple.security.get-task-allow",
                            title: "Resolving common notarization issues",
                            path: "security/resolving-common-notarization-issues"
                        ),
                        try appleEntitlementDocumentationSource(
                            key: "com.apple.security.get-task-allow",
                            title: "Notarizing macOS software before distribution",
                            path: "security/notarizing-macos-software-before-distribution"
                        )
                    ]
                ),
                EntitlementExplanation(
                    key: "com.apple.security.cs.allow-jit",
                    title: "Allow JIT-compiled code",
                    summary: "A true value requests the Hardened Runtime exception for writable and executable memory created using MAP_JIT.",
                    valueShape: .boolean,
                    contextLimits: [
                        "Apple documents this exception for macOS apps that adopt Hardened Runtime. It does not establish that the inspected executable creates or executes JIT code.",
                        "MAP_JIT and Apple silicon memory-protection requirements still depend on the platform and implementation."
                    ],
                    sources: [
                        try appleEntitlementDocumentationSource(
                            key: "com.apple.security.cs.allow-jit", title: "Apple entitlement reference",
                            path: "bundleresources/entitlements/com.apple.security.cs.allow-jit"
                        ),
                        try appleEntitlementDocumentationSource(
                            key: "com.apple.security.cs.allow-jit", title: "Porting just-in-time compilers to Apple silicon",
                            path: "apple-silicon/porting-just-in-time-compilers-to-apple-silicon"
                        )
                    ]
                ),
                try booleanExplanation(
                    key: "com.apple.security.cs.allow-unsigned-executable-memory",
                    title: "Allow unsigned executable memory",
                    summary: "A true value requests the Hardened Runtime exception for writable and executable memory without the restrictions of MAP_JIT.",
                    contextLimits: [
                        "Apple documents this macOS exception for particular compatibility cases and recommends considering whether the exception is needed. Its presence does not show memory was created or executed."
                    ]
                ),
                try booleanExplanation(
                    key: "com.apple.security.cs.disable-library-validation",
                    title: "Disable library validation",
                    summary: "A true value requests a Hardened Runtime exception to the library-validation rule that normally accepts Apple-signed code or code signed with the executable's Team ID.",
                    contextLimits: [
                        "Apple describes this macOS exception for programs that load third-party plug-ins. It does not identify a library loaded at runtime or prove that other platform checks accepted that library."
                    ]
                ),
                try booleanExplanation(
                    key: "com.apple.security.cs.debugger",
                    title: "Debugging tool",
                    summary: "A true value declares the macOS executable as a debugging tool that requests attaching to other processes or obtaining task ports.",
                    contextLimits: [
                        "Apple documents target-side get-task-allow and System Integrity Protection restrictions, along with administrator authorization for a non-root user. The tool-side declaration alone does not authorize every target.",
                        "This is distinct from com.apple.security.get-task-allow in the program being debugged. Static inspection does not show attachment or authorization succeeded."
                    ]
                )
            ]
        )
    }
}

private func booleanExplanation(
    key: String,
    title: String,
    summary: String,
    contextLimits: [String]
) throws(EntitlementExplanationCatalogError) -> EntitlementExplanation {
    EntitlementExplanation(
        key: key, title: title, summary: summary, valueShape: .boolean,
        contextLimits: contextLimits,
        sources: [try appleEntitlementDocumentationSource(
            key: key, title: "Apple entitlement reference",
            path: "bundleresources/entitlements/\(key)"
        )]
    )
}

private func appleEntitlementDocumentationSource(
    key: String,
    title: String,
    path: String
) throws(EntitlementExplanationCatalogError) -> EntitlementExplanationSource {
    let address = "https://developer.apple.com/documentation/\(path)"
    guard let url = URL(string: address) else {
        throw .invalidSourceURL(key: key, url: address)
    }
    return EntitlementExplanationSource(title: title, url: url)
}

private func validateEntitlementExplanation(
    _ record: EntitlementExplanation
) throws(EntitlementExplanationCatalogError) {
    guard record.key.hasPrefix("com.apple."), record.key.utf8.count <= 256,
          record.key.utf8.allSatisfy(entitlementExplanationIdentifierByte),
          record.key.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty }) else {
        throw .invalidKey(record.key)
    }
    try validateEntitlementExplanationText(record.title, key: record.key, field: .title, maximumBytes: 160)
    try validateEntitlementExplanationText(record.summary, key: record.key, field: .summary, maximumBytes: 1_000)
    guard !record.contextLimits.isEmpty else { throw .missingContextLimits(key: record.key) }
    for limit in record.contextLimits {
        try validateEntitlementExplanationText(limit, key: record.key, field: .contextLimit, maximumBytes: 1_000)
    }
    guard !record.sources.isEmpty else { throw .missingSources(key: record.key) }
    var urls: Set<URL> = []
    for source in record.sources {
        try validateEntitlementExplanationText(source.title, key: record.key, field: .sourceTitle, maximumBytes: 160)
        let url = source.url
        guard url.absoluteString.utf8.count <= 2_048, url.scheme == "https",
              url.host == "developer.apple.com", url.port == nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.hasPrefix("/documentation/") || url.path.hasPrefix("/library/archive/") else {
            throw .invalidSourceURL(key: record.key, url: url.absoluteString)
        }
        guard urls.insert(url).inserted else {
            throw .duplicateSourceURL(key: record.key, url: url.absoluteString)
        }
    }
}

private func validateEntitlementExplanationText(
    _ text: String,
    key: String,
    field: EntitlementExplanationTextField,
    maximumBytes: Int
) throws(EntitlementExplanationCatalogError) {
    guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          text.utf8.count <= maximumBytes,
          !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
        throw .invalidText(key: key, field: field)
    }
}

private func entitlementExplanationIdentifierByte(_ byte: UInt8) -> Bool {
    (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte)
        || byte == 45 || byte == 46 || byte == 95
}

private func entitlementExplanationReviewDateIsValid(_ date: String) -> Bool {
    guard date.utf8.count == 10 else { return false }
    let bytes = Array(date.utf8)
    guard bytes[4] == 45, bytes[7] == 45,
          bytes.enumerated().allSatisfy({ index, byte in
              index == 4 || index == 7 || (48...57).contains(byte)
          }),
          let year = Int(date.prefix(4)), let month = Int(date.dropFirst(5).prefix(2)),
          let day = Int(date.suffix(2)), year > 0, (1...12).contains(month) else {
        return false
    }
    let leapYear = year.isMultiple(of: 400) || (year.isMultiple(of: 4) && !year.isMultiple(of: 100))
    let days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return (1...days[month - 1]).contains(day)
}
