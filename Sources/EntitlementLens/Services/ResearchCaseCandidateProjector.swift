import Foundation

enum ResearchCaseSampleKind: String, Codable, Hashable, Sendable {
    case controlledFixture = "controlled_fixture"
    case systemBinary = "system_binary"
    case reviewedScan = "reviewed_scan"
}

struct ResearchCaseCandidateMetadata: Hashable, Sendable {
    let caseID: String
    let sampleKind: ResearchCaseSampleKind
    let sourceReference: String
    let artifactLabel: String
    let sourceCommit: String
}

enum ResearchCaseCandidateError: LocalizedError {
    case invalidMetadata(String)
    case missingEvidence(String)
    case ineligibleEvidence(String)
    case unrepresentableDeclaration(String)

    var errorDescription: String? {
        switch self {
        case let .invalidMetadata(reason):
            "Research case metadata is invalid: \(reason)"
        case let .missingEvidence(reason):
            "The selected finding cannot become a research case: \(reason)"
        case let .ineligibleEvidence(reason):
            "The selected finding needs further review before a research case can be prepared: \(reason)"
        case let .unrepresentableDeclaration(reason):
            "An entitlement cannot be represented by public case schema v1: \(reason)"
        }
    }
}

enum ResearchCaseSignatureIntegrity: String, Encodable, Hashable, Sendable {
    case valid, invalid, unsigned, unavailable

    init(_ status: SignatureStatus) {
        switch status {
        case .valid: self = .valid
        case .invalid: self = .invalid
        case .unsigned: self = .unsigned
        case .unavailable: self = .unavailable
        }
    }
}

enum ResearchCaseDeclarationValue: Encodable, Hashable, Sendable {
    case boolean(Bool)
    case string(String)
    case integer(Int64)
    case real(Double)

    private enum CodingKeys: String, CodingKey { case type, boolean, string, integer, real }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .boolean(value):
            try container.encode("boolean", forKey: .type)
            try container.encode(value, forKey: .boolean)
        case let .string(value):
            try container.encode("string", forKey: .type)
            try container.encode(value, forKey: .string)
        case let .integer(value):
            try container.encode("integer", forKey: .type)
            try container.encode(value, forKey: .integer)
        case let .real(value):
            try container.encode("real", forKey: .type)
            try container.encode(value, forKey: .real)
        }
    }
}

struct ResearchCaseDeclaration: Encodable, Hashable, Sendable {
    let key: String
    let value: ResearchCaseDeclarationValue
}

struct ResearchCaseArchitecture: Encodable, Hashable, Sendable {
    let name: String
    let collectionState: StaticCollectionState
    let signatureIntegrity: ResearchCaseSignatureIntegrity
    let declarations: [ResearchCaseDeclaration]

    private enum CodingKeys: String, CodingKey {
        case name, declarations
        case collectionState = "collection_state"
        case signatureIntegrity = "signature_integrity"
    }
}

struct ResearchCaseCollector: Encodable, Hashable, Sendable {
    let name: String
    let sourceCommit: String
    let featureSchemaVersion: UInt16
    let collectedAtUTC: String
    let hostMacOSVersion: String
    let hostMacOSBuild: String

    private enum CodingKeys: String, CodingKey {
        case name
        case sourceCommit = "source_commit"
        case featureSchemaVersion = "feature_schema_version"
        case collectedAtUTC = "collected_at_utc"
        case hostMacOSVersion = "host_macos_version"
        case hostMacOSBuild = "host_macos_build"
    }
}

/// A local, single-artifact candidate. The caller must review the encoded record before sharing it.
struct ResearchCaseCandidate: Encodable, Hashable, Sendable {
    let schemaVersion: Int
    let caseID: String
    let sampleKind: ResearchCaseSampleKind
    let sourceReference: String
    let artifactLabel: String
    let artifactSHA256: String
    let collector: ResearchCaseCollector
    let signatureIntegrity: ResearchCaseSignatureIntegrity
    let entitlementCollectionState: StaticCollectionState
    let architectures: [ResearchCaseArchitecture]
    let evidenceScope: String
    let runtimeAuthorization: String

    private enum CodingKeys: String, CodingKey {
        case collector, architectures
        case schemaVersion = "schema_version"
        case caseID = "case_id"
        case sampleKind = "sample_kind"
        case sourceReference = "source_reference"
        case artifactLabel = "artifact_label"
        case artifactSHA256 = "artifact_sha256"
        case signatureIntegrity = "signature_integrity"
        case entitlementCollectionState = "entitlement_collection_state"
        case evidenceScope = "evidence_scope"
        case runtimeAuthorization = "runtime_authorization"
    }
}

/// Projects only complete architecture-qualified signed declarations. It performs no file access or source-commit verification.
enum ResearchCaseCandidateProjector {
    static func project(finding: ScanFinding, metadata: ResearchCaseCandidateMetadata) throws -> ResearchCaseCandidate {
        try validate(metadata)
        guard finding.kind == .machO else {
            throw ResearchCaseCandidateError.ineligibleEvidence("Choose one Mach-O finding; other file kinds need a different case format.")
        }
        guard let signing = finding.signing, let features = finding.staticFeatures else {
            throw ResearchCaseCandidateError.missingEvidence("Signing or versioned static-feature evidence is missing.")
        }
        guard finding.installedCounterpart == nil, finding.runningBoardPolicies.isEmpty,
              finding.embeddedObjects.isEmpty, finding.warnings.isEmpty,
              signing.extractionWarnings.isEmpty, signing.entitlementSlots.allSatisfy({ $0.warning == nil }) else {
            throw ResearchCaseCandidateError.ineligibleEvidence("The finding contains additional evidence or warnings that case schema v1 cannot retain. Use a focused scan without Deep carve and review its coverage.")
        }
        guard signing.executionPolicy.status == .notAssessed,
              signing.runtimeAuthorization.status == .notAssessed else {
            throw ResearchCaseCandidateError.ineligibleEvidence("Observed execution or runtime authorization cannot be represented by this static-only case.")
        }
        guard !signing.resourceIntegrity.isProblem else {
            throw ResearchCaseCandidateError.ineligibleEvidence("Resource-integrity problems cannot be represented separately from signature integrity.")
        }
        guard features.context.collector == "EntitlementLens",
              features.analyzedPath == finding.provenance.analyzedPath,
              features.artifactSHA256 == finding.provenance.sha256,
              features.context.hostOperatingSystem == finding.provenance.hostOperatingSystem,
              finding.provenance.sourceOperatingSystem == nil
                || finding.provenance.sourceOperatingSystem == finding.provenance.hostOperatingSystem,
              isLowercaseHex(finding.provenance.sha256, length: 64) else {
            throw ResearchCaseCandidateError.ineligibleEvidence("The collector, analyzed path, artifact digest, or operating-system context is inconsistent.")
        }
        do { try StaticResearchEvidenceValidator.validate(finding) }
        catch let error as StaticResearchConsumerError {
            switch error {
            case let .invalidEvidence(_, reason):
                throw ResearchCaseCandidateError.ineligibleEvidence("Recorded static evidence is inconsistent: \(reason)")
            case .invalidExport, .invalidSources:
                throw error
            }
        }
        guard features.architectures.state == .complete,
              features.architectures.reason == nil,
              features.architectures.limitations.isEmpty,
              features.entitlements.state == .complete,
              features.entitlements.reason == nil,
              features.entitlements.limitations.isEmpty,
              features.entitlements.limits.isEmpty,
              caseComplete(signing.entitlementCollectionState) else {
            throw ResearchCaseCandidateError.ineligibleEvidence("Architecture or entitlement collection is incomplete, limited, or lacks a recorded completion state.")
        }
        let slices = finding.provenance.machOSlices
        let groups = signing.architectureEntitlements
        guard !slices.isEmpty, slices.count <= 16, groups.count == slices.count,
              features.architectures.records.count == slices.count,
              Set(slices.map(\.architecture)).count == slices.count,
              Set(groups.map(\.architecture)).count == groups.count,
              Set(features.architectures.records.map(\.slice.architecture)) == Set(slices.map(\.architecture)),
              Set(groups.map(\.architecture)) == Set(slices.map(\.architecture)),
              Set(signing.entitlementSlots.map(\.architecture)).isSubset(of: Set(groups.map(\.architecture))) else {
            throw ResearchCaseCandidateError.ineligibleEvidence("Each collected architecture and entitlement slot must map uniquely to one recorded Mach-O slice.")
        }
        let standard = features.entitlements.records.filter { if case .standardDictionary = $0.source { true } else { false } }
        guard standard.count == 1, standard[0].state == .complete,
              standard[0].reason == nil, standard[0].signatureIntegrity == signing.status,
              equalEntries(standard[0].values, signing.entitlements),
              features.entitlements.records.count == groups.count + 1 else {
            throw ResearchCaseCandidateError.ineligibleEvidence("The unscoped and architecture-qualified entitlement evidence is inconsistent or cannot be represented without loss.")
        }
        var architectures: [ResearchCaseArchitecture] = []
        for group in groups {
            guard caseComplete(group.collectionState), group.warnings.isEmpty else {
                throw ResearchCaseCandidateError.ineligibleEvidence("An architecture has incomplete entitlement collection or warnings.")
            }
            let records = features.entitlements.records.filter {
                if case let .architecture(name) = $0.source { name == group.architecture } else { false }
            }
            guard records.count == 1, records[0].state == .complete, records[0].reason == nil,
                  records[0].signatureIntegrity == group.status,
                  equalEntries(records[0].values, group.entitlements),
                  records[0].slots.allSatisfy({ $0.warning == nil }) else {
                throw ResearchCaseCandidateError.ineligibleEvidence("An architecture's retained entitlement evidence is incomplete or inconsistent.")
            }
            let signedSlots = signing.entitlementSlots.filter { $0.architecture == group.architecture }
            guard records[0].slots.count == signedSlots.count,
                  Set(records[0].slots).count == records[0].slots.count,
                  Set(signedSlots).count == signedSlots.count,
                  Set(records[0].slots) == Set(signedSlots),
                  records[0].slots.allSatisfy({ equalEntries($0.decodedEntitlements, group.entitlements) }) else {
                throw ResearchCaseCandidateError.ineligibleEvidence("An entitlement slot differs from the architecture's signed declaration dictionary.")
            }
            let declarations = try group.entitlements.map(declaration).sorted { $0.key < $1.key }
            guard declarations.count <= 256 else {
                throw ResearchCaseCandidateError.unrepresentableDeclaration("An architecture exceeds the 256-declaration limit.")
            }
            architectures.append(ResearchCaseArchitecture(
                name: try architectureName(group.architecture), collectionState: .complete,
                signatureIntegrity: ResearchCaseSignatureIntegrity(group.status), declarations: declarations
            ))
        }
        guard architectures.contains(where: { equalDeclarations($0.declarations, standard[0].values) }) else {
            throw ResearchCaseCandidateError.ineligibleEvidence("The unscoped dictionary contains declarations not retained in any architecture.")
        }
        let host = features.context.hostOperatingSystem
        guard host.productName == "macOS", validMacOSVersion(host.productVersion),
              !host.buildVersion.isEmpty, host.buildVersion.utf8.allSatisfy(isASCIIAlphaNumeric),
              features.context.collectedAt.timeIntervalSince1970.isFinite else {
            throw ResearchCaseCandidateError.ineligibleEvidence("The recorded collection time or macOS version/build cannot be represented by the public schema.")
        }
        let date = ISO8601DateFormatter().string(from: features.context.collectedAt)
        return ResearchCaseCandidate(
            schemaVersion: 1, caseID: metadata.caseID, sampleKind: metadata.sampleKind,
            sourceReference: metadata.sourceReference, artifactLabel: metadata.artifactLabel,
            artifactSHA256: finding.provenance.sha256,
            collector: ResearchCaseCollector(name: "EntitlementLens", sourceCommit: metadata.sourceCommit,
                featureSchemaVersion: features.schemaVersion.rawValue, collectedAtUTC: date,
                hostMacOSVersion: host.productVersion, hostMacOSBuild: host.buildVersion),
            signatureIntegrity: ResearchCaseSignatureIntegrity(signing.status), entitlementCollectionState: .complete,
            architectures: architectures, evidenceScope: "static_signed_declarations", runtimeAuthorization: "not_assessed"
        )
    }

    static func jsonData(for candidate: ResearchCaseCandidate) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(candidate)
    }

    private static func validate(_ metadata: ResearchCaseCandidateMetadata) throws {
        let parts = metadata.caseID.split(separator: "-", omittingEmptySubsequences: false)
        guard !metadata.caseID.isEmpty, metadata.caseID.utf8.count <= 100,
              parts.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy(isASCIILowercaseOrDigit) }) else {
            throw ResearchCaseCandidateError.invalidMetadata("Case ID must be lowercase ASCII words joined by hyphens, at most 100 bytes.")
        }
        guard safeLabel(metadata.sourceReference, maximum: 140) else {
            throw ResearchCaseCandidateError.invalidMetadata("Source reference must use 1–140 ASCII letters, digits, spaces, periods, underscores, or hyphens.")
        }
        guard safeLabel(metadata.artifactLabel, maximum: 80) else {
            throw ResearchCaseCandidateError.invalidMetadata("Artifact label must use 1–80 ASCII letters, digits, spaces, periods, underscores, or hyphens.")
        }
        guard isLowercaseHex(metadata.sourceCommit, length: 40) else {
            throw ResearchCaseCandidateError.invalidMetadata("Source commit must be the exact 40-character lowercase Git SHA of the collector source.")
        }
    }

    private static func declaration(_ entry: EntitlementEntry) throws -> ResearchCaseDeclaration {
        guard !entry.key.isEmpty, entry.key.utf8.count <= 256,
              entry.key.utf8.allSatisfy({ isASCIIAlphaNumeric($0) || [45, 46, 95].contains($0) }) else {
            throw ResearchCaseCandidateError.unrepresentableDeclaration("A key contains unsupported characters or exceeds 256 bytes.")
        }
        let value: ResearchCaseDeclarationValue
        switch entry.value {
        case let .boolean(item): value = .boolean(item)
        case let .integer(item): value = .integer(item)
        case let .real(item):
            guard item.isFinite else {
                throw ResearchCaseCandidateError.unrepresentableDeclaration("A real value is not finite.")
            }
            value = .real(item)
        case let .string(item):
            guard item.utf8.count <= 512,
                  item.utf8.allSatisfy({ isASCIIAlphaNumeric($0) || [32, 45, 46, 95].contains($0) }) else {
                throw ResearchCaseCandidateError.unrepresentableDeclaration("A string value contains path-like or unrestricted characters, or exceeds 512 bytes.")
            }
            value = .string(item)
        case .data, .date, .array, .dictionary:
            throw ResearchCaseCandidateError.unrepresentableDeclaration("Data, dates, arrays, and dictionaries are not supported by public case schema v1.")
        }
        return ResearchCaseDeclaration(key: entry.key, value: value)
    }

    private static func architectureName(_ name: String) throws -> String {
        guard !name.isEmpty, name.utf8.count <= 40,
              name.utf8.allSatisfy({ isASCIIAlphaNumeric($0) || [46, 95].contains($0) }) else {
            throw ResearchCaseCandidateError.ineligibleEvidence("An architecture name is outside the public schema.")
        }
        return name
    }

    private static func caseComplete(_ state: EntitlementCollectionState?) -> Bool {
        if case .complete? = state { return true }
        return false
    }

    private static func equalEntries(_ lhs: [EntitlementEntry], _ rhs: [EntitlementEntry]) -> Bool {
        Set(lhs.map(\.key)).count == lhs.count && Set(rhs.map(\.key)).count == rhs.count
            && Set(lhs) == Set(rhs)
    }

    private static func equalDeclarations(_ declarations: [ResearchCaseDeclaration], _ entries: [EntitlementEntry]) -> Bool {
        guard let projected = try? entries.map(declaration) else { return false }
        return Set(declarations) == Set(projected)
    }

    private static func validMacOSVersion(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return (2...3).contains(parts.count) && parts.allSatisfy { !$0.isEmpty && $0.utf8.allSatisfy(isASCIIDigit) }
    }

    private static func safeLabel(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum && value.utf8.allSatisfy {
            isASCIIAlphaNumeric($0) || [32, 45, 46, 95].contains($0)
        }
    }

    private static func isLowercaseHex(_ value: String, length: Int) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy { isASCIIDigit($0) || (97...102).contains($0) }
    }

    private static func isASCIIDigit(_ byte: UInt8) -> Bool { (48...57).contains(byte) }
    private static func isASCIILowercaseOrDigit(_ byte: UInt8) -> Bool {
        isASCIIDigit(byte) || (97...122).contains(byte)
    }
    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        isASCIILowercaseOrDigit(byte) || (65...90).contains(byte)
    }
}
