import Foundation

enum FileKind: String, Codable, CaseIterable, Identifiable, Sendable {
    case machO
    case bundle
    case propertyList
    case other

    var id: String { rawValue }

    var title: String {
        switch self {
        case .machO: "Mach-O"
        case .bundle: "Bundle"
        case .propertyList: "Property List"
        case .other: "Raw File"
        }
    }

    var systemImage: String {
        switch self {
        case .machO: "cpu"
        case .bundle: "shippingbox"
        case .propertyList: "list.bullet.rectangle"
        case .other: "doc"
        }
    }
}

enum SignatureStatus: Codable, Hashable, Sendable {
    case valid
    case unsigned
    case invalid(code: Int32, message: String)
    case unavailable(code: Int32, message: String)

    var title: String {
        switch self {
        case .valid: "Intact"
        case .unsigned: "Unsigned"
        case .invalid: "Invalid"
        case .unavailable: "Unavailable"
        }
    }

    var detail: String? {
        switch self {
        case .valid, .unsigned:
            return nil
        case let .invalid(code, message), let .unavailable(code, message):
            return "OSStatus \(code): \(message)"
        }
    }
}

enum ResourceIntegrityStatus: Codable, Hashable, Sendable {
    case verified
    case notApplicable(reason: String)
    case invalid(code: Int32, message: String)
    case unavailable(code: Int32, message: String)

    var title: String {
        switch self {
        case .verified: "Verified"
        case .notApplicable: "Not applicable"
        case .invalid: "Invalid"
        case .unavailable: "Unavailable"
        }
    }

    var detail: String? {
        switch self {
        case .verified:
            return nil
        case let .notApplicable(reason):
            return reason
        case let .invalid(code, message), let .unavailable(code, message):
            return "OSStatus \(code): \(message)"
        }
    }

    var isProblem: Bool {
        switch self {
        case .invalid, .unavailable:
            return true
        case .verified, .notApplicable:
            return false
        }
    }
}

enum ExecutionPolicyStatus: String, Codable, Hashable, Sendable {
    case notAssessed
    case observedAllowed
    case observedDenied

    var title: String {
        switch self {
        case .notAssessed: "Not assessed"
        case .observedAllowed: "Observed allowed"
        case .observedDenied: "Observed denied"
        }
    }
}

struct ExecutionPolicyAssessment: Codable, Hashable, Sendable {
    let status: ExecutionPolicyStatus
    let detail: String
}

struct SourceOperatingSystem: Codable, Hashable, Sendable {
    let rootPath: String
    let productName: String
    let productVersion: String
    let buildVersion: String

    var displayValue: String {
        "\(productName) \(productVersion) (\(buildVersion))"
    }
}

struct MachOSlice: Codable, Hashable, Identifiable, Sendable {
    let architecture: String
    let fileOffset: UInt64
    let fileSize: UInt64
    let uuid: String?
    let platform: String?
    let minimumOSVersion: String?
    let sdkVersion: String?
    let codeSignatureOffset: UInt64?
    let codeSignatureSize: UInt64?

    var id: String {
        "\(architecture):\(fileOffset):\(uuid ?? "none")"
    }
}

enum EntitlementDeclarationScope: String, Codable, Hashable, Sendable {
    case declaredCodeSignature

    var title: String { "Declared in code signature" }
}

struct RuntimeAuthorizationAssessment: Codable, Hashable, Sendable {
    let status: ExecutionPolicyStatus
    let detail: String
}

struct ArchitectureEntitlements: Codable, Hashable, Identifiable, Sendable {
    let architecture: String
    let status: SignatureStatus
    let uniqueCDHash: String?
    let entitlements: [EntitlementEntry]
    let warnings: [String]

    var id: String { architecture }
}

enum CodeSignatureEntitlementFormat: String, Codable, Hashable, Sendable {
    case xml
    case der

    var title: String {
        switch self {
        case .xml: "XML entitlement slot"
        case .der: "DER entitlement slot"
        }
    }
}

struct CodeSignatureEntitlementSlot: Codable, Hashable, Identifiable, Sendable {
    let architecture: String
    let slotType: UInt32
    let format: CodeSignatureEntitlementFormat
    let fileOffset: UInt64
    let byteCount: Int
    let sha256: String
    let decodedEntitlements: [EntitlementEntry]
    let decoderSource: String
    let warning: String?

    var id: String { "\(architecture):\(slotType):\(fileOffset)" }
}

struct ArtifactProvenance: Codable, Hashable, Sendable {
    let analyzedPath: String
    let sha256: String
    let fileSize: Int64
    let createdAt: Date?
    let modifiedAt: Date?
    let ownerUserID: UInt32
    let ownerGroupID: UInt32
    let posixMode: UInt16
    let inode: UInt64
    let deviceID: UInt64
    let fileSystemFlags: UInt32
    let volumeName: String?
    let volumeUUID: String?
    let quarantineValue: String?
    let sourceOperatingSystem: SourceOperatingSystem?
    let hostOperatingSystem: SourceOperatingSystem
    let machOSlices: [MachOSlice]
}

enum CounterpartRelationship: String, Codable, Hashable, Sendable {
    case identical
    case different

    var title: String {
        switch self {
        case .identical: "Identical"
        case .different: "Different"
        }
    }
}

struct InstalledCounterpartComparison: Codable, Hashable, Sendable {
    let path: String
    let analyzedPath: String
    let relationship: CounterpartRelationship
    let sha256: String
    let signatureStatus: SignatureStatus
    let uniqueCDHash: String?
    let platformIdentifier: UInt32?
    let sourceOperatingSystem: SourceOperatingSystem?
    let machOSlices: [MachOSlice]
    let entitlementKeys: [String]
    let differences: [String]
}

struct EntitlementEntry: Codable, Hashable, Identifiable, Sendable {
    let key: String
    let value: EntitlementValue

    var id: String { key }
    var isPrivate: Bool { key.hasPrefix("com.apple.private.") }
}

enum EmbeddedObjectFormat: String, Codable, Sendable {
    case xmlPropertyList
    case binaryPropertyList
    case printableStrings

    var title: String {
        switch self {
        case .xmlPropertyList: "XML property list"
        case .binaryPropertyList: "Binary property list"
        case .printableStrings: "Printable-string matches"
        }
    }
}

struct RawStringMatch: Codable, Hashable, Identifiable, Sendable {
    let offset: Int
    let value: String

    var id: Int { offset }
}

struct EmbeddedObject: Codable, Hashable, Identifiable, Sendable {
    let id: UUID
    let offset: Int
    let length: Int
    let format: EmbeddedObjectFormat
    let confidence: Int
    let summary: String
    let entitlementKeys: [String]
    let stringMatches: [RawStringMatch]
}

struct SigningDetails: Codable, Hashable, Sendable {
    let status: SignatureStatus
    let resourceIntegrity: ResourceIntegrityStatus
    let executionPolicy: ExecutionPolicyAssessment
    let identifier: String?
    let teamIdentifier: String?
    let format: String?
    let source: String?
    let mainExecutable: String?
    let requirements: String?
    let signatureFlags: UInt32?
    let rawEntitlementsByteCount: Int?
    let uniqueCDHash: String?
    let cdHashes: [String]
    let platformIdentifier: UInt32?
    let signingTime: Date?
    let timestamp: Date?
    let authorities: [String]
    let entitlements: [EntitlementEntry]
    let entitlementScope: EntitlementDeclarationScope
    let runtimeAuthorization: RuntimeAuthorizationAssessment
    let architectureEntitlements: [ArchitectureEntitlements]
    let entitlementSlots: [CodeSignatureEntitlementSlot]
    let extractionWarnings: [String]
}

enum RunningBoardConfidence: String, Codable, Hashable, Sendable {
    case confirmedCurrent
    case appleCorrelated
    case buildScoped
    case inferred
    case unresolved

    var title: String {
        switch self {
        case .confirmedCurrent: "Confirmed current"
        case .appleCorrelated: "Apple correlated"
        case .buildScoped: "Build scoped"
        case .inferred: "Inferred"
        case .unresolved: "Unresolved"
        }
    }
}

struct RunningBoardPolicyReference: Codable, Hashable, Identifiable, Sendable {
    let domain: String
    let policy: String
    let sourcePath: String
    let objectPath: String
    let osBuild: String

    var id: String { "\(domain)/\(policy):\(objectPath):\(osBuild)" }
    var label: String { "\(domain)/\(policy)" }
}

struct RunningReasonDecoding: Codable, Hashable, Identifiable, Sendable {
    let rawValue: String
    let numericValue: Int64?
    let decodedLabel: String?
    let decoderSource: String
    let confidence: RunningBoardConfidence
    let installedPolicyReferences: [RunningBoardPolicyReference]

    var id: String { "\(rawValue):\(decodedLabel ?? "unresolved")" }
}

struct JetsamBandDecoding: Codable, Hashable, Identifiable, Sendable {
    let rawValue: Int
    let decodedLabel: String?
    let decoderSource: String
    let confidence: RunningBoardConfidence

    var id: Int { rawValue }
}

struct CPURoleDecoding: Codable, Hashable, Identifiable, Sendable {
    let rawValue: String
    let rbsNumericValue: Int?
    let rbsLabel: String?
    let darwinNumericValue: Int?
    let darwinLabel: String?
    let decoderSource: String
    let confidence: RunningBoardConfidence

    var id: String { rawValue }
}

struct CoalitionLevelDecoding: Codable, Hashable, Identifiable, Sendable {
    let rawValue: String
    let numericValue: Int?
    let decodedLabel: String?
    let decoderSource: String
    let confidence: RunningBoardConfidence

    var id: String { rawValue }
}

struct DurationPolicyDecoding: Codable, Hashable, Identifiable, Sendable {
    let rawStartPolicy: String?
    let startNumericValue: Int?
    let startLabel: String?
    let rawEndPolicy: String?
    let endNumericValue: Int?
    let endLabel: String?
    let warningDuration: Double?
    let invalidationDuration: Double?
    let decoderSource: String
    let confidence: RunningBoardConfidence

    var id: String {
        "\(rawStartPolicy ?? "none"): \(rawEndPolicy ?? "none"): \(warningDuration ?? -1): \(invalidationDuration ?? -1)"
    }
}

struct RunningBoardPolicyDecoding: Codable, Hashable, Identifiable, Sendable {
    let domain: String
    let policy: String
    let sourcePath: String
    let sourceFileHash: String
    let osBuild: String
    let originatorEntitlement: String?
    let runningReasons: [RunningReasonDecoding]
    let jetsamBands: [JetsamBandDecoding]
    let cpuRoles: [CPURoleDecoding]
    let coalitionLevels: [CoalitionLevelDecoding]
    let durationPolicies: [DurationPolicyDecoding]

    var id: String { "\(domain)/\(policy):\(sourceFileHash)" }
}

struct ScanFinding: Codable, Hashable, Identifiable, Sendable {
    let id: UUID
    let path: String
    let kind: FileKind
    let fileFormat: String
    let fileSize: Int64?
    let signing: SigningDetails?
    let provenance: ArtifactProvenance
    let installedCounterpart: InstalledCounterpartComparison?
    let runningBoardPolicies: [RunningBoardPolicyDecoding]
    let embeddedObjects: [EmbeddedObject]
    let warnings: [String]

    var name: String {
        URL(fileURLWithPath: path).lastPathComponent
    }

    var entitlementCount: Int {
        guard let signing else { return 0 }
        return distinctEntitlementKeys(entitlementSourceGroups(signing)).count
    }

    var privateEntitlementCount: Int {
        guard let signing else { return 0 }
        return distinctPrivateEntitlementKeys(entitlementSourceGroups(signing)).count
    }

    var hasSigningProblem: Bool {
        guard let signing else {
            return false
        }
        switch signing.status {
        case .valid:
            return signing.resourceIntegrity.isProblem
        case .invalid, .unsigned, .unavailable:
            return true
        }
    }
}

enum ScanIssueCategory: String, Codable, CaseIterable, Sendable {
    case skipped
    case posixPermissions
    case privacyProtection
    case systemPolicy
    case unavailable
    case fileProvider
    case analysis

    var title: String {
        switch self {
        case .skipped: "Skipped"
        case .posixPermissions: "POSIX permissions"
        case .privacyProtection: "Privacy protection"
        case .systemPolicy: "System policy"
        case .unavailable: "Unavailable item"
        case .fileProvider: "File provider"
        case .analysis: "Analysis"
        }
    }

    var systemImage: String {
        switch self {
        case .skipped: "forward.end"
        case .posixPermissions: "person.badge.key"
        case .privacyProtection: "hand.raised.fill"
        case .systemPolicy: "lock.shield.fill"
        case .unavailable: "questionmark.folder"
        case .fileProvider: "icloud.and.arrow.down"
        case .analysis: "exclamationmark.magnifyingglass"
        }
    }
}

enum ScanOperation: String, Codable, Sendable {
    case enumerateDirectory
    case readMetadata
    case classifyFile
    case analyzeFile

    var title: String {
        switch self {
        case .enumerateDirectory: "Enumerate directory"
        case .readMetadata: "Read metadata"
        case .classifyFile: "Classify file"
        case .analyzeFile: "Analyze file"
        }
    }
}

struct ScanIssue: Codable, Hashable, Identifiable, Sendable {
    let id: UUID
    let path: String
    let category: ScanIssueCategory
    let operation: ScanOperation
    let message: String
    let errorDomain: String
    let errorCode: Int
    let recoverySuggestion: String
    let privilegedRetryEligible: Bool
}

struct ScanConfiguration: Sendable {
    let roots: [URL]
    let includeHidden: Bool
    let deepCarve: Bool
    let maximumWorkerCount: Int
    let queueCapacity: Int
    let maximumCarveBytes: Int
    let excludedPathPrefixes: [URL]
}

struct ScanStatistics: Sendable {
    var discovered: Int = 0
    var machO: Int = 0
    var bundles: Int = 0
    var propertyLists: Int = 0
    var rawFiles: Int = 0
    var findings: Int = 0
    var issues: Int = 0
}

struct ScanUpdateBatch: Sendable {
    let discovered: Int
    let machO: Int
    let bundles: Int
    let propertyLists: Int
    let rawFiles: Int
    let findings: [ScanFinding]
    let issues: [ScanIssue]
}

enum ScanUpdate: Sendable {
    case batch(ScanUpdateBatch)
    case completed
    case cancelled
}

enum ResultFilter: String, CaseIterable, Hashable, Identifiable, Sendable {
    case all
    case entitlements
    case privateEntitlements
    case embeddedObjects
    case runningBoard
    case signingProblems

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all: "All Results"
        case .entitlements: "Entitlements"
        case .privateEntitlements: "Private Entitlements"
        case .embeddedObjects: "Embedded Objects"
        case .runningBoard: "RunningBoard"
        case .signingProblems: "Signing Problems"
        }
    }

    var systemImage: String {
        switch self {
        case .all: "tray.full"
        case .entitlements: "checkmark.seal"
        case .privateEntitlements: "lock.shield"
        case .embeddedObjects: "doc.badge.gearshape"
        case .runningBoard: "memorychip"
        case .signingProblems: "exclamationmark.triangle"
        }
    }
}
