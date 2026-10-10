import Foundation

enum StaticSigningMode: String, Codable, Hashable, Sendable {
    case certificateBacked = "certificate_backed"
    case adHoc = "ad_hoc"
    case unsigned
    case unavailable
}

struct StaticNativeCodeDirectoryHash: Codable, Hashable, Sendable {
    let hashType: UInt32
    let value: String

    enum CodingKeys: String, CodingKey {
        case hashType = "hash_type"
        case value
    }
}

/// Signing identity and native integrity are independent of certificate trust and execution policy.
struct StaticSigner: Codable, Hashable, Sendable {
    let location: StaticEvidenceLocation
    let signingIdentifier: String?
    let teamIdentifier: String?
    let mode: StaticSigningMode
    let signatureFlags: UInt32?
    let signatureIntegrity: SignatureStatus
    let selectedCDHash: String?
    let nativeCDHashes: [StaticNativeCodeDirectoryHash]
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case location, mode, warnings
        case signingIdentifier = "signing_identifier"
        case teamIdentifier = "team_id"
        case signatureFlags = "signature_flags"
        case signatureIntegrity = "signature_integrity"
        case selectedCDHash = "selected_cdhash"
        case nativeCDHashes = "native_cdhashes"
    }
}

struct StaticCertificateNameField: Codable, Hashable, Sendable {
    let oid: String
    let value: String
}

enum StaticCertificateSource: String, Codable, Hashable, Sendable {
    case cmsEmbedded = "cms_embedded"
}

/// CMS order is native decoder enumeration order. Chain order is a DER fingerprint match
/// against Security.framework's chain, whose contents may include nonembedded certificates.
struct StaticCertificate: Codable, Hashable, Sendable {
    let location: StaticEvidenceLocation
    let source: StaticCertificateSource
    let cmsIndex: Int
    let chainIndex: Int?
    let derSHA256: String
    let derByteCount: Int
    let subjectSummary: String?
    let subject: [StaticCertificateNameField]
    let issuer: [StaticCertificateNameField]
    let serialNumber: String?
    let notBefore: Date?
    let notAfter: Date?
    let metadataState: StaticCollectionState
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case location, source, subject, issuer, warnings
        case cmsIndex = "cms_index"
        case chainIndex = "chain_index"
        case derSHA256 = "der_sha256"
        case derByteCount = "der_byte_count"
        case subjectSummary = "subject_summary"
        case serialNumber = "serial_number"
        case notBefore = "not_before"
        case notAfter = "not_after"
        case metadataState = "metadata_state"
    }
}

enum StaticCodeDirectoryKind: String, Codable, Hashable, Sendable {
    case primary
    case alternate
}

enum StaticCodeDirectoryHashAlgorithm: String, Codable, Hashable, Sendable {
    case sha1
    case sha256
    case sha256Truncated = "sha256_truncated"
    case sha384
}

/// The digest covers the CodeDirectory blob itself. The CDHash is its first 20 bytes;
/// SHA-256-truncated uses a 20-byte digest. Neither value is a whole-file hash.
struct StaticComputedCodeDirectoryHash: Codable, Hashable, Sendable {
    let algorithm: StaticCodeDirectoryHashAlgorithm
    let digest: String
    let cdHash: String

    enum CodingKeys: String, CodingKey {
        case algorithm, digest
        case cdHash = "cdhash"
    }
}

/// Internal offsets are relative to this CodeDirectory's start; location.fileOffset is absolute.
/// A page-size exponent of zero denotes an unpaged signature and has no pageSizeBytes value.
struct StaticCodeDirectory: Codable, Hashable, Sendable {
    let location: StaticEvidenceLocation
    let slotType: UInt32
    let kind: StaticCodeDirectoryKind
    let length: UInt32
    let version: UInt32
    let versionSupported: Bool
    let flags: UInt32
    let signingIdentifier: String
    let teamIdentifier: String?
    let hashType: UInt8
    let hashSize: UInt8
    let hashOffset: UInt32
    let identifierOffset: UInt32
    let teamOffset: UInt32?
    let scatterOffset: UInt32?
    let preEncryptOffset: UInt32?
    let specialSlotCount: UInt32
    let codeSlotCount: UInt32
    let pageSizeExponent: UInt8
    let pageSizeBytes: UInt64?
    let platform: UInt8
    let codeLimit: UInt32
    let codeLimit64: UInt64?
    let effectiveCodeLimit: UInt64
    let computedHash: StaticComputedCodeDirectoryHash?
    let nativeCDHash: String?
    let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case location, kind, length, version, flags, platform, warnings
        case slotType = "slot_type"
        case versionSupported = "version_supported"
        case signingIdentifier = "signing_identifier"
        case teamIdentifier = "team_id"
        case hashType = "hash_type"
        case hashSize = "hash_size"
        case hashOffset = "hash_offset"
        case identifierOffset = "identifier_offset"
        case teamOffset = "team_offset"
        case scatterOffset = "scatter_offset"
        case preEncryptOffset = "pre_encrypt_offset"
        case specialSlotCount = "special_slot_count"
        case codeSlotCount = "code_slot_count"
        case pageSizeExponent = "page_size_exponent"
        case pageSizeBytes = "page_size_bytes"
        case codeLimit = "code_limit"
        case codeLimit64 = "code_limit_64"
        case effectiveCodeLimit = "effective_code_limit"
        case computedHash = "computed_hash"
        case nativeCDHash = "native_cdhash"
    }
}

struct SignatureStaticInspection: Sendable {
    let signer: StaticFeatureCollection<StaticSigner>
    let embeddedCertificates: StaticFeatureCollection<StaticCertificate>
    let codeDirectories: StaticFeatureCollection<StaticCodeDirectory>
}
