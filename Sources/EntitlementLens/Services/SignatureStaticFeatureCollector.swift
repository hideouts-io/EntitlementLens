import Foundation
import Security

/// Read-only native signing information is collected for each named Mach-O architecture.
/// CMS decoding is separate from the existing integrity assessment and never evaluates trust.
enum SignatureStaticFeatureCollector {
    private static let maximumArchitectureScopes = 1_024
    private static let maximumStringBytes = 65_536
    private static let maximumDigestRecords = 6
    private static let maximumDigestBytes = 64
    private static let signerLimits: [StaticCollectionLimit] = [
        StaticCollectionLimit(name: "signer_architecture_scopes", value: UInt64(maximumArchitectureScopes), unit: .records),
        StaticCollectionLimit(name: "signer_string_bytes", value: UInt64(maximumStringBytes), unit: .bytes),
        StaticCollectionLimit(name: "native_cdhash_records", value: UInt64(maximumDigestRecords), unit: .records),
        StaticCollectionLimit(name: "native_cdhash_bytes", value: UInt64(maximumDigestBytes), unit: .bytes)
    ]

    private struct NativeSigningInformation {
        let identifier: String?
        let teamIdentifier: String?
        let flags: UInt32?
        let selectedHash: String?
        let hashes: [StaticNativeCodeDirectoryHash]
        let certificates: [SecCertificate]
        let cms: Data?
    }

    private struct ScopeInspection {
        let signer: StaticSigner?
        let signerFailure: String?
        let certificates: StaticFeatureCollection<StaticCertificate>
    }

    private enum SignatureRegionPresence {
        case absent
        case declared
        case unavailable
    }

    static func inspect(
        sourceURL: URL, analyzedURL: URL, signing: SigningDetails, slices: [MachOSlice]
    ) throws -> SignatureStaticInspection {
        try Task.checkCancellation()
        var scopes: [ScopeInspection] = []
        var scopeFailures: [String] = []
        if slices.isEmpty {
            scopes.append(try inspectStandard(sourceURL: sourceURL, analyzedURL: analyzedURL, signing: signing))
        } else {
            for slice in slices.prefix(maximumArchitectureScopes) {
                try Task.checkCancellation()
                if slices.filter({ $0.architecture == slice.architecture }).count > 1 {
                    let reason = "Architecture name \(slice.architecture) appears in multiple slices; Security.framework's name selector cannot establish a unique slice association."
                    scopeFailures.append(reason)
                    continue
                }
                scopes.append(try inspectSlice(analyzedURL: analyzedURL, signing: signing, slice: slice))
            }
            if slices.count > maximumArchitectureScopes {
                scopeFailures.append("The \(slices.count) architectures exceed the \(maximumArchitectureScopes)-scope native signing collection limit.")
            }
        }
        let signers = scopes.compactMap(\.signer)
        let signerFailures = scopeFailures + scopes.compactMap(\.signerFailure)
        let signerWarnings = signers.flatMap(\.warnings)
        let signerCollection = StaticFeatureCollection(
            state: signerFailures.isEmpty && signerWarnings.isEmpty ? .complete : (signers.isEmpty ? .unavailable : .partial),
            reason: signerFailures.first ?? signerWarnings.first,
            records: signers, limitations: [
                "Signing mode and identifier are static declarations; they do not establish certificate trust or runtime authorization.",
                "Signature integrity is separate from certificate metadata. Native integrity checks do not validate bundle resources here."
            ] + signerFailures + signerWarnings, limits: signerLimits)
        let certificateRecords = scopes.flatMap { $0.certificates.records }
        let certificateFailures = scopeFailures + scopes.filter { $0.certificates.state != .complete }
            .compactMap { $0.certificates.reason }
        let certificateCollection = StaticFeatureCollection(
            state: certificateFailures.isEmpty ? .complete : (certificateRecords.isEmpty ? .unavailable : .partial),
            reason: certificateFailures.first, records: certificateRecords,
            limitations: Array(Set(scopes.flatMap { $0.certificates.limitations })).sorted() + scopeFailures,
            limits: signerLimits.prefix(1) + StaticCertificateInspector.limits)
        let directories = try StaticCodeDirectoryParser.inspect(analyzedURL: analyzedURL, slices: slices, signers: signers)
        return SignatureStaticInspection(signer: signerCollection,
            embeddedCertificates: certificateCollection, codeDirectories: directories)
    }

    private static func inspectStandard(
        sourceURL: URL, analyzedURL: URL, signing: SigningDetails
    ) throws -> ScopeInspection {
        let location = StaticEvidenceLocation(sourcePath: analyzedURL.path, architecture: nil, sliceOffset: nil,
            fileOffset: nil, byteCount: nil, propertyListKey: nil, method: .securityFramework)
        var code: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(sourceURL as CFURL, SecCSFlags(rawValue: 0), &code)
        guard status == errSecSuccess, let code else {
            return unavailableScope(operation: "SecStaticCodeCreateWithPath", status: status, location: location)
        }
        return try inspectCode(code: code, location: location, integrity: signing.status, signatureRegion: .unavailable)
    }

    private static func inspectSlice(
        analyzedURL: URL, signing: SigningDetails, slice: MachOSlice
    ) throws -> ScopeInspection {
        let location = StaticEvidenceLocation(sourcePath: analyzedURL.path, architecture: slice.architecture,
            sliceOffset: slice.fileOffset, fileOffset: nil, byteCount: nil, propertyListKey: nil, method: .securityFramework)
        let attributes: [String: String] = [kSecCodeAttributeArchitecture as String: slice.architecture]
        var code: SecStaticCode?
        let status = SecStaticCodeCreateWithPathAndAttributes(analyzedURL as CFURL, SecCSFlags(rawValue: 0),
            attributes as CFDictionary, &code)
        guard status == errSecSuccess, let code else {
            return unavailableScope(operation: "SecStaticCodeCreateWithPathAndAttributes", status: status, location: location)
        }
        let declarations = signing.architectureEntitlements.filter { $0.architecture == slice.architecture }
        let integrity: SignatureStatus
        if declarations.count == 1, let declaration = declarations.first {
            integrity = declaration.status
        } else {
            try Task.checkCancellation()
            let validity = SecStaticCodeCheckValidity(code,
                SecCSFlags(rawValue: kSecCSDoNotValidateResources).union(.noNetworkAccess), nil)
            if validity == errSecSuccess {
                integrity = .valid
            } else if validity == errSecCSUnsigned {
                integrity = .unsigned
            } else {
                integrity = .invalid(code: validity, message: OSStatusMessage.describe(validity))
            }
        }
        let signatureRegion: SignatureRegionPresence = slice.codeSignatureOffset != nil || slice.codeSignatureSize != nil
            ? .declared : .absent
        return try inspectCode(code: code, location: location, integrity: integrity, signatureRegion: signatureRegion)
    }

    private static func inspectCode(
        code: SecStaticCode, location: StaticEvidenceLocation, integrity: SignatureStatus, signatureRegion: SignatureRegionPresence
    ) throws -> ScopeInspection {
        try Task.checkCancellation()
        var rawInformation: CFDictionary?
        let status = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &rawInformation)
        guard status == errSecSuccess, let rawInformation else {
            if status == errSecCSUnsigned, signatureRegion == .absent {
                let record = StaticSigner(location: location, signingIdentifier: nil, teamIdentifier: nil,
                    mode: .unsigned, signatureFlags: nil, signatureIntegrity: .unsigned,
                    selectedCDHash: nil, nativeCDHashes: [], warnings: [])
                return ScopeInspection(signer: record, signerFailure: nil,
                    certificates: emptyCertificates(reason: "Native inspection established unsigned code with no embedded CMS certificate set."))
            }
            return unavailableScope(operation: "SecCodeCopySigningInformation", status: status, location: location)
        }
        let information: NativeSigningInformation
        do {
            information = try decodeSigningInformation(rawInformation as NSDictionary)
        } catch let error as StaticSignatureCollectionError {
            let reason = "Signing information for \(scopeDescription(location)) could not be decoded: \(error.localizedDescription)"
            return ScopeInspection(signer: nil, signerFailure: reason,
                certificates: unavailableCertificates(reason: reason))
        }
        let certificateCollection: StaticFeatureCollection<StaticCertificate>
        if let cms = information.cms, !cms.isEmpty {
            do {
                certificateCollection = try StaticCertificateInspector.inspect(cms: cms,
                    chain: information.certificates, location: location)
            } catch is CancellationError {
                throw CancellationError()
            } catch let error as StaticSignatureCollectionError {
                certificateCollection = unavailableCertificates(reason:
                    "CMS certificates for \(scopeDescription(location)) could not be decoded: \(error.localizedDescription)")
            }
        } else if information.flags.map({ $0 & SecCodeSignatureFlags.adhoc.rawValue != 0 }) == true {
            certificateCollection = emptyCertificates(reason: "Ad hoc signatures contain no CMS certificate set.")
        } else if information.identifier == nil, signatureRegion == .absent {
            certificateCollection = emptyCertificates(reason: "Native inspection established unsigned code with no embedded CMS certificate set.")
        } else {
            certificateCollection = unavailableCertificates(reason:
                "Security.framework returned no CMS data for \(scopeDescription(location)); absence of embedded certificates was not established.")
        }
        let mode: StaticSigningMode
        var warnings: [String] = []
        if information.flags.map({ $0 & SecCodeSignatureFlags.adhoc.rawValue != 0 }) == true {
            mode = .adHoc
        } else if !information.certificates.isEmpty || !certificateCollection.records.isEmpty {
            mode = .certificateBacked
        } else if information.identifier == nil, signatureRegion == .absent {
            mode = .unsigned
        } else {
            mode = .unavailable
            warnings.append("Native metadata did not establish ad hoc, certificate-backed, or unsigned signing mode for \(scopeDescription(location)).")
        }
        if information.identifier == nil, signatureRegion == .declared {
            warnings.append("Mach-O declares a signature region but native metadata supplies no signing identifier; unsigned status does not establish absence of signing data.")
        }
        let record = StaticSigner(location: location, signingIdentifier: information.identifier,
            teamIdentifier: information.teamIdentifier, mode: mode, signatureFlags: information.flags,
            signatureIntegrity: integrity, selectedCDHash: information.selectedHash,
            nativeCDHashes: information.hashes, warnings: warnings)
        return ScopeInspection(signer: record, signerFailure: nil, certificates: certificateCollection)
    }

    /// NSDictionary is the native Security.framework boundary; only consumed fields are decoded.
    private static func decodeSigningInformation(_ information: NSDictionary) throws -> NativeSigningInformation {
        let identifier = try optionalString(information: information, key: kSecCodeInfoIdentifier)
        let team = try optionalString(information: information, key: kSecCodeInfoTeamIdentifier)
        let flags: UInt32?
        if information[kSecCodeInfoFlags] != nil {
            guard let number = information[kSecCodeInfoFlags] as? NSNumber else {
                throw StaticSignatureCollectionError.invalidNativeField("kSecCodeInfoFlags", "integer")
            }
            flags = try unsignedInteger(number: number, field: "kSecCodeInfoFlags")
        } else { flags = nil }
        let selected: String?
        if information[kSecCodeInfoUnique] != nil {
            guard let data = information[kSecCodeInfoUnique] as? Data else {
                throw StaticSignatureCollectionError.invalidNativeField("kSecCodeInfoUnique", "CDHash data")
            }
            selected = try nativeHash(data: data, field: "kSecCodeInfoUnique")
        } else { selected = nil }
        let hashes = try nativeHashes(information)
        let certificates: [SecCertificate]
        if information[kSecCodeInfoCertificates] != nil {
            guard let values = information[kSecCodeInfoCertificates] as? [SecCertificate],
                values.allSatisfy({ CFGetTypeID($0) == SecCertificateGetTypeID() }) else {
                throw StaticSignatureCollectionError.invalidNativeField("kSecCodeInfoCertificates", "SecCertificate array")
            }
            guard values.count <= StaticCertificateInspector.maximumCertificates else {
                throw StaticSignatureCollectionError.limitExceeded("native certificate chain count", values.count,
                    StaticCertificateInspector.maximumCertificates)
            }
            certificates = values
        } else { certificates = [] }
        let cms: Data?
        if information[kSecCodeInfoCMS] != nil {
            guard let value = information[kSecCodeInfoCMS] as? Data else {
                throw StaticSignatureCollectionError.invalidNativeField("kSecCodeInfoCMS", "CMS data")
            }
            guard value.count <= StaticCertificateInspector.maximumCMSBytes else {
                throw StaticSignatureCollectionError.limitExceeded("native CMS bytes", value.count,
                    StaticCertificateInspector.maximumCMSBytes)
            }
            cms = value
        } else { cms = nil }
        return NativeSigningInformation(identifier: identifier, teamIdentifier: team, flags: flags,
            selectedHash: selected, hashes: hashes, certificates: certificates, cms: cms)
    }

    private static func nativeHashes(_ information: NSDictionary) throws -> [StaticNativeCodeDirectoryHash] {
        guard information[kSecCodeInfoCdHashes] != nil || information[kSecCodeInfoDigestAlgorithms] != nil else { return [] }
        guard let hashes = information[kSecCodeInfoCdHashes] as? [Data],
            let algorithms = information[kSecCodeInfoDigestAlgorithms] as? [NSNumber], hashes.count == algorithms.count else {
            throw StaticSignatureCollectionError.invalidNativeField("kSecCodeInfoCdHashes", "hashes and matching digest algorithms")
        }
        guard hashes.count <= maximumDigestRecords else {
            throw StaticSignatureCollectionError.limitExceeded("native CDHash count", hashes.count, maximumDigestRecords)
        }
        return try zip(algorithms, hashes).map { algorithm, hash in
            StaticNativeCodeDirectoryHash(hashType: try unsignedInteger(number: algorithm,
                field: "kSecCodeInfoDigestAlgorithms"), value: try nativeHash(data: hash, field: "kSecCodeInfoCdHashes"))
        }
    }

    private static func unsignedInteger(number: NSNumber, field: String) throws -> UInt32 {
        let integerTypes: Set<String> = ["c", "C", "s", "S", "i", "I", "l", "L", "q", "Q"]
        guard CFGetTypeID(number) == CFNumberGetTypeID(),
            integerTypes.contains(String(cString: number.objCType)),
            number.int64Value >= 0, number.uint64Value <= UInt64(UInt32.max) else {
            throw StaticSignatureCollectionError.invalidNativeField(field, "unsigned 32-bit integer")
        }
        return UInt32(number.uint64Value)
    }

    private static func optionalString(information: NSDictionary, key: CFString) throws -> String? {
        guard information[key] != nil else { return nil }
        guard let value = information[key] as? String else {
            throw StaticSignatureCollectionError.invalidNativeField(key as String, "string")
        }
        guard value.utf8.count <= maximumStringBytes else {
            throw StaticSignatureCollectionError.limitExceeded("\(key) string bytes", value.utf8.count, maximumStringBytes)
        }
        return value
    }

    private static func nativeHash(data: Data, field: String) throws -> String {
        guard !data.isEmpty, data.count <= maximumDigestBytes else {
            throw StaticSignatureCollectionError.limitExceeded("\(field) bytes", data.count, maximumDigestBytes)
        }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private static func unavailableScope(
        operation: String, status: OSStatus, location: StaticEvidenceLocation
    ) -> ScopeInspection {
        let reason = "\(operation) failed for \(scopeDescription(location)) with OSStatus \(status): \(OSStatusMessage.describe(status))"
        return ScopeInspection(signer: nil, signerFailure: reason, certificates: unavailableCertificates(reason: reason))
    }

    private static func scopeDescription(_ location: StaticEvidenceLocation) -> String {
        if let architecture = location.architecture, let offset = location.sliceOffset {
            return "\(architecture) slice at offset \(offset) in \(location.sourcePath)"
        }
        return "standard native scope in \(location.sourcePath)"
    }

    private static func emptyCertificates(reason: String) -> StaticFeatureCollection<StaticCertificate> {
        StaticFeatureCollection(state: .complete, reason: reason, records: [],
            limitations: ["No certificate trust or network assessment was performed."], limits: StaticCertificateInspector.limits)
    }

    private static func unavailableCertificates(reason: String) -> StaticFeatureCollection<StaticCertificate> {
        StaticFeatureCollection(state: .unavailable, reason: reason, records: [],
            limitations: [reason, "No certificate trust or network assessment was performed."], limits: StaticCertificateInspector.limits)
    }
}

enum StaticSignatureCollectionError: LocalizedError {
    case nativeOperation(String, OSStatus)
    case invalidNativeField(String, String)
    case limitExceeded(String, Int, Int)

    var errorDescription: String? {
        switch self {
        case let .nativeOperation(operation, status): "\(operation) failed with OSStatus \(status): \(OSStatusMessage.describe(status))"
        case let .invalidNativeField(field, expected): "Native field \(field) did not contain the required \(expected)."
        case let .limitExceeded(field, size, maximum): "\(field) has \(size) elements or bytes; the permitted bound is 1 through \(maximum)."
        }
    }
}
