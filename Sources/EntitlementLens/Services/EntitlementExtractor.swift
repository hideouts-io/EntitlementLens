import Foundation
import Security

enum EntitlementExtractor {
    static func inspect(_ url: URL) -> SigningDetails {
        let isBundle = isDirectory(url)
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            url as CFURL,
            SecCSFlags(rawValue: 0),
            &staticCode
        )
        guard createStatus == errSecSuccess, let staticCode else {
            return unavailableDetails(status: createStatus, isBundle: isBundle)
        }

        let validityFlags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSDoNotValidateResources)
            .union(.noNetworkAccess)
        let validityStatus = SecStaticCodeCheckValidity(staticCode, validityFlags, nil)
        let identifierStatus: SignatureStatus

        var rawInformation: CFDictionary?
        let informationFlags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        let informationStatus = SecCodeCopySigningInformation(staticCode, informationFlags, &rawInformation)
        guard informationStatus == errSecSuccess, let rawInformation else {
            return unavailableDetails(status: informationStatus, isBundle: isBundle)
        }

        let information = rawInformation as NSDictionary
        let identifier = information[kSecCodeInfoIdentifier as String] as? String
        identifierStatus = signatureStatus(identifier: identifier, validityStatus: validityStatus)
        let decoded = decodeEntitlements(information[kSecCodeInfoEntitlementsDict as String])
        let mainExecutable = (information[kSecCodeInfoMainExecutable as String] as? URL)?.path
        let executableURL = mainExecutable.map(URL.init(fileURLWithPath:)) ?? url
        let architectureResult = inspectArchitectures(codeURL: url, executableURL: executableURL)
        let slotInspection = CodeSignatureParser.inspect(
            executableURL,
            slices: architectureResult.slices,
            architectureEntitlements: architectureResult.entitlements
        )
        let decodeWarnings = decoded.warning.map { [$0] } ?? []

        return SigningDetails(
            status: identifierStatus,
            resourceIntegrity: resourceIntegrity(
                staticCode: staticCode,
                isBundle: isBundle,
                signatureStatus: identifierStatus,
                signatureValidityStatus: validityStatus
            ),
            executionPolicy: staticExecutionPolicyAssessment(),
            identifier: identifier,
            teamIdentifier: information[kSecCodeInfoTeamIdentifier as String] as? String,
            format: information[kSecCodeInfoFormat as String] as? String,
            source: information[kSecCodeInfoSource as String] as? String,
            mainExecutable: mainExecutable,
            requirements: information[kSecCodeInfoRequirements as String] as? String,
            signatureFlags: (information[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value,
            rawEntitlementsByteCount: (information[kSecCodeInfoEntitlements as String] as? Data)?.count,
            uniqueCDHash: hexString(information[kSecCodeInfoUnique as String] as? Data),
            cdHashes: ((information[kSecCodeInfoCdHashes as String] as? [Data]) ?? []).map(hexString).compactMap { $0 },
            platformIdentifier: (information[kSecCodeInfoPlatformIdentifier as String] as? NSNumber)?.uint32Value,
            signingTime: information[kSecCodeInfoTime as String] as? Date,
            timestamp: information[kSecCodeInfoTimestamp as String] as? Date,
            authorities: certificateSubjects(information[kSecCodeInfoCertificates as String]),
            entitlements: decoded.entries,
            entitlementScope: .declaredCodeSignature,
            runtimeAuthorization: runtimeAuthorizationAssessment(),
            architectureEntitlements: architectureResult.entitlements,
            entitlementSlots: slotInspection.slots,
            extractionWarnings: decodeWarnings + architectureResult.warnings + slotInspection.warnings,
            entitlementCollectionState: collectionState(decoded: decoded.state, status: identifierStatus, slices: architectureResult.slices)
        )
    }

    private static func unavailableDetails(status: OSStatus, isBundle: Bool) -> SigningDetails {
        SigningDetails(
            status: .unavailable(code: status, message: OSStatusMessage.describe(status)),
            resourceIntegrity: isBundle
                ? .unavailable(code: status, message: OSStatusMessage.describe(status))
                : .notApplicable(reason: "Single-file code has no signed bundle resource envelope."),
            executionPolicy: staticExecutionPolicyAssessment(),
            identifier: nil,
            teamIdentifier: nil,
            format: nil,
            source: nil,
            mainExecutable: nil,
            requirements: nil,
            signatureFlags: nil,
            rawEntitlementsByteCount: nil,
            uniqueCDHash: nil,
            cdHashes: [],
            platformIdentifier: nil,
            signingTime: nil,
            timestamp: nil,
            authorities: [],
            entitlements: [],
            entitlementScope: .declaredCodeSignature,
            runtimeAuthorization: runtimeAuthorizationAssessment(),
            architectureEntitlements: [],
            entitlementSlots: [],
            extractionWarnings: [],
            entitlementCollectionState: .unavailable(reason: "Signing information could not be read: OSStatus \(status): \(OSStatusMessage.describe(status))")
        )
    }

    private static func inspectArchitectures(
        codeURL: URL,
        executableURL: URL
    ) -> (entitlements: [ArchitectureEntitlements], slices: [MachOSlice], warnings: [String]) {
        let slices: [MachOSlice]
        do {
            slices = try MachOInspector.inspect(executableURL)
        } catch {
            return ([], [], ["Per-architecture inspection could not parse \(executableURL.path): \(error.localizedDescription)"])
        }
        var warnings: [String] = []
        let results = slices.map { slice in
            inspectArchitecture(codeURL: codeURL, slice: slice)
        }
        for result in results {
            warnings.append(contentsOf: result.warnings.map { "\(result.architecture): \($0)" })
        }
        return (results, slices, warnings)
    }

    private static func inspectArchitecture(codeURL: URL, slice: MachOSlice) -> ArchitectureEntitlements {
        let architecture = slice.architecture
        let attributes = [kSecCodeAttributeArchitecture as String: architecture] as CFDictionary
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPathAndAttributes(
            codeURL as CFURL,
            SecCSFlags(rawValue: 0),
            attributes,
            &staticCode
        )
        guard createStatus == errSecSuccess, let staticCode else {
            return ArchitectureEntitlements(
                architecture: architecture,
                status: .unavailable(code: createStatus, message: OSStatusMessage.describe(createStatus)),
                uniqueCDHash: nil,
                entitlements: [],
                warnings: ["SecStaticCodeCreateWithPathAndAttributes failed with OSStatus \(createStatus): \(OSStatusMessage.describe(createStatus))"],
                collectionState: .unavailable(reason: "Could not create the architecture-specific code object.")
            )
        }
        let validityStatus = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSDoNotValidateResources).union(.noNetworkAccess),
            nil
        )
        var rawInformation: CFDictionary?
        let informationStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        )
        guard informationStatus == errSecSuccess, let rawInformation else {
            return ArchitectureEntitlements(
                architecture: architecture,
                status: .unavailable(code: informationStatus, message: OSStatusMessage.describe(informationStatus)),
                uniqueCDHash: nil,
                entitlements: [],
                warnings: ["SecCodeCopySigningInformation failed with OSStatus \(informationStatus): \(OSStatusMessage.describe(informationStatus))"],
                collectionState: .unavailable(reason: "Could not read the architecture-specific signing information.")
            )
        }
        let information = rawInformation as NSDictionary
        let identifier = information[kSecCodeInfoIdentifier as String] as? String
        let decoded = decodeEntitlements(information[kSecCodeInfoEntitlementsDict as String])
        let status = signatureStatus(identifier: identifier, validityStatus: validityStatus)
        return ArchitectureEntitlements(
            architecture: architecture,
            status: status,
            uniqueCDHash: hexString(information[kSecCodeInfoUnique as String] as? Data),
            entitlements: decoded.entries,
            warnings: decoded.warning.map { [$0] } ?? [],
            collectionState: collectionState(decoded: decoded.state, status: status, slices: [slice])
        )
    }

    /// Security.framework can describe an unrecognized signature container as unsigned.
    /// A declared nonempty signature region prevents that outcome from establishing empty entitlements.
    private static func collectionState(
        decoded: EntitlementCollectionState, status: SignatureStatus, slices: [MachOSlice]
    ) -> EntitlementCollectionState {
        if case .unavailable = decoded { return decoded }
        if status == .unsigned, slices.contains(where: { $0.codeSignatureOffset != nil && ($0.codeSignatureSize ?? 0) > 0 }) {
            return .unavailable(reason: "Mach-O declares a code-signature region, but Security.framework did not recognize its signing identity. Empty returned entitlements do not establish absence.")
        }
        return decoded
    }

    private static func signatureStatus(identifier: String?, validityStatus: OSStatus) -> SignatureStatus {
        if identifier == nil {
            return .unsigned
        }
        if validityStatus == errSecSuccess {
            return .valid
        }
        return .invalid(code: validityStatus, message: OSStatusMessage.describe(validityStatus))
    }

    private static func resourceIntegrity(
        staticCode: SecStaticCode,
        isBundle: Bool,
        signatureStatus: SignatureStatus,
        signatureValidityStatus: OSStatus
    ) -> ResourceIntegrityStatus {
        guard isBundle else {
            return .notApplicable(reason: "Single-file code has no signed bundle resource envelope.")
        }
        guard signatureStatus == .valid else {
            return .unavailable(
                code: signatureValidityStatus,
                message: "Resource verification was not interpreted independently because executable signature integrity failed: \(OSStatusMessage.describe(signatureValidityStatus))"
            )
        }
        let status = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures).union(.noNetworkAccess),
            nil
        )
        if status == errSecSuccess {
            return .verified
        }
        return .invalid(code: status, message: OSStatusMessage.describe(status))
    }

    private static func staticExecutionPolicyAssessment() -> ExecutionPolicyAssessment {
        ExecutionPolicyAssessment(
            status: .notAssessed,
            detail: "Static Security.framework inspection does not query the active AMFI trust cache or prove that this code can launch."
        )
    }

    private static func runtimeAuthorizationAssessment() -> RuntimeAuthorizationAssessment {
        RuntimeAuthorizationAssessment(
            status: .notAssessed,
            detail: "These are declared code-signature entitlements. Effective authorization also depends on AMFI, provisioning, sandbox, TCC, SIP, task state, and service-side policy at runtime."
        )
    }

    private static func decodeEntitlements(_ rawValue: Any?) -> (entries: [EntitlementEntry], warning: String?, state: EntitlementCollectionState) {
        guard let rawValue else {
            return ([], nil, .complete)
        }
        guard let dictionary = rawValue as? [String: Any] else {
            let warning = "kSecCodeInfoEntitlementsDict was present but was not a string-keyed dictionary."
            return ([], warning, .unavailable(reason: warning))
        }
        do {
            let entries = try dictionary
                .map { EntitlementEntry(key: $0.key, value: try PropertyListValueDecoder.decode($0.value)) }
                .sorted { $0.key < $1.key }
            return (entries, nil, .complete)
        } catch {
            let warning = "Security.framework returned entitlements that could not be decoded: \(error.localizedDescription)"
            return ([], warning, .unavailable(reason: warning))
        }
    }

    private static func certificateSubjects(_ rawValue: Any?) -> [String] {
        guard let certificates = rawValue as? [SecCertificate] else {
            return []
        }
        return certificates.compactMap { SecCertificateCopySubjectSummary($0) as String? }
    }

    private static func hexString(_ data: Data?) -> String? {
        data?.map { String(format: "%02x", $0) }.joined()
    }

    private static func isDirectory(_ url: URL) -> Bool {
        var isDirectory = ObjCBool(false)
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else {
            return false
        }
        return isDirectory.boolValue
    }
}
