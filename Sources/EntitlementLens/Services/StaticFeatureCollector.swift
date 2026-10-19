import Foundation

enum StaticFeatureCollector {
    static func collectCode(
        sourceURL: URL,
        kind: FileKind,
        provenance: ArtifactProvenance,
        signing: SigningDetails,
        machO: MachOStaticInspection
    ) throws -> StaticFeatureSet {
        try Task.checkCancellation()
        let analyzedURL = URL(fileURLWithPath: provenance.analyzedPath)
        let signature = try SignatureStaticFeatureCollector.inspect(
            sourceURL: sourceURL, analyzedURL: analyzedURL, signing: signing, slices: provenance.machOSlices
        )
        let configuration = try PersistenceStaticFeatureCollector.inspect(
            sourceURL: sourceURL, kind: kind, analyzedPath: provenance.analyzedPath
        )
        let persistenceAPI = try PersistenceAPIReferenceCollector.collect(
            apiReferences: machO.apiReferences, analyzedPath: provenance.analyzedPath
        )
        let persistence = try combinedPersistence(configuration: configuration, apiReferences: persistenceAPI)
        return StaticFeatureSet(
            schemaVersion: .v3,
            analyzedPath: provenance.analyzedPath,
            artifactSHA256: provenance.sha256,
            context: context(provenance),
            signer: signature.signer,
            embeddedCertificates: signature.embeddedCertificates,
            entitlements: entitlementEvidence(signing: signing, provenance: provenance),
            architectures: machO.architectures,
            loadCommands: machO.loadCommands,
            linkedFrameworks: machO.linkedFrameworks,
            apiReferences: machO.apiReferences,
            persistenceCharacteristics: persistence,
            codeDirectoryData: signature.codeDirectories
        )
    }

    static func collectFile(
        sourceURL: URL,
        kind: FileKind,
        provenance: ArtifactProvenance
    ) throws -> StaticFeatureSet {
        try Task.checkCancellation()
        let reason = "The selected artifact is not Mach-O code; this feature family does not apply."
        let persistence = try PersistenceStaticFeatureCollector.inspect(
            sourceURL: sourceURL, kind: kind, analyzedPath: provenance.analyzedPath
        )
        return StaticFeatureSet(
            schemaVersion: .v3,
            analyzedPath: provenance.analyzedPath,
            artifactSHA256: provenance.sha256,
            context: context(provenance),
            signer: notApplicable(reason),
            embeddedCertificates: notApplicable(reason),
            entitlements: notApplicable("The selected artifact has no code-signature entitlement dictionary. Embedded entitlement-like data remains supporting evidence."),
            architectures: notApplicable(reason),
            loadCommands: notApplicable(reason),
            linkedFrameworks: notApplicable(reason),
            apiReferences: notApplicable(reason),
            persistenceCharacteristics: persistence,
            codeDirectoryData: notApplicable(reason)
        )
    }

    private static func context(_ provenance: ArtifactProvenance) -> StaticCollectionContext {
        let appBundle = Bundle.main.bundleIdentifier == "io.hideouts.EntitlementLens" ? Bundle.main : nil
        return StaticCollectionContext(
            collector: "EntitlementLens",
            appVersion: appBundle?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
            appBuild: appBundle?.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
            collectedAt: Date(),
            hostOperatingSystem: provenance.hostOperatingSystem
        )
    }

    private static func notApplicable<Record: Codable & Hashable & Sendable>(_ reason: String) -> StaticFeatureCollection<Record> {
        StaticFeatureCollection(state: .notApplicable, reason: reason, records: [], limitations: [], limits: [])
    }

    private static func combinedPersistence(
        configuration: StaticFeatureCollection<StaticPersistenceCharacteristic>,
        apiReferences: StaticFeatureCollection<StaticPersistenceCharacteristic>
    ) throws -> StaticFeatureCollection<StaticPersistenceCharacteristic> {
        try Task.checkCancellation()
        let maximumRecords = 512
        let scopes = [configuration, apiReferences].filter { $0.state != .notApplicable }
        let records = configuration.records + apiReferences.records
        var reasons = scopes.compactMap(\.reason)
        var limitations = configuration.limitations + apiReferences.limitations
        let state: StaticCollectionState
        if records.count > maximumRecords {
            state = .partial
            let reason = "Combined persistence collection reached the \(maximumRecords)-record limit; subsequent API references were not retained."
            reasons.append(reason)
            limitations.append(reason)
        } else if scopes.isEmpty { state = .notApplicable }
        else if scopes.allSatisfy({ $0.state == .complete }) { state = .complete }
        else if scopes.allSatisfy({ $0.state == .unsupported }) { state = .unsupported }
        else if scopes.allSatisfy({ $0.state == .unavailable }) { state = .unavailable }
        else if scopes.allSatisfy({ $0.state == .notCollected }) { state = .notCollected }
        else { state = .partial }
        return StaticFeatureCollection(state: state, reason: reasons.isEmpty ? nil : reasons.joined(separator: "\n"),
            records: Array(records.prefix(maximumRecords)), limitations: limitations,
            limits: configuration.limits + apiReferences.limits + [
                StaticCollectionLimit(name: "combined_persistence_records", value: UInt64(maximumRecords), unit: .records)
            ])
    }
}

private func entitlementEvidence(
    signing: SigningDetails,
    provenance: ArtifactProvenance
) -> StaticFeatureCollection<StaticEntitlementEvidence> {
    let records = entitlementSourceGroups(signing).map { group in
        let architecture: String?
        let slices: [MachOSlice]
        switch group.source {
        case .standardDictionary:
            architecture = nil
            slices = []
        case let .architecture(label):
            architecture = label
            slices = provenance.machOSlices.filter { $0.architecture == label }
        }
        let state: StaticCollectionState
        let reason: String?
        switch group.collectionState {
        case .complete:
            if architecture != nil && slices.count != 1 {
                state = .partial
                reason = "The architecture-specific dictionary cannot be attributed to exactly one recorded Mach-O slice."
            } else {
                state = .complete
                reason = nil
            }
        case let .unavailable(detail):
            state = .unavailable
            reason = detail
        case nil:
            state = .notCollected
            reason = "This dictionary's collection completeness was not recorded."
        }
        return StaticEntitlementEvidence(
            source: group.source,
            state: state,
            reason: reason,
            signatureIntegrity: group.status,
            nativeCDHash: group.uniqueCDHash,
            values: group.entitlements,
            slots: architecture.map { label in signing.entitlementSlots.filter { $0.architecture == label } } ?? [],
            location: StaticEvidenceLocation(
                sourcePath: provenance.analyzedPath, architecture: architecture,
                sliceOffset: slices.count == 1 ? slices.first?.fileOffset : nil,
                fileOffset: nil, byteCount: nil, propertyListKey: nil, method: .securityFramework
            )
        )
    }
    let limitations = signing.extractionWarnings + signing.entitlementSlots.compactMap(\.warning)
    let state: StaticCollectionState
    if records.allSatisfy({ $0.state == .complete }) && limitations.isEmpty {
        state = .complete
    } else if records.allSatisfy({ $0.state == .unavailable }) {
        state = .unavailable
    } else if records.allSatisfy({ $0.state == .notCollected }) {
        state = .notCollected
    } else {
        state = .partial
    }
    return StaticFeatureCollection(
        state: state,
        reason: state == .complete ? nil : "One or more entitlement dictionaries or signature slots have incomplete collection; inspect each record and the limitations.",
        records: records,
        limitations: limitations,
        limits: []
    )
}
