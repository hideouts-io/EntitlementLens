import CryptoKit
import Foundation

/// A bounded local validation path for retained app exports. Paths inside JSON never authorize file reads.
enum StaticResearchExportConsumer {
    static let maximumArtifacts = 256
    static let maximumTotalSourceBytes = 128 * 1_024 * 1_024

    static func inspect(exportURL: URL, sourceURLs: [URL]) throws -> StaticResearchReport {
        try Task.checkCancellation()
        let export = try StaticResearchFileReader.exportData(at: exportURL)
        try StaticResearchFileReader.validateJSONStructure(export)
        let findings: [ScanFinding]
        do { findings = try JSONDecoder().decode([ScanFinding].self, from: export) }
        catch let error as DecodingError { throw StaticResearchConsumerError.invalidExport(decodingReason(error)) }
        guard findings.count <= maximumArtifacts else {
            throw StaticResearchConsumerError.invalidExport("The export exceeds the \(maximumArtifacts)-artifact limit.")
        }
        guard Set(findings.map(\.id)).count == findings.count else {
            throw StaticResearchConsumerError.invalidExport("Finding identifiers are duplicated.")
        }
        for finding in findings { try StaticResearchEvidenceValidator.validate(finding) }
        let sources = try sourceSelection(sourceURLs, findings: findings)
        var consumedSourceBytes = 0
        var artifacts: [StaticResearchArtifact] = []
        for finding in findings {
            try Task.checkCancellation()
            let path = finding.provenance.analyzedPath
            let verification: StaticResearchSourceVerification
            if let url = sources[path] {
                let source = try verifySource(finding, url: url, maximumBytes: maximumTotalSourceBytes - consumedSourceBytes)
                verification = source.verification
                consumedSourceBytes += source.byteCount
            } else {
                verification = result(identity: .notProvided, api: .notPerformed, hash: nil,
                                      names: 0, slots: 0, reason: "Source bytes were not explicitly supplied.")
            }
            artifacts.append(StaticResearchArtifact(
                findingID: finding.id, selectedPath: finding.path, provenance: finding.provenance,
                staticFeatures: finding.staticFeatures, families: StaticResearchCoverage.families(for: finding.staticFeatures),
                entitlementScopes: StaticResearchCoverage.entitlementScopes(for: finding.staticFeatures),
                sourceVerification: verification
            ))
        }
        try Task.checkCancellation()
        return StaticResearchReport(
            reportVersion: 1, exportPath: exportURL.path, exportSHA256: sha256(export),
            limits: reportLimits,
            limitations: [
                "Presence and absence describe the original collection scope; incomplete empty observations remain unknown.",
                "Source verification opens only explicitly supplied analyzed-artifact files; external configuration evidence is retained without re-reading its source.",
                "Failed source reads conservatively consume their permitted byte allowance; each bounded reader may read one extra byte to detect growth.",
                "SHA-256 matches establish byte identity, not origin, trust, runtime behavior, or successful authentication.",
                "API checks compare retained NUL-terminated name bytes and reference-slot bounds. They do not reconstruct bindings, section attribution, fixups, or PAC values, or make incomplete collections complete."
            ], artifacts: artifacts
        )
    }

    static func data(for report: StaticResearchReport) throws -> Data {
        try Task.checkCancellation()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(report)
        try Task.checkCancellation()
        return data
    }

    private static var reportLimits: [StaticCollectionLimit] {
        [
            StaticCollectionLimit(name: "export_bytes", value: UInt64(StaticResearchFileReader.maximumExportBytes), unit: .bytes),
            StaticCollectionLimit(name: "artifacts", value: UInt64(maximumArtifacts), unit: .records),
            StaticCollectionLimit(name: "source_bytes_per_file", value: UInt64(StaticResearchFileReader.maximumSourceBytes), unit: .bytes),
            StaticCollectionLimit(name: "total_source_bytes", value: UInt64(maximumTotalSourceBytes), unit: .bytes),
            StaticCollectionLimit(name: "json_depth", value: UInt64(StaticResearchFileReader.maximumJSONDepth), unit: .depth),
            StaticCollectionLimit(name: "json_nodes", value: UInt64(StaticResearchFileReader.maximumJSONNodes), unit: .records),
            StaticCollectionLimit(name: "json_string_bytes", value: UInt64(StaticResearchFileReader.maximumJSONStringBytes), unit: .bytes)
        ]
    }

    private static func sourceSelection(_ urls: [URL], findings: [ScanFinding]) throws -> [String: URL] {
        guard urls.count <= maximumArtifacts else {
            throw StaticResearchConsumerError.invalidSources("Select at most \(maximumArtifacts) source files.")
        }
        let paths = Set(findings.map { $0.provenance.analyzedPath })
        var selected: [String: URL] = [:]
        for url in urls {
            guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
                  url.path.hasPrefix("/"), !url.path.contains("\0") else {
                throw StaticResearchConsumerError.invalidSources("Source URLs must name local absolute files without NUL bytes.")
            }
            guard paths.contains(url.path), selected.updateValue(url, forKey: url.path) == nil else {
                throw StaticResearchConsumerError.invalidSources("Every selected path must match one analyzed artifact and occur once.")
            }
        }
        return selected
    }

    private static func verifySource(
        _ finding: ScanFinding, url: URL, maximumBytes: Int
    ) throws -> SourceResult {
        let bytes: Data
        do {
            bytes = try StaticResearchFileReader.sourceData(
                at: url, maximumBytes: maximumBytes
            )
        } catch let error as StaticResearchFileError {
            if error.containsCancellation { throw error }
            return SourceResult(verification: result(identity: .unavailable, api: .notPerformed, hash: nil, names: 0, slots: 0,
                          reason: error.localizedDescription), byteCount: min(maximumBytes, StaticResearchFileReader.maximumSourceBytes))
        }
        return SourceResult(verification: try verifyIdentity(finding, bytes: bytes), byteCount: bytes.count)
    }

    private static func verifyIdentity(_ finding: ScanFinding, bytes: Data) throws -> StaticResearchSourceVerification {
        try Task.checkCancellation()
        let hash = sha256(bytes)
        try Task.checkCancellation()
        guard hash == finding.provenance.sha256, Int64(bytes.count) == finding.provenance.fileSize else {
            return result(identity: .mismatch, api: .notPerformed, hash: hash, names: 0, slots: 0,
                          reason: "Supplied source SHA-256 or byte size differs from the retained artifact provenance.")
        }
        guard let features = finding.staticFeatures else {
            return result(identity: .matched, api: .notPerformed, hash: hash, names: 0, slots: 0,
                          reason: "Byte identity matched; API collection was not recorded in this legacy finding.")
        }
        guard !features.apiReferences.records.isEmpty else {
            return result(identity: .matched, api: .notApplicable, hash: hash, names: 0, slots: 0,
                          reason: "Byte identity matched; no retained API names are available for byte comparison.")
        }
        return try verifyAPIBytes(features.apiReferences.records, bytes: bytes, hash: hash)
    }

    private static func verifyAPIBytes(
        _ references: [StaticAPIReference], bytes: Data, hash: String
    ) throws -> StaticResearchSourceVerification {
        var names = 0
        var slots = 0
        var incomplete = false
        for reference in references {
            try Task.checkCancellation()
            let location = reference.location
            guard [.symbolTable, .dyldBindStream, .chainedFixupImports, .objectiveCMetadata].contains(location.method),
                  let offset = location.fileOffset, let count = location.byteCount else {
                incomplete = true
                continue
            }
            let expected = Data(reference.name.utf8) + Data([0])
            guard count == UInt64(expected.count),
                  StaticResearchEvidenceValidator.rangeFits(offset: offset, count: count, size: UInt64(bytes.count)),
                  bytes.subdata(in: Int(offset)..<Int(offset + count)) == expected else {
                return result(identity: .matched, api: .mismatch, hash: hash, names: names, slots: slots,
                              reason: "A retained API name differs from the supplied source bytes at its recorded extent.")
            }
            names += 1
            if let slot = reference.referenceLocation, let slotOffset = slot.fileOffset, let slotCount = slot.byteCount {
                guard [4, 8].contains(slotCount),
                      StaticResearchEvidenceValidator.rangeFits(offset: slotOffset, count: slotCount, size: UInt64(bytes.count)) else {
                    return result(identity: .matched, api: .mismatch, hash: hash, names: names, slots: slots,
                                  reason: "A retained reference slot is outside the supplied source bytes.")
                }
                slots += 1
            } else if location.method == .objectiveCMetadata { incomplete = true }
        }
        return result(identity: .matched, api: incomplete ? .incomplete : .matched, hash: hash, names: names, slots: slots,
                      reason: incomplete ? "Some retained names or legacy Objective-C slots lack supported byte-verification evidence." : nil)
    }

    private static func result(
        identity: StaticResearchIdentityState, api: StaticResearchAPIByteState, hash: String?,
        names: Int, slots: Int, reason: String?
    ) -> StaticResearchSourceVerification {
        StaticResearchSourceVerification(identityState: identity, apiByteState: api, actualSHA256: hash,
                                         checkedAPINameCount: names, checkedReferenceSlotCount: slots, reason: reason)
    }

    private static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private struct SourceResult {
        let verification: StaticResearchSourceVerification
        let byteCount: Int
    }

    private static func decodingReason(_ error: DecodingError) -> String {
        switch error {
        case .keyNotFound: "A required export field is missing. Select an intact app JSON export."
        case .typeMismatch: "An export field has an incompatible type. Select an intact app JSON export."
        case .valueNotFound: "A required export value is null. Select an intact app JSON export."
        case .dataCorrupted: "JSON syntax, UTF-8, or a typed export value is invalid. Select an intact app JSON export."
        @unknown default: "The typed app export could not be decoded. Select an intact app JSON export."
        }
    }
}
