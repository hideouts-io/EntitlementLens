import Foundation

enum ExportFormat: String, Sendable {
    case json
    case csv

    var fileExtension: String { rawValue }
}

enum ResultExporter {
    static func data(for findings: [ScanFinding], format: ExportFormat) throws -> Data {
        switch format {
        case .json:
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            return try encoder.encode(findings)
        case .csv:
            return Data(try csv(findings).utf8)
        }
    }

    private static func csv(_ findings: [ScanFinding]) throws -> String {
        let header = [
            "path", "analyzed_path", "file_type", "file_format", "signature_integrity", "signature_detail",
            "resource_integrity", "resource_integrity_detail", "execution_policy", "execution_policy_detail",
            "identifier", "team_id", "platform_identifier",
            "unique_cdhash", "sha256", "source_os", "host_os", "counterpart_path",
            "counterpart_relationship", "counterpart_sha256", "counterpart_differences",
            "entitlement_key", "entitlement_value",
            "entitlement_source", "entitlement_architecture", "source_signature_integrity", "source_signature_detail",
            "source_cdhash", "source_notes", "collection_notes", "entitlement_value_json",
            "counterpart_entitlement_summary", "counterpart_entitlement_comparison_json"
        ].joined(separator: ",") + "\n"
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let rows = try findings.flatMap { finding -> [String] in
            // Retain the complete comparison, including installed-only keys and architectures,
            // on the first declaration row per artifact. Repeating it for every key would
            // make export size grow quadratically; summaries remain on every row.
            let comparisonJSON: String
            if let comparison = finding.installedCounterpart?.entitlementComparison {
                let data = try encoder.encode(comparison)
                guard let json = String(data: data, encoding: .utf8) else {
                    throw ResultExportError.invalidComparisonJSON(finding.path)
                }
                comparisonJSON = json
            } else {
                comparisonJSON = ""
            }
            guard let signing = finding.signing else {
                return [row(finding: finding, group: nil, entitlement: nil, valueJSON: "", comparisonJSON: comparisonJSON)]
            }
            return try entitlementSourceGroups(signing).enumerated().flatMap { groupIndex, group -> [String] in
                if group.entitlements.isEmpty {
                    return [row(finding: finding, group: group, entitlement: nil, valueJSON: "",
                        comparisonJSON: groupIndex == 0 ? comparisonJSON : "")]
                }
                return try group.entitlements.sorted { $0.key < $1.key }.enumerated().map { entryIndex, entry in
                    let data = try encoder.encode(entry.value)
                    guard let valueJSON = String(data: data, encoding: .utf8) else {
                        throw ResultExportError.invalidEntitlementJSON(entry.key)
                    }
                    return row(finding: finding, group: group, entitlement: entry, valueJSON: valueJSON,
                        comparisonJSON: groupIndex == 0 && entryIndex == 0 ? comparisonJSON : "")
                }
            }
        }
        return header + rows.joined(separator: "\n") + (rows.isEmpty ? "" : "\n")
    }

    private static func row(
        finding: ScanFinding,
        group: EntitlementSourceGroup?,
        entitlement: EntitlementEntry?,
        valueJSON: String,
        comparisonJSON: String
    ) -> String {
        let platformIdentifier = finding.signing?.platformIdentifier.map(String.init) ?? ""
        let sourceOperatingSystem = finding.provenance.sourceOperatingSystem?.displayValue ?? ""
        let source: String
        let architecture: String
        switch group?.source {
        case .standardDictionary:
            source = "standard_dictionary"
            architecture = ""
        case let .architecture(label):
            source = "architecture_dictionary"
            architecture = label
        case nil:
            source = "not_applicable"
            architecture = ""
        }
        let sourceNotes = (group?.warnings ?? []) + (entitlement == nil && group != nil ? ["No entries returned."] : [])
        let collectionNotes = Set(finding.warnings + (finding.signing?.extractionWarnings ?? [])).sorted()
        let values: [String] = [
            finding.path,
            finding.provenance.analyzedPath,
            finding.kind.title,
            finding.fileFormat,
            finding.signing?.status.title ?? "Not applicable",
            finding.signing?.status.detail ?? "",
            finding.signing?.resourceIntegrity.title ?? "Not applicable",
            finding.signing?.resourceIntegrity.detail ?? "",
            finding.signing?.executionPolicy.status.title ?? "Not applicable",
            finding.signing?.executionPolicy.detail ?? "",
            finding.signing?.identifier ?? "",
            finding.signing?.teamIdentifier ?? "",
            platformIdentifier,
            finding.signing?.uniqueCDHash ?? "",
            finding.provenance.sha256,
            sourceOperatingSystem,
            finding.provenance.hostOperatingSystem.displayValue,
            finding.installedCounterpart?.path ?? "",
            finding.installedCounterpart?.relationship.title ?? "",
            finding.installedCounterpart?.sha256 ?? "",
            finding.installedCounterpart?.differences.joined(separator: " ") ?? "",
            entitlement?.key ?? "",
            entitlement?.value.displayValue ?? "",
            source,
            architecture,
            group?.status.title ?? "Not applicable",
            group?.status.detail ?? "",
            group?.uniqueCDHash ?? "",
            sourceNotes.joined(separator: "\n"),
            collectionNotes.joined(separator: "\n"),
            valueJSON,
            finding.installedCounterpart?.entitlementComparison?.summary ?? "",
            comparisonJSON
        ]
        return values.map(escapeCSV).joined(separator: ",")
    }

    private static func escapeCSV(_ value: String) -> String {
        "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\""
    }
}

private enum ResultExportError: LocalizedError {
    case invalidEntitlementJSON(String)
    case invalidComparisonJSON(String)

    var errorDescription: String? {
        switch self {
        case let .invalidEntitlementJSON(key):
            "Could not export entitlement \(key): the encoded value was not UTF-8 JSON."
        case let .invalidComparisonJSON(path):
            "Could not export the counterpart comparison for \(path): the encoded comparison was not UTF-8 JSON."
        }
    }
}
