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
            return Data(csv(findings).utf8)
        }
    }

    private static func csv(_ findings: [ScanFinding]) -> String {
        let header = [
            "path", "analyzed_path", "file_type", "file_format", "signature_integrity", "signature_detail",
            "resource_integrity", "resource_integrity_detail", "execution_policy", "execution_policy_detail",
            "identifier", "team_id", "platform_identifier",
            "unique_cdhash", "sha256", "source_os", "host_os", "counterpart_path",
            "counterpart_relationship", "counterpart_sha256", "counterpart_differences",
            "entitlement_key", "entitlement_value"
        ].joined(separator: ",") + "\n"
        let rows = findings.flatMap { finding -> [String] in
            let entries = finding.signing?.entitlements ?? []
            if entries.isEmpty {
                return [row(finding: finding, entitlement: nil)]
            }
            return entries.map { row(finding: finding, entitlement: $0) }
        }
        return header + rows.joined(separator: "\n") + (rows.isEmpty ? "" : "\n")
    }

    private static func row(finding: ScanFinding, entitlement: EntitlementEntry?) -> String {
        let platformIdentifier = finding.signing?.platformIdentifier.map(String.init) ?? ""
        let sourceOperatingSystem = finding.provenance.sourceOperatingSystem?.displayValue ?? ""
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
            entitlement?.value.displayValue ?? ""
        ]
        return values.map(escapeCSV).joined(separator: ",")
    }

    private static func escapeCSV(_ value: String) -> String {
        "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\""
    }
}
