import Foundation

enum InstalledCounterpartComparator {
    private static let systemPathMarkers: [String] = [
        "/System/", "/usr/", "/bin/", "/sbin/", "/Applications/", "/Library/"
    ]

    static func compare(
        sourceURL: URL,
        sourceProvenance: ArtifactProvenance,
        sourceSigning: SigningDetails
    ) throws -> InstalledCounterpartComparison? {
        guard let counterpartURL = installedCounterpartURL(sourceURL),
              counterpartURL.standardizedFileURL != sourceURL.standardizedFileURL,
              FileManager.default.fileExists(atPath: counterpartURL.path) else {
            return nil
        }

        let counterpartSigning = EntitlementExtractor.inspect(counterpartURL)
        let analyzedURL = counterpartSigning.mainExecutable.map(URL.init(fileURLWithPath:)) ?? counterpartURL
        let counterpartProvenance = try ArtifactProvenanceCollector.collectCode(
            sourceURL: counterpartURL,
            analyzedURL: analyzedURL
        )
        let differences = comparisonDifferences(
            sourceProvenance: sourceProvenance,
            sourceSigning: sourceSigning,
            counterpartProvenance: counterpartProvenance,
            counterpartSigning: counterpartSigning
        )

        return InstalledCounterpartComparison(
            path: counterpartURL.path,
            analyzedPath: counterpartProvenance.analyzedPath,
            relationship: sourceProvenance.sha256 == counterpartProvenance.sha256 ? .identical : .different,
            sha256: counterpartProvenance.sha256,
            signatureStatus: counterpartSigning.status,
            uniqueCDHash: counterpartSigning.uniqueCDHash,
            platformIdentifier: counterpartSigning.platformIdentifier,
            sourceOperatingSystem: counterpartProvenance.sourceOperatingSystem,
            machOSlices: counterpartProvenance.machOSlices,
            entitlementKeys: counterpartSigning.entitlements.map(\.key),
            differences: differences
        )
    }

    private static func installedCounterpartURL(_ sourceURL: URL) -> URL? {
        let sourcePath = sourceURL.standardizedFileURL.path
        let ranges = systemPathMarkers.compactMap { marker in
            sourcePath.range(of: marker, options: .backwards)
        }.sorted { $0.lowerBound < $1.lowerBound }
        return ranges
            .map { URL(fileURLWithPath: String(sourcePath[$0.lowerBound...])) }
            .first { FileManager.default.fileExists(atPath: $0.path) }
    }

    private static func comparisonDifferences(
        sourceProvenance: ArtifactProvenance,
        sourceSigning: SigningDetails,
        counterpartProvenance: ArtifactProvenance,
        counterpartSigning: SigningDetails
    ) -> [String] {
        var differences: [String] = []
        if sourceProvenance.sha256 != counterpartProvenance.sha256 {
            differences.append("SHA-256 differs.")
        }
        if sourceSigning.uniqueCDHash != counterpartSigning.uniqueCDHash {
            differences.append("Unique CodeDirectory hash differs.")
        }
        if sourceSigning.platformIdentifier != counterpartSigning.platformIdentifier {
            differences.append("Code-signing platform identifier differs.")
        }
        if sliceIdentity(sourceProvenance.machOSlices) != sliceIdentity(counterpartProvenance.machOSlices) {
            differences.append("Mach-O architectures or build targets differ.")
        }
        if sourceSigning.entitlements.map(\.key) != counterpartSigning.entitlements.map(\.key) {
            differences.append("Entitlement keys differ.")
        }
        if sourceSigning.entitlements != counterpartSigning.entitlements {
            differences.append("Entitlement values differ.")
        }
        return differences
    }

    private static func sliceIdentity(_ slices: [MachOSlice]) -> [String] {
        slices.map { slice in
            [
                slice.architecture,
                slice.uuid ?? "",
                slice.platform ?? "",
                slice.minimumOSVersion ?? "",
                slice.sdkVersion ?? ""
            ].joined(separator: "|")
        }
    }
}
