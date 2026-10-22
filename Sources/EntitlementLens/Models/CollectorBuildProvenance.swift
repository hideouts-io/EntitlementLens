import Foundation

enum CollectorBuildState: String, Codable, Hashable, Sendable {
    case clean, dirty, unknown
}

/// Build-recorded source identity, retained with a scan rather than inferred from the reviewing app.
struct CollectorBuildProvenance: Codable, Hashable, Sendable {
    let state: CollectorBuildState
    let sourceCommit: String?

    static let unknown = CollectorBuildProvenance(state: .unknown, sourceCommit: nil)

    var exactSourceCommit: String? {
        guard state == .clean, let sourceCommit, Self.validSourceCommit(sourceCommit) else { return nil }
        return sourceCommit
    }

    init(state: CollectorBuildState, sourceCommit: String?) {
        self.state = state
        self.sourceCommit = sourceCommit
    }

    init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: CollectorBuildField.self)
        guard fields.allKeys.allSatisfy({ ["state", "source_commit"].contains($0.stringValue) }) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                debugDescription: "Collector build provenance contains an unrecognized field."))
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(CollectorBuildState.self, forKey: .state)
        sourceCommit = try container.decodeIfPresent(String.self, forKey: .sourceCommit)
        guard sourceCommit.map(Self.validSourceCommit) != false,
              state == .clean ? sourceCommit != nil : !container.contains(.sourceCommit) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                debugDescription: "Collector build provenance lacks a valid source revision."))
        }
    }

    /// Missing, unreadable, or malformed bundle metadata is unknown; runtime Git state is never consulted.
    static func bundled(in bundle: Bundle) -> CollectorBuildProvenance {
        let url = bundle.bundleURL.appendingPathComponent("Contents/Info.plist")
        do {
            return try decodeInfoPlist(Data(contentsOf: url))
        } catch {
            return .unknown
        }
    }

    static func decodeInfoPlist(_ data: Data) throws -> CollectorBuildProvenance {
        try PropertyListDecoder().decode(CollectorBuildInfoPlist.self, from: data).collectorBuild ?? .unknown
    }

    private static func validSourceCommit(_ value: String) -> Bool {
        value.utf8.count == 40 && value.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    private enum CodingKeys: String, CodingKey {
        case state
        case sourceCommit = "source_commit"
    }
}

private struct CollectorBuildInfoPlist: Decodable {
    let collectorBuild: CollectorBuildProvenance?

    private enum CodingKeys: String, CodingKey {
        case collectorBuild = "EntitlementLensCollectorBuild"
    }
}

private struct CollectorBuildField: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        return nil
    }
}
