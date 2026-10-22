import Foundation
import Testing
@testable import EntitlementLens

struct CollectorBuildProvenanceTests {
    @Test
    func decodesStrictBuildIdentityAndRejectsMalformedExactClaims() throws {
        let clean = try CollectorBuildProvenance.decodeInfoPlist(collectorBuildPlist("""
        <key>state</key><string>clean</string><key>source_commit</key><string>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</string>
        """))
        #expect(clean.state == .clean)
        #expect(clean.exactSourceCommit == String(repeating: "a", count: 40))
        for state in [CollectorBuildState.dirty, .unknown] {
            let provenance = try CollectorBuildProvenance.decodeInfoPlist(collectorBuildPlist("""
            <key>state</key><string>\(state.rawValue)</string>
            """))
            #expect(provenance.state == state)
            #expect(provenance.exactSourceCommit == nil)
        }
        let malformed = [
            "<key>state</key><string>clean</string>",
            "<key>state</key><string>clean</string><key>source_commit</key><string>a29639f</string>",
            "<key>state</key><string>clean</string><key>source_commit</key><string>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</string>",
            "<key>state</key><string>clean</string><key>source_commit</key><integer>1</integer>",
            "<key>state</key><string>dirty</string><key>source_commit</key><string>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</string>",
            "<key>state</key><string>unknown</string><key>source_commit</key><string>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</string>",
            "<key>state</key><string>unreviewed</string>",
            "<key>state</key><string>clean</string><key>source_commit</key><string>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</string><key>other</key><true/>"
        ]
        for fields in malformed {
            #expect(throws: DecodingError.self) {
                _ = try CollectorBuildProvenance.decodeInfoPlist(collectorBuildPlist(fields))
            }
        }
        let missing = Data("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>".utf8)
        #expect(try CollectorBuildProvenance.decodeInfoPlist(missing) == .unknown)
    }

    @Test
    func readsOnlyEmbeddedBundleMetadataAndReportsMissingOrInvalidMetadataAsUnknown() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-build-provenance-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Collector build fixture cleanup failed: \(error.localizedDescription)") }
        }
        let fixtures: [(String, Data, CollectorBuildProvenance)] = [
            ("Clean", collectorBuildPlist("<key>state</key><string>clean</string><key>source_commit</key><string>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</string>"),
                CollectorBuildProvenance(state: .clean, sourceCommit: String(repeating: "a", count: 40))),
            ("Dirty", collectorBuildPlist("<key>state</key><string>dirty</string>"),
                CollectorBuildProvenance(state: .dirty, sourceCommit: nil)),
            ("Missing", Data("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundlePackageType</key><string>APPL</string></dict></plist>".utf8), .unknown),
            ("Malformed", collectorBuildPlist("<key>state</key><string>clean</string>"), .unknown)
        ]
        for (name, plist, expected) in fixtures {
            let url = root.appendingPathComponent("\(name).app")
            let contents = url.appendingPathComponent("Contents")
            try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
            try plist.write(to: contents.appendingPathComponent("Info.plist"))
            let bundle = try #require(Bundle(url: url))
            #expect(CollectorBuildProvenance.bundled(in: bundle) == expected)
        }
    }
}

private func collectorBuildPlist(_ fields: String) -> Data {
    Data("""
    <?xml version="1.0" encoding="UTF-8"?>
    <plist version="1.0"><dict><key>CFBundlePackageType</key><string>APPL</string>
    <key>EntitlementLensCollectorBuild</key><dict>\(fields)</dict></dict></plist>
    """.utf8)
}
