import CryptoKit
import Darwin
import Foundation
import Testing
@testable import EntitlementLens

struct PersistenceStaticFeatureIntegrationTests {
    @Test
    func selectedXMLAndBinaryLaunchdDeclarationsPreserveTypedValuesAndExactHashes() throws {
        let root = try persistenceFixtureDirectory()
        defer { cleanupPersistenceFixture(root) }
        let xmlURL = root.appendingPathComponent("agent.xml.plist")
        let binaryURL = root.appendingPathComponent("agent.binary.plist")
        let xml = persistenceLaunchdXML(label: "fixture.agent", program: "/nonexistent/fixture-helper")
        try writePersistencePropertyList(xml: xml, format: .xml, url: xmlURL)
        try writePersistencePropertyList(xml: xml, format: .binary, url: binaryURL)
        let xmlFeatures = try PersistenceStaticFeatureCollector.inspect(sourceURL: xmlURL, kind: .propertyList, analyzedPath: xmlURL.path)
        let binaryFeatures = try PersistenceStaticFeatureCollector.inspect(sourceURL: binaryURL, kind: .propertyList, analyzedPath: binaryURL.path)
        #expect(xmlFeatures.state == .complete)
        #expect(binaryFeatures.state == .complete)
        #expect(xmlFeatures.records.count == 6)
        #expect(xmlFeatures.records.map(\.declarationValue) == binaryFeatures.records.map(\.declarationValue))
        #expect(xmlFeatures.records.first { $0.declarationKey == "RunAtLoad" }?.declarationValue == .boolean(false))
        #expect(xmlFeatures.records.first { $0.declarationKey == "KeepAlive" }?.declarationValue == .dictionary([
            "SuccessfulExit": .boolean(false), "PathState": .dictionary(["/nonexistent/fixture-state": .boolean(true)])
        ]))
        #expect(xmlFeatures.records.first { $0.declarationKey == "Program" }?.declaredExecutablePaths == ["/nonexistent/fixture-helper"])
        #expect(xmlFeatures.records.first { $0.declarationKey == "ProgramArguments" }?.declaredExecutablePaths.isEmpty == true)
        for (url, features) in [(xmlURL, xmlFeatures), (binaryURL, binaryFeatures)] {
            let bytes = try Data(contentsOf: url)
            let hash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
            #expect(features.records.allSatisfy { $0.sourceSHA256 == hash && $0.location.byteCount == UInt64(bytes.count) })
            #expect(features.records.allSatisfy { $0.location.sourcePath == url.path && $0.association == .selectedPropertyList })
            let encoded = try JSONEncoder().encode(features)
            #expect(try JSONDecoder().decode(StaticFeatureCollection<StaticPersistenceCharacteristic>.self, from: encoded) == features)
            #expect(!String(decoding: encoded, as: UTF8.self).contains("UNRELATED-SECRET-MARKER"))
        }
        let argumentsOnly = root.appendingPathComponent("arguments-only.plist")
        try writePersistencePropertyList(xml: "<plist version=\"1.0\"><dict><key>Label</key><string>fixture.arguments</string><key>ProgramArguments</key><array><string>/nonexistent/fixture-helper</string><string>--fixture</string></array></dict></plist>", format: .binary, url: argumentsOnly)
        let argumentFeatures = try PersistenceStaticFeatureCollector.inspect(sourceURL: argumentsOnly, kind: .propertyList, analyzedPath: argumentsOnly.path)
        #expect(argumentFeatures.state == .complete)
        #expect(argumentFeatures.records.first { $0.declarationKey == "ProgramArguments" }?.declaredExecutablePaths == ["/nonexistent/fixture-helper"])
    }

    @Test
    func bundleEvidenceUsesContainedConfigurationsAndExplicitDeclarations() throws {
        let root = try persistenceFixtureDirectory()
        defer { cleanupPersistenceFixture(root) }
        let bundle = root.appendingPathComponent("Fixture.app")
        let info = bundle.appendingPathComponent("Contents/Info.plist")
        let agent = bundle.appendingPathComponent("Contents/Library/LaunchAgents/fixture.agent.plist")
        let daemon = bundle.appendingPathComponent("Contents/Library/LaunchDaemons/fixture.daemon.plist")
        let loginInfo = bundle.appendingPathComponent("Contents/Library/LoginItems/FixtureLogin.app/Contents/Info.plist")
        try writePersistencePropertyList(xml: """
            <plist version="1.0"><dict><key>SMPrivilegedExecutables</key><dict>
            <key>fixture.helper.b</key><string>identifier fixture.helper.b</string>
            <key>fixture.helper.a</key><string>identifier fixture.helper.a</string>
            </dict><key>UnrelatedSecret</key><string>UNRELATED-SECRET-MARKER</string></dict></plist>
            """, format: .binary, url: info)
        try writePersistencePropertyList(xml: persistenceLaunchdXML(label: "fixture.agent", program: "/nonexistent/fixture-helper"), format: .xml, url: agent)
        try writePersistencePropertyList(xml: """
            <plist version="1.0"><dict><key>Label</key><string>fixture.daemon</string>
            <key>BundleProgram</key><string>Contents/MacOS/UncreatedHelper</string><key>RunAtLoad</key><true/></dict></plist>
            """, format: .binary, url: daemon)
        try writePersistencePropertyList(xml: """
            <plist version="1.0"><dict><key>CFBundleExecutable</key><string>UncreatedLoginExecutable</string>
            <key>CFBundleIdentifier</key><string>fixture.login</string></dict></plist>
            """, format: .xml, url: loginInfo)
        let features = try PersistenceStaticFeatureCollector.inspect(sourceURL: bundle, kind: .bundle, analyzedPath: bundle.path)
        #expect(features.state == .complete)
        #expect(Set(features.records.map(\.kind)) == [.launchdDeclaration, .privilegedHelperDeclaration, .loginItemBundle, .loginItemExecutableDeclaration])
        let helpers = features.records.filter { $0.kind == .privilegedHelperDeclaration }
        #expect(helpers.map(\.declaredIdentifier) == ["fixture.helper.a", "fixture.helper.b"])
        #expect(helpers.allSatisfy { $0.association == .explicitBundleDeclaration && $0.declaredExecutablePaths.isEmpty })
        let bundleProgram = try #require(features.records.first {
            $0.declarationKey == "BundleProgram" && $0.location.sourcePath == daemon.path
        })
        #expect(bundleProgram.bundleProgramCandidatePath == bundle.appendingPathComponent("Contents/MacOS/UncreatedHelper").path)
        #expect(bundleProgram.declaredExecutablePaths == ["Contents/MacOS/UncreatedHelper"])
        #expect(!FileManager.default.fileExists(atPath: try #require(bundleProgram.bundleProgramCandidatePath)))
        let layout = try #require(features.records.first { $0.kind == .loginItemBundle })
        #expect(layout.sourceSHA256 == nil)
        #expect(layout.location.method == .bundleLayout)
        let login = try #require(features.records.first { $0.kind == .loginItemExecutableDeclaration })
        #expect(login.declaredIdentifier == "fixture.login")
        #expect(login.declarationValue == .string("UncreatedLoginExecutable"))
        #expect(login.location.sourcePath == loginInfo.path)
        #expect(login.sourceSHA256 != nil)
        #expect(features.records.allSatisfy { $0.location.sourcePath.hasPrefix(bundle.path + "/") })
        #expect(try PersistenceStaticFeatureCollector.inspect(sourceURL: bundle, kind: .bundle, analyzedPath: bundle.path) == features)
    }

    @Test
    func malformedDeclarationsFailExplicitlyAndLabelAloneIsNotPersistenceEvidence() throws {
        let root = try persistenceFixtureDirectory()
        defer { cleanupPersistenceFixture(root) }
        let url = root.appendingPathComponent("selected.plist")
        for fragment in [
            "<key>ProgramArguments</key><array><integer>3</integer></array>",
            "<key>Program</key><string>/does/not/exist</string><key>RunAtLoad</key><integer>1</integer>",
            "<key>Program</key><string>/does/not/exist</string><key>KeepAlive</key><dict><key>SuccessfulExit</key><string>true</string></dict>",
            "<key>BundleProgram</key><string>../external-helper</string>",
            "<key>BundleProgram</key><string>/external-helper</string>"
        ] {
            try writePersistencePropertyList(xml: "<plist version=\"1.0\"><dict><key>Label</key><string>fixture.invalid</string>\(fragment)</dict></plist>", format: .xml, url: url)
            let features = try PersistenceStaticFeatureCollector.inspect(sourceURL: url, kind: .propertyList, analyzedPath: url.path)
            #expect(features.state == .unavailable)
            #expect(features.records.isEmpty)
            #expect(features.reason?.contains("invalid") == true)
        }
        try writePersistencePropertyList(xml: "<plist version=\"1.0\"><dict><key>Label</key><string>arbitrary.fixture</string></dict></plist>", format: .xml, url: url)
        let unrelated = try PersistenceStaticFeatureCollector.inspect(sourceURL: url, kind: .propertyList, analyzedPath: url.path)
        #expect(unrelated.state == .notApplicable)
        #expect(unrelated.records.isEmpty)
        try writePersistencePropertyList(xml: "<plist version=\"1.0\"><dict><key>Program</key><string>/does/not/exist</string></dict></plist>", format: .xml, url: url)
        let noLabel = try PersistenceStaticFeatureCollector.inspect(sourceURL: url, kind: .propertyList, analyzedPath: url.path)
        #expect(noLabel.state == .unavailable)
        #expect(noLabel.records.isEmpty)
        #expect(noLabel.reason?.contains("invalid Label") == true)
        try Data("not a plist".utf8).write(to: url)
        let malformed = try PersistenceStaticFeatureCollector.inspect(sourceURL: url, kind: .propertyList, analyzedPath: url.path)
        #expect(malformed.state == .unavailable)
        #expect(malformed.reason?.contains("decode persistence configuration") == true)
    }

    @Test
    func symlinkedFilesAndScopedDirectoriesAreNeverFollowed() throws {
        let root = try persistenceFixtureDirectory()
        defer { cleanupPersistenceFixture(root) }
        let externalDirectory = root.appendingPathComponent("outside-selected-bundle")
        let external = externalDirectory.appendingPathComponent("external.plist")
        try writePersistencePropertyList(xml: persistenceLaunchdXML(label: "outside.fixture", program: "/does/not/exist"), format: .xml, url: external)
        let selectedLink = root.appendingPathComponent("selected-link.plist")
        try FileManager.default.createSymbolicLink(at: selectedLink, withDestinationURL: external)
        let selected = try PersistenceStaticFeatureCollector.inspect(sourceURL: selectedLink, kind: .propertyList, analyzedPath: selectedLink.path)
        #expect(selected.state == .unavailable)
        #expect(selected.records.isEmpty)

        let bundle = root.appendingPathComponent("Symlink.app")
        try writePersistencePropertyList(xml: "<plist version=\"1.0\"><dict/></plist>", format: .xml, url: bundle.appendingPathComponent("Contents/Info.plist"))
        let library = bundle.appendingPathComponent("Contents/Library")
        try FileManager.default.createDirectory(at: library, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(at: library.appendingPathComponent("LaunchAgents"), withDestinationURL: externalDirectory)
        let features = try PersistenceStaticFeatureCollector.inspect(sourceURL: bundle, kind: .bundle, analyzedPath: bundle.path)
        #expect(features.state == .partial)
        #expect(features.records.isEmpty)
        #expect(features.reason?.contains("Symlink paths are not followed") == true)
        #expect(!features.records.contains { $0.declaredIdentifier == "outside.fixture" })
    }

    @Test
    func incompleteLoginItemRetainsLayoutWithAnExplicitPartialFailure() throws {
        let root = try persistenceFixtureDirectory()
        defer { cleanupPersistenceFixture(root) }
        let bundle = root.appendingPathComponent("Incomplete.app")
        try writePersistencePropertyList(xml: "<plist version=\"1.0\"><dict/></plist>", format: .xml, url: bundle.appendingPathComponent("Contents/Info.plist"))
        try FileManager.default.createDirectory(at: bundle.appendingPathComponent("Contents/Library/LoginItems/Empty.app"), withIntermediateDirectories: true)
        let features = try PersistenceStaticFeatureCollector.inspect(sourceURL: bundle, kind: .bundle, analyzedPath: bundle.path)
        #expect(features.state == .partial)
        #expect(features.records.map(\.kind) == [.loginItemBundle])
        #expect(features.reason?.contains("missing") == true)
    }

    @Test
    func scopedRecordAndFileBoundsAreReportedWithoutHostWideCollection() throws {
        let root = try persistenceFixtureDirectory()
        defer { cleanupPersistenceFixture(root) }
        let bundle = root.appendingPathComponent("Many.app")
        try writePersistencePropertyList(xml: "<plist version=\"1.0\"><dict/></plist>", format: .xml, url: bundle.appendingPathComponent("Contents/Info.plist"))
        let agents = bundle.appendingPathComponent("Contents/Library/LaunchAgents")
        for index in 0..<140 {
            let url = agents.appendingPathComponent(String(format: "%03d.plist", index))
            try writePersistencePropertyList(xml: persistenceLaunchdXML(label: "fixture.\(index)", program: "/does/not/exist"), format: .binary, url: url)
        }
        let features = try PersistenceStaticFeatureCollector.inspect(sourceURL: bundle, kind: .bundle, analyzedPath: bundle.path)
        #expect(features.state == .partial)
        #expect(features.records.count == 512)
        #expect(features.reason?.contains("configuration file count") == true)
        #expect(features.reason?.contains("export record count") == true)
        #expect(features.records.allSatisfy { $0.location.sourcePath.hasPrefix(agents.path + "/") })
        #expect(!features.records.contains { $0.declaredIdentifier == "fixture.139" })
    }

    @Test
    func oversizedDeepAndNonRegularConfigurationsFailWithinBounds() throws {
        let root = try persistenceFixtureDirectory()
        defer { cleanupPersistenceFixture(root) }
        let large = root.appendingPathComponent("large.plist")
        try Data(repeating: 0x20, count: 1_048_577).write(to: large)
        let oversized = try PersistenceStaticFeatureCollector.inspect(sourceURL: large, kind: .propertyList, analyzedPath: large.path)
        #expect(oversized.state == .unavailable)
        #expect(oversized.reason?.contains("property-list byte size") == true)
        let deep = root.appendingPathComponent("deep.plist")
        let nested = String(repeating: "<array>", count: 18) + "<string>deep</string>" + String(repeating: "</array>", count: 18)
        try writePersistencePropertyList(xml: "<plist version=\"1.0\"><dict><key>ProgramArguments</key>\(nested)</dict></plist>", format: .binary, url: deep)
        let nestedFeatures = try PersistenceStaticFeatureCollector.inspect(sourceURL: deep, kind: .propertyList, analyzedPath: deep.path)
        #expect(nestedFeatures.state == .unavailable)
        #expect(nestedFeatures.reason?.contains("value nesting depth") == true)
        let pipe = root.appendingPathComponent("pipe.plist")
        #expect(mkfifo(pipe.path, 0o600) == 0)
        let nonregular = try PersistenceStaticFeatureCollector.inspect(sourceURL: pipe, kind: .propertyList, analyzedPath: pipe.path)
        #expect(nonregular.state == .unavailable)
        #expect(nonregular.reason?.contains("unsupported filesystem type") == true)
    }

    @Test
    func cancelledCollectionPropagatesCancellation() async throws {
        let root = try persistenceFixtureDirectory()
        defer { cleanupPersistenceFixture(root) }
        let url = root.appendingPathComponent("cancelled.plist")
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try PersistenceStaticFeatureCollector.inspect(sourceURL: url, kind: .propertyList, analyzedPath: url.path)
        }
        do {
            _ = try await task.value
            Issue.record("Cancelled persistence collection unexpectedly completed.")
        } catch is CancellationError { }
    }
}

private func persistenceFixtureDirectory() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-persistence-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func cleanupPersistenceFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Persistence fixture cleanup failed: \(error.localizedDescription)") }
}

private func writePersistencePropertyList(xml: String, format: PropertyListSerialization.PropertyListFormat, url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    let native = try PropertyListSerialization.propertyList(from: Data(xml.utf8), options: [], format: nil)
    let bytes = try PropertyListSerialization.data(fromPropertyList: native, format: format, options: 0)
    try bytes.write(to: url)
}

private func persistenceLaunchdXML(label: String, program: String) -> String {
    """
    <plist version="1.0"><dict><key>Label</key><string>\(label)</string>
    <key>Program</key><string>\(program)</string><key>ProgramArguments</key><array><string>\(program)</string><string>--fixture</string></array>
    <key>BundleProgram</key><string>Contents/MacOS/FixtureHelper</string><key>RunAtLoad</key><false/>
    <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/><key>PathState</key><dict><key>/nonexistent/fixture-state</key><true/></dict></dict>
    <key>EnvironmentVariables</key><dict><key>TOKEN</key><string>UNRELATED-SECRET-MARKER</string></dict>
    </dict></plist>
    """
}
