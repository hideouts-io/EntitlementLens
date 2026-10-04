import Foundation
import Testing
@testable import EntitlementLens

@MainActor
struct EntitlementExplorerIntegrationTests {
    @Test
    func signedDeclarationsSupportExactGlobAndTypedQueriesWithoutStaleResults() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-explorer-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Explorer fixture cleanup failed: \(error.localizedDescription)") }
        }
        let executable = try makeSignedUniversalFixture(root: root,
            arm64Entitlements: explorerArm64Plist(), x86Entitlements: explorerX86Plist())
        let supportingEvidence = root.appendingPathComponent("supporting.plist")
        try Data("<plist version=\"1.0\"><dict><key>com.apple.security.explorer-embedded-only</key><true/></dict></plist>".utf8)
            .write(to: supportingEvidence)
        let store = ScanStore()
        store.browserMode = .entitlements
        store.startScan(roots: [executable, supportingEvidence])
        try await waitForExplorer(store)
        #expect(store.lastError == nil)
        #expect(store.explorerQueryError == nil)
        #expect(store.findings.count == 2)
        let retainedFindings = store.findings
        #expect(!store.explorerGroups.contains { $0.key == "com.apple.security.explorer-embedded-only" })
        let rawFinding = try #require(store.findings.first { $0.path == supportingEvidence.path })
        #expect(rawFinding.signing == nil)
        #expect(!rawFinding.embeddedObjects.isEmpty)

        store.explorerKeyMode = .exact
        store.explorerKeyPattern = "fixture.shared"
        try await waitForExplorer(store)
        #expect(store.explorerGroups.isEmpty)
        store.explorerKeyPattern = "entitlementlens.fixture.CaseKey"
        try await waitForExplorer(store)
        #expect(store.explorerGroups.map(\.key) == ["entitlementlens.fixture.CaseKey"])
        store.explorerKeyPattern = "entitlementlens.fixture.casekey"
        try await waitForExplorer(store)
        #expect(store.explorerGroups.isEmpty)
        store.explorerKeyMode = .glob
        store.explorerKeyPattern = "entitlementlens.fixture.*"
        try await waitForExplorer(store)
        #expect(Set(store.explorerGroups.map(\.key)) == ["entitlementlens.fixture.CaseKey", "entitlementlens.fixture.shared",
            "entitlementlens.fixture.true", "entitlementlens.fixture.number"])
        store.explorerKeyPattern = "ENTITLEMENTLENS.*"
        try await waitForExplorer(store)
        #expect(store.explorerGroups.isEmpty)
        store.explorerKeyPattern = "entitlementlens.fixture.?aseKey"
        try await waitForExplorer(store)
        #expect(store.explorerGroups.map(\.key) == ["entitlementlens.fixture.CaseKey"])

        store.explorerKeyMode = .exact
        store.explorerKeyPattern = "entitlementlens.fixture.shared"
        store.explorerValueMode = .booleanFalse
        try await waitForExplorer(store)
        let booleanGroup = try #require(store.explorerGroups.first)
        #expect(architectureNames(booleanGroup.declarations) == ["arm64"])
        #expect(booleanGroup.declarations.allSatisfy { $0.value == .boolean(false) })
        store.explorerValueMode = .stringEquals
        store.explorerValueText = "false"
        try await waitForExplorer(store)
        let stringGroup = try #require(store.explorerGroups.first)
        #expect(architectureNames(stringGroup.declarations) == ["x86_64"])
        #expect(stringGroup.declarations.allSatisfy { $0.value == .string("false") })
        store.explorerValueMode = .integerEquals
        store.explorerValueText = "7"
        try await waitForExplorer(store)
        #expect(store.explorerGroups.isEmpty)
        store.explorerValueMode = .booleanTrue
        try await waitForExplorer(store)
        #expect(store.explorerGroups.isEmpty)
        store.explorerKeyPattern = "entitlementlens.fixture.true"
        try await waitForExplorer(store)
        #expect(store.explorerGroups.first?.declarations.allSatisfy { $0.value == .boolean(true) } == true)
        store.explorerKeyPattern = "com.apple.private.entitlementlens-explorer.absent"
        store.explorerValueMode = .booleanFalse
        try await waitForExplorer(store)
        #expect(store.explorerGroups.isEmpty)

        store.explorerKeyPattern = "entitlementlens.fixture.number"
        store.explorerValueMode = .integerEquals
        store.explorerValueText = "7"
        try await waitForExplorer(store)
        let integerGroup = try #require(store.explorerGroups.first)
        #expect(architectureNames(integerGroup.declarations) == ["arm64"])
        #expect(integerGroup.declarations.allSatisfy { $0.value == .integer(7) })
        store.explorerValueMode = .stringEquals
        try await waitForExplorer(store)
        let numericStringGroup = try #require(store.explorerGroups.first)
        #expect(architectureNames(numericStringGroup.declarations) == ["x86_64"])
        #expect(numericStringGroup.declarations.allSatisfy { $0.value == .string("7") })
        // The installed codesign rejects real-valued entitlement XML; this assertion validates numeric query parsing only.
        #expect(try entitlementValuePredicate(mode: .realEquals, text: "7") == .realEquals(7))
        store.explorerValueMode = .realEquals
        try await waitForExplorer(store)
        #expect(store.explorerGroups.isEmpty)
        for invalidReal in ["NaN", "inf"] {
            store.explorerValueText = invalidReal
            try await waitForExplorer(store)
            #expect(store.explorerQueryError != nil)
            #expect(store.explorerGroups.isEmpty)
        }
        store.explorerValueText = "7"
        try await waitForExplorer(store)
        #expect(store.explorerQueryError == nil)
        #expect(store.explorerGroups.isEmpty)
        store.explorerValueMode = .integerEquals
        store.explorerValueText = "7.5"
        try await waitForExplorer(store)
        #expect(store.explorerQueryError != nil)
        #expect(store.explorerGroups.isEmpty)
        store.explorerValueText = "7"
        try await waitForExplorer(store)
        #expect(store.explorerQueryError == nil)
        #expect(store.explorerGroups.map(\.key) == ["entitlementlens.fixture.number"])

        store.explorerValueMode = .any
        for pattern in ["entitlementlens.fixture.shared", "missing", "entitlementlens.fixture.number", "entitlementlens.fixture.true"] {
            store.explorerKeyPattern = pattern
        }
        try await waitForExplorer(store)
        #expect(store.explorerGroups.map(\.key) == ["entitlementlens.fixture.true"])
        store.selectedEntitlementKey = "entitlementlens.fixture.true"
        let declaration = try #require(store.selectedEntitlementDeclarations.first)
        store.selectedFindingID = declaration.findingID
        #expect(store.selectedFinding?.path == executable.path)
        store.selectedFilter = .embeddedObjects
        store.searchText = "supporting.plist"
        try await waitForExplorer(store)
        #expect(store.filteredFindings.map(\.id) == [rawFinding.id])
        #expect(store.selectedFindingID == declaration.findingID)
        store.browserMode = .files
        try await waitForExplorer(store)
        #expect(store.selectedFinding?.id == rawFinding.id)
        store.browserMode = .entitlements
        try await waitForExplorer(store)
        #expect(store.selectedFinding?.id == declaration.findingID)
        #expect(store.findings == retainedFindings)
        let json = try ResultExporter.data(for: store.findings, format: .json)
        #expect(try JSONDecoder().decode([ScanFinding].self, from: json) == retainedFindings)
        let csv = String(decoding: try ResultExporter.data(for: store.findings, format: .csv), as: UTF8.self)
        #expect(retainedFindings.allSatisfy { csv.contains($0.path) })
        #expect(csv.contains("entitlementlens.fixture.number"))

        let invalidExecutable = root.appendingPathComponent("invalid.universal")
        try FileManager.default.copyItem(at: executable, to: invalidExecutable)
        let slice = try #require(MachOInspector.inspect(executable).first { $0.architecture == "arm64" })
        let reservedOffset = try #require(Int(exactly: slice.fileOffset)) + 28
        var damaged = try Data(contentsOf: invalidExecutable)
        damaged[reservedOffset] ^= 1
        try damaged.write(to: invalidExecutable)
        store.startScan(roots: [invalidExecutable])
        store.explorerKeyPattern = "entitlementlens.fixture.shared"
        try await waitForExplorer(store)
        let invalidGroup = try #require(store.explorerGroups.first)
        let invalidDeclaration = try #require(invalidGroup.declarations.first {
            if case .architecture("arm64") = $0.source { return true }
            return false
        })
        guard case .invalid = invalidDeclaration.status else { throw ExplorerFixtureError.expectedInvalidSignature }
        #expect(invalidDeclaration.value == .boolean(false))
        #expect(invalidGroup.declarations.contains {
            if case .architecture("x86_64") = $0.source { return $0.status == .valid }
            return false
        })

        store.startScan(roots: [URL(fileURLWithPath: "/usr/bin/ssh")])
        store.explorerKeyPattern = "keychain-access-groups"
        try await waitForExplorer(store)
        let systemGroup = try #require(store.explorerGroups.first)
        #expect(systemGroup.key == "keychain-access-groups")
        #expect(systemGroup.executableCount == 1)
        #expect(systemGroup.declarations.allSatisfy { $0.path == "/usr/bin/ssh" && $0.status == .valid })

        store.startScan(roots: [URL(fileURLWithPath: "/usr/bin/true")])
        try await waitForExplorer(store)
        #expect(store.lastError == nil)
        #expect(store.findings.map(\.path) == ["/usr/bin/true"])
        #expect(store.explorerGroups.isEmpty)
        #expect(store.selectedEntitlementKey == nil)
        #expect(store.selectedEntitlementDeclarations.isEmpty)
    }

    @Test
    func bundleAndExecutableAliasesRetainAllDeclarationsWithOneExecutableCount() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-explorer-aliases-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Explorer app fixture cleanup failed: \(error.localizedDescription)") }
        }
        let universal = try makeSignedUniversalFixture(root: root,
            arm64Entitlements: explorerArm64Plist(), x86Entitlements: explorerX86Plist())
        let bundle = try makeSignedExplorerApp(root: root, universal: universal)
        let executable = bundle.appendingPathComponent("Contents/MacOS/Fixture")
        let analyzedPath = executable.resolvingSymlinksInPath().path
        let store = ScanStore()
        store.browserMode = .entitlements
        store.explorerKeyMode = .exact
        store.explorerKeyPattern = "entitlementlens.fixture.shared"
        store.startScan(roots: [bundle, executable])
        try await waitForExplorer(store)
        #expect(store.lastError == nil)
        let codeFindings = store.findings.filter { $0.signing != nil }
        #expect(codeFindings.count == 2)
        let bundleFinding = try #require(codeFindings.first { $0.kind == .bundle })
        let executableFinding = try #require(codeFindings.first { $0.kind == .machO })
        let group = try #require(store.explorerGroups.first)
        #expect(group.executableCount == 1)
        #expect(group.aliasCount == 2)
        #expect(group.declarations.count == 6)
        #expect(Set(group.declarations.map(\.path)) == [bundleFinding.path, executableFinding.path])
        #expect(bundleFinding.path == bundle.path)
        #expect(FileManager.default.contentsEqual(atPath: executableFinding.path, andPath: executable.path))
        #expect(Set(group.declarations.map(\.analyzedPath)) == [analyzedPath])
        #expect(group.declarations.allSatisfy { $0.status == .valid })
        #expect(group.declarations.contains {
            if case .architecture("arm64") = $0.source { return $0.value == .boolean(false) }
            return false
        })
        #expect(group.declarations.contains {
            if case .architecture("x86_64") = $0.source { return $0.value == .string("false") }
            return false
        })
        #expect(bundleFinding.signing?.resourceIntegrity == .verified)
        let executableSigning = try #require(executableFinding.signing)
        if case .notApplicable = executableSigning.resourceIntegrity {} else {
            Issue.record("The standalone executable unexpectedly has bundle-resource integrity state.")
        }
        #expect(group.declarations.filter { $0.findingID == bundleFinding.id }.count == 3)
        #expect(group.declarations.filter { $0.findingID == executableFinding.id }.count == 3)
        store.selectedEntitlementKey = group.key
        #expect(store.selectedEntitlementDeclarations.count == 6)
        store.selectedFindingID = bundleFinding.id
        #expect(store.selectedFinding?.kind == .bundle)

        let copiedBundle = root.appendingPathComponent("FixtureCopy.app", isDirectory: true)
        try FileManager.default.copyItem(at: bundle, to: copiedBundle)
        store.startScan(roots: [bundle, copiedBundle])
        try await waitForExplorer(store)
        let copiedGroup = try #require(store.explorerGroups.first)
        #expect(copiedGroup.executableCount == 2)
        #expect(copiedGroup.aliasCount == 4)
        #expect(copiedGroup.declarations.count == 12)
        #expect(Set(copiedGroup.declarations.map { $0.executableIdentity.sha256 }).count == 1)
        #expect(Set(copiedGroup.declarations.map { $0.executableIdentity.inode }).count == 2)
        #expect(copiedGroup.declarations.allSatisfy { $0.status == .valid })
    }

    @Test
    func stoppingRealScanRetainsCollectedExplorerDeclarations() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-explorer-stop-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer {
            do { try FileManager.default.removeItem(at: root) }
            catch { Issue.record("Stopped explorer fixture cleanup failed: \(error.localizedDescription)") }
        }
        let fixture = try makeSignedUniversalFixture(root: root,
            arm64Entitlements: explorerArm64Plist(), x86Entitlements: explorerX86Plist())
        let scanRoot = root.appendingPathComponent("executables", isDirectory: true)
        try FileManager.default.createDirectory(at: scanRoot, withIntermediateDirectories: false)
        for index in 0..<1_000 {
            try FileManager.default.copyItem(at: fixture, to: scanRoot.appendingPathComponent("fixture-\(index)"))
        }
        let store = ScanStore()
        store.browserMode = .entitlements
        store.explorerKeyMode = .exact
        store.explorerKeyPattern = "entitlementlens.fixture.shared"
        store.startScan(roots: [scanRoot])
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while store.findings.isEmpty && store.isScanning {
            guard ContinuousClock.now < deadline else { throw ExplorerFixtureError.partialScanTimeout(scanRoot.path) }
            try await Task.sleep(for: .milliseconds(1))
        }
        guard store.isScanning else { throw ExplorerFixtureError.scanCompletedBeforeStop(scanRoot.path) }
        store.cancelScan()
        let retained = store.findings
        let retainedIDs = retained.map(\.id)
        try #require(!retainedIDs.isEmpty)
        try await waitForExplorer(store)
        #expect(store.scanWasCancelled)
        #expect(!store.isScanning)
        #expect(store.findings.map(\.id) == retainedIDs)
        let group = try #require(store.explorerGroups.first { $0.key == "entitlementlens.fixture.shared" })
        let expected = try entitlementKeyGroups(entitlementDeclarations(retained), query: EntitlementExplorerQuery(
            keyPattern: "entitlementlens.fixture.shared", keyMode: .exact, valuePredicate: .any))
        let expectedGroup = try #require(expected.first)
        #expect(Set(group.declarations.map(\.id)) == Set(expectedGroup.declarations.map(\.id)))
        #expect(group.declarations.count == expectedGroup.declarations.count)
        #expect(Set(group.declarations.map(\.findingID)).isSubset(of: Set(retainedIDs)))
        let signedFindingCount = retained.filter { $0.signing != nil }.count
        #expect(group.executableCount == signedFindingCount)
        #expect(group.aliasCount == signedFindingCount)
    }

    private func waitForExplorer(_ store: ScanStore) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(30))
        while store.isScanning || store.isFiltering || store.isExploring {
            guard ContinuousClock.now < deadline else { throw ExplorerFixtureError.presentationTimeout }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}

private enum ExplorerFixtureError: LocalizedError {
    case presentationTimeout
    case expectedInvalidSignature
    case partialScanTimeout(String)
    case scanCompletedBeforeStop(String)
    case mismatchedResourceEnvelopes(String, String)

    var errorDescription: String? {
        switch self {
        case .presentationTimeout:
            "The explorer did not finish updating within 30 seconds."
        case .expectedInvalidSignature:
            "Changing the signed arm64 Mach-O header did not produce an invalid signature."
        case let .partialScanTimeout(path):
            "The real 1,000-executable scan at \(path) returned no partial findings within 30 seconds."
        case let .scanCompletedBeforeStop(path):
            "The real 1,000-executable scan at \(path) completed before a partial Stop could be observed; the Stop behavior was not tested."
        case let .mismatchedResourceEnvelopes(arm64, x86):
            "The separately signed fixture bundles have different CodeResources envelopes: \(arm64) and \(x86). They cannot be combined into one valid universal app."
        }
    }
}

private func architectureNames(_ declarations: [EntitlementDeclaration]) -> Set<String> {
    Set(declarations.compactMap {
        if case let .architecture(architecture) = $0.source { return architecture }
        return nil
    })
}

private func makeSignedExplorerApp(root: URL, universal: URL) throws -> URL {
    let arm64Bundle = root.appendingPathComponent("Arm64Fixture.app", isDirectory: true)
    let x86Bundle = root.appendingPathComponent("X86Fixture.app", isDirectory: true)
    let arm64 = try makeThinExplorerApp(bundle: arm64Bundle, architecture: "arm64", universal: universal,
        entitlements: root.appendingPathComponent("arm64.plist"))
    let x86 = try makeThinExplorerApp(bundle: x86Bundle, architecture: "x86_64", universal: universal,
        entitlements: root.appendingPathComponent("x86_64.plist"))
    let arm64Resources = arm64Bundle.appendingPathComponent("Contents/_CodeSignature/CodeResources")
    let x86Resources = x86Bundle.appendingPathComponent("Contents/_CodeSignature/CodeResources")
    guard try Data(contentsOf: arm64Resources) == Data(contentsOf: x86Resources) else {
        throw ExplorerFixtureError.mismatchedResourceEnvelopes(arm64Resources.path, x86Resources.path)
    }
    let bundle = root.appendingPathComponent("Fixture.app", isDirectory: true)
    try FileManager.default.copyItem(at: arm64Bundle, to: bundle)
    let executable = bundle.appendingPathComponent("Contents/MacOS/Fixture")
    _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
        arguments: ["lipo", "-create", arm64.path, x86.path, "-output", executable.path])
    _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/codesign"),
        arguments: ["--verify", "--strict", "--all-architectures", bundle.path])
    return bundle
}

private func makeThinExplorerApp(bundle: URL, architecture: String, universal: URL, entitlements: URL) throws -> URL {
    let contents = bundle.appendingPathComponent("Contents", isDirectory: true)
    let executable = contents.appendingPathComponent("MacOS/Fixture")
    try FileManager.default.createDirectory(at: executable.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data("""
    <plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>Fixture</string>
    <key>CFBundleIdentifier</key><string>io.hideouts.EntitlementLens.IntegrationFixture</string>
    <key>CFBundleName</key><string>Fixture</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>1</string>
    </dict></plist>
    """.utf8).write(to: contents.appendingPathComponent("Info.plist"))
    _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/xcrun"),
        arguments: ["lipo", "-thin", architecture, universal.path, "-output", executable.path])
    _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/codesign"),
        arguments: ["--force", "--sign", "-", "--entitlements", entitlements.path, bundle.path])
    return executable
}

private func explorerArm64Plist() -> Data {
    Data("""
    <plist version="1.0"><dict>
    <key>com.apple.private.entitlementlens-explorer.arm64</key><true/>
    <key>entitlementlens.fixture.shared</key><false/>
    <key>entitlementlens.fixture.true</key><true/>
    <key>entitlementlens.fixture.number</key><integer>7</integer>
    <key>entitlementlens.fixture.CaseKey</key><string>case-sensitive</string>
    </dict></plist>
    """.utf8)
}

private func explorerX86Plist() -> Data {
    Data("""
    <plist version="1.0"><dict>
    <key>com.apple.private.entitlementlens-explorer.x86-only</key><false/>
    <key>entitlementlens.fixture.shared</key><string>false</string>
    <key>entitlementlens.fixture.true</key><true/>
    <key>entitlementlens.fixture.number</key><string>7</string>
    <key>entitlementlens.fixture.CaseKey</key><string>case-sensitive</string>
    </dict></plist>
    """.utf8)
}
