import Foundation
import Security
import Testing
@testable import EntitlementLens

struct SignatureStaticFeatureIntegrationTests {
    @Test
    func detachedNativeCMSIsDecodedAndEncryptedOrUnboundedEnvelopesAreRejected() throws {
        let url = URL(fileURLWithPath: "/usr/bin/ssh")
        let cms = try signatureNativeCMS(url)
        let location = StaticEvidenceLocation(sourcePath: url.path, architecture: nil, sliceOffset: nil,
            fileOffset: nil, byteCount: nil, propertyListKey: nil, method: .securityFramework)
        let actual = try StaticCertificateInspector.inspect(cms: cms, chain: [], location: location)
        #expect(actual.state == .complete)
        #expect(!actual.records.isEmpty)
        #expect(actual.records.allSatisfy { $0.chainIndex == nil })
        let signedDataOID = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
        let typeRange = try #require(cms.range(of: signedDataOID))
        let encrypted = try signatureReplacingByte(cms, offset: typeRange.upperBound - 1, value: 0x03)
        #expect(throws: StaticSignatureCollectionError.self) {
            try StaticCertificateInspector.inspect(cms: encrypted, chain: [], location: location)
        }
        let indefinite = try signatureReplacingByte(cms, offset: 1, value: 0x80)
        #expect(throws: StaticSignatureCollectionError.self) {
            try StaticCertificateInspector.inspect(cms: indefinite, chain: [], location: location)
        }
    }

    @Test
    func nativeSignedCodeExportsEmbeddedCertificatesAndMatchingCodeDirectoryHashes() throws {
        let url = URL(fileURLWithPath: "/usr/bin/ssh")
        let slices = try MachOInspector.inspect(url)
        let result = try inspectStaticSignature(url)
        #expect(result.signer.state == .complete)
        #expect(result.signer.records.count == slices.count)
        #expect(result.signer.records.allSatisfy {
            $0.mode == .certificateBacked && $0.signatureIntegrity == .valid && $0.signingIdentifier != nil
        })
        #expect(result.embeddedCertificates.state == .complete)
        #expect(!result.embeddedCertificates.records.isEmpty)
        #expect(result.embeddedCertificates.records.allSatisfy {
            $0.source == .cmsEmbedded && $0.derSHA256.count == 64 && $0.derByteCount > 0
                && !$0.subject.isEmpty && !$0.issuer.isEmpty && $0.serialNumber != nil
                && $0.notBefore != nil && $0.notAfter != nil && $0.metadataState == .complete
        })
        for slice in slices {
            let certificates = result.embeddedCertificates.records.filter { $0.location.sliceOffset == slice.fileOffset }
            #expect(certificates.contains { $0.chainIndex == 0 })
            #expect(certificates.map(\.cmsIndex) == Array(certificates.indices))
            #expect(certificates.allSatisfy { $0.location.sourcePath == url.path && $0.location.architecture == slice.architecture })
        }
        #expect(result.codeDirectories.state == .complete)
        #expect(result.codeDirectories.records.count >= slices.count)
        #expect(result.codeDirectories.records.allSatisfy {
            $0.computedHash?.cdHash == $0.nativeCDHash && $0.nativeCDHash?.count == 40
                && $0.location.method == .codeDirectory && $0.location.fileOffset != nil
        })
        let encoded = try JSONEncoder().encode(result.embeddedCertificates)
        #expect(try JSONDecoder().decode(StaticFeatureCollection<StaticCertificate>.self, from: encoded)
            == result.embeddedCertificates)
        let directories = try JSONEncoder().encode(result.codeDirectories)
        #expect(try JSONDecoder().decode(StaticFeatureCollection<StaticCodeDirectory>.self, from: directories)
            == result.codeDirectories)
    }

    @Test
    func adHocUniversalAndUnsignedArtifactsRetainDifferentSigningModes() throws {
        let root = try signatureFixtureRoot()
        defer { removeSignatureFixture(root) }
        let empty = Data("<plist version=\"1.0\"><dict/></plist>".utf8)
        let universal = try makeSignedUniversalFixture(root: root, arm64Entitlements: empty, x86Entitlements: empty)
        let slices = try MachOInspector.inspect(universal)
        let adHoc = try inspectStaticSignature(universal)
        #expect(adHoc.signer.state == .complete)
        #expect(adHoc.signer.records.count == 2)
        #expect(adHoc.signer.records.allSatisfy { $0.mode == .adHoc && $0.signatureIntegrity == .valid && $0.teamIdentifier == nil })
        #expect(adHoc.embeddedCertificates.state == .complete)
        #expect(adHoc.embeddedCertificates.records.isEmpty)
        #expect(adHoc.codeDirectories.state == .complete)
        #expect(Set(adHoc.codeDirectories.records.map { $0.location.sliceOffset }) == Set(slices.map { Optional($0.fileOffset) }))
        #expect(Set(adHoc.codeDirectories.records.compactMap { $0.computedHash?.cdHash }).count == 2)
        let unsigned = root.appendingPathComponent("unsigned")
        try FileManager.default.copyItem(at: universal, to: unsigned)
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/codesign"),
            arguments: ["--remove-signature", unsigned.path])
        let unsignedResult = try inspectStaticSignature(unsigned)
        #expect(unsignedResult.signer.state == .complete)
        #expect(unsignedResult.signer.records.count == 2)
        #expect(unsignedResult.signer.records.allSatisfy { $0.mode == .unsigned && $0.signingIdentifier == nil && $0.teamIdentifier == nil })
        #expect(unsignedResult.embeddedCertificates.state == .complete)
        #expect(unsignedResult.embeddedCertificates.records.isEmpty)
        #expect(unsignedResult.codeDirectories.state == .complete)
        #expect(unsignedResult.codeDirectories.records.isEmpty)
    }

    @Test
    func nativeDualDigestSignaturesRetainPrimaryAndAlternateDirectories() throws {
        let root = try signatureFixtureRoot()
        defer { removeSignatureFixture(root) }
        let empty = Data("<plist version=\"1.0\"><dict/></plist>".utf8)
        let universal = try makeSignedUniversalFixture(root: root, arm64Entitlements: empty, x86Entitlements: empty)
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/codesign"),
            arguments: ["--force", "--sign", "-", "--timestamp=none", "--digest-algorithm=sha1,sha256",
                "--identifier", "io.hideouts.EntitlementLens.DualDigestFixture", universal.path])
        let result = try inspectStaticSignature(universal)
        let slices = try MachOInspector.inspect(universal)
        #expect(result.codeDirectories.state == .complete)
        for slice in slices {
            let records = result.codeDirectories.records.filter { $0.location.sliceOffset == slice.fileOffset }
            #expect(records.count == 2)
            #expect(records.map(\.kind) == [.primary, .alternate])
            #expect(Set(records.compactMap { $0.computedHash?.algorithm }) == [.sha1, .sha256])
            #expect(records.allSatisfy { $0.computedHash?.cdHash == $0.nativeCDHash })
            #expect(records.allSatisfy { $0.signingIdentifier == "io.hideouts.EntitlementLens.DualDigestFixture" })
        }
        let original = try Data(contentsOf: universal)
        let first = try #require(slices.first)
        let signatureOffset = Int(try #require(first.codeSignatureOffset))
        let alternateIndex = try signatureSlotIndex(data: original, signatureOffset: signatureOffset, slotType: 0x1000)
        let alternateOffset = signatureOffset + Int(try signatureBigUInt32(original, offset: alternateIndex + 4))
        let futureAlternate = root.appendingPathComponent("future-alternate")
        try signatureReplacingUInt32(original, offset: alternateOffset + 8, value: 0x20700).write(to: futureAlternate)
        let partial = try inspectStaticSignature(futureAlternate)
        #expect(partial.codeDirectories.state == .partial)
        let retained = partial.codeDirectories.records.filter { $0.location.sliceOffset == first.fileOffset }
        #expect(retained.count == 1)
        #expect(retained.first?.kind == .primary)
        #expect(retained.first?.computedHash?.algorithm == .sha1)
    }

    @Test
    func unsupportedAndMalformedSignatureCopiesPreserveUnaffectedSliceEvidence() throws {
        let root = try signatureFixtureRoot()
        defer { removeSignatureFixture(root) }
        let empty = Data("<plist version=\"1.0\"><dict/></plist>".utf8)
        let universal = try makeSignedUniversalFixture(root: root, arm64Entitlements: empty, x86Entitlements: empty)
        let original = try Data(contentsOf: universal)
        let slices = try MachOInspector.inspect(universal)
        let first = try #require(slices.first)
        let signatureOffset = Int(try #require(first.codeSignatureOffset))
        let primaryIndex = try signatureSlotIndex(data: original, signatureOffset: signatureOffset, slotType: 0)
        let primaryOffset = signatureOffset + Int(try signatureBigUInt32(original, offset: primaryIndex + 4))

        let future = root.appendingPathComponent("future-version")
        try signatureReplacingUInt32(original, offset: primaryOffset + 8, value: 0x20700).write(to: future)
        let futureResult = try inspectStaticSignature(future)
        #expect(futureResult.codeDirectories.state == .partial)
        #expect(futureResult.codeDirectories.records.allSatisfy { $0.location.sliceOffset != first.fileOffset })
        #expect(futureResult.codeDirectories.limitations.contains { $0.contains("0x20700") })

        let unknownHash = root.appendingPathComponent("unknown-hash")
        try signatureReplacingByte(original, offset: primaryOffset + 37, value: 99).write(to: unknownHash)
        let hashResult = try inspectStaticSignature(unknownHash)
        #expect(hashResult.codeDirectories.state == .partial)
        let unsupported = try #require(hashResult.codeDirectories.records.first { $0.location.sliceOffset == first.fileOffset })
        #expect(unsupported.hashType == 99)
        #expect(unsupported.computedHash == nil)
        #expect(unsupported.nativeCDHash == nil)
        #expect(!unsupported.warnings.isEmpty)

        let otherIndex = signatureOffset + 12 + (primaryIndex == signatureOffset + 12 ? 8 : 0)
        let overlapping = root.appendingPathComponent("overlapping-slots")
        let primaryRelativeOffset = try signatureBigUInt32(original, offset: primaryIndex + 4)
        try signatureReplacingUInt32(original, offset: otherIndex + 4, value: primaryRelativeOffset).write(to: overlapping)
        let overlapResult = try inspectStaticSignature(overlapping)
        #expect(overlapResult.codeDirectories.state == .partial)
        #expect(overlapResult.codeDirectories.records.allSatisfy { $0.location.sliceOffset != first.fileOffset })
        #expect(overlapResult.codeDirectories.limitations.contains { $0.contains("overlaps") })

        let oversized = root.appendingPathComponent("out-of-bounds-directory")
        try signatureReplacingUInt32(original, offset: primaryOffset + 16, value: UInt32.max).write(to: oversized)
        let oversizedResult = try inspectStaticSignature(oversized)
        #expect(oversizedResult.codeDirectories.state == .partial)
        #expect(oversizedResult.codeDirectories.records.allSatisfy { $0.location.sliceOffset != first.fileOffset })
        #expect(!oversizedResult.codeDirectories.limitations.isEmpty)

        let placeholder = root.appendingPathComponent("null-unrelated-slot")
        let requirementsIndex = try signatureSlotIndex(data: original, signatureOffset: signatureOffset, slotType: 2)
        try signatureReplacingUInt32(original, offset: requirementsIndex + 4, value: 0).write(to: placeholder)
        let placeholderResult = try inspectStaticSignature(placeholder)
        #expect(placeholderResult.codeDirectories.state == .complete)
        #expect(placeholderResult.codeDirectories.records.count == slices.count)

        let nullDirectory = root.appendingPathComponent("null-directory-slot")
        try signatureReplacingUInt32(original, offset: primaryIndex + 4, value: 0).write(to: nullDirectory)
        let nullResult = try inspectStaticSignature(nullDirectory)
        #expect(nullResult.codeDirectories.state == .partial)
        #expect(nullResult.codeDirectories.records.allSatisfy { $0.location.sliceOffset != first.fileOffset })
        #expect(nullResult.codeDirectories.limitations.contains { $0.contains("null") })
    }

    @Test
    func unsupportedFutureVersionAndHashAreExplicitWithoutOtherSlices() throws {
        let root = try signatureFixtureRoot()
        defer { removeSignatureFixture(root) }
        let empty = Data("<plist version=\"1.0\"><dict/></plist>".utf8)
        let universal = try makeSignedUniversalFixture(root: root, arm64Entitlements: empty, x86Entitlements: empty)
        let thin = root.appendingPathComponent("thin")
        _ = try runFixtureTool(executable: URL(fileURLWithPath: "/usr/bin/lipo"),
            arguments: [universal.path, "-thin", "arm64", "-output", thin.path])
        let original = try Data(contentsOf: thin)
        let slice = try #require(MachOInspector.inspect(thin).first)
        let signatureOffset = Int(try #require(slice.codeSignatureOffset))
        let primaryIndex = try signatureSlotIndex(data: original, signatureOffset: signatureOffset, slotType: 0)
        let primaryOffset = signatureOffset + Int(try signatureBigUInt32(original, offset: primaryIndex + 4))
        let future = root.appendingPathComponent("future-thin")
        try signatureReplacingUInt32(original, offset: primaryOffset + 8, value: 0x30000).write(to: future)
        let futureResult = try inspectStaticSignature(future)
        #expect(futureResult.codeDirectories.state == .unsupported)
        #expect(futureResult.codeDirectories.records.isEmpty)
        #expect(futureResult.codeDirectories.reason != nil)
        let hash = root.appendingPathComponent("unknown-hash-thin")
        try signatureReplacingByte(original, offset: primaryOffset + 37, value: 99).write(to: hash)
        let hashResult = try inspectStaticSignature(hash)
        #expect(hashResult.codeDirectories.state == .unsupported)
        #expect(hashResult.codeDirectories.records.count == 1)
        #expect(hashResult.codeDirectories.records.first?.computedHash == nil)
    }
}

private func inspectStaticSignature(_ url: URL) throws -> SignatureStaticInspection {
    try SignatureStaticFeatureCollector.inspect(sourceURL: url, analyzedURL: url,
        signing: EntitlementExtractor.inspect(url), slices: MachOInspector.inspect(url))
}

private func signatureNativeCMS(_ url: URL) throws -> Data {
    var code: SecStaticCode?
    let createStatus = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(rawValue: 0), &code)
    guard createStatus == errSecSuccess, let code else {
        throw StaticSignatureCollectionError.nativeOperation("CMS fixture code creation", createStatus)
    }
    var rawInformation: CFDictionary?
    let status = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &rawInformation)
    guard status == errSecSuccess, let rawInformation,
        let cms = (rawInformation as NSDictionary)[kSecCodeInfoCMS] as? Data else {
        throw StaticSignatureCollectionError.invalidNativeField("CMS fixture", "native signed CMS data")
    }
    return cms
}

private func signatureFixtureRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-signature-static-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    return root
}

private func removeSignatureFixture(_ root: URL) {
    do { try FileManager.default.removeItem(at: root) }
    catch { Issue.record("Static-signature fixture cleanup failed: \(error.localizedDescription)") }
}

private enum SignatureStaticFixtureError: Error {
    case outOfBounds(Int, Int)
    case missingSlot(UInt32)
}

private func signatureBigUInt32(_ data: Data, offset: Int) throws -> UInt32 {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw SignatureStaticFixtureError.outOfBounds(offset, data.count)
    }
    return data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
}

private func signatureSlotIndex(data: Data, signatureOffset: Int, slotType: UInt32) throws -> Int {
    let count = Int(try signatureBigUInt32(data, offset: signatureOffset + 8))
    for index in 0..<count {
        let offset = signatureOffset + 12 + index * 8
        if try signatureBigUInt32(data, offset: offset) == slotType { return offset }
    }
    throw SignatureStaticFixtureError.missingSlot(slotType)
}

private func signatureReplacingUInt32(_ data: Data, offset: Int, value: UInt32) throws -> Data {
    guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
        throw SignatureStaticFixtureError.outOfBounds(offset, data.count)
    }
    var copy = data
    copy.replaceSubrange(offset..<(offset + 4), with: [
        UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)
    ])
    return copy
}

private func signatureReplacingByte(_ data: Data, offset: Int, value: UInt8) throws -> Data {
    guard offset >= 0, offset < data.count else {
        throw SignatureStaticFixtureError.outOfBounds(offset, data.count)
    }
    var copy = data
    copy[offset] = value
    return copy
}
