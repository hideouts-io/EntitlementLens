import Foundation
import Testing
@testable import EntitlementLens

struct ResearchCaseSchemaValidatorTests {
    @Test
    func acceptsProjectorEncodedCandidateAndReturnsReviewMetadata() throws {
        let candidate = ResearchCaseCandidate(
            schemaVersion: 1, caseID: "controlled-case", sampleKind: .controlledFixture,
            sourceReference: "Controlled fixture", artifactLabel: "Controlled fixture",
            artifactSHA256: String(repeating: "a", count: 64),
            collector: ResearchCaseCollector(name: "EntitlementLens", sourceCommit: String(repeating: "b", count: 40),
                featureSchemaVersion: 1, collectedAtUTC: "2026-10-22T10:00:00Z",
                hostMacOSVersion: "15.1.2", hostMacOSBuild: "24B83"),
            signatureIntegrity: .valid, entitlementCollectionState: .complete,
            architectures: [ResearchCaseArchitecture(name: "arm64", collectionState: .complete,
                signatureIntegrity: .valid, declarations: [
                    ResearchCaseDeclaration(key: "com.example.flag", value: .boolean(true)),
                    ResearchCaseDeclaration(key: "com.example.note", value: .string("reviewed")),
                    ResearchCaseDeclaration(key: "com.example.count", value: .integer(2)),
                    ResearchCaseDeclaration(key: "com.example.ratio", value: .real(0.5))
                ])],
            evidenceScope: "static_signed_declarations", runtimeAuthorization: "not_assessed"
        )
        let data = try ResearchCaseCandidateProjector.jsonData(for: candidate)
        let metadata = try ResearchCaseSchemaValidator.validate(data)
        #expect(metadata.caseID == "controlled-case")
        #expect(metadata.artifactLabel == "Controlled fixture")
        #expect(metadata.sourceCommit == String(repeating: "b", count: 40))
    }

    @Test
    func acceptsSchemaValidUnicodeAndWideIntegerWithoutReserializing() throws {
        let key = String(repeating: "💡", count: 256)
        let text = String(repeating: "e\u{0301}", count: 256)
        let candidate = try changed(caseJSON,
            replacing: "\"key\":\"com.example.flag\",\"value\":{\"type\":\"boolean\",\"boolean\":true}",
            with: "\"key\":\"\(key)\",\"value\":{\"type\":\"string\",\"string\":\"\(text)\"}")
        let wide = try changed(candidate, replacing: "\"feature_schema_version\":1",
            with: "\"feature_schema_version\":9223372036854775808")
        let integer = try changed(wide, replacing: "\"type\":\"string\",\"string\":\"\(text)\"",
            with: "\"type\":\"integer\",\"integer\":9223372036854775808")
        let metadata = try ResearchCaseSchemaValidator.validate(Data(integer.utf8))
        #expect(metadata.caseID == "case-one")
        _ = try ResearchCaseSchemaValidator.validate(Data(wide.utf8))
        let numeric = try changed(caseJSON, replacing: "\"feature_schema_version\":1",
            with: "\"feature_schema_version\":1.0")
        _ = try ResearchCaseSchemaValidator.validate(Data(numeric.utf8))
        let largeExponent = try changed(caseJSON, replacing: "\"feature_schema_version\":1",
            with: "\"feature_schema_version\":1e999999999999999999999999999")
        let largeInteger = try changed(largeExponent, replacing: "\"type\":\"boolean\",\"boolean\":true",
            with: "\"type\":\"integer\",\"integer\":1e999999999999999999999999999")
        _ = try ResearchCaseSchemaValidator.validate(Data(largeInteger.utf8))
        let exponentialOne = try changed(caseJSON, replacing: "\"schema_version\":1",
            with: "\"schema_version\":10e-1")
        _ = try ResearchCaseSchemaValidator.validate(Data(exponentialOne.utf8))
    }

    @Test
    func rejectsUnknownMissingAndDuplicateFieldsAtAllObjectLevels() throws {
        let unknownRoot = try changed(caseJSON, replacing: "\"schema_version\":1",
            with: "\"schema_version\":1,\"other\":\"unexpected\"")
        try expectInvalid(unknownRoot, path: "$")
        let unknownCollector = try changed(caseJSON, replacing: "\"name\":\"EntitlementLens\"",
            with: "\"name\":\"EntitlementLens\",\"other\":0")
        try expectInvalid(unknownCollector, path: "$.collector")
        let unknownArchitecture = try changed(caseJSON, replacing: "\"name\":\"arm64\"",
            with: "\"name\":\"arm64\",\"other\":0")
        try expectInvalid(unknownArchitecture, path: "$.architectures[0]")
        let unknownDeclaration = try changed(caseJSON, replacing: "\"key\":\"com.example.flag\"",
            with: "\"key\":\"com.example.flag\",\"other\":0")
        try expectInvalid(unknownDeclaration, path: "$.architectures[0].declarations[0]")
        let missing = try changed(caseJSON, replacing: ",\"runtime_authorization\":\"not_assessed\"", with: "")
        try expectInvalid(missing, path: "$.runtime_authorization")
        let duplicate = try changed(caseJSON, replacing: "\"case_id\":\"case-one\"",
            with: "\"case_id\":\"case-one\",\"\\u0063ase_id\":\"case-two\"")
        try expectInvalid(duplicate, path: "$")
    }

    @Test
    func rejectsWrongTypesEnumsConstantsAndOneOfShapes() throws {
        try expectInvalid(try changed(caseJSON, replacing: "\"schema_version\":1",
            with: "\"schema_version\":true"), path: "$.schema_version")
        try expectInvalid(try changed(caseJSON, replacing: "\"schema_version\":1",
            with: "\"schema_version\":1.00000000000000001"), path: "$.schema_version")
        try expectInvalid(try changed(caseJSON, replacing: "\"feature_schema_version\":1",
            with: "\"feature_schema_version\":0.99999999999999999999"), path: "$.collector.feature_schema_version")
        try expectInvalid(try changed(caseJSON, replacing: "\"evidence_scope\":\"static_signed_declarations\"",
            with: "\"evidence_scope\":\"runtime_granted\""), path: "$.evidence_scope")
        try expectInvalid(try changed(caseJSON, replacing: "\"signature_integrity\":\"valid\"",
            with: "\"signature_integrity\":\"trusted\""), path: "$.signature_integrity")
        try expectInvalid(try changed(caseJSON, replacing: "\"type\":\"boolean\",\"boolean\":true",
            with: "\"type\":\"boolean\",\"boolean\":1"), path: "$.architectures[0].declarations[0].value.boolean")
        try expectInvalid(try changed(caseJSON, replacing: "\"type\":\"boolean\",\"boolean\":true",
            with: "\"type\":\"integer\",\"integer\":true"), path: "$.architectures[0].declarations[0].value.integer")
        try expectInvalid(try changed(caseJSON, replacing: "\"type\":\"boolean\",\"boolean\":true",
            with: "\"type\":\"integer\",\"integer\":1.5"), path: "$.architectures[0].declarations[0].value.integer")
        try expectInvalid(try changed(caseJSON, replacing: "\"type\":\"boolean\",\"boolean\":true",
            with: "\"type\":\"integer\",\"integer\":1e-1000"), path: "$.architectures[0].declarations[0].value.integer")
        try expectInvalid(try changed(caseJSON, replacing: "\"type\":\"boolean\",\"boolean\":true",
            with: "\"type\":\"boolean\",\"boolean\":true,\"string\":\"extra\""),
            path: "$.architectures[0].declarations[0].value")
    }

    @Test
    func rejectsBoundsPatternsAndInvalidCalendarDate() throws {
        try expectInvalid(try changed(caseJSON, replacing: "\"case_id\":\"case-one\"",
            with: "\"case_id\":\"Case-One\""), path: "$.case_id")
        try expectInvalid(try changed(caseJSON, replacing: "\"source_reference\":\"Fixture\"",
            with: "\"source_reference\":\"/private/file\""), path: "$.source_reference")
        try expectInvalid(try changed(caseJSON, replacing: "\"collected_at_utc\":\"2026-10-22T10:00:00Z\"",
            with: "\"collected_at_utc\":\"2026-02-30T10:00:00Z\""), path: "$.collector.collected_at_utc")
        try expectInvalid(try changed(caseJSON, replacing: "\"feature_schema_version\":1",
            with: "\"feature_schema_version\":0"), path: "$.collector.feature_schema_version")
        try expectInvalid(try changed(caseJSON,
            replacing: "\"architectures\":[{\"name\":\"arm64\",\"collection_state\":\"complete\",\"signature_integrity\":\"valid\",\"declarations\":[{\"key\":\"com.example.flag\",\"value\":{\"type\":\"boolean\",\"boolean\":true}}]}]",
            with: "\"architectures\":[]"), path: "$.architectures")
        let tooLongKey = String(repeating: "💡", count: 257)
        try expectInvalid(try changed(caseJSON, replacing: "\"key\":\"com.example.flag\"",
            with: "\"key\":\"\(tooLongKey)\""), path: "$.architectures[0].declarations[0].key")
        let tooLongValue = String(repeating: "e\u{0301}", count: 257)
        try expectInvalid(try changed(caseJSON, replacing: "\"type\":\"boolean\",\"boolean\":true",
            with: "\"type\":\"string\",\"string\":\"\(tooLongValue)\""),
            path: "$.architectures[0].declarations[0].value.string")
    }

    @Test
    func dateTimeMatchesResearchValidatorCalendarZoneAndSeparatorCases() throws {
        let field = "\"collected_at_utc\":\"2026-10-22T10:00:00Z\""
        for date in [
            "2024-02-29T23:59:60Z", "2026-10-22t10:00:00z",
            "2026-10-22 10:00:00Z", "2026-10-22\\t10:00:00Z",
            "2026-10-22\u{00A0}10:00:00Z", "2026-10-22T00:59:60+01:00",
            "2026-10-22T10:00:00+23", "2026-10-22T10:00:00+2359",
            "2026-10-22T10:00:00+23:59", "2026-10-22T10:00:00.123Z"
        ] {
            let candidate = try changed(caseJSON, replacing: field, with: "\"collected_at_utc\":\"\(date)\"")
            _ = try ResearchCaseSchemaValidator.validate(Data(candidate.utf8))
        }
        for date in [
            "2025-02-29T10:00:00Z", "2026-10-22T10:00:00+24:00",
            "2026-10-22T10:00:00", "2026-10-22T25:00:00Z",
            "2026-10-22T10:60:00Z", "2026-10-22T10:00:00.Z",
            "2026-10-22T23:99:60+00:40", "2026-10-22T24:59:60+01:00"
        ] {
            try expectInvalid(try changed(caseJSON, replacing: field,
                with: "\"collected_at_utc\":\"\(date)\""), path: "$.collector.collected_at_utc")
        }
    }

    @Test
    func rejectsMalformedAndOversizedInput() throws {
        try expectInvalid("{\"case_id\":", path: "$")
        #expect(throws: ResearchCaseSchemaError.self) {
            _ = try ResearchCaseSchemaValidator.validate(Data(repeating: 0x20, count: ResearchCaseSchemaValidator.maximumBytes + 1))
        }
    }
}

private let caseJSON = """
{"schema_version":1,"case_id":"case-one","sample_kind":"controlled_fixture","source_reference":"Fixture","artifact_label":"Fixture","artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","collector":{"name":"EntitlementLens","source_commit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","feature_schema_version":1,"collected_at_utc":"2026-10-22T10:00:00Z","host_macos_version":"15.1.2","host_macos_build":"24B83"},"signature_integrity":"valid","entitlement_collection_state":"complete","architectures":[{"name":"arm64","collection_state":"complete","signature_integrity":"valid","declarations":[{"key":"com.example.flag","value":{"type":"boolean","boolean":true}}]}],"evidence_scope":"static_signed_declarations","runtime_authorization":"not_assessed"}
"""

private enum ResearchCaseTestFixtureError: Error {
    case missingReplacement
}

private func changed(_ input: String, replacing original: String, with replacement: String) throws -> String {
    guard input.contains(original) else { throw ResearchCaseTestFixtureError.missingReplacement }
    return input.replacingOccurrences(of: original, with: replacement)
}

private func expectInvalid(_ json: String, path: String) throws {
    do {
        _ = try ResearchCaseSchemaValidator.validate(Data(json.utf8))
        Issue.record("Expected an invalid case at \(path).")
    } catch let error as ResearchCaseSchemaError {
        switch error {
        case let .invalid(actualPath, _): #expect(actualPath == path)
        case .fileTooLarge: Issue.record("Expected a schema error at \(path), but the input exceeded the size limit.")
        }
    }
}
