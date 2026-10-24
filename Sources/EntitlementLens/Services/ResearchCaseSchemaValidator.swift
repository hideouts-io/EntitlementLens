import Foundation

struct ResearchCaseReviewMetadata: Hashable, Sendable {
    let caseID: String
    let artifactLabel: String
    let artifactSHA256: String
    let sourceCommit: String
}

enum ResearchCaseSchemaError: LocalizedError {
    case fileTooLarge(maximumBytes: Int)
    case invalid(path: String, reason: String)

    var errorDescription: String? {
        switch self {
        case let .fileTooLarge(maximumBytes):
            "The saved candidate exceeds the \(maximumBytes)-byte review limit. Choose a smaller case-v1 JSON file."
        case let .invalid(path, reason):
            "The saved candidate is invalid at \(path): \(reason) Choose a valid case-v1 JSON file."
        }
    }
}

/// Validates the complete closed case-v1 contract from EntitlementLens-Research.
/// Source schema SHA-256: c6266444b15c3cbf13368cef9d991bef0cefd483cf7f21c084952b0b06ee276e.
/// This checks structure only; it does not verify provenance, signatures, or sharing rights.
enum ResearchCaseSchemaValidator {
    static let maximumBytes = 8 * 1_024 * 1_024

    static func validate(_ data: Data) throws -> ResearchCaseReviewMetadata {
        guard data.count <= maximumBytes else {
            throw ResearchCaseSchemaError.fileTooLarge(maximumBytes: maximumBytes)
        }
        do {
            try StaticResearchFileReader.validateJSONStructure(data)
        } catch let error as StaticResearchFileError {
            switch error {
            case let .invalidJSONStructure(_, reason):
                throw ResearchCaseSchemaError.invalid(path: "$", reason: reason)
            case let .jsonLimitExceeded(limit, maximum):
                throw ResearchCaseSchemaError.invalid(path: "$", reason: "JSON \(limit.rawValue) exceeds the limit of \(maximum).")
            default:
                throw error
            }
        }
        var parser = ResearchCaseJSONParser(data: data)
        let root = try closedObject(try parser.parse(), path: "$", fields: [
            "schema_version", "case_id", "sample_kind", "source_reference", "artifact_label",
            "artifact_sha256", "collector", "signature_integrity", "entitlement_collection_state",
            "architectures", "evidence_scope", "runtime_authorization"
        ])
        let schemaVersion = try number(try field(root, "schema_version", path: "$"), path: "$.schema_version")
        guard schemaVersion.isExactlyOne else {
            throw ResearchCaseSchemaError.invalid(path: "$.schema_version", reason: "Expected case schema version 1.")
        }
        let caseID = try string(try field(root, "case_id", path: "$"), path: "$.case_id")
        guard caseID.unicodeScalars.count <= 100, validCaseID(caseID) else {
            throw ResearchCaseSchemaError.invalid(path: "$.case_id", reason: "Expected at most 100 lowercase ASCII letters or digits in nonempty hyphen-separated parts.")
        }
        try enumString(try field(root, "sample_kind", path: "$"), path: "$.sample_kind",
            allowed: ["controlled_fixture", "system_binary", "reviewed_scan"])
        _ = try safeLabel(try field(root, "source_reference", path: "$"), path: "$.source_reference", maximum: 140)
        let artifactLabel = try safeLabel(try field(root, "artifact_label", path: "$"), path: "$.artifact_label", maximum: 80)
        let artifactSHA256 = try hexString(try field(root, "artifact_sha256", path: "$"), path: "$.artifact_sha256", length: 64)
        let sourceCommit = try validateCollector(try field(root, "collector", path: "$"))
        try signatureIntegrity(try field(root, "signature_integrity", path: "$"), path: "$.signature_integrity")
        try collectionState(try field(root, "entitlement_collection_state", path: "$"), path: "$.entitlement_collection_state")
        let architectures = try array(try field(root, "architectures", path: "$"), path: "$.architectures")
        guard (1...16).contains(architectures.count) else {
            throw ResearchCaseSchemaError.invalid(path: "$.architectures", reason: "Expected 1–16 architecture records.")
        }
        for (index, architecture) in architectures.enumerated() {
            try validateArchitecture(architecture, path: "$.architectures[\(index)]")
        }
        try constant(try field(root, "evidence_scope", path: "$"), path: "$.evidence_scope", expected: "static_signed_declarations")
        try constant(try field(root, "runtime_authorization", path: "$"), path: "$.runtime_authorization", expected: "not_assessed")
        return ResearchCaseReviewMetadata(caseID: caseID, artifactLabel: artifactLabel,
            artifactSHA256: artifactSHA256, sourceCommit: sourceCommit)
    }

    private static func validateCollector(_ value: ResearchCaseJSONValue) throws -> String {
        let path = "$.collector"
        let object = try closedObject(value, path: path, fields: [
            "name", "source_commit", "feature_schema_version", "collected_at_utc", "host_macos_version", "host_macos_build"
        ])
        try constant(try field(object, "name", path: path), path: "\(path).name", expected: "EntitlementLens")
        let sourceCommit = try hexString(try field(object, "source_commit", path: path),
            path: "\(path).source_commit", length: 40)
        let featureVersion = try number(try field(object, "feature_schema_version", path: path),
            path: "\(path).feature_schema_version")
        guard featureVersion.isAtLeastOne, featureVersion.isInteger else {
            throw ResearchCaseSchemaError.invalid(path: "\(path).feature_schema_version", reason: "Expected an integer of at least 1.")
        }
        let date = try string(try field(object, "collected_at_utc", path: path), path: "\(path).collected_at_utc")
        guard validDateTime(date) else {
            throw ResearchCaseSchemaError.invalid(path: "\(path).collected_at_utc", reason: "Expected a valid case-v1 date and time with a time zone.")
        }
        let version = try string(try field(object, "host_macos_version", path: path), path: "\(path).host_macos_version")
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        guard (2...3).contains(parts.count), parts.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy(isDigit) }) else {
            throw ResearchCaseSchemaError.invalid(path: "\(path).host_macos_version", reason: "Expected two or three dot-separated numeric components.")
        }
        let build = try string(try field(object, "host_macos_build", path: path), path: "\(path).host_macos_build")
        guard !build.isEmpty, build.utf8.allSatisfy(isASCIIAlphaNumeric) else {
            throw ResearchCaseSchemaError.invalid(path: "\(path).host_macos_build", reason: "Expected a nonempty ASCII letter-and-digit build identifier.")
        }
        return sourceCommit
    }

    private static func validateArchitecture(_ value: ResearchCaseJSONValue, path: String) throws {
        let object = try closedObject(value, path: path, fields: ["name", "collection_state", "signature_integrity", "declarations"])
        let name = try string(try field(object, "name", path: path), path: "\(path).name")
        guard !name.isEmpty, name.unicodeScalars.count <= 40,
              name.utf8.allSatisfy({ isASCIIAlphaNumeric($0) || $0 == 0x5F || $0 == 0x2E }) else {
            throw ResearchCaseSchemaError.invalid(path: "\(path).name", reason: "Expected 1–40 ASCII letters, digits, underscores, or periods.")
        }
        try collectionState(try field(object, "collection_state", path: path), path: "\(path).collection_state")
        try signatureIntegrity(try field(object, "signature_integrity", path: path), path: "\(path).signature_integrity")
        let declarations = try array(try field(object, "declarations", path: path), path: "\(path).declarations")
        guard declarations.count <= 256 else {
            throw ResearchCaseSchemaError.invalid(path: "\(path).declarations", reason: "Expected at most 256 declarations.")
        }
        for (index, declaration) in declarations.enumerated() {
            try validateDeclaration(declaration, path: "\(path).declarations[\(index)]")
        }
    }

    private static func validateDeclaration(_ value: ResearchCaseJSONValue, path: String) throws {
        let object = try closedObject(value, path: path, fields: ["key", "value"])
        let key = try string(try field(object, "key", path: path), path: "\(path).key")
        guard (1...256).contains(key.unicodeScalars.count),
              !key.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" }) else {
            throw ResearchCaseSchemaError.invalid(path: "\(path).key", reason: "Expected 1–256 Unicode code points without carriage returns or line feeds.")
        }
        let valuePath = "\(path).value"
        let rawValue = try field(object, "value", path: path)
        guard case let .object(valueObject) = rawValue else {
            throw ResearchCaseSchemaError.invalid(path: valuePath, reason: "Expected a typed declaration object.")
        }
        let kind = try string(try field(valueObject, "type", path: valuePath), path: "\(valuePath).type")
        switch kind {
        case "boolean":
            _ = try closedObject(rawValue, path: valuePath, fields: ["type", "boolean"])
            guard case .boolean = try field(valueObject, "boolean", path: valuePath) else {
                throw ResearchCaseSchemaError.invalid(path: "\(valuePath).boolean", reason: "Expected a JSON boolean.")
            }
        case "string":
            _ = try closedObject(rawValue, path: valuePath, fields: ["type", "string"])
            let content = try string(try field(valueObject, "string", path: valuePath), path: "\(valuePath).string")
            guard content.unicodeScalars.count <= 512 else {
                throw ResearchCaseSchemaError.invalid(path: "\(valuePath).string", reason: "Expected at most 512 Unicode code points.")
            }
        case "integer":
            _ = try closedObject(rawValue, path: valuePath, fields: ["type", "integer"])
            let content = try number(try field(valueObject, "integer", path: valuePath), path: "\(valuePath).integer")
            guard content.isInteger else {
                throw ResearchCaseSchemaError.invalid(path: "\(valuePath).integer", reason: "Expected a JSON integer.")
            }
        case "real":
            _ = try closedObject(rawValue, path: valuePath, fields: ["type", "real"])
            _ = try number(try field(valueObject, "real", path: valuePath), path: "\(valuePath).real")
        default:
            throw ResearchCaseSchemaError.invalid(path: "\(valuePath).type", reason: "Expected boolean, string, integer, or real.")
        }
    }

    private static func closedObject(_ value: ResearchCaseJSONValue, path: String, fields: [String]) throws -> [String: ResearchCaseJSONValue] {
        guard case let .object(object) = value else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected a JSON object.")
        }
        let allowed = Set(fields)
        guard object.keys.allSatisfy(allowed.contains) else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "An unrecognized field is present.")
        }
        for fieldName in fields where object[fieldName] == nil {
            throw ResearchCaseSchemaError.invalid(path: "\(path).\(fieldName)", reason: "A required field is missing.")
        }
        return object
    }

    private static func field(_ object: [String: ResearchCaseJSONValue], _ name: String, path: String) throws -> ResearchCaseJSONValue {
        guard let value = object[name] else {
            throw ResearchCaseSchemaError.invalid(path: "\(path).\(name)", reason: "A required field is missing.")
        }
        return value
    }

    private static func string(_ value: ResearchCaseJSONValue, path: String) throws -> String {
        guard case let .string(text) = value else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected a JSON string.")
        }
        return text
    }

    private static func number(_ value: ResearchCaseJSONValue, path: String) throws -> ResearchCaseJSONNumber {
        guard case let .number(number) = value else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected a JSON number.")
        }
        return number
    }

    private static func array(_ value: ResearchCaseJSONValue, path: String) throws -> [ResearchCaseJSONValue] {
        guard case let .array(items) = value else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected a JSON array.")
        }
        return items
    }

    private static func constant(_ value: ResearchCaseJSONValue, path: String, expected: String) throws {
        guard try string(value, path: path) == expected else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "The case-v1 constant has an unexpected value.")
        }
    }

    private static func enumString(_ value: ResearchCaseJSONValue, path: String, allowed: Set<String>) throws {
        guard allowed.contains(try string(value, path: path)) else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "The value is outside the case-v1 allowed set.")
        }
    }

    private static func signatureIntegrity(_ value: ResearchCaseJSONValue, path: String) throws {
        try enumString(value, path: path, allowed: ["valid", "invalid", "unsigned", "unavailable"])
    }

    private static func collectionState(_ value: ResearchCaseJSONValue, path: String) throws {
        try enumString(value, path: path, allowed: ["complete", "partial", "not_collected", "unsupported", "unavailable", "not_applicable"])
    }

    private static func safeLabel(_ value: ResearchCaseJSONValue, path: String, maximum: Int) throws -> String {
        let label = try string(value, path: path)
        guard (1...maximum).contains(label.unicodeScalars.count),
              label.utf8.allSatisfy({ isASCIIAlphaNumeric($0) || [0x20, 0x2E, 0x5F, 0x2D].contains($0) }) else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected 1–\(maximum) ASCII letters, digits, spaces, periods, underscores, or hyphens.")
        }
        return label
    }

    private static func hexString(_ value: ResearchCaseJSONValue, path: String, length: Int) throws -> String {
        let text = try string(value, path: path)
        guard text.utf8.count == length,
              text.utf8.allSatisfy({ isDigit($0) || (0x61...0x66).contains($0) }) else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected exactly \(length) lowercase hexadecimal characters.")
        }
        return text
    }

    private static func validCaseID(_ text: String) -> Bool {
        let parts = text.split(separator: "-", omittingEmptySubsequences: false)
        return !parts.isEmpty && parts.allSatisfy {
            !$0.isEmpty && $0.utf8.allSatisfy { isDigit($0) || (0x61...0x7A).contains($0) }
        }
    }

    private static func validDateTime(_ text: String) -> Bool {
        let scalars = text.unicodeScalars
        guard let separatorIndex = scalars.index(scalars.startIndex, offsetBy: 10, limitedBy: scalars.endIndex),
              separatorIndex != scalars.endIndex, isDateTimeSeparator(scalars[separatorIndex]) else { return false }
        let dateBytes = [UInt8](text[..<separatorIndex].utf8)
        let timeStart = scalars.index(after: separatorIndex)
        let timeBytes = [UInt8](text[timeStart...].utf8)
        guard dateBytes.count == 10, timeBytes.count >= 9,
              dateBytes[4] == 0x2D, dateBytes[7] == 0x2D,
              timeBytes[2] == 0x3A, timeBytes[5] == 0x3A,
              let year = decimal(dateBytes, start: 0, count: 4),
              let month = decimal(dateBytes, start: 5, count: 2),
              let day = decimal(dateBytes, start: 8, count: 2),
              let hour = decimal(timeBytes, start: 0, count: 2),
              let minute = decimal(timeBytes, start: 3, count: 2),
              let second = decimal(timeBytes, start: 6, count: 2),
              (1...12).contains(month), hour <= 23, minute <= 59, second <= 60 else {
            return false
        }
        let days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
        guard day >= 1, day <= days[month] + (month == 2 && leap ? 1 : 0) else { return false }
        var index = 8
        if index < timeBytes.count, timeBytes[index] == 0x2E {
            index += 1
            let start = index
            while index < timeBytes.count && isDigit(timeBytes[index]) { index += 1 }
            guard index > start else { return false }
        }
        guard index < timeBytes.count else { return false }
        if timeBytes[index] == 0x5A || timeBytes[index] == 0x7A {
            guard index + 1 == timeBytes.count else { return false }
            if hour <= 23 && minute <= 59 && second < 60 { return true }
            return (hour == 23 && minute == 59) && second == 60
        }
        guard timeBytes[index] == 0x2B || timeBytes[index] == 0x2D else { return false }
        let sign = timeBytes[index] == 0x2D ? -1 : 1
        index += 1
        guard let offsetHour = decimal(timeBytes, start: index, count: 2), offsetHour <= 23 else { return false }
        index += 2
        var offsetMinute = 0
        if index < timeBytes.count {
            if timeBytes[index] == 0x3A { index += 1 }
            guard let parsed = decimal(timeBytes, start: index, count: 2), parsed <= 59 else { return false }
            offsetMinute = parsed
            index += 2
        }
        guard index == timeBytes.count else { return false }
        if hour <= 23 && minute <= 59 && second < 60 { return true }
        guard second == 60 else { return false }
        let utcMinute = minute - offsetMinute * sign
        let utcHour = hour - offsetHour * sign - (utcMinute < 0 ? 1 : 0)
        return (utcHour == 23 || utcHour == -1) && (utcMinute == 59 || utcMinute == -1)
    }

    private static func isDateTimeSeparator(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x54, 0x74, 0x09...0x0D, 0x20, 0xA0, 0x1680,
             0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
            true
        default:
            false
        }
    }

    private static func decimal(_ bytes: [UInt8], start: Int, count: Int) -> Int? {
        guard start >= 0, count > 0, start <= bytes.count - count else { return nil }
        var result = 0
        for byte in bytes[start..<(start + count)] {
            guard isDigit(byte) else { return nil }
            result = result * 10 + Int(byte - 0x30)
        }
        return result
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte)
    }

    private static func isASCIIAlphaNumeric(_ byte: UInt8) -> Bool {
        isDigit(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }
}
