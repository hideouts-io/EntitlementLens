import CoreFoundation
import Foundation

indirect enum EntitlementValue: Codable, Hashable, Sendable {
    case string(String)
    case boolean(Bool)
    case integer(Int64)
    case real(Double)
    case data(String)
    case date(Date)
    case array([EntitlementValue])
    case dictionary([String: EntitlementValue])

    var typeTitle: String {
        switch self {
        case .string: "String"
        case .boolean: "Boolean"
        case .integer: "Integer"
        case .real: "Real"
        case .data: "Data"
        case .date: "Date"
        case .array: "Array"
        case .dictionary: "Dictionary"
        }
    }

    var displayValue: String {
        switch self {
        case let .string(value):
            return value
        case let .boolean(value):
            return value ? "true" : "false"
        case let .integer(value):
            return String(value)
        case let .real(value):
            return String(value)
        case let .data(value):
            return "Base64: \(value)"
        case let .date(value):
            return value.formatted(date: .abbreviated, time: .standard)
        case let .array(values):
            return values.map(\.displayValue).joined(separator: ", ")
        case let .dictionary(values):
            return values
                .sorted { $0.key < $1.key }
                .map { "\($0.key): \($0.value.displayValue)" }
                .joined(separator: ", ")
        }
    }
}

enum PropertyListValueError: LocalizedError {
    case nonStringDictionaryKey
    case unsupportedValue(String)

    var errorDescription: String? {
        switch self {
        case .nonStringDictionaryKey:
            return "The property list contains a dictionary key that is not a string."
        case let .unsupportedValue(typeName):
            return "The property list contains an unsupported value of type \(typeName)."
        }
    }
}

enum PropertyListValueDecoder {
    static func decode(_ value: Any) throws -> EntitlementValue {
        let typeReference = value as CFTypeRef
        if CFGetTypeID(typeReference) == CFBooleanGetTypeID(), let boolean = value as? Bool {
            return .boolean(boolean)
        }
        if let string = value as? String {
            return .string(string)
        }
        if let number = value as? NSNumber {
            if CFNumberIsFloatType(number) {
                return .real(number.doubleValue)
            }
            return .integer(number.int64Value)
        }
        if let data = value as? Data {
            return .data(data.base64EncodedString())
        }
        if let date = value as? Date {
            return .date(date)
        }
        if let array = value as? [Any] {
            return .array(try array.map(decode))
        }
        if let dictionary = value as? [String: Any] {
            var decoded: [String: EntitlementValue] = [:]
            for (key, child) in dictionary {
                decoded[key] = try decode(child)
            }
            return .dictionary(decoded)
        }
        if value is NSDictionary {
            throw PropertyListValueError.nonStringDictionaryKey
        }
        throw PropertyListValueError.unsupportedValue(String(reflecting: type(of: value)))
    }
}
