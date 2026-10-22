import Foundation

indirect enum ResearchCaseJSONValue {
    case object([String: ResearchCaseJSONValue])
    case array([ResearchCaseJSONValue])
    case string(String)
    case number(ResearchCaseJSONNumber)
    case boolean(Bool)
    case null
}

/// Retains a JSON number's exact decimal value without an Int64 or binary floating-point conversion.
struct ResearchCaseJSONNumber {
    let token: String
    let negative: Bool
    let digits: [UInt8]
    let fractionDigits: Int
    let exponent: Int

    private var firstNonzeroIndex: Int? {
        digits.firstIndex(where: { $0 != 0x30 })
    }

    var isInteger: Bool {
        guard firstNonzeroIndex != nil else { return true }
        let trailingZeros = digits.reversed().prefix(while: { $0 == 0x30 }).count
        return exponent >= fractionDigits - trailingZeros
    }

    var isAtLeastOne: Bool {
        guard !negative, let first = firstNonzeroIndex else { return false }
        return exponent >= fractionDigits - (digits.count - first) + 1
    }

    var isExactlyOne: Bool {
        guard !negative, let first = firstNonzeroIndex, digits[first] == 0x31,
              digits[(first + 1)...].allSatisfy({ $0 == 0x30 }) else { return false }
        return exponent == fractionDigits - (digits.count - first - 1)
    }
}

/// Parses bounded JSON without losing duplicate object fields or conflating booleans with numbers.
struct ResearchCaseJSONParser {
    private let bytes: [UInt8]
    private let stringDecoder = JSONDecoder()
    private var position = 0

    init(data: Data) {
        bytes = [UInt8](data)
    }

    mutating func parse() throws -> ResearchCaseJSONValue {
        skipWhitespace()
        let value = try parseValue(path: "$", depth: 0)
        skipWhitespace()
        guard position == bytes.count else {
            throw ResearchCaseSchemaError.invalid(path: "$", reason: "Unexpected content follows the JSON value.")
        }
        return value
    }

    private mutating func parseValue(path: String, depth: Int) throws -> ResearchCaseJSONValue {
        try Task.checkCancellation()
        guard position < bytes.count else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "The JSON value is incomplete.")
        }
        switch bytes[position] {
        case 0x7B:
            return .object(try parseObject(path: path, depth: depth))
        case 0x5B:
            return .array(try parseArray(path: path, depth: depth))
        case 0x22:
            return .string(try parseString(path: path))
        case 0x74:
            try parseLiteral([0x74, 0x72, 0x75, 0x65], path: path)
            return .boolean(true)
        case 0x66:
            try parseLiteral([0x66, 0x61, 0x6C, 0x73, 0x65], path: path)
            return .boolean(false)
        case 0x6E:
            try parseLiteral([0x6E, 0x75, 0x6C, 0x6C], path: path)
            return .null
        case 0x2D, 0x30...0x39:
            return .number(try parseNumber(path: path))
        default:
            throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected a JSON value.")
        }
    }

    private mutating func parseObject(path: String, depth: Int) throws -> [String: ResearchCaseJSONValue] {
        guard depth < 64 else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "JSON nesting exceeds the supported limit.")
        }
        position += 1
        skipWhitespace()
        var result: [String: ResearchCaseJSONValue] = [:]
        if consume(0x7D) { return result }
        while true {
            guard position < bytes.count, bytes[position] == 0x22 else {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected an object field name.")
            }
            let key = try parseString(path: path)
            guard result[key] == nil else {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "Duplicate object field names are not allowed.")
            }
            skipWhitespace()
            guard consume(0x3A) else {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected a colon after an object field name.")
            }
            skipWhitespace()
            // Schema validation uses fixed field names, so an untrusted key is never included in an error path.
            result[key] = try parseValue(path: path, depth: depth + 1)
            skipWhitespace()
            if consume(0x7D) { return result }
            guard consume(0x2C) else {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected a comma or closing brace.")
            }
            skipWhitespace()
        }
    }

    private mutating func parseArray(path: String, depth: Int) throws -> [ResearchCaseJSONValue] {
        guard depth < 64 else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "JSON nesting exceeds the supported limit.")
        }
        position += 1
        skipWhitespace()
        var result: [ResearchCaseJSONValue] = []
        if consume(0x5D) { return result }
        while true {
            result.append(try parseValue(path: "\(path)[\(result.count)]", depth: depth + 1))
            skipWhitespace()
            if consume(0x5D) { return result }
            guard consume(0x2C) else {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "Expected a comma or closing bracket.")
            }
            skipWhitespace()
        }
    }

    private mutating func parseString(path: String) throws -> String {
        let start = position
        position += 1
        while position < bytes.count {
            let byte = bytes[position]
            position += 1
            if byte == 0x22 {
                do {
                    return try stringDecoder.decode(String.self, from: Data(bytes[start..<position]))
                } catch {
                    throw ResearchCaseSchemaError.invalid(path: path, reason: "A JSON string has invalid UTF-8 or escapes.")
                }
            }
            if byte == 0x5C {
                guard position < bytes.count else { break }
                position += 1
            } else if byte < 0x20 {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "A JSON string contains an unescaped control character.")
            }
        }
        throw ResearchCaseSchemaError.invalid(path: path, reason: "A JSON string is incomplete.")
    }

    private mutating func parseNumber(path: String) throws -> ResearchCaseJSONNumber {
        let start = position
        let negative = consume(0x2D)
        if negative, position == bytes.count {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "A JSON number is incomplete.")
        }
        let integerStart = position
        if consume(0x30) {
            // A following digit is rejected by the containing parser as unexpected content.
        } else {
            guard position < bytes.count, (0x31...0x39).contains(bytes[position]) else {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "A JSON number has an invalid integer part.")
            }
            repeat { position += 1 } while position < bytes.count && isDigit(bytes[position])
        }
        let integerEnd = position
        var fractionStart = position
        var fractionEnd = position
        if consume(0x2E) {
            guard position < bytes.count, isDigit(bytes[position]) else {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "A JSON number has an incomplete fraction.")
            }
            fractionStart = position
            repeat { position += 1 } while position < bytes.count && isDigit(bytes[position])
            fractionEnd = position
        }
        var exponent = 0
        if consume(0x65) || consume(0x45) {
            let exponentNegative = !consume(0x2B) && consume(0x2D)
            guard position < bytes.count, isDigit(bytes[position]) else {
                throw ResearchCaseSchemaError.invalid(path: path, reason: "A JSON number has an incomplete exponent.")
            }
            let saturation = bytes.count + 1
            repeat {
                if exponent < saturation {
                    exponent = min(saturation, exponent * 10 + Int(bytes[position] - 0x30))
                }
                position += 1
            } while position < bytes.count && isDigit(bytes[position])
            if exponentNegative { exponent = -exponent }
        }
        var digits = [UInt8](bytes[integerStart..<integerEnd])
        digits.append(contentsOf: bytes[fractionStart..<fractionEnd])
        return ResearchCaseJSONNumber(token: String(decoding: bytes[start..<position], as: UTF8.self),
            negative: negative, digits: digits, fractionDigits: fractionEnd - fractionStart, exponent: exponent)
    }

    private mutating func parseLiteral(_ literal: [UInt8], path: String) throws {
        guard bytes.count - position >= literal.count,
              bytes[position..<(position + literal.count)].elementsEqual(literal) else {
            throw ResearchCaseSchemaError.invalid(path: path, reason: "A JSON literal is invalid.")
        }
        position += literal.count
    }

    private mutating func skipWhitespace() {
        while position < bytes.count && [0x20, 0x09, 0x0A, 0x0D].contains(bytes[position]) {
            position += 1
        }
    }

    private mutating func consume(_ byte: UInt8) -> Bool {
        guard position < bytes.count, bytes[position] == byte else { return false }
        position += 1
        return true
    }

    private func isDigit(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte)
    }
}
