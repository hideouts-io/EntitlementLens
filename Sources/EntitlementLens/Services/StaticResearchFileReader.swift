import Darwin
import Foundation

enum StaticResearchJSONLimit: String {
    case nestingDepth = "nesting depth"
    case valueNodes = "value node count"
    case stringBytes = "encoded string byte size"
}

enum StaticResearchFileError: LocalizedError {
    case unsupportedURL
    case unsafePath(String)
    case filesystem(operation: String, path: String, code: Int32)
    case unexpectedFileType(String)
    case limitExceeded(path: String, maximumBytes: Int)
    case changedDuringRead(String)
    case invalidJSONStructure(offset: Int, reason: String)
    case jsonLimitExceeded(limit: StaticResearchJSONLimit, maximum: Int)
    case cleanupFailed(path: String, code: Int32, primary: Error)

    var errorDescription: String? {
        switch self {
        case .unsupportedURL:
            "Research input must be a local file URL. Select a local JSON export or source artifact."
        case let .unsafePath(path):
            "Research input has an unsafe file path: \(path). Select a nonempty absolute path without NUL bytes."
        case let .filesystem(operation, path, code):
            "Could not \(operation) research input \(path): errno \(code) (\(String(cString: strerror(code)))). Final symlink paths are not followed."
        case let .unexpectedFileType(path):
            "Research input is not a regular file: \(path). Directories, FIFOs, and devices are unsupported."
        case let .limitExceeded(path, maximumBytes):
            "Research input exceeds the \(maximumBytes)-byte limit: \(path). Select an export or artifact within the collection bound."
        case let .changedDuringRead(path):
            "Research input changed while it was being read: \(path). Retry with an unchanged regular file."
        case let .invalidJSONStructure(offset, reason):
            "Research JSON has invalid structure at byte \(offset): \(reason). Select an intact JSON export."
        case let .jsonLimitExceeded(limit, maximum):
            "Research JSON exceeds the \(limit.rawValue) limit of \(maximum). Select an export within the collection bound."
        case let .cleanupFailed(path, code, primary):
            "\(Self.primaryFailureDescription(primary)) Closing the research input descriptor also failed at \(path): errno \(code) (\(String(cString: strerror(code))))."
        }
    }

    var containsCancellation: Bool {
        guard case let .cleanupFailed(_, _, primary) = self else { return false }
        if primary is CancellationError { return true }
        return (primary as? StaticResearchFileError)?.containsCancellation == true
    }

    private static func primaryFailureDescription(_ error: Error) -> String {
        if let error = error as? StaticResearchFileError { return error.localizedDescription }
        if error is CancellationError { return "Research input collection was cancelled." }
        return "Research input collection failed: \((error as NSError).domain) code \((error as NSError).code)."
    }
}

/// Reads immutable local byte snapshots without following a final symlink or loading inspected images.
enum StaticResearchFileReader {
    static let maximumExportBytes = 16 * 1_024 * 1_024
    static let maximumSourceBytes = 64 * 1_024 * 1_024
    static let maximumJSONDepth = 64
    static let maximumJSONNodes = 200_000
    static let maximumJSONStringBytes = 1_024 * 1_024
    private static let readChunkBytes = 16_384

    static func exportData(at url: URL) throws -> Data {
        try regularFileData(at: url, maximumBytes: maximumExportBytes)
    }

    static func sourceData(at url: URL) throws -> Data {
        try regularFileData(at: url, maximumBytes: maximumSourceBytes)
    }

    static func sourceData(at url: URL, maximumBytes: Int) throws -> Data {
        guard maximumBytes >= 0 else {
            throw StaticResearchFileError.limitExceeded(path: url.path, maximumBytes: 0)
        }
        return try regularFileData(at: url, maximumBytes: min(maximumSourceBytes, maximumBytes))
    }

    /// Bounds lexical structure before typed JSON decoding; JSONDecoder still validates grammar, UTF-8, and schema.
    /// Containers, member-name strings, value strings, and scalar tokens each consume one node.
    static func validateJSONStructure(_ data: Data) throws {
        try Task.checkCancellation()
        guard data.count <= maximumExportBytes else {
            throw StaticResearchFileError.limitExceeded(path: "JSON data", maximumBytes: maximumExportBytes)
        }
        try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            var containers: [UInt8] = []
            var nodeCount = 0
            var index = 0
            var nextCancellationCheck = 0
            while index < bytes.count {
                if index >= nextCancellationCheck {
                    try Task.checkCancellation()
                    nextCancellationCheck = index + readChunkBytes
                }
                let byte = bytes[index]
                switch byte {
                case 0x7B, 0x5B:
                    nodeCount = try incrementedNodeCount(nodeCount)
                    guard containers.count < maximumJSONDepth else {
                        throw StaticResearchFileError.jsonLimitExceeded(limit: .nestingDepth, maximum: maximumJSONDepth)
                    }
                    containers.append(byte)
                    index += 1
                case 0x7D, 0x5D:
                    let expected: UInt8 = byte == 0x7D ? 0x7B : 0x5B
                    guard containers.popLast() == expected else {
                        throw StaticResearchFileError.invalidJSONStructure(offset: index, reason: "The closing container does not match an open container.")
                    }
                    index += 1
                case 0x22:
                    nodeCount = try incrementedNodeCount(nodeCount)
                    index = try endOfJSONString(bytes, start: index)
                case 0x20, 0x09, 0x0A, 0x0D, 0x2C, 0x3A:
                    index += 1
                default:
                    nodeCount = try incrementedNodeCount(nodeCount)
                    index = try endOfScalarToken(bytes, start: index)
                }
            }
            guard containers.isEmpty else {
                throw StaticResearchFileError.invalidJSONStructure(offset: bytes.count, reason: "A container is not closed.")
            }
            guard nodeCount > 0 else {
                throw StaticResearchFileError.invalidJSONStructure(offset: 0, reason: "No JSON value is present.")
            }
        }
        try Task.checkCancellation()
    }

    private static func incrementedNodeCount(_ count: Int) throws -> Int {
        guard count < maximumJSONNodes else {
            throw StaticResearchFileError.jsonLimitExceeded(limit: .valueNodes, maximum: maximumJSONNodes)
        }
        return count + 1
    }

    private static func endOfJSONString(_ bytes: UnsafeRawBufferPointer, start: Int) throws -> Int {
        var index = start + 1
        var nextCancellationCheck = index
        while index < bytes.count {
            if index >= nextCancellationCheck {
                try Task.checkCancellation()
                nextCancellationCheck = index + readChunkBytes
            }
            guard index - start - 1 <= maximumJSONStringBytes else {
                throw StaticResearchFileError.jsonLimitExceeded(limit: .stringBytes, maximum: maximumJSONStringBytes)
            }
            let byte = bytes[index]
            if byte == 0x22 { return index + 1 }
            guard byte >= 0x20 else {
                throw StaticResearchFileError.invalidJSONStructure(offset: index, reason: "A string contains an unescaped control byte.")
            }
            if byte == 0x5C {
                guard index + 1 < bytes.count else {
                    throw StaticResearchFileError.invalidJSONStructure(offset: index, reason: "A string escape is incomplete.")
                }
                switch bytes[index + 1] {
                case 0x22, 0x5C, 0x2F, 0x62, 0x66, 0x6E, 0x72, 0x74:
                    index += 2
                case 0x75:
                    guard index + 5 < bytes.count,
                          (index + 2...index + 5).allSatisfy({ isHexadecimalDigit(bytes[$0]) }) else {
                        throw StaticResearchFileError.invalidJSONStructure(offset: index, reason: "A Unicode escape must contain four hexadecimal digits.")
                    }
                    index += 6
                default:
                    throw StaticResearchFileError.invalidJSONStructure(offset: index, reason: "A string has an unsupported JSON escape.")
                }
            } else {
                index += 1
            }
        }
        throw StaticResearchFileError.invalidJSONStructure(offset: start, reason: "A string is not terminated.")
    }

    private static func isHexadecimalDigit(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x41...0x46).contains(byte) || (0x61...0x66).contains(byte)
    }

    private static func endOfScalarToken(_ bytes: UnsafeRawBufferPointer, start: Int) throws -> Int {
        var index = start
        var nextCancellationCheck = index
        while index < bytes.count {
            if index >= nextCancellationCheck {
                try Task.checkCancellation()
                nextCancellationCheck = index + readChunkBytes
            }
            switch bytes[index] {
            case 0x20, 0x09, 0x0A, 0x0D, 0x2C, 0x3A, 0x7B, 0x7D, 0x5B, 0x5D, 0x22:
                return index
            default:
                index += 1
            }
        }
        return index
    }

    private static func regularFileData(at url: URL, maximumBytes: Int) throws -> Data {
        try Task.checkCancellation()
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost" else {
            throw StaticResearchFileError.unsupportedURL
        }
        let path = url.path
        guard !path.isEmpty, path.hasPrefix("/"), !path.contains("\0") else {
            throw StaticResearchFileError.unsafePath(path)
        }
        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
        guard descriptor >= 0 else { throw filesystemError(operation: "open", path: path) }
        let data: Data
        do { data = try boundedData(descriptor: descriptor, path: path, maximumBytes: maximumBytes) }
        catch {
            guard close(descriptor) == 0 else {
                throw StaticResearchFileError.cleanupFailed(path: path, code: errno, primary: error)
            }
            throw error
        }
        guard close(descriptor) == 0 else { throw filesystemError(operation: "close descriptor", path: path) }
        return data
    }

    private static func boundedData(descriptor: Int32, path: String, maximumBytes: Int) throws -> Data {
        var before = stat()
        guard fstat(descriptor, &before) == 0 else { throw filesystemError(operation: "read metadata", path: path) }
        guard before.st_mode & S_IFMT == S_IFREG else { throw StaticResearchFileError.unexpectedFileType(path) }
        guard before.st_size >= 0, before.st_size <= maximumBytes else {
            throw StaticResearchFileError.limitExceeded(path: path, maximumBytes: maximumBytes)
        }
        var data = Data()
        data.reserveCapacity(Int(before.st_size))
        var buffer = [UInt8](repeating: 0, count: readChunkBytes)
        while true {
            try Task.checkCancellation()
            let count = read(descriptor, &buffer, min(buffer.count, maximumBytes + 1 - data.count))
            guard count >= 0 else { throw filesystemError(operation: "read", path: path) }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
            guard data.count <= maximumBytes else {
                throw StaticResearchFileError.limitExceeded(path: path, maximumBytes: maximumBytes)
            }
        }
        try Task.checkCancellation()
        var after = stat()
        guard fstat(descriptor, &after) == 0 else { throw filesystemError(operation: "recheck metadata", path: path) }
        guard before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_mode == after.st_mode, before.st_nlink == after.st_nlink,
              before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              data.count == before.st_size else { throw StaticResearchFileError.changedDuringRead(path) }
        return data
    }

    private static func filesystemError(operation: String, path: String) -> StaticResearchFileError {
        .filesystem(operation: operation, path: path, code: errno)
    }
}
