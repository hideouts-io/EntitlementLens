import CryptoKit
import Darwin
import Foundation

enum PersistenceStaticCollectionError: LocalizedError {
    case missingPath(String)
    case filesystem(operation: String, path: String, code: Int32)
    case unexpectedFileType(String)
    case unsafeRelativePath(String)
    case limitExceeded(path: String, limit: String)
    case changedDuringRead(String)
    case malformedPropertyList(path: String, key: String, expected: String)
    case nativePropertyList(path: String, cause: Error)
    case cleanupFailed(path: String, operation: String, code: Int32, primary: Error)

    var errorDescription: String? {
        switch self {
        case let .missingPath(path):
            "The persistence configuration path is missing: \(path)."
        case let .filesystem(operation, path, code):
            "Could not \(operation) \(path): errno \(code) (\(String(cString: strerror(code)))). Symlink paths are not followed."
        case let .unexpectedFileType(path):
            "The persistence configuration path has an unsupported filesystem type: \(path)."
        case let .unsafeRelativePath(path):
            "A persistence configuration path is not a safe, contained relative path: \(path)."
        case let .limitExceeded(path, limit):
            "Persistence configuration collection reached the \(limit) limit at \(path)."
        case let .changedDuringRead(path):
            "Persistence configuration changed while it was being read: \(path). Rescan an unchanged artifact."
        case let .malformedPropertyList(path, key, expected):
            "Persistence configuration \(path) has an invalid \(key) declaration; expected \(expected)."
        case let .nativePropertyList(path, cause):
            "Could not decode persistence configuration \(path): \((cause as NSError).domain) code \((cause as NSError).code)."
        case let .cleanupFailed(path, operation, code, primary):
            "\(Self.primaryFailureDescription(primary)) Cleanup operation \(operation) also failed at \(path): errno \(code) (\(String(cString: strerror(code))))."
        }
    }

    var containsCancellation: Bool {
        switch self {
        case let .cleanupFailed(_, _, _, primary), let .nativePropertyList(_, primary):
            if primary is CancellationError { return true }
            return (primary as? PersistenceStaticCollectionError)?.containsCancellation == true
        default: return false
        }
    }

    private static func primaryFailureDescription(_ error: Error) -> String {
        if let error = error as? PersistenceStaticCollectionError { return error.localizedDescription }
        if error is CancellationError { return "Persistence configuration collection was cancelled." }
        return "Persistence configuration collection failed: \((error as NSError).domain) code \((error as NSError).code)."
    }
}

private struct PersistenceNativeValue {
    let value: Any
    let depth: Int
}

struct PersistenceStaticPropertyList {
    let values: [String: EntitlementValue]
    let sha256: String
    let byteCount: UInt64
}

/// An anchored descriptor prevents configuration reads through symlinked bundle components.
enum PersistenceStaticFileReader {
    static let maximumFileBytes = 1_048_576
    static let maximumDirectoryEntries = 256
    static let maximumContainerMembers = 1_024
    static let maximumValueNodes = 8_192
    static let maximumValueDepth = 16
    static let maximumStringBytes = 65_536
    static let maximumPathDepth = 8

    static func withDirectory<Result>(at url: URL, operation: (Int32) throws -> Result) throws -> Result {
        try Task.checkCancellation()
        let descriptor = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY | O_NONBLOCK)
        guard descriptor >= 0 else { throw filesystemError(operation: "open directory", path: url.path) }
        return try withDescriptor(descriptor, path: url.path, operation: operation)
    }

    static func confirmDirectory(root: Int32, relativePath: String, rootURL: URL) throws {
        try withContained(root: root, relativePath: relativePath, rootURL: rootURL, flags: O_DIRECTORY) { _ in () }
    }

    static func directoryEntries(root: Int32, relativePath: String, rootURL: URL) throws -> [String] {
        let path = rootURL.appendingPathComponent(relativePath).path
        return try withContained(root: root, relativePath: relativePath, rootURL: rootURL, flags: O_DIRECTORY) { descriptor in
            try withDirectoryStream(descriptor: descriptor, path: path) { directory in
                try readDirectoryNames(directory: directory, path: path)
            }
        }
    }

    private static func readDirectoryNames(directory: UnsafeMutablePointer<DIR>, path: String) throws -> [String] {
        var names: [String] = []
        while true {
            try Task.checkCancellation()
            errno = 0
            guard let entry = readdir(directory) else {
                guard errno == 0 else { throw filesystemError(operation: "enumerate directory", path: path) }
                return names.sorted()
            }
            let name: String? = withUnsafePointer(to: entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) {
                    String(validatingCString: $0)
                }
            }
            guard let name else {
                throw PersistenceStaticCollectionError.unexpectedFileType(path)
            }
            if name == "." || name == ".." { continue }
            guard names.count < maximumDirectoryEntries else {
                throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "directory entry count")
            }
            names.append(name)
        }
    }

    static func propertyList(root: Int32, relativePath: String, rootURL: URL, keys: [String]) throws -> PersistenceStaticPropertyList {
        let path = rootURL.appendingPathComponent(relativePath).path
        return try withContained(root: root, relativePath: relativePath, rootURL: rootURL, flags: 0) { descriptor in
            let data = try boundedData(descriptor: descriptor, path: path)
            let values = try projectedValues(data: data, path: path, keys: keys)
            let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            return PersistenceStaticPropertyList(values: values, sha256: hash, byteCount: UInt64(data.count))
        }
    }

    private static func withContained<Result>(root: Int32, relativePath: String, rootURL: URL, flags: Int32,
                                               operation: (Int32) throws -> Result) throws -> Result {
        let components = relativePath.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.isEmpty, components.count <= maximumPathDepth,
              components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("\0") }) else {
            throw PersistenceStaticCollectionError.unsafeRelativePath(relativePath)
        }
        return try withComponents(parent: root, components: components[...], path: rootURL.appendingPathComponent(relativePath).path,
                                  flags: flags, operation: operation)
    }

    private static func withComponents<Result>(parent: Int32, components: ArraySlice<Substring>, path: String,
                                                flags: Int32, operation: (Int32) throws -> Result) throws -> Result {
        try Task.checkCancellation()
        guard let component = components.first else { throw PersistenceStaticCollectionError.unsafeRelativePath(path) }
        let directoryFlag = components.count == 1 ? flags : O_DIRECTORY
        let descriptor = openat(parent, String(component), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | directoryFlag)
        guard descriptor >= 0 else { throw filesystemError(operation: "open contained configuration", path: path) }
        return try withDescriptor(descriptor, path: path) { descriptor in
            if components.count == 1 { return try operation(descriptor) }
            return try withComponents(parent: descriptor, components: components.dropFirst(), path: path, flags: flags, operation: operation)
        }
    }

    private static func withDescriptor<Result>(_ descriptor: Int32, path: String, operation: (Int32) throws -> Result) throws -> Result {
        let result: Result
        do { result = try operation(descriptor) }
        catch {
            guard close(descriptor) == 0 else {
                throw PersistenceStaticCollectionError.cleanupFailed(path: path, operation: "close descriptor", code: errno, primary: error)
            }
            throw error
        }
        guard close(descriptor) == 0 else { throw filesystemError(operation: "close descriptor", path: path) }
        return result
    }

    private static func withDirectoryStream<Result>(descriptor: Int32, path: String,
                                                     operation: (UnsafeMutablePointer<DIR>) throws -> Result) throws -> Result {
        let duplicate = dup(descriptor)
        guard duplicate >= 0 else { throw filesystemError(operation: "duplicate directory descriptor", path: path) }
        guard let directory = fdopendir(duplicate) else {
            let primary = filesystemError(operation: "open directory stream", path: path)
            guard close(duplicate) == 0 else {
                throw PersistenceStaticCollectionError.cleanupFailed(path: path, operation: "close directory descriptor", code: errno, primary: primary)
            }
            throw primary
        }
        let result: Result
        do { result = try operation(directory) }
        catch {
            guard closedir(directory) == 0 else {
                throw PersistenceStaticCollectionError.cleanupFailed(path: path, operation: "close directory stream", code: errno, primary: error)
            }
            throw error
        }
        guard closedir(directory) == 0 else { throw filesystemError(operation: "close directory stream", path: path) }
        return result
    }

    private static func boundedData(descriptor: Int32, path: String) throws -> Data {
        var before = stat()
        guard fstat(descriptor, &before) == 0 else { throw filesystemError(operation: "read metadata", path: path) }
        guard before.st_mode & S_IFMT == S_IFREG else { throw PersistenceStaticCollectionError.unexpectedFileType(path) }
        guard before.st_size >= 0, before.st_size <= maximumFileBytes else {
            throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "property-list byte size")
        }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            try Task.checkCancellation()
            let count = read(descriptor, &buffer, min(buffer.count, maximumFileBytes + 1 - data.count))
            guard count >= 0 else { throw filesystemError(operation: "read configuration", path: path) }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
            guard data.count <= maximumFileBytes else {
                throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "property-list byte size")
            }
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0 else { throw filesystemError(operation: "recheck metadata", path: path) }
        guard before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              data.count == before.st_size else { throw PersistenceStaticCollectionError.changedDuringRead(path) }
        return data
    }

    /// The native untyped boundary is projected and bounded before invoking the existing typed decoder.
    private static func projectedValues(data: Data, path: String, keys: [String]) throws -> [String: EntitlementValue] {
        let object: Any
        do { object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) }
        catch { throw PersistenceStaticCollectionError.nativePropertyList(path: path, cause: error) }
        guard let dictionary = object as? [String: Any] else {
            throw PersistenceStaticCollectionError.malformedPropertyList(path: path, key: "root", expected: "a dictionary")
        }
        guard dictionary.count <= maximumContainerMembers else {
            throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "dictionary member count")
        }
        var decoded: [String: EntitlementValue] = [:]
        for key in keys {
            try Task.checkCancellation()
            guard let value = dictionary[key] else { continue }
            try validateNativeValue(value, path: path)
            do { decoded[key] = try PropertyListValueDecoder.decode(value) }
            catch { throw PersistenceStaticCollectionError.nativePropertyList(path: path, cause: error) }
        }
        return decoded
    }

    private static func validateNativeValue(_ value: Any, path: String) throws {
        var pending = [PersistenceNativeValue(value: value, depth: 0)]
        var nodes = 0
        while let current = pending.popLast() {
            try Task.checkCancellation()
            nodes += 1
            guard nodes <= maximumValueNodes, pending.count <= maximumValueNodes else {
                throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "value node count")
            }
            guard current.depth <= maximumValueDepth else {
                throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "value nesting depth")
            }
            if let string = current.value as? String, string.utf8.count > maximumStringBytes {
                throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "string byte size")
            }
            if let values = current.value as? [Any] {
                guard values.count <= maximumContainerMembers else {
                    throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "array member count")
                }
                pending.append(contentsOf: values.map { PersistenceNativeValue(value: $0, depth: current.depth + 1) })
            }
            if let values = current.value as? [String: Any] {
                guard values.count <= maximumContainerMembers,
                      values.keys.allSatisfy({ $0.utf8.count <= maximumStringBytes }) else {
                    throw PersistenceStaticCollectionError.limitExceeded(path: path, limit: "dictionary member or key size")
                }
                pending.append(contentsOf: values.values.map { PersistenceNativeValue(value: $0, depth: current.depth + 1) })
            }
        }
    }

    private static func filesystemError(operation: String, path: String) -> PersistenceStaticCollectionError {
        let code = errno
        if code == ENOENT { return .missingPath(path) }
        return .filesystem(operation: operation, path: path, code: code)
    }
}
