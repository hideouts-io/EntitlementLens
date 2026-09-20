import CryptoKit
import Darwin
import Foundation

enum ArtifactProvenanceError: LocalizedError {
    case cannotOpen(String)
    case readFailed(String, String)
    case metadataFailed(String, Int32)
    case malformedSystemVersion(String)

    var errorDescription: String? {
        switch self {
        case let .cannotOpen(path):
            "Could not open \(path) for SHA-256 hashing."
        case let .readFailed(path, reason):
            "Could not read \(path) for SHA-256 hashing: \(reason)"
        case let .metadataFailed(path, code):
            "Could not read filesystem metadata for \(path): errno \(code) (\(String(cString: strerror(code))))."
        case let .malformedSystemVersion(path):
            "The system version property list at \(path) is missing required product or build fields."
        }
    }
}

enum ArtifactProvenanceCollector {
    static func collectCode(sourceURL: URL, analyzedURL: URL) throws -> ArtifactProvenance {
        try collect(
            sourceURL: sourceURL,
            analyzedURL: analyzedURL,
            machOSlices: try MachOInspector.inspect(analyzedURL)
        )
    }

    static func collectFile(_ url: URL) throws -> ArtifactProvenance {
        try collect(sourceURL: url, analyzedURL: url, machOSlices: [])
    }

    private static func collect(
        sourceURL: URL,
        analyzedURL: URL,
        machOSlices: [MachOSlice]
    ) throws -> ArtifactProvenance {
        let standardizedURL = analyzedURL.standardizedFileURL
        var metadata = stat()
        guard lstat(standardizedURL.path, &metadata) == 0 else {
            throw ArtifactProvenanceError.metadataFailed(standardizedURL.path, errno)
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: standardizedURL.path)
        let volumeValues = try standardizedURL.resourceValues(forKeys: [.volumeNameKey, .volumeUUIDStringKey])
        return ArtifactProvenance(
            analyzedPath: standardizedURL.path,
            sha256: try sha256(standardizedURL),
            fileSize: (attributes[.size] as? NSNumber)?.int64Value ?? Int64(metadata.st_size),
            createdAt: attributes[.creationDate] as? Date,
            modifiedAt: attributes[.modificationDate] as? Date,
            ownerUserID: metadata.st_uid,
            ownerGroupID: metadata.st_gid,
            posixMode: UInt16(metadata.st_mode & 0o7777),
            inode: UInt64(metadata.st_ino),
            deviceID: UInt64(metadata.st_dev),
            fileSystemFlags: metadata.st_flags,
            volumeName: volumeValues.volumeName,
            volumeUUID: volumeValues.volumeUUIDString,
            quarantineValue: try quarantineValue(standardizedURL),
            sourceOperatingSystem: try SourceOperatingSystemDetector.detect(containing: sourceURL),
            hostOperatingSystem: try SourceOperatingSystemDetector.current(),
            machOSlices: machOSlices
        )
    }

    static func sha256(_ url: URL) throws -> String {
        guard let stream = InputStream(url: url) else {
            throw ArtifactProvenanceError.cannotOpen(url.path)
        }
        stream.open()
        defer { stream.close() }
        var digest = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1_048_576)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count > 0 {
                digest.update(data: Data(buffer[0..<count]))
                continue
            }
            if count == 0 {
                break
            }
            let reason = stream.streamError?.localizedDescription ?? "InputStream returned a read error without details."
            throw ArtifactProvenanceError.readFailed(url.path, reason)
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func quarantineValue(_ url: URL) throws -> String? {
        let attribute = "com.apple.quarantine"
        let length = getxattr(url.path, attribute, nil, 0, 0, 0)
        if length < 0 {
            if errno == ENOATTR {
                return nil
            }
            throw ArtifactProvenanceError.metadataFailed(url.path, errno)
        }
        var bytes = [UInt8](repeating: 0, count: length)
        let readLength = getxattr(url.path, attribute, &bytes, bytes.count, 0, 0)
        guard readLength >= 0 else {
            throw ArtifactProvenanceError.metadataFailed(url.path, errno)
        }
        return String(decoding: bytes.prefix(readLength), as: UTF8.self)
    }
}

private enum SourceOperatingSystemDetector {
    private static let systemTreeComponents: Set<String> = [
        "Applications", "Library", "System", "bin", "sbin", "usr"
    ]

    static func current() throws -> SourceOperatingSystem {
        let rootURL = URL(fileURLWithPath: "/", isDirectory: true)
        guard let system = try read(rootURL: rootURL) else {
            throw ArtifactProvenanceError.malformedSystemVersion(
                "/System/Library/CoreServices/SystemVersion.plist"
            )
        }
        return system
    }

    static func detect(containing sourceURL: URL) throws -> SourceOperatingSystem? {
        let standardizedURL = sourceURL.standardizedFileURL
        var isDirectory = ObjCBool(false)
        let exists = FileManager.default.fileExists(atPath: standardizedURL.path, isDirectory: &isDirectory)
        var candidate = exists && isDirectory.boolValue
            ? standardizedURL
            : standardizedURL.deletingLastPathComponent()

        while true {
            if belongsToSystemTree(sourceURL: standardizedURL, rootURL: candidate),
               let system = try read(rootURL: candidate) {
                return system
            }
            if candidate.path == "/" {
                return nil
            }
            candidate.deleteLastPathComponent()
        }
    }

    private static func belongsToSystemTree(sourceURL: URL, rootURL: URL) -> Bool {
        let rootPath = rootURL.path == "/" ? "/" : rootURL.path + "/"
        guard sourceURL.path.hasPrefix(rootPath) else {
            return false
        }
        let relativePath = String(sourceURL.path.dropFirst(rootPath.count))
        guard let firstComponent = relativePath.split(separator: "/").first else {
            return false
        }
        return systemTreeComponents.contains(String(firstComponent))
    }

    private static func read(rootURL: URL) throws -> SourceOperatingSystem? {
        let plistURL = rootURL
            .appendingPathComponent("System", isDirectory: true)
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("CoreServices", isDirectory: true)
            .appendingPathComponent("SystemVersion.plist", isDirectory: false)
        guard FileManager.default.fileExists(atPath: plistURL.path) else {
            return nil
        }
        let data = try Data(contentsOf: plistURL)
        let object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dictionary = object as? [String: Any],
              let productName = dictionary["ProductName"] as? String,
              let productVersion = dictionary["ProductVersion"] as? String,
              let buildVersion = dictionary["ProductBuildVersion"] as? String else {
            throw ArtifactProvenanceError.malformedSystemVersion(plistURL.path)
        }
        return SourceOperatingSystem(
            rootPath: rootURL.path,
            productName: productName,
            productVersion: productVersion,
            buildVersion: buildVersion
        )
    }
}
