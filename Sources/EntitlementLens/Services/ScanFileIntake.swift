import Darwin
import Foundation

enum ScanFileIntakeError: LocalizedError {
    case invalidURL
    case symbolicLink(String)
    case unsupported(String)
    case filesystem(operation: String, path: String, code: Int32)

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            "Scan File/App requires a local file with a nonempty absolute path without NUL bytes. Select a local Mach-O file, code bundle, or property list."
        case let .symbolicLink(path):
            "Scan File/App does not follow a symbolic link selected at \(path). Select the original file or bundle."
        case let .unsupported(path):
            "Scan File/App cannot inspect \(path). Select a Mach-O file, code bundle with a contained Mach-O executable, or property list. Use Scan Folder for ordinary directories and enable Deep carve there for raw files."
        case let .filesystem(operation, path, code):
            "Scan File/App could not \(operation) \(path): errno \(code) (\(String(cString: strerror(code)))). Check that the item exists and you have permission to read it, then select it again."
        }
    }
}

/// Preflights one explicit root before replacing results; bundle descendants remain within the existing enumerator's scope.
enum ScanFileIntake {
    static func validatedRoot(at url: URL) throws -> URL {
        guard url.isFileURL, url.host == nil || url.host == "" || url.host == "localhost",
              url.path.hasPrefix("/"), !url.path.contains("\0") else {
            throw ScanFileIntakeError.invalidURL
        }
        try Task.checkCancellation()
        try checkReadableItem(url)
        guard let file = try FileClassifier.classify(url), file.kind != .other else {
            throw ScanFileIntakeError.unsupported(url.path)
        }
        if file.kind == .bundle {
            let executable = try ArtifactAnalysisIdentity.analyzedURL(for: file).resolvingSymlinksInPath()
            try checkReadableItem(executable)
            guard try FileClassifier.classify(executable)?.kind == .machO else {
                throw ScanFileIntakeError.unsupported(executable.path)
            }
        }
        try Task.checkCancellation()
        return url.standardizedFileURL
    }

    private static func checkReadableItem(_ url: URL) throws {
        var metadata = stat()
        guard lstat(url.path, &metadata) == 0 else {
            throw filesystemError(operation: "read metadata for", url: url)
        }
        let kind = metadata.st_mode & S_IFMT
        guard kind != S_IFLNK else { throw ScanFileIntakeError.symbolicLink(url.path) }
        guard kind == S_IFREG || kind == S_IFDIR else { throw ScanFileIntakeError.unsupported(url.path) }
        let flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | (kind == S_IFDIR ? O_DIRECTORY : 0)
        let descriptor = open(url.path, flags)
        guard descriptor >= 0 else { throw filesystemError(operation: "open", url: url) }
        guard close(descriptor) == 0 else { throw filesystemError(operation: "close", url: url) }
    }

    private static func filesystemError(operation: String, url: URL) -> ScanFileIntakeError {
        ScanFileIntakeError.filesystem(operation: operation, path: url.path, code: errno)
    }
}
