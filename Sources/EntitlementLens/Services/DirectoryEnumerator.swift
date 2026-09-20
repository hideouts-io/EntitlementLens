import Darwin
import Foundation

enum FileEnumerationEvent: Sendable {
    case url(URL)
    case issue(ScanIssue)
}

private struct FileIdentity: Hashable {
    let device: UInt64
    let inode: UInt64
}

enum DirectoryEnumerator {
    static func enumerate(
        configuration: ScanConfiguration,
        receive: @escaping @Sendable (FileEnumerationEvent) async -> Void
    ) async {
        var visited: Set<FileIdentity> = []
        for root in configuration.roots {
            guard !Task.isCancelled else {
                return
            }
            guard !isExcluded(root, prefixes: configuration.excludedPathPrefixes) else {
                await receive(.issue(AccessIssueClassifier.skipped(path: root.path, operation: .enumerateDirectory,
                    reason: "Excluded scan root; descendants were not enumerated.")))
                continue
            }
            do {
                guard let identity = try fileIdentity(root), visited.insert(identity).inserted else {
                    await receive(.issue(AccessIssueClassifier.skipped(path: root.path, operation: .readMetadata,
                        reason: "Symbolic link or previously enumerated file identity; not analyzed again.")))
                    continue
                }
                await receive(.url(root))
                let rootValues = try root.resourceValues(forKeys: [.isDirectoryKey])
                guard rootValues.isDirectory == true else {
                    continue
                }
            } catch {
                await receive(.issue(AccessIssueClassifier.classify(
                    error: error,
                    path: root.path,
                    operation: .readMetadata
                )))
                continue
            }

            var pendingErrors: [(URL, Error)] = []
            guard let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: [
                    .isDirectoryKey,
                    .isRegularFileKey,
                    .isSymbolicLinkKey,
                    .isHiddenKey,
                    .fileSizeKey
                ],
                options: [],
                errorHandler: { url, error in
                    pendingErrors.append((url, error))
                    return true
                }
            ) else {
                await receive(.issue(AccessIssueClassifier.analysisIssue(
                    path: root.path,
                    operation: .enumerateDirectory,
                    message: "FileManager could not create a directory enumerator for this location."
                )))
                continue
            }

            while let object = enumerator.nextObject() {
                for (url, error) in pendingErrors {
                    await receive(.issue(AccessIssueClassifier.classify(
                        error: error,
                        path: url.path,
                        operation: .enumerateDirectory
                    )))
                }
                pendingErrors.removeAll(keepingCapacity: true)
                guard !Task.isCancelled else {
                    return
                }
                guard let url = object as? URL else {
                    await receive(.issue(AccessIssueClassifier.analysisIssue(
                        path: root.path,
                        operation: .enumerateDirectory,
                        message: "FileManager returned a directory entry that is not a file URL."
                    )))
                    continue
                }
                if isExcluded(url, prefixes: configuration.excludedPathPrefixes) {
                    enumerator.skipDescendants()
                    await receive(.issue(AccessIssueClassifier.skipped(path: url.path, operation: .enumerateDirectory,
                        reason: "Excluded path; descendants were not enumerated.")))
                    continue
                }
                do {
                    let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey, .isHiddenKey])
                    if !configuration.includeHidden && values.isHidden == true {
                        enumerator.skipDescendants()
                        await receive(.issue(AccessIssueClassifier.skipped(path: url.path, operation: .enumerateDirectory,
                            reason: "Hidden item excluded by scan options; descendants were not enumerated.")))
                        continue
                    }
                    if values.isSymbolicLink == true {
                        enumerator.skipDescendants()
                        await receive(.issue(AccessIssueClassifier.skipped(path: url.path, operation: .readMetadata,
                            reason: "Symbolic link not followed.")))
                        continue
                    }
                    guard let identity = try fileIdentity(url), visited.insert(identity).inserted else {
                        if values.isDirectory == true {
                            enumerator.skipDescendants()
                        }
                        await receive(.issue(AccessIssueClassifier.skipped(path: url.path, operation: .readMetadata,
                            reason: "Previously enumerated file identity; not analyzed again.")))
                        continue
                    }
                    await receive(.url(url))
                } catch {
                    await receive(.issue(AccessIssueClassifier.classify(
                        error: error,
                        path: url.path,
                        operation: .readMetadata
                    )))
                }
            }
            for (url, error) in pendingErrors {
                await receive(.issue(AccessIssueClassifier.classify(
                    error: error,
                    path: url.path,
                    operation: .enumerateDirectory
                )))
            }
        }
    }

    private static func fileIdentity(_ url: URL) throws -> FileIdentity? {
        var metadata = stat()
        guard lstat(url.path, &metadata) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        if (metadata.st_mode & S_IFMT) == S_IFLNK {
            return nil
        }
        return FileIdentity(device: UInt64(metadata.st_dev), inode: UInt64(metadata.st_ino))
    }

    private static func isExcluded(_ url: URL, prefixes: [URL]) -> Bool {
        let path = url.standardizedFileURL.path
        return prefixes.contains { prefix in
            let excluded = prefix.standardizedFileURL.path
            return path == excluded || path.hasPrefix(excluded + "/")
        }
    }
}
