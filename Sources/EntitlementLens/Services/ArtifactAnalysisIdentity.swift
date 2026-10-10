import Foundation

enum ArtifactAnalysisIdentityError: LocalizedError {
    case missingExecutable(String)
    case externalExecutable(String)
    case changedExecutable(String, String)
    case changedContents(String)

    var errorDescription: String? {
        switch self {
        case let .missingExecutable(path):
            "Could not resolve the executable declared by the bundle at \(path). Check its Info.plist and executable file before scanning again."
        case let .externalExecutable(path):
            "The executable declared by \(path) resolves outside the selected bundle. Select a bundle with a contained executable before scanning again."
        case let .changedExecutable(expected, actual):
            "The executable selected during analysis changed from \(expected) to \(actual). Stop changes to the bundle and scan it again."
        case let .changedContents(path):
            "The bytes of \(path) changed during static evidence collection. Stop changes to the file and scan it again; no finding was retained."
        }
    }
}

/// Compares hashes around path-based native inspection and rejects detected content changes.
struct ArtifactAnalysisIdentity: Sendable {
    let analyzedURL: URL
    let sha256: String

    static func capture(_ file: ClassifiedFile) throws -> ArtifactAnalysisIdentity {
        let analyzedURL: URL
        if file.kind == .bundle {
            guard let executable = Bundle(url: file.url)?.executableURL else {
                throw ArtifactAnalysisIdentityError.missingExecutable(file.url.path)
            }
            let rootComponents = file.url.resolvingSymlinksInPath().pathComponents
            let executableComponents = executable.resolvingSymlinksInPath().pathComponents
            guard executableComponents.count > rootComponents.count,
                  executableComponents.starts(with: rootComponents) else {
                throw ArtifactAnalysisIdentityError.externalExecutable(file.url.path)
            }
            analyzedURL = executable.standardizedFileURL
        } else {
            analyzedURL = file.url.standardizedFileURL
        }
        try Task.checkCancellation()
        return ArtifactAnalysisIdentity(analyzedURL: analyzedURL, sha256: try ArtifactProvenanceCollector.sha256(analyzedURL))
    }

    func verifyProvenance(_ provenance: ArtifactProvenance) throws {
        guard URL(fileURLWithPath: provenance.analyzedPath).resolvingSymlinksInPath() == analyzedURL.resolvingSymlinksInPath() else {
            throw ArtifactAnalysisIdentityError.changedExecutable(analyzedURL.path, provenance.analyzedPath)
        }
        guard provenance.sha256 == sha256 else {
            throw ArtifactAnalysisIdentityError.changedContents(analyzedURL.path)
        }
    }

    func verifyCurrentContents() throws {
        try Task.checkCancellation()
        guard try ArtifactProvenanceCollector.sha256(analyzedURL) == sha256 else {
            throw ArtifactAnalysisIdentityError.changedContents(analyzedURL.path)
        }
    }
}
