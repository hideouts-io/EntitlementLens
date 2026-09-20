import AppKit
import Foundation

enum ResultItemActionError: LocalizedError {
    case missingItem(String)
    case textEditUnavailable
    case pasteboardWriteFailed

    var errorDescription: String? {
        switch self {
        case let .missingItem(path): "The item no longer exists at \(path)."
        case .textEditUnavailable: "TextEdit could not be located on this Mac."
        case .pasteboardWriteFailed: "The data could not be written to the clipboard."
        }
    }
}

enum ResultItemActions {
    static func revealInFinder(_ finding: ScanFinding) throws {
        let url = try existingURL(path: finding.path)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    @MainActor
    static func openInTextEdit(_ finding: ScanFinding) async throws {
        let url = try existingURL(path: finding.signing?.mainExecutable ?? finding.path)
        guard let textEditURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.TextEdit") else {
            throw ResultItemActionError.textEditUnavailable
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        try await NSWorkspace.shared.open(
            [url],
            withApplicationAt: textEditURL,
            configuration: configuration
        )
    }

    static func copyPath(_ finding: ScanFinding) throws {
        try copyString(finding.path)
    }

    static func copyAllData(_ finding: ScanFinding) throws {
        let data = try ResultExporter.data(for: [finding], format: .json)
        guard let string = String(data: data, encoding: .utf8) else {
            throw ResultItemActionError.pasteboardWriteFailed
        }
        try copyString(string)
    }

    private static func existingURL(path: String) throws -> URL {
        guard FileManager.default.fileExists(atPath: path) else {
            throw ResultItemActionError.missingItem(path)
        }
        return URL(fileURLWithPath: path)
    }

    private static func copyString(_ value: String) throws {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setString(value, forType: .string) else {
            throw ResultItemActionError.pasteboardWriteFailed
        }
    }
}
