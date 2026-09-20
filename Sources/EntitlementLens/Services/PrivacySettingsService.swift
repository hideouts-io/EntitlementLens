import AppKit
import Foundation

enum PrivacySettingsError: LocalizedError {
    case invalidSettingsURL
    case settingsDidNotOpen

    var errorDescription: String? {
        switch self {
        case .invalidSettingsURL: "The Full Disk Access settings URL is invalid."
        case .settingsDidNotOpen: "System Settings did not open the Full Disk Access pane."
        }
    }
}

enum PrivacySettingsService {
    static func openFullDiskAccess() throws {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") else {
            throw PrivacySettingsError.invalidSettingsURL
        }
        guard NSWorkspace.shared.open(url) else {
            throw PrivacySettingsError.settingsDidNotOpen
        }
    }
}
