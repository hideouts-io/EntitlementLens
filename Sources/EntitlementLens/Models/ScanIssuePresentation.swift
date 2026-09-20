import Foundation

extension ScanIssue {
    var collectionLabel: String {
        switch category {
        case .skipped: "Skipped"
        case .posixPermissions, .privacyProtection: "Permission-limited"
        case .systemPolicy: "Policy-limited"
        case .unavailable, .fileProvider: "Unavailable"
        case .analysis: "Failed / incomplete"
        }
    }
}
