import Foundation

enum AccessIssueClassifier {
    static func skipped(path: String, operation: ScanOperation, reason: String) -> ScanIssue {
        ScanIssue(id: UUID(), path: path, category: .skipped, operation: operation,
                  message: reason, errorDomain: "EntitlementLens.Scope", errorCode: 0,
                  recoverySuggestion: "Not analyzed; absence of evidence cannot be inferred. Review scan scope and options before rescanning.",
                  privilegedRetryEligible: false)
    }

    static func classify(error: Error, path: String, operation: ScanOperation) -> ScanIssue {
        let cocoaError = error as NSError
        let classification = classification(for: cocoaError)
        return ScanIssue(
            id: UUID(),
            path: path,
            category: classification.category,
            operation: operation,
            message: cocoaError.localizedDescription,
            errorDomain: cocoaError.domain,
            errorCode: cocoaError.code,
            recoverySuggestion: classification.recoverySuggestion,
            privilegedRetryEligible: classification.privilegedRetryEligible
        )
    }

    static func analysisIssue(path: String, operation: ScanOperation, message: String) -> ScanIssue {
        ScanIssue(
            id: UUID(),
            path: path,
            category: .analysis,
            operation: operation,
            message: message,
            errorDomain: "EntitlementLens",
            errorCode: 1,
            recoverySuggestion: "Verify that the path still exists and points to a local file or bundle.",
            privilegedRetryEligible: false
        )
    }

    private static func classification(
        for error: NSError
    ) -> (category: ScanIssueCategory, recoverySuggestion: String, privilegedRetryEligible: Bool) {
        if let underlyingError = error.userInfo[NSUnderlyingErrorKey] as? NSError,
           underlyingError.domain == NSPOSIXErrorDomain {
            return posixClassification(code: underlyingError.code)
        }
        if error.domain == NSPOSIXErrorDomain {
            return posixClassification(code: error.code)
        }
        if error.domain == NSCocoaErrorDomain {
            return cocoaClassification(code: error.code)
        }
        return (
            .analysis,
            "Inspect the error domain and code. Additional privileges may not change this result.",
            false
        )
    }

    private static func posixClassification(
        code: Int
    ) -> (category: ScanIssueCategory, recoverySuggestion: String, privilegedRetryEligible: Bool) {
        switch Int32(code) {
        case EACCES:
            return (
                .posixPermissions,
                "The current account lacks a POSIX permission. A narrowly scoped privileged retry may provide metadata or signature information.",
                true
            )
        case EPERM:
            return (
                .privacyProtection,
                "Grant Full Disk Access in System Settings if this is protected user data. Root access alone does not bypass TCC or SIP.",
                false
            )
        case ENOENT, ENOTDIR:
            return (
                .unavailable,
                "The item moved, disappeared, or is no longer reachable. Scan the parent directory again.",
                false
            )
        default:
            return (
                .analysis,
                "Inspect the POSIX error and retry after resolving the underlying filesystem condition.",
                false
            )
        }
    }

    private static func cocoaClassification(
        code: Int
    ) -> (category: ScanIssueCategory, recoverySuggestion: String, privilegedRetryEligible: Bool) {
        switch code {
        case NSFileReadNoPermissionError:
            return (
                .privacyProtection,
                "Grant Full Disk Access if this is protected user data. For an ordinary mode-bit denial, a future privileged retry can inspect the exact item.",
                false
            )
        case NSFileNoSuchFileError, NSFileReadNoSuchFileError:
            return (
                .unavailable,
                "The item moved or disappeared while it was being scanned.",
                false
            )
        case NSFileReadUnknownError:
            return (
                .systemPolicy,
                "macOS may be withholding this item through a system policy, device state, or provider. Inspect the underlying error before changing privileges.",
                false
            )
        default:
            return (
                .analysis,
                "Inspect the Cocoa error and retry after resolving the underlying filesystem condition.",
                false
            )
        }
    }
}
