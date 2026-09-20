import Foundation
import Security

enum OSStatusMessage {
    static func describe(_ status: OSStatus) -> String {
        if let message = SecCopyErrorMessageString(status, nil) as String? {
            return message
        }
        return "Security.framework did not provide an error description."
    }
}
