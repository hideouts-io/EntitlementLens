import AppKit
import Foundation
import PrivilegedProtocol
import Security
import ServiceManagement

enum PrivilegedHelperState: Equatable, Sendable {
    case adHocSignature
    case notRegistered
    case requiresApproval
    case enabled
    case notFound

    var title: String {
        switch self {
        case .adHocSignature: "Requires a team-signed build"
        case .notRegistered: "Not enabled"
        case .requiresApproval: "Approval required"
        case .enabled: "Enabled"
        case .notFound: "Helper is missing from the app bundle"
        }
    }
}

enum PrivilegedHelperError: LocalizedError {
    case adHocSignature
    case noEligiblePaths
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .adHocSignature:
            "The privileged helper is disabled for ad hoc builds. Sign the app and helper with the same Apple Development or Developer ID team first."
        case .noEligiblePaths:
            "No POSIX-permission issues are eligible for a privileged retry."
        case .invalidResponse:
            "The privileged helper returned an invalid or incompatible response."
        }
    }
}

enum PrivilegedHelperController {
    static func state() -> PrivilegedHelperState {
        guard currentTeamIdentifier() != nil else {
            return .adHocSignature
        }
        switch service.status {
        case .notRegistered: return .notRegistered
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        @unknown default: return .notFound
        }
    }

    static func register() throws {
        guard currentTeamIdentifier() != nil else {
            throw PrivilegedHelperError.adHocSignature
        }
        try service.register()
    }

    static func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    static func inspect(paths: [String]) async throws -> [PrivilegedInspectionRecord] {
        guard !paths.isEmpty else {
            throw PrivilegedHelperError.noEligiblePaths
        }
        let uniquePaths = Array(Set(paths)).sorted()
        let request = PrivilegedInspectionRequest(
            schemaVersion: PrivilegedHelperConstants.schemaVersion,
            paths: Array(uniquePaths.prefix(PrivilegedHelperConstants.maximumPaths))
        )
        let requestData = try JSONEncoder().encode(request)
        let responseData = try await PrivilegedHelperXPCClient.inspect(requestData: requestData)
        let response = try JSONDecoder().decode(PrivilegedInspectionResponse.self, from: responseData)
        guard response.schemaVersion == PrivilegedHelperConstants.schemaVersion else {
            throw PrivilegedHelperError.invalidResponse
        }
        return response.records
    }

    private static var service: SMAppService {
        SMAppService.daemon(plistName: PrivilegedHelperConstants.launchDaemonPlistName)
    }

    private static func currentTeamIdentifier() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &code) == errSecSuccess, let code else {
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(
            code,
            SecCSFlags(rawValue: 0),
            &staticCode
        ) == errSecSuccess,
        let staticCode else {
            return nil
        }
        var rawInformation: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        ) == errSecSuccess,
        let rawInformation else {
            return nil
        }
        return (rawInformation as NSDictionary)[kSecCodeInfoTeamIdentifier as String] as? String
    }
}

private enum PrivilegedHelperXPCClient {
    static func inspect(requestData: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let session = PrivilegedHelperRequestSession(continuation: continuation)
            session.start(requestData: requestData)
        }
    }
}

private final class PrivilegedHelperRequestSession: @unchecked Sendable {
    private let connection: NSXPCConnection
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?

    init(continuation: CheckedContinuation<Data, Error>) {
        self.continuation = continuation
        connection = NSXPCConnection(
            machServiceName: PrivilegedHelperConstants.serviceName,
            options: .privileged
        )
    }

    func start(requestData: Data) {
        connection.remoteObjectInterface = NSXPCInterface(with: PrivilegedHelperXPCProtocol.self)
        connection.interruptionHandler = { [self] in
            finish(.failure(NSError(
                domain: NSCocoaErrorDomain,
                code: NSXPCConnectionInterrupted,
                userInfo: [NSLocalizedDescriptionKey: "The privileged helper connection was interrupted."]
            )))
        }
        connection.invalidationHandler = { [self] in
            finish(.failure(NSError(
                domain: NSCocoaErrorDomain,
                code: NSXPCConnectionInvalid,
                userInfo: [NSLocalizedDescriptionKey: "The privileged helper connection became invalid."]
            )))
        }
        connection.resume()
        let proxy = connection.remoteObjectProxyWithErrorHandler { [self] error in
            finish(.failure(error))
        }
        guard let helper = proxy as? PrivilegedHelperXPCProtocol else {
            finish(.failure(PrivilegedHelperError.invalidResponse))
            return
        }
        helper.inspect(requestData) { [self] responseData, error in
            if let error {
                finish(.failure(error))
            } else if let responseData {
                finish(.success(responseData))
            } else {
                finish(.failure(PrivilegedHelperError.invalidResponse))
            }
        }
    }

    private func finish(_ result: Result<Data, Error>) {
        lock.lock()
        guard let continuation else {
            lock.unlock()
            return
        }
        self.continuation = nil
        lock.unlock()
        connection.invalidate()
        continuation.resume(with: result)
    }
}
