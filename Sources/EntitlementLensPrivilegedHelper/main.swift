import Foundation
import PrivilegedProtocol
import Security
import Darwin

private enum HelperRequestError: LocalizedError {
    case invalidSchema(Int)
    case emptyRequest
    case tooManyPaths(Int)
    case relativePath(String)
    case nonCanonicalPath(String)
    case symbolicLinkPath(String)
    case requestTooLarge(Int)

    var errorDescription: String? {
        switch self {
        case let .invalidSchema(version): "Unsupported privileged request schema version: \(version)."
        case .emptyRequest: "A privileged inspection request must contain at least one path."
        case let .tooManyPaths(count): "The request contains \(count) paths; the limit is \(PrivilegedHelperConstants.maximumPaths)."
        case let .relativePath(path): "Privileged inspection requires an absolute path: \(path)."
        case let .nonCanonicalPath(path): "Privileged inspection requires a canonical path without dot components: \(path)."
        case let .symbolicLinkPath(path): "Privileged inspection refuses symbolic links: \(path)."
        case let .requestTooLarge(size): "The request is \(size) bytes; the limit is 1048576 bytes."
        }
    }
}

private enum ClientCodeValidator {
    static func accepts(_ connection: NSXPCConnection) -> Bool {
        guard let helperTeam = ownTeamIdentifier(), !helperTeam.isEmpty else {
            return false
        }
        let attributes = [
            kSecGuestAttributePid as String: NSNumber(value: connection.processIdentifier)
        ] as CFDictionary
        var guestCode: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(rawValue: 0), &guestCode) == errSecSuccess,
              let guestCode,
              let information = signingInformation(for: guestCode) else {
            return false
        }
        let identifier = information[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = information[kSecCodeInfoTeamIdentifier as String] as? String
        return identifier == PrivilegedHelperConstants.applicationIdentifier && teamIdentifier == helperTeam
    }

    private static func ownTeamIdentifier() -> String? {
        var ownCode: SecCode?
        guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &ownCode) == errSecSuccess,
              let ownCode,
              let information = signingInformation(for: ownCode) else {
            return nil
        }
        return information[kSecCodeInfoTeamIdentifier as String] as? String
    }

    private static func signingInformation(for code: SecCode) -> NSDictionary? {
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
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(staticCode, flags, &rawInformation) == errSecSuccess,
              let rawInformation else {
            return nil
        }
        guard SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures),
            nil
        ) == errSecSuccess else {
            return nil
        }
        return rawInformation as NSDictionary
    }
}

private enum PrivilegedInspectionEngine {
    static func inspect(requestData: Data) throws -> Data {
        guard requestData.count <= 1_048_576 else {
            throw HelperRequestError.requestTooLarge(requestData.count)
        }
        let request = try JSONDecoder().decode(PrivilegedInspectionRequest.self, from: requestData)
        try validate(request)
        let records = request.paths.map(inspectPath)
        let response = PrivilegedInspectionResponse(
            schemaVersion: PrivilegedHelperConstants.schemaVersion,
            records: records
        )
        return try JSONEncoder().encode(response)
    }

    private static func validate(_ request: PrivilegedInspectionRequest) throws {
        guard request.schemaVersion == PrivilegedHelperConstants.schemaVersion else {
            throw HelperRequestError.invalidSchema(request.schemaVersion)
        }
        guard !request.paths.isEmpty else {
            throw HelperRequestError.emptyRequest
        }
        guard request.paths.count <= PrivilegedHelperConstants.maximumPaths else {
            throw HelperRequestError.tooManyPaths(request.paths.count)
        }
        for path in request.paths where !path.hasPrefix("/") {
            throw HelperRequestError.relativePath(path)
        }
        for path in request.paths where (path as NSString).standardizingPath != path {
            throw HelperRequestError.nonCanonicalPath(path)
        }
    }

    private static func inspectPath(_ path: String) -> PrivilegedInspectionRecord {
        do {
            try rejectSymbolicLink(path)
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            let signing = signingInformation(path: path)
            return PrivilegedInspectionRecord(
                id: UUID(),
                path: path,
                fileSize: (attributes[.size] as? NSNumber)?.int64Value,
                ownerUserID: (attributes[.ownerAccountID] as? NSNumber)?.uint32Value,
                ownerGroupID: (attributes[.groupOwnerAccountID] as? NSNumber)?.uint32Value,
                posixMode: (attributes[.posixPermissions] as? NSNumber)?.uint16Value,
                signingStatus: signing.status,
                identifier: signing.identifier,
                teamIdentifier: signing.teamIdentifier,
                entitlementCount: signing.entitlementCount,
                entitlementsPropertyList: signing.entitlements,
                errorDomain: signing.error?.domain,
                errorCode: signing.error?.code,
                errorMessage: signing.error?.localizedDescription
            )
        } catch {
            let cocoaError = error as NSError
            return PrivilegedInspectionRecord(
                id: UUID(),
                path: path,
                fileSize: nil,
                ownerUserID: nil,
                ownerGroupID: nil,
                posixMode: nil,
                signingStatus: nil,
                identifier: nil,
                teamIdentifier: nil,
                entitlementCount: nil,
                entitlementsPropertyList: nil,
                errorDomain: cocoaError.domain,
                errorCode: cocoaError.code,
                errorMessage: cocoaError.localizedDescription
            )
        }
    }

    private static func rejectSymbolicLink(_ path: String) throws {
        var metadata = stat()
        guard lstat(path, &metadata) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        guard (metadata.st_mode & S_IFMT) != S_IFLNK else {
            throw HelperRequestError.symbolicLinkPath(path)
        }
    }

    private static func signingInformation(
        path: String
    ) -> (
        status: Int32?,
        identifier: String?,
        teamIdentifier: String?,
        entitlementCount: Int?,
        entitlements: Data?,
        error: NSError?
    ) {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: path) as CFURL,
            SecCSFlags(rawValue: 0),
            &staticCode
        )
        guard createStatus == errSecSuccess, let staticCode else {
            return (nil, nil, nil, nil, nil, NSError(domain: NSOSStatusErrorDomain, code: Int(createStatus)))
        }
        let validityStatus = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSDoNotValidateResources),
            nil
        )
        var rawInformation: CFDictionary?
        let copyStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &rawInformation
        )
        guard copyStatus == errSecSuccess, let rawInformation else {
            return (validityStatus, nil, nil, nil, nil, NSError(domain: NSOSStatusErrorDomain, code: Int(copyStatus)))
        }
        let information = rawInformation as NSDictionary
        let rawEntitlements = information[kSecCodeInfoEntitlementsDict as String]
        let entitlements = rawEntitlements.flatMap { value in
            try? PropertyListSerialization.data(fromPropertyList: value, format: .binary, options: 0)
        }
        return (
            validityStatus,
            information[kSecCodeInfoIdentifier as String] as? String,
            information[kSecCodeInfoTeamIdentifier as String] as? String,
            (rawEntitlements as? NSDictionary)?.count,
            entitlements,
            nil
        )
    }
}

private final class PrivilegedHelperService: NSObject, PrivilegedHelperXPCProtocol {
    func inspect(_ requestData: Data, reply: @escaping (Data?, NSError?) -> Void) {
        do {
            reply(try PrivilegedInspectionEngine.inspect(requestData: requestData), nil)
        } catch {
            reply(nil, error as NSError)
        }
    }
}

private final class PrivilegedHelperListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let service = PrivilegedHelperService()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard ClientCodeValidator.accepts(connection) else {
            return false
        }
        connection.exportedInterface = NSXPCInterface(with: PrivilegedHelperXPCProtocol.self)
        connection.exportedObject = service
        connection.resume()
        return true
    }
}

private let listener = NSXPCListener(machServiceName: PrivilegedHelperConstants.serviceName)
private let delegate = PrivilegedHelperListenerDelegate()
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
