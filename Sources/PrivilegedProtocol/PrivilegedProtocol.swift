import Foundation

public enum PrivilegedHelperConstants {
    public static let applicationIdentifier = "io.hideouts.EntitlementLens"
    public static let helperIdentifier = "io.hideouts.EntitlementLens.PrivilegedHelper"
    public static let serviceName = "io.hideouts.EntitlementLens.PrivilegedHelper"
    public static let launchDaemonPlistName = "io.hideouts.EntitlementLens.PrivilegedHelper.plist"
    public static let schemaVersion = 1
    public static let maximumPaths = 256
}

public struct PrivilegedInspectionRequest: Codable, Sendable {
    public let schemaVersion: Int
    public let paths: [String]

    public init(schemaVersion: Int, paths: [String]) {
        self.schemaVersion = schemaVersion
        self.paths = paths
    }
}

public struct PrivilegedInspectionRecord: Codable, Sendable, Identifiable {
    public let id: UUID
    public let path: String
    public let fileSize: Int64?
    public let ownerUserID: UInt32?
    public let ownerGroupID: UInt32?
    public let posixMode: UInt16?
    public let signingStatus: Int32?
    public let identifier: String?
    public let teamIdentifier: String?
    public let entitlementCount: Int?
    public let entitlementsPropertyList: Data?
    public let errorDomain: String?
    public let errorCode: Int?
    public let errorMessage: String?

    public init(
        id: UUID,
        path: String,
        fileSize: Int64?,
        ownerUserID: UInt32?,
        ownerGroupID: UInt32?,
        posixMode: UInt16?,
        signingStatus: Int32?,
        identifier: String?,
        teamIdentifier: String?,
        entitlementCount: Int?,
        entitlementsPropertyList: Data?,
        errorDomain: String?,
        errorCode: Int?,
        errorMessage: String?
    ) {
        self.id = id
        self.path = path
        self.fileSize = fileSize
        self.ownerUserID = ownerUserID
        self.ownerGroupID = ownerGroupID
        self.posixMode = posixMode
        self.signingStatus = signingStatus
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.entitlementCount = entitlementCount
        self.entitlementsPropertyList = entitlementsPropertyList
        self.errorDomain = errorDomain
        self.errorCode = errorCode
        self.errorMessage = errorMessage
    }
}

public struct PrivilegedInspectionResponse: Codable, Sendable {
    public let schemaVersion: Int
    public let records: [PrivilegedInspectionRecord]

    public init(schemaVersion: Int, records: [PrivilegedInspectionRecord]) {
        self.schemaVersion = schemaVersion
        self.records = records
    }
}

@objc public protocol PrivilegedHelperXPCProtocol {
    func inspect(_ requestData: Data, reply: @escaping (Data?, NSError?) -> Void)
}
