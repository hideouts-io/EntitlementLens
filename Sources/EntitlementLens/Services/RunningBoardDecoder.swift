import Foundation

struct RunningBoardCatalog: Sendable {
    let referencesByReason: [Int64: [RunningBoardPolicyReference]]
    let osBuild: String
    let warnings: [String]
}

enum RunningBoardDecoder {
    private static let installedDirectory = URL(
        fileURLWithPath: "/System/Library/LifecyclePolicy/DomainAttributes",
        isDirectory: true
    )

    static func loadCurrentCatalog() -> RunningBoardCatalog {
        let osBuild = currentBuild()
        var references: [Int64: [RunningBoardPolicyReference]] = [:]
        var warnings: [String] = []
        do {
            let urls = try FileManager.default.contentsOfDirectory(
                at: installedDirectory,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            ).filter { $0.pathExtension == "plist" }
            for url in urls {
                do {
                    let document = try decodeDocument(url)
                    let domain = url.deletingPathExtension().lastPathComponent
                    for (policy, payload) in document {
                        for (groupIndex, group) in payload.attributeGroups.enumerated() {
                            for (attributeIndex, attribute) in group.attributes.enumerated() {
                                guard attribute.className == "RBSRunningReasonAttribute",
                                      let number = attribute.runningReason?.integralValue else {
                                    continue
                                }
                                references[number, default: []].append(RunningBoardPolicyReference(
                                    domain: domain,
                                    policy: policy,
                                    sourcePath: url.path,
                                    objectPath: "\(policy)/AttributeGroups[\(groupIndex)]/Attributes[\(attributeIndex)]",
                                    osBuild: osBuild
                                ))
                            }
                        }
                    }
                } catch {
                    warnings.append("RunningBoard catalog could not decode \(url.path): \(error.localizedDescription)")
                }
            }
        } catch {
            warnings.append("RunningBoard catalog could not enumerate \(installedDirectory.path): \(error.localizedDescription)")
        }
        let sorted = references.mapValues { values in
            values.sorted { ($0.domain, $0.policy, $0.objectPath) < ($1.domain, $1.policy, $1.objectPath) }
        }
        return RunningBoardCatalog(referencesByReason: sorted, osBuild: osBuild, warnings: warnings)
    }

    static func inspect(
        _ url: URL,
        sourceFileHash: String,
        sourceOSBuild: String,
        catalog: RunningBoardCatalog
    ) throws -> [RunningBoardPolicyDecoding] {
        guard url.path.contains("/LifecyclePolicy/DomainAttributes/") else {
            return []
        }
        let document = try decodeDocument(url)
        let domain = url.deletingPathExtension().lastPathComponent
        return document.keys.sorted().compactMap { policy in
            guard let payload = document[policy] else {
                return nil
            }
            let attributes = payload.attributeGroups.flatMap(\.attributes)
            let runningReasons = attributes.compactMap { attribute -> RunningReasonDecoding? in
                guard attribute.className == "RBSRunningReasonAttribute", let raw = attribute.runningReason else {
                    return nil
                }
                return decodeRunningReason(raw, catalog: catalog)
            }
            let jetsamBands = attributes.compactMap { attribute -> JetsamBandDecoding? in
                guard attribute.className == "RBSJetsamPriorityGrant", let band = attribute.band else {
                    return nil
                }
                return decodeJetsamBand(band)
            }
            let cpuRoles = attributes.compactMap { attribute -> CPURoleDecoding? in
                guard attribute.className == "RBSCPUAccessGrant", let role = attribute.role else {
                    return nil
                }
                return decodeCPURole(role)
            }
            let coalitionLevels = attributes.compactMap { attribute -> CoalitionLevelDecoding? in
                guard attribute.className == "RBSCoalitionLevelGrant", let level = attribute.coalitionLevel else {
                    return nil
                }
                return decodeCoalitionLevel(level)
            }
            let durations = attributes.compactMap { attribute -> DurationPolicyDecoding? in
                guard attribute.className == "RBSDurationAttribute" else {
                    return nil
                }
                return decodeDuration(attribute)
            }
            let hasKnownValues = !runningReasons.isEmpty || !jetsamBands.isEmpty || !cpuRoles.isEmpty
                || !coalitionLevels.isEmpty || !durations.isEmpty
            guard hasKnownValues else {
                return nil
            }
            return RunningBoardPolicyDecoding(
                domain: domain,
                policy: policy,
                sourcePath: url.path,
                sourceFileHash: sourceFileHash,
                osBuild: sourceOSBuild,
                originatorEntitlement: payload.restriction?.entitlement,
                runningReasons: runningReasons,
                jetsamBands: jetsamBands,
                cpuRoles: cpuRoles,
                coalitionLevels: coalitionLevels,
                durationPolicies: durations
            )
        }
    }

    private static func decodeRunningReason(
        _ raw: PlistNumber,
        catalog: RunningBoardCatalog
    ) -> RunningReasonDecoding {
        let references = raw.integralValue.flatMap { catalog.referencesByReason[$0] } ?? []
        let labels = Array(Set(references.map(\.label))).sorted()
        return RunningReasonDecoding(
            rawValue: raw.rawValue,
            numericValue: raw.integralValue,
            decodedLabel: labels.isEmpty ? nil : labels.joined(separator: ", "),
            decoderSource: labels.isEmpty
                ? "No match in current installed LifecyclePolicy index"
                : "Current installed LifecyclePolicy index for build \(catalog.osBuild)",
            confidence: labels.isEmpty ? .unresolved : .buildScoped,
            installedPolicyReferences: references
        )
    }

    private static func decodeJetsamBand(_ rawValue: Int) -> JetsamBandDecoding {
        let labels: [Int: String] = [
            0: "JETSAM_PRIORITY_IDLE", 10: "JETSAM_PRIORITY_IDLE_DEFERRED / AGING_BAND1",
            15: "JETSAM_PRIORITY_AGING_BAND1_STUCK", 20: "JETSAM_PRIORITY_BACKGROUND_OPPORTUNISTIC",
            30: "JETSAM_PRIORITY_BACKGROUND", 40: "JETSAM_PRIORITY_MAIL / ELEVATED_INACTIVE",
            50: "JETSAM_PRIORITY_PHONE", 75: "JETSAM_PRIORITY_FREEZER", 80: "JETSAM_PRIORITY_UI_SUPPORT",
            90: "JETSAM_PRIORITY_FOREGROUND_SUPPORT", 100: "JETSAM_PRIORITY_FOREGROUND",
            120: "JETSAM_PRIORITY_AUDIO_AND_ACCESSORY", 130: "JETSAM_PRIORITY_CONDUCTOR",
            150: "JETSAM_PRIORITY_DRIVER_APPLE", 160: "JETSAM_PRIORITY_HOME",
            170: "JETSAM_PRIORITY_EXECUTIVE", 180: "JETSAM_PRIORITY_IMPORTANT",
            190: "JETSAM_PRIORITY_CRITICAL / TELEPHONY", 210: "JETSAM_PRIORITY_MAX",
            999: "JETSAM_PRIORITY_INTERNAL"
        ]
        return JetsamBandDecoding(
            rawValue: rawValue,
            decodedLabel: labels[rawValue],
            decoderSource: "Apple XNU memorystatus priority constants",
            confidence: labels[rawValue] == nil ? .unresolved : .appleCorrelated
        )
    }

    private static func decodeCPURole(_ rawValue: String) -> CPURoleDecoding {
        let mappings: [String: (Int, String, Int?, String?)] = [
            "RBSRoleNone": (1, "None", nil, nil),
            "RBSRoleBackground": (2, "Background", 6, "PRIO_DARWIN_ROLE_DARWIN_BG"),
            "RBSRoleLaunchTAL": (3, "LaunchTAL", 5, "PRIO_DARWIN_ROLE_TAL_LAUNCH"),
            "RBSRoleNonUserInteractive": (4, "NonUserInteractive", 3, "PRIO_DARWIN_ROLE_NON_UI"),
            "RBSRoleUserInitiated": (5, "UserInitiated", 7, "PRIO_DARWIN_ROLE_USER_INIT"),
            "RBSRoleUserInteractiveNonFocal": (6, "UserInteractiveNonFocal", 4, "PRIO_DARWIN_ROLE_UI_NON_FOCAL"),
            "RBSRoleUserInteractive": (7, "UserInteractive", 2, "PRIO_DARWIN_ROLE_UI"),
            "RBSRoleUserInteractiveFocal": (8, "UserInteractiveFocal", 1, "PRIO_DARWIN_ROLE_UI_FOCAL")
        ]
        let mapping = mappings[rawValue]
        return CPURoleDecoding(
            rawValue: rawValue,
            rbsNumericValue: mapping?.0,
            rbsLabel: mapping?.1,
            darwinNumericValue: mapping?.2,
            darwinLabel: mapping?.3,
            decoderSource: "Current RunningBoard conversion plus Xcode private kernel role header",
            confidence: mapping == nil ? .unresolved : .confirmedCurrent
        )
    }

    private static func decodeCoalitionLevel(_ rawValue: String) -> CoalitionLevelDecoding {
        let mappings = ["RBSCoalitionLevelLow": (1, "Low"), "RBSCoalitionLevelHigh": (100, "High")]
        let mapping = mappings[rawValue]
        return CoalitionLevelDecoding(
            rawValue: rawValue,
            numericValue: mapping?.0,
            decodedLabel: mapping?.1,
            decoderSource: "Current RunningBoard attribute-factory decoding",
            confidence: mapping == nil ? .unresolved : .confirmedCurrent
        )
    }

    private static func decodeDuration(_ attribute: PolicyAttribute) -> DurationPolicyDecoding {
        let starts: [String: (Int, String)] = [
            "RBSDurationStartPolicyFixed": (1, "Fixed"),
            "RBSDurationStartPolicyProcessStartRelative": (2, "Proc-Start-Relative"),
            "RBSDurationStartPolicyAfterOriginatorExit": (3, "After-Originator-Exit"),
            "RBSDurationStartPolicyRelative": (101, "Relative"),
            "RBSDurationStartPolicyDelayedRelative": (102, "Delayed-Relative"),
            "RBSDurationStartPolicyDelayedFixed": (103, "Delayed-Fixed")
        ]
        let ends: [String: (Int, String)] = [
            "RBSDurationEndPolicyWarnOnly": (0, "WarnOnly"),
            "RBSDurationEndPolicyInvalidate": (1, "Invalidate"),
            "RBSDurationEndPolicyTerminate": (2, "InvalidateAndTerminateProcess")
        ]
        let start = attribute.startPolicy.flatMap { starts[$0] }
        let end = attribute.endPolicy.flatMap { ends[$0] }
        return DurationPolicyDecoding(
            rawStartPolicy: attribute.startPolicy,
            startNumericValue: start?.0,
            startLabel: start?.1,
            rawEndPolicy: attribute.endPolicy,
            endNumericValue: end?.0,
            endLabel: end?.1,
            warningDuration: attribute.warningDuration,
            invalidationDuration: attribute.invalidationDuration,
            decoderSource: "Current RunningBoard conversion and attribute-factory decoding",
            confidence: start == nil || end == nil ? .unresolved : .confirmedCurrent
        )
    }

    private static func decodeDocument(_ url: URL) throws -> [String: PolicyPayload] {
        try PropertyListDecoder().decode([String: PolicyPayload].self, from: Data(contentsOf: url))
    }

    private static func currentBuild() -> String {
        let url = URL(fileURLWithPath: "/System/Library/CoreServices/SystemVersion.plist")
        guard let data = try? Data(contentsOf: url),
              let dictionary = try? PropertyListDecoder().decode([String: String].self, from: data),
              let build = dictionary["ProductBuildVersion"] else {
            return "unknown"
        }
        return build
    }
}

private struct PolicyPayload: Decodable {
    let attributeGroups: [PolicyAttributeGroup]
    let restriction: PolicyRestriction?

    enum CodingKeys: String, CodingKey {
        case attributeGroups = "AttributeGroups"
        case restriction = "Restriction"
    }
}

private struct PolicyAttributeGroup: Decodable {
    let attributes: [PolicyAttribute]

    enum CodingKeys: String, CodingKey {
        case attributes = "Attributes"
    }
}

private struct PolicyRestriction: Decodable {
    let entitlement: String?

    enum CodingKeys: String, CodingKey {
        case entitlement = "Entitlement"
    }
}

private struct PolicyAttribute: Decodable {
    let className: String
    let runningReason: PlistNumber?
    let band: Int?
    let role: String?
    let coalitionLevel: String?
    let startPolicy: String?
    let endPolicy: String?
    let warningDuration: Double?
    let invalidationDuration: Double?

    enum CodingKeys: String, CodingKey {
        case className = "Class"
        case runningReason = "RunningReason"
        case band = "Band"
        case role = "Role"
        case coalitionLevel = "CoalitionLevel"
        case startPolicy = "StartPolicy"
        case endPolicy = "EndPolicy"
        case warningDuration = "WarningDuration"
        case invalidationDuration = "InvalidationDuration"
    }
}

private enum PlistNumber: Decodable {
    case integer(Int64)
    case real(Double)

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(Int64.self) {
            self = .integer(value)
            return
        }
        self = .real(try container.decode(Double.self))
    }

    var rawValue: String {
        switch self {
        case let .integer(value): return String(value)
        case let .real(value): return String(value)
        }
    }

    var integralValue: Int64? {
        switch self {
        case let .integer(value): return value
        case let .real(value):
            guard value.rounded() == value, value >= Double(Int64.min), value <= Double(Int64.max) else {
                return nil
            }
            return Int64(value)
        }
    }
}
