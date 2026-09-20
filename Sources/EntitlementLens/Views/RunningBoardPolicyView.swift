import SwiftUI

struct RunningBoardPolicyView: View {
    let policies: [RunningBoardPolicyDecoding]

    var body: some View {
        GroupBox {
            VStack(spacing: 0) {
                ForEach(policies) { policy in
                    VStack(alignment: .leading, spacing: 10) {
                        Label("\(policy.domain)/\(policy.policy)", systemImage: "memorychip")
                            .font(.headline)
                        metadata("Source", policy.sourcePath)
                        metadata("Source SHA-256", policy.sourceFileHash)
                        metadata("Source OS build", policy.osBuild)
                        if let entitlement = policy.originatorEntitlement {
                            metadata("Originator entitlement", entitlement)
                        }
                        ForEach(policy.runningReasons) { reason in
                            metadata("RunningReason raw", reason.rawValue)
                            metadata("Numeric enum", reason.numericValue.map(String.init) ?? "Not integral")
                            metadata("Build-scoped label", reason.decodedLabel ?? "Unresolved")
                            metadata("Decoder source", reason.decoderSource)
                            metadata("Confidence", reason.confidence.title)
                            ForEach(reason.installedPolicyReferences) { reference in
                                metadata("Installed reference", "\(reference.label) — \(reference.sourcePath)#\(reference.objectPath)")
                            }
                        }
                        ForEach(policy.cpuRoles) { role in
                            metadata("CPU role", "\(role.rawValue) → RBS \(role.rbsNumericValue.map(String.init) ?? "?") \(role.rbsLabel ?? "unresolved")")
                            metadata("Darwin role", "\(role.darwinNumericValue.map(String.init) ?? "?") \(role.darwinLabel ?? "unresolved")")
                        }
                        ForEach(policy.jetsamBands) { band in
                            metadata("Jetsam band", "\(band.rawValue) → \(band.decodedLabel ?? "unnamed") [\(band.confidence.title)]")
                        }
                        ForEach(policy.coalitionLevels) { level in
                            metadata("Coalition level", "\(level.rawValue) → \(level.numericValue.map(String.init) ?? "?") \(level.decodedLabel ?? "unresolved")")
                        }
                        ForEach(policy.durationPolicies) { duration in
                            metadata("Duration start", "\(duration.rawStartPolicy ?? "not set") → \(duration.startNumericValue.map(String.init) ?? "?") \(duration.startLabel ?? "unresolved")")
                            metadata("Duration end", "\(duration.rawEndPolicy ?? "not set") → \(duration.endNumericValue.map(String.init) ?? "?") \(duration.endLabel ?? "unresolved")")
                            metadata("Duration intervals", "warning \(number(duration.warningDuration)); invalidation \(number(duration.invalidationDuration)) (raw policy intervals)")
                        }
                    }
                    .padding(.vertical, 10)
                    if policy.id != policies.last?.id {
                        Divider()
                    }
                }
            }
        } label: {
            Label("RunningBoard Policy Decoder", systemImage: "point.3.connected.trianglepath.dotted")
        }
    }

    private func metadata(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label + ":")
                .foregroundStyle(.secondary)
            Text(value)
                .textSelection(.enabled)
        }
        .font(.caption)
    }

    private func number(_ value: Double?) -> String {
        value.map { String($0) } ?? "not set"
    }
}
