import Foundation

enum StaticResearchConsumerError: LocalizedError {
    case invalidExport(String)
    case invalidEvidence(findingID: UUID, reason: String)
    case invalidSources(String)

    var errorDescription: String? {
        switch self {
        case let .invalidExport(reason): "Research export cannot be decoded: \(reason)"
        case let .invalidEvidence(id, reason): "Research evidence is inconsistent for finding \(id): \(reason)"
        case let .invalidSources(reason): "Research source selection is invalid: \(reason)"
        }
    }
}

/// Validates declared identity and ranges before projection; it does not rerun the original collectors.
enum StaticResearchEvidenceValidator {
    static func validate(_ finding: ScanFinding) throws {
        try Task.checkCancellation()
        let provenance = finding.provenance
        try require(validPath(provenance.analyzedPath), finding, "The analyzed path must be absolute and contain no NUL bytes.")
        try require(validSHA256(provenance.sha256), finding, "The artifact SHA-256 must contain 64 lowercase hexadecimal characters.")
        try require(provenance.fileSize >= 0, finding, "The artifact byte size is negative.")
        let fileSize = UInt64(provenance.fileSize)
        var slices: [SliceIdentity: MachOSlice] = [:]
        for slice in provenance.machOSlices {
            try validateSlice(slice, fileSize: fileSize, finding: finding)
            let key = SliceIdentity(slice)
            try require(slices.updateValue(slice, forKey: key) == nil, finding, "An architecture and slice-offset identity is duplicated.")
        }
        guard let features = finding.staticFeatures else { return }
        try require(features.analyzedPath == provenance.analyzedPath && features.artifactSHA256 == provenance.sha256,
                    finding, "Feature identity does not match artifact provenance.")
        var featureSlices = Set<SliceIdentity>()
        for record in features.architectures.records {
            try Task.checkCancellation()
            try validateSlice(record.slice, fileSize: fileSize, finding: finding)
            let key = SliceIdentity(record.slice)
            try require(featureSlices.insert(key).inserted, finding, "Feature architecture identity is duplicated.")
            try require(slices[key] == record.slice, finding, "Feature architecture does not match a provenance slice.")
            try require(record.location.architecture == key.architecture && record.location.sliceOffset == key.offset,
                        finding, "Architecture location does not match its slice identity.")
        }
        let locations = features.signer.records.map(\.location)
            + features.embeddedCertificates.records.map(\.location)
            + features.entitlements.records.map(\.location)
            + features.architectures.records.map(\.location)
            + features.loadCommands.records.map(\.location)
            + features.linkedFrameworks.records.map(\.location)
            + features.codeDirectoryData.records.map(\.location)
        for location in locations {
            try Task.checkCancellation()
            try validateLocation(location, slices: slices, finding: finding)
        }
        var entitlementScopes = Set<EntitlementScopeIdentity>()
        for evidence in features.entitlements.records {
            try require(entitlementScopes.insert(EntitlementScopeIdentity(
                source: evidence.source, architecture: evidence.location.architecture, offset: evidence.location.sliceOffset
            )).inserted, finding, "An entitlement dictionary scope is duplicated.")
            switch evidence.source {
            case .standardDictionary:
                try require(evidence.location.architecture == nil && evidence.location.sliceOffset == nil,
                            finding, "The standard entitlement dictionary claims an architecture-specific location.")
            case let .architecture(label):
                try require(!label.isEmpty && evidence.location.architecture == label,
                            finding, "Entitlement source and location architecture disagree.")
                if evidence.state == .complete {
                    let matching = slices.values.filter { $0.architecture == label }
                    try require(matching.count == 1 && evidence.location.sliceOffset == matching.first?.fileOffset,
                                finding, "Complete architecture entitlement evidence lacks a unique recorded slice location.")
                }
            }
            try require(Set(evidence.values.map(\.key)).count == evidence.values.count,
                        finding, "An entitlement dictionary contains duplicate keys.")
            for slot in evidence.slots {
                try require(slot.byteCount >= 0 && validSHA256(slot.sha256), finding, "Entitlement slot size or SHA-256 is invalid.")
                try require(rangeFits(offset: slot.fileOffset, count: UInt64(slot.byteCount), size: fileSize),
                            finding, "An entitlement slot extends beyond the artifact.")
                let mappings = slices.values.filter {
                    $0.architecture == slot.architecture && slot.fileOffset >= $0.fileOffset
                        && rangeFits(offset: slot.fileOffset - $0.fileOffset, count: UInt64(slot.byteCount), size: $0.fileSize)
                }
                try require(mappings.count == 1, finding, "An entitlement slot cannot be mapped uniquely to its architecture slice.")
                if case let .architecture(label) = evidence.source {
                    try require(label == slot.architecture, finding, "Entitlement dictionary and slot architecture disagree.")
                    if let offset = evidence.location.sliceOffset {
                        try require(mappings.first?.fileOffset == offset, finding, "Entitlement slot belongs to a different slice.")
                    }
                }
                try require(Set(slot.decodedEntitlements.map(\.key)).count == slot.decodedEntitlements.count,
                            finding, "A decoded entitlement slot contains duplicate keys.")
            }
        }
        for record in features.apiReferences.records {
            try Task.checkCancellation()
            try validateAPI(record, slices: slices, finding: finding)
        }
        for record in features.persistenceCharacteristics.records {
            try Task.checkCancellation()
            try require(validPath(record.location.sourcePath), finding, "Persistence evidence has an invalid source path.")
            if record.location.sourcePath == provenance.analyzedPath {
                try validateLocation(record.location, slices: slices, finding: finding)
            } else {
                try validateExtent(record.location, finding: finding)
            }
            if let hash = record.sourceSHA256 {
                try require(validSHA256(hash), finding, "Persistence configuration SHA-256 is invalid.")
            }
            if let api = record.apiReference {
                try require(record.kind == .apiReference && record.location == api.location
                            && features.apiReferences.records.contains(api), finding,
                            "Persistence API evidence does not retain an original API reference and location.")
            }
        }
    }

    static func rangeFits(offset: UInt64, count: UInt64, size: UInt64) -> Bool {
        let end = offset.addingReportingOverflow(count)
        return !end.overflow && end.partialValue <= size
    }

    private static func validateAPI(
        _ record: StaticAPIReference, slices: [SliceIdentity: MachOSlice], finding: ScanFinding
    ) throws {
        try require(!record.name.isEmpty && record.name.utf8.count <= 4_096 && !record.name.contains("\0"),
                    finding, "API reference name is empty, oversized, or contains a NUL byte.")
        try validateLocation(record.location, slices: slices, finding: finding)
        if let slot = record.referenceLocation {
            try validateLocation(slot, slices: slices, finding: finding)
            try require(slot.architecture == record.location.architecture && slot.sliceOffset == record.location.sliceOffset,
                        finding, "API name and reference slot have different slice identities.")
            try require(slot.fileOffset != nil && (slot.byteCount == 4 || slot.byteCount == 8), finding, "API reference slot lacks a supported pointer-sized file range.")
            if record.location.method == .objectiveCMetadata {
                try require(slot.method == .objectiveCMetadata && slot.byteCount == 8, finding,
                            "Objective-C reference slot lacks the original method and eight-byte extent.")
            }
        }
        if [.symbolTable, .dyldBindStream, .chainedFixupImports, .objectiveCMetadata].contains(record.location.method) {
            try require(record.location.fileOffset != nil && record.location.byteCount == UInt64(record.name.utf8.count + 1),
                        finding, "API name lacks its exact NUL-terminated byte extent.")
        }
        if record.location.method == .objectiveCMetadata {
            try require(record.location.architecture != nil && record.location.sliceOffset != nil,
                        finding, "Objective-C metadata lacks a slice identity.")
        }
    }

    private static func validateLocation(
        _ location: StaticEvidenceLocation, slices: [SliceIdentity: MachOSlice], finding: ScanFinding
    ) throws {
        try require(location.sourcePath == finding.provenance.analyzedPath, finding,
                    "Artifact feature location names a different source path.")
        try validateExtent(location, finding: finding)
        if let offset = location.fileOffset, let count = location.byteCount {
            try require(rangeFits(offset: offset, count: count, size: UInt64(finding.provenance.fileSize)),
                        finding, "Evidence bytes extend beyond the artifact.")
        }
        if let sliceOffset = location.sliceOffset {
            guard let architecture = location.architecture,
                  let slice = slices[SliceIdentity(architecture: architecture, offset: sliceOffset)] else {
                throw StaticResearchConsumerError.invalidEvidence(findingID: finding.id, reason: "Evidence names an unknown slice identity.")
            }
            if let offset = location.fileOffset, let count = location.byteCount {
                try require(offset >= slice.fileOffset
                            && rangeFits(offset: offset - slice.fileOffset, count: count, size: slice.fileSize),
                            finding, "Evidence bytes extend beyond their architecture slice.")
            }
        }
    }

    private static func validateExtent(_ location: StaticEvidenceLocation, finding: ScanFinding) throws {
        try require((location.fileOffset == nil) == (location.byteCount == nil), finding,
                    "Evidence offset and byte count must be present together.")
        if let offset = location.fileOffset, let count = location.byteCount {
            try require(!offset.addingReportingOverflow(count).overflow, finding, "Evidence byte range overflows.")
        }
    }

    private static func validateSlice(_ slice: MachOSlice, fileSize: UInt64, finding: ScanFinding) throws {
        try require(!slice.architecture.isEmpty && slice.fileSize > 0
                    && rangeFits(offset: slice.fileOffset, count: slice.fileSize, size: fileSize),
                    finding, "Architecture slice has an invalid name or file range.")
    }

    private static func validPath(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.contains("\0")
    }

    private static func validSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    private static func require(_ condition: Bool, _ finding: ScanFinding, _ reason: String) throws {
        guard condition else { throw StaticResearchConsumerError.invalidEvidence(findingID: finding.id, reason: reason) }
    }

    private struct SliceIdentity: Hashable {
        let architecture: String
        let offset: UInt64

        init(_ slice: MachOSlice) { architecture = slice.architecture; offset = slice.fileOffset }
        init(architecture: String, offset: UInt64) { self.architecture = architecture; self.offset = offset }
    }

    private struct EntitlementScopeIdentity: Hashable {
        let source: EntitlementSource
        let architecture: String?
        let offset: UInt64?
    }
}
