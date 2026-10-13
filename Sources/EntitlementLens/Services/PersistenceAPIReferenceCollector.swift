import Foundation

enum PersistenceAPIReferenceError: LocalizedError, Equatable {
    case sourceMismatch(referenceIndex: Int, expectedPath: String, actualPath: String)
    case secondarySourceMismatch(referenceIndex: Int, expectedPath: String, actualPath: String)
    case secondarySliceMismatch(referenceIndex: Int, primary: StaticEvidenceLocation, secondary: StaticEvidenceLocation)
    case invalidClassReference(referenceIndex: Int, reason: String)

    var errorDescription: String? {
        switch self {
        case let .sourceMismatch(index, expectedPath, actualPath):
            "Persistence API reference \(index) belongs to \(actualPath), but the analyzed artifact is \(expectedPath). Collect references from the analyzed artifact before projecting them."
        case let .secondarySourceMismatch(index, expectedPath, actualPath):
            "Persistence API reference \(index) has a secondary location in \(actualPath), but the analyzed artifact is \(expectedPath). Collect both locations from the analyzed artifact before projecting them."
        case let .secondarySliceMismatch(index, primary, secondary):
            "Persistence API reference \(index) has secondary architecture \(secondary.architecture ?? "unspecified") at slice \(secondary.sliceOffset.map(String.init) ?? "unspecified"), differing from primary architecture \(primary.architecture ?? "unspecified") at slice \(primary.sliceOffset.map(String.init) ?? "unspecified"). Collect both locations from the same architecture and slice before projecting them."
        case let .invalidClassReference(index, reason):
            "Persistence API reference \(index) declares invalid SMAppService class metadata: \(reason) Collect complete validated Objective-C name and reference-slot evidence before projecting it."
        }
    }
}

/// Projects SDK-declared ServiceManagement imports and attributed class references without inferring their use.
enum PersistenceAPIReferenceCollector {
    private static let maximumRecords = 64
    private static let modernClassName = "SMAppService"
    private static let recognizedNames: Set<String> = [
        "_SMLoginItemSetEnabled", "_SMJobBless", "_SMJobSubmit", "_SMJobRemove"
    ]
    private static let parsedImportMethods: Set<StaticEvidenceMethod> = [
        .symbolTable, .dyldBindStream, .chainedFixupImports
    ]
    private static let limitations = [
        "Only exact imported spellings of SMLoginItemSetEnabled, SMJobBless, SMJobSubmit, and SMJobRemove, and attributable SMAppService Objective-C class-reference metadata are projected; other persistence interfaces are outside this method's scope.",
        "Named references do not establish framework ownership, runtime availability, receiver-selector relationships, API calls, installation, registration, enabled persistence, or execution.",
        "SMAppService requires validated Objective-C metadata with matching source, architecture, slice, exact name extent, and an aligned eight-byte reference slot. Literal class-symbol imports, selectors, ambiguous bindings, definitions, and raw strings are not projected as modern ServiceManagement references.",
        "Weak external undefined imports remain named static references; their presence does not establish availability or a call."
    ]

    static func collect(apiReferences: StaticFeatureCollection<StaticAPIReference>, analyzedPath: String) throws -> StaticFeatureCollection<StaticPersistenceCharacteristic> {
        try Task.checkCancellation()
        var records: [StaticPersistenceCharacteristic] = []
        var limitReached = false
        for (index, reference) in apiReferences.records.enumerated() {
            try Task.checkCancellation()
            // Validate every source, including references that would be excluded or follow the output limit.
            guard reference.location.sourcePath == analyzedPath else {
                throw PersistenceAPIReferenceError.sourceMismatch(referenceIndex: index, expectedPath: analyzedPath,
                                                                   actualPath: reference.location.sourcePath)
            }
            if let secondary = reference.referenceLocation {
                guard secondary.sourcePath == analyzedPath else {
                    throw PersistenceAPIReferenceError.secondarySourceMismatch(referenceIndex: index, expectedPath: analyzedPath,
                                                                                actualPath: secondary.sourcePath)
                }
                guard secondary.architecture == reference.location.architecture,
                      secondary.sliceOffset == reference.location.sliceOffset else {
                    throw PersistenceAPIReferenceError.secondarySliceMismatch(referenceIndex: index, primary: reference.location,
                                                                               secondary: secondary)
                }
            }
            let isLegacyImport = reference.kind == .importedSymbol
                && parsedImportMethods.contains(reference.location.method) && recognizedNames.contains(reference.name)
            let isModernClass = reference.kind == .objectiveCClass && reference.name == modernClassName
                && reference.location.method == .objectiveCMetadata
            guard isLegacyImport || isModernClass else { continue }
            if isModernClass { try validateClassReference(reference, referenceIndex: index) }
            guard records.count < maximumRecords else { limitReached = true; continue }
            records.append(StaticPersistenceCharacteristic(
                kind: .apiReference, declarationKey: nil, declarationValue: nil, declaredIdentifier: nil,
                declaredExecutablePaths: [], association: .selectedArtifact, bundleProgramCandidatePath: nil,
                sourceSHA256: nil, apiReference: reference, location: reference.location
            ))
        }
        let state: StaticCollectionState
        if limitReached && apiReferences.state == .complete { state = .partial }
        else { state = apiReferences.state }
        let reason: String?
        if limitReached {
            let limitReason = "The persistence API projection reached its \(maximumRecords)-reference limit; subsequent matching references are not represented."
            if let sourceReason = apiReferences.reason { reason = sourceReason + " " + limitReason }
            else { reason = limitReason }
        } else { reason = apiReferences.reason }
        return StaticFeatureCollection(
            state: state, reason: reason, records: records,
            limitations: apiReferences.limitations + limitations,
            limits: apiReferences.limits + [StaticCollectionLimit(name: "persistence_api_references", value: UInt64(maximumRecords), unit: .records)]
        )
    }

    /// Validates attribution shape; the Mach-O collector establishes actual name bytes, bindings, and section bounds.
    private static func validateClassReference(_ reference: StaticAPIReference, referenceIndex: Int) throws {
        let primary = reference.location
        let nameCount = UInt64(reference.name.utf8.count) + 1
        guard primary.architecture?.isEmpty == false, let sliceOffset = primary.sliceOffset,
              let nameOffset = primary.fileOffset, primary.byteCount == nameCount, primary.propertyListKey == nil else {
            throw PersistenceAPIReferenceError.invalidClassReference(referenceIndex: referenceIndex,
                reason: "The primary location must identify an architecture, slice, and exact NUL-terminated name extent without a property-list key.")
        }
        guard nameOffset >= sliceOffset, nameOffset <= UInt64.max - nameCount else {
            throw PersistenceAPIReferenceError.invalidClassReference(referenceIndex: referenceIndex,
                reason: "The class-name extent precedes its slice or overflows a 64-bit file offset.")
        }
        guard let slot = reference.referenceLocation, slot.method == .objectiveCMetadata,
              let slotOffset = slot.fileOffset, slot.byteCount == 8, slot.propertyListKey == nil else {
            throw PersistenceAPIReferenceError.invalidClassReference(referenceIndex: referenceIndex,
                reason: "The referring location must identify an eight-byte Objective-C metadata slot without a property-list key.")
        }
        guard slotOffset >= sliceOffset, slotOffset <= UInt64.max - 8, (slotOffset - sliceOffset) % 8 == 0 else {
            throw PersistenceAPIReferenceError.invalidClassReference(referenceIndex: referenceIndex,
                reason: "The reference slot precedes its slice, overflows a 64-bit file offset, or is not eight-byte aligned relative to the slice.")
        }
        guard nameOffset + nameCount <= slotOffset || slotOffset + 8 <= nameOffset else {
            throw PersistenceAPIReferenceError.invalidClassReference(referenceIndex: referenceIndex,
                reason: "The class-name bytes overlap their referring metadata slot.")
        }
    }
}
