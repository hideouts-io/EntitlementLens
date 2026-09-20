import Foundation

struct RawEvidenceScan: Sendable {
    let objects: [EmbeddedObject]
    let warnings: [String]
}

private struct StringScanState {
    var currentBytes: [UInt8] = []
    var currentOffset = 0
    var matches: [RawStringMatch] = []
}

enum RawEvidenceScanner {
    private static let xmlStart = Data("<plist".utf8)
    private static let xmlEnd = Data("</plist>".utf8)
    private static let binaryStart = Data("bplist00".utf8)
    private static let chunkSize = 1_048_576
    private static let maximumObjectBytes = 8 * 1_024 * 1_024
    private static let maximumXMLObjects = 32
    private static let maximumBinaryObjects = 8
    private static let maximumStringMatches = 100
    private static let maximumWarnings = 64
    private static let indicators = [
        "com.apple.security.",
        "com.apple.developer.",
        "com.apple.private.",
        "application-identifier",
        "keychain-access-groups",
        "get-task-allow",
        "platform-application",
        "seatbelt-profiles",
        "dynamic-codesigning",
        "task_for_pid-allow"
    ]

    static func inspect(_ url: URL, kind: FileKind, maximumBytes: Int) throws -> RawEvidenceScan {
        let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
        guard values.isRegularFile == true else {
            return RawEvidenceScan(objects: [], warnings: [])
        }
        guard let fileSize = values.fileSize else {
            throw CocoaError(.fileReadUnknown)
        }
        let scanLimit = min(fileSize, maximumBytes)
        var warnings: [String] = []
        if fileSize > maximumBytes {
            warnings.append("Deep carving inspected the first \(maximumBytes) of \(fileSize) bytes; the remainder is outside the configured coverage limit.")
        }

        let handle = try FileHandle(forReadingFrom: url)
        defer { handle.closeFile() }
        var objects: [EmbeddedObject] = []
        var stringState = StringScanState()
        var rollingData = Data()
        var rollingOffset = 0
        var totalRead = 0
        var xmlSearchOffset = 0
        var binarySearchOffset = 0

        while totalRead < scanLimit {
            try Task.checkCancellation()
            let requested = min(chunkSize, scanLimit - totalRead)
            let chunk = try handle.read(upToCount: requested) ?? Data()
            guard !chunk.isEmpty else {
                throw RawEvidenceScanError.unexpectedEndOfFile(url.path, totalRead, scanLimit)
            }
            stringState = try consumeStrings(chunk, absoluteOffset: totalRead, state: stringState)
            if rollingData.isEmpty {
                rollingOffset = totalRead
            }
            rollingData.append(chunk)
            totalRead += chunk.count
            let isFinal = totalRead == scanLimit

            let xmlResult = carveXML(
                rollingData,
                baseOffset: rollingOffset,
                searchOffset: xmlSearchOffset,
                existingCount: objects.filter { $0.format == .xmlPropertyList }.count,
                isFinal: isFinal
            )
            objects.append(contentsOf: xmlResult.objects)
            appendWarnings(xmlResult.warnings, to: &warnings)
            xmlSearchOffset = xmlResult.nextSearchOffset

            let binaryResult = carveBinaryPropertyLists(
                rollingData,
                baseOffset: rollingOffset,
                searchOffset: binarySearchOffset,
                existingCount: objects.filter { $0.format == .binaryPropertyList }.count,
                wholeFile: kind == .propertyList,
                isFinal: isFinal
            )
            objects.append(contentsOf: binaryResult.objects)
            appendWarnings(binaryResult.warnings, to: &warnings)
            binarySearchOffset = binaryResult.nextSearchOffset

            let earliestNeeded = min(xmlSearchOffset, binarySearchOffset)
            let boundedStart = max(0, totalRead - maximumObjectBytes)
            let retainFrom = max(rollingOffset, max(earliestNeeded, boundedStart))
            if retainFrom > rollingOffset {
                let dropCount = retainFrom - rollingOffset
                // Data.removeFirst preserves slice indices; carvers use zero-based buffer offsets.
                rollingData = Data(rollingData.dropFirst(dropCount))
                rollingOffset = retainFrom
            }
        }

        stringState = finishStrings(stringState)
        if !stringState.matches.isEmpty {
            objects.append(EmbeddedObject(
                id: UUID(),
                offset: stringState.matches.first?.offset ?? 0,
                length: stringState.matches.reduce(0) { $0 + $1.value.utf8.count },
                format: .printableStrings,
                confidence: 10,
                summary: "Printable ASCII strings contain entitlement-related keywords; this is not proof of signed entitlements.",
                entitlementKeys: [],
                stringMatches: stringState.matches
            ))
        }
        return RawEvidenceScan(objects: objects, warnings: warnings)
    }

    private static func carveXML(
        _ data: Data,
        baseOffset: Int,
        searchOffset: Int,
        existingCount: Int,
        isFinal: Bool
    ) -> (objects: [EmbeddedObject], warnings: [String], nextSearchOffset: Int) {
        guard existingCount < maximumXMLObjects else {
            return ([], [], baseOffset + data.count)
        }
        var objects: [EmbeddedObject] = []
        var warnings: [String] = []
        var localSearch = max(0, searchOffset - baseOffset)
        while localSearch < data.count, existingCount + objects.count < maximumXMLObjects,
              let startRange = data.range(of: xmlStart, in: localSearch..<data.endIndex) {
            let absoluteStart = baseOffset + startRange.lowerBound
            guard let endRange = data.range(of: xmlEnd, in: startRange.lowerBound..<data.endIndex) else {
                let available = data.count - startRange.lowerBound
                if available >= maximumObjectBytes {
                    warnings.append("XML plist marker at offset \(absoluteStart) exceeded the \(maximumObjectBytes)-byte object bound without a closing tag.")
                    localSearch = startRange.upperBound
                    continue
                }
                if isFinal {
                    warnings.append("XML plist marker at offset \(absoluteStart) has no closing </plist> tag within scanned coverage.")
                    return (objects, warnings, baseOffset + data.count)
                }
                return (objects, warnings, absoluteStart)
            }
            let end = endRange.upperBound
            let carved = Data(data[startRange.lowerBound..<end])
            do {
                let decoded = try decodePropertyList(carved)
                let keys = relevantKeys(decoded)
                if !keys.isEmpty {
                    objects.append(EmbeddedObject(
                        id: UUID(),
                        offset: absoluteStart,
                        length: carved.count,
                        format: .xmlPropertyList,
                        confidence: 80,
                        summary: "Parsed bounded XML property list containing entitlement-like keys.",
                        entitlementKeys: keys,
                        stringMatches: []
                    ))
                }
            } catch {
                warnings.append("XML plist carving failed at offset \(absoluteStart): \(error.localizedDescription)")
            }
            localSearch = end
        }
        let splitMarkerOverlap = xmlStart.count - 1
        let completedOffset = baseOffset + max(localSearch, data.count - splitMarkerOverlap)
        return (objects, warnings, completedOffset)
    }

    private static func carveBinaryPropertyLists(
        _ data: Data,
        baseOffset: Int,
        searchOffset: Int,
        existingCount: Int,
        wholeFile: Bool,
        isFinal: Bool
    ) -> (objects: [EmbeddedObject], warnings: [String], nextSearchOffset: Int) {
        guard existingCount < maximumBinaryObjects else {
            return ([], [], baseOffset + data.count)
        }
        var objects: [EmbeddedObject] = []
        var warnings: [String] = []
        var localSearch = max(0, searchOffset - baseOffset)
        while localSearch < data.count, existingCount + objects.count < maximumBinaryObjects,
              let markerRange = data.range(of: binaryStart, in: localSearch..<data.endIndex) {
            let absoluteStart = baseOffset + markerRange.lowerBound
            let candidateData = Data(data[markerRange.lowerBound..<data.endIndex])
            let boundedLength = binaryPlistLength(candidateData)
            guard let boundedLength else {
                if candidateData.count >= maximumObjectBytes {
                    warnings.append("Binary plist marker at offset \(absoluteStart) exceeded the \(maximumObjectBytes)-byte structural bound without a valid trailer.")
                    localSearch = markerRange.upperBound
                    continue
                }
                if isFinal {
                    warnings.append("Binary plist marker at offset \(absoluteStart) has no valid bounded trailer within scanned coverage.")
                    return (objects, warnings, baseOffset + data.count)
                }
                return (objects, warnings, absoluteStart)
            }
            let candidate = Data(candidateData.prefix(boundedLength))
            do {
                let decoded = try decodePropertyList(candidate)
                let keys = relevantKeys(decoded)
                if !keys.isEmpty {
                    objects.append(EmbeddedObject(
                        id: UUID(),
                        offset: absoluteStart,
                        length: boundedLength,
                        format: .binaryPropertyList,
                        confidence: wholeFile && absoluteStart == 0 ? 85 : 75,
                        summary: "Parsed structurally bounded binary property list containing entitlement-like keys.",
                        entitlementKeys: keys,
                        stringMatches: []
                    ))
                }
            } catch {
                warnings.append("Binary plist carving failed at offset \(absoluteStart): \(error.localizedDescription)")
            }
            localSearch = markerRange.lowerBound + boundedLength
        }
        let splitMarkerOverlap = binaryStart.count - 1
        let completedOffset = baseOffset + max(localSearch, data.count - splitMarkerOverlap)
        return (objects, warnings, completedOffset)
    }

    private static func binaryPlistLength(_ data: Data) -> Int? {
        guard data.starts(with: binaryStart), data.count >= 40 else {
            return nil
        }
        return data.withUnsafeBytes { rawBuffer in
            let bytes = rawBuffer.bindMemory(to: UInt8.self)
            for trailerOffset in 8...(data.count - 32) {
                guard bytes[trailerOffset] == 0, bytes[trailerOffset + 1] == 0,
                      bytes[trailerOffset + 2] == 0, bytes[trailerOffset + 3] == 0,
                      bytes[trailerOffset + 4] == 0, bytes[trailerOffset + 5] == 0 else {
                    continue
                }
                let offsetSize = Int(bytes[trailerOffset + 6])
                let referenceSize = Int(bytes[trailerOffset + 7])
                guard (1...8).contains(offsetSize), (1...8).contains(referenceSize),
                      let objectCount = uint64(bytes, offset: trailerOffset + 8),
                      let topObject = uint64(bytes, offset: trailerOffset + 16),
                      let offsetTableOffset = uint64(bytes, offset: trailerOffset + 24),
                      objectCount > 0, objectCount <= 1_000_000, topObject < objectCount else {
                    continue
                }
                let tableByteCount = objectCount.multipliedReportingOverflow(by: UInt64(offsetSize))
                let tableEnd = offsetTableOffset.addingReportingOverflow(tableByteCount.partialValue)
                guard !tableByteCount.overflow, !tableEnd.overflow,
                      tableEnd.partialValue == UInt64(trailerOffset), offsetTableOffset >= 8 else {
                    continue
                }
                return trailerOffset + 32
            }
            return nil
        }
    }

    private static func consumeStrings(
        _ data: Data,
        absoluteOffset: Int,
        state: StringScanState
    ) throws -> StringScanState {
        guard state.matches.count < maximumStringMatches else {
            return state
        }
        var next = state
        for (relativeOffset, byte) in data.enumerated() {
            if relativeOffset.isMultiple(of: 4_096) { try Task.checkCancellation() }
            if (0x20...0x7E).contains(byte) {
                if next.currentBytes.isEmpty {
                    next.currentOffset = absoluteOffset + relativeOffset
                }
                next.currentBytes.append(byte)
                continue
            }
            next = finishCurrentString(next)
            if next.matches.count == maximumStringMatches {
                break
            }
        }
        return next
    }

    private static func finishStrings(_ state: StringScanState) -> StringScanState {
        finishCurrentString(state)
    }

    private static func finishCurrentString(_ state: StringScanState) -> StringScanState {
        var next = state
        // Clear the returned state before returning it; defer mutates only the local copy.
        next.currentBytes = []
        guard state.currentBytes.count >= 4,
              let value = String(bytes: state.currentBytes, encoding: .ascii) else {
            return next
        }
        let lowercased = value.lowercased()
        guard indicators.contains(where: { lowercased.contains($0) }) else {
            return next
        }
        next.matches.append(RawStringMatch(offset: next.currentOffset, value: value))
        return next
    }

    private static func decodePropertyList(_ data: Data) throws -> EntitlementValue {
        let object = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return try PropertyListValueDecoder.decode(object)
    }

    private static func relevantKeys(_ value: EntitlementValue) -> [String] {
        switch value {
        case let .dictionary(dictionary):
            let local = dictionary.keys.filter(isEntitlementKey)
            let nested = dictionary.values.flatMap(relevantKeys)
            return Array(Set(local + nested)).sorted()
        case let .array(values):
            return Array(Set(values.flatMap(relevantKeys))).sorted()
        case .string, .boolean, .integer, .real, .data, .date:
            return []
        }
    }

    private static func isEntitlementKey(_ key: String) -> Bool {
        let lowercased = key.lowercased()
        return indicators.contains { lowercased.hasPrefix($0) || lowercased == $0 }
    }

    private static func uint64(_ bytes: UnsafeBufferPointer<UInt8>, offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= bytes.count else {
            return nil
        }
        return (offset..<(offset + 8)).reduce(0) { ($0 << 8) | UInt64(bytes[$1]) }
    }

    private static func appendWarnings(_ source: [String], to destination: inout [String]) {
        let remaining = max(0, maximumWarnings - destination.count)
        destination.append(contentsOf: source.prefix(remaining))
    }
}

enum RawEvidenceScanError: LocalizedError {
    case unexpectedEndOfFile(String, Int, Int)

    var errorDescription: String? {
        switch self {
        case let .unexpectedEndOfFile(path, read, expected):
            "Raw evidence scan reached the end of \(path) after \(read) bytes; \(expected) bytes were expected from metadata."
        }
    }
}
