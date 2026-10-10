import Foundation

enum MachOInspectionError: LocalizedError {
    case truncated(String, UInt64)
    case invalidLoadCommand(String, UInt64, String)
    case excessiveHeader(String, UInt32)
    case invalidFatSliceCount(String, UInt32)
    case sliceOverlapsTable(String, UInt64, UInt64)
    case invalidSliceMagic(String, UInt64)
    case invalidCodeSignature(String, UInt64, String)
    case duplicateCodeSignature(String, String)
    case fileCloseFailed(String, String, String)

    var errorDescription: String? {
        switch self {
        case let .truncated(path, offset):
            "The Mach-O data in \(path) is truncated at file offset \(offset)."
        case let .invalidLoadCommand(path, offset, reason):
            "The Mach-O file \(path) has an invalid load command at file offset \(offset): \(reason)"
        case let .excessiveHeader(path, size):
            "The Mach-O load-command area in \(path) is unexpectedly large: \(size) bytes."
        case let .invalidFatSliceCount(path, count):
            "The FAT Mach-O file \(path) declares \(count) slices; the supported range is 1 through 128."
        case let .sliceOverlapsTable(path, offset, tableEnd):
            "The FAT slice in \(path) starts at file offset \(offset), before the architecture table ends at \(tableEnd)."
        case let .invalidSliceMagic(path, offset):
            "The FAT slice in \(path) at file offset \(offset) does not begin with a thin Mach-O header."
        case let .invalidCodeSignature(path, offset, reason):
            "The code-signature load command in \(path) at file offset \(offset) is invalid: \(reason)"
        case let .duplicateCodeSignature(path, architecture):
            "The \(architecture) slice in \(path) contains more than one LC_CODE_SIGNATURE command."
        case let .fileCloseFailed(path, inspectionFailure, closeFailure):
            "Mach-O inspection of \(path) failed: \(inspectionFailure) Closing its read handle also failed: \(closeFailure)"
        }
    }
}

enum MachOInspector {
    private struct ThinFormat {
        let byteOrder: MachOByteOrder
        let is64Bit: Bool
    }

    private struct FatFormat {
        let byteOrder: MachOByteOrder
        let is64Bit: Bool
    }

    private struct ParsedSlice {
        let url: URL
        let slice: MachOSlice
        let cpuType: UInt32
        let cpuSubtype: UInt32
        let fileType: UInt32
        let machHeaderFlags: UInt32
        let format: ThinFormat
        let headerSize: UInt64
        let commandCount: UInt32
        let commands: Data
    }

    private struct ImportCommands {
        let symbolTable: MachOSymbolTableDescriptor?
        let symbolIssue: String?
        let bindingStreams: [MachODyldBindStream]?
        let bindingIssue: String?
        let segments: [MachODyldSegment]
        let segmentIssue: String?
        let chainedImports: MachOChainedImportDescriptor?
        let chainedIssue: String?
        let dylibCount: UInt32
    }

    private static let maximumLoadCommandBytes: UInt32 = 16 * 1_024 * 1_024
    private static let maximumExportedLoadCommands: UInt64 = 4_096
    private static let maximumExportedDependencies: UInt64 = 4_096
    private static let maximumLoadCommandStringBytes: UInt64 = 4_096
    private static let maximumAPIReferencesPerSlice = 16_384

    static func inspect(_ url: URL) throws -> [MachOSlice] {
        try inspectSlices(url, transform: { parsed, _, _ in parsed.slice })
    }

    /// Uses the same structural parser as inspect; optional feature failures retain other slice evidence.
    static func inspectStaticFeatures(_ url: URL) throws -> MachOStaticInspection {
        let slices = try inspectSlices(url, transform: collectStaticFeatures)
        return MachOStaticInspection(
            architectures: try combine(slices.map(\.architectures), limits: architectureLimits),
            loadCommands: try combine(slices.map(\.loadCommands), limits: loadCommandLimits),
            linkedFrameworks: try combine(slices.map(\.linkedFrameworks), limits: dependencyLimits),
            apiReferences: try combine(slices.map(\.apiReferences), limits: apiLimits)
        )
    }

    private static func inspectSlices<Record>(
        _ url: URL, transform: (ParsedSlice, FileHandle, UInt64) throws -> Record
    ) throws -> [Record] {
        try Task.checkCancellation()
        let handle = try FileHandle(forReadingFrom: url)
        let records: [Record]
        do {
            let fileSize = try handle.seekToEnd()
            let prefix = try read(handle: handle, offset: 0, count: 8, fileSize: fileSize, path: url.path)
            if let fatFormat = fatFormat(prefix) {
                records = try inspectFat(
                    handle: handle, url: url, prefix: prefix, format: fatFormat,
                    fileSize: fileSize, transform: transform
                )
            } else if let thinFormat = thinFormat(prefix) {
                let parsed = try inspectThin(
                    handle: handle, url: url, fileOffset: 0, fileSize: fileSize,
                    containerSize: fileSize, format: thinFormat
                )
                records = [try transform(parsed, handle, fileSize)]
            } else {
                records = []
            }
        } catch let inspectionError {
            do { try handle.close() }
            catch let closeError {
                throw MachOInspectionError.fileCloseFailed(
                    url.path, inspectionError.localizedDescription, closeError.localizedDescription
                )
            }
            throw inspectionError
        }
        try handle.close()
        return records
    }

    private static func inspectFat<Record>(
        handle: FileHandle,
        url: URL,
        prefix: Data,
        format: FatFormat,
        fileSize: UInt64,
        transform: (ParsedSlice, FileHandle, UInt64) throws -> Record
    ) throws -> [Record] {
        let count = try uint32(prefix, offset: 4, order: format.byteOrder, path: url.path)
        guard count > 0, count <= 128 else {
            throw MachOInspectionError.invalidFatSliceCount(url.path, count)
        }
        let entrySize = format.is64Bit ? 32 : 20
        let tableSize = 8 + Int(count) * entrySize
        let tableRange = try MachOByteRange(
            offset: 0, length: UInt64(tableSize), containerLength: fileSize,
            path: url.path, context: .fatTable
        )
        let table = try read(handle: handle, offset: 0, count: tableSize, fileSize: fileSize, path: url.path)
        return try (0..<Int(count)).map { index in
            try Task.checkCancellation()
            let entryOffset = 8 + index * entrySize
            let sliceOffset = format.is64Bit
                ? try uint64(table, offset: entryOffset + 8, order: format.byteOrder, path: url.path)
                : UInt64(try uint32(table, offset: entryOffset + 8, order: format.byteOrder, path: url.path))
            let sliceSize = format.is64Bit
                ? try uint64(table, offset: entryOffset + 16, order: format.byteOrder, path: url.path)
                : UInt64(try uint32(table, offset: entryOffset + 12, order: format.byteOrder, path: url.path))
            _ = try MachOByteRange(
                offset: sliceOffset, length: sliceSize, containerLength: fileSize,
                path: url.path, context: .fatSlice
            )
            guard sliceOffset >= tableRange.end else {
                throw MachOInspectionError.sliceOverlapsTable(url.path, sliceOffset, tableRange.end)
            }
            _ = try MachOByteRange(
                offset: 0, length: 8, containerLength: sliceSize,
                path: url.path, context: .thinHeader
            )
            let slicePrefix = try read(
                handle: handle, offset: sliceOffset, count: 8, fileSize: fileSize, path: url.path
            )
            guard let format = thinFormat(slicePrefix) else {
                throw MachOInspectionError.invalidSliceMagic(url.path, sliceOffset)
            }
            let parsed = try inspectThin(
                handle: handle,
                url: url,
                fileOffset: sliceOffset,
                fileSize: sliceSize,
                containerSize: fileSize,
                format: format
            )
            return try transform(parsed, handle, fileSize)
        }
    }

    private static func inspectThin(
        handle: FileHandle,
        url: URL,
        fileOffset: UInt64,
        fileSize: UInt64,
        containerSize: UInt64,
        format: ThinFormat
    ) throws -> ParsedSlice {
        let headerSize = format.is64Bit ? 32 : 28
        _ = try MachOByteRange(
            offset: fileOffset, length: fileSize, containerLength: containerSize,
            path: url.path, context: .fatSlice
        )
        let headerRange = try MachOByteRange(
            offset: 0, length: UInt64(headerSize), containerLength: fileSize,
            path: url.path, context: .thinHeader
        )
        let header = try read(
            handle: handle, offset: fileOffset, count: headerSize, fileSize: containerSize, path: url.path
        )
        let cpuType = try uint32(header, offset: 4, order: format.byteOrder, path: url.path)
        let cpuSubtype = try uint32(header, offset: 8, order: format.byteOrder, path: url.path)
        let fileType = try uint32(header, offset: 12, order: format.byteOrder, path: url.path)
        let machHeaderFlags = try uint32(header, offset: 24, order: format.byteOrder, path: url.path)
        let commandCount = try uint32(header, offset: 16, order: format.byteOrder, path: url.path)
        let commandBytes = try uint32(header, offset: 20, order: format.byteOrder, path: url.path)
        guard commandBytes <= maximumLoadCommandBytes else {
            throw MachOInspectionError.excessiveHeader(url.path, commandBytes)
        }
        let commandRange = try MachOByteRange(
            offset: headerRange.end, length: UInt64(commandBytes), containerLength: fileSize,
            path: url.path, context: .loadCommands
        )
        guard commandCount <= commandBytes / 8 else {
            throw MachOInspectionError.invalidLoadCommand(
                url.path, fileOffset + headerRange.end,
                "\(commandCount) commands cannot fit in the declared \(commandBytes)-byte area."
            )
        }
        let commands = try read(
            handle: handle,
            offset: fileOffset + commandRange.offset,
            count: Int(commandBytes),
            fileSize: containerSize,
            path: url.path
        )
        var commandOffset = 0
        var uuid: String?
        var platform: String?
        var minimumOSVersion: String?
        var sdkVersion: String?
        var codeSignatureOffset: UInt64?
        var codeSignatureSize: UInt64?
        let architecture = architectureName(cpuType: cpuType, cpuSubtype: cpuSubtype)

        for _ in 0..<commandCount {
            try Task.checkCancellation()
            let absoluteCommandOffset = fileOffset + commandRange.offset + UInt64(commandOffset)
            guard commandOffset <= commands.count, 8 <= commands.count - commandOffset else {
                throw MachOInspectionError.invalidLoadCommand(url.path, absoluteCommandOffset, "The command header is truncated.")
            }
            let command = try uint32(commands, offset: commandOffset, order: format.byteOrder, path: url.path)
            let commandSize = try uint32(commands, offset: commandOffset + 4, order: format.byteOrder, path: url.path)
            guard commandSize >= 8, Int(commandSize) <= commands.count - commandOffset else {
                throw MachOInspectionError.invalidLoadCommand(
                    url.path, absoluteCommandOffset, "The declared command size \(commandSize) does not fit the load-command area."
                )
            }
            let alignment: UInt32 = format.is64Bit ? 8 : 4
            guard commandSize % alignment == 0 else {
                throw MachOInspectionError.invalidLoadCommand(
                    url.path, absoluteCommandOffset, "The command size \(commandSize) is not aligned to \(alignment) bytes."
                )
            }
            let minimumSize: UInt32
            switch command {
            case 0x1B, 0x32: minimumSize = 24
            case 0x24, 0x25, 0x2F, 0x30, 0x1D: minimumSize = 16
            default: minimumSize = 8
            }
            guard commandSize >= minimumSize else {
                throw MachOInspectionError.invalidLoadCommand(
                    url.path, absoluteCommandOffset, "Command 0x\(String(command, radix: 16)) requires at least \(minimumSize) bytes, but declares \(commandSize)."
                )
            }
            if command == 0x1B {
                uuid = UUID(uuid: uuidTuple(commands, offset: commandOffset + 8)).uuidString
            } else if command == 0x32 {
                let platformValue = try uint32(commands, offset: commandOffset + 8, order: format.byteOrder, path: url.path)
                let minimumValue = try uint32(commands, offset: commandOffset + 12, order: format.byteOrder, path: url.path)
                let sdkValue = try uint32(commands, offset: commandOffset + 16, order: format.byteOrder, path: url.path)
                platform = platformName(platformValue)
                minimumOSVersion = versionString(minimumValue)
                sdkVersion = versionString(sdkValue)
            } else if [0x24, 0x25, 0x2F, 0x30].contains(command) {
                let minimumValue = try uint32(commands, offset: commandOffset + 8, order: format.byteOrder, path: url.path)
                let sdkValue = try uint32(commands, offset: commandOffset + 12, order: format.byteOrder, path: url.path)
                platform = legacyPlatformName(command)
                minimumOSVersion = versionString(minimumValue)
                sdkVersion = versionString(sdkValue)
            } else if command == 0x1D {
                guard codeSignatureOffset == nil else {
                    throw MachOInspectionError.duplicateCodeSignature(url.path, architecture)
                }
                let relativeOffset = try uint32(commands, offset: commandOffset + 8, order: format.byteOrder, path: url.path)
                let size = try uint32(commands, offset: commandOffset + 12, order: format.byteOrder, path: url.path)
                let signatureRange = try MachOByteRange(
                    offset: UInt64(relativeOffset), length: UInt64(size), containerLength: fileSize,
                    path: url.path, context: .codeSignature
                )
                guard size >= 12, signatureRange.offset >= commandRange.end else {
                    throw MachOInspectionError.invalidCodeSignature(
                        url.path, absoluteCommandOffset,
                        "The region must contain a 12-byte SuperBlob header and begin after the load-command area at slice offset \(commandRange.end)."
                    )
                }
                codeSignatureOffset = fileOffset + signatureRange.offset
                codeSignatureSize = UInt64(size)
            }
            commandOffset += Int(commandSize)
        }

        guard commandOffset == commands.count else {
            throw MachOInspectionError.invalidLoadCommand(
                url.path, fileOffset + commandRange.offset + UInt64(commandOffset),
                "The commands consume \(commandOffset) bytes, but sizeofcmds declares \(commands.count)."
            )
        }

        let slice = MachOSlice(
            architecture: architecture,
            fileOffset: fileOffset,
            fileSize: fileSize,
            uuid: uuid,
            platform: platform,
            minimumOSVersion: minimumOSVersion,
            sdkVersion: sdkVersion,
            codeSignatureOffset: codeSignatureOffset,
            codeSignatureSize: codeSignatureSize
        )
        return ParsedSlice(
            url: url, slice: slice, cpuType: cpuType, cpuSubtype: cpuSubtype,
            fileType: fileType, machHeaderFlags: machHeaderFlags, format: format,
            headerSize: UInt64(headerSize), commandCount: commandCount, commands: commands
        )
    }

    private static var architectureLimits: [StaticCollectionLimit] {
        [StaticCollectionLimit(name: "fat_architecture_slices", value: 128, unit: .records)]
    }

    private static var loadCommandLimits: [StaticCollectionLimit] {
        architectureLimits + [
            StaticCollectionLimit(name: "load_command_bytes_per_slice", value: UInt64(maximumLoadCommandBytes), unit: .bytes),
            StaticCollectionLimit(name: "load_command_records_per_slice", value: maximumExportedLoadCommands, unit: .records),
            StaticCollectionLimit(name: "load_command_string_bytes", value: maximumLoadCommandStringBytes, unit: .bytes)
        ]
    }

    private static var dependencyLimits: [StaticCollectionLimit] {
        architectureLimits + [
            StaticCollectionLimit(name: "dependency_records_per_slice", value: maximumExportedDependencies, unit: .records),
            StaticCollectionLimit(name: "dependency_install_name_bytes", value: maximumLoadCommandStringBytes, unit: .bytes)
        ]
    }

    private static var apiLimits: [StaticCollectionLimit] {
        MachOImportedSymbolCollector.limits + MachODyldBindCollector.limits + MachOChainedImportCollector.limits
        + MachOChainedPointerCollector.limits + MachOObjectiveCLayoutParser.limits + MachOObjectiveCReferenceCollector.limits + [
            StaticCollectionLimit(name: "bind_addressable_segments_per_slice", value: 16, unit: .records),
            StaticCollectionLimit(name: "api_reference_records_per_slice", value: UInt64(maximumAPIReferencesPerSlice), unit: .records)
        ]
    }

    private static func collectStaticFeatures(
        _ parsed: ParsedSlice, _ handle: FileHandle, _ containerSize: UInt64
    ) throws -> MachOStaticInspection {
        var commands: [StaticLoadCommand] = []
        var dependencies: [StaticLinkedDependency] = []
        var firstCommandIssue: String?
        var firstDependencyIssue: String?
        var symbolTable: MachOSymbolTableDescriptor?
        var symbolIssue: String?
        var bindingStreams: [MachODyldBindStream]?
        var bindingIssue: String?
        var segments: [MachODyldSegment] = []
        var segmentIssue: String?
        var segmentCommandCount: UInt32 = 0
        var chainedImports: MachOChainedImportDescriptor?
        var chainedIssue: String?
        var dylibCount: UInt32 = 0
        var commandLimitReached = false
        var dependencyLimitReached = false
        var commandOffset = 0
        for _ in 0..<parsed.commandCount {
            try Task.checkCancellation()
            let command = try uint32(parsed.commands, offset: commandOffset, order: parsed.format.byteOrder, path: parsed.url.path)
            let commandSize = try uint32(parsed.commands, offset: commandOffset + 4, order: parsed.format.byteOrder, path: parsed.url.path)
            let commandFileOffset = parsed.slice.fileOffset + parsed.headerSize + UInt64(commandOffset)
            let location = StaticEvidenceLocation(
                sourcePath: parsed.url.path, architecture: parsed.slice.architecture, sliceOffset: parsed.slice.fileOffset,
                fileOffset: commandFileOffset,
                byteCount: UInt64(commandSize), propertyListKey: nil, method: .loadCommand
            )
            var dylib: StaticDylibDeclaration?
            var searchPath: String?
            var decodingIssue: String?
            let kind = dependencyKind(command)
            if kind != nil { dylibCount += 1 }
            do {
                if kind != nil || command == 0x0D {
                    dylib = try decodeDylib(parsed: parsed, offset: commandOffset, size: commandSize)
                } else if command == 0x8000_001C {
                    searchPath = try commandString(parsed: parsed, offset: commandOffset, size: commandSize, minimumSize: 12)
                }
            } catch let error as MachOInspectionError {
                decodingIssue = error.localizedDescription
                if firstCommandIssue == nil { firstCommandIssue = error.localizedDescription }
                if kind != nil, firstDependencyIssue == nil { firstDependencyIssue = error.localizedDescription }
            }
            if let dylib, let kind {
                if UInt64(dependencies.count) < maximumExportedDependencies {
                    dependencies.append(StaticLinkedDependency(
                        installName: dylib.installName, frameworkName: frameworkName(dylib.installName), kind: kind,
                        currentVersion: dylib.currentVersion, compatibilityVersion: dylib.compatibilityVersion, location: location
                    ))
                } else { dependencyLimitReached = true }
            }
            if command == 0x02 {
                do {
                    guard symbolTable == nil, symbolIssue == nil else {
                        throw MachOInspectionError.invalidLoadCommand(
                            parsed.url.path, parsed.slice.fileOffset + parsed.headerSize + UInt64(commandOffset),
                            "The slice contains more than one LC_SYMTAB or a previously invalid symbol-table command."
                        )
                    }
                    symbolTable = try decodeSymbolTable(parsed: parsed, offset: commandOffset, size: commandSize)
                } catch let error as MachOInspectionError {
                    symbolIssue = error.localizedDescription
                    decodingIssue = error.localizedDescription
                }
            }
            if command == 0x01 || command == 0x19 {
                // A bind opcode's four-bit immediate can address only the first sixteen segments.
                if segmentCommandCount < 16 {
                    do {
                        segments.append(try decodeBindSegment(parsed: parsed, offset: commandOffset, size: commandSize, command: command))
                    } catch let error as MachOInspectionError {
                        segmentIssue = error.localizedDescription
                        decodingIssue = error.localizedDescription
                    }
                }
                segmentCommandCount += 1
            }
            if command == 0x22 || command == 0x8000_0022 {
                do {
                    guard bindingStreams == nil, bindingIssue == nil else {
                        throw MachOInspectionError.invalidLoadCommand(parsed.url.path, commandFileOffset,
                            "The slice contains multiple dyld-info commands or an earlier invalid binding descriptor.")
                    }
                    bindingStreams = try decodeBindingStreams(parsed: parsed, offset: commandOffset, size: commandSize)
                } catch let error as MachOInspectionError {
                    bindingIssue = error.localizedDescription
                    decodingIssue = error.localizedDescription
                }
            }
            if command == 0x8000_0034 {
                do {
                    guard chainedImports == nil, chainedIssue == nil else {
                        throw MachOInspectionError.invalidLoadCommand(parsed.url.path, commandFileOffset,
                            "The slice contains multiple chained-fixup commands or an earlier invalid import descriptor.")
                    }
                    chainedImports = try decodeChainedImports(parsed: parsed, offset: commandOffset, size: commandSize)
                } catch let error as MachOInspectionError {
                    chainedIssue = error.localizedDescription
                    decodingIssue = error.localizedDescription
                }
            }
            if let decodingIssue, firstCommandIssue == nil { firstCommandIssue = decodingIssue }
            if UInt64(commands.count) < maximumExportedLoadCommands {
                commands.append(StaticLoadCommand(
                    commandID: command, name: commandName(command), commandSize: commandSize,
                    location: location, dylib: dylib, runtimeSearchPath: searchPath, decodingIssue: decodingIssue
                ))
            } else { commandLimitReached = true }
            commandOffset += Int(commandSize)
        }
        let commandLimitations = [
            "All retained command headers are represented; decoded payloads cover dylib declarations and LC_RPATH. UUID and OS/SDK metadata are represented in architectures.",
            "Import command descriptors are decoded for the separate api_references methods. Other command payloads are not decoded. Unrecognized command IDs retain a nil name. Command and slice order follows the artifact."
        ] + (commandLimitReached ? ["The load-command record limit was reached; subsequent command headers are omitted from this export."] : [])
        let dependencyLimitations = [
            "Only LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, and LC_LOAD_UPWARD_DYLIB declarations are collected.",
            "Framework names are derived from the first install-name path component ending in .framework. Declarations do not establish runtime loading or API calls."
        ] + (dependencyLimitReached ? ["The dependency record limit was reached; subsequent declarations are omitted from this export."] : [])
        let apiReferences = try collectAPIReferences(parsed: parsed, handle: handle, containerSize: containerSize,
            commands: ImportCommands(symbolTable: symbolTable, symbolIssue: symbolIssue, bindingStreams: bindingStreams,
                bindingIssue: bindingIssue, segments: segments, segmentIssue: segmentIssue,
                chainedImports: chainedImports, chainedIssue: chainedIssue, dylibCount: dylibCount))
        return MachOStaticInspection(
            architectures: StaticFeatureCollection(
                state: .complete, reason: nil,
                records: [StaticArchitecture(
                    slice: parsed.slice, cpuType: parsed.cpuType, cpuSubtype: parsed.cpuSubtype,
                    location: StaticEvidenceLocation(
                        sourcePath: parsed.url.path, architecture: parsed.slice.architecture, sliceOffset: parsed.slice.fileOffset,
                        fileOffset: parsed.slice.fileOffset, byteCount: parsed.headerSize, propertyListKey: nil, method: .machOHeader
                    )
                )], limitations: [], limits: architectureLimits
            ),
            loadCommands: StaticFeatureCollection(
                state: firstCommandIssue == nil && !commandLimitReached ? .complete : .partial,
                reason: firstCommandIssue ?? (commandLimitReached ? "The \(maximumExportedLoadCommands)-command export limit was reached for \(parsed.slice.architecture) at file offset \(parsed.slice.fileOffset)." : nil),
                records: commands, limitations: commandLimitations, limits: loadCommandLimits
            ),
            linkedFrameworks: StaticFeatureCollection(
                state: firstDependencyIssue == nil && !dependencyLimitReached ? .complete : .partial,
                reason: firstDependencyIssue ?? (dependencyLimitReached ? "The \(maximumExportedDependencies)-dependency export limit was reached for \(parsed.slice.architecture) at file offset \(parsed.slice.fileOffset)." : nil),
                records: dependencies, limitations: dependencyLimitations, limits: dependencyLimits
            ),
            apiReferences: apiReferences
        )
    }

    private static func collectAPIReferences(
        parsed: ParsedSlice, handle: FileHandle, containerSize: UInt64, commands: ImportCommands
    ) throws -> StaticFeatureCollection<StaticAPIReference> {
        let minimumDataOffset = parsed.headerSize + UInt64(parsed.commands.count)
        var collections: [StaticFeatureCollection<StaticAPIReference>] = []
        var ordinaryBindings: StaticFeatureCollection<StaticAPIReference>?
        var chainedInspection: MachOChainedImportInspection?
        if let issue = commands.symbolIssue {
            collections.append(failedAPICollection(parsed: parsed, reason: issue,
                limitations: MachOImportedSymbolCollector.limitations, limits: MachOImportedSymbolCollector.limits))
        } else if let table = commands.symbolTable {
            collections.append(try MachOImportedSymbolCollector.collect(
                handle: handle, url: parsed.url, slice: parsed.slice, containerSize: containerSize,
                minimumDataOffset: minimumDataOffset, table: table))
        } else {
            collections.append(StaticFeatureCollection(state: .unsupported,
                reason: "The \(parsed.slice.architecture) slice at file offset \(parsed.slice.fileOffset) has no LC_SYMTAB; symbol-table collection is unavailable for this scope.",
                records: [], limitations: MachOImportedSymbolCollector.limitations, limits: MachOImportedSymbolCollector.limits))
        }
        if let issue = commands.bindingIssue {
            collections.append(failedAPICollection(parsed: parsed, reason: issue,
                limitations: MachODyldBindCollector.limitations, limits: MachODyldBindCollector.limits))
        } else if let streams = commands.bindingStreams {
            if let issue = commands.segmentIssue {
                collections.append(failedAPICollection(parsed: parsed, reason: issue,
                    limitations: MachODyldBindCollector.limitations, limits: MachODyldBindCollector.limits))
            } else {
                let bindings = try MachODyldBindCollector.collect(
                    handle: handle, url: parsed.url, slice: parsed.slice, containerSize: containerSize,
                    minimumDataOffset: minimumDataOffset, streams: streams, segments: commands.segments,
                    pointerSize: parsed.format.is64Bit ? 8 : 4, dylibCount: commands.dylibCount)
                ordinaryBindings = bindings
                collections.append(bindings)
            }
        }
        if let issue = commands.chainedIssue {
            collections.append(failedAPICollection(parsed: parsed, reason: issue,
                limitations: MachOChainedImportCollector.limitations, limits: MachOChainedImportCollector.limits))
        } else if let descriptor = commands.chainedImports {
            let inspection = try MachOChainedImportCollector.inspect(
                handle: handle, url: parsed.url, slice: parsed.slice, containerSize: containerSize,
                minimumDataOffset: minimumDataOffset, descriptor: descriptor, dylibCount: commands.dylibCount)
            chainedInspection = inspection
            collections.append(inspection.references)
        }
        let objectiveC = try collectObjectiveCReferences(parsed: parsed, handle: handle,
            containerSize: containerSize, minimumDataOffset: minimumDataOffset,
            commands: commands, ordinaryBindings: ordinaryBindings, chainedInspection: chainedInspection)
        if objectiveC.state != .notApplicable { collections.append(objectiveC) }
        let combined = try combine(collections, limits: apiLimits)
        guard combined.records.count > maximumAPIReferencesPerSlice else { return combined }
        let reason = "Combined API collection for \(parsed.slice.architecture) at slice offset \(parsed.slice.fileOffset) reached its \(maximumAPIReferencesPerSlice)-record limit; subsequent method records were not retained."
        return StaticFeatureCollection(state: .partial,
            reason: combined.reason.map { $0 + " " + reason } ?? reason,
            records: Array(combined.records.prefix(maximumAPIReferencesPerSlice)),
            limitations: combined.limitations + [reason], limits: apiLimits)
    }

    private static func collectObjectiveCReferences(
        parsed: ParsedSlice, handle: FileHandle, containerSize: UInt64,
        minimumDataOffset: UInt64, commands: ImportCommands,
        ordinaryBindings: StaticFeatureCollection<StaticAPIReference>?, chainedInspection: MachOChainedImportInspection?
    ) throws -> StaticFeatureCollection<StaticAPIReference> {
        do {
            let layout = try MachOObjectiveCLayoutParser.parse(commands: parsed.commands,
                commandCount: parsed.commandCount, slice: parsed.slice, headerSize: parsed.headerSize,
                is64Bit: parsed.format.is64Bit, byteOrder: parsed.format.byteOrder)
            let pointerSource: MachOObjectiveCPointerSource
            if !layout.sections.contains(where: {
                ["__objc_selrefs", "__objc_classrefs"].contains($0.sectionName) && $0.byteCount > 0
            }) {
                pointerSource = .unavailable("No Objective-C reference slots require pointer collection.")
            } else if let issue = commands.chainedIssue {
                pointerSource = .unavailable(issue)
            } else if let descriptor = commands.chainedImports, let chainedInspection {
                guard commands.bindingStreams == nil, commands.bindingIssue == nil else {
                    throw MachOObjectiveCLayoutError.unsupported(parsed.url.path,
                        "The slice mixes chained fixups and an ordinary binding descriptor; metadata pointer ownership is not established.")
                }
                let pointers = try MachOChainedPointerCollector.collect(handle: handle, url: parsed.url,
                    slice: parsed.slice, containerSize: containerSize, minimumDataOffset: minimumDataOffset,
                    descriptor: descriptor, segments: layout.segments, imports: chainedInspection.entries)
                pointerSource = .chainedFixups(pointers)
            } else if let ordinaryBindings {
                pointerSource = .ordinaryBindings(ordinaryBindings)
            } else {
                pointerSource = .unavailable(commands.bindingIssue ?? commands.segmentIssue
                    ?? "No ordinary binding or supported chained-pointer source was established for this slice.")
            }
            return try MachOObjectiveCReferenceCollector.collect(handle: handle, url: parsed.url,
                slice: parsed.slice, containerSize: containerSize, minimumDataOffset: minimumDataOffset,
                sections: layout.sections, byteOrder: parsed.format.byteOrder, fileType: parsed.fileType,
                machHeaderFlags: parsed.machHeaderFlags, pointerSource: pointerSource)
        } catch let error as MachOObjectiveCLayoutError {
            return StaticFeatureCollection(state: error.collectionState,
                reason: "\(parsed.slice.architecture) at file offset \(parsed.slice.fileOffset): \(error.localizedDescription)",
                records: [], limitations: MachOObjectiveCLayoutParser.limitations + MachOObjectiveCReferenceCollector.limitations,
                limits: MachOObjectiveCLayoutParser.limits + MachOObjectiveCReferenceCollector.limits)
        } catch let error as MachOByteRangeError {
            return failedAPICollection(parsed: parsed, reason: error.localizedDescription,
                limitations: MachOObjectiveCLayoutParser.limitations + MachOObjectiveCReferenceCollector.limitations,
                limits: MachOObjectiveCLayoutParser.limits + MachOObjectiveCReferenceCollector.limits)
        }
    }

    private static func failedAPICollection(
        parsed: ParsedSlice, reason: String, limitations: [String], limits: [StaticCollectionLimit]
    ) -> StaticFeatureCollection<StaticAPIReference> {
        StaticFeatureCollection(state: .unavailable,
            reason: "\(parsed.slice.architecture) at file offset \(parsed.slice.fileOffset): \(reason)",
            records: [], limitations: limitations, limits: limits)
    }

    private static func decodeBindSegment(
        parsed: ParsedSlice, offset: Int, size: UInt32, command: UInt32
    ) throws -> MachODyldSegment {
        let expectedCommand: UInt32 = parsed.format.is64Bit ? 0x19 : 0x01
        let minimumSize: UInt32 = parsed.format.is64Bit ? 72 : 56
        guard command == expectedCommand, size >= minimumSize else {
            throw MachOInspectionError.invalidLoadCommand(parsed.url.path,
                parsed.slice.fileOffset + parsed.headerSize + UInt64(offset),
                "The segment header does not match the slice's pointer width or minimum header size.")
        }
        let virtualSize = parsed.format.is64Bit
            ? try uint64(parsed.commands, offset: offset + 32, order: parsed.format.byteOrder, path: parsed.url.path)
            : UInt64(try uint32(parsed.commands, offset: offset + 28, order: parsed.format.byteOrder, path: parsed.url.path))
        let fileOffset = parsed.format.is64Bit
            ? try uint64(parsed.commands, offset: offset + 40, order: parsed.format.byteOrder, path: parsed.url.path)
            : UInt64(try uint32(parsed.commands, offset: offset + 32, order: parsed.format.byteOrder, path: parsed.url.path))
        let fileSize = parsed.format.is64Bit
            ? try uint64(parsed.commands, offset: offset + 48, order: parsed.format.byteOrder, path: parsed.url.path)
            : UInt64(try uint32(parsed.commands, offset: offset + 36, order: parsed.format.byteOrder, path: parsed.url.path))
        guard fileOffset <= parsed.slice.fileSize, fileSize <= parsed.slice.fileSize - fileOffset,
            fileSize <= virtualSize else {
            throw MachOInspectionError.invalidLoadCommand(parsed.url.path,
                parsed.slice.fileOffset + parsed.headerSize + UInt64(offset),
                "The segment's file-backed range exceeds its slice or declared virtual size.")
        }
        return MachODyldSegment(virtualSize: virtualSize, fileOffset: fileOffset, fileSize: fileSize)
    }

    private static func decodeBindingStreams(
        parsed: ParsedSlice, offset: Int, size: UInt32
    ) throws -> [MachODyldBindStream] {
        guard size >= 48 else {
            throw MachOInspectionError.invalidLoadCommand(parsed.url.path,
                parsed.slice.fileOffset + parsed.headerSize + UInt64(offset),
                "LC_DYLD_INFO requires a 48-byte header.")
        }
        let fields: [(kind: MachODyldBindKind, offset: Int)] = [(.normal, 16), (.weak, 24), (.lazy, 32)]
        return try fields.map { field in
            MachODyldBindStream(kind: field.kind,
                dataOffset: try uint32(parsed.commands, offset: offset + field.offset, order: parsed.format.byteOrder, path: parsed.url.path),
                dataSize: try uint32(parsed.commands, offset: offset + field.offset + 4, order: parsed.format.byteOrder, path: parsed.url.path))
        }
    }

    private static func decodeChainedImports(
        parsed: ParsedSlice, offset: Int, size: UInt32
    ) throws -> MachOChainedImportDescriptor {
        guard size >= 16 else {
            throw MachOInspectionError.invalidLoadCommand(parsed.url.path,
                parsed.slice.fileOffset + parsed.headerSize + UInt64(offset),
                "LC_DYLD_CHAINED_FIXUPS requires a 16-byte linkedit header.")
        }
        return MachOChainedImportDescriptor(
            dataOffset: try uint32(parsed.commands, offset: offset + 8, order: parsed.format.byteOrder, path: parsed.url.path),
            dataSize: try uint32(parsed.commands, offset: offset + 12, order: parsed.format.byteOrder, path: parsed.url.path),
            byteOrder: parsed.format.byteOrder)
    }

    private static func decodeDylib(parsed: ParsedSlice, offset: Int, size: UInt32) throws -> StaticDylibDeclaration {
        let name = try commandString(parsed: parsed, offset: offset, size: size, minimumSize: 24)
        return StaticDylibDeclaration(
            installName: name,
            timestamp: try uint32(parsed.commands, offset: offset + 12, order: parsed.format.byteOrder, path: parsed.url.path),
            currentVersion: versionString(try uint32(parsed.commands, offset: offset + 16, order: parsed.format.byteOrder, path: parsed.url.path)),
            compatibilityVersion: versionString(try uint32(parsed.commands, offset: offset + 20, order: parsed.format.byteOrder, path: parsed.url.path))
        )
    }

    private static func commandString(parsed: ParsedSlice, offset: Int, size: UInt32, minimumSize: UInt32) throws -> String {
        let absoluteOffset = parsed.slice.fileOffset + parsed.headerSize + UInt64(offset)
        guard size >= minimumSize else {
            throw MachOInspectionError.invalidLoadCommand(parsed.url.path, absoluteOffset, "The string-bearing command requires at least \(minimumSize) bytes.")
        }
        let relativeOffset = try uint32(parsed.commands, offset: offset + 8, order: parsed.format.byteOrder, path: parsed.url.path)
        guard relativeOffset >= minimumSize, relativeOffset < size else {
            throw MachOInspectionError.invalidLoadCommand(parsed.url.path, absoluteOffset, "String offset \(relativeOffset) does not address payload bytes within this \(size)-byte command.")
        }
        let stringStart = offset + Int(relativeOffset)
        let stringByteCount = min(Int(size - relativeOffset), Int(maximumLoadCommandStringBytes) + 1)
        let stringBytes = parsed.commands[stringStart..<(stringStart + stringByteCount)]
        guard let terminator = stringBytes.firstIndex(of: 0), terminator > stringStart else {
            throw MachOInspectionError.invalidLoadCommand(parsed.url.path, absoluteOffset, "The string is empty or lacks a NUL terminator within this command and its \(maximumLoadCommandStringBytes)-byte collection limit.")
        }
        guard let value = String(data: parsed.commands[stringStart..<terminator], encoding: .utf8) else {
            throw MachOInspectionError.invalidLoadCommand(parsed.url.path, absoluteOffset, "The command string is not valid UTF-8; replacement characters were not substituted.")
        }
        return value
    }

    private static func decodeSymbolTable(parsed: ParsedSlice, offset: Int, size: UInt32) throws -> MachOSymbolTableDescriptor {
        guard size >= 24 else {
            throw MachOInspectionError.invalidLoadCommand(
                parsed.url.path, parsed.slice.fileOffset + parsed.headerSize + UInt64(offset),
                "LC_SYMTAB requires at least 24 bytes."
            )
        }
        return MachOSymbolTableDescriptor(
            symbolOffset: try uint32(parsed.commands, offset: offset + 8, order: parsed.format.byteOrder, path: parsed.url.path),
            symbolCount: try uint32(parsed.commands, offset: offset + 12, order: parsed.format.byteOrder, path: parsed.url.path),
            stringOffset: try uint32(parsed.commands, offset: offset + 16, order: parsed.format.byteOrder, path: parsed.url.path),
            stringSize: try uint32(parsed.commands, offset: offset + 20, order: parsed.format.byteOrder, path: parsed.url.path),
            byteOrder: parsed.format.byteOrder, recordFormat: parsed.format.is64Bit ? .nlist64 : .nlist32
        )
    }

    private static func dependencyKind(_ command: UInt32) -> StaticDependencyKind? {
        switch command {
        case 0x0C: .load
        case 0x8000_0018: .weakLoad
        case 0x8000_001F: .reexport
        case 0x20: .lazyLoad
        case 0x8000_0023: .upwardLoad
        default: nil
        }
    }

    private static func frameworkName(_ installName: String) -> String? {
        guard let component = installName.split(separator: "/").first(where: { $0.hasSuffix(".framework") }) else { return nil }
        let name = String(component.dropLast(".framework".count))
        return name.isEmpty ? nil : name
    }

    private static func combine<Record: Codable & Hashable & Sendable>(
        _ collections: [StaticFeatureCollection<Record>], limits: [StaticCollectionLimit]
    ) throws -> StaticFeatureCollection<Record> {
        guard !collections.isEmpty else {
            return StaticFeatureCollection(
                state: .notApplicable, reason: "The inspected file does not contain a Mach-O header.",
                records: [], limitations: [], limits: limits
            )
        }
        let state: StaticCollectionState
        if collections.allSatisfy({ $0.state == .complete }) { state = .complete }
        else if collections.allSatisfy({ $0.state == .unsupported }) { state = .unsupported }
        else if collections.allSatisfy({ $0.state == .unavailable }) { state = .unavailable }
        else { state = .partial }
        var records: [Record] = []
        var limitations: [String] = []
        var reasons: [String] = []
        for collection in collections {
            try Task.checkCancellation()
            records.append(contentsOf: collection.records)
            if let reason = collection.reason { reasons.append(reason) }
            for limitation in collection.limitations {
                if !limitations.contains(limitation) { limitations.append(limitation) }
            }
        }
        return StaticFeatureCollection(
            state: state, reason: reasons.isEmpty ? nil : reasons.joined(separator: " "),
            records: records, limitations: limitations, limits: limits
        )
    }

    private static func commandName(_ command: UInt32) -> String? {
        switch command {
        case 0x01: "LC_SEGMENT"
        case 0x02: "LC_SYMTAB"
        case 0x03: "LC_SYMSEG"
        case 0x04: "LC_THREAD"
        case 0x05: "LC_UNIXTHREAD"
        case 0x06: "LC_LOADFVMLIB"
        case 0x07: "LC_IDFVMLIB"
        case 0x08: "LC_IDENT"
        case 0x09: "LC_FVMFILE"
        case 0x0A: "LC_PREPAGE"
        case 0x0B: "LC_DYSYMTAB"
        case 0x0C: "LC_LOAD_DYLIB"
        case 0x0D: "LC_ID_DYLIB"
        case 0x0E: "LC_LOAD_DYLINKER"
        case 0x0F: "LC_ID_DYLINKER"
        case 0x10: "LC_PREBOUND_DYLIB"
        case 0x11: "LC_ROUTINES"
        case 0x12: "LC_SUB_FRAMEWORK"
        case 0x13: "LC_SUB_UMBRELLA"
        case 0x14: "LC_SUB_CLIENT"
        case 0x15: "LC_SUB_LIBRARY"
        case 0x16: "LC_TWOLEVEL_HINTS"
        case 0x17: "LC_PREBIND_CKSUM"
        case 0x8000_0018: "LC_LOAD_WEAK_DYLIB"
        case 0x19: "LC_SEGMENT_64"
        case 0x1A: "LC_ROUTINES_64"
        case 0x1B: "LC_UUID"
        case 0x8000_001C: "LC_RPATH"
        case 0x1D: "LC_CODE_SIGNATURE"
        case 0x1E: "LC_SEGMENT_SPLIT_INFO"
        case 0x8000_001F: "LC_REEXPORT_DYLIB"
        case 0x20: "LC_LAZY_LOAD_DYLIB"
        case 0x21: "LC_ENCRYPTION_INFO"
        case 0x22: "LC_DYLD_INFO"
        case 0x8000_0022: "LC_DYLD_INFO_ONLY"
        case 0x8000_0023: "LC_LOAD_UPWARD_DYLIB"
        case 0x24: "LC_VERSION_MIN_MACOSX"
        case 0x25: "LC_VERSION_MIN_IPHONEOS"
        case 0x26: "LC_FUNCTION_STARTS"
        case 0x27: "LC_DYLD_ENVIRONMENT"
        case 0x8000_0028: "LC_MAIN"
        case 0x29: "LC_DATA_IN_CODE"
        case 0x2A: "LC_SOURCE_VERSION"
        case 0x2B: "LC_DYLIB_CODE_SIGN_DRS"
        case 0x2C: "LC_ENCRYPTION_INFO_64"
        case 0x2D: "LC_LINKER_OPTION"
        case 0x2E: "LC_LINKER_OPTIMIZATION_HINT"
        case 0x2F: "LC_VERSION_MIN_TVOS"
        case 0x30: "LC_VERSION_MIN_WATCHOS"
        case 0x31: "LC_NOTE"
        case 0x32: "LC_BUILD_VERSION"
        case 0x8000_0033: "LC_DYLD_EXPORTS_TRIE"
        case 0x8000_0034: "LC_DYLD_CHAINED_FIXUPS"
        case 0x8000_0035: "LC_FILESET_ENTRY"
        case 0x36: "LC_ATOM_INFO"
        case 0x37: "LC_FUNCTION_VARIANTS"
        case 0x38: "LC_FUNCTION_VARIANT_FIXUPS"
        case 0x39: "LC_TARGET_TRIPLE"
        case 0x3A: "LC_LAZY_LOAD_DYLIB_INFO"
        default: nil
        }
    }

    private static func read(
        handle: FileHandle,
        offset: UInt64,
        count: Int,
        fileSize: UInt64,
        path: String
    ) throws -> Data {
        try Task.checkCancellation()
        _ = try MachOByteRange(
            offset: offset, length: UInt64(count), containerLength: fileSize,
            path: path, context: .fileRead
        )
        try handle.seek(toOffset: offset)
        let data = try handle.read(upToCount: count) ?? Data()
        guard data.count == count else {
            throw MachOInspectionError.truncated(path, offset + UInt64(data.count))
        }
        return data
    }

    private static func thinFormat(_ data: Data) -> ThinFormat? {
        guard data.count >= 4 else {
            return nil
        }
        switch Array(data.prefix(4)) {
        case [0xCE, 0xFA, 0xED, 0xFE]: return ThinFormat(byteOrder: .little, is64Bit: false)
        case [0xCF, 0xFA, 0xED, 0xFE]: return ThinFormat(byteOrder: .little, is64Bit: true)
        case [0xFE, 0xED, 0xFA, 0xCE]: return ThinFormat(byteOrder: .big, is64Bit: false)
        case [0xFE, 0xED, 0xFA, 0xCF]: return ThinFormat(byteOrder: .big, is64Bit: true)
        default: return nil
        }
    }

    private static func fatFormat(_ data: Data) -> FatFormat? {
        guard data.count >= 4 else {
            return nil
        }
        switch Array(data.prefix(4)) {
        case [0xCA, 0xFE, 0xBA, 0xBE]: return FatFormat(byteOrder: .big, is64Bit: false)
        case [0xBE, 0xBA, 0xFE, 0xCA]: return FatFormat(byteOrder: .little, is64Bit: false)
        case [0xCA, 0xFE, 0xBA, 0xBF]: return FatFormat(byteOrder: .big, is64Bit: true)
        case [0xBF, 0xBA, 0xFE, 0xCA]: return FatFormat(byteOrder: .little, is64Bit: true)
        default: return nil
        }
    }

    private static func uint32(_ data: Data, offset: Int, order: MachOByteOrder, path: String) throws -> UInt32 {
        guard offset >= 0, offset <= data.count, 4 <= data.count - offset else {
            throw MachOInspectionError.truncated(path, UInt64(max(offset, 0)))
        }
        let bytes = data[offset..<(offset + 4)]
        switch order {
        case .little:
            return bytes.enumerated().reduce(0) { value, item in
                value | (UInt32(item.element) << UInt32(item.offset * 8))
            }
        case .big:
            return bytes.reduce(0) { ($0 << 8) | UInt32($1) }
        }
    }

    private static func uint64(_ data: Data, offset: Int, order: MachOByteOrder, path: String) throws -> UInt64 {
        guard offset >= 0, offset <= data.count, 8 <= data.count - offset else {
            throw MachOInspectionError.truncated(path, UInt64(max(offset, 0)))
        }
        let bytes = data[offset..<(offset + 8)]
        switch order {
        case .little:
            return bytes.enumerated().reduce(0) { value, item in
                value | (UInt64(item.element) << UInt64(item.offset * 8))
            }
        case .big:
            return bytes.reduce(0) { ($0 << 8) | UInt64($1) }
        }
    }

    private static func uuidTuple(_ data: Data, offset: Int) -> uuid_t {
        let bytes = Array(data[offset..<(offset + 16)])
        return (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        )
    }

    private static func architectureName(cpuType: UInt32, cpuSubtype: UInt32) -> String {
        let subtype = cpuSubtype & 0x00FF_FFFF
        switch (cpuType, subtype) {
        case (0x0100_000C, 2): return "arm64e"
        case (0x0100_000C, 3): return "arm64.x1"
        case (0x0100_000C, 12): return "arm64e.x1"
        case (0x0100_000C, 0), (0x0100_000C, 1): return "arm64"
        case (0x0100_0007, 8): return "x86_64h"
        case (0x0100_0007, _): return "x86_64"
        case (12, _): return "arm"
        case (7, _): return "i386"
        default: return "cpu-\(cpuType)-subtype-\(subtype)"
        }
    }

    private static func platformName(_ value: UInt32) -> String {
        switch value {
        case 1: "macOS"
        case 2: "iOS"
        case 3: "tvOS"
        case 4: "watchOS"
        case 6: "Mac Catalyst"
        case 7: "iOS Simulator"
        case 8: "tvOS Simulator"
        case 9: "watchOS Simulator"
        case 10: "DriverKit"
        case 11: "visionOS"
        case 12: "visionOS Simulator"
        default: "Platform \(value)"
        }
    }

    private static func legacyPlatformName(_ command: UInt32) -> String {
        switch command {
        case 0x24: "macOS"
        case 0x25: "iOS"
        case 0x2F: "tvOS"
        case 0x30: "watchOS"
        default: "Unknown"
        }
    }

    private static func versionString(_ value: UInt32) -> String {
        let major = value >> 16
        let minor = (value >> 8) & 0xFF
        let patch = value & 0xFF
        return patch == 0 ? "\(major).\(minor)" : "\(major).\(minor).\(patch)"
    }
}
