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
        }
    }
}

enum MachOInspector {
    private enum ByteOrder {
        case little
        case big
    }

    private struct ThinFormat {
        let byteOrder: ByteOrder
        let is64Bit: Bool
    }

    private struct FatFormat {
        let byteOrder: ByteOrder
        let is64Bit: Bool
    }

    private static let maximumLoadCommandBytes: UInt32 = 16 * 1_024 * 1_024

    static func inspect(_ url: URL) throws -> [MachOSlice] {
        let handle = try FileHandle(forReadingFrom: url)
        defer { handle.closeFile() }
        let fileSize = try handle.seekToEnd()
        let prefix = try read(handle: handle, offset: 0, count: 8, fileSize: fileSize, path: url.path)
        if let fatFormat = fatFormat(prefix) {
            return try inspectFat(handle: handle, url: url, prefix: prefix, format: fatFormat, fileSize: fileSize)
        }
        guard let thinFormat = thinFormat(prefix) else {
            return []
        }
        return [try inspectThin(
            handle: handle,
            url: url,
            fileOffset: 0,
            fileSize: fileSize,
            containerSize: fileSize,
            format: thinFormat
        )]
    }

    private static func inspectFat(
        handle: FileHandle,
        url: URL,
        prefix: Data,
        format: FatFormat,
        fileSize: UInt64
    ) throws -> [MachOSlice] {
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
            return try inspectThin(
                handle: handle,
                url: url,
                fileOffset: sliceOffset,
                fileSize: sliceSize,
                containerSize: fileSize,
                format: format
            )
        }
    }

    private static func inspectThin(
        handle: FileHandle,
        url: URL,
        fileOffset: UInt64,
        fileSize: UInt64,
        containerSize: UInt64,
        format: ThinFormat
    ) throws -> MachOSlice {
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

        return MachOSlice(
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
    }

    private static func read(
        handle: FileHandle,
        offset: UInt64,
        count: Int,
        fileSize: UInt64,
        path: String
    ) throws -> Data {
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

    private static func uint32(_ data: Data, offset: Int, order: ByteOrder, path: String) throws -> UInt32 {
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

    private static func uint64(_ data: Data, offset: Int, order: ByteOrder, path: String) throws -> UInt64 {
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
        case (0x0100_000C, _): return "arm64"
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
