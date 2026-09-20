import Foundation

struct ClassifiedFile: Sendable {
    let url: URL
    let kind: FileKind
    let format: String
    let fileSize: Int64?
}

enum FileClassifier {
    private static let bundleExtensions: Set<String> = [
        "app", "appex", "bundle", "framework", "plugin", "xpc"
    ]

    private static let unambiguousMachOMagics: [UInt32: String] = [
        0xFEEDFACE: "Mach-O 32-bit",
        0xCEFAEDFE: "Mach-O 32-bit (swapped)",
        0xFEEDFACF: "Mach-O 64-bit",
        0xCFFAEDFE: "Mach-O 64-bit (swapped)",
        0xBEBAFECA: "Universal Mach-O (swapped)",
        0xCAFEBABF: "Universal Mach-O 64-bit",
        0xBFBAFECA: "Universal Mach-O 64-bit (swapped)"
    ]

    static func classify(_ url: URL) throws -> ClassifiedFile? {
        let values = try url.resourceValues(forKeys: [
            .isDirectoryKey,
            .isRegularFileKey,
            .isSymbolicLinkKey,
            .fileSizeKey
        ])
        if values.isSymbolicLink == true {
            return nil
        }
        if values.isDirectory == true {
            let pathExtension = url.pathExtension.lowercased()
            guard bundleExtensions.contains(pathExtension) else {
                return nil
            }
            return ClassifiedFile(
                url: url,
                kind: .bundle,
                format: "\(pathExtension.uppercased()) bundle",
                fileSize: values.fileSize.map(Int64.init)
            )
        }
        guard values.isRegularFile == true else {
            return nil
        }
        let fileSize = values.fileSize.map(Int64.init)
        if ["plist", "entitlements"].contains(url.pathExtension.lowercased()) {
            return ClassifiedFile(url: url, kind: .propertyList, format: "Property list", fileSize: fileSize)
        }
        let header = try readHeader(url)
        if let format = machOFormat(header, fileSize: fileSize) {
            return ClassifiedFile(url: url, kind: .machO, format: format, fileSize: fileSize)
        }
        let format = magic(header) == 0xCAFE_BABE ? "Java class file" : "Raw file"
        return ClassifiedFile(url: url, kind: .other, format: format, fileSize: fileSize)
    }

    static func looksLikeMachO(_ url: URL) throws -> Bool {
        let values = try url.resourceValues(forKeys: [.fileSizeKey])
        return machOFormat(try readHeader(url), fileSize: values.fileSize.map(Int64.init)) != nil
    }

    private static func readHeader(_ url: URL) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { handle.closeFile() }
        return try handle.read(upToCount: 40) ?? Data()
    }

    private static func machOFormat(_ data: Data, fileSize: Int64?) -> String? {
        guard let magic = magic(data) else {
            return nil
        }
        if let format = unambiguousMachOMagics[magic] {
            return format
        }
        guard magic == 0xCAFE_BABE,
              let fileSize,
              isPlausibleUniversalMachO(data, fileSize: fileSize) else {
            return nil
        }
        return "Universal Mach-O"
    }

    private static func isPlausibleUniversalMachO(_ data: Data, fileSize: Int64) -> Bool {
        guard data.count >= 28,
              let architectureCount = uint32(data, offset: 4),
              (1...128).contains(architectureCount),
              let cpuType = uint32(data, offset: 8),
              let sliceOffset = uint32(data, offset: 16),
              let sliceSize = uint32(data, offset: 20),
              let alignment = uint32(data, offset: 24),
              knownCPUType(cpuType),
              sliceSize > 0,
              alignment < 32 else {
            return false
        }
        let sliceEnd = UInt64(sliceOffset) + UInt64(sliceSize)
        return sliceEnd <= UInt64(max(fileSize, 0))
    }

    private static func knownCPUType(_ value: UInt32) -> Bool {
        let baseType = value & 0x00FF_FFFF
        return [7, 12, 18].contains(baseType)
    }

    private static func magic(_ data: Data) -> UInt32? {
        uint32(data, offset: 0)
    }

    private static func uint32(_ data: Data, offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= data.count else {
            return nil
        }
        return data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | UInt32($1) }
    }
}
