import Foundation
import Testing

struct FixtureToolOutput {
    let standardOutput: Data
    let standardError: Data
}

enum FixtureToolError: LocalizedError {
    case failed(String, [String], Int32, String, String)

    var errorDescription: String? {
        switch self {
        case let .failed(executable, arguments, status, output, errors):
            "Fixture tool \(executable) failed with exit status \(status), arguments \(arguments), stdout: \(output), stderr: \(errors)"
        }
    }
}

func runFixtureTool(executable: URL, arguments: [String]) throws -> FixtureToolOutput {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("EntitlementLens-tool-\(UUID())")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer {
        do { try FileManager.default.removeItem(at: root) }
        catch { Issue.record("Fixture tool output cleanup failed: \(error.localizedDescription)") }
    }
    let outputURL = root.appendingPathComponent("stdout")
    let errorURL = root.appendingPathComponent("stderr")
    try Data().write(to: outputURL)
    try Data().write(to: errorURL)
    let outputHandle = try FileHandle(forWritingTo: outputURL)
    let errorHandle = try FileHandle(forWritingTo: errorURL)
    defer {
        do { try outputHandle.close() }
        catch { Issue.record("Fixture stdout close failed: \(error.localizedDescription)") }
        do { try errorHandle.close() }
        catch { Issue.record("Fixture stderr close failed: \(error.localizedDescription)") }
    }
    let process = Process()
    process.executableURL = executable
    process.arguments = arguments
    process.standardOutput = outputHandle
    process.standardError = errorHandle
    try process.run()
    process.waitUntilExit()
    let output = try Data(contentsOf: outputURL)
    let errors = try Data(contentsOf: errorURL)
    guard process.terminationStatus == 0 else {
        throw FixtureToolError.failed(executable.path, arguments, process.terminationStatus,
            String(decoding: output, as: UTF8.self), String(decoding: errors, as: UTF8.self))
    }
    return FixtureToolOutput(standardOutput: output, standardError: errors)
}

func makeSignedUniversalFixture(root: URL, arm64Entitlements: Data, x86Entitlements: Data) throws -> URL {
    let source = root.appendingPathComponent("fixture.c")
    let arm64Plist = root.appendingPathComponent("arm64.plist")
    let x86Plist = root.appendingPathComponent("x86_64.plist")
    let arm64 = root.appendingPathComponent("fixture.arm64")
    let x86 = root.appendingPathComponent("fixture.x86_64")
    let universal = root.appendingPathComponent("fixture.universal")
    try Data("int main(void) { return 0; }\n".utf8).write(to: source)
    try arm64Entitlements.write(to: arm64Plist)
    try x86Entitlements.write(to: x86Plist)
    let xcrun = URL(fileURLWithPath: "/usr/bin/xcrun")
    let codesign = URL(fileURLWithPath: "/usr/bin/codesign")
    _ = try runFixtureTool(executable: xcrun,
        arguments: ["clang", "-target", "arm64-apple-macos14.0", source.path, "-o", arm64.path])
    _ = try runFixtureTool(executable: xcrun,
        arguments: ["clang", "-target", "x86_64-apple-macos14.0", source.path, "-o", x86.path])
    _ = try runFixtureTool(executable: codesign,
        arguments: ["--force", "--sign", "-", "--identifier", "io.hideouts.EntitlementLens.IntegrationFixture",
            "--entitlements", arm64Plist.path, arm64.path])
    _ = try runFixtureTool(executable: codesign,
        arguments: ["--force", "--sign", "-", "--identifier", "io.hideouts.EntitlementLens.IntegrationFixture",
            "--entitlements", x86Plist.path, x86.path])
    _ = try runFixtureTool(executable: xcrun,
        arguments: ["lipo", "-create", arm64.path, x86.path, "-output", universal.path])
    _ = try runFixtureTool(executable: codesign,
        arguments: ["--verify", "--strict", "--all-architectures", universal.path])
    return universal
}
