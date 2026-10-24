import CryptoKit
import Darwin
import Foundation

private enum SnapshotError: LocalizedError {
    case invalidRoot
    case invalidCommit
    case invalidTrackedList
    case hiddenTrackedChanges
    case gitFailed(String)
    case outputLimit(String)

    var errorDescription: String? {
        switch self {
        case .invalidRoot:
            "Git did not identify the expected repository root."
        case .invalidCommit:
            "Git did not return a lowercase 40-character commit identifier."
        case .invalidTrackedList:
            "Git did not return a valid tracked-path listing."
        case .hiddenTrackedChanges:
            "Git index flags hide tracked changes from working-tree inspection."
        case let .gitFailed(operation):
            "Git \(operation) failed or exceeded its 10-second limit."
        case let .outputLimit(operation):
            "Git \(operation) exceeded its output limit."
        }
    }
}

private func gitOutput(_ arguments: [String], operation: String, root: URL, maximumBytes: Int) throws -> Data {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
    process.arguments = arguments
    process.currentDirectoryURL = root
    process.environment = ProcessInfo.processInfo.environment.filter { !$0.key.hasPrefix("GIT_") }
    process.standardInput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    let pipe = Pipe()
    process.standardOutput = pipe
    do {
        try process.run()
    } catch {
        throw SnapshotError.gitFailed(operation)
    }
    pipe.fileHandleForWriting.closeFile()

    let timeout = DispatchSource.makeTimerSource(queue: .global())
    timeout.schedule(deadline: .now() + .seconds(10))
    timeout.setEventHandler {
        if process.isRunning {
            _ = Darwin.kill(process.processIdentifier, SIGKILL)
        }
    }
    timeout.resume()
    defer {
        timeout.cancel()
        pipe.fileHandleForReading.closeFile()
    }

    var output = Data()
    while true {
        let chunk = pipe.fileHandleForReading.readData(ofLength: 4_096)
        if chunk.isEmpty { break }
        guard output.count + chunk.count <= maximumBytes else {
            if process.isRunning {
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
            throw SnapshotError.outputLimit(operation)
        }
        output.append(chunk)
    }
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw SnapshotError.gitFailed(operation)
    }
    return output
}

private func gitLine(_ data: Data) -> String? {
    guard data.last == 0x0A, !data.dropLast().contains(0x0A) else { return nil }
    return String(data: data.dropLast(), encoding: .utf8)
}

private func snapshot(at root: URL) throws -> String {
    let identifiedRoot = try gitOutput(
        ["rev-parse", "--show-toplevel"], operation: "root inspection", root: root, maximumBytes: 4_096
    )
    guard let identifiedPath = gitLine(identifiedRoot),
          URL(fileURLWithPath: identifiedPath, isDirectory: true)
              .resolvingSymlinksInPath().standardizedFileURL.path == root.path else {
        throw SnapshotError.invalidRoot
    }
    let commit = try gitOutput(
        ["rev-parse", "--verify", "HEAD^{commit}"], operation: "commit inspection", root: root, maximumBytes: 128
    )
    guard let sourceCommit = gitLine(commit), sourceCommit.utf8.count == 40,
          sourceCommit.utf8.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }) else {
        throw SnapshotError.invalidCommit
    }

    // Git status omits assume-unchanged and skip-worktree edits. Reject those index flags,
    // and count ignored SwiftPM sources and versioned manifests without scanning build caches.
    let tracked = try gitOutput(
        ["ls-files", "-v", "-z"], operation: "tracked-path inspection", root: root,
        maximumBytes: 4 * 1_024 * 1_024
    )
    guard tracked.isEmpty || tracked.last == 0 else {
        throw SnapshotError.invalidTrackedList
    }
    for record in tracked.split(separator: 0) {
        guard record.count >= 3, record[record.index(after: record.startIndex)] == 0x20 else {
            throw SnapshotError.invalidTrackedList
        }
        let marker = record[record.startIndex]
        if marker == 0x53 || (0x61...0x7A).contains(marker) {
            throw SnapshotError.hiddenTrackedChanges
        }
    }
    let status = try gitOutput(
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"],
        operation: "working-tree inspection", root: root, maximumBytes: 4 * 1_024 * 1_024
    )
    let ignoredSources = try gitOutput(
        ["ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "Sources", "Plugins", "Package.swift", ":(top,glob)Package@swift-*.swift"],
        operation: "ignored-source inspection", root: root, maximumBytes: 4 * 1_024 * 1_024
    )
    var worktree = status
    worktree.append(0xFF)
    worktree.append(ignoredSources)
    let worktreeDigest = SHA256.hash(data: worktree).map { String(format: "%02x", $0) }.joined()
    let state = status.isEmpty && ignoredSources.isEmpty ? "clean" : "dirty"
    return "\(state)|\(sourceCommit)|\(worktreeDigest)"
}

guard CommandLine.arguments.count == 2 else {
    fputs("warning: collector build provenance is unknown: expected one repository-root argument.\n", stderr)
    print("unknown")
    exit(0)
}

let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
    .resolvingSymlinksInPath().standardizedFileURL
do {
    print(try snapshot(at: root))
} catch {
    fputs("warning: collector build provenance is unknown: \(error.localizedDescription)\n", stderr)
    print("unknown")
}
