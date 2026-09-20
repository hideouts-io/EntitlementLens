import Foundation

/// Encoding and atomic file writes run outside the UI actor, against an immutable snapshot.
func writeExport(to url: URL, encode: @escaping @Sendable () throws -> Data) async throws {
    try await Task.detached(priority: .utility) {
        let data = try encode()
        try data.write(to: url, options: [.atomic])
    }.value
}
