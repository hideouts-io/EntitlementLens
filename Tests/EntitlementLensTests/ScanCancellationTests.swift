import Foundation
import Testing
@testable import EntitlementLens

struct ScanCancellationTests {
    @Test
    func cancellationReleasesFullQueueProducer() async throws {
        let channel = ScanWorkChannel(capacity: 1)
        let url = URL(fileURLWithPath: "/usr/bin/true")
        await channel.send(url)
        let producer = Task { await channel.send(url) }
        // Allow the producer to suspend behind the full queue before cancelling.
        try await Task.sleep(for: .milliseconds(30))
        producer.cancel()
        await producer.value
        #expect(await channel.next() == url)
        #expect(await channel.next() == nil)
    }

    @Test
    func cancellationReleasesEmptyQueueConsumer() async throws {
        let channel = ScanWorkChannel(capacity: 1)
        let consumer = Task { await channel.next() }
        try await Task.sleep(for: .milliseconds(30))
        consumer.cancel()
        #expect(await consumer.value == nil)
        await channel.send(URL(fileURLWithPath: "/usr/bin/true"))
        #expect(await channel.next() == nil)
    }

    @Test
    func finishingQueueDrainsAlreadyAcceptedWork() async {
        let channel = ScanWorkChannel(capacity: 2)
        let first = URL(fileURLWithPath: "/usr/bin/true")
        let second = URL(fileURLWithPath: "/usr/bin/false")
        await channel.send(first)
        await channel.send(second)
        await channel.finish()
        #expect(await channel.next() == first)
        #expect(await channel.next() == second)
        #expect(await channel.next() == nil)
    }
}
