// LinuxServiceDiscoveryConsumerTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import NIOCore
import MDNSCore
@testable import MDNSLinux

/// `LinuxServiceDiscovery` as a DNS-SD consumer, driven through the internal
/// sender seam: no socket is bound. Outgoing queries are captured; responses
/// are fed in through `handleIncoming(data:from:)`. The suite time limit is the
/// hang guard — every await here is cancellable.
@Suite("LinuxServiceDiscovery — DNS-SD consumer", .timeLimit(.minutes(1)))
struct LinuxServiceDiscoveryConsumerTests {

    static let type = "_matterc._udp"
    static let instance = "ABCDEF0123456789"
    static let fullName = "\(instance).\(type).local"
    static let txt: [String: String] = ["D": "3840", "CM": "1", "SII": "5000"]

    static let ptr = DNSRecord(name: "\(type).local", type: .ptr, ttl: 120, rdata: .ptr(domain: fullName))
    static let srv = DNSRecord(name: fullName, type: .srv, ttl: 120,
                               rdata: .srv(priority: 0, weight: 0, port: 5540, target: "host-1.local"))
    static let txtRecord = DNSRecord(name: fullName, type: .txt, ttl: 120, rdata: .txt(["D=3840", "CM=1", "SII=5000"]))
    static let a = DNSRecord(name: "host-1.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, 10])))

    static let record = ServiceRecord(name: instance, serviceType: ServiceType(type), host: "", port: 0)

    /// A discovery whose outgoing messages land in the returned stream.
    static func makeDiscovery(
        resolveTimeout: Duration = .seconds(5),
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) }
    ) -> (LinuxServiceDiscovery, AsyncStream<DNSMessage>) {
        let (sent, sink) = AsyncStream.makeStream(of: DNSMessage.self)
        let discovery = LinuxServiceDiscovery(resolveTimeout: resolveTimeout, sleep: sleep) { sink.yield($0) }
        return (discovery, sent)
    }

    static func feed(_ discovery: LinuxServiceDiscovery, _ records: [DNSRecord]) async throws {
        let data = DNSMessage(isResponse: true, isAuthoritative: true, answers: records).encode()
        await discovery.handleIncoming(data: data, from: try SocketAddress(ipAddress: "127.0.0.1", port: 5353))
    }

    static func questions(_ message: DNSMessage?) -> Set<String> {
        Set((message?.questions ?? []).map { "\($0.name) \($0.type)" })
    }

    // MARK: - Browse

    @Test("browse yields the instance with TXT once PTR, SRV and TXT have arrived in separate packets")
    func browseYieldsAfterTXT() async throws {
        let (discovery, sent) = Self.makeDiscovery()
        var queries = sent.makeAsyncIterator()
        var results = discovery.browse(serviceType: ServiceType(Self.type)).makeAsyncIterator()

        #expect(Self.questions(await queries.next()) == ["_matterc._udp.local ptr"])

        try await Self.feed(discovery, [Self.ptr])
        #expect(Self.questions(await queries.next()) == ["\(Self.fullName) srv", "\(Self.fullName) txt"])

        try await Self.feed(discovery, [Self.srv])
        #expect(Self.questions(await queries.next()) == ["host-1.local a", "host-1.local aaaa"])

        try await Self.feed(discovery, [Self.txtRecord])
        let found = try #require(await results.next())
        #expect(found.name == Self.instance)
        #expect(found.serviceType == ServiceType(Self.type))
        #expect(found.txtRecords == Self.txt)
    }

    @Test("browse yields again when TXT changes, and not for a goodbye")
    func browseReyieldsOnTXTChange() async throws {
        let (discovery, sent) = Self.makeDiscovery()
        var queries = sent.makeAsyncIterator()
        var results = discovery.browse(serviceType: ServiceType(Self.type)).makeAsyncIterator()
        _ = await queries.next() // PTR query: the browse is registered

        try await Self.feed(discovery, [Self.ptr, Self.srv, Self.txtRecord, Self.a])
        #expect(try #require(await results.next()).txtRecords == Self.txt)

        // Same TXT again: no yield. Then a goodbye: no yield. Then the instance
        // returns with a changed TXT: one yield, carrying the new TXT.
        try await Self.feed(discovery, [Self.ptr, Self.txtRecord])
        var goodbye = Self.ptr
        goodbye.ttl = 0
        try await Self.feed(discovery, [goodbye])
        let changed = DNSRecord(name: Self.fullName, type: .txt, ttl: 120, rdata: .txt(["D=3840", "CM=0"]))
        try await Self.feed(discovery, [Self.ptr, changed])

        #expect(try #require(await results.next()).txtRecords == ["D": "3840", "CM": "0"])
    }

    // MARK: - Resolve

    @Test("resolveService returns the host, the SRV port and the TXT; resolve returns the SRV port")
    func resolveServiceReturnsSRVPortAndTXT() async throws {
        let (discovery, sent) = Self.makeDiscovery()
        var queries = sent.makeAsyncIterator()

        async let resolving = discovery.resolveService(Self.record)
        #expect(Self.questions(await queries.next()) == ["\(Self.fullName) srv", "\(Self.fullName) txt"])
        try await Self.feed(discovery, [Self.srv, Self.txtRecord])
        #expect(Self.questions(await queries.next()) == ["host-1.local a", "host-1.local aaaa"])
        try await Self.feed(discovery, [Self.a])

        let resolved = try await resolving
        #expect(resolved == ResolvedService(address: NetworkAddress(host: "192.0.2.10", port: 5540), txtRecords: Self.txt))

        // Now answered from the cache, with the real SRV port rather than 0.
        #expect(try await discovery.resolve(Self.record) == NetworkAddress(host: "192.0.2.10", port: 5540))
    }

    @Test("Two concurrent resolveService calls for one instance both complete")
    func concurrentResolves() async throws {
        let (discovery, sent) = Self.makeDiscovery()
        var queries = sent.makeAsyncIterator()

        async let first = discovery.resolveService(Self.record)
        async let second = discovery.resolveService(Self.record)
        _ = await queries.next()
        _ = await queries.next() // both waiters are registered

        try await Self.feed(discovery, [Self.srv, Self.txtRecord, Self.a])
        let expected = ResolvedService(address: NetworkAddress(host: "192.0.2.10", port: 5540), txtRecords: Self.txt)
        #expect(try await first == expected)
        #expect(try await second == expected)
    }

    @Test("A satisfied resolve cancels its timeout, so it cannot fail a later resolve of the same instance")
    func satisfiedResolveCancelsItsTimeout() async throws {
        let timers = ManualTimers()
        let (discovery, sent) = Self.makeDiscovery(sleep: { _ in try await timers.sleep() })
        var queries = sent.makeAsyncIterator()
        var timerEvents = timers.events.makeAsyncIterator()

        async let first = discovery.resolveService(Self.record)
        _ = await queries.next()
        #expect(await timerEvents.next() == .parked(0))
        try await Self.feed(discovery, [Self.srv, Self.txtRecord, Self.a])
        #expect(try await first.address.port == 5540)
        #expect(await timerEvents.next() == .cancelled(0))

        // Forget the instance, then resolve it again: the second waiter has
        // its own timer, and nothing left over from the first can fail it.
        var goodbyes = [Self.srv, Self.txtRecord, Self.a]
        for index in goodbyes.indices { goodbyes[index].ttl = 0 }
        try await Self.feed(discovery, goodbyes)

        async let second = discovery.resolveService(Self.record)
        _ = await queries.next()
        #expect(await timerEvents.next() == .parked(1))
        try await Self.feed(discovery, [Self.srv, Self.txtRecord, Self.a])
        #expect(try await second.address.port == 5540)
        #expect(await timerEvents.next() == .cancelled(1))
    }

    @Test("A resolve with no answer throws resolveTimeout")
    func resolveTimesOut() async throws {
        let (discovery, _) = Self.makeDiscovery(resolveTimeout: .milliseconds(50))
        await #expect {
            _ = try await discovery.resolveService(Self.record)
        } throws: { error in
            guard case LinuxServiceDiscoveryError.resolveTimeout = error else { return false }
            return true
        }
    }

    @Test("When the address resolves but TXT never arrives, the timeout returns the address with empty TXT")
    func resolveWithoutTXTReturnsAddress() async throws {
        let timers = ManualTimers()
        let (discovery, sent) = Self.makeDiscovery(sleep: { _ in try await timers.sleep() })
        var queries = sent.makeAsyncIterator()
        var timerEvents = timers.events.makeAsyncIterator()

        async let resolving = discovery.resolveService(Self.record)
        _ = await queries.next()
        try await Self.feed(discovery, [Self.srv, Self.a])
        #expect(await timerEvents.next() == .parked(0))
        await timers.fire(0)

        let resolved = try await resolving
        #expect(resolved == ResolvedService(address: NetworkAddress(host: "192.0.2.10", port: 5540), txtRecords: [:]))
    }

    @Test("Cancelling a pending resolve ends it with CancellationError and cancels its timeout")
    func cancelledResolve() async throws {
        let timers = ManualTimers()
        let (discovery, sent) = Self.makeDiscovery(sleep: { _ in try await timers.sleep() })
        var queries = sent.makeAsyncIterator()
        var timerEvents = timers.events.makeAsyncIterator()

        let resolving = Task { try await discovery.resolveService(Self.record) }
        _ = await queries.next()
        #expect(await timerEvents.next() == .parked(0))
        resolving.cancel()

        await #expect(throws: CancellationError.self) { try await resolving.value }
        #expect(await timerEvents.next() == .cancelled(0))
    }

    @Test("Resolving a service advertised locally returns its port and TXT without a query")
    func resolveLocallyAdvertised() async throws {
        let (discovery, _) = Self.makeDiscovery()
        let local = ServiceRecord(name: "local-1", serviceType: ServiceType(Self.type), host: "", port: 5541,
                                  txtRecords: ["D": "1234"])
        try await discovery.advertise(service: local)
        let resolved = try await discovery.resolveService(local)
        await discovery.stopAdvertising()
        #expect(resolved.address.port == 5541)
        #expect(resolved.txtRecords == ["D": "1234"])
    }
}

// MARK: - ManualTimers

/// A `sleep` stand-in whose sleeps end only when the test fires them or the
/// sleeping task is cancelled. Reports each sleep parking and each
/// cancellation, in order, on `events`.
actor ManualTimers {
    enum Event: Equatable, Sendable {
        case parked(Int)
        case cancelled(Int)
    }

    nonisolated let events: AsyncStream<Event>
    private nonisolated let sink: AsyncStream<Event>.Continuation
    private var nextID = 0
    private var parked: [Int: CheckedContinuation<Void, Error>] = [:]
    private var cancelledBeforeParking: Set<Int> = []

    init() {
        (events, sink) = AsyncStream.makeStream(of: Event.self)
    }

    func sleep() async throws {
        let id = nextID
        nextID += 1
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                if cancelledBeforeParking.remove(id) != nil {
                    sink.yield(.cancelled(id))
                    continuation.resume(throwing: CancellationError())
                    return
                }
                parked[id] = continuation
                sink.yield(.parked(id))
            }
        } onCancel: {
            Task { await self.cancel(id) }
        }
    }

    func fire(_ id: Int) {
        parked.removeValue(forKey: id)?.resume()
    }

    private func cancel(_ id: Int) {
        guard let continuation = parked.removeValue(forKey: id) else {
            cancelledBeforeParking.insert(id)
            return
        }
        sink.yield(.cancelled(id))
        continuation.resume(throwing: CancellationError())
    }
}
