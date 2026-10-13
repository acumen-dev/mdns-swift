// LinuxServiceDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import NIOCore
import NIOPosix
import MDNSCore
import Logging

// MARK: - LinuxServiceDiscovery

/// Linux platform mDNS/DNS-SD service discovery using a pure-Swift mDNS responder (RFC 6762).
///
/// Binds a UDP socket to port 5353 and joins the IPv4 mDNS multicast group
/// (`224.0.0.251`). Handles PTR/SRV/TXT advertisement without any external
/// dependency beyond SwiftNIO.
///
/// As a DNS-SD consumer it caches every record it hears. `browse` follows a
/// PTR with SRV and TXT queries for the instance, then A/AAAA for the SRV
/// target, and yields each instance once its TXT is known (again whenever
/// the TXT changes). `resolveService` returns the SRV target's address, the
/// SRV port and the TXT.
///
/// ```swift
/// let discovery = LinuxServiceDiscovery()
/// try await discovery.advertise(service: ServiceRecord(
///     name: "My Bridge",
///     serviceType: "_hap._tcp",
///     host: "",
///     port: 51826,
///     txtRecords: ["id": "AA:BB:CC:DD:EE:FF", "c#": "1"]
/// ))
/// for await record in discovery.browse(serviceType: "_hap._tcp") {
///     print("Found: \(record.name)")
/// }
/// ```
public actor LinuxServiceDiscovery: ServiceDiscovery {

    // MARK: - State

    private var advertised: [String: ServiceRecord] = [:]
    /// Browse subscriptions, keyed by stream so each can be removed on termination.
    private var browsers: [UUID: Browser] = [:]
    /// Streams that terminated before their browser was added. `addBrowser`
    /// and `removeBrowser` arrive on separate unstructured tasks, so removal
    /// can win; the tombstone stops the late add from leaking a browser.
    private var removedBrowsers: Set<UUID> = []
    /// Resolve waiters, keyed by lowercase full instance name, then by waiter.
    private var pendingResolves: [String: [UUID: ResolveWaiter]] = [:]
    private var cache = DNSSDCache()
    /// Follow-up questions last asked, by lowercase name and type, with the
    /// interval before the same question may be asked again (RFC 6762 §5.2).
    private var followUpBackoff: [String: (asked: ContinuousClock.Instant, interval: Duration)] = [:]
    private var channel: Channel?
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let logger: Logger
    private var announceTask: Task<Void, Never>?
    /// How long each resolve waits for an answer.
    private let resolveTimeout: Duration
    private let sleep: @Sendable (Duration) async throws -> Void
    private let now: @Sendable () -> ContinuousClock.Instant
    /// Test seam: when set, outgoing messages go here and no socket is bound.
    private let injectedSender: (@Sendable (DNSMessage) async -> Void)?

    private struct Browser {
        let serviceType: String
        let continuation: AsyncStream<ServiceRecord>.Continuation
        /// The TXT last yielded for each instance, by lowercase full name.
        var yielded: [String: [String: String]] = [:]
    }

    private struct ResolveWaiter {
        let instance: String
        let serviceType: String
        let continuation: CheckedContinuation<ResolvedService, Error>
        let timeout: Task<Void, Never>
    }

    // MARK: - Init

    public init(logger: Logger = Logger(label: "mdns.linux.discovery")) {
        self.init(
            logger: logger,
            resolveTimeout: .seconds(5),
            sleep: { try await Task.sleep(for: $0) },
            now: { .now },
            injectedSender: nil
        )
    }

    /// Never binds a socket: every outgoing message is handed to `sender`, and
    /// responses are fed in through `handleIncoming(data:from:)`.
    init(
        logger: Logger = Logger(label: "mdns.linux.discovery"),
        resolveTimeout: Duration = .seconds(5),
        sleep: @escaping @Sendable (Duration) async throws -> Void = { try await Task.sleep(for: $0) },
        now: @escaping @Sendable () -> ContinuousClock.Instant = { .now },
        sender: @escaping @Sendable (DNSMessage) async -> Void
    ) {
        self.init(logger: logger, resolveTimeout: resolveTimeout, sleep: sleep, now: now, injectedSender: sender)
    }

    private init(
        logger: Logger,
        resolveTimeout: Duration,
        sleep: @escaping @Sendable (Duration) async throws -> Void,
        now: @escaping @Sendable () -> ContinuousClock.Instant,
        injectedSender: (@Sendable (DNSMessage) async -> Void)?
    ) {
        self.logger = logger
        self.resolveTimeout = resolveTimeout
        self.sleep = sleep
        self.now = now
        self.injectedSender = injectedSender
    }

    // MARK: - ServiceDiscovery

    public func advertise(service: ServiceRecord) async throws {
        try await ensureMDNSChannel()
        advertised[service.name] = service
        try await sendAnnouncement(for: service, ttl: 4500)
        restartAnnounceTask()
        logger.info("Advertising '\(service.name)' as \(service.serviceType.rawValue)")
    }

    public func stopAdvertising() async {
        let all = advertised
        advertised.removeAll()
        announceTask?.cancel()
        announceTask = nil
        for service in all.values {
            try? await sendAnnouncement(for: service, ttl: 0)
        }
    }

    public func stopAdvertising(name: String) async {
        guard let service = advertised.removeValue(forKey: name) else { return }
        try? await sendAnnouncement(for: service, ttl: 0)
        if advertised.isEmpty {
            announceTask?.cancel()
            announceTask = nil
        }
    }

    /// `nonisolated` to satisfy the non-`async` `ServiceDiscovery` protocol requirement.
    /// Actor state is accessed safely via `Task { await self. }` inside the closure.
    public nonisolated func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord> {
        let type = serviceType.rawValue
        let streamID = UUID()
        return AsyncStream { [weak self] continuation in
            Task { [weak self] in
                guard await self?.addBrowser(continuation, id: streamID, serviceType: type) == true else { return }
                try? await self?.ensureMDNSChannel()
                try? await self?.send(DNSMessage(
                    isResponse: false,
                    questions: [DNSQuestion(name: "\(type).local", type: .ptr)]
                ))
            }
            continuation.onTermination = { @Sendable [weak self] _ in
                Task { await self?.removeBrowser(id: streamID) }
            }
        }
    }

    public func resolve(_ record: ServiceRecord) async throws -> NetworkAddress {
        try await resolveService(record).address
    }

    /// Answers from the cache when it can; otherwise queries SRV and TXT for
    /// `<instance>.<type>.local`, then A/AAAA for the SRV target. If only the
    /// TXT is still missing when the timeout elapses, returns the address with
    /// empty TXT; if the address is missing, throws `resolveTimeout`.
    public func resolveService(_ record: ServiceRecord) async throws -> ResolvedService {
        try await ensureMDNSChannel()
        // For a service we're already advertising, return our own address immediately.
        if let local = advertised[record.name] {
            return ResolvedService(
                address: NetworkAddress(host: ProcessInfo.processInfo.hostName, port: local.port),
                txtRecords: local.txtRecords
            )
        }
        let instance = record.name
        let type = record.serviceType.rawValue
        cache.ingest([], now: now())
        if let resolved = cachedResolution(instance: instance, serviceType: type) {
            return resolved
        }

        let key = DNSSDCache.key(instance: instance, serviceType: type)
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                let timeout = Task { [sleep, resolveTimeout] in
                    do { try await sleep(resolveTimeout) } catch { return }
                    guard !Task.isCancelled else { return }
                    self.expireResolve(key: key, id: id)
                }
                pendingResolves[key, default: [:]][id] = ResolveWaiter(
                    instance: instance, serviceType: type, continuation: continuation, timeout: timeout
                )
                let fullName = "\(instance).\(type).local"
                var questions = [DNSQuestion(name: fullName, type: .srv), DNSQuestion(name: fullName, type: .txt)]
                if let srv = cache.srv(instance: instance, serviceType: type), cache.addresses(host: srv.target).isEmpty {
                    questions += [DNSQuestion(name: srv.target, type: .a), DNSQuestion(name: srv.target, type: .aaaa)]
                }
                Task { try? await self.send(DNSMessage(isResponse: false, questions: questions)) }
            }
        } onCancel: {
            Task { await self.cancelResolve(key: key, id: id) }
        }
    }

    // MARK: - Internal: Browse subscriptions

    /// Returns `false`, adding nothing, when the stream already terminated.
    func addBrowser(
        _ continuation: AsyncStream<ServiceRecord>.Continuation,
        id: UUID,
        serviceType: String
    ) -> Bool {
        guard removedBrowsers.remove(id) == nil else { return false }
        browsers[id] = Browser(serviceType: serviceType, continuation: continuation)
        // Instances already complete in the cache are yielded straight away.
        cache.ingest([], now: now())
        updateBrowser(id: id)
        return true
    }

    func removeBrowser(id: UUID) {
        if browsers.removeValue(forKey: id) == nil {
            removedBrowsers.insert(id)
        }
    }

    var browserCount: Int { browsers.count }

    /// Yields each instance whose TXT is known and differs from what this
    /// browser last yielded for it; forgets instances that have left the
    /// cache, so one that returns is yielded again.
    private func updateBrowser(id: UUID) {
        guard var browser = browsers[id] else { return }
        let type = browser.serviceType
        let instances = cache.instances(of: type)
        let present = Set(instances.map { DNSSDCache.key(instance: $0, serviceType: type) })
        browser.yielded = browser.yielded.filter { present.contains($0.key) }
        for instance in instances {
            guard let txt = cache.txt(instance: instance, serviceType: type) else { continue }
            let key = DNSSDCache.key(instance: instance, serviceType: type)
            guard browser.yielded[key] != txt else { continue }
            browser.yielded[key] = txt
            browser.continuation.yield(ServiceRecord(
                name: instance, serviceType: ServiceType(type), host: "", port: 0, txtRecords: txt
            ))
        }
        browsers[id] = browser
    }

    // MARK: - Internal: Resolve waiters

    private func cachedResolution(instance: String, serviceType: String) -> ResolvedService? {
        guard let address = cachedAddress(instance: instance, serviceType: serviceType),
              let txt = cache.txt(instance: instance, serviceType: serviceType)
        else { return nil }
        return ResolvedService(address: address, txtRecords: txt)
    }

    private func cachedAddress(instance: String, serviceType: String) -> NetworkAddress? {
        guard let srv = cache.srv(instance: instance, serviceType: serviceType),
              let host = cache.addresses(host: srv.target).first
        else { return nil }
        return NetworkAddress(host: host, port: srv.port)
    }

    private func removeWaiter(key: String, id: UUID) -> ResolveWaiter? {
        guard let waiter = pendingResolves[key]?.removeValue(forKey: id) else { return nil }
        if pendingResolves[key]?.isEmpty == true { pendingResolves[key] = nil }
        return waiter
    }

    /// Resumes every waiter whose instance the cache can now answer in full.
    private func fulfilResolves() {
        for (key, waiters) in pendingResolves {
            guard let waiter = waiters.values.first,
                  let resolved = cachedResolution(instance: waiter.instance, serviceType: waiter.serviceType)
            else { continue }
            pendingResolves[key] = nil
            for waiter in waiters.values {
                waiter.timeout.cancel()
                waiter.continuation.resume(returning: resolved)
            }
        }
    }

    private func expireResolve(key: String, id: UUID) {
        guard let waiter = removeWaiter(key: key, id: id) else { return }
        cache.ingest([], now: now())
        if let address = cachedAddress(instance: waiter.instance, serviceType: waiter.serviceType) {
            logger.notice("No TXT for '\(waiter.instance)' within the resolve timeout; returning its address with empty TXT")
            waiter.continuation.resume(returning: ResolvedService(address: address, txtRecords: [:]))
        } else {
            waiter.continuation.resume(throwing: LinuxServiceDiscoveryError.resolveTimeout(
                "\(waiter.instance).\(waiter.serviceType).local"
            ))
        }
    }

    private func cancelResolve(key: String, id: UUID) {
        guard let waiter = removeWaiter(key: key, id: id) else { return }
        waiter.timeout.cancel()
        waiter.continuation.resume(throwing: CancellationError())
    }

    // MARK: - Internal: mDNS channel

    private func ensureMDNSChannel() async throws {
        guard channel == nil, injectedSender == nil else { return }

        let callback: @Sendable (Data, SocketAddress) -> Void = { [weak self] data, addr in
            Task { await self?.handleIncoming(data: data, from: addr) }
        }
        let handler = MDNSChannelHandler(callback: callback)

        let ch = try await DatagramBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(handler)
                }
            }
            .bind(host: "0.0.0.0", port: 5353)
            .get()

        // Join IPv4 mDNS multicast group 224.0.0.251
        let multicastAddr = try SocketAddress(ipAddress: "224.0.0.251", port: 5353)
        try await (ch as! MulticastChannel).joinGroup(multicastAddr).get()

        self.channel = ch
        logger.debug("mDNS socket bound on port 5353")
    }

    // MARK: - Internal: Send helpers

    private func sendAnnouncement(for service: ServiceRecord, ttl: UInt32) async throws {

        let hostname = ProcessInfo.processInfo.hostName
        let instanceName = "\(service.name).\(service.serviceType.rawValue)"
        let serviceTypeDomain = "\(service.serviceType.rawValue).local"

        var msg = DNSMessage(isResponse: true, isAuthoritative: true)

        // PTR: _service._proto.local → instance._service._proto.local
        msg.answers.append(DNSRecord(
            name: serviceTypeDomain,
            type: .ptr,
            ttl: ttl,
            rdata: .ptr(domain: instanceName)
        ))

        if ttl > 0 {
            // SRV: instance → priority:0 weight:0 port:N hostname.local
            msg.answers.append(DNSRecord(
                name: instanceName,
                type: .srv,
                ttl: ttl,
                rdata: .srv(priority: 0, weight: 0, port: service.port, target: "\(hostname).local")
            ))
            // TXT: instance → key=value strings
            let txtStrings = service.txtRecords.map { "\($0.key)=\($0.value)" }
            msg.answers.append(DNSRecord(
                name: instanceName,
                type: .txt,
                ttl: ttl,
                rdata: .txt(txtStrings.isEmpty ? [""] : txtStrings)
            ))
        }

        try await send(msg)
    }

    private func send(_ message: DNSMessage) async throws {
        if let injectedSender {
            await injectedSender(message)
            return
        }
        guard let ch = channel else { return }
        try await sendToMulticast(ch: ch, message: message)
    }

    private func sendToMulticast(ch: Channel, message: DNSMessage) async throws {
        let dest = try SocketAddress(ipAddress: "224.0.0.251", port: 5353)
        let encoded = message.encode()
        var buf = ch.allocator.buffer(capacity: encoded.count)
        buf.writeBytes(encoded)
        try await ch.writeAndFlush(AddressedEnvelope(remoteAddress: dest, data: buf)).get()
    }

    // MARK: - Internal: Announce task

    private func restartAnnounceTask() {
        announceTask?.cancel()
        announceTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled else { break }
                await self?.reannounceAll()
            }
        }
    }

    private func reannounceAll() async {
        for service in advertised.values {
            try? await sendAnnouncement(for: service, ttl: 4500)
        }
    }

    // MARK: - Internal: Incoming packet handler

    func handleIncoming(data: Data, from sender: SocketAddress) async {
        guard let msg = DNSMessage.decode(from: data) else { return }
        if msg.isResponse {
            await handleResponse(msg)
        } else {
            handleQuery(msg)
        }
    }

    /// Updates the cache, browsers and waiters, then sends any follow-up
    /// queries before returning, so a caller that awaits this sees them sent.
    private func handleResponse(_ msg: DNSMessage) async {
        let records = msg.answers + msg.additionals
        let heard = now()
        cache.ingest(records, now: heard)
        for record in records where record.ttl > 0 {
            followUpBackoff["\(record.name.dnsLowercased) \(record.type.rawValue)"] = nil
        }
        let questions = followUps(after: records, now: heard)
        for id in browsers.keys { updateBrowser(id: id) }
        fulfilResolves()
        guard !questions.isEmpty else { return }
        try? await send(DNSMessage(isResponse: false, questions: questions))
    }

    /// Queries what a browse or a pending resolve still lacks, driven by the
    /// records just heard: a browsed type's PTR → SRV and TXT for the
    /// instance; an interesting instance's SRV → A/AAAA for its target.
    ///
    /// A question still unanswered is not asked again until its interval has
    /// passed: 1 s after the first ask, doubling with each repeat up to an
    /// hour (RFC 6762 §5.2). Hearing an answer resets it. A pending resolve's
    /// address question is the exception: it is asked whatever the backoff
    /// (counting as a repeat), because a resolve waits on it with a bounded
    /// timeout, and an earlier browse's unanswered ask would otherwise
    /// silence it — once the interval has doubled a few times, for longer
    /// than the resolve waits.
    private func followUps(after records: [DNSRecord], now: ContinuousClock.Instant) -> [DNSQuestion] {
        var questions: [DNSQuestion] = []
        func ask(_ name: String, _ type: DNSRecordType, bypassingBackoff: Bool = false) {
            let key = "\(name.dnsLowercased) \(type.rawValue)"
            let previous = followUpBackoff[key]
            if !bypassingBackoff, let previous, now - previous.asked < previous.interval { return }
            // A bypassing ask is not limited by the backoff: once per packet.
            guard !questions.contains(where: { "\($0.name.dnsLowercased) \($0.type.rawValue)" == key }) else { return }
            let interval = previous.map { min($0.interval * 2, .seconds(3600)) } ?? .seconds(1)
            followUpBackoff[key] = (now, interval)
            questions.append(DNSQuestion(name: name, type: type))
        }
        let browsedTypes = Set(browsers.values.map(\.serviceType))

        for record in records where record.ttl > 0 {
            switch record.rdata {
            case .ptr(let domain):
                let owner = record.name.dnsLowercased
                for type in browsedTypes where owner == "\(type).local".dnsLowercased {
                    guard let instance = DNSSDCache.instanceName(fullName: domain, serviceType: type) else { continue }
                    if cache.srv(instance: instance, serviceType: type) == nil { ask(domain, .srv) }
                    if cache.txt(instance: instance, serviceType: type) == nil { ask(domain, .txt) }
                }
            case .srv(_, _, _, let target):
                let isPending = pendingResolves[record.name.dnsLowercased] != nil
                let isBrowsed = browsedTypes.contains {
                    DNSSDCache.instanceName(fullName: record.name, serviceType: $0) != nil
                }
                guard isPending || isBrowsed, cache.addresses(host: target).isEmpty else { continue }
                ask(target, .a, bypassingBackoff: isPending)
                ask(target, .aaaa, bypassingBackoff: isPending)
            default:
                continue
            }
        }
        return questions
    }

    /// Extracts `(recordName, host)` pairs from A/AAAA records in resolve
    /// order — **every A match before any AAAA match**, regardless of the
    /// order records happened to appear in the packet. `DNSSDCache.addresses`
    /// formats a host's cached records through this, and a resolve takes the
    /// first address, so this library's IPv4 preference holds (see
    /// `MDNSApple`'s equivalent preference in `AppleServiceDiscovery.resolve`).
    /// Because the cache holds a host's records across packets, an A record
    /// heard after an AAAA record still sorts first.
    ///
    /// An AAAA record's 16 raw bytes are formatted as a bracketed IPv6
    /// literal (`"[fe80:0:0:0:1234:5678:9abc:def0]"`) — RFC 3986 requires
    /// the brackets; a bare colon-separated literal is not a valid URL host
    /// and previously broke `URLComponents`-based transports downstream
    /// (see the sibling fix in `MDNSApple`'s `NetworkAddress(endpoint:)`).
    /// No zero-run compression (`::`) — verbose but unambiguous, and this
    /// hand-rolled parser has no need to match `nw_path`/`getnameinfo`'s
    /// exact canonical form.
    ///
    /// Rdata decoded off the wire is a `Data` slice of the whole message,
    /// whose indices do not start at 0, so the bytes are copied to an array
    /// before indexing.
    ///
    /// Pure and side-effect-free — the actual regression coverage for both
    /// fixes lives here, unit-testable with no live socket involved.
    static func resolvableHosts(from records: [DNSRecord]) -> [(recordName: String, host: String)] {
        var results: [(recordName: String, host: String)] = []
        for record in records {
            guard case .a(let data) = record.rdata, data.count == 4 else { continue }
            let bytes = Array(data)
            results.append((record.name, "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])"))
        }
        for record in records {
            guard case .aaaa(let data) = record.rdata, data.count == 16 else { continue }
            let bytes = Array(data)
            let groups = stride(from: 0, to: 16, by: 2).map { i in
                String(format: "%x", UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]))
            }
            results.append((record.name, "[\(groups.joined(separator: ":"))]"))
        }
        return results
    }

    private func handleQuery(_ msg: DNSMessage) {
        for question in msg.questions {
            guard question.type == .ptr || question.type == .any else { continue }
            let queryServiceType = question.name.replacingOccurrences(of: ".local", with: "")
            for service in advertised.values where service.serviceType.rawValue == queryServiceType {
                Task { try? await sendAnnouncement(for: service, ttl: 4500) }
            }
        }
    }
}

// MARK: - MDNSChannelHandler

private final class MDNSChannelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    private let callback: @Sendable (Data, SocketAddress) -> Void

    init(callback: @escaping @Sendable (Data, SocketAddress) -> Void) {
        self.callback = callback
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var envelope = Self.unwrapInboundIn(data)
        let bytes = envelope.data.readBytes(length: envelope.data.readableBytes) ?? []
        callback(Data(bytes), envelope.remoteAddress)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}

// MARK: - Errors

public enum LinuxServiceDiscoveryError: Error, Sendable {
    case resolveTimeout(String)
    case channelSetupFailed
}
