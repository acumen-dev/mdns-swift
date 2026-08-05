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
/// (`224.0.0.251`). Handles PTR/SRV/TXT advertisement and PTR browsing without
/// any external dependency beyond SwiftNIO.
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
    /// Keyed by service type string → (UUID → continuation), to allow
    /// precise removal on stream termination without requiring class identity.
    private var browseStreams: [String: [UUID: AsyncStream<ServiceRecord>.Continuation]] = [:]
    private var pendingResolves: [String: CheckedContinuation<NetworkAddress, Error>] = [:]
    private var channel: Channel?
    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let logger: Logger
    private var announceTask: Task<Void, Never>?

    // MARK: - Init

    public init(logger: Logger = Logger(label: "mdns.linux.discovery")) {
        self.logger = logger
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
        let key = serviceType.rawValue
        let streamID = UUID()
        return AsyncStream { [weak self] continuation in
            Task { [weak self] in
                await self?.addBrowseContinuation(continuation, id: streamID, key: key)
                try? await self?.ensureMDNSChannel()
                try? await self?.sendPTRQuery(serviceType: key)
            }
            continuation.onTermination = { @Sendable [weak self] _ in
                Task { await self?.removeBrowseContinuation(id: streamID, key: key) }
            }
        }
    }

    public func resolve(_ record: ServiceRecord) async throws -> NetworkAddress {
        try await ensureMDNSChannel()
        // For a service we're already advertising, return our own address immediately.
        if let local = advertised[record.name] {
            return NetworkAddress(host: ProcessInfo.processInfo.hostName, port: local.port)
        }
        let hostname = record.host.isEmpty ? "\(record.name).local" : record.host
        return try await withCheckedThrowingContinuation { cont in
            pendingResolves[hostname] = cont
            Task {
                try? await self.sendAQuery(hostname: hostname)
                try? await Task.sleep(for: .seconds(5))
                self.timeoutResolve(hostname: hostname)
            }
        }
    }

    // MARK: - Internal: Browse continuation management

    private func addBrowseContinuation(
        _ cont: AsyncStream<ServiceRecord>.Continuation,
        id: UUID,
        key: String
    ) {
        browseStreams[key, default: [:]][id] = cont
    }

    private func removeBrowseContinuation(id: UUID, key: String) {
        browseStreams[key]?.removeValue(forKey: id)
    }

    private func timeoutResolve(hostname: String) {
        guard let cont = pendingResolves.removeValue(forKey: hostname) else { return }
        cont.resume(throwing: LinuxServiceDiscoveryError.resolveTimeout(hostname))
    }

    // MARK: - Internal: mDNS channel

    private func ensureMDNSChannel() async throws {
        guard channel == nil else { return }

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
        guard let ch = channel else { return }

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

        try await sendToMulticast(ch: ch, message: msg)
    }

    private func sendPTRQuery(serviceType: String) async throws {
        guard let ch = channel else { return }
        var msg = DNSMessage(isResponse: false)
        msg.questions.append(DNSQuestion(name: "\(serviceType).local", type: .ptr))
        try await sendToMulticast(ch: ch, message: msg)
    }

    private func sendAQuery(hostname: String) async throws {
        guard let ch = channel else { return }
        var msg = DNSMessage(isResponse: false)
        msg.questions.append(DNSQuestion(name: hostname, type: .a))
        msg.questions.append(DNSQuestion(name: hostname, type: .aaaa))
        try await sendToMulticast(ch: ch, message: msg)
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

    func handleIncoming(data: Data, from sender: SocketAddress) {
        guard let msg = DNSMessage.decode(from: data) else { return }
        if msg.isResponse {
            handleResponse(msg)
        } else {
            handleQuery(msg)
        }
    }

    private func handleResponse(_ msg: DNSMessage) {
        let records = msg.answers + msg.additionals

        for record in records {
            guard case .ptr(let domain) = record.rdata else { continue }
            let parts = record.name.split(separator: ".")
            guard parts.count >= 3 else { continue }
            // record.name is e.g. "_hap._tcp.local" — strip ".local" for lookup key
            let serviceTypeKey = parts.dropLast().joined(separator: ".")
            guard let conts = browseStreams[serviceTypeKey], !conts.isEmpty else { continue }
            // domain is "InstanceName._hap._tcp.local"
            let domainParts = domain.split(separator: ".")
            let instanceName = domainParts.first.map(String.init) ?? domain
            let serviceTypeParts = domainParts.dropFirst().dropLast().joined(separator: ".")
            let discovered = ServiceRecord(
                name: instanceName, serviceType: ServiceType(serviceTypeParts),
                host: "", port: 0, txtRecords: [:]
            )
            for cont in conts.values { cont.yield(discovered) }
        }

        for (recordName, host) in Self.resolvableHosts(from: records) {
            fulfillResolve(recordName: recordName, host: host)
        }
    }

    /// Extracts `(recordName, host)` pairs from A/AAAA records in resolve
    /// order — **every A match before any AAAA match**, regardless of the
    /// order records happened to appear in the packet. `fulfillResolve`
    /// resolves and discards the pending continuation on its first call for
    /// a given name, so whichever pair is considered first always wins;
    /// without this ordering, an AAAA record placed earlier in the same
    /// response would win over an A record placed later, even though this
    /// library otherwise prefers IPv4 throughout (see `MDNSApple`'s
    /// equivalent preference in `AppleServiceDiscovery.resolve`). This only
    /// resolves the single-packet case — an AAAA-only packet arriving
    /// before a separate, later A-only packet for the same name is a
    /// cross-packet race this cannot fix without buffering, which isn't
    /// implemented here.
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
    /// Pure and side-effect-free — the actual regression coverage for both
    /// fixes lives here, unit-testable with no live socket involved.
    static func resolvableHosts(from records: [DNSRecord]) -> [(recordName: String, host: String)] {
        var results: [(recordName: String, host: String)] = []
        for record in records {
            guard case .a(let bytes) = record.rdata, bytes.count == 4 else { continue }
            results.append((record.name, "\(bytes[0]).\(bytes[1]).\(bytes[2]).\(bytes[3])"))
        }
        for record in records {
            guard case .aaaa(let bytes) = record.rdata, bytes.count == 16 else { continue }
            let groups = stride(from: 0, to: 16, by: 2).map { i in
                String(format: "%x", UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]))
            }
            results.append((record.name, "[\(groups.joined(separator: ":"))]"))
        }
        return results
    }

    private func fulfillResolve(recordName: String, host: String) {
        let bare = recordName.replacingOccurrences(of: ".local", with: "")
        for key in pendingResolves.keys where key.hasPrefix(bare) || bare.hasPrefix(key) {
            if let cont = pendingResolves.removeValue(forKey: key) {
                cont.resume(returning: NetworkAddress(host: host, port: 0))
            }
        }
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
