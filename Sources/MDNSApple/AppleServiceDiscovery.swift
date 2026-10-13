// AppleServiceDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import Network
import dnssd
import Darwin
import MDNSCore
import Logging

/// Apple platform mDNS/DNS-SD service discovery using Network.framework (browsing/resolving)
/// and the C-level `DNSServiceRegister` API (advertising).
///
/// **Advertising** uses `DNSServiceRegister` from the `dnssd` framework, which
/// natively supports comma-separated subtypes in the `regtype` parameter:
/// `"_matterc._udp,_CM,_L3840,_S15"`. This is required for filtered browsing —
/// `NetService` with the same comma format does NOT register subtypes, it only
/// advertises the primary type.
///
/// **Browsing** and **resolving** use `NWBrowser` and `NWConnection` from
/// Network.framework, which are better suited for asynchronous discovery.
///
/// ```swift
/// let discovery = AppleServiceDiscovery()
///
/// // Advertise a service
/// try await discovery.advertise(service: ServiceRecord(
///     name: "My Device",
///     serviceType: "_hap._tcp",
///     host: "",
///     port: 51826,
///     txtRecords: ["id": "AA:BB:CC:DD:EE:FF", "c#": "1"],
///     subtypes: []
/// ))
///
/// // Browse for services
/// for await record in discovery.browse(serviceType: "_hap._tcp") {
///     let address = try await discovery.resolve(record)
///     print("Found \(record.name) at \(address)")
/// }
/// ```
public final class AppleServiceDiscovery: ServiceDiscovery, @unchecked Sendable {

    // MARK: - Thread Safety
    //
    // `advertisedRefs` and `browsers` are guarded by `lock`.
    // Rules:
    //   • Always acquire `lock` before reading or writing either collection.
    //   • Never hold `lock` across an `await` or a callback.

    private let lock = NSLock()

    // MARK: - State

    /// Active advertisement `DNSServiceRef`s keyed by service name.
    /// Each ref keeps the DNS-SD SRV/TXT records (and subtypes) alive with
    /// mDNSResponder until `DNSServiceRefDeallocate` is called.
    private var advertisedRefs: [String: DNSServiceRef] = [:]
    /// Connection ref that owns all `bridge.local.` AAAA records.
    /// Created when the first operational advertisement is registered.
    /// One `DNSServiceRefDeallocate` removes all records registered on this connection.
    private var bridgeAddressRef: DNSServiceRef?
    /// Custom hostname used as the SRV target for operational advertisements.
    /// We register link-local IPv6 AAAA records for this hostname on EVERY LAN
    /// interface (each with its specific ifIndex).
    private let bridgeHostname = "matter-bridge.local."
    private var browsers: [NWBrowser] = []
    private let queue = DispatchQueue(label: "mdns.discovery", qos: .userInitiated)
    private let logger: Logger

    // MARK: - Locking Helpers

    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    // MARK: - Init

    public init(logger: Logger = Logger(label: "mdns.apple.discovery")) {
        self.logger = logger
    }

    // MARK: - TXT Encoding

    /// Encode TXT key/value pairs into RFC 6763 wire format: each entry is a
    /// length byte followed by the UTF-8 bytes of `"key=value"`.
    ///
    /// Hand-rolled because `NetService.data(fromTXTRecord:)` is unavailable on
    /// watchOS (and deprecated everywhere else). Keys are sorted so the output
    /// is deterministic; entries longer than 255 bytes are truncated, matching
    /// the Linux responder's TXT encoding. An empty dictionary yields empty
    /// `Data`, which `DNSServiceRegister` accepts as "no TXT record".
    static func txtRecordData(_ records: [String: String]) -> Data {
        var out = Data()
        for (key, value) in records.sorted(by: { $0.key < $1.key }) {
            let bytes = Array("\(key)=\(value)".utf8)
            out.append(UInt8(min(bytes.count, 255)))
            out.append(contentsOf: bytes.prefix(255))
        }
        return out
    }

    // MARK: - ServiceDiscovery

    public func advertise(service: ServiceRecord) async throws {
        // Cancel any existing advertisement for this name (under lock).
        let existing = withLock { () -> DNSServiceRef? in
            let ref = advertisedRefs[service.name]
            advertisedRefs.removeValue(forKey: service.name)
            return ref
        }
        if let ref = existing {
            DNSServiceRefDeallocate(ref)
        }

        // Build the TXT record payload in RFC 6763 wire format.
        let txtData = Self.txtRecordData(service.txtRecords)

        // Build the regtype string.
        // DNSServiceRegister natively supports comma-separated subtypes:
        //   "_matterc._udp,_CM,_L3840,_S15"
        // Each comma-separated token after the primary type is registered as a
        // DNS-SD subtype (_CM._sub._matterc._udp, _L3840._sub._matterc._udp, etc.).
        let typeString: String
        if service.subtypes.isEmpty {
            typeString = service.serviceType.rawValue
        } else {
            typeString = service.serviceType.rawValue + "," + service.subtypes.joined(separator: ",")
        }

        // Port must be in network byte order for DNSServiceRegister.
        let portBig = CFSwapInt16HostToBig(service.port)

        // Restrict advertisement to the primary LAN interface.
        // Both commissionable and operational use the system hostname (hostParam=nil)
        // so that mDNSResponder resolves SRV targets using the Mac's own Bonjour
        // records (e.g. my-mac.local. → fe80:: + IPv4).  CHIP's address scorer picks
        // link-local IPv6 first, so CASE connects on the same address as PASE even
        // when VPN/Tailscale addresses are also present in the hostname's record set.
        //
        // A custom hostname (matter-bridge.local.) was tried but caused CASE to fail:
        // homed's DNSServiceGetAddrInfo for the custom hostname returned no result,
        // preventing operational discovery from completing.
        let lan = primaryLANInterface()
        let ifIndex = lan?.index ?? 0

        // Both commissionable and operational use the system hostname (nil = default).
        let hostParam: String? = nil

        // Callers that need to be reachable from any interface (e.g. HAP accessories
        // discoverable on both Ethernet and Wi-Fi) set `advertiseOnAllInterfaces = true`,
        // which passes ifIndex=0 to DNSServiceRegister.  The default restricts to the
        // primary LAN interface to prevent VPN/Tailscale addresses from interfering with
        // protocols like Matter that rely on specific link addresses for session establishment.
        let serviceIfIndex: UInt32 = service.advertiseOnAllInterfaces ? 0 : ifIndex

        if service.advertiseOnAllInterfaces {
            logger.debug("mDNS advertising '\(service.name)' on all interfaces")
        } else if let lan {
            logger.debug("mDNS advertising '\(service.name)' restricted to \(lan.name) (ifIndex=\(lan.index), \(lan.ipv4))")
        }
        if service.serviceType.rawValue == "_matter._tcp" {
            logNetworkInterfaces()
        }

        var sdRef: DNSServiceRef?
        let err: DNSServiceErrorType = txtData.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            DNSServiceRegister(
                &sdRef,
                0,              // flags
                serviceIfIndex,
                service.name,
                typeString,
                "local.",
                hostParam,      // nil = system hostname (e.g. my-mac.local.)
                portBig,
                UInt16(txtData.count),
                ptr.baseAddress,
                nil,            // callback
                nil             // context
            )
        }

        guard err == kDNSServiceErr_NoError, let ref = sdRef else {
            throw ServiceDiscoveryError.registrationFailed(code: Int(err))
        }

        // Schedule the ref so mDNSResponder keeps the SRV/TXT records alive.
        // Without this, mDNSResponder's keepalive timer fires (~30–60 s after
        // registration) and evicts the record — causing homed's operational
        // discovery to time out during CASE session establishment.
        DNSServiceSetDispatchQueue(ref, queue)

        withLock { advertisedRefs[service.name] = ref }

        let subtypeDesc = service.subtypes.isEmpty ? "" : " subtypes=[\(service.subtypes.joined(separator: ","))]"
        let ifDesc = serviceIfIndex == 0 ? "all interfaces" : (lan.map { "\($0.name) (ifIndex=\($0.index))" } ?? "ifIndex=\(serviceIfIndex)")
        logger.info("Advertising '\(service.name)' as \(service.serviceType.rawValue)\(subtypeDesc) on port \(service.port) [\(ifDesc)]")
    }

    public func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord> {
        // `bonjourWithTXTRecord` so each result's metadata carries the
        // instance's TXT; plain `.bonjour` reports names with empty metadata.
        // Every change re-walks all results, so an instance whose TXT changes
        // is yielded again with the new TXT.
        let descriptor = NWBrowser.Descriptor.bonjourWithTXTRecord(type: serviceType.rawValue, domain: "local.")
        let browser = NWBrowser(for: descriptor, using: .udp)

        return AsyncStream { continuation in
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                guard let self else { return }
                for result in results {
                    if let record = self.serviceRecord(from: result, serviceType: serviceType) {
                        continuation.yield(record)
                    }
                }
            }

            browser.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .failed(let error):
                    self.logger.error("Browse failed: \(error)")
                    continuation.finish()
                case .cancelled:
                    continuation.finish()
                default:
                    break
                }
            }

            continuation.onTermination = { @Sendable [weak self] _ in
                browser.cancel()
                self?.withLock { self?.browsers.removeAll { $0 === browser } }
            }

            browser.start(queue: self.queue)
            withLock { browsers.append(browser) }
        }
    }

    /// How long an IPv4-constrained resolve attempt gets before falling back
    /// to an unconstrained one. Needed because an `NWConnection` with no
    /// viable path for its constraint (e.g. an IPv4-only connection to a
    /// device with no IPv4 address) commonly parks in `.waiting` rather than
    /// transitioning to `.failed` — without a deadline, ``resolve(_:)``
    /// would simply hang for an IPv6-only device instead of falling back.
    static let ipv4PreferenceTimeout: Duration = .seconds(2)

    /// Resolves an instance to an address. Honours task cancellation: a
    /// cancelled resolve throws `CancellationError` promptly.
    public func resolve(_ record: ServiceRecord) async throws -> NetworkAddress {
        let endpoint = NWEndpoint.service(
            name: record.name,
            type: record.serviceType.rawValue,
            domain: "local.",
            interface: nil
        )

        // Prefer IPv4: most LAN smart-home devices this library targets
        // (Shelly, Hue, Matter accessories) are IPv4-first in practice, and
        // an unscoped IPv6 candidate isn't guaranteed to exist or work end
        // to end even when mDNS opportunistically announces one. If no
        // IPv4-constrained attempt succeeds in time, fall through to an
        // unconstrained attempt — whatever `currentPath.remoteEndpoint`
        // resolves to. Either attempt can still yield a scoped address. A
        // scoped routable IPv4 address comes back as its literal; a scoped
        // IPv6 or IPv4 link-local one needs its scope, so see `resolveOnce`'s
        // `fallbackHostname` use for why that's not a failure.
        let ipv4Parameters = NWParameters.udp
        if let ipOptions = ipv4Parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ipOptions.version = .v4
        }
        if let address = try? await resolveOnce(
            endpoint: endpoint,
            parameters: ipv4Parameters,
            recordName: record.name,
            timeout: Self.ipv4PreferenceTimeout
        ) {
            return address
        }
        try Task.checkCancellation()

        return try await resolveOnce(endpoint: endpoint, parameters: .udp, recordName: record.name, timeout: nil)
    }

    /// One resolve attempt over one `NWConnection`, optionally bounded by
    /// `timeout` (used only for the IPv4-preference attempt — an
    /// unconstrained fallback attempt has nothing further to fall back to,
    /// so it runs until `NWConnection` itself reports `.ready`/`.failed`, or
    /// the calling task is cancelled, which throws `CancellationError`).
    private func resolveOnce(
        endpoint: NWEndpoint,
        parameters: NWParameters,
        recordName: String,
        timeout: Duration?
    ) async throws -> NetworkAddress {
        let connection = NWConnection(to: endpoint, using: parameters)
        defer { connection.stateUpdateHandler = nil }

        return try await withThrowingTaskGroup(of: NetworkAddress.self) { group in
            group.addTask {
                let outcome = ResolveOutcome()
                // `onCancel` resumes the continuation itself rather than
                // waiting for the connection's `.cancelled` state: a
                // connection cancelled racing with `start` need
                // not report any state. `ResolveOutcome` resumes at most once.
                return try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { [weak self, weak connection] (cont: CheckedContinuation<NetworkAddress, Error>) in
                        outcome.install(cont)
                        guard let self, let connection else {
                            outcome.finish(.failure(CancellationError()))
                            return
                        }
                        // `connection` is captured weakly: the handler would otherwise
                        // form a cycle that only a delivered `.cancelled` breaks, and a
                        // cancel racing `start` may never deliver one.
                        connection.stateUpdateHandler = { [weak self, weak connection] state in
                            guard let self, let connection else { return }
                            switch state {
                            case .ready:
                                // A `fallbackHostname` matters even here, not
                                // just in the caller's own resolve-failure
                                // fallback, for a scoped IPv6 or IPv4
                                // link-local host (a scoped routable IPv4
                                // host is kept as its literal): it still carries a
                                // correctly-resolved port from this same SRV
                                // lookup, which mDNS *browsing* alone never
                                // provides (`ServiceRecord.port` is `0` until
                                // something resolves it) — losing that port by
                                // treating a scoped host as a hard failure would
                                // just move the same "not a valid URL" problem
                                // from a bad host to a bad (`0`) port.
                                if let remoteEndpoint = connection.currentPath?.remoteEndpoint,
                                   let address = NetworkAddress(
                                       endpoint: remoteEndpoint,
                                       fallbackHostname: "\(recordName).local"
                                   ) {
                                    outcome.finish(.success(address))
                                } else {
                                    outcome.finish(.failure(ServiceDiscoveryError.resolveFailed(recordName)))
                                }
                                connection.cancel()
                            case .failed(let error):
                                self.logger.error("Resolve failed for '\(recordName)': \(error)")
                                outcome.finish(.failure(error))
                                connection.cancel()
                            case .cancelled:
                                outcome.finish(.failure(CancellationError()))
                            default:
                                break
                            }
                        }
                        connection.start(queue: self.queue)
                    }
                } onCancel: {
                    outcome.cancel()
                    connection.cancel()
                }
            }
            if let timeout {
                group.addTask {
                    // Cancelled sleep must still cancel the connection.
                    defer { connection.cancel() }
                    try await Task.sleep(for: timeout)
                    throw ServiceDiscoveryError.resolveFailed(recordName)
                }
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    /// Resolves an instance to its address (via ``resolve(_:)``) and TXT.
    ///
    /// The TXT comes from `record` when it carries one — a browse result
    /// does. Otherwise it is looked up with `DNSServiceResolve`, bounded by
    /// ``txtResolveTimeout``. If that lookup gets no answer, the result
    /// carries the address with empty TXT; only an address failure throws.
    public func resolveService(_ record: ServiceRecord) async throws -> ResolvedService {
        try await resolveService(record) { [self] record in
            try await resolveTXT(record, timeout: Self.txtResolveTimeout)
        }
    }

    /// ``resolveService(_:)`` with the TXT lookup injected, so the
    /// "address resolved, TXT did not" outcome is testable deterministically.
    func resolveService(
        _ record: ServiceRecord,
        lookUpTXT: @Sendable (ServiceRecord) async throws -> [String: String]
    ) async throws -> ResolvedService {
        let address = try await resolve(record)
        if !record.txtRecords.isEmpty {
            return ResolvedService(address: address, txtRecords: record.txtRecords)
        }
        do {
            return ResolvedService(address: address, txtRecords: try await lookUpTXT(record))
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            logger.notice("TXT for '\(record.name)' could not be obtained (\(error)); returning address with empty TXT")
            return ResolvedService(address: address, txtRecords: [:])
        }
    }

    /// How long the `DNSServiceResolve` TXT lookup in ``resolveService(_:)``
    /// gets. The same bound the address resolve puts on its first attempt
    /// (``ipv4PreferenceTimeout``).
    static let txtResolveTimeout: Duration = ipv4PreferenceTimeout

    /// Look up an instance's TXT record with `DNSServiceResolve`, throwing
    /// ``ServiceDiscoveryError/resolveFailed(_:)`` if no answer arrives
    /// within `timeout`.
    func resolveTXT(_ record: ServiceRecord, timeout: Duration) async throws -> [String: String] {
        let name = record.name
        let lookup = TXTLookup(name: name, type: record.serviceType.rawValue, queue: queue)
        return try await withThrowingTaskGroup(of: [String: String].self) { group in
            group.addTask { try await lookup.run() }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw ServiceDiscoveryError.resolveFailed(name)
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    public func stopAdvertising() async {
        let (toStop, addrRef) = withLock { () -> ([DNSServiceRef], DNSServiceRef?) in
            let all = Array(advertisedRefs.values)
            advertisedRefs.removeAll()
            let addr = bridgeAddressRef
            bridgeAddressRef = nil
            return (all, addr)
        }
        for ref in toStop {
            DNSServiceRefDeallocate(ref)
        }
        if let addrRef {
            DNSServiceRefDeallocate(addrRef)
        }
    }

    public func stopAdvertising(name: String) async {
        let ref = withLock { () -> DNSServiceRef? in
            let r = advertisedRefs[name]
            advertisedRefs.removeValue(forKey: name)
            return r
        }
        if let ref {
            DNSServiceRefDeallocate(ref)
        }
    }

    // MARK: - Private

    /// Find the interface index for the primary local-area-network interface.
    ///
    /// Returns the index of the first `en*` interface (sorted by index, lowest first) that is:
    /// - UP and RUNNING
    /// - Not a loopback or point-to-point (VPN/PPP) interface
    /// - Has an assigned IPv4 address
    ///
    /// This covers Wi-Fi (`en0` on most Macs) and wired Ethernet (`en1`, `en2`, …).
    /// VPN tunnels (`utun*`), bridges (`bridge*`), and other virtual interfaces are
    /// excluded.  Restricting `DNSServiceRegister` to this interface ensures the client
    /// resolves the SRV record to the LAN IP, not a VPN or global-IPv6 address.
    ///
    /// Returns `0` (all interfaces) if no suitable interface is found.
    private struct LANInterface {
        let index: UInt32
        let name: String
        let ipv4: String
    }

    /// Find the primary LAN interface (lowest-indexed `en*` with an IPv4 address).
    private func primaryLANInterface() -> LANInterface? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let head = ifaddr else { return nil }
        defer { freeifaddrs(head) }

        var best: (idx: UInt32, name: String, ip: String)? = nil

        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }

            guard let addr = ifa.pointee.ifa_addr else { continue }
            guard addr.pointee.sa_family == UInt8(AF_INET) else { continue }

            let flags = ifa.pointee.ifa_flags
            guard (flags & UInt32(IFF_UP))         != 0,
                  (flags & UInt32(IFF_RUNNING))     != 0,
                  (flags & UInt32(IFF_LOOPBACK))    == 0,
                  (flags & UInt32(IFF_POINTOPOINT)) == 0 else { continue }

            let name = String(cString: ifa.pointee.ifa_name)
            guard name.hasPrefix("en") else { continue }

            let idx = if_nametoindex(ifa.pointee.ifa_name)
            guard idx != 0 else { continue }
            if let b = best, idx >= b.idx { continue }

            // Extract dotted-decimal IPv4
            var sinCopy = UnsafeRawPointer(addr).load(as: sockaddr_in.self)
            var ipBuf   = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            Darwin.inet_ntop(AF_INET, &sinCopy.sin_addr, &ipBuf, socklen_t(INET_ADDRSTRLEN))
            let ip = String(decoding: ipBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)

            best = (UInt32(idx), name, ip)
        }

        guard let b = best else { return nil }
        return LANInterface(index: b.idx, name: b.name, ipv4: b.ip)
    }

    /// Backwards-compat shim used by advertise().
    private func primaryLANInterfaceIndex() -> UInt32 {
        primaryLANInterface()?.index ?? 0
    }

    // MARK: - Address Record Helpers

    /// No-op callback required by `DNSServiceRegisterRecord` — a NULL callback pointer
    /// causes `kDNSServiceErr_BadParam`.  We don't need conflict notifications.
    private static let addressRecordCallback: DNSServiceRegisterRecordReply = { _, _, _, _, _ in }

    /// Register a link-local AAAA record for `hostname` on the interface identified by
    /// `ifIndex`, using a connection-based `DNSServiceRef` so a single dealloc removes it.
    ///
    /// **Why AAAA-only and why a specific interface index?**
    /// mDNSResponder can serve link-local (`fe80::`) AAAA records registered on a
    /// specific interface — it will NOT serve them when registered globally
    /// (`interfaceIndex=0`).  By registering only AAAA (no A record), the client's address
    /// scorer has no IPv4 candidate to prefer, so it uses the link-local IPv6 directly.
    ///
    /// - Returns: The owning `DNSServiceRef`, or `nil` on failure.
    private func registerAddressRecord(hostname: String, ifIndex: UInt32) -> DNSServiceRef? {
        guard let addr6 = getLinkLocalIPv6(ifIndex: ifIndex) else {
            logger.warning("No link-local IPv6 on ifIndex=\(ifIndex) — cannot register AAAA for \(hostname)")
            return nil
        }

        var connRef: DNSServiceRef?
        let connErr = DNSServiceCreateConnection(&connRef)
        guard connErr == kDNSServiceErr_NoError, let conn = connRef else {
            logger.error("DNSServiceCreateConnection failed: \(connErr)")
            return nil
        }
        // Schedule the connection so mDNSResponder keeps it alive.
        // Without this, mDNSResponder's keepalive timer fires (typically after
        // 30–60 s) and evicts all records registered on this connection.
        DNSServiceSetDispatchQueue(conn, queue)

        var recordRef: DNSRecordRef?
        let err: DNSServiceErrorType = withUnsafeBytes(of: addr6) { ptr in
            DNSServiceRegisterRecord(
                conn,
                &recordRef,
                DNSServiceFlags(kDNSServiceFlagsShared), // no probing delay
                ifIndex,                                 // specific interface — required for link-local
                hostname,
                UInt16(kDNSServiceType_AAAA),
                UInt16(kDNSServiceClass_IN),
                UInt16(MemoryLayout<in6_addr>.size),
                ptr.baseAddress,
                0,
                Self.addressRecordCallback,
                nil
            )
        }

        guard err == kDNSServiceErr_NoError else {
            logger.error("DNSServiceRegisterRecord AAAA failed: \(err) for \(hostname) on ifIndex=\(ifIndex)")
            DNSServiceRefDeallocate(conn)
            return nil
        }

        var ipBuf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var addrCopy = addr6
        Darwin.inet_ntop(AF_INET6, &addrCopy, &ipBuf, socklen_t(INET6_ADDRSTRLEN))
        let ipStr = String(decoding: ipBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
        var ifNameBuf = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
        Darwin.if_indextoname(ifIndex, &ifNameBuf)
        let ifName = String(decoding: ifNameBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
        logger.info("Registered \(hostname) AAAA → \(ipStr) on \(ifName) (ifIndex=\(ifIndex))")

        return conn
    }

    /// Return the interface index for a named interface, or `nil` if unknown.
    private func lookupIfIndex(forName name: String) -> UInt32? {
        let idx = Darwin.if_nametoindex(name)
        return idx != 0 ? UInt32(idx) : nil
    }

    // MARK: - Multi-Interface AAAA Registration

    /// Enumerate all active `en*` interfaces that are UP, RUNNING, non-loopback,
    /// non-point-to-point, and have a link-local IPv6 address.
    ///
    /// On a dual-homed Mac this typically returns both `en0` (Ethernet) and `en1`
    /// (Wi-Fi).  Registering a hostname AAAA on each interface separately
    /// means a query arriving on any interface gets answered locally.
    private func allActiveLANInterfaces() -> [(name: String, index: UInt32, linkLocalIPv6: in6_addr)] {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let head = ifaddr else { return [] }
        defer { freeifaddrs(head) }

        var results: [(name: String, index: UInt32, linkLocalIPv6: in6_addr)] = []
        var seen: Set<UInt32> = []

        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }

            guard let addr = ifa.pointee.ifa_addr else { continue }
            guard addr.pointee.sa_family == UInt8(AF_INET6) else { continue }

            let flags = ifa.pointee.ifa_flags
            guard (flags & UInt32(IFF_UP))         != 0,
                  (flags & UInt32(IFF_RUNNING))     != 0,
                  (flags & UInt32(IFF_LOOPBACK))    == 0,
                  (flags & UInt32(IFF_POINTOPOINT)) == 0 else { continue }

            let name = String(cString: ifa.pointee.ifa_name)
            guard name.hasPrefix("en") else { continue }

            let idx = UInt32(if_nametoindex(ifa.pointee.ifa_name))
            guard idx != 0, !seen.contains(idx) else { continue }

            let sin6 = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            let ipv6 = sin6.sin6_addr
            let b0 = ipv6.__u6_addr.__u6_addr8.0
            let b1 = ipv6.__u6_addr.__u6_addr8.1
            guard b0 == 0xFE && (b1 & 0xC0) == 0x80 else { continue } // fe80::/10 only

            seen.insert(idx)
            results.append((name: name, index: idx, linkLocalIPv6: ipv6))
        }

        return results.sorted { $0.index < $1.index }
    }

    /// Register `hostname` A + AAAA on **every** active LAN interface.
    ///
    /// - **A record** (IPv4): registered on all interfaces (`ifIndex=0`) using the
    ///   primary LAN interface's IPv4 address.
    /// - **AAAA records** (link-local IPv6): registered per-interface using each
    ///   interface's own `fe80::` address and its specific `ifIndex`.
    ///
    /// All records share one connection-based `DNSServiceRef` so a single
    /// `DNSServiceRefDeallocate` removes all of them.
    ///
    /// Returns the owning connection ref, or `nil` if every registration fails.
    private func registerAddressRecords(hostname: String) -> DNSServiceRef? {
        let interfaces = allActiveLANInterfaces()
        guard !interfaces.isEmpty else {
            logger.warning("No active LAN interfaces with link-local IPv6 found — cannot register address records for \(hostname)")
            return nil
        }

        var connRef: DNSServiceRef?
        let connErr = DNSServiceCreateConnection(&connRef)
        guard connErr == kDNSServiceErr_NoError, let conn = connRef else {
            logger.error("DNSServiceCreateConnection failed: \(connErr)")
            return nil
        }
        // Schedule the connection so mDNSResponder keeps it alive.
        // Without this, mDNSResponder's keepalive timer fires (typically after
        // 30–60 s) and evicts all records registered on this connection.
        DNSServiceSetDispatchQueue(conn, queue)

        var registered = 0

        // ── A record (IPv4) ──────────────────────────────────────────────────
        if let lan = primaryLANInterface() {
            var inAddr = in_addr()
            if Darwin.inet_pton(AF_INET, lan.ipv4, &inAddr) == 1 {
                var recordRef: DNSRecordRef?
                let err: DNSServiceErrorType = withUnsafeBytes(of: inAddr) { ptr in
                    DNSServiceRegisterRecord(
                        conn,
                        &recordRef,
                        DNSServiceFlags(kDNSServiceFlagsShared), // no probing delay
                        0,                                        // all interfaces for IPv4
                        hostname,
                        UInt16(kDNSServiceType_A),
                        UInt16(kDNSServiceClass_IN),
                        UInt16(MemoryLayout<in_addr>.size),
                        ptr.baseAddress,
                        0,
                        Self.addressRecordCallback,
                        nil
                    )
                }
                if err == kDNSServiceErr_NoError {
                    logger.info("Registered \(hostname) A → \(lan.ipv4) on all interfaces")
                    registered += 1
                } else {
                    logger.warning("DNSServiceRegisterRecord A failed: \(err)")
                }
            } else {
                logger.warning("inet_pton failed for \(lan.ipv4) — skipping A record for \(hostname)")
            }
        } else {
            logger.warning("No primary LAN interface found — skipping A record for \(hostname)")
        }

        // ── AAAA records (link-local IPv6, per interface) ─────────────────────
        for iface in interfaces {
            var ipBuf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            var addrCopy = iface.linkLocalIPv6
            Darwin.inet_ntop(AF_INET6, &addrCopy, &ipBuf, socklen_t(INET6_ADDRSTRLEN))
            let ipStr = String(decoding: ipBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)

            var recordRef: DNSRecordRef?
            let err: DNSServiceErrorType = withUnsafeBytes(of: iface.linkLocalIPv6) { ptr in
                DNSServiceRegisterRecord(
                    conn,
                    &recordRef,
                    DNSServiceFlags(kDNSServiceFlagsShared), // no probing delay
                    iface.index,                             // specific interface — required for link-local
                    hostname,
                    UInt16(kDNSServiceType_AAAA),
                    UInt16(kDNSServiceClass_IN),
                    UInt16(MemoryLayout<in6_addr>.size),
                    ptr.baseAddress,
                    0,
                    Self.addressRecordCallback,
                    nil
                )
            }

            if err == kDNSServiceErr_NoError {
                logger.info("Registered \(hostname) AAAA → \(ipStr) on \(iface.name) (ifIndex=\(iface.index))")
                registered += 1
            } else {
                logger.warning("DNSServiceRegisterRecord AAAA failed on \(iface.name) (ifIndex=\(iface.index)): \(err)")
            }
        }

        if registered == 0 {
            logger.error("All address registrations failed for \(hostname)")
            DNSServiceRefDeallocate(conn)
            return nil
        }

        return conn
    }

    /// Find the link-local IPv6 address (`fe80::/10`) for the interface with the given index.
    private func getLinkLocalIPv6(ifIndex: UInt32) -> in6_addr? {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0, let head = ifap else { return nil }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            guard if_nametoindex(ifa.pointee.ifa_name) == ifIndex,
                  ifa.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET6),
                  let sa = ifa.pointee.ifa_addr else { continue }
            let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            let addr = sin6.sin6_addr
            let b0 = addr.__u6_addr.__u6_addr8.0
            let b1 = addr.__u6_addr.__u6_addr8.1
            if b0 == 0xFE && (b1 & 0xC0) == 0x80 { // fe80::/10
                return addr
            }
        }
        return nil
    }

    /// Log a summary of all active non-loopback interfaces.
    private func logNetworkInterfaces() {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let head = ifaddr else { return }
        defer { freeifaddrs(head) }

        var lines: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            guard let addr = ifa.pointee.ifa_addr else { continue }
            let family = addr.pointee.sa_family
            guard family == UInt8(AF_INET) || family == UInt8(AF_INET6) else { continue }
            let flags = ifa.pointee.ifa_flags
            guard (flags & UInt32(IFF_LOOPBACK)) == 0,
                  (flags & UInt32(IFF_UP))        != 0 else { continue }

            let ifname = String(cString: ifa.pointee.ifa_name)
            var ipBuf  = [CChar](repeating: 0, count: 64)
            let raw    = UnsafeRawPointer(addr)
            if family == UInt8(AF_INET) {
                var s = raw.load(as: sockaddr_in.self)
                Darwin.inet_ntop(AF_INET, &s.sin_addr, &ipBuf, 64)
            } else {
                var s = raw.load(as: sockaddr_in6.self)
                Darwin.inet_ntop(AF_INET6, &s.sin6_addr, &ipBuf, 64)
            }
            let ip   = String(decoding: ipBuf.prefix(while: { $0 != 0 }).map(UInt8.init), as: UTF8.self)
            let pptp = (flags & UInt32(IFF_POINTOPOINT)) != 0 ? " [point-to-point/VPN]" : ""
            lines.append("  \(ifname): \(ip)\(pptp)")
        }
        if !lines.isEmpty {
            logger.info("Network interfaces (may affect mDNS resolution):\n\(lines.joined(separator: "\n"))")
        }
    }

    /// Convert an `NWBrowser.Result` to a `ServiceRecord`.
    private func serviceRecord(
        from result: NWBrowser.Result,
        serviceType: ServiceType
    ) -> ServiceRecord? {
        guard case .service(let name, _, _, _) = result.endpoint else {
            return nil
        }

        // Decode the raw wire bytes rather than walking `NWTXTRecord`'s
        // entries, so browse follows the same RFC 6763 rule (bare keys,
        // first-occurrence-wins duplicates) as `resolveService`.
        var txtRecords: [String: String] = [:]
        if case .bonjour(let txtRecord) = result.metadata {
            txtRecords = TXTRecord.decode(wireFormat: txtRecord.data)
        }

        return ServiceRecord(
            name: name,
            serviceType: serviceType,
            host: "",
            port: 0,
            txtRecords: txtRecords
        )
    }
}

// MARK: - Errors

/// Errors specific to Apple platform discovery.
public enum ServiceDiscoveryError: Error, Sendable {
    case resolveFailed(String)
    case registrationFailed(code: Int)
}

// MARK: - ResolveOutcome

/// Resumes one `resolveOnce` continuation exactly once, from whichever of the
/// connection's state handler or task cancellation gets there first.
private final class ResolveOutcome: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<NetworkAddress, Error>?
    private var cancelledEarly = false
    private var finished = false

    func install(_ continuation: CheckedContinuation<NetworkAddress, Error>) {
        lock.lock()
        if finished || cancelledEarly {
            finished = true
            lock.unlock()
            continuation.resume(throwing: CancellationError())
        } else {
            self.continuation = continuation
            lock.unlock()
        }
    }

    func finish(_ result: Result<NetworkAddress, Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        let first = !finished
        finished = true
        lock.unlock()
        if first, let pending { pending.resume(with: result) }
    }

    func cancel() {
        lock.lock()
        let pending = continuation
        continuation = nil
        if pending == nil { cancelledEarly = true } else { finished = true }
        lock.unlock()
        pending?.resume(throwing: CancellationError())
    }
}

#endif
