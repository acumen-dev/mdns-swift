// NWEndpoint+NetworkAddress.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import Network
import MDNSCore

// MARK: - NetworkAddress ↔ NWEndpoint Conversion

extension NetworkAddress {

    /// Create a `NetworkAddress` from an `NWEndpoint`.
    ///
    /// Only `.hostPort` endpoints are supported — returns `nil` for
    /// `.service`, `.unix`, `.url`, or other endpoint types.
    ///
    /// Also returns `nil` for an **interface-scoped** `.ipv4`/`.ipv6`
    /// address (`addr.interface != nil` — both address families support
    /// this, not just IPv6). Network.framework attaches a scope whenever a
    /// resolved path is tied to a specific local interface (routine on a
    /// multi-interface host — Wi-Fi + Ethernet, a VPN, a bridge — not just a
    /// link-local-address edge case), and its string form appends a
    /// `%<interfaceName>` suffix (`"192.168.1.23%en1"`,
    /// `"fe80::1%en0"`). That suffix is not valid inside a URL authority
    /// component — `URLComponents` cannot parse it — and it is not portable
    /// even where some caller could work around that: `en1` names an
    /// interface on *this* process's view of the network, meaningless after
    /// a restart, from a different host, or once persisted as a plain
    /// string. Rejecting it here (rather than producing an address a
    /// downstream URL-based transport cannot use) surfaces as an ordinary
    /// `ServiceDiscoveryError.resolveFailed` from ``resolve(_:)``, which
    /// callers already treat as "fall back to the plain `.local` hostname" —
    /// resolved fresh, and unscoped, at actual connection time instead of
    /// baked in here.
    public init?(endpoint: NWEndpoint) {
        guard case .hostPort(let host, let port) = endpoint else {
            return nil
        }
        let hostString: String
        switch host {
        case .ipv4(let addr):
            guard addr.interface == nil else { return nil }
            hostString = "\(addr)"
        case .ipv6(let addr):
            guard addr.interface == nil else { return nil }
            // Bracket per RFC 3986 — a bare IPv6 literal is not a valid URL
            // host. Only reachable for a non-scoped address (global unicast
            // or ULA); a scoped one was already rejected above.
            hostString = "[\(addr)]"
        case .name(let name, _):
            hostString = name
        @unknown default:
            return nil
        }
        self.init(host: hostString, port: port.rawValue)
    }
}

extension NWEndpoint {

    /// Create an `NWEndpoint.hostPort` from a `NetworkAddress`.
    public static func hostPort(from address: NetworkAddress) -> NWEndpoint {
        .hostPort(host: NWEndpoint.Host(address.host), port: NWEndpoint.Port(rawValue: address.port)!)
    }
}
#endif
