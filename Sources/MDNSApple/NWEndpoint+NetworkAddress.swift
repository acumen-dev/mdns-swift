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
    /// A routable `.ipv4` address is rendered as its bare dotted-quad
    /// literal, scoped or not. Network.framework attaches an interface scope
    /// whenever a resolved path is tied to a specific local interface
    /// (routine on a multi-interface host — Wi-Fi + Ethernet, a VPN, a
    /// bridge), and its string form appends a `%<interfaceName>` suffix
    /// (`"192.168.1.23%en1"`). For a routable IPv4 address that scope is a
    /// path annotation: `sockaddr_in` has no scope field, and the routing
    /// table picks the interface for the literal alone. The literal is valid
    /// in a URL authority and portable once persisted.
    ///
    /// An IPv4 link-local address (`169.254.0.0/16`) is the exception: it
    /// is unique only on its link, and the unscoped `169.254` route exists
    /// on one interface only, so without its scope the literal may go out
    /// the wrong interface. A scoped one is treated like a scoped IPv6
    /// address, below.
    ///
    /// Substitutes `fallbackHostname` (if provided) for an
    /// **interface-scoped** `.ipv6` address (`addr.interface != nil`,
    /// typically link-local `fe80::/10`) or scoped IPv4 link-local address,
    /// whose scope *is* addressing: the
    /// `%<interfaceName>` suffix is not valid inside a URL authority
    /// component — `URLComponents` cannot parse it — and it is not portable
    /// even where some caller could work around that: `en0` names an
    /// interface on *this* process's view of the network, meaningless after
    /// a restart, from a different host, or once persisted as a plain
    /// string.
    ///
    /// Substituting the hostname (rather than failing the whole resolve)
    /// matters because **`port` is still correct** — it came from the same
    /// successful SRV resolution as the rejected host, and mDNS browsing
    /// alone never carries a port at all (`ServiceRecord.port` is `0` until
    /// something resolves it). A caller that instead discards this whole
    /// address and falls back to a bare "`<name>.local`" guess, as if
    /// nothing had been resolved, loses that port along with it — producing
    /// a URL like `http://foo.local:0/rpc`, invalid for an entirely
    /// different reason than the one this fix addresses. With no
    /// `fallbackHostname` supplied, a scoped IPv6 or IPv4 link-local
    /// address is rejected (`nil`).
    public init?(endpoint: NWEndpoint, fallbackHostname: String? = nil) {
        guard case .hostPort(let host, let port) = endpoint else {
            return nil
        }
        let hostString: String
        switch host {
        case .ipv4(let addr):
            if addr.interface != nil, addr.isLinkLocal {
                guard let fallbackHostname else { return nil }
                hostString = fallbackHostname
            } else {
                // From the bytes: the description carries a scope's `%<interface>`.
                hostString = addr.rawValue.map { String($0) }.joined(separator: ".")
            }
        case .ipv6(let addr):
            if let fallbackHostname, addr.interface != nil {
                hostString = fallbackHostname
            } else {
                guard addr.interface == nil else { return nil }
                // Bracket per RFC 3986 — a bare IPv6 literal is not a valid
                // URL host. Only reachable for a non-scoped address (global
                // unicast or ULA); a scoped one is handled above.
                hostString = "[\(addr)]"
            }
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
