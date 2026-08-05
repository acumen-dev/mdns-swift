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
    /// Substitutes `fallbackHostname` (if provided) for an
    /// **interface-scoped** `.ipv4`/`.ipv6` address (`addr.interface != nil`
    /// — both address families support this, not just IPv6).
    /// Network.framework attaches a scope whenever a resolved path is tied
    /// to a specific local interface (routine on a multi-interface host —
    /// Wi-Fi + Ethernet, a VPN, a bridge — not just a link-local-address
    /// edge case), and its string form appends a `%<interfaceName>` suffix
    /// (`"192.168.1.23%en1"`, `"fe80::1%en0"`). That suffix is not valid
    /// inside a URL authority component — `URLComponents` cannot parse it —
    /// and it is not portable even where some caller could work around
    /// that: `en1` names an interface on *this* process's view of the
    /// network, meaningless after a restart, from a different host, or once
    /// persisted as a plain string.
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
    /// `fallbackHostname` supplied, the address is rejected (`nil`) exactly
    /// as before.
    public init?(endpoint: NWEndpoint, fallbackHostname: String? = nil) {
        guard case .hostPort(let host, let port) = endpoint else {
            return nil
        }
        let hostString: String
        switch host {
        case .ipv4(let addr):
            if let fallbackHostname, addr.interface != nil {
                hostString = fallbackHostname
            } else {
                guard addr.interface == nil else { return nil }
                hostString = "\(addr)"
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
