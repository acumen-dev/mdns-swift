// NetworkAddressTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
import MDNSCore

#if canImport(Network)
import Network
@testable import MDNSApple

/// `NetworkAddress(endpoint:)` used to hand back whatever raw string
/// `IPv4Address`/`IPv6Address` interpolation produced — including, for an
/// interface-scoped address (routine on any multi-interface host, not just
/// a link-local-IPv6 edge case), a `%<interfaceName>` suffix that
/// `URLComponents` cannot parse at all. That broke every URL-based
/// transport built on top of this library with a crash, not a catchable
/// error — confirmed against real hardware, see `acumen-shelly`'s CLAUDE.md.
/// These pin down both the rejection of scoped addresses and the URL
/// safety of everything this initializer does still accept.
@Suite("NetworkAddress(endpoint:) never yields a host that breaks URL construction")
struct NetworkAddressTests {
    @Test("a plain (unscoped) IPv4 endpoint resolves to a usable, URL-safe host")
    func plainIPv4() throws {
        let addr = try #require(IPv4Address("192.168.1.23"))
        let endpoint = NWEndpoint.hostPort(host: .ipv4(addr), port: 80)
        let address = try #require(NetworkAddress(endpoint: endpoint))
        #expect(address.host == "192.168.1.23")
        #expect(address.port == 80)
        try #require(urlBuilds(fromHost: address.host))
    }

    @Test("an interface-scoped IPv4 endpoint (e.g. \"192.168.1.23%en1\") is rejected when no fallback is given")
    func scopedIPv4Rejected() throws {
        let addr = try #require(IPv4Address("192.168.1.23%en1"))
        #expect(addr.interface != nil) // sanity: this really is what we think it is
        let endpoint = NWEndpoint.hostPort(host: .ipv4(addr), port: 80)
        #expect(NetworkAddress(endpoint: endpoint) == nil)
    }

    @Test("a scoped IPv4 endpoint substitutes the fallback hostname but keeps the resolved port")
    func scopedIPv4UsesFallbackHostnamePreservingPort() throws {
        let addr = try #require(IPv4Address("192.168.173.104%en1"))
        let endpoint = NWEndpoint.hostPort(host: .ipv4(addr), port: 80)
        let address = try #require(NetworkAddress(endpoint: endpoint, fallbackHostname: "shelly1.local"))
        #expect(address.host == "shelly1.local")
        // The real, actual bug this guards against: a caller that discards
        // a scoped address's port along with its rejected host — falling
        // back to a bare "<name>.local" guess with no port info, since mDNS
        // browsing alone never carries one — ends up dispatching to port 0,
        // which fails at request-submission time (NSURLErrorBadURL) even
        // though `URLComponents` itself doesn't reject it. Confirmed
        // against real hardware — see CLAUDE.md item 5's fix history.
        #expect(address.port == 80)
        try #require(urlBuilds(fromHost: address.host, port: Int(address.port)))
    }

    @Test("a plain (unscoped) global/ULA IPv6 endpoint resolves to a bracketed, URL-safe host")
    func plainIPv6() throws {
        let addr = try #require(IPv6Address("fd00::1"))
        let endpoint = NWEndpoint.hostPort(host: .ipv6(addr), port: 8080)
        let address = try #require(NetworkAddress(endpoint: endpoint))
        #expect(address.host == "[fd00::1]")
        try #require(urlBuilds(fromHost: address.host))
    }

    @Test("a link-local (interface-scoped) IPv6 endpoint is rejected, not bracketed as-is, when no fallback is given")
    func scopedIPv6Rejected() throws {
        let addr = try #require(IPv6Address("fe80::1234:5678:9abc:def0%en0"))
        #expect(addr.interface != nil)
        let endpoint = NWEndpoint.hostPort(host: .ipv6(addr), port: 80)
        #expect(NetworkAddress(endpoint: endpoint) == nil)
    }

    @Test("a scoped IPv6 endpoint substitutes the fallback hostname but keeps the resolved port")
    func scopedIPv6UsesFallbackHostnamePreservingPort() throws {
        let addr = try #require(IPv6Address("fe80::1234:5678:9abc:def0%en0"))
        let endpoint = NWEndpoint.hostPort(host: .ipv6(addr), port: 8080)
        let address = try #require(NetworkAddress(endpoint: endpoint, fallbackHostname: "shelly1.local"))
        #expect(address.host == "shelly1.local")
        #expect(address.port == 8080)
        try #require(urlBuilds(fromHost: address.host, port: Int(address.port)))
    }

    @Test("a plain, unscoped address ignores a supplied fallback hostname entirely")
    func unscopedAddressIgnoresFallback() throws {
        let addr = try #require(IPv4Address("192.168.1.23"))
        let endpoint = NWEndpoint.hostPort(host: .ipv4(addr), port: 80)
        let address = try #require(NetworkAddress(endpoint: endpoint, fallbackHostname: "shelly1.local"))
        #expect(address.host == "192.168.1.23")
    }

    @Test("a .name host (an mDNS hostname target) passes through unchanged")
    func nameHostPassesThrough() throws {
        let endpoint = NWEndpoint.hostPort(host: .name("shelly1pmg4-abc123.local", nil), port: 80)
        let address = try #require(NetworkAddress(endpoint: endpoint))
        #expect(address.host == "shelly1pmg4-abc123.local")
        try #require(urlBuilds(fromHost: address.host))
    }

    @Test("a non-hostPort endpoint (e.g. .service) yields nil")
    func nonHostPortEndpointRejected() {
        let endpoint = NWEndpoint.service(name: "x", type: "_shelly._tcp", domain: "local.", interface: nil)
        #expect(NetworkAddress(endpoint: endpoint) == nil)
    }

    /// The actual regression guard: whatever `NetworkAddress(endpoint:)`
    /// does hand back must be usable to build a real URL — this is the
    /// exact construction `ShellyHTTPTransportConfiguration.makeURL()` (and
    /// any future consumer) performs.
    private func urlBuilds(fromHost host: String, port: Int = 80) -> Bool {
        var components = URLComponents()
        components.scheme = "http"
        components.host = host
        components.port = port
        components.path = "/rpc"
        return components.url != nil
    }
}
#endif
