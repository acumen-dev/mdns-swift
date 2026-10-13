// LinuxServiceDiscoveryResolveTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MDNSLinux

/// `LinuxServiceDiscovery.resolvableHosts(from:)` — the pure, side-effect-free
/// core of `handleResponse`'s A/AAAA handling. Pins down two fixes:
///
/// 1. An AAAA record used to format as a bare, unbracketed colon-separated
///    literal (`"fe80:0:0:0:1234:5678:9abc:def0"`), which is not a valid URL
///    host — the same class of defect fixed in `MDNSApple`'s
///    `NetworkAddress(endpoint:)` (see that file's tests), just reached via
///    hand-rolled DNS message parsing instead of Network.framework.
/// 2. `handleResponse` resolved on whichever record type it encountered
///    first in the response, with no preference — an AAAA record appearing
///    before an A record in the same packet would silently win. This
///    library prefers IPv4 throughout (see `MDNSApple`'s equivalent
///    preference in `AppleServiceDiscovery.resolve`); the Linux backend
///    should not have been the odd one out.
/// 3. An AAAA record was written with every group in full
///    (`"[fd00:0:0:0:0:0:0:1]"`), where the socket layer and Network.framework
///    write the canonical compressed form (`"[fd00::1]"`); a consumer that
///    matched a reply's sender against the resolved host by string never saw
///    the reply.
@Suite("LinuxServiceDiscovery.resolvableHosts — A/AAAA formatting and ordering")
struct LinuxServiceDiscoveryResolveTests {
    @Test("an A record formats as a plain, URL-safe dotted-quad host")
    func aRecordFormatsPlain() throws {
        let record = DNSRecord(name: "shelly1pmg4-abc123.local", type: .a, ttl: 120, rdata: .a(Data([192, 168, 1, 23])))
        let results = LinuxServiceDiscovery.resolvableHosts(from: [record])
        #expect(results.count == 1)
        #expect(results[0].recordName == "shelly1pmg4-abc123.local")
        #expect(results[0].host == "192.168.1.23")
        try #require(urlBuilds(fromHost: results[0].host))
    }

    @Test("an AAAA record formats as a bracketed, URL-safe IPv6 host")
    func aaaaRecordFormatsBracketed() throws {
        let bytes = Data([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
        let record = DNSRecord(name: "shelly1pmg4-abc123.local", type: .aaaa, ttl: 120, rdata: .aaaa(bytes))
        let results = LinuxServiceDiscovery.resolvableHosts(from: [record])
        #expect(results.count == 1)
        #expect(results[0].host == "[fe80::1234:5678:9abc:def0]")
        try #require(urlBuilds(fromHost: results[0].host))
    }

    @Test(
        "an AAAA record formats in the canonical compressed form (RFC 5952), as inet_ntop writes it",
        arguments: [
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], "[::1]"),
            ([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05], "[fd00::5]"),
            ([0xfd, 0, 0, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0x0b, 0, 0, 0, 0], "[fd00:a::b:0:0]"),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "[::]"),
        ] as [([UInt8], String)]
    )
    func aaaaRecordFormatsCompressed(bytes: [UInt8], host: String) throws {
        let record = DNSRecord(name: "host-1.local", type: .aaaa, ttl: 120, rdata: .aaaa(Data(bytes)))
        let results = LinuxServiceDiscovery.resolvableHosts(from: [record])
        #expect(results.map(\.host) == [host])
        try #require(urlBuilds(fromHost: results[0].host))
    }

    @Test("when both an A and AAAA record are present, the A-derived host is ordered first regardless of packet order")
    func preferOrdersARecordFirst() {
        let name = "shelly1pmg4-abc123.local"
        let aaaaRecord = DNSRecord(
            name: name, type: .aaaa, ttl: 120,
            rdata: .aaaa(Data([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]))
        )
        let aRecord = DNSRecord(name: name, type: .a, ttl: 120, rdata: .a(Data([192, 168, 1, 23])))

        // AAAA listed BEFORE A in the input, matching a packet where the
        // responder happened to put the AAAA answer first.
        let results = LinuxServiceDiscovery.resolvableHosts(from: [aaaaRecord, aRecord])

        #expect(results.count == 2)
        #expect(results[0].host == "192.168.1.23") // A wins the race regardless of input order
        #expect(results[1].host == "[fe80::1234:5678:9abc:def0]")
    }

    @Test("malformed byte counts are skipped rather than producing a garbled host")
    func malformedByteCountsSkipped() {
        let shortA = DNSRecord(name: "x.local", type: .a, ttl: 120, rdata: .a(Data([192, 168, 1])))
        let shortAAAA = DNSRecord(name: "x.local", type: .aaaa, ttl: 120, rdata: .aaaa(Data([0xfe, 0x80])))
        #expect(LinuxServiceDiscovery.resolvableHosts(from: [shortA, shortAAAA]).isEmpty)
    }

    @Test("non-address records (e.g. PTR) contribute nothing")
    func nonAddressRecordsIgnored() {
        let ptr = DNSRecord(name: "_shelly._tcp.local", type: .ptr, ttl: 120, rdata: .ptr(domain: "shelly1.local"))
        #expect(LinuxServiceDiscovery.resolvableHosts(from: [ptr]).isEmpty)
    }

    @Test("records decoded off the wire (Data slices of the message) format without trapping")
    func decodedRecordsFormat() throws {
        let v6 = Data([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
        let message = DNSMessage(isResponse: true, answers: [
            DNSRecord(name: "host-1.local", type: .aaaa, ttl: 120, rdata: .aaaa(v6)),
            DNSRecord(name: "host-1.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, 1]))),
        ])
        let decoded = try #require(DNSMessage.decode(from: message.encode()))
        let hosts = LinuxServiceDiscovery.resolvableHosts(from: decoded.answers).map(\.host)
        #expect(hosts == ["192.0.2.1", "[fe80::1234:5678:9abc:def0]"])
    }

    private func urlBuilds(fromHost host: String) -> Bool {
        var components = URLComponents()
        components.scheme = "http"
        components.host = host
        components.port = 80
        components.path = "/rpc"
        return components.url != nil
    }
}
