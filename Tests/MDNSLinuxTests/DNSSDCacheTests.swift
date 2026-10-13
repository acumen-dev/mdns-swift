// DNSSDCacheTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MDNSLinux

/// `DNSSDCache` — the pure record cache `LinuxServiceDiscovery` feeds from
/// every response. Records are built with the `DNSMessage` encoder and
/// decoded back, so the cache sees exactly what it would see off the wire.
@Suite("DNSSDCache")
struct DNSSDCacheTests {

    static let type = "_matterc._udp"
    static let instance = "ABCDEF0123456789"
    static let fullName = "\(instance).\(type).local"

    /// Encodes the records as a response and decodes them again.
    static func wire(_ records: [DNSRecord]) throws -> [DNSRecord] {
        let data = DNSMessage(isResponse: true, isAuthoritative: true, answers: records).encode()
        let decoded = try #require(DNSMessage.decode(from: data))
        return decoded.answers + decoded.additionals
    }

    static func commissionable(ttl: UInt32 = 120) -> [DNSRecord] {
        [
            DNSRecord(name: "\(type).local", type: .ptr, ttl: ttl, rdata: .ptr(domain: fullName)),
            DNSRecord(name: fullName, type: .srv, ttl: ttl,
                      rdata: .srv(priority: 0, weight: 0, port: 5540, target: "host-1.local")),
            DNSRecord(name: fullName, type: .txt, ttl: ttl, rdata: .txt(["D=3840", "CM=1", "SII=5000"])),
            DNSRecord(name: "host-1.local", type: .a, ttl: ttl, rdata: .a(Data([192, 0, 2, 10]))),
        ]
    }

    @Test("PTR + SRV + TXT + A for a commissionable instance give its TXT, SRV and address")
    func commissionableInstance() throws {
        var cache = DNSSDCache()
        cache.ingest(try Self.wire(Self.commissionable()), now: .now)

        #expect(cache.instances(of: Self.type) == [Self.instance])
        let srv = try #require(cache.srv(instance: Self.instance, serviceType: Self.type))
        #expect(srv.target == "host-1.local")
        #expect(srv.port == 5540)
        #expect(cache.txt(instance: Self.instance, serviceType: Self.type) == ["D": "3840", "CM": "1", "SII": "5000"])
        #expect(cache.addresses(host: srv.target) == ["192.0.2.10"])
    }

    @Test("Names match case-insensitively; the instance keeps its received case")
    func caseInsensitiveNames() throws {
        var cache = DNSSDCache()
        cache.ingest(try Self.wire(Self.commissionable()), now: .now)
        #expect(cache.instances(of: "_MATTERC._UDP") == [Self.instance])
        #expect(cache.srv(instance: "abcdef0123456789", serviceType: Self.type)?.port == 5540)
        #expect(cache.addresses(host: "HOST-1.local") == ["192.0.2.10"])
    }

    @Test("A TTL-0 PTR removes the instance")
    func goodbyeRemovesInstance() throws {
        var cache = DNSSDCache()
        cache.ingest(try Self.wire(Self.commissionable()), now: .now)
        cache.ingest(try Self.wire([
            DNSRecord(name: "\(Self.type).local", type: .ptr, ttl: 0, rdata: .ptr(domain: Self.fullName)),
        ]), now: .now)
        #expect(cache.instances(of: Self.type).isEmpty)
    }

    @Test("Records expire after their TTL")
    func recordsExpire() throws {
        var cache = DNSSDCache()
        let start = ContinuousClock.now
        cache.ingest(try Self.wire(Self.commissionable(ttl: 120)), now: start)
        cache.ingest([], now: start + .seconds(119))
        #expect(cache.instances(of: Self.type) == [Self.instance])
        cache.ingest([], now: start + .seconds(120))
        #expect(cache.instances(of: Self.type).isEmpty)
        #expect(cache.srv(instance: Self.instance, serviceType: Self.type) == nil)
        #expect(cache.txt(instance: Self.instance, serviceType: Self.type) == nil)
        #expect(cache.addresses(host: "host-1.local").isEmpty)
    }

    @Test("An instance name containing a dot and a space is preserved")
    func instanceWithDotAndSpace() throws {
        let instance = "Instance 1.a"
        let full = "\(instance).\(Self.type).local"
        var cache = DNSSDCache()
        cache.ingest(try Self.wire([
            DNSRecord(name: "\(Self.type).local", type: .ptr, ttl: 120, rdata: .ptr(domain: full)),
            DNSRecord(name: full, type: .srv, ttl: 120,
                      rdata: .srv(priority: 0, weight: 0, port: 5540, target: "host-1.local")),
        ]), now: .now)
        #expect(cache.instances(of: Self.type) == [instance])
        #expect(cache.srv(instance: instance, serviceType: Self.type)?.port == 5540)
    }

    @Test("TXT holding a single empty string gives [:]")
    func emptyTXT() throws {
        var cache = DNSSDCache()
        cache.ingest(try Self.wire([
            DNSRecord(name: Self.fullName, type: .txt, ttl: 120, rdata: .txt([""])),
        ]), now: .now)
        #expect(cache.txt(instance: Self.instance, serviceType: Self.type) == [:])
    }

    @Test("A bare-key TXT entry gives \"\"")
    func bareKeyTXT() throws {
        var cache = DNSSDCache()
        cache.ingest(try Self.wire([
            DNSRecord(name: Self.fullName, type: .txt, ttl: 120, rdata: .txt(["flag", "D=3840"])),
        ]), now: .now)
        #expect(cache.txt(instance: Self.instance, serviceType: Self.type) == ["flag": "", "D": "3840"])
    }

    @Test("A newer TXT replaces the older one")
    func txtReplaced() throws {
        var cache = DNSSDCache()
        cache.ingest(try Self.wire(Self.commissionable()), now: .now)
        cache.ingest(try Self.wire([
            DNSRecord(name: Self.fullName, type: .txt, ttl: 120, rdata: .txt(["D=3840", "CM=0"])),
        ]), now: .now)
        #expect(cache.txt(instance: Self.instance, serviceType: Self.type) == ["D": "3840", "CM": "0"])
    }

    @Test("Two hosts' A records don't cross-match")
    func hostsDoNotCrossMatch() throws {
        var cache = DNSSDCache()
        cache.ingest(try Self.wire([
            DNSRecord(name: "host-1.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, 1]))),
            DNSRecord(name: "host-10.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, 10]))),
        ]), now: .now)
        #expect(cache.addresses(host: "host-1.local") == ["192.0.2.1"])
        #expect(cache.addresses(host: "host-10.local") == ["192.0.2.10"])
    }

    @Test("Addresses list A before AAAA, formatted as resolvableHosts formats them")
    func addressOrderAndFormat() throws {
        let v6 = Data([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
        var cache = DNSSDCache()
        cache.ingest(try Self.wire([
            DNSRecord(name: "host-1.local", type: .aaaa, ttl: 120, rdata: .aaaa(v6)),
            DNSRecord(name: "host-1.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, 1]))),
        ]), now: .now)
        #expect(cache.addresses(host: "host-1.local") == ["192.0.2.1", "[fe80:0:0:0:1234:5678:9abc:def0]"])

        // A goodbye for one address removes only that address.
        cache.ingest(try Self.wire([
            DNSRecord(name: "host-1.local", type: .a, ttl: 0, rdata: .a(Data([192, 0, 2, 1]))),
        ]), now: .now)
        #expect(cache.addresses(host: "host-1.local") == ["[fe80:0:0:0:1234:5678:9abc:def0]"])
    }

    // MARK: Cache-flush (RFC 6762 §10.2)

    static func address(_ last: UInt8, cacheFlush: Bool) -> DNSRecord {
        DNSRecord(name: "host-1.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, last])), cacheFlush: cacheFlush)
    }

    @Test("A cache-flush A record heard later replaces the host's older A record")
    func cacheFlushReplacesOlderAddress() {
        var cache = DNSSDCache()
        let start = ContinuousClock.now
        cache.ingest([Self.address(1, cacheFlush: true)], now: start)
        cache.ingest([Self.address(2, cacheFlush: true)], now: start + .seconds(2))
        #expect(cache.addresses(host: "host-1.local") == ["192.0.2.2"])
    }

    @Test("Without cache-flush both addresses are kept, the newest first")
    func sharedAddressesNewestFirst() {
        var cache = DNSSDCache()
        let start = ContinuousClock.now
        cache.ingest([Self.address(1, cacheFlush: false)], now: start)
        cache.ingest([Self.address(2, cacheFlush: false)], now: start + .seconds(2))
        #expect(cache.addresses(host: "host-1.local") == ["192.0.2.2", "192.0.2.1"])
    }

    @Test("Cache-flush records heard within 1 s of each other are kept together")
    func cacheFlushKeepsSameBurst() {
        var cache = DNSSDCache()
        let start = ContinuousClock.now
        cache.ingest([Self.address(1, cacheFlush: true)], now: start)
        cache.ingest([Self.address(2, cacheFlush: true)], now: start + .milliseconds(500))
        #expect(cache.addresses(host: "host-1.local") == ["192.0.2.2", "192.0.2.1"])
    }

    @Test("Cache-flush on an A record leaves the host's AAAA records alone")
    func cacheFlushIsPerType() {
        let v6 = Data([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
        var cache = DNSSDCache()
        let start = ContinuousClock.now
        cache.ingest([DNSRecord(name: "host-1.local", type: .aaaa, ttl: 120, rdata: .aaaa(v6), cacheFlush: true)], now: start)
        cache.ingest([Self.address(2, cacheFlush: true)], now: start + .seconds(2))
        #expect(cache.addresses(host: "host-1.local") == ["192.0.2.2", "[fe80:0:0:0:1234:5678:9abc:def0]"])
    }
}
