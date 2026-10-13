// MDNSMessageTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import Foundation
@testable import MDNSLinux

@Suite("DNSMessage Encode/Decode Tests")
struct DNSMessageTests {

    @Test("Encode and decode a PTR response")
    func ptrResponseRoundTrip() throws {
        var msg = DNSMessage(isResponse: true, isAuthoritative: true)
        msg.answers.append(DNSRecord(
            name: "_hap._tcp.local",
            type: .ptr,
            ttl: 4500,
            rdata: .ptr(domain: "My Device._hap._tcp.local")
        ))

        let data = msg.encode()
        let decoded = try #require(DNSMessage.decode(from: data))

        #expect(decoded.isResponse == true)
        #expect(decoded.isAuthoritative == true)
        #expect(decoded.answers.count == 1)
        guard case .ptr(let domain) = decoded.answers[0].rdata else {
            Issue.record("Expected PTR rdata")
            return
        }
        #expect(domain == "My Device._hap._tcp.local")
        #expect(decoded.answers[0].ttl == 4500)
    }

    @Test("Encode and decode a PTR query")
    func ptrQueryRoundTrip() throws {
        var msg = DNSMessage(isResponse: false)
        msg.questions.append(DNSQuestion(name: "_hap._tcp.local", type: .ptr))

        let data = msg.encode()
        let decoded = try #require(DNSMessage.decode(from: data))

        #expect(decoded.isResponse == false)
        #expect(decoded.questions.count == 1)
        #expect(decoded.questions[0].name == "_hap._tcp.local")
        #expect(decoded.questions[0].type == .ptr)
    }

    @Test("Encode and decode SRV + TXT records")
    func srvTxtRoundTrip() throws {
        var msg = DNSMessage(isResponse: true, isAuthoritative: true)
        msg.answers.append(DNSRecord(
            name: "My Device._hap._tcp.local",
            type: .srv,
            ttl: 4500,
            rdata: .srv(priority: 0, weight: 0, port: 51826, target: "myhost.local")
        ))
        msg.answers.append(DNSRecord(
            name: "My Device._hap._tcp.local",
            type: .txt,
            ttl: 4500,
            rdata: .txt(["id=AA:BB:CC:DD:EE:FF", "c#=1", "s#=1"])
        ))

        let data = msg.encode()
        let decoded = try #require(DNSMessage.decode(from: data))

        #expect(decoded.answers.count == 2)
        guard case .srv(_, _, let port, let target) = decoded.answers[0].rdata else {
            Issue.record("Expected SRV rdata")
            return
        }
        #expect(port == 51826)
        #expect(target == "myhost.local")

        guard case .txt(let strings) = decoded.answers[1].rdata else {
            Issue.record("Expected TXT rdata")
            return
        }
        #expect(strings.contains("id=AA:BB:CC:DD:EE:FF"))
        #expect(strings.contains("c#=1"))
    }

    @Test("Encode and decode A record")
    func aRecordRoundTrip() throws {
        var msg = DNSMessage(isResponse: true, isAuthoritative: true)
        msg.answers.append(DNSRecord(
            name: "myhost.local",
            type: .a,
            ttl: 4500,
            rdata: .a(Data([192, 168, 1, 42]))
        ))

        let data = msg.encode()
        let decoded = try #require(DNSMessage.decode(from: data))

        guard case .a(let bytes) = decoded.answers[0].rdata else {
            Issue.record("Expected A rdata")
            return
        }
        #expect(Array(bytes) == [192, 168, 1, 42])
    }

    @Test("Decode returns nil for truncated data")
    func truncatedDataReturnsNil() {
        let truncated = Data([0x00, 0x00, 0x84]) // incomplete header
        #expect(DNSMessage.decode(from: truncated) == nil)
    }

    @Test("Goodbye record has TTL 0")
    func goodbyeRecord() throws {
        var msg = DNSMessage(isResponse: true, isAuthoritative: true)
        msg.answers.append(DNSRecord(
            name: "_hap._tcp.local",
            type: .ptr,
            ttl: 0,
            rdata: .ptr(domain: "My Device._hap._tcp.local")
        ))

        let data = msg.encode()
        let decoded = try #require(DNSMessage.decode(from: data))
        #expect(decoded.answers[0].ttl == 0)
    }

    @Test("Authority records are skipped, so the additionals after them decode as additionals")
    func authoritySectionSkipped() throws {
        let authority = DNSRecord(name: "host-1.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, 99])))
        let additional = DNSRecord(name: "host-1.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, 10])))
        var data = DNSMessage(isResponse: true, answers: [authority], additionals: [additional]).encode()
        // The encoder has no authority section; re-label the first record as
        // one by rewriting the header counts: ANCOUNT 0, NSCOUNT 1, ARCOUNT 1.
        data[6] = 0; data[7] = 0
        data[8] = 0; data[9] = 1
        data[10] = 0; data[11] = 1

        let decoded = try #require(DNSMessage.decode(from: data))
        #expect(decoded.answers.isEmpty)
        #expect(decoded.additionals.count == 1)
        guard case .a(let bytes) = decoded.additionals.first?.rdata else {
            Issue.record("Expected an A record in the additionals")
            return
        }
        #expect(Array(bytes) == [192, 0, 2, 10])
    }

    @Test("A TXT string that is not valid UTF-8 decodes with U+FFFD rather than being emptied")
    func txtNonUTF8Kept() throws {
        let record = DNSRecord(name: "i._t._udp.local", type: .txt, ttl: 120, rdata: .txt(["k=x"]))
        var data = DNSMessage(isResponse: true, answers: [record]).encode()
        data[data.count - 1] = 0xFF // the trailing "x"
        let decoded = try #require(DNSMessage.decode(from: data))
        guard case .txt(let strings) = decoded.answers.first?.rdata else {
            Issue.record("Expected TXT rdata")
            return
        }
        #expect(strings == ["k=\u{FFFD}"])
    }

    @Test("Decode carries the cache-flush bit: set on a response's records, clear on a query's")
    func cacheFlushDecoded() throws {
        let record = DNSRecord(name: "host-1.local", type: .a, ttl: 120, rdata: .a(Data([192, 0, 2, 1])))
        let response = try #require(DNSMessage.decode(from: DNSMessage(isResponse: true, answers: [record]).encode()))
        #expect(response.answers.first?.cacheFlush == true)
        let query = try #require(DNSMessage.decode(from: DNSMessage(isResponse: false, answers: [record]).encode()))
        #expect(query.answers.first?.cacheFlush == false)
    }
}
