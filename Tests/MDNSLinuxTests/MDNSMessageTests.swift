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
}
