// AppleServiceDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
import MDNSCore

// Network I/O tests (advertising, browsing, resolving) require a live mDNS
// environment and are exercised manually or in integration tests.
// This file verifies that the MDNSApple module compiles and types are correct.

#if canImport(Network)
@testable import MDNSApple

@Suite("AppleServiceDiscovery Compile-time Tests")
struct AppleServiceDiscoveryTests {

    @Test("AppleServiceDiscovery conforms to ServiceDiscovery")
    func conformance() {
        // Verify the conformance compiles — existence is enough.
        let _: any ServiceDiscovery = AppleServiceDiscovery()
    }

    @Test("ServiceDiscoveryError cases exist")
    func errorCases() {
        let e1 = ServiceDiscoveryError.resolveFailed("test")
        let e2 = ServiceDiscoveryError.registrationFailed(code: -65563)
        _ = e1
        _ = e2
    }
}

@Suite("TXT Record Encoding")
struct TXTRecordEncodingTests {

    @Test("Entries are length-prefixed key=value, sorted by key")
    func wireFormat() {
        let data = AppleServiceDiscovery.txtRecordData(["id": "AA:BB", "c#": "1"])
        var expected = Data()
        expected.append(4)
        expected.append(contentsOf: Array("c#=1".utf8))
        expected.append(8)
        expected.append(contentsOf: Array("id=AA:BB".utf8))
        #expect(data == expected)
    }

    @Test("Empty dictionary encodes as empty data")
    func emptyRecords() {
        #expect(AppleServiceDiscovery.txtRecordData([:]).isEmpty)
    }

    @Test("Entries longer than 255 bytes are truncated")
    func oversizedEntry() {
        let data = AppleServiceDiscovery.txtRecordData(["k": String(repeating: "x", count: 300)])
        #expect(data.count == 256)
        #expect(data.first == 255)
    }
}
#endif
