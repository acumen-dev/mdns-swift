// AppleServiceDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
import MDNSCore

// Network I/O tests (advertising, browsing, resolving) require a live mDNS
// environment and are exercised manually or in integration tests.
// This file verifies that the MDNSApple module compiles and types are correct.

#if canImport(Network)
import MDNSApple

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
#endif
