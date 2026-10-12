// AppleServiceDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
import MDNSCore

// Compile-time and wire-format tests, plus live round-trip tests that
// advertise, browse and resolve against the system mDNS responder using a
// test-only service type (so they never surface in a real browse).

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
@Suite("TXT Record Decoding")
struct TXTRecordDecodingTests {

    @Test("Decoding inverts encoding")
    func roundTrip() {
        let records = ["D": "1234", "CM": "1", "SII": "5000"]
        let data = AppleServiceDiscovery.txtRecordData(records)
        #expect(AppleServiceDiscovery.txtRecords(from: data) == records)
    }

    @Test("Key with '=' and no value decodes as empty; bare key is dropped")
    func emptyAndBareKeys() {
        var data = Data()
        data.append(2)
        data.append(contentsOf: Array("a=".utf8))
        data.append(1)
        data.append(contentsOf: Array("b".utf8))
        #expect(AppleServiceDiscovery.txtRecords(from: data) == ["a": ""])
    }

    @Test("Truncated entry is ignored")
    func truncated() {
        var data = Data()
        data.append(10)
        data.append(contentsOf: Array("a=1".utf8))
        #expect(AppleServiceDiscovery.txtRecords(from: data).isEmpty)
    }

    @Test("Empty data decodes as empty TXT")
    func empty() {
        #expect(AppleServiceDiscovery.txtRecords(from: Data()).isEmpty)
    }
}

// MARK: - Live round-trip

/// Live tests against the system mDNS responder. A test-only service type and
/// a random instance name keep them off every real browse and away from each
/// other.
@Suite("AppleServiceDiscovery Live TXT Tests")
struct AppleServiceDiscoveryLiveTests {

    static let serviceType: ServiceType = "_mdnstest3b._udp"
    static let port: UInt16 = 51234
    static let txt = ["D": "1234", "CM": "1", "SII": "5000"]
    static let hangGuard: Duration = .seconds(30)

    struct HangGuardExpired: Error, CustomStringConvertible {
        let description: String
    }

    private static func makeRecord() -> ServiceRecord {
        ServiceRecord(
            name: "mdnstest-\(UUID().uuidString)",
            serviceType: serviceType,
            host: "",
            port: port,
            txtRecords: txt,
            advertiseOnAllInterfaces: true
        )
    }

    /// Advertises `record`, runs `body`, and always withdraws the advertisement.
    private static func withAdvertised<T: Sendable>(
        _ discovery: AppleServiceDiscovery,
        _ record: ServiceRecord,
        _ body: () async throws -> T
    ) async throws -> T {
        try await discovery.advertise(service: record)
        do {
            let result = try await body()
            await discovery.stopAdvertising(name: record.name)
            return result
        } catch {
            await discovery.stopAdvertising(name: record.name)
            throw error
        }
    }

    /// Races `body` against the hang guard.
    private static func withHangGuard<T: Sendable>(
        _ what: String,
        _ body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await body() }
            group.addTask {
                try await Task.sleep(for: hangGuard)
                throw HangGuardExpired(description: "hang guard expired: \(what)")
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    private enum BrowseOutcome: Sendable {
        case matched(ServiceRecord)
        case ended(lastSeen: [String: String]?, yields: Int)
        case hangGuard
    }

    /// Browses until a record named `name` arrives carrying `txt`. On hang-guard
    /// expiry, fails with the last TXT seen for that name.
    private static func browseForMatch(
        _ discovery: AppleServiceDiscovery,
        name: String,
        txt: [String: String]
    ) async throws -> ServiceRecord {
        let outcome = await withTaskGroup(of: BrowseOutcome.self) { group -> BrowseOutcome in
            group.addTask {
                var lastSeen: [String: String]?
                var yields = 0
                for await record in discovery.browse(serviceType: serviceType) where record.name == name {
                    yields += 1
                    lastSeen = record.txtRecords
                    if record.txtRecords == txt { return .matched(record) }
                }
                return .ended(lastSeen: lastSeen, yields: yields)
            }
            group.addTask {
                try? await Task.sleep(for: hangGuard)
                return .hangGuard
            }
            let first = await group.next()!
            group.cancelAll()
            if case .hangGuard = first {
                // Collect what the browse saw before it was cancelled.
                return await group.next()!
            }
            return first
        }
        guard case .matched(let record) = outcome else {
            throw HangGuardExpired(description: "browse never yielded the expected TXT; \(outcome)")
        }
        return record
    }

    @Test("browse yields the advertised instance with its TXT")
    func browseYieldsTXT() async throws {
        let discovery = AppleServiceDiscovery()
        let record = Self.makeRecord()
        try await Self.withAdvertised(discovery, record) {
            let found = try await Self.browseForMatch(discovery, name: record.name, txt: Self.txt)
            #expect(found.txtRecords == Self.txt)
            #expect(found.serviceType == Self.serviceType)
        }
    }

    @Test("resolveService on a browsed record returns the port and TXT")
    func resolveServiceOnBrowsedRecord() async throws {
        let discovery = AppleServiceDiscovery()
        let record = Self.makeRecord()
        try await Self.withAdvertised(discovery, record) {
            let found = try await Self.browseForMatch(discovery, name: record.name, txt: Self.txt)
            let resolved = try await Self.withHangGuard("resolveService(browsed)") {
                try await discovery.resolveService(found)
            }
            #expect(resolved.address.port == Self.port)
            #expect(resolved.txtRecords == Self.txt)
        }
    }

    @Test("resolveService on a bare name/type record looks the TXT up")
    func resolveServiceOnBareRecord() async throws {
        let discovery = AppleServiceDiscovery()
        let record = Self.makeRecord()
        try await Self.withAdvertised(discovery, record) {
            let bare = ServiceRecord(name: record.name, serviceType: Self.serviceType, host: "", port: 0)
            #expect(bare.txtRecords.isEmpty)
            let resolved = try await Self.withHangGuard("resolveService(bare)") {
                try await discovery.resolveService(bare)
            }
            #expect(resolved.address.port == Self.port)
            #expect(resolved.txtRecords == Self.txt)
        }
    }

    @Test("TXT lookup for an absent instance throws when its timeout elapses")
    func txtLookupTimesOut() async throws {
        let discovery = AppleServiceDiscovery()
        let absent = ServiceRecord(
            name: "mdnstest-absent-\(UUID().uuidString)",
            serviceType: Self.serviceType,
            host: "",
            port: 0
        )
        await #expect(throws: ServiceDiscoveryError.self) {
            try await Self.withHangGuard("resolveTXT(absent)") {
                try await discovery.resolveTXT(absent, timeout: .milliseconds(1))
            }
        }
    }
}
#endif
