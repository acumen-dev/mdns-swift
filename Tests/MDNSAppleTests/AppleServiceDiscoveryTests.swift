// AppleServiceDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
import MDNSCore

// Compile-time and wire-format tests, plus live round-trip tests that
// advertise, browse and resolve against the system mDNS responder using a
// test-only service type (so they never surface in a real browse).

#if canImport(Network)
import Network
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
@Suite("Apple TXT bytes follow the shared RFC 6763 rule")
struct AppleTXTDecodingTests {

    @Test("The encoder's output decodes back to the same TXT")
    func encoderRoundTrip() {
        let records = ["D": "1234", "CM": "1", "SII": "5000"]
        let data = AppleServiceDiscovery.txtRecordData(records)
        #expect(TXTRecord.decode(wireFormat: data) == records)
    }

    /// Browse decodes `NWTXTRecord.data`; this pins that those bytes keep
    /// what the rule needs (bare keys, duplicate order).
    @Test("NWTXTRecord.data keeps bare keys and duplicate order for the shared rule")
    func nwTXTRecordBytes() {
        var wire = Data()
        for entry in ["D=1234", "flag", "e=", "D=9999"] {
            wire.append(UInt8(entry.utf8.count))
            wire.append(contentsOf: Array(entry.utf8))
        }
        let record = NWTXTRecord(wire)
        #expect(TXTRecord.decode(wireFormat: record.data) == ["D": "1234", "flag": "", "e": ""])
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

    /// Runs `operation` in its own task, cancels it once it has started, and
    /// reports how it ended: `nil` if it did not return before
    /// `guardDuration`, else whether it threw `CancellationError`. The wait is
    /// a cancellable stream read, so an operation that ignores cancellation
    /// fails the check instead of hanging the test.
    private static func cancelledOutcome(
        guardDuration: Duration = hangGuard,
        _ operation: @escaping @Sendable () async throws -> Void
    ) async -> Bool? {
        let (finished, signal) = AsyncStream<Bool>.makeStream()
        let task = Task {
            defer { signal.finish() }
            do {
                try await operation()
                signal.yield(false)
            } catch {
                signal.yield(error is CancellationError)
            }
        }
        // Long enough for the operation to be in flight; the assertion is only
        // that it returns, not when.
        try? await Task.sleep(for: .milliseconds(100))
        task.cancel()
        return await withTaskGroup(of: Bool?.self) { group in
            group.addTask {
                for await threwCancellation in finished { return threwCancellation }
                return nil
            }
            group.addTask {
                try? await Task.sleep(for: guardDuration)
                return nil
            }
            defer { group.cancelAll() }
            return await group.next()!
        }
    }

    @Test("cancelling resolve of an absent instance returns instead of hanging")
    func resolveHonoursCancellation() async {
        let discovery = AppleServiceDiscovery()
        let absent = ServiceRecord(
            name: "mdnstest-absent-\(UUID().uuidString)",
            serviceType: Self.serviceType,
            host: "",
            port: 0
        )
        let outcome = await Self.cancelledOutcome {
            _ = try await discovery.resolve(absent)
        }
        #expect(outcome == true, "resolve must throw CancellationError promptly (nil = hung)")
    }

    @Test("cancelling resolveService of an absent instance returns instead of hanging")
    func resolveServiceHonoursCancellation() async {
        let discovery = AppleServiceDiscovery()
        let absent = ServiceRecord(
            name: "mdnstest-absent-\(UUID().uuidString)",
            serviceType: Self.serviceType,
            host: "",
            port: 0
        )
        let outcome = await Self.cancelledOutcome {
            _ = try await discovery.resolveService(absent)
        }
        #expect(outcome == true, "resolveService must throw CancellationError promptly (nil = hung)")
    }

    @Test("resolveTXT for an absent instance throws when its timeout elapses")
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

    @Test("resolveService returns the address with empty TXT when the TXT can't be obtained")
    func resolveServiceWithoutTXT() async throws {
        let discovery = AppleServiceDiscovery()
        let record = Self.makeRecord()
        try await Self.withAdvertised(discovery, record) {
            let bare = ServiceRecord(name: record.name, serviceType: Self.serviceType, host: "", port: 0)
            let resolved = try await Self.withHangGuard("resolveService(TXT unavailable)") {
                try await discovery.resolveService(bare) { record in
                    throw ServiceDiscoveryError.resolveFailed(record.name)
                }
            }
            #expect(resolved.address.port == Self.port)
            #expect(resolved.txtRecords.isEmpty)
        }
    }

    @Test("browse yields an instance again when its TXT changes")
    func browseReyieldsChangedTXT() async throws {
        let discovery = AppleServiceDiscovery()
        let original = Self.makeRecord()
        let changedTXT = ["D": "1234", "CM": "0", "SII": "5000"]
        let changed = ServiceRecord(
            name: original.name,
            serviceType: Self.serviceType,
            host: "",
            port: Self.port,
            txtRecords: changedTXT,
            advertiseOnAllInterfaces: true
        )
        try await Self.withAdvertised(discovery, original) {
            try await Self.withHangGuard("browse re-yield on TXT change") {
                var readvertised = false
                var lastSeen: [String: String]?
                for await record in discovery.browse(serviceType: Self.serviceType) where record.name == original.name {
                    lastSeen = record.txtRecords
                    if !readvertised, record.txtRecords == Self.txt {
                        readvertised = true
                        try await discovery.advertise(service: changed)
                    } else if readvertised, record.txtRecords == changedTXT {
                        return
                    }
                }
                throw HangGuardExpired(
                    description: "browse ended before the changed TXT; readvertised=\(readvertised) lastSeen=\(String(describing: lastSeen))"
                )
            }
        }
    }
}
#endif
