// ServiceDiscoveryTests.swift
// Copyright 2026 Monagle Pty Ltd

import Testing
@testable import MDNSCore

@Suite("ServiceType Tests")
struct ServiceTypeTests {

    @Test("ServiceType rawValue round-trip")
    func rawValueRoundTrip() {
        let t = ServiceType("_hap._tcp")
        #expect(t.rawValue == "_hap._tcp")
        #expect(t.description == "_hap._tcp")
    }

    @Test("ServiceType equality")
    func equality() {
        let a = ServiceType("_hap._tcp")
        let b: ServiceType = "_hap._tcp"   // ExpressibleByStringLiteral
        let c = ServiceType(rawValue: "_hap._tcp")
        #expect(a == b)
        #expect(a == c)
    }

    @Test("ServiceType is Hashable")
    func hashable() {
        var set: Set<ServiceType> = ["_hap._tcp", "_matterc._udp"]
        set.insert("_hap._tcp")
        #expect(set.count == 2)
    }

    @Test("ServiceType extensions can add static members")
    func staticExtensions() {
        // Demonstrates the extension pattern consumers will use.
        #expect(ServiceType.hapAccessory.rawValue == "_hap._tcp")
    }
}

// Example of what matter-swift / hap-swift would do:
extension ServiceType {
    fileprivate static let hapAccessory = ServiceType("_hap._tcp")
}

@Suite("ServiceRecord Tests")
struct ServiceRecordTests {

    @Test("ServiceRecord stores all fields")
    func serviceRecordFields() {
        let record = ServiceRecord(
            name: "My Device",
            serviceType: ServiceType("_hap._tcp"),
            host: "192.168.1.1",
            port: 51826,
            txtRecords: ["id": "AA:BB:CC:DD:EE:FF"],
            subtypes: ["_pairing"],
            preferredInterface: "en0"
        )
        #expect(record.name == "My Device")
        #expect(record.serviceType == ServiceType("_hap._tcp"))
        #expect(record.host == "192.168.1.1")
        #expect(record.port == 51826)
        #expect(record.txtRecords["id"] == "AA:BB:CC:DD:EE:FF")
        #expect(record.subtypes == ["_pairing"])
        #expect(record.preferredInterface == "en0")
    }

    @Test("ServiceRecord defaults")
    func serviceRecordDefaults() {
        let record = ServiceRecord(name: "X", serviceType: ServiceType("_test._tcp"), host: "", port: 0)
        #expect(record.txtRecords.isEmpty)
        #expect(record.subtypes.isEmpty)
        #expect(record.preferredInterface == nil)
    }
}

@Suite("NetworkAddress Tests")
struct NetworkAddressTests {

    @Test("NetworkAddress stores host and port")
    func networkAddressFields() {
        let addr = NetworkAddress(host: "192.168.1.1", port: 5540)
        #expect(addr.host == "192.168.1.1")
        #expect(addr.port == 5540)
    }

    @Test("NetworkAddress is Hashable")
    func networkAddressHashable() {
        let a = NetworkAddress(host: "::1", port: 51826)
        let b = NetworkAddress(host: "::1", port: 51826)
        let c = NetworkAddress(host: "::1", port: 5540)
        #expect(a == b)
        #expect(a != c)
        var set = Set<NetworkAddress>()
        set.insert(a)
        set.insert(b)
        #expect(set.count == 1)
    }
}

@Suite("ResolvedService Tests")
struct ResolvedServiceTests {

    /// A conformer that predates `resolveService` and implements only `resolve`.
    private struct AddressOnlyDiscovery: ServiceDiscovery {
        let address: NetworkAddress
        func advertise(service: ServiceRecord) async throws {}
        func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord> {
            AsyncStream { $0.finish() }
        }
        func resolve(_ record: ServiceRecord) async throws -> NetworkAddress { address }
        func stopAdvertising() async {}
    }

    @Test("Default resolveService returns the resolved address and the record's TXT")
    func defaultResolveService() async throws {
        let address = NetworkAddress(host: "fe80::1", port: 5540)
        let discovery = AddressOnlyDiscovery(address: address)
        let record = ServiceRecord(
            name: "Instance",
            serviceType: "_test._udp",
            host: "",
            port: 0,
            txtRecords: ["D": "1234", "CM": "1"]
        )
        let resolved = try await discovery.resolveService(record)
        #expect(resolved.address == address)
        #expect(resolved.txtRecords == ["D": "1234", "CM": "1"])
    }

    @Test("ResolvedService defaults to empty TXT and is Hashable")
    func resolvedServiceDefaults() {
        let a = ResolvedService(address: NetworkAddress(host: "::1", port: 1))
        let b = ResolvedService(address: NetworkAddress(host: "::1", port: 1), txtRecords: [:])
        #expect(a.txtRecords.isEmpty)
        #expect(a == b)
        #expect(Set([a, b]).count == 1)
    }
}

@Suite("TXTRecord decoding (RFC 6763 §6)")
struct TXTRecordDecodeTests {

    @Test("key=value, key= and bare key")
    func valueForms() {
        #expect(TXTRecord.decode(["a=1", "b=", "c"]) == ["a": "1", "b": "", "c": ""])
    }

    @Test("Only the first '=' separates key from value")
    func valueContainsEquals() {
        #expect(TXTRecord.decode(["k=a=b"]) == ["k": "a=b"])
    }

    @Test("Duplicate keys: the first occurrence wins, compared case-insensitively")
    func duplicates() {
        #expect(TXTRecord.decode(["D=1", "D=2"]) == ["D": "1"])
        #expect(TXTRecord.decode(["D=1", "d=2"]) == ["D": "1"])
        #expect(TXTRecord.decode(["flag", "flag=x"]) == ["flag": ""])
    }

    @Test("Keys are preserved as received")
    func keyCasePreserved() {
        #expect(TXTRecord.decode(["Sii=5000"]) == ["Sii": "5000"])
    }

    @Test("Empty strings and strings with no key are ignored")
    func emptyAndKeyless() {
        #expect(TXTRecord.decode([""]) == [:])
        #expect(TXTRecord.decode([]) == [:])
        #expect(TXTRecord.decode(["=x", "", "a=1"]) == ["a": "1"])
    }

    @Test("Wire format: length-prefixed strings decode by the same rule")
    func wireFormat() {
        var bytes: [UInt8] = []
        for entry in ["D=1234", "flag", "D=9"] {
            bytes.append(UInt8(entry.utf8.count))
            bytes.append(contentsOf: entry.utf8)
        }
        #expect(TXTRecord.decode(wireFormat: bytes) == ["D": "1234", "flag": ""])
    }

    @Test("Wire format: a single empty string decodes to empty TXT")
    func wireFormatSingleEmptyString() {
        #expect(TXTRecord.decode(wireFormat: [0]) == [:])
        #expect(TXTRecord.decode(wireFormat: [UInt8]()) == [:])
    }

    @Test("Wire format: an entry overrunning the buffer ends decoding")
    func wireFormatTruncated() {
        var bytes: [UInt8] = [3]
        bytes.append(contentsOf: "a=1".utf8)
        bytes.append(10)
        bytes.append(contentsOf: "b=2".utf8)
        #expect(TXTRecord.decode(wireFormat: bytes) == ["a": "1"])
    }

    // MARK: Malformed input (pinned)

    @Test("A 255-byte entry is kept whole")
    func maximumLengthEntry() {
        let value = String(repeating: "v", count: 253)
        var bytes: [UInt8] = [255]
        bytes.append(contentsOf: "k=\(value)".utf8)
        #expect(TXTRecord.decode(wireFormat: bytes) == ["k": value])
        #expect(TXTRecord.decode(["k=\(value)"]) == ["k": value])
    }

    @Test("Non-UTF-8 value bytes are replaced with U+FFFD and the key is kept")
    func nonUTF8Value() {
        let entry: [UInt8] = Array("k=".utf8) + [0xFF, 0x41]
        let bytes: [UInt8] = [UInt8(entry.count)] + entry
        #expect(TXTRecord.decode(wireFormat: bytes) == ["k": "\u{FFFD}A"])
    }

    @Test("An entry with no key ('=v') is dropped")
    func keylessEntryDropped() {
        #expect(TXTRecord.decode(["=v"]) == [:])
        #expect(TXTRecord.decode(wireFormat: [2] + Array("=v".utf8)) == [:])
    }

    @Test("The split is at the first '=' byte, even when a combining mark follows it")
    func combiningMarkAfterEquals() {
        #expect(TXTRecord.decode(["a=\u{301}b"]) == ["a": "\u{301}b"])
    }

    @Test("Duplicate detection lowercases ASCII only: the Kelvin sign is not 'k'")
    func kelvinSignIsNotK() {
        #expect(TXTRecord.decode(["k=1", "\u{212A}=2"]) == ["k": "1", "\u{212A}": "2"])
    }
}
