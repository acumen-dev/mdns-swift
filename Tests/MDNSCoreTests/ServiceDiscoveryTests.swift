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
