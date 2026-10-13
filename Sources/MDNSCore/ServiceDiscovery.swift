// ServiceDiscovery.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

// MARK: - ServiceType

/// A DNS-SD service type string (e.g. `"_hap._tcp"` or `"_matterc._udp"`).
///
/// Use this type instead of raw strings for service type values. Consumers can
/// add their own static members via extension:
///
/// ```swift
/// // In matter-swift:
/// extension ServiceType {
///     public static let commissionable = ServiceType("_matterc._udp")
///     public static let operational    = ServiceType("_matter._tcp")
/// }
///
/// // In hap-swift:
/// extension ServiceType {
///     public static let accessory = ServiceType("_hap._tcp")
/// }
/// ```
public struct ServiceType: RawRepresentable, Sendable, Hashable, ExpressibleByStringLiteral {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    public init(stringLiteral value: String) {
        self.rawValue = value
    }
}

extension ServiceType: CustomStringConvertible {
    public var description: String { rawValue }
}

// MARK: - ServiceRecord

/// A discovered or advertised service record.
public struct ServiceRecord: Sendable {
    /// Human-readable service instance name (e.g. `"My Bridge"`).
    public let name: String
    /// DNS-SD service type (e.g. `.commissionable`, `.accessory`).
    public let serviceType: ServiceType
    /// Resolved hostname, or empty string when not yet resolved.
    public let host: String
    /// Port number.
    public let port: UInt16
    /// DNS-SD TXT record key/value pairs.
    public let txtRecords: [String: String]
    /// DNS-SD subtypes to register alongside the primary service type.
    ///
    /// For example, `["_CM", "_L3840", "_S15"]` alongside `"_matterc._udp"` registers
    /// `_CM._sub._matterc._udp` etc., enabling filtered browsing.
    public let subtypes: [String]
    /// Preferred network interface name hint — advisory only.
    ///
    /// Implementations may use this to restrict advertisement to a specific interface.
    /// Passing `nil` means no preference.
    public let preferredInterface: String?

    /// When `true`, the service is advertised on all network interfaces (`ifIndex = 0`).
    ///
    /// Use this for protocols that must be reachable from any interface — for example,
    /// HAP accessories need to be discoverable by iOS whether the Mac is connected via
    /// Ethernet or Wi-Fi. The default (`false`) restricts advertisement to the primary
    /// LAN interface, which prevents VPN/Tailscale addresses from interfering with
    /// protocols like Matter that rely on specific link addresses for session establishment.
    public let advertiseOnAllInterfaces: Bool

    public init(
        name: String,
        serviceType: ServiceType,
        host: String,
        port: UInt16,
        txtRecords: [String: String] = [:],
        subtypes: [String] = [],
        preferredInterface: String? = nil,
        advertiseOnAllInterfaces: Bool = false
    ) {
        self.name = name
        self.serviceType = serviceType
        self.host = host
        self.port = port
        self.txtRecords = txtRecords
        self.subtypes = subtypes
        self.preferredInterface = preferredInterface
        self.advertiseOnAllInterfaces = advertiseOnAllInterfaces
    }
}

// MARK: - NetworkAddress

/// A resolved network address (host + port).
public struct NetworkAddress: Sendable, Hashable {
    public let host: String
    public let port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }
}

// MARK: - ResolvedService

/// A resolved DNS-SD service instance: where to connect, plus its TXT record.
public struct ResolvedService: Sendable, Hashable {
    public let address: NetworkAddress
    public let txtRecords: [String: String]

    public init(address: NetworkAddress, txtRecords: [String: String] = [:]) {
        self.address = address
        self.txtRecords = txtRecords
    }
}

// MARK: - TXTRecord

/// DNS-SD TXT record decoding (RFC 6763 §6), shared by every platform
/// implementation so browse and resolve results follow one rule:
///
/// - `key=value` → `value`; `key=` → `""`; a bare `key` (no `=`) → `""`.
/// - Each entry splits at its first `=` byte, so a value may itself contain
///   `=`, and a combining mark after the `=` stays in the value.
/// - Empty strings, and strings beginning with `=` (no key), are ignored —
///   so a TXT record holding a single empty string decodes to `[:]`.
/// - Keys are kept as received. Keys compare case-insensitively over ASCII
///   only (§6.4 keys are printable US-ASCII), and when a key repeats, the
///   first occurrence wins.
/// - Bytes that are not valid UTF-8 are replaced with U+FFFD; the entry is
///   kept.
package enum TXTRecord {

    /// Decode TXT character-strings, in the order received.
    package static func decode(_ strings: [String]) -> [String: String] {
        decode(entries: strings.map { Array($0.utf8) })
    }

    /// Decode a TXT record in wire format: a sequence of character-strings,
    /// each a length byte followed by that many bytes. An entry that overruns
    /// the buffer ends decoding.
    package static func decode(wireFormat bytes: some Collection<UInt8>) -> [String: String] {
        let bytes = Array(bytes)
        var entries: [ArraySlice<UInt8>] = []
        var index = 0
        while index < bytes.count {
            let length = Int(bytes[index])
            index += 1
            guard index + length <= bytes.count else { break }
            entries.append(bytes[index ..< index + length])
            index += length
        }
        return decode(entries: entries)
    }

    private static let equalsSign = UInt8(ascii: "=")

    private static func decode<Entry: Collection<UInt8>>(entries: [Entry]) -> [String: String] {
        var records: [String: String] = [:]
        var seen: Set<[UInt8]> = []
        for entry in entries {
            let separator = entry.firstIndex(of: equalsSign)
            let key = entry[..<(separator ?? entry.endIndex)]
            let value = separator.map { entry[entry.index(after: $0)...] } ?? entry[entry.endIndex...]
            guard !key.isEmpty, seen.insert(key.map(asciiLowercased)).inserted else { continue }
            records[String(decoding: key, as: UTF8.self)] = String(decoding: value, as: UTF8.self)
        }
        return records
    }

    private static func asciiLowercased(_ byte: UInt8) -> UInt8 {
        (UInt8(ascii: "A") ... UInt8(ascii: "Z")).contains(byte) ? byte | 0x20 : byte
    }
}

// MARK: - ServiceDiscovery

/// Platform-agnostic mDNS/DNS-SD service discovery protocol.
///
/// Implementations provide platform-specific service discovery:
/// - `MDNSApple`: `NWBrowser` / `DNSServiceRegister`
/// - `MDNSLinux`: pure-Swift RFC 6762 mDNS responder
public protocol ServiceDiscovery: Sendable {
    /// Advertise a service on the local network.
    ///
    /// Multiple services can be advertised simultaneously.
    /// Each service is identified by its `name` — advertising a service with the same name
    /// replaces the previous advertisement.
    func advertise(service: ServiceRecord) async throws

    /// Browse for services of a given type.
    ///
    /// Returns an `AsyncStream` that yields records as they are discovered.
    func browse(serviceType: ServiceType) -> AsyncStream<ServiceRecord>

    /// Resolve a discovered service record to a network address.
    ///
    /// Must honour task cancellation: a cancelled resolve stops and throws
    /// promptly (`CancellationError`). Resolution may otherwise wait
    /// indefinitely for an instance that never answers, so callers bound it
    /// by cancelling.
    func resolve(_ record: ServiceRecord) async throws -> NetworkAddress

    /// Resolves an instance to its address and TXT record.
    ///
    /// `txtRecords` is empty when the instance's TXT could not be obtained;
    /// address resolution failure throws. Must honour task cancellation as
    /// ``resolve(_:)`` does: callers bound it by cancelling.
    func resolveService(_ record: ServiceRecord) async throws -> ResolvedService

    /// Stop all active advertisements.
    func stopAdvertising() async

    /// Stop advertising a specific service by name.
    func stopAdvertising(name: String) async
}

extension ServiceDiscovery {
    /// Default implementation: stop all advertisements.
    public func stopAdvertising(name: String) async {
        await stopAdvertising()
    }

    /// Default for conformers that predate TXT resolution: address only,
    /// plus whatever TXT the browse result carried.
    public func resolveService(_ record: ServiceRecord) async throws -> ResolvedService {
        ResolvedService(address: try await resolve(record), txtRecords: record.txtRecords)
    }
}
