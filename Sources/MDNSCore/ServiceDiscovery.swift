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

    public init(
        name: String,
        serviceType: ServiceType,
        host: String,
        port: UInt16,
        txtRecords: [String: String] = [:],
        subtypes: [String] = [],
        preferredInterface: String? = nil
    ) {
        self.name = name
        self.serviceType = serviceType
        self.host = host
        self.port = port
        self.txtRecords = txtRecords
        self.subtypes = subtypes
        self.preferredInterface = preferredInterface
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
    func resolve(_ record: ServiceRecord) async throws -> NetworkAddress

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
}
