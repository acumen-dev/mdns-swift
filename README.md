# mdns-swift

Shared mDNS/DNS-SD service discovery for Swift — used by [matter-swift](https://github.com/monagle/matter-swift) and [hap-swift](https://github.com/monagle/hap-swift).

[![Swift 6.1+](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20|%20iOS%20|%20Linux-blue.svg)](https://swift.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE.md)
[![CI](https://github.com/acumen-dev/mdns-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/acumen-dev/mdns-swift/actions/workflows/ci.yml)

## Overview

`mdns-swift` is a pure-Swift mDNS/DNS-SD service discovery library (RFC 6762) with platform-specific backends:

- **Apple platforms** — `NWBrowser` for browsing/resolving, `DNSServiceRegister` for advertising (supports DNS-SD subtypes required by Matter commissioning)
- **Linux** — Pure-Swift RFC 6762 over SwiftNIO, no system daemon dependency: a responder (advertising) and a DNS-SD consumer (browse, plus resolve to address, port and TXT)

The library is intentionally protocol-agnostic. Consumers define their own service types via `ServiceType` extensions:

```swift
// In matter-swift
extension ServiceType {
    public static let commissionable: ServiceType = "_matterc._udp"
    public static let operational:    ServiceType = "_matter._tcp"
}

// In hap-swift
extension ServiceType {
    public static let hapAccessory: ServiceType = "_hap._tcp"
}
```

## Quick Start

Add `mdns-swift` to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/acumen-dev/mdns-swift.git", from: "1.0.0")
]
```

### Advertise a service

```swift
import MDNSCore
#if canImport(Network)
import MDNSApple
let discovery: any ServiceDiscovery = AppleServiceDiscovery()
#else
import MDNSLinux
let discovery: any ServiceDiscovery = LinuxServiceDiscovery()
#endif

try await discovery.advertise(service: ServiceRecord(
    name: "My Bridge",
    serviceType: "_hap._tcp",
    host: "",
    port: 51826,
    txtRecords: ["id": "AA:BB:CC:DD:EE:FF", "c#": "1"]
))
```

### Browse for services

```swift
for await record in discovery.browse(serviceType: "_hap._tcp") {
    print("Found: \(record.name) (port \(record.port))")
}
```

### Resolve to a network address

```swift
let address = try await discovery.resolve(record)
print("Connecting to \(address.host):\(address.port)")
```

`resolveService` returns the address together with the instance's TXT record, as a `ResolvedService`:

```swift
let resolved = try await discovery.resolveService(record)
print("\(resolved.address.host):\(resolved.address.port) TXT \(resolved.txtRecords)")
```

The contract for both:

- `txtRecords` may be empty when the instance's TXT could not be obtained; failing to resolve the address throws.
- Both must honour task cancellation, throwing `CancellationError` promptly. A resolve may otherwise wait indefinitely for an instance that never answers, so callers bound it by cancelling.
- A conformer that implements only `resolve` gets a default `resolveService`: the resolved address plus whatever TXT the browse result carried.

#### Host forms

`NetworkAddress.host` is one of:

- an IPv4 dotted quad (`"192.0.2.10"`);
- a bracketed IPv6 literal (`"[fd00::1]"`) — the RFC 3986 URL-host form. Strip the brackets before handing it to a socket API (`inet_pton`, `getaddrinfo`, NIO's `SocketAddress(ipAddress:port:)`). Both backends write the canonical compressed form `inet_ntop` produces (RFC 5952), the form the socket layer reports for a datagram's sender;
- on Apple platforms, `"<instance>.local"` when the resolved address is interface-scoped (scoped IPv6, typically link-local, or scoped IPv4 link-local), since the scope cannot travel in a portable string. The port is still the resolved one.

`MDNSLinux` carries no interface scope; a link-local address comes back as an unscoped literal.

## Module Architecture

| Module | Purpose | Platforms |
|--------|---------|-----------|
| **MDNSCore** | `ServiceDiscovery` protocol, `ServiceRecord`, `ServiceType`, `NetworkAddress`, `ResolvedService`. Zero platform dependencies. | All |
| **MDNSApple** | `AppleServiceDiscovery` using Network.framework + `dnssd`. | Apple only |
| **MDNSLinux** | `LinuxServiceDiscovery` using SwiftNIO + pure-Swift RFC 6762 codec: responder and DNS-SD consumer (browse/resolve). | All (primary target: Linux) |

```
MDNSCore
    ↑
├── MDNSApple   (Apple platforms)
└── MDNSLinux   (Linux / cross-platform)
```

## Service Types

`ServiceType` is a `RawRepresentable` struct backed by the DNS-SD string (e.g. `"_hap._tcp"`). It conforms to `ExpressibleByStringLiteral` and `Hashable`, so consumers add typed static members via Swift extensions:

```swift
extension ServiceType {
    static let myService: ServiceType = "_myservice._tcp"
}

// Both of these work:
discovery.browse(serviceType: .myService)
discovery.browse(serviceType: "_myservice._tcp")
```

## Platform Requirements

| Platform | Minimum Version |
|----------|----------------|
| macOS | 14.0 |
| iOS | 17.0 |
| tvOS | 17.0 |
| watchOS | 10.0 |
| visionOS | 1.0 |
| Linux | Swift 6.1+ (Ubuntu 24.04 tested) |

## Dependencies

- [swift-log](https://github.com/apple/swift-log) 1.0+ — all targets
- [swift-nio](https://github.com/apple/swift-nio) 2.65+ — `MDNSLinux` only

## License

Licensed under the Apache License, Version 2.0. See [LICENSE.md](LICENSE.md) for details.
