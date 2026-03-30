# mdns-swift

Shared mDNS/DNS-SD service discovery for Swift — used by [matter-swift](https://github.com/monagle/matter-swift) and [hap-swift](https://github.com/monagle/hap-swift).

[![Swift 6.1+](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-macOS%20|%20iOS%20|%20Linux-blue.svg)](https://swift.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE.md)
[![CI](https://github.com/acumen-dev/mdns-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/acumen-dev/mdns-swift/actions/workflows/ci.yml)

## Overview

`mdns-swift` is a pure-Swift mDNS/DNS-SD service discovery library (RFC 6762) with platform-specific backends:

- **Apple platforms** — `NWBrowser` for browsing/resolving, `DNSServiceRegister` for advertising (supports DNS-SD subtypes required by Matter commissioning)
- **Linux** — Pure-Swift RFC 6762 responder over SwiftNIO; no system daemon dependency

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
    .package(url: "https://github.com/acumen-dev/mdns-swift.git", from: "0.1.0")
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

## Module Architecture

| Module | Purpose | Platforms |
|--------|---------|-----------|
| **MDNSCore** | `ServiceDiscovery` protocol, `ServiceRecord`, `ServiceType`, `NetworkAddress`. Zero platform dependencies. | All |
| **MDNSApple** | `AppleServiceDiscovery` using Network.framework + `dnssd`. | Apple only |
| **MDNSLinux** | `LinuxServiceDiscovery` using SwiftNIO + pure-Swift RFC 6762 codec. | All (primary target: Linux) |

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
| macOS | 15.0 |
| iOS | 18.0 |
| tvOS | 18.0 |
| watchOS | 11.0 |
| visionOS | 2.0 |
| Linux | Swift 6.1+ (Ubuntu 24.04 tested) |

## Dependencies

- [swift-log](https://github.com/apple/swift-log) 1.0+ — all targets
- [swift-nio](https://github.com/apple/swift-nio) 2.65+ — `MDNSLinux` only

## License

Licensed under the Apache License, Version 2.0. See [LICENSE.md](LICENSE.md) for details.
