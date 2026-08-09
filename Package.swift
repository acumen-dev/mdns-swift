// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "mdns-swift",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .tvOS(.v17),
        .watchOS(.v10),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "MDNSCore",  targets: ["MDNSCore"]),
        .library(name: "MDNSApple", targets: ["MDNSApple"]),
        .library(name: "MDNSLinux", targets: ["MDNSLinux"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
    ],
    targets: [
        .target(
            name: "MDNSCore",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .target(
            name: "MDNSApple",
            dependencies: [
                "MDNSCore",
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .target(
            name: "MDNSLinux",
            dependencies: [
                "MDNSCore",
                .product(name: "NIOCore",  package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "Logging",  package: "swift-log"),
            ]
        ),
        .testTarget(name: "MDNSCoreTests",  dependencies: ["MDNSCore"]),
        .testTarget(name: "MDNSAppleTests", dependencies: ["MDNSApple"]),
        .testTarget(name: "MDNSLinuxTests", dependencies: ["MDNSLinux"]),
    ]
)
