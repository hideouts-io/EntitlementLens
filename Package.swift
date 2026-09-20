// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "EntitlementLens",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "EntitlementLens", targets: ["EntitlementLens"]),
        .executable(name: "EntitlementLensPrivilegedHelper", targets: ["EntitlementLensPrivilegedHelper"])
    ],
    targets: [
        .target(name: "PrivilegedProtocol"),
        .executableTarget(
            name: "EntitlementLens",
            dependencies: ["PrivilegedProtocol"],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("ServiceManagement")
            ]
        ),
        .executableTarget(
            name: "EntitlementLensPrivilegedHelper",
            dependencies: ["PrivilegedProtocol"],
            linkerSettings: [
                .linkedFramework("Security")
            ]
        ),
        .testTarget(
            name: "EntitlementLensTests",
            dependencies: ["EntitlementLens"]
        )
    ]
)
