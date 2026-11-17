// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MeshDesktopCore",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "MeshDesktopCore",
            targets: ["MeshDesktopCore"]
        )
    ],
    targets: [
        .target(
            name: "MeshDesktopCore",
            path: "Sources/MeshDesktopCore",
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "MeshDesktopCoreTests",
            dependencies: ["MeshDesktopCore"],
            path: "Tests/MeshDesktopCoreTests",
            swiftSettings: [
                .enableUpcomingFeature("StrictConcurrency")
            ]
        )
    ]
)
