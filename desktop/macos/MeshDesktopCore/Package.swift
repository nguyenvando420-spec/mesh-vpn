// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MeshDesktopCore",
    defaultLocalization: "en",
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
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "MeshDesktopCoreTests",
            dependencies: ["MeshDesktopCore"],
            path: "Tests/MeshDesktopCoreTests"
        )
    ]
)
