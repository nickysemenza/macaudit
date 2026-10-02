// swift-tools-version: 6.0
// MacAuditKit: the Swift face of the Rust engine. `Generated/` and the
// xcframework are produced by scripts/build-ffi.sh and are not committed.
import PackageDescription

let package = Package(
    name: "MacAuditKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MacAuditKit", targets: ["MacAuditKit"]),
        .library(name: "MacAuditNavigation", targets: ["MacAuditNavigation"]),
        .library(name: "MacAuditCollections", targets: ["MacAuditCollections"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-collections", exact: "1.2.1"),
        .package(url: "https://github.com/pointfreeco/swift-navigation", exact: "2.4.2"),
        .package(url: "https://github.com/pointfreeco/swift-snapshot-testing", exact: "1.19.6"),
        .package(url: "https://github.com/pointfreeco/swift-case-paths", exact: "1.5.6"),
        .package(url: "https://github.com/pointfreeco/swift-concurrency-extras", exact: "1.2.0"),
        .package(url: "https://github.com/pointfreeco/swift-custom-dump", exact: "1.3.3"),
        .package(url: "https://github.com/pointfreeco/swift-perception", exact: "1.4.1"),
        .package(url: "https://github.com/pointfreeco/xctest-dynamic-overlay", exact: "1.4.1"),
        .package(url: "https://github.com/swiftlang/swift-syntax", exact: "600.0.1"),
    ],
    targets: [
        .binaryTarget(name: "MacAuditFFI", path: "MacAuditFFI.xcframework"),
        .target(
            name: "MacAuditKit",
            dependencies: ["MacAuditFFI",
                .product(name: "OrderedCollections", package: "swift-collections"),
                .product(name: "DequeModule", package: "swift-collections"),
            ],
            linkerSettings: [
                // What the Rust static library needs at final link; build
                // scripts' link directives do not survive into a .a. Keep in
                // sync with `--print native-static-libs` (see build-ffi.sh).
                .linkedFramework("Foundation"),
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
                .linkedLibrary("objc"),
                .linkedLibrary("iconv"),
            ]
        ),
        .target(name: "MacAuditNavigation", dependencies: [
            .product(name: "SwiftUINavigation", package: "swift-navigation"),
        ]),
        .target(name: "MacAuditCollections", dependencies: [
            .product(name: "OrderedCollections", package: "swift-collections"),
            .product(name: "DequeModule", package: "swift-collections"),
        ]),
        .testTarget(name: "MacAuditKitTests", dependencies: ["MacAuditKit",
            .product(name: "SnapshotTesting", package: "swift-snapshot-testing"),
        ]),
    ],
    swiftLanguageModes: [.v6]
)
