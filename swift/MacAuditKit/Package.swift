// swift-tools-version: 6.0
// MacAuditKit: the Swift face of the Rust engine. `Generated/` and the
// xcframework are produced by scripts/build-ffi.sh and are not committed.
import PackageDescription

let package = Package(
    name: "MacAuditKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MacAuditKit", targets: ["MacAuditKit"])
    ],
    targets: [
        .binaryTarget(name: "MacAuditFFI", path: "MacAuditFFI.xcframework"),
        .target(
            name: "MacAuditKit",
            dependencies: ["MacAuditFFI"],
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
        .testTarget(name: "MacAuditKitTests", dependencies: ["MacAuditKit"]),
    ],
    swiftLanguageModes: [.v6]
)
