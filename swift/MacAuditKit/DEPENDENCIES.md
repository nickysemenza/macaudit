# Reproducible Swift dependency graph

MacAuditKit uses Swift 6 language mode with a Swift 6.0 tools floor. Native CI selects Xcode 26.3 (Swift 6.2). The root manifest pins transitive packages as well as its three required direct dependencies so resolving with a newer SDK cannot silently raise that floor.

| Package | Exact version | Selected manifest tools floor |
| --- | --- | --- |
| swift-collections | 1.2.1 | 5.10 |
| swift-navigation | 2.4.2 | 6.0 (`Package@swift-6.0.swift`) |
| swift-snapshot-testing | 1.19.6 | 6.0 |
| swift-case-paths | 1.5.6 | 6.0 (`Package@swift-6.0.swift`) |
| swift-concurrency-extras | 1.2.0 | 6.0 (`Package@swift-6.0.swift`) |
| swift-custom-dump | 1.3.3 | 6.0 (`Package@swift-6.0.swift`) |
| swift-perception | 1.4.1 | 5.9 |
| xctest-dynamic-overlay | 1.4.1 | 6.0 (`Package@swift-6.0.swift`) |
| swift-syntax | 600.0.1 | 5.8 |

Syntax 600 is within the macro packages' declared ranges and matches the minimum Swift 6.0 compiler generation. SnapshotTesting remains test-only. The navigation and collections wrapper products expose their respective libraries to the native app without adding SnapshotTesting to its production graph.

`Package.resolved` records the complete product-selected graph and exact revisions. The app's separately owned `apps/MacAudit/Package.resolved` must contain the same pins after package resolution; Xcode's generated workspace lock should mirror that file. Do not regenerate locks with unconstrained transitive versions or use dependency updates as part of normal builds.

After downgrading an existing Swift 6.4 workspace, resolve once with `swift package --package-path swift/MacAuditKit --manifest-cache none --disable-build-manifest-caching resolve`. A cached newer manifest can otherwise retain the removed CustomDump `FoundationNetworking` trait. Normal verification uses `swift test --package-path swift/MacAuditKit --force-resolved-versions`.

Validation must distinguish manifest compatibility from actual compilation. A passing build with a newer compiler is not evidence that Xcode 26.3 or Swift 6.0 compiles the graph. The CI Xcode 26.3 job is the native compiler check; a Swift 6.0 toolchain build is the separate minimum-floor check when that toolchain is available.
