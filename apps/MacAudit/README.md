# Native application validation

The generated Xcode project is ignored. `Package.resolved` here is the tracked
Xcode dependency graph; XcodeGen copies it into the generated workspace. The
local MacAuditKit manifest owns the pinned navigation and collections products.
SnapshotTesting is linked only to the app test target.

After the bridge owner produces the FFI bindings and XCFramework, from the repo
root run:

```sh
xcodegen generate --spec apps/MacAudit/project.yml
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild \
  -project apps/MacAudit/MacAudit.xcodeproj -scheme MacAudit \
  -destination 'platform=macOS' -onlyUsePackageVersionsFromResolvedFile \
  -skipMacroValidation \
  CODE_SIGNING_ALLOWED=NO test
```

The test scheme sets `MACAUDIT_APP_TESTS=1`. The app host does not instantiate a
real engine or launch a scan in tests; deterministic injected engines exercise
navigation, cache eviction, run invalidation, cleanup gating, and scene budgets.
Non-test launches honor `MACAUDIT_HOME` for both the engine's home override and
the initial Explore root; XCTest hosts always use `/fixture` and no real engine.
The Home override also anchors `~` and relative GUI paths. Root admission is
serialized and disables cleanup/refresh until validation finishes. Rejected
roots preserve the previous root, run, and presentation; accepted runs clear
presentation before activating their buffered mailbox. No prevalidation cancel
is sent to the engine.
After an intentional dependency update, resolve in Xcode, copy the workspace's
`xcshareddata/swiftpm/Package.resolved` back here, and review all changed pins.
Packaging and verification scripts must generate the project first and use
`-onlyUsePackageVersionsFromResolvedFile`; do not silently re-resolve release pins.
The app lock has nine exact pins, including SwiftSyntax 600.0.1 and compatible
transitive versions constrained by MacAuditKit. Matching pins and manifest tools
floors do not prove compilation on an older Swift/Xcode toolchain.

For a host-only Release check against an arm64 FFI build,
use the same flags with `-configuration Release`,
`-destination 'platform=macOS,arch=arm64'`, `ARCHS=arm64`, and
`ONLY_ACTIVE_ARCH=YES`. Use `scripts/build-ffi.sh --release` first for an optimized
engine. This is not a universal distribution check or a full-application
benchmark. Default Release builds also require the Intel slice;
produce a matching `scripts/build-ffi.sh --release --universal` framework before
universal packaging. The existing distribution remains arm64-only. The bridge
build rejects standard libraries whose deployment floor is newer than macOS 14,
before replacing generated artifacts. Use official Rust 1.93: local Homebrew
Rust 1.98.1 embeds a macOS 26 standard library despite setting the application
deployment target to 14. A compatible link still does not prove macOS 14 runtime
behavior.

Explore has separate sources of truth: indexed folder allocation drives the
treemap and folder table; direct files remain residual Other mass. The live file
table and inspector label their observation time and never contribute live
metadata to scan allocation. Icons use SF Symbols, with no disk icon cache.
Whole-root search matches directory and file names or relative paths without
reading file contents. Its combined result cap is 1,000; live file matches have
their own observation time, coverage, cancellation and truncation state. File
selection does not navigate a file as a directory or change scanned allocation.
Cancel keeps current-run partial rows available while worker retirement is
reconciled; Refresh invalidates the cancelled run and all pending responses.
Audit location filters use engine-paginated path-component boundaries, including
findings beyond already loaded pages. Outside-root links reveal in Finder without
replacing the selected root or run.
Scan tables and inspectors say "Unique files", not directory entries. Root
accounting distinguishes observed directory entries from unique charged files,
and labels optional entry/external-link counts unknown when absent rather than
reporting an exact zero for partial scans. Allocation is not reclaimable space;
external hard links and shared extents can retain storage after deletion.
Audit uses authoritative run/revision/request-fenced pages of 500 rows with a
four-page LRU, not mailbox findings as a complete dataset. Page controls support
Option-Command-Left/Right; table selection uses native keyboard navigation and
Space marks findings. Search, sorting, charts and overview category amounts are
explicitly bounded loaded-page samples. Whole-scan reclaimable aggregates are
not inferred from these samples. Cleanup retains at most 256 marked findings.
Inventory revision wakeups coalesce on a 150 ms cadence and refresh the current
directory/owner before section completion; progress-only wakeups do not requery.
Treemap geometry uses run/path/local node revision and loaded-row count, never
live-file observation timestamps or unrelated Audit revisions. The Global Audit
volume bar reports used space only; overlapping loaded category samples are not
treated as a disjoint allocation partition or used to infer unscanned space.

For unattended builds, `-skipMacroValidation` explicitly trusts the pinned
Point-Free macro packages without storing an Xcode preference. Review those
sources/pins before using this opt-in; interactive Xcode can approve them instead.

Optional `MACAUDIT_TRACE=1` emits at most 512 native timing records per process
to stderr. Records cover directory/name/Audit/owner query waits, scene layout
and cache hits, metadata decoding, and small MainActor installation intervals.
They include numeric run/request/generation/revision context when available,
never paths or finding metadata. There is no OS logger, file logger, preference,
or trace persistence. Query elapsed time includes scheduling and bridge waits;
`work=main_actor` covers installation only, not all SwiftUI rendering. These
records are diagnostic observations, not a native speed benchmark or a complete
main-thread profile. Trace output itself can affect timings; leave it disabled
for normal use.

The app tests include a deterministic treemap presentation-text snapshot and
fixed 800 × 600 NSHostingView image fixtures for treemap selection, the indexed
and live tables, the inspector, and empty/error states. Every OS runs a rendering
smoke test and retains its five images as xcresult attachments. Pixel comparison
tests run only on macOS 15 and skip elsewhere: a newer OS cannot create valid
macOS 15 references. Normal CI also explicitly skips missing references, with a
message stating that image comparison is not verified; smoke rendering still runs.
Fixtures inject fake engines rooted at `/fixture`, reject scan roots outside that
fixture, force light appearance, English/POSIX locale and UTC, request disabled
animations, and normalize capture to 800 × 600 pixels.

On the pinned macOS 15 runner with the CI-selected Xcode 26.3 toolchain, explicitly
record references with the `MacAuditSnapshotReferences` scheme and
`-only-testing:MacAuditAppTests/RenderedPresentationTests`, using the build flags
above. SnapshotTesting reports recording as a test failure so the new images must
be reviewed. Retrieve the five PNGs from
`apptests/__Snapshots__/RenderedPresentationTests`, review and check them into
source control, then rerun with the normal `MacAudit` scheme to compare. Run the
separate `MacAuditSnapshotValidation` scheme as the required release gate: it fails
if the OS is not macOS 15 or any reference is missing, and never records a baseline.
No image references have been verified or committed yet; normal CI skips are not
a passed image-comparison gate. No macOS 27 captures are checked in as macOS 15
goldens. Rendering smoke tests do not verify actual keyboard/VoiceOver interactions.

App windows explicitly disable AppKit restoration, snapshot restoration, and
frame autosave. The app does not read or write preferences or an application state
file. Actual macOS 14 runtime/filesystem verification remains a release gate;
builds and the window-policy unit test do not certify OS-owned files.
Root selection deliberately uses the enum-backed in-memory path sheet with Home,
Boot Volume, and arbitrary typed paths (including `~/cf-repos`), not NSOpenPanel.
Apple's public `NSSavePanel.identifier` documentation and SDK header describe
directory state saved/restored through user defaults; no documented
persistence-free guarantee was found. Disabling owned-window restoration is not
claimed to disable panel preferences. Removing the panel avoids that app-scoped
panel-state surface without private APIs, swizzling, or preferences mutations.

Presentation is memory-only: directory LRU 8, owner LRU 8, scene LRU 3, loaded
directory rows 2,048, live file rows 128, scene tiles 2,048, scene labels 128,
and navigation history 64. Name search is bounded at 1,000 matches.
Bounded result caches, loaded pages, scenes, searches, and retained cleanup marks
keep their query-memory lease while derived row/string payloads survive. Reset
and eviction release the associated leases; no presentation cache is persisted.

Manual release gates remain: actual macOS 14.0, VoiceOver navigation and actions,
keyboard focus across tables/treemap/inspector, and FileProvider dataless folders,
permission-denied roots, aliases, and mount boundaries. A newer SDK build does
not replace these checks. Signing and notarization are separate release gates;
local validation builds disable code signing. Projects and Apps remain global when the Explore root
changes. Disk combines the selected root with fixed targets, whose rows and
inspectors say Global Audit (`context=audit_host`). Explore has no arbitrary
file deletion action. The current bridge exposes 17 scanner sections; no
unbacked eighteenth section is invented by the app.
