# Stateless scan-to-screen validation

MacAudit keeps selected-root disk exploration separate from global host audits.
The runtime must not create caches, reports, config files, history or preferences.
Development fixtures, generated bindings, lockfiles and compiler outputs are not
runtime scan history.

## Automated checks

Run these from the repository root:

```sh
cargo devtools check-dependencies
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo test --no-default-features --lib --locked
cargo bench --bench inventory
scripts/build-ffi.sh --debug
swift test --package-path swift/MacAuditKit --force-resolved-versions
xcodegen generate --spec apps/MacAudit/project.yml
xcodebuild -project apps/MacAudit/MacAudit.xcodeproj -scheme MacAudit \
  -configuration Debug -destination 'platform=macOS' \
  -derivedDataPath build/DerivedData -onlyUsePackageVersionsFromResolvedFile \
  -skipMacroValidation ARCHS=arm64 ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=NO test
```

App tests use `MACAUDIT_APP_TESTS=1` and a fake engine. Never run an automatic
real scan of a developer's Home as a test. All real filesystem fixtures use
temporary directories with explicit roots. Old persisted files should be seeded
with sentinel contents, then checked unchanged after launch, scan, refresh and
exit.

The Cargo graph checker validates declared package MSRVs and license metadata;
it does not substitute for building with the supported compiler or preserving
third-party notices in distribution. Swift dependencies are pinned in
`swift/MacAuditKit/Package.resolved`; the application must resolve the same versions.

Use the official Rust 1.93 toolchain for reproducible engine/native validation.
Setting `MACOSX_DEPLOYMENT_TARGET=14.0` cannot lower the deployment floor of a
precompiled Rust standard library. The bridge build checks that floor before
replacing any generated artifacts and rejects incompatible toolchains. Local
Homebrew Rust 1.98.1 has a macOS 26 standard library and is rejected; official
Rust 1.93 has a macOS 11 standard library and passes this admission check.
Actual macOS 14 runtime verification remains separate.

Release build-time dependencies remain unstripped. A local Rust 1.93/Xcode 27
release build with stripped procedural macros failed dynamic loading with
`mis-aligned LINKEDIT string pool`; the bounded `zerofrom` build reproduces it.
The build-dependency profile fixes this without disabling shipping-binary
stripping. The CI native job uses the same Rust version and arm64-only build.
`-skipMacroValidation` trusts the reviewed, pinned macro graph without saving an
Xcode preference; it does not relax Swift strict concurrency or sign the app.

### Local results — October 2, 2026

Official Rust 1.93.0, Xcode 27 and Swift 6.4 on an arm64 macOS 27 host:

| Check | Result |
| --- | --- |
| Cargo formatting, workspace/all-target Clippy | Pass, warnings denied |
| Rust default library | 735 passed |
| CLI integration tests | 8 passed |
| UniFFI tests | 65 passed |
| Rust development-tool tests | 26 passed |
| Rust library without default features | 608 passed |
| Swift package tests | 43 passed |
| Native application tests | 42 passed, 5 explicit macOS 15 image-comparison skips |
| Paired optimized Rust bridge / generated Swift | Pass |
| Native arm64 Debug and Release builds | Pass, no newer-macOS static-object warnings |
| Temporary ad-hoc hardened app / CLI signature verification | Pass, both binaries target macOS 14 |
| Rendered fixture smoke tests | Five 800 × 600 images exported and visually inspected |
| Dependency graph | 442 Cargo packages checked; both Swift locks pinned |
| Incompatible-standard-library admission | Rejected before replacing generated artifacts |

Run-forwarder regressions verify that an undrained external event receiver cannot
prevent cancellation retirement, and closing an old receiver cannot terminate
new-generation attribution. Resource-limit errors remain bounded, run-owned and
available to headless collection even when external delivery is cancelled.
FFI and TUI reconcile retired current-run terminal status from authoritative
engine metadata when a saturated event queue drops terminal messages. They
retain partial findings and existing failure details, reject stale runs and
wait for actual worker retirement before reconciling.
Retiring filesystem work still stays counted until the underlying operation
returns; cancelling a token does not establish that blocked kernel I/O stopped.
Subprocess admission reserves pipe-buffer reallocation peak before spawning;
output clones retain the reservation until their last owner drops. Filename
search tests cover ordinary files, relative paths, excluded-path boundaries,
symlink refusal, cancellation, 1,000-result truncation, resource exhaustion and
wide-tree workspace growth. Live matches never rewrite scanned totals.
Native regressions verify canonical-root containment, outside-root Finder reveal,
findings beyond loaded pages, stale location-filter responses, late cancelled-run
findings, worker retirement, stale refresh callbacks and live-search selection.

A fixture-only native smoke test verifies the Explore/Audit shell, root-picker
choices and typed subset-root acceptance with immediate result invalidation.
It uses an isolated ad-hoc app copy with fake/offline mode and a temporary root;
this is not a full keyboard or VoiceOver validation.

These are local results, not a recorded remote CI run or an actual Swift 6.0/6.2
compiler check. Native image baselines have not been verified on macOS 15;
the five skips are not successful pixel comparisons. Temporary fixture homes
and fake native engines keep tests from scanning the developer's Home.
Ad-hoc signatures are verified on temporary copies, not installed over a user's
application; this does not establish Developer ID signing or notarization.

`cargo devtools third-party-notices <output>` preserves packaged license text and verified
exact-version upstream sidecars in the distribution. The three objc2-family
sidecars preserve upstream licensing notices only: complete MIT terms and
attribution have not been independently verified. The notices generator
prints this limitation rather than substituting a generic license template.
The owner has accepted this limitation for personal use; it is not a blocker
for this branch. Notarization remains handled by the existing release CI.

Build helpers use the development-only `macaudit-devtools` Rust workspace member;
CI, bridge generation and packaging do not require Python. The helper is not
linked into or shipped with the application or CLI. Python installation auditing
is a product feature, not a Python tooling dependency. Pre-existing archived
benchmark files remain untouched and are not part of the build or validation path.
The Rust notices output matches the earlier generator byte-for-byte. Helper
regressions cover the exact Rust 1.93.0 floor, malformed graphs, missing license
texts, checksum/provenance mismatches, pinned Swift revisions and failed commands.
Target-directory lookup also preserves overridden paths with spaces, quotes and
Unicode without a scripting-language interpreter.

## Performance measurements

`cargo bench --bench inventory` covers a 100,000-directory bounded projection
and controlled flat, wide, deep and hardlinked traversals through bounded
projection and JSON serialization. Criterion measures repeated warm-cache runs,
not cold disk or UI latency. First publication measurements fall back to final
scene availability when a fixture completes before the 100 ms publication
deadline. Results and exact limitations are in `stateless-performance.md`.
The earlier `docs/audits/benchmark` results describe the pre-rearchitecture
walker and must not be quoted as measurements of the new application.

For full-pipeline profiling, record root acceptance, first usable Explore scene,
walk completion, each query request/response, publication, decode and scene-layout
completion. Report p50/p95 across repeated wide, flat, deep and hardlinked fixtures,
plus serialized bytes, main-actor duration, engine reservations and process peak
RSS. RSS includes the Swift runtime, allocator and frameworks; it is not the same
as the engine-owned 1 GiB admission budget. Compare the same fixture and build
profile before making a speed claim.

Set `RUST_LOG=macaudit=debug,macaudit_ffi=debug` for stderr-only engine timings
and `MACAUDIT_TRACE=1` for stderr-only Swift query, decode and layout timings.
Both are opt-in; neither creates a log file or transmits telemetry. Capture
stdout/stderr externally only when deliberately measuring a development run.
The app CI pins macOS 15 and Xcode 26.3; local macOS 27 rendering is not a
substitute for that snapshot baseline or for macOS 14 runtime verification.

## Native release gates

These checks require a human or a controlled macOS test environment:

- Run the signed/hardened arm64 Release app on macOS 14; the existing distribution remains arm64-only.
- Navigate root picker, table, inspector and cleanup with only the keyboard.
- Use VoiceOver for focus, selection, current path, partial coverage and residual buckets.
- Test a controlled File Provider root with dataless entries and confirm no hydration.
- Induce blocked filesystem I/O, Refresh, and verify retiring work remains visible and budgeted.
- Confirm Trash versus permanent effects and outside-root global cleanup paths without using real valuable data.
- Inspect signing with `codesign --verify --strict` and verify notarized distribution separately.

Mocks and a successful build cannot establish no-materialization, accessibility,
macOS 14 runtime behavior or notarization correctness.

Cleanup retains the physical target identities captured for confirmation and
checks them again immediately before each action. These checks reject replaced
targets, redirected parents and overlapping actions, but native pathname-based
Trash and package-manager commands cannot eliminate every race with another
process modifying the filesystem after the final check.
