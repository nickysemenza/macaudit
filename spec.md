# macaudit — a "why is my Mac like this" TUI

A Rust TUI that audits a macOS machine: applications inventory, disk-hogging build
artifacts, background daemons, dev environment sprawl — with safe, explicit
remediation. Read-heavy, streaming, parallel. Working name `macaudit` (bikeshed later).

---

## 1. Architecture overview

```
                    tokio runtime (multi-threaded)
 ┌──────────────────────────────────────────────────────────────┐
 │                                                              │
 │  ScannerManager                                              │
 │  ├── AppsScanner        (tokio::process)                     │
 │  ├── BrewScanner        (tokio::process + reqwest)           │
 │  ├── FsScanner          (spawn_blocking → ignore::WalkParallel) │
 │  ├── LaunchdScanner     (tokio::process + fs)                │
 │  ├── ShellEnvScanner    (tokio::process)                     │
 │  ├── RuntimesScanner    (fs + tokio::process)                │
 │  ├── DockerScanner      (tokio::process)                     │
 │  ├── PortsScanner       (tokio::process)                     │
 │  ├── GitScanner         (gix or tokio::process, fed by FsScanner) │
 │  ├── SimulatorScanner   (tokio::process)                     │
 │  └── SshKeysScanner     (fs)                                 │
 │                                                              │
 │        all send ScanEvent via tokio::sync::mpsc ──────┐      │
 └───────────────────────────────────────────────────────┼──────┘
                                                         ▼
                              ┌──────────────────────────────┐
                              │ Main task: ratatui event loop │
                              │  - crossterm EventStream      │
                              │  - drain ScanEvent channel    │
                              │  - apply to AppState, draw    │
                              │  - NO I/O ever                │
                              └──────────────────────────────┘
```

Rules of the road:

- **Main loop never blocks.** It `tokio::select!`s over (a) crossterm's async
  `EventStream`, (b) the `ScanEvent` mpsc receiver, (c) a ~30fps draw tick.
- **Filesystem walking is not async.** `FsScanner` runs `ignore::WalkParallel`
  inside `spawn_blocking`; it communicates back through the same mpsc channel
  (use the blocking `blocking_send` from the walker threads, or bridge via
  `crossbeam-channel` → forwarder task).
- **Subprocesses via `tokio::process::Command`**, concurrent with
  `JoinSet`/`try_join!`.
- **Cancellation**: one `tokio_util::sync::CancellationToken` per scan
  generation. Rescan = cancel old token, bump generation counter, spawn new
  scanners. Events carry the generation; stale-generation events are dropped.
  The fs walker threads check `token.is_cancelled()` per directory entry.
- **Network** (v1.1+, but design for it now): `reqwest` for
  `formulae.brew.sh` API and GitHub releases. This is the tokio payoff.

## 2. Core types

```rust
/// Every scanner produces Findings. This is the universal currency.
pub struct Finding {
    pub id: FindingId,              // stable hash of (kind, primary path/name)
    pub kind: FindingKind,          // enum, see below
    pub title: String,              // "node_modules — cubby/app"
    pub detail: String,             // human-readable elaboration
    pub path: Option<PathBuf>,
    pub size_bytes: Option<u64>,    // apparent or on-disk; see SizeKind
    pub last_used: Option<SystemTime>, // staleness signal (project mtime, git date, atime)
    pub severity: Severity,         // Info | Attention | Reclaimable | Warning
    pub remedies: Vec<Remedy>,
    pub meta: serde_json::Value,    // scanner-specific extras (version, arch, cask name…)
}

pub enum FindingKind {
    App, BrewFormula, BrewCask, BuildArtifact, CacheDir, LaunchdItem,
    PathEntry, RuntimeVersion, DockerObject, PortListener, GitRepo,
    Simulator, SshKey, IosBackup, LocalSnapshot,
    TmDestination, TmExclusion, TmExclusionCandidate, TmBackupEstimate,
    TmStaleMount, TmPurgeable,
}

pub struct Remedy {
    pub label: String,              // "Delete (move to Trash)"
    pub command: RemedyCommand,
    pub reclaims_bytes: Option<u64>,
    pub destructive: bool,          // gates a confirm dialog
}

pub enum RemedyCommand {
    Trash { path: PathBuf },                        // via `trash` crate — DEFAULT for deletions
    Shell { program: String, args: Vec<String> },   // e.g. brew install --cask --adopt x
    RevealInFinder { path: PathBuf },               // open -R
    CopyToClipboard { text: String },               // for anything we won't run ourselves
}

pub enum ScanEvent {
    Started   { scanner: ScannerId, gen: u64 },
    Progress  { scanner: ScannerId, gen: u64, msg: String, done: u64, total: Option<u64> },
    Finding   { scanner: ScannerId, gen: u64, finding: Finding },
    Finished  { scanner: ScannerId, gen: u64, duration: Duration },
    Failed    { scanner: ScannerId, gen: u64, error: String },
}

#[async_trait]
pub trait Scanner: Send + Sync {
    fn id(&self) -> ScannerId;
    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()>;
    // ScanCtx = { tx: mpsc::Sender<ScanEvent>, token: CancellationToken,
    //             gen: u64, config: Arc<Config> }
}
```

Design notes:

- `Finding.id` must be **stable across runs** (hash of kind + canonical path or
  name) — the same artifact/app/daemon must produce the same id every scan.
- Sizes: report **on-disk blocks** (`MetadataExt::blocks() * 512`), not
  `len()`. APFS clones and sparse files make apparent size a lie.
- Remedies never take free-form input. Every executable path/arg comes from the
  scan itself. Deletions default to Trash, with `--rm` opt-in flag for real `rm`.

## 3. Scanners (v1 set)

### 3.1 AppsScanner
- `system_profiler SPApplicationsDataType -json` → all apps: path, version,
  arch (flag Intel/Rosetta on Apple Silicon), signed-by, obtained-from.
- Classify: System (`/System/Applications`) / User (`/Applications`,
  `~/Applications`) / cask-managed / App Store (`_MASReceipt` present or `mas list`)
  / **Unmanaged** (the interesting bucket).
- Remedies: RevealInFinder; for unmanaged apps with a matching cask (see
  BrewScanner correlation): `brew install --cask --adopt <name>`.

### 3.2 BrewScanner
- Three bounded calls: `brew info --json=v2 --installed` (formulae + casks in
  one process: versions, aliases, each install receipt's
  `runtime_dependencies` with `declared_directly`, `installed_on_request`,
  cask `depends_on`/`artifacts`), `brew outdated --json=v2`, and
  `brew autoremove --dry-run` (read-only; the confirmed-orphan signal).
  Never shell per formula (brew's ruby startup is ~1s each); never `brew
  leaves` — a leaf is structural, not "user-requested".
- `brewgraph.rs` builds the graph in-process: receipt edges preferred, the
  formula's current declarations only as a flagged fallback, aliases/old
  names/tap-qualified resolution that refuses ambiguity, stubs for
  dependencies missing from the inventory, cycle-safe closures, "why
  installed" chains up to requested roots, and `removal_preview(set)` →
  removable / blocked (still-needed) / predicted orphans / brew-confirmed
  orphans / unknown-origin orphans, set-based sizes, dependents-first order.
- Emits: one finding per formula (meta: origin, direct + transitive
  dependencies/dependents, cask dependents, dependency source, why
  installed, autoremove candidate, single-package removal preview, graph
  caveats, `group` by origin) and per cask (app paths, binary artifacts,
  depends_on), plus the `__autoremove__` summary. Remedies: `brew upgrade`
  when outdated; guarded `brew uninstall` only when nothing installed still
  needs it (never `--ignore-dependencies`); `brew autoremove` on the summary.
- Degrades: `brew info` failure → partial inventory from `brew list`
  (origin unknown, no graph); no brew → one Info finding.
- v1.1: hit `https://formulae.brew.sh/api/cask.json` (cached to disk, ETag) to
  match Unmanaged apps to available casks by bundle id/name.

### 3.3 FsScanner (the big one)
- `ignore::WalkParallel` from configured roots (default `~`, honoring an
  ignore list; skip `~/Library` except explicit cache targets below).
- **One walk, many detectors.** Per directory entry, cheap predicate checks:
  - Artifact dirs by name + sibling marker: `node_modules` (sibling
    `package.json`), `target` (sibling `Cargo.toml`), `.venv`/`venv`
    (`pyvenv.cfg` inside), `__pycache__`, `build`/`dist` (only with recognized
    project marker — avoid false positives), `.next`, `.turbo`,
    `node_modules/.cache`, `.wrangler`, `Pods` (sibling `Podfile`).
  - `.git` → emit repo path to GitScanner's queue.
  - Large loose files (> configurable threshold, default 1 GiB).
- On artifact hit: **do not descend further for discovery**; hand subtree to a
  sizing pool (rayon or a bounded set of blocking tasks) that sums disk blocks.
  Emit the Finding immediately with `size_bytes: None`, then a follow-up
  updated Finding when sizing completes (UI shows "…" then the number).
- Staleness: parent project mtime = max mtime of non-artifact files at project
  root (cheap heuristic) or GitScanner's last-commit date when available.
- Also size these fixed paths (no walk needed):
  `~/Library/Developer/Xcode/DerivedData`, `~/Library/Developer/Xcode/iOS DeviceSupport`,
  `~/Library/Developer/CoreSimulator/Caches`, `~/.npm`, `~/.pnpm-store`,
  `~/.cargo/registry`, `~/.rustup/toolchains`, `~/go/pkg/mod`,
  `~/Library/Caches` (top-level per-app breakdown),
  `~/Library/Application Support/MobileSync/Backup` (old iOS backups!).

### 3.4 LaunchdScanner
- Enumerate `~/Library/LaunchAgents`, `/Library/LaunchAgents`,
  `/Library/LaunchDaemons`; parse plists (`plist` crate); `launchctl list` for
  running state; `sfltool dumpbtm` for the Ventura+ background-items registry.
- **Orphan detection**: plist whose `Program`/`ProgramArguments[0]` binary no
  longer exists, or references an app not in AppsScanner's inventory → Warning
  + Trash remedy for the plist (destructive; requires the plist be unloaded first —
  remedy is a two-step: `launchctl bootout` then Trash).

### 3.5 ShellEnvScanner
- Find the login shell via `dscl . -read /Users/<user> UserShell` (fallback
  `$SHELL`) and read its `$PATH` with the right invocation (`fish -lc
  'string join : $PATH'`, `zsh -ilc 'echo $PATH'`, `bash -ilc 'echo
  $PATH'`); unsupported shells fall back to the process PATH with a note.
  Never read rc files. Flag duplicates, dead entries, system bin shadowing
  brew, and (`__path_diff__`) entries only the shell or only this process
  has — agents and apps launch MacAudit with a different environment.
- Shell startup time: `<shell> -i -c exit` (3 runs, median). > 500ms → Attention.

### 3.13 ToolsScanner (Global Tools)
- Filesystem-metadata probes per manager (`scan/global_tools/*`), each
  degrading independently (absent / partial / failed): npm prefixes
  (Homebrew, /usr/local, `~/.npm-global`, version-manager nodes, configured
  extras, plus `npm prefix -g` as one more candidate), pnpm `global/v<N>`
  (hash symlink = identity root) and legacy `global/<N>` (`.modules.yaml`
  store/virtual-store/packageManager; same-major pnpm from `.tools` for
  removal), cargo `.crates2.json`/`.crates.toml` (rustup proxies excluded),
  bun, pipx (`pipx_metadata.json`, interpreter validity via the venv's
  python symlink chain + `pyvenv.cfg`), uv (`uv-receipt.toml` entrypoints;
  a missing launcher is "may be recreated", not broken), pip site-packages
  (dist-info `INSTALLER`/`RECORD`/`Requires-Dist`; Cellar-linked or
  brew-installed → owned by a formula and protected; Homebrew's
  pip/setuptools/wheel bootstrap protected; Apple sites inventory-only;
  manual installs get a per-package `--break-system-packages` uninstall).
- Cross-installation analysis: command resolution against the login-shell
  PATH and the process PATH (`which`), duplicate/shadow detection,
  ownership of every PATH candidate (installation, cask, formula, rustup),
  project correlation (manifests, lockfiles, pins, bootstrap `X_VERSION=`,
  CI tokens; "project alternative" only when the local binary exists,
  range satisfaction via node-semver/semver), opt-in aggregated shell
  history. Classification precedence: broken > required > orphan >
  duplicate > shadowed > project alternative > review.
- Emits `GlobalTool` (key `{manager}:{root}:{name}`, no version),
  `CommandResolution` (per command name) and `ToolCoverage` findings.
  Remedies: manager-native uninstall (guarded `ToolInstall`/`PipPackage`),
  launcher-only Trash of launchers this installation owns (guarded
  `Launcher`, an alternative while a native remedy exists, primary when the
  package is already gone), copy-to-clipboard for inferred-interpreter
  sites, and explicit `--version` probes. Never executes discovered
  binaries during a scan; never imports Python modules.

### 3.6 RuntimesScanner
- Detect nvm/fnm/volta/mise/asdf/pyenv/rustup by their dirs; list installed
  toolchain versions + per-version size. Flag: multiple managers for the same
  runtime; versions unused by any project (best-effort: cross-ref `.nvmrc`/
  `.node-version`/`mise.toml` files found by FsScanner).
- `rustup toolchain list` + old toolchains; `xcrun simctl list runtimes -j` →
  SimulatorScanner overlap, keep simulators there.

### 3.7 DockerScanner
- If docker CLI present and daemon reachable: `docker system df -v --format json`
  → images (dangling!), stopped containers, unused volumes, build cache.
  Remedies: `docker system prune` variants (destructive). Daemon down → single
  Info finding, not an error.

### 3.8 PortsScanner
- `lsof -nP -iTCP -sTCP:LISTEN` → listener list with pid/process/port; join
  against process start time. No remedies except RevealInFinder on the binary
  and CopyToClipboard `kill <pid>`.

### 3.9 GitScanner
- Consumes repo paths from FsScanner via an internal channel. Per repo
  (bounded concurrency ~8): dirty working tree? unpushed commits? last commit
  date? stash count? Prefer `gix` (pure Rust, fast) over shelling `git`.
- Findings: "6 repos with uncommitted work", per-repo detail.

### 3.10 SimulatorScanner
- `xcrun simctl list devices -j` + runtime sizes. Unavailable/legacy runtimes →
  Reclaimable with `xcrun simctl delete unavailable` remedy.

### 3.11 SshKeysScanner
- `~/.ssh`: key files, type/bits (parse pubkey), mtime as age proxy, keys with
  no matching entry in `config`. Old RSA-2048 or > 5y old → Attention. Info only.

### 3.12 TimeMachineScanner
- Sources: `tmutil destinationinfo -X` (per-destination health: last backup,
  `RESULT` code, quota vs. used); `defaults export
  /Library/Preferences/com.apple.TimeMachine -` for `SkipPaths` and backup
  history (TCC-protected plist, but `cfprefsd` serves the export anyway);
  `tmutil isexcluded <paths…>` batched over a shallow enumeration of `/`,
  home and `~/Library` hubs to prune excluded directories, size exclusions
  and find candidates (regenerable caches/toolchains, cloud-synced folders) — a batch aborts at the first privacy-protected
  path, so the scanner pre-filters known-FDA paths and resumes past them;
  `diskutil info -plist /System/Volumes/Data`; one `osascript` JXA read of
  `NSURLVolumeAvailableCapacityForImportantUsageKey` for purgeable space;
  `tmutil listlocalsnapshots /` for local snapshots. No **Full Disk Access**
  → `isexcluded`/estimate findings degrade to destination-only, FDA-limited
  rather than silently empty.
- Emits `TmDestination`, `TmExclusion` (per `SkipPaths` entry, sized),
  `TmExclusionCandidate` (`tmutil addexclusion` remedy), `TmBackupEstimate`
  (exclusion-aware measured estimate of the next backup), `TmStaleMount`
  (orphaned `/Volumes/Backups of …` mounts), `TmPurgeable` (purgeable-space
  upper bound — no per-snapshot size without root) and `LocalSnapshot`.
  `TmExclusion` is always `Info` and `TmExclusionCandidate` at most
  `Attention` — never `Reclaimable`, because excluding a path shrinks future
  backups, not current disk usage. Root-only remedies (`tmutil addexclusion -p`, `rmdir` on a stale
  mount) are `CopyToClipboard`; `tmutil deletelocalsnapshots <date>` remains
  a direct, destructive remedy.

## 4. TUI layout (ratatui + crossterm)

- **Nav rail** (left, adaptive width): one row per section (Overview, Apps,
  Brew, Disk, Daemons, Shell, Runtimes, Docker, Ports, Git, Simulators, Keys,
  Time Machine) — a map, not a focusable list. `←/→`, `h/l`, `Tab`/`Shift-Tab`,
  digits `1`-`9`/`0`, or a click always switch sections; row movement never
  touches it. Full rows (≥100 cols) show a status glyph (spinner / ⚠),
  finding count, and compact reclaimable size; 70-99 cols shows title only;
  below 70 the rail is hidden and the statusbar names the section instead.
- **Main panel**: a tree (Apps/Brew/Disk, ordered by total size) or flat
  sortable table for the rest, with columns specific to each section (e.g.
  Git: Repo · Branch · State · Size · Used · Path; Ports: Port · PID ·
  Command · User · Host · Binary). Severity colors the primary cell rather
  than occupying a column; `z` folds/unfolds the tree group under the
  cursor. `s` cycles a section's sort (default → each sortable column →
  severity); clicking a column header sorts by it, clicking again flips
  direction.
- **Detail pane** (optional, right): shown automatically at 120+ columns,
  hidden below, `p` forces it either way; not shown on the Overview. Renders
  the selected Finding as typed key/value rows plus every remedy's literal
  command, wrapped so it's never clipped.
- **Bottom bar**: clickable key hints + running totals ("Selected: 7 items ·
  18.3 GB"); becomes the filter text-input line while filtering.
- **Keys**: `←/→`/`h/l`/`Tab` switch sections, `j/k`/`↑/↓` move the
  selection, `space` mark, `enter` opens detail (or folds/unfolds a group
  header), `z` fold/unfold, `p` toggle detail pane, `x` execute remedies on
  marked (confirm dialog listing exact commands; destructive ones in red),
  `r` rescan section, `R` rescan all, `/` filter (`esc` clears it, else
  quits), `s` cycle sort, `H` toggle System apps, `?` help, `q` quit;
  `d` flips the Brew explorer direction, `e` cycles the selected row's
  remedy, `v` previews the marked batch, `c` reopens the last cleanup
  report (see §4.1).
- **Mouse**: a click on a nav rail row switches section; a row click selects,
  a double-click opens detail or folds a group header; a column header click
  sorts; a statusbar hint click performs its action; wheel switches sections
  over the rail, moves the selection over the main panel, and scrolls over
  the detail pane. Every click/wheel resolves through a `Viewport`/`Hit` map
  recorded during the previous draw, then is re-expressed as the same
  keyboard `Action` a key would produce — the mouse can never do anything a
  key can't.
- Detail pane shows the Finding's full meta + each remedy's literal command —
  the tool must never run anything the user hasn't seen verbatim.
- Remediation runs as tokio tasks; results stream into an activity log pane;
  affected Findings get re-checked (targeted rescan) after completion.
- Presentation architecture: `src/ui/present/` holds one `SectionPresenter`
  per scanner (its `Column`s, sort behavior, and a detail fn) so a section's
  columns live next to nothing else; `src/ui/rows.rs` is the single renderer
  that draws any section's rows from its presenter; `src/ui/layout.rs` owns
  `Viewport`/`Hit`, the screen-geometry map recorded during `draw` that mouse
  handling and paging read back.

### 4.1 Cleanup workflow
- `x` opens the confirm dialog after an in-memory preflight
  (`cleanup::preflight_static`): stale ids, duplicate targets and
  still-needed Homebrew packages are listed as refused with reasons; the
  dialog shows the exact commands in execution order, the Homebrew impact,
  preserved launchers and follow-ups. `v` previews the same model without
  confirming; `e` picks an alternative remedy for the selected row.
- `y` spawns `cleanup::run_batch`: a refreshing preflight re-checks every
  `Guard` against fresh data, then runs dependents-first (Homebrew per the
  preview's order, then native uninstalls, launcher-only removals, `brew
  autoremove` last). `Esc` cancels remaining actions between commands. After
  execution: rescan of the touched sections, `brew autoremove --dry-run`
  re-run when Homebrew changed, before/after inventory, bounded `--version`
  probes of retained related tools (before *and* after), verification
  verdicts (removed / still present / ok / pre-existing failure /
  regression), JSON report under `<state_dir>/cleanup-reports/`. Marks whose
  findings vanish on rescan are dropped and announced.

## 5. CLI surface (clap)

```
macaudit                # TUI (default)
macaudit scan [--section apps,disk,…] --json    # machine-readable, for scripts
macaudit clean --dry-run                        # print remedy commands, run nothing
macaudit config path|edit
```

`--json` output = `Vec<Finding>` (serde). This makes the core testable and
scriptable independent of the TUI.

Additional subcommands: `tools [--json] [--manager …] [--class …]`, `tools
verify [--json] [--limit N]`, `brew why <name> [--json]`, `brew deps <name>
[--json]`, `clean --dry-run [--select …] [--json]` (Brew/Tools rows listed
only when evidence suggests removal unless selected; prints preflight
refusals and Homebrew impact).

## 6. Config (`~/.config/macaudit/config.toml`)

```toml
[scan]
roots = ["~/code", "~/Desktop"]        # fs walk roots; default ["~"]
ignore = ["~/Library/CloudStorage"]    # never descend
large_file_threshold_gb = 1

[artifacts]
# user-extensible rules
extra = [{ dir = ".gradle", marker = "build.gradle" }]

[behavior]
delete_mode = "trash"                  # "trash" | "rm"
stale_after_days = 90                  # threshold for the staleness badge
```

`[tools]` (see README for every knob): `shell_history_evidence` (opt-in,
aggregated), `project_roots`/`project_max_depth`/`project_time_budget_secs`,
`verify_after_cleanup`/`verify_limit`/`verify_timeout_secs`,
`write_cleanup_reports`, manager homes (`pnpm_home`, `cargo_home`,
`pipx_home`, `uv_tool_dir`, `bun_home`), `extra_npm_prefixes`,
`python_sites`, `include_apple_python`, `homebrew_prefix`.

## 7. Crates

| Purpose | Crate |
|---|---|
| Async runtime | `tokio` (rt-multi-thread, process, sync, time) |
| Cancellation | `tokio-util` |
| TUI | `ratatui`, `crossterm` (event-stream feature) |
| Parallel walk | `ignore` (WalkParallel) |
| Sizing pool | `rayon` |
| Subprocess JSON | `serde`, `serde_json` |
| Plists | `plist` |
| Git | `gix` |
| HTTP (v1.1) | `reqwest` (rustls) |
| Trash | `trash` |
| CLI | `clap` (derive) |
| Errors | `anyhow` (bin), `thiserror` (lib) |
| Sizes | `humansize` |
| Config | `toml`, `directories` |
| Size cache | `rusqlite` (bundled) |

## 8. Milestones (for Claude Code)

1. **M1 – skeleton**: clap + tokio + ratatui shell, ScanEvent plumbing,
   ScannerManager with a fake scanner emitting synthetic findings, generation-
   based cancellation, sidebar/table/detail UI, marking. *(No real scanners —
   proves the architecture.)*
2. **M2 – Brew + Apps**: real AppsScanner + BrewScanner, tree view,
   unmanaged-app bucket, `--json` output. First useful build.
3. **M3 – FsScanner**: parallel walk, artifact detection, streaming sizes,
   staleness, fixed-path caches, large files.
4. **M4 – remediation**: Remedy execution engine, confirm dialog, Trash
   default, activity log, post-remedy targeted rescan.
5. **M5 – the long tail**: Launchd, ShellEnv, Runtimes, Docker, Ports, Git,
   Simulators, SshKeys, Time Machine(tmutil).
6. **M6 (v1.1) – network**: formulae.brew.sh cask matching for unmanaged apps;
   GitHub-releases latest-version checks for Sparkle/unmanaged apps.

- M7 — developer-tool audit: Brew graph explorer, Global Tools section,
  login-shell resolution, evidence-based classification, ownership-aware
  cleanup with preflight/verification/reports. Done.

## 9. Testing notes

- Scanners take a `ScanCtx`; unit-test them by injecting a mock command runner
  (trait over "run program, get stdout") and fixture JSON captured from real
  `system_profiler`/`brew` output (check fixtures into `tests/fixtures/`).
- FsScanner: build temp dir trees in tests (`tempfile`); assert findings +
  that discovery does not descend into artifact dirs.
- Remedy engine: dry-run mode is the test seam — assert generated commands,
  never execute in tests.
- One `cargo test` integration test that runs `macaudit scan --json` end-to-end
  against a fixture HOME (env-var override for all paths — make every hardcoded
  path above resolve through `Config`/`directories` so tests can redirect them).