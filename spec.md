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
  name) — this is what makes snapshot diffing (§8) work.
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
- `brew list --formula --versions`, `brew list --cask --versions`,
  `brew leaves`, `brew outdated --json=v2`, `brew deps --installed --json=v2`
  (one call; build the dep tree in-process — do NOT shell `brew deps` per formula,
  brew's ruby startup is ~1s each).
- Emits: leaves vs dependency-only formulae (dep tree for the UI), outdated
  items with `brew upgrade <x>` remedies, casks correlated to .app paths via
  `brew info --json=v2 --installed --cask` artifacts.
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
- Parse `$PATH` from a login shell (`zsh -ilc 'echo $PATH'`): duplicates,
  entries pointing at nonexistent dirs, ordering surprises (e.g. system bin
  shadowing brew).
- Shell startup time: `time zsh -i -c exit` (3 runs, median). > 500ms → Attention.

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

### 3.12 SnapshotsScanner (small but lucrative)
- `tmutil listlocalsnapshots /` — Time Machine local snapshots silently eat
  tens of GB. Remedy: `tmutil deletelocalsnapshots <date>` (destructive).

## 4. TUI layout (ratatui + crossterm)

- **Left sidebar**: sections (Apps, Brew, Disk, Daemons, Shell, Runtimes,
  Docker, Ports, Git, Keys) with per-section status glyph: spinner while
  scanning, count + total reclaimable when done, ⚠ on failure.
- **Main panel**: tree view (Apps/Brew) or sortable table (Disk/others).
  Tree nodes collapsible; `h` toggles System apps visibility.
- **Bottom bar**: keybinds + running totals ("Selected: 7 items · 18.3 GB").
- **Keys**: arrows/jk navigate, `space` mark, `enter` detail pane, `x` execute
  remedies on marked (confirm dialog listing exact commands; destructive ones
  in red), `r` rescan section, `R` rescan all, `/` filter, `s` cycle sort,
  `q` quit.
- Detail pane shows the Finding's full meta + each remedy's literal command —
  the tool must never run anything the user hasn't seen verbatim.
- Remediation runs as tokio tasks; results stream into an activity log pane;
  affected Findings get re-checked (targeted rescan) after completion.

## 5. CLI surface (clap)

```
macaudit                # TUI (default)
macaudit scan [--section apps,disk,…] --json    # machine-readable, for scripts
macaudit clean --dry-run                        # print remedy commands, run nothing
macaudit snapshot save|list|diff [A B]          # see §8
macaudit config path|edit
```

`--json` output = `Vec<Finding>` (serde). This makes the core testable and
scriptable independent of the TUI.

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
| Snapshot store | `rusqlite` (bundled) |

## 8. Snapshots & diff (the "audit" in audit tool)

- `macaudit snapshot save` → serialize all Findings into SQLite at
  `~/.local/state/macaudit/history.db` (one row per Finding, keyed by stable
  `FindingId`, plus a snapshots table with timestamp + machine info).
- `macaudit snapshot diff` → new / removed / grown Findings between two
  snapshots: "node_modules total grew 6.1 GB since June 1", "3 new login
  items appeared", "Rosetta app count: 4 → 2".
- TUI: a "Δ since last snapshot" badge per section once ≥1 snapshot exists.
- Auto-save a snapshot on every full scan completion (cheap; makes diff
  useful without ceremony).

## 9. Milestones (for Claude Code)

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
   Simulators, SshKeys, Snapshots(tmutil).
6. **M6 – history**: SQLite snapshots + diff + TUI badges.
7. **M7 (v1.1) – network**: formulae.brew.sh cask matching for unmanaged apps;
   GitHub-releases latest-version checks for Sparkle/unmanaged apps.

## 10. Testing notes

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