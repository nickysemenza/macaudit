# macaudit

A "why is my Mac like this" TUI — audits apps, disk hogs, daemons, and
dev-environment sprawl, with safe, explicit remediation.

<!-- screenshot placeholder -->

## Features

- **Resource Health overview + 14 audit sections**: a manual point-in-time
  CPU/memory/swap/disk/process summary, plus Apps, Brew, Global Tools, Disk,
  Daemons, Shell, Runtimes, Docker, Ports, Git, Simulators, iOS Devices,
  Keys, and Time Machine — see the [sections tour](#sections-tour) below.
- **iPhone storage, from the Mac.** Plug in an iPhone or iPad and the iOS
  Devices section reads what Settings › iPhone Storage won't tell you: how
  much is *purgeable* (on one 256 GB phone, 146 GB hiding behind "19 GB
  free"), and a sortable per-app table splitting each app's bundle from its
  data — the Spotify-with-38-GB-of-downloads kind of finding. Needs the
  optional `libimobiledevice` and `ideviceinstaller` formulae; the section
  says so when they're missing.
- **Developer-tool audit.** Every global installation across npm, pnpm
  (current *and* legacy layouts), cargo, pipx, uv, pip site-packages and bun,
  with the manager that owns it, the launchers it exports, which copy your
  *login shell* actually runs (fish/zsh/bash) versus what MacAudit's own
  process sees, whether a project already pins its own copy, and an
  evidence-ranked classification (broken / duplicate / shadowed /
  project-alternative / required / orphan / review). See
  [Global tools](#global-tools) below.
- **Homebrew dependency explorer.** A real tree over Homebrew's install
  receipts: what a formula needs, why it is installed (up to the packages
  you asked for), origin from Homebrew's own `installed_on_request` flag,
  and a batch removal preview that separates packages still needed by
  something you keep, predicted orphans, and Homebrew-confirmed
  `autoremove` candidates.
- **Ownership-aware cleanup.** Marked removals are re-checked against a
  fresh scan right before they run, executed dependents-first with
  manager-native commands, verified afterwards, and written to a JSON audit
  report. See [Cleanup workflow](#cleanup-workflow).
- **Streaming, parallel scans.** Scanners run concurrently as async tasks
  (or in a blocking pool for the filesystem walk) and stream findings into
  the UI as they're discovered — nothing waits for the slowest scanner.
- **Remediation with a Trash-first default.** Every finding that can be
  cleaned up carries an explicit remedy command; batch-executing marked
  items always shows you the exact command before it runs, and deletions go
  to the Trash unless you opt into `--rm`.

## Safety model

Scanning never modifies the things it audits: no files are deleted, no
packages touched, no settings changed. Honest fine print on what a scan
*does* do:

- **Read-only inspection commands are executed** (`system_profiler`, `brew`,
  `git status`, `lsof`, `tmutil`, `defaults export`, `diskutil`, `osascript`,
  …). Worth knowing about: `brew` is always run with
  `HOMEBREW_NO_AUTO_UPDATE=1` so it can't trigger Homebrew's auto-update
  (`brew autoremove --dry-run` is read-only), and the Shell and Global Tools
  sections start your *login shell* (fish, zsh or bash, found via directory
  services) to read its real `$PATH` and measure startup time — which, by
  definition, executes your own shell configuration files. No rc file is
  ever read or displayed. The Global Tools scan otherwise reads manager
  metadata from disk only (optionally `npm prefix -g`): it never executes
  the tools it finds and never imports Python modules. The Time Machine
  section only ever queries `tmutil` (`listlocalsnapshots`,
  `destinationinfo`, `isexcluded`) and reads Time Machine's own preferences
  via `defaults export` (backed by `cfprefsd`, not direct file access) and
  volume info via `diskutil info`; the one `osascript` call is a JXA read of
  Foundation's `NSURL` volume-capacity key, never AppleEvents automation of
  another app. Scanning never changes Time Machine settings; the section's
  remedies (`tmutil deletelocalsnapshots`, `tmutil thinlocalsnapshots`, the
  sticky `tmutil addexclusion <path>`) run only when you confirm them, and
  anything that would need admin rights (`tmutil addexclusion -p`, removing
  a stale `/Volumes/Backups of …` directory) is offered as a command to
  copy, since macaudit never elevates.
- **The iOS Devices section talks to a physically connected, paired
  device** — a step beyond commands run on this Mac, so spelled out: it runs
  `idevice_id -l`, `ideviceinfo -x`, `ideviceinfo -q com.apple.disk_usage -x`
  and `ideviceinstaller list --all --xml` (with an explicit attribute list),
  all reads through the same lockdown services Finder uses. Nothing is ever
  executed *against* the phone: the only remedy is an `ideviceinstaller
  uninstall` command copied to the clipboard for you to run yourself. The
  tools are optional (`brew install libimobiledevice ideviceinstaller`);
  without them, or without a phone, the section shows one row saying so.
- **Health probes are explicit and bounded.** `--version` checks run only
  when you ask (`macaudit tools verify`, or the `Verify` alternative remedy
  on a tool), and after a cleanup for retained tools related to the batch —
  each capped by count and timeout, and always shown as a command.
- **macaudit writes its own state**: the size cache and cleanup reports
  (`~/.local/state/macaudit`), and the catalog cache
  (`~/Library/Caches/macaudit`). Never anything outside its own directories.
- **Nothing runs unseen.** Every remedy — delete, `brew upgrade`, `docker
  builder prune`, whatever — is rendered as a literal command string and
  shown to you (in the detail pane, and again in the confirm dialog) before
  it ever executes. You always see exactly what will run.
- **Deletions default to Trash**, not `rm -rf`. Pass `--rm` if you want real
  deletion instead; that choice is explicit, global, and visible in every
  rendered command.
- **Cleanups are guarded, not just previewed.** Every destructive tool or
  Homebrew remedy carries an ownership guard that is re-evaluated against a
  fresh scan after you confirm and before anything runs (one `brew info`
  for all Homebrew targets, a fresh manager probe for tools, `readlink` for
  launchers, the dist-info for pip packages). A target that changed, moved,
  is now needed by something you keep, or now belongs to another installation
  is refused and reported, never run. `Esc` stops a running batch between
  actions; an in-flight command is never killed. No rollback is offered —
  versions are recorded in the report for manual reinstall guidance only.
- **Network access is on by default, narrow, and easy to disable.** The only
  endpoints ever contacted are `formulae.brew.sh` (Homebrew cask catalog)
  and `api.github.com` (release checks), both cached to disk so repeated
  scans don't re-fetch. Run with `--offline` (or set `[network] offline =
  true`) to guarantee zero HTTP — cached catalog data still works offline.

## Install

**Homebrew** (Apple Silicon, macOS 14+) — one cask installs both the
`macaudit` CLI and MacAudit.app:

```sh
brew install --cask nickysemenza/tap/macaudit
```

The cask lives in [nickysemenza/homebrew-tap](https://github.com/nickysemenza/homebrew-tap)
and downloads the zip from [Releases](https://github.com/nickysemenza/macaudit/releases);
`brew upgrade` picks up new releases because the release workflow bumps the
cask there. Releases are signed with a Developer ID certificate and
notarized by Apple, so the app opens with a plain double-click and the CLI
runs without a Gatekeeper "killed" — no right-click → Open dance.

**From source** — the CLI needs a stable Rust toolchain:

```sh
cargo install --path .
```

### MacAudit.app (SwiftUI)

The same engine, as a native macOS app. The Rust engine is linked in-process
through [UniFFI](https://mozilla.github.io/uniffi-rs/) (`crates/macaudit-ffi`);
`swift/MacAuditKit` wraps the generated bindings and `apps/MacAudit` is the
app. Requires Xcode 26+ (the app icon is an Icon Composer document,
`apps/MacAudit/Resources/AppIcon.icon`, which older `actool`s can't compile)
and [xcodegen](https://github.com/yonaskolb/XcodeGen).

```sh
scripts/run-app.sh                        # all of the below, then launches the signed app (--release, --fake, --no-open, --no-ffi)
```

Or step by step:

```sh
scripts/build-ffi.sh                      # engine .a → xcframework + Swift bindings (debug; --release, --universal)
xcodegen generate --spec apps/MacAudit/project.yml
open apps/MacAudit/MacAudit.xcodeproj     # or: xcodebuild -project … -scheme MacAudit build
```

Re-run `build-ffi.sh` after any Rust change: the generated Swift and the
static library carry matching checksums and are always rebuilt together
(both are gitignored). `MACAUDIT_FAKE=1` in the scheme's environment (or the
"Use fake data" toggle in Settings on debug builds) runs the app on the
synthetic `--fake` findings; `MACAUDIT_HOME` works as for the CLI.

The app is not sandboxed — it scans `~`, runs `brew`/`docker`/`xcrun` and
moves files to the Trash, none of which the App Sandbox allows. It does run
with the hardened runtime, in every configuration, because notarization
requires it. Local builds are signed with an Apple Development certificate
(team in `project.yml`; override `DEVELOPMENT_TEAM`, or pass
`CODE_SIGN_IDENTITY=-` for an ad-hoc build) — macOS keys its folder-access
grants on the signing identity, and an ad-hoc signature changes with every
rebuild, so it would re-prompt each time. Because a Finder-launched app
inherits launchd's
minimal `PATH`, the engine adopts the login shell's `PATH` at startup (the
same disclosure as the Shell scanner: this starts your shell once). Mail,
Messages, Safari and Time Machine data need **Full Disk Access** granted to
MacAudit.app in System Settings; without it those subtrees are skipped.

## Usage

```sh
macaudit                              # launch the TUI (default)
macaudit scan --json                  # machine-readable scan, for scripts
macaudit scan --section apps,disk     # restrict to specific sections
macaudit clean --dry-run              # print remedy commands, run nothing
macaudit clean --dry-run --select wget,npm:/opt/homebrew/lib/node_modules:eslint
                                      # preview specific findings (+ preflight, Homebrew impact); --json for scripts
macaudit tools                        # every global tool installation, its manager, class and commands
macaudit tools --class broken,duplicate,shadowed --json
macaudit tools verify                 # explicit, bounded `--version` probes of every tool launcher
macaudit brew why python@3.14         # why is it installed — who needs it, up to the roots you asked for
macaudit brew deps wget               # what does it need (direct, then transitive)
macaudit config path                  # print the config file path
macaudit config edit                  # open the config file in $EDITOR
```

Global flags (apply to every subcommand and the TUI):

| Flag | Effect |
|---|---|
| `--rm` | Delete for real (`rm -rf`) instead of moving to Trash. |
| `--offline` | Disable all network access. |
| `--fake` | Use synthetic findings instead of real scanners (for demos/testing). |

## Keybindings

The left sidebar is a *nav rail*, not a selectable list: section-switching
keys always switch sections, and row-movement keys always move rows.

| Key | Action |
|---|---|
| `←`/`→`, `h`/`l`, `tab`/`shift-tab` | Previous / next section |
| `1`-`9`, `0` | Jump to section |
| `j`/`k`, `↑`/`↓` | Move selection |
| `PgUp` / `PgDn` (`ctrl-u` / `ctrl-d`) | Page selection |
| `space` | Mark / unmark row |
| `enter` | Open detail (on a group header or dependency node: fold/unfold) |
| `z` | Fold / unfold the group or dependency node under the cursor |
| `d` | Brew: flip the explorer between *needs* and *needed by* |
| `p` | Show / hide detail pane |
| `J` / `K`, wheel | Scroll detail pane |
| `e` | Cycle which remedy the row will run (e.g. launcher-only removal, `--version` probe) and mark it |
| `v` | Preview the marked batch: refusals, Homebrew impact, what stays, follow-ups |
| `x` | Execute marked remedies (confirm dialog; every target is re-checked before running) |
| `c` | Reopen the last cleanup report |
| `r` | Refresh current section's point-in-time sample |
| `R` | Refresh all sections |
| `/` | Filter by substring (`esc` clears) |
| `s` | Cycle sort (size / name / severity) |
| `H` | Toggle System apps visibility |
| `?` | Toggle this help |
| `q` | Quit |

The detail pane shows automatically once the terminal is at least 120
columns wide (`p` forces it either way), and the nav rail itself adapts to
width: full (with finding counts and reclaimable size) at 100+ columns,
title-only from 70-99, and hidden below 70 (the statusbar then names the
current section instead).

### Mouse

| Target | Click | Double-click | Wheel |
|---|---|---|---|
| Nav rail row | Switch section | — | Switch section |
| Data row | Select | Open detail / fold header | Move selection 3 rows |
| Column header | Sort by it (click again to flip direction) | — | — |
| Statusbar hint | Perform its action | — | — |
| Overview source row | Jump to that section | — | — |
| Detail pane | — | — | Scroll |

Mouse works while the `/` filter box is open; the Confirm, Help, Preview,
Cleanup and Report overlays swallow it.

## Configuration

`~/.config/macaudit/config.toml` — all fields optional; a missing or partial
file falls back to these defaults:

```toml
[scan]
roots = []                       # Disk walk roots; empty -> ["/"] (whole boot volume); ["~"] for home only
ignore = []                      # paths to never descend into (tilde-expanded)
large_file_threshold_gb = 1.0    # loose files larger than this are flagged
# Applies to git worktree, Homebrew keg and Time Machine backup-set estimate
# sizing only — the Disk section's single getattrlistbulk walk is never
# cached, so this TTL has no effect on it.
size_cache_ttl_hours = 24        # how long a cached artifact size stays fresh

[artifacts]
# user-extensible artifact-dir rules: a directory name plus a required
# sibling marker file, in addition to the built-in ones (node_modules,
# target, .venv, __pycache__, build/dist, .next, .turbo, Pods, ...)
extra = []
# example: extra = [{ dir = ".gradle", marker = "build.gradle" }]

[behavior]
delete_mode = "trash"            # "trash" | "rm" (overridden by --rm)
stale_after_days = 90            # threshold for the staleness badge

[network]
offline = false                  # disable all network access (overridden by --offline)
catalog_max_age_days = 7         # refresh the Homebrew cask catalog at most this often
github_max_checks_per_scan = 10  # max GitHub release lookups per scan
github_cache_ttl_hours = 72      # how long a cached GitHub release result stays fresh

[tools]
shell_history_evidence = false   # opt in: per-command counts + last-used dates only, never raw history
project_roots = []               # repos to correlate against; empty -> [scan] roots -> $HOME
project_max_depth = 6            # how deep below a root to look for manifests
project_time_budget_secs = 10    # correlation stops (and says so) past this
verify_after_cleanup = true      # bounded --version probes of retained tools related to a batch
verify_limit = 25
verify_timeout_secs = 5
write_cleanup_reports = true     # JSON audit trail under ~/.local/state/macaudit/cleanup-reports/
extra_npm_prefixes = []          # besides Homebrew, /usr/local, ~/.npm-global and version-manager nodes
pnpm_home = "~/Library/pnpm"
cargo_home = "~/.cargo"
pipx_home = "~/.local/pipx"
uv_tool_dir = "~/.local/share/uv/tools"
bun_home = "~/.bun"
python_sites = []                # extra site-packages dirs to inventory
include_apple_python = true      # /Library/Python sites: inventory only, never remedies
# homebrew_prefix = "/opt/homebrew"   # override the Cellar prefix (default: $HOMEBREW_PREFIX, /opt/homebrew, /usr/local)
```

## Sections tour

| Section | What it finds |
|---|---|
| Resource Health | Manual CPU load, memory pressure/compression, swap, and current high-CPU/RAM processes. Root Disk explicitly distinguishes raw APFS free space from macOS available capacity, which includes purgeable space. It names the count of local Time Machine snapshots, but does not invent a byte size for them: macOS does not report a reliable per-snapshot or aggregate total. It is a point-in-time view, not a background monitor. |
| Apps | Installed applications, classified System / User / cask-managed / App Store / Unmanaged, with arch (Intel/Rosetta) and code-signing info. |
| Brew | Installed formulae and casks as an origin-grouped dependency explorer (explicitly installed / installed as dependency / unknown origin / autoremove candidates / casks) built from `brew info --json=v2 --installed` install receipts; `d` flips between *needs* and *needed by*, direct and transitive rows are distinguished, cask `depends_on` and `binary` artifacts are included. Origin comes from Homebrew's `installed_on_request` flag — a leaf is never assumed to be user-requested or unneeded; `brew autoremove --dry-run` provides the confirmed-orphan signal. Uninstall remedies exist only for packages nothing installed still needs (never `--ignore-dependencies`); outdated packages keep `brew upgrade`. |
| Global Tools | Every installation by npm, pnpm (hashed `global/v<N>` and legacy `global/<N>` layouts), cargo, pipx, uv, pip (Homebrew, Apple and user site-packages) and bun, keyed by manager + install root + package so two copies stay distinct and stable across scans. Per installation: version (or `unknown`), interpreter/runtime and whether it still exists, exported commands, launchers and their targets, resolution in your login shell vs this process, ownership, project evidence, and a classification. Includes one row per command name (shell vs process resolution with every PATH candidate and its owner) and a coverage row per manager. |
| Disk | Build artifacts (`node_modules`, `target`, `.venv`, etc.), package-manager caches, and large loose files found by a single `getattrlistbulk`-based parallel filesystem walk of the whole boot volume (mount points are never crossed; `[scan] roots = ["~"]` limits it to the home directory), plus allocation categories measured exactly off that same walk rather than estimated: the home directory's (Development, Documents, Caches, Application Support, Package caches, …) and the system's (Applications, macOS, System Library, System data). Only the home directory — or a configured root that is not one of its ancestors — is mined for artifacts, repositories and loose large files; `/System`, `/Applications`, `/Library`, `/private` and other accounts are sized for the categories and the folder browser but never classified (Homebrew's taps are repositories, system frameworks contain `node_modules`). Unreadable folders are counted and surfaced as a coverage note on the affected category rather than silently under-reporting — TCC-protected user data (Mail, Messages, Safari, … without Full Disk Access) with a Full Disk Access hint, root-owned system folders as exactly that; a category is flagged for attention only once enough of it is unreadable to matter. A "Largest files" group lists the top 25 files on the scanned roots regardless of the size threshold, Reveal-in-Finder only — context for where the disk went, not a cleanup candidate. macOS packages (`.app`, `.xcodeproj`, Photos/Music/iMovie libraries, VM bundles, …) are opaque to the walk — nothing inside one is ever listed or offered for deletion; a large data library is reported as a single informational item ("Data libraries" group, Reveal in Finder only) so the disk picture is complete — it is never a cleanup candidate. A `target` dir is recognised by its sibling `Cargo.toml` *or* by cargo's own `.rustc_info.json`/`CACHEDIR.TAG` inside it (relocated target dirs, workspace members); its primary remedy is `cargo clean --manifest-path …` with Trash as the alternative. Artifacts inside a linked git worktree name the main repository they belong to. A pnpm-linked `node_modules` reports how much of its size is hard-linked from the pnpm store (reclaimed only by `pnpm store prune`) and estimates the real reclaim; APFS clones are not detectable and can make it smaller still. The full directory tree from the walk is also published (`ScanEvent::DirTree`) for a drill-down folder browser, which the app/TUI is building separately. |
| Daemons | LaunchAgents/LaunchDaemons, flagging orphaned entries whose binary no longer exists. |
| Shell | Your login shell's `$PATH` (fish/zsh/bash): duplicates, dead entries, system dirs shadowing Homebrew, which entries MacAudit's own process cannot see (agents and apps launch with a different environment), and shell startup time. |
| Runtimes | Language version managers (nvm/fnm/volta/mise/asdf/pyenv/rustup) and their installed toolchain versions. |
| Docker | Reclaimable space per category (images, containers, volumes, build cache) via `docker system df`, plus active container CPU/RAM samples via one-shot `docker stats`. |
| Ports | Listening TCP ports with the owning process and PID. |
| Git | Local repos with uncommitted work, unpushed commits (including branches with no upstream), stashes, and working-tree sizes; package-manager checkouts are filtered out. |
| Simulators | iOS Simulator devices and runtimes, with targeted delete remedies for unavailable ones. |
| iOS Devices | A USB-connected iPhone/iPad's capacity, free, purgeable and committed space via `ideviceinfo`, plus every installed app's bundle and data size via `ideviceinstaller`; apps whose data dwarfs the app (offline downloads, caches) are flagged for attention. Read-only — remedies are copy-to-clipboard commands. |
| Keys | SSH keys in `~/.ssh`, flagging old or weak ones. |
| Time Machine | Backup health per destination (last backup, failures, quota), an exclusion-aware estimate of what the backup set would contain, exclusions and how much each saves, suggested exclusions with one-click `tmutil addexclusion`, stale `/Volumes/Backups of …` mount points, and local snapshots with the purgeable-space upper bound. |

## Global tools

What the section answers, and how honestly:

- **Classification is evidence-ranked, and "review" is the default.** A tool
  is *broken* when a launcher dangles, its interpreter is gone, or a declared
  binary is missing; *required* when something depends on it (a Homebrew
  formula owns the files, another package `Requires-Dist` it); *duplicate*
  when another installation or a cask binary provides the same command;
  *shadowed* when another copy wins resolution in your login shell;
  *project alternative* only when a repository under your roots has the tool
  **installed** locally (`node_modules/.bin`, `.venv/bin`, a pinned
  bootstrap download) — a manifest line alone is listed as evidence, not an
  alternative; *orphan* only when the manager itself confirms it. Being
  global, old, absent from shell history, or unreferenced by any repo is
  never treated as unnecessary.
- **Ownership is read from metadata, never guessed from `pip list`.** In
  Homebrew's site-packages, files symlinked into the Cellar (or `INSTALLER:
  brew`) belong to a formula and are protected; Homebrew's own pip/
  setuptools/wheel bootstrap is protected; `INSTALLER: pip` with real files
  is a manual install and gets a per-package
  `python3.X -m pip uninstall -y --break-system-packages <name>` — the
  externally-managed override is shown on that exact action, never applied
  silently, and there is no "uninstall everything" remedy. Apple's
  `/Library/Python` is inventory-only; project virtual environments are
  never inventoried.
- **pnpm layouts are handled separately.** The current `global/v<N>` layout
  uses `pnpm remove -g`; a legacy `global/<N>` layout is removed only with a
  pnpm of the same major found under `~/Library/pnpm/.tools` (with explicit
  `--global-dir`, `--store-dir` and `--virtual-store-dir` from its
  `.modules.yaml`); otherwise only its launchers are offered. pnpm homes and
  stores are never removal targets, and the `pnpm` package itself is
  protected.
- **Launchers are owned.** A launcher is removed only when it resolves into
  the installation being removed; a same-named launcher owned by another
  tool (uv's `~/.local/bin/mcp-proxy` next to a pipx copy, a cask's
  `/opt/homebrew/bin/codex` next to npm's) is listed as preserved. A missing
  uv entrypoint is reported with the note that `uv tool upgrade` may
  recreate it — not as broken.
- **Shell history is opt-in and aggregated.** With
  `shell_history_evidence = true`, only per-command invocation counts and
  the most recent timestamp are recorded, for command names the scan already
  knows; raw lines, arguments and anything secret-shaped never leave the
  parser, and a match is supporting evidence only.

## Cleanup workflow

1. **Discover** — the Global Tools and Brew sections (or `macaudit tools`,
   `macaudit brew why <x>`).
2. **Inspect** — the detail pane: classification reasons, per-command
   resolution, launchers, project evidence, interpreter ownership, and for
   Homebrew the requested roots that keep a dependency plus its single-package
   removal preview.
3. **Mark** — `space` on any row, including dependency nodes in the
   explorer (a shared dependency marked under one parent is marked
   everywhere); `e` picks an alternative remedy such as launcher-only
   removal.
4. **Preview** — `v` shows the batch: exact commands in execution order,
   refusals with reasons, Homebrew impact (still-needed packages stay,
   predicted orphans, brew-confirmed orphans, unknown-origin candidates),
   preserved launchers, follow-ups.
5. **Confirm** — `x` opens the same model as a confirm dialog.
6. **Execute** — after `y`, every target is re-checked against fresh data,
   then the batch runs dependents-first (Homebrew, then manager-native
   uninstalls, then launcher-only removals, then `brew autoremove` last).
   `Esc` stops after the current action.
7. **Verify** — the touched sections rescan, `brew autoremove --dry-run` is
   re-run so newly unneeded dependencies are offered from fresh data,
   retained tools related to the batch get bounded `--version` probes
   (run before *and* after, so a failure that already existed is reported as
   pre-existing, not as a regression), and the report (`c`) lists what ran,
   failed, was cancelled or refused, plus the verification table. The same
   report is written to `~/.local/state/macaudit/cleanup-reports/<ts>.json`.

Marks whose findings vanish on a rescan are dropped and announced; an open
confirm dialog is rebuilt so it can never reference a stale target.

### Known limitations

- Legacy pnpm layouts are removable natively only when a same-major pnpm
  exists locally; other pnpm layouts than `global/<N>` / `global/v<N>` are
  not understood.
- Current Homebrew does not report `installed_as_dependency`; origin relies
  on `installed_on_request` alone and is `unknown` when that flag is absent.
- Python `Requires-Dist` markers other than `extra ==` are not evaluated
  (they are listed as unevaluated). Apple and application-bundled Pythons
  are inventory-only.
- Login shells other than fish, zsh and bash fall back to the process PATH
  (the coverage row says so).

## Cutting a release

```sh
git tag v0.1.0 && git push --tags
```

That's it — there is no version to bump. The tag is the only version
source: `version` in `Cargo.toml` and `MARKETING_VERSION` in
`apps/MacAudit/project.yml` are `0.0.0` floors that
[build.rs](build.rs) and
[scripts/embed-git-version.sh](scripts/embed-git-version.sh) raise to the
nearest git tag at build time (a dev build of the CLI reports the full
`git describe`, e.g. `0.1.1-3-gabc1234-dirty`), and `scripts/package.sh`
passes the release version explicitly to both, then checks that the built
CLI and app report it.

[release.yml](.github/workflows/release.yml) builds the CLI and the app for
arm64, signs both with the Developer ID certificate, notarizes them, staples
the app, uploads `MacAudit-<version>.zip` (containing `MacAudit.app` and
`macaudit` side by side) to a GitHub Release, and triggers `bump.yml` in the
tap, which rewrites the cask's `version`/`sha256` with `brew bump-cask-pr`.
Running it by hand from the Actions tab (workflow_dispatch) does everything
except the release and the bump, under the nearest tag's version, and
uploads the zip as a workflow artifact — use that to prove the secrets work
before tagging.

The same two scripts run locally when the Developer ID certificate is in
your keychain:

```sh
scripts/package.sh 0.1.0 build/dist          # build + sign into build/dist (SIGN_IDENTITY=- for ad-hoc)
NOTARY_KEY_PATH=AuthKey.p8 NOTARY_KEY_ID=… NOTARY_ISSUER_ID=… \
  scripts/notarize.sh build/dist MacAudit-0.1.0.zip
```

### Release signing

`release.yml` needs six repository secrets, the same set (and the same
certificate, notary key and team `Y9A97FXT63`) as
[overboard](https://github.com/nickysemenza/overboard#release-signing),
whose README walks through generating each:

| Secret | Value |
|---|---|
| `DEVELOPER_ID_P12_BASE64` | `base64 -i cert.p12` of the exported Developer ID Application cert + key |
| `DEVELOPER_ID_P12_PASSWORD` | the `.p12` export password |
| `APP_STORE_CONNECT_API_KEY_P8` | contents of the App Store Connect API key's `.p8` |
| `APP_STORE_CONNECT_KEY_ID` | that key's ID |
| `APP_STORE_CONNECT_ISSUER_ID` | the key's issuer ID |
| `HOMEBREW_TAP_TOKEN` | fine-grained PAT with Actions read/write on `nickysemenza/homebrew-tap` only |

Set each with `gh secret set <NAME> --repo nickysemenza/macaudit`.

## License

MIT
