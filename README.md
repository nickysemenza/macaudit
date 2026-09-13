# macaudit

A "why is my Mac like this" TUI — audits apps, disk hogs, daemons, and
dev-environment sprawl, with safe, explicit remediation.

<!-- screenshot placeholder -->

## Features

- **Resource Health overview + 12 audit sections**: a manual point-in-time
  CPU/memory/swap/disk/process summary, plus Apps, Brew, Disk, Daemons, Shell,
  Runtimes, Docker, Ports, Git, Simulators, Keys, and Snapshots — see the
  [sections tour](#sections-tour) below.
- **Streaming, parallel scans.** Scanners run concurrently as async tasks
  (or in a blocking pool for the filesystem walk) and stream findings into
  the UI as they're discovered — nothing waits for the slowest scanner.
- **Snapshots & diff.** Every full scan is auto-saved to a local SQLite
  history so you can see what grew, what's new, and what disappeared since
  last time (`macaudit snapshot diff`).
- **Remediation with a Trash-first default.** Every finding that can be
  cleaned up carries an explicit remedy command; batch-executing marked
  items always shows you the exact command before it runs, and deletions go
  to the Trash unless you opt into `--rm`.

## Safety model

Scanning never modifies the things it audits: no files are deleted, no
packages touched, no settings changed. Honest fine print on what a scan
*does* do:

- **Read-only inspection commands are executed** (`system_profiler`, `brew`,
  `git status`, `lsof`, …). Two worth knowing about: `brew` is always run
  with `HOMEBREW_NO_AUTO_UPDATE=1` so it can't trigger Homebrew's
  auto-update, and the Shell section starts an interactive `zsh` to read
  your real login `$PATH` and measure startup time — which, by definition,
  executes your own shell configuration files.
- **macaudit writes its own state**: size caches and the catalog cache
  (`~/Library/Caches/macaudit`), and snapshot history
  (`~/.local/state/macaudit`). Never anything outside its own directories.
- **Nothing runs unseen.** Every remedy — delete, `brew upgrade`, `docker
  builder prune`, whatever — is rendered as a literal command string and
  shown to you (in the detail pane, and again in the confirm dialog) before
  it ever executes. You always see exactly what will run.
- **Deletions default to Trash**, not `rm -rf`. Pass `--rm` if you want real
  deletion instead; that choice is explicit, global, and visible in every
  rendered command.
- **Network access is on by default, narrow, and easy to disable.** The only
  endpoints ever contacted are `formulae.brew.sh` (Homebrew cask catalog)
  and `api.github.com` (release checks), both cached to disk so repeated
  scans don't re-fetch. Run with `--offline` (or set `[network] offline =
  true`) to guarantee zero HTTP — cached catalog data still works offline.

## Install

Requires macOS and a stable Rust toolchain.

```sh
cargo install --path .
```

## Usage

```sh
macaudit                              # launch the TUI (default)
macaudit scan --json                  # machine-readable scan, for scripts
macaudit scan --section apps,disk     # restrict to specific sections
macaudit clean --dry-run              # print remedy commands, run nothing
macaudit snapshot save                # scan and store a snapshot
macaudit snapshot list                # list stored snapshots
macaudit snapshot diff [A B]          # diff two snapshots (defaults: latest two)
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

| Key | Action |
|---|---|
| `j`/`k`, arrows | Move selection |
| `tab` / `shift-tab` | Next / previous section |
| `←` / `→` | Collapse/expand tree group (else switch section) |
| `space` | Mark / unmark row |
| `enter` | Toggle detail pane (else expand/collapse tree group) |
| `x` | Execute marked remedies (confirm dialog) |
| `r` | Refresh the current point-in-time section |
| `R` | Refresh all sections and save durable history |
| `/` | Filter by substring |
| `s` | Cycle sort (size / name / severity) |
| `h` | Toggle System apps visibility |
| `PgUp` / `PgDn` (or `ctrl-u` / `ctrl-d`) | Scroll detail pane |
| `?` | Toggle keybindings help |
| `q` | Quit |

## Configuration

`~/.config/macaudit/config.toml` — all fields optional; a missing or partial
file falls back to these defaults:

```toml
[scan]
roots = []                       # fs walk roots; empty -> [$HOME]
ignore = []                      # paths to never descend into (tilde-expanded)
large_file_threshold_gb = 1.0    # loose files larger than this are flagged
# Cached sizes are reused while the tree root's mtime is unchanged AND the
# entry is younger than this TTL. Deep-nested changes don't bump a root's
# mtime, so a stale size can persist up to the TTL — lower it if that matters.
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
```

## Sections tour

| Section | What it finds |
|---|---|
| Resource Health | Manual CPU load, memory pressure/compression, swap, and current high-CPU/RAM processes. Root Disk explicitly distinguishes raw APFS free space from macOS available capacity, which includes purgeable space. It names the count of local Time Machine snapshots, but does not invent a byte size for them: macOS does not report a reliable per-snapshot or aggregate total. It is a point-in-time view, not a background monitor; live observations never enter snapshot diffs. |
| Apps | Installed applications, classified System / User / cask-managed / App Store / Unmanaged, with arch (Intel/Rosetta) and code-signing info. |
| Brew | Installed formulae and casks, dependency tree, outdated packages, casks correlated to installed `.app`s. |
| Disk | Build artifacts (`node_modules`, `target`, `.venv`, etc.), package-manager caches, and large loose files found by a parallel filesystem walk, plus bounded top-level allocation categories with explicit coverage labels. |
| Daemons | LaunchAgents/LaunchDaemons, flagging orphaned entries whose binary no longer exists. |
| Shell | `$PATH` duplicates and dead entries, plus shell startup time. |
| Runtimes | Language version managers (nvm/fnm/volta/mise/asdf/pyenv/rustup) and their installed toolchain versions. |
| Docker | Reclaimable space per category (images, containers, volumes, build cache) via `docker system df`, plus active container CPU/RAM samples via one-shot `docker stats`; active samples are not stored in history. |
| Ports | Listening TCP ports with the owning process and PID. |
| Git | Local repos with uncommitted work, unpushed commits (including branches with no upstream), stashes, and working-tree sizes; package-manager checkouts are filtered out. |
| Simulators | iOS Simulator devices and runtimes, with targeted delete remedies for unavailable ones. |
| Keys | SSH keys in `~/.ssh`, flagging old or weak ones. |
| Snapshots | Time Machine local disk snapshots, which silently consume disk space. |

## License

MIT
