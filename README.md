# macaudit

A "why is my Mac like this" TUI — audits apps, disk hogs, daemons, and
dev-environment sprawl, with safe, explicit remediation.

<!-- screenshot placeholder -->

## Features

- **12 scanner sections**: Apps, Brew, Disk, Daemons, Shell, Runtimes,
  Docker, Ports, Git, Simulators, Keys, Snapshots — see the
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

macaudit is **read-only by default**. Scanning never modifies your system.

- **Nothing runs unseen.** Every remedy — delete, `brew upgrade`, `docker
  system prune`, whatever — is rendered as a literal command string and
  shown to you (in the detail pane, and again in the confirm dialog) before
  it ever executes. You always see exactly what will run.
- **Deletions default to Trash**, not `rm -rf`. Pass `--rm` if you want real
  deletion instead; that choice is explicit, global, and visible in every
  rendered command.
- **Network access is optional and narrow.** Nothing talks to the network
  unless you enable it; run with `--offline` to guarantee zero network
  calls. When enabled, the only endpoints ever contacted are
  `formulae.brew.sh` (Homebrew cask catalog) and `api.github.com` (release
  checks), both cached to disk so repeated scans don't re-fetch.

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
| `r` | Rescan current section |
| `R` | Rescan all sections |
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
| Apps | Installed applications, classified System / User / cask-managed / App Store / Unmanaged, with arch (Intel/Rosetta) and code-signing info. |
| Brew | Installed formulae and casks, dependency tree, outdated packages, casks correlated to installed `.app`s. |
| Disk | Build artifacts (`node_modules`, `target`, `.venv`, etc.), package-manager caches, and large loose files found by a parallel filesystem walk. |
| Daemons | LaunchAgents/LaunchDaemons and Ventura+ background items, flagging orphaned entries whose binary no longer exists. |
| Shell | `$PATH` duplicates and dead entries, plus shell startup time. |
| Runtimes | Language version managers (nvm/fnm/volta/mise/asdf/pyenv/rustup) and their installed toolchain versions. |
| Docker | Docker images, stopped containers, unused volumes, and build cache, when the daemon is reachable. |
| Ports | Listening TCP ports with the owning process and PID. |
| Git | Local repos with uncommitted work, unpushed commits, or stale branches. |
| Simulators | iOS Simulator devices and runtimes, flagging unavailable/legacy ones. |
| Keys | SSH keys in `~/.ssh`, flagging old or weak ones. |
| Snapshots | Time Machine local disk snapshots, which silently consume disk space. |

## License

MIT (or your choice)
