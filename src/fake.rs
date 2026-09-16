//! A synthetic scanner used by the `--fake` flag and manual QA of the TUI. It
//! proves the architecture end-to-end (streaming findings, deferred sizing,
//! remedies, cancellation) without touching the real machine, and — via
//! [`fixtures`] — gives every section enough realistic, varied findings that
//! the Overview cards, tree grouping (`meta.group`), and detail pane all have
//! something believable to render.
//!
//! Every fixture's `meta` keys and title/detail formats are copied from the
//! real scanner that owns the section (see the `src/scan/*.rs` module docs),
//! so this doubles as a seed for the UI ↔ scanner contract: if a real scanner
//! changes its `meta` shape, this file should change with it.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde_json::json;

use crate::model::{
    Finding, FindingKind, Guard, Remedy, RemedyCommand, ScanEvent, ScannerId, Severity,
};
use crate::scan::walk::{BigFile, DirNode, DirTree};
use crate::scan::{ScanCtx, Scanner};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// `days` in the past, saturating at the Unix epoch rather than panicking —
/// fixtures only need "plausibly old", not calendar precision.
fn ago(days: u64) -> SystemTime {
    SystemTime::now()
        .checked_sub(Duration::from_secs(days.saturating_mul(86_400)))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn reveal(path: &str) -> Remedy {
    Remedy {
        label: "Reveal in Finder".to_string(),
        command: RemedyCommand::RevealInFinder {
            path: PathBuf::from(path),
        },
        reclaims_bytes: None,
        destructive: false,
        alternative: false,
        guard: None,
    }
}

fn trash(path: &str, reclaims_bytes: Option<u64>) -> Remedy {
    Remedy {
        label: "Move to Trash".to_string(),
        command: RemedyCommand::Trash {
            path: PathBuf::from(path),
        },
        reclaims_bytes,
        destructive: true,
        alternative: false,
        guard: None,
    }
}

/// 6-10 realistic findings for one section, seeded deterministically (no
/// randomness) so they can double as regression fixtures. Meta keys and
/// title/detail formats mirror the real scanner for that section exactly.
pub fn fixtures(id: ScannerId) -> Vec<Finding> {
    match id {
        ScannerId::System => system_fixtures(),
        ScannerId::Apps => apps_fixtures(),
        ScannerId::Brew => brew_fixtures(),
        ScannerId::Fs => fs_fixtures(),
        ScannerId::Launchd => launchd_fixtures(),
        ScannerId::ShellEnv => shell_env_fixtures(),
        ScannerId::Runtimes => runtimes_fixtures(),
        ScannerId::Docker => docker_fixtures(),
        ScannerId::Ports => ports_fixtures(),
        ScannerId::Git => git_fixtures(),
        ScannerId::Simulator => simulator_fixtures(),
        ScannerId::Ios => ios_fixtures(),
        ScannerId::SshKeys => ssh_keys_fixtures(),
        ScannerId::TimeMachine => time_machine_fixtures(),
        ScannerId::Tools => tools_fixtures(),
    }
}

/// Mirrors `src/scan/system.rs`: 4 SystemMetric findings (`role` one of
/// cpu/memory/swap/disk) plus a handful of ProcessResource findings.
fn system_fixtures() -> Vec<Finding> {
    vec![
        Finding::new(FindingKind::SystemMetric, "cpu-load", "CPU load")
            .detail("load average 6.42 / 4.10 / 3.05 across 8 cores")
            .severity(Severity::Attention)
            .meta(json!({
                "role": "cpu",
                "load_1": 6.42,
                "load_5": 4.10,
                "load_15": 3.05,
                "cores": 8,
            })),
        Finding::new(FindingKind::SystemMetric, "memory", "Memory pressure")
            .detail("14.2 GiB used of 16.0 GiB; 2.1 GiB compressed; 82% pressure")
            .severity(Severity::Warning)
            .meta(json!({
                "role": "memory",
                "used_bytes": 15 * GIB + 205 * MIB,
                "total_bytes": 16 * GIB,
                "compressed_bytes": 2 * GIB + 100 * MIB,
                "pressure_percent": 82,
                "free_percent": 18,
            })),
        Finding::new(FindingKind::SystemMetric, "swap", "Swap")
            .detail("512.0 MiB used of 2.0 GiB")
            .severity(Severity::Info)
            .meta(json!({
                "role": "swap",
                "used_bytes": 512 * MIB,
                "total_bytes": 2 * GIB,
            })),
        Finding::new(FindingKind::SystemMetric, "root-disk", "Root disk")
            .detail(
                "412.3 GiB used of 494.4 GiB; 82.1 GiB APFS free; 96.4 GiB macOS available \
                 (includes ~14.3 GiB macOS-managed space: 3 local Time Machine snapshots, \
                 whose exact bytes macOS does not report, plus other purgeable space it does \
                 not itemize)",
            )
            .size(412 * GIB + 300 * MIB)
            .severity(Severity::Attention)
            .meta(json!({
                "role": "disk",
                "capacity_bytes": 494 * GIB + 400 * MIB,
                "used_bytes": 412 * GIB + 300 * MIB,
                "apfs_free_bytes": 82 * GIB + 100 * MIB,
                "macos_available_bytes": 96 * GIB + 400 * MIB,
                "estimated_reclaimable_bytes": 14 * GIB + 300 * MIB,
                "local_time_machine_snapshot_count": 3,
            })),
        Finding::new(FindingKind::ProcessResource, "4821:node", "node (pid 4821)")
            .detail("12.4% CPU · 180.0 MiB resident · dev · S")
            .severity(Severity::Info)
            .meta(json!({
                "role": "process", "pid": 4821, "user": "dev", "cpu_percent": 12.4,
                "memory_percent": 1.1, "rss_bytes": 180 * MIB, "state": "S", "command": "node",
            })),
        Finding::new(FindingKind::ProcessResource, "512:Xcode", "Xcode (pid 512)")
            .detail("64.2% CPU · 2.1 GiB resident · dev · S")
            .severity(Severity::Attention)
            .meta(json!({
                "role": "process", "pid": 512, "user": "dev", "cpu_percent": 64.2,
                "memory_percent": 13.2, "rss_bytes": 2 * GIB + 100 * MIB, "state": "S",
                "command": "Xcode",
            })),
        Finding::new(
            FindingKind::ProcessResource,
            "933:com.docker.backend",
            "com.docker.backend (pid 933)",
        )
        .detail("8.1% CPU · 512.0 MiB resident · dev · S")
        .severity(Severity::Info)
        .meta(json!({
            "role": "process", "pid": 933, "user": "dev", "cpu_percent": 8.1,
            "memory_percent": 3.2, "rss_bytes": 512 * MIB, "state": "S",
            "command": "com.docker.backend",
        })),
        Finding::new(
            FindingKind::ProcessResource,
            "210:mds_stores",
            "mds_stores (pid 210)",
        )
        .detail("132.5% CPU · 620.0 MiB resident · root · R")
        .severity(Severity::Warning)
        .meta(json!({
            "role": "process", "pid": 210, "user": "root", "cpu_percent": 132.5,
            "memory_percent": 3.9, "rss_bytes": 620 * MIB, "state": "R",
            "command": "mds_stores",
        })),
    ]
}

/// Mirrors `src/scan/apps.rs`: key = bundle path, title `"{name} {version}"`,
/// meta classification/group/arch/obtained_from/signed_by/version/bundle_id/
/// rosetta_or_intel_only/is_apple_silicon_host. `available_cask` is normally
/// added later by net enrichment (`src/net/enrich.rs`); seeded directly here
/// so the cask-upgrade badge has something to render in `--fake` mode.
fn apps_fixtures() -> Vec<Finding> {
    vec![
        Finding::new(
            FindingKind::App,
            "/System/Applications/Safari.app",
            "Safari 17.4",
        )
        .path("/System/Applications/Safari.app")
        .detail("system — apple")
        .severity(Severity::Info)
        .meta(json!({
            "classification": "system", "group": "System", "arch": "arch_arm_i64",
            "obtained_from": "apple", "signed_by": "Software Signing, Apple Root CA",
            "version": "17.4", "bundle_id": "com.apple.Safari",
            "rosetta_or_intel_only": false, "is_apple_silicon_host": true,
        }))
        .remedy(reveal("/System/Applications/Safari.app")),
        Finding::new(FindingKind::App, "/Applications/Xcode.app", "Xcode 15.3")
            .path("/Applications/Xcode.app")
            .detail("app_store — mac_app_store")
            .severity(Severity::Info)
            .meta(json!({
                "classification": "app_store", "group": "App Store", "arch": "arch_arm_i64",
                "obtained_from": "mac_app_store", "signed_by": "Apple Mac OS Application Signing",
                "version": "15.3", "bundle_id": "com.apple.dt.Xcode",
                "rosetta_or_intel_only": false, "is_apple_silicon_host": true,
            }))
            .remedy(reveal("/Applications/Xcode.app")),
        Finding::new(
            FindingKind::App,
            "/Applications/Keynote.app",
            "Keynote 13.3",
        )
        .path("/Applications/Keynote.app")
        .detail("user — apple")
        .severity(Severity::Info)
        .meta(json!({
            "classification": "user", "group": "User", "arch": "arch_arm_i64",
            "obtained_from": "apple", "signed_by": "Software Signing, Apple Root CA",
            "version": "13.3", "bundle_id": "com.apple.iWork.Keynote",
            "rosetta_or_intel_only": false, "is_apple_silicon_host": true,
        }))
        .remedy(reveal("/Applications/Keynote.app")),
        Finding::new(FindingKind::App, "/Applications/Slack.app", "Slack 4.36.0")
            .path("/Applications/Slack.app")
            .detail("cask — identified_developer")
            .severity(Severity::Info)
            .meta(json!({
                "classification": "cask", "group": "Homebrew Cask", "arch": "arch_arm_i64",
                "obtained_from": "identified_developer",
                "signed_by": "Developer ID Application: Slack Technologies, Inc.",
                "version": "4.36.0", "bundle_id": "com.tinyspeck.slackmacgap",
                "rosetta_or_intel_only": false, "is_apple_silicon_host": true,
                "managed_by_cask": "slack",
            }))
            .remedy(reveal("/Applications/Slack.app")),
        Finding::new(
            FindingKind::App,
            "/Applications/Docker.app",
            "Docker 4.29.0",
        )
        .path("/Applications/Docker.app")
        .detail("cask — identified_developer")
        .severity(Severity::Info)
        .meta(json!({
            "classification": "cask", "group": "Homebrew Cask", "arch": "arch_arm_i64",
            "obtained_from": "identified_developer",
            "signed_by": "Developer ID Application: Docker Inc",
            "version": "4.29.0", "bundle_id": "com.docker.docker",
            "rosetta_or_intel_only": false, "is_apple_silicon_host": true,
            "managed_by_cask": "docker",
        }))
        .remedy(reveal("/Applications/Docker.app")),
        Finding::new(FindingKind::App, "/Applications/iTerm.app", "iTerm 3.4.20")
            .path("/Applications/iTerm.app")
            .detail("unmanaged — identified_developer")
            .severity(Severity::Attention)
            .meta(json!({
                "classification": "unmanaged", "group": "Unmanaged (Applications)",
                "arch": "arch_arm_i64", "obtained_from": "identified_developer",
                "signed_by": "Developer ID Application: George Nachman",
                "version": "3.4.20", "bundle_id": "com.googlecode.iterm2",
                "rosetta_or_intel_only": false, "is_apple_silicon_host": true,
                "available_cask": "iterm2",
            }))
            .remedy(reveal("/Applications/iTerm.app")),
        Finding::new(
            FindingKind::App,
            "/Applications/LegacyPhotoEditor.app",
            "LegacyPhotoEditor 1.0",
        )
        .path("/Applications/LegacyPhotoEditor.app")
        .detail("unmanaged — identified_developer (Intel/Rosetta on Apple Silicon)")
        .severity(Severity::Attention)
        .meta(json!({
            "classification": "unmanaged", "group": "Unmanaged (Applications)",
            "arch": "arch_i64", "obtained_from": "identified_developer",
            "signed_by": "Developer ID Application: OldVendor LLC",
            "version": "1.0", "bundle_id": "com.oldvendor.legacyphotoeditor",
            "rosetta_or_intel_only": true, "is_apple_silicon_host": true,
        }))
        .remedy(reveal("/Applications/LegacyPhotoEditor.app")),
        Finding::new(
            FindingKind::App,
            "/Library/Application Support/VendorCo/VendorHelper.app",
            "VendorHelper 2.1",
        )
        .path("/Library/Application Support/VendorCo/VendorHelper.app")
        .detail("unmanaged — unknown source")
        .severity(Severity::Attention)
        .meta(json!({
            "classification": "unmanaged", "group": "Unmanaged (helpers & other locations)",
            "arch": "arch_arm_i64", "obtained_from": "unknown",
            "signed_by": null, "version": "2.1", "bundle_id": null,
            "rosetta_or_intel_only": false, "is_apple_silicon_host": true,
        }))
        .remedy(reveal(
            "/Library/Application Support/VendorCo/VendorHelper.app",
        )),
    ]
}

/// Mirrors `src/scan/brew.rs`: BrewFormula meta name/full_name/version/
/// install_reason (requested|dependency|unknown, from installed_on_request)/
/// is_leaf/dependencies/dependents (+ `_transitive`)/autoremove_candidate/
/// removal_preview/group, detail `"{reason} — {ver}[ · leaf]"`; BrewCask meta
/// token/version/app_paths/binaries/depends_on/cask_dependents/group=Casks;
/// plus the `__autoremove__` summary row.
fn brew_fixtures() -> Vec<Finding> {
    struct F<'a> {
        name: &'a str,
        version: &'a str,
        reason: &'a str,
        deps: &'a [&'a str],
        deps_t: &'a [&'a str],
        used_by: &'a [&'a str],
        used_by_t: &'a [&'a str],
        auto: bool,
    }
    /// The one-line `desc` Homebrew publishes for each package.
    fn brew_desc(name: &str) -> Option<&'static str> {
        Some(match name {
            "wget" => "Internet file retriever",
            "ripgrep" => "Search tool like grep and The Silver Searcher",
            "jq" => "Lightweight and flexible command-line JSON processor",
            "python@3.14" => "Interpreted, interactive, object-oriented programming language",
            "pgcli" => "CLI for Postgres with auto-completion and syntax highlighting",
            "pre-commit" => "Framework for managing multi-language pre-commit hooks",
            "yt-dlp" => "Feature-rich command-line audio/video downloader",
            "openssl@3" => "Cryptography and SSL/TLS Toolkit",
            "libidn2" => "International domain name library (IDNA2008, Punycode and TR46)",
            "libunistring" => "C string library for manipulating Unicode strings",
            "pcre2" => "Perl compatible regular expressions library with a new API",
            "oniguruma" => "Regular expressions library",
            "libevent" => "Asynchronous event library",
            "docker" => "App to build and share containerised applications and microservices",
            "visual-studio-code" => "Open-source code editor",
            "pdftk-java" => "Command-line tool for working with PDFs",
            _ => return None,
        })
    }

    fn formula(f: F<'_>) -> Finding {
        let F {
            name,
            version,
            reason,
            deps,
            deps_t,
            used_by,
            used_by_t,
            auto,
        } = f;
        let leaf = used_by.is_empty() && used_by_t.is_empty();
        let group = if auto {
            "Autoremove candidates"
        } else {
            match reason {
                "requested" => "Explicitly installed",
                "dependency" => "Installed as dependency",
                _ => "Unknown origin",
            }
        };
        let mut detail = format!("{reason} — {version}");
        if leaf {
            detail.push_str(" · leaf");
        }
        if auto {
            detail.push_str(" · brew autoremove candidate");
        }
        let description = brew_desc(name);
        if let Some(d) = description {
            detail.push_str(&format!(" · {d}"));
        }
        let on_request = match reason {
            "requested" => json!(true),
            "dependency" => json!(false),
            _ => json!(null),
        };
        let mut f = Finding::new(FindingKind::BrewFormula, name, name)
            .detail(detail)
            .path(PathBuf::from(format!("/opt/homebrew/Cellar/{name}")))
            .severity(if auto { Severity::Reclaimable } else { Severity::Info })
            .provenance("brew info --json=v2 --installed (install receipt runtime_dependencies); brew autoremove --dry-run")
            .meta(json!({
                "name": name, "full_name": name, "tap": "homebrew/core", "aliases": [],
                "version": version, "description": description, "install_reason": reason, "installed_on_request": on_request,
                "installed_as_dependency": null, "is_leaf": leaf, "pinned": false,
                "outdated": false, "current_version": null,
                "dependencies": deps, "dependents": used_by,
                "dependencies_transitive": deps_t, "dependents_transitive": used_by_t,
                "cask_dependents": [], "dependency_source": "installed_runtime",
                "why_installed": { "reason": reason, "requested_roots": used_by_t.iter().chain(used_by.iter()).collect::<Vec<_>>(), "paths": [] },
                "autoremove_candidate": auto,
                "removal_preview": { "removable": leaf, "blocked_by": used_by, "would_orphan": [], "confirmed_orphans": [], "uncertain_orphans": [] },
                "graph_caveats": [], "completeness": "full", "group": group,
            }));
        if leaf {
            f = f.remedy(
                Remedy::new(
                    "Uninstall formula",
                    RemedyCommand::Shell {
                        program: "brew".to_string(),
                        args: vec!["uninstall".to_string(), name.to_string()],
                    },
                )
                .destructive()
                .guard(Guard::BrewFormula {
                    full_name: name.to_string(),
                    expected_version: Some(version.to_string()),
                    require_no_retained_dependents: true,
                }),
            );
        }
        f
    }
    fn cask(
        token: &str,
        version: &str,
        app: &str,
        binary: Option<&str>,
        formula_deps: &[&str],
    ) -> Finding {
        let binaries = match binary {
            Some(b) => {
                json!([{ "source": format!("bin/{b}"), "target": format!("/opt/homebrew/bin/{b}") }])
            }
            None => json!([]),
        };
        let description = brew_desc(token);
        let mut detail = format!("cask — {version}");
        if let Some(d) = description {
            detail.push_str(&format!(" · {d}"));
        }
        Finding::new(FindingKind::BrewCask, token, token)
            .detail(detail)
            .severity(Severity::Info)
            .provenance("brew info --json=v2 --installed")
            .meta(json!({
                "token": token, "name": token, "version": version, "description": description,
                "app_paths": [format!("/Applications/{app}")], "binaries": binaries,
                "depends_on": { "formula": formula_deps, "cask": [] }, "cask_dependents": [],
                "outdated": false, "current_version": null, "completeness": "full", "group": "Casks",
            }))
            .remedy(
                Remedy::new(
                    "Uninstall cask",
                    RemedyCommand::Shell {
                        program: "brew".to_string(),
                        args: vec!["uninstall".to_string(), "--cask".to_string(), token.to_string()],
                    },
                )
                .destructive()
                .guard(Guard::BrewCask { token: token.to_string(), expected_version: Some(version.to_string()) }),
            )
    }
    let mut wget = formula(F {
        name: "wget",
        version: "1.21.4",
        reason: "requested",
        deps: &["libidn2", "openssl@3"],
        deps_t: &["libunistring"],
        used_by: &[],
        used_by_t: &[],
        auto: false,
    })
    .severity(Severity::Attention)
    .detail("requested — 1.21.4 · leaf · 1.24.5 available");
    if let Some(m) = wget.meta.as_object_mut() {
        m.insert("outdated".into(), json!(true));
        m.insert("current_version".into(), json!("1.24.5"));
    }
    wget.remedies.insert(
        0,
        Remedy::new(
            "Upgrade to 1.24.5",
            RemedyCommand::Shell {
                program: "brew".to_string(),
                args: vec!["upgrade".to_string(), "wget".to_string()],
            },
        ),
    );
    vec![
        formula(F { name: "ripgrep", version: "14.1.0", reason: "requested", deps: &["pcre2"], deps_t: &[], used_by: &[], used_by_t: &[], auto: false }),
        formula(F { name: "jq", version: "1.7.1", reason: "requested", deps: &["oniguruma"], deps_t: &[], used_by: &[], used_by_t: &[], auto: false }),
        wget,
        formula(F { name: "python@3.14", version: "3.14.7", reason: "requested", deps: &["openssl@3", "sqlite", "xz"], deps_t: &["ca-certificates"], used_by: &["pgcli", "pre-commit", "yt-dlp"], used_by_t: &[], auto: false }),
        formula(F { name: "pgcli", version: "4.3.0", reason: "requested", deps: &["python@3.14"], deps_t: &["openssl@3", "sqlite", "xz", "ca-certificates"], used_by: &[], used_by_t: &[], auto: false }),
        formula(F { name: "pre-commit", version: "4.3.0", reason: "requested", deps: &["python@3.14"], deps_t: &["openssl@3", "sqlite", "xz", "ca-certificates"], used_by: &[], used_by_t: &[], auto: false }),
        formula(F { name: "yt-dlp", version: "2026.09.01", reason: "requested", deps: &["python@3.14"], deps_t: &["openssl@3", "sqlite", "xz", "ca-certificates"], used_by: &[], used_by_t: &[], auto: false }),
        formula(F { name: "openssl@3", version: "3.6.3", reason: "dependency", deps: &["ca-certificates"], deps_t: &[], used_by: &["python@3.14", "wget"], used_by_t: &["pgcli", "pre-commit", "yt-dlp"], auto: false }),
        formula(F { name: "libidn2", version: "2.3.7", reason: "dependency", deps: &["libunistring"], deps_t: &[], used_by: &["wget"], used_by_t: &[], auto: false }),
        formula(F { name: "libunistring", version: "1.2", reason: "dependency", deps: &[], deps_t: &[], used_by: &["libidn2"], used_by_t: &["wget"], auto: false }),
        formula(F { name: "pcre2", version: "10.43", reason: "dependency", deps: &[], deps_t: &[], used_by: &["ripgrep"], used_by_t: &[], auto: false }),
        formula(F { name: "oniguruma", version: "6.9.9", reason: "dependency", deps: &[], deps_t: &[], used_by: &["jq"], used_by_t: &[], auto: false }),
        formula(F { name: "libevent", version: "2.1.13", reason: "dependency", deps: &[], deps_t: &[], used_by: &[], used_by_t: &[], auto: true }),
        formula(F { name: "oldlib", version: "0.1", reason: "unknown", deps: &[], deps_t: &[], used_by: &[], used_by_t: &[], auto: false }),
        cask("docker", "4.29.0", "Docker.app", None, &[]),
        cask("visual-studio-code", "1.89.1", "Visual Studio Code.app", Some("code"), &[]),
        cask("pdftk-java", "3.3.3", "PDFtk.app", Some("pdftk"), &["openjdk"]),
        Finding::new(FindingKind::BrewFormula, "__autoremove__", "Homebrew autoremove candidates")
            .detail("1 formula(e) Homebrew reports as no longer needed: libevent")
            .severity(Severity::Reclaimable)
            .provenance("brew autoremove --dry-run")
            .meta(json!({ "candidates": ["libevent"], "source": "brew autoremove --dry-run", "group": "Autoremove candidates" }))
            .remedy(
                Remedy::new(
                    "Remove all unneeded dependencies",
                    RemedyCommand::Shell { program: "brew".into(), args: vec!["autoremove".into()] },
                )
                .destructive(),
            ),
    ]
}

/// Mirrors `src/scan/global_tools`: GlobalTool meta manager/layout/name/
/// version (null = unknown)/identity_key/root/commands/launchers/resolution/
/// classifications/primary_classification/completeness/removal/group;
/// CommandResolution meta command/user_shell/user_resolution/
/// process_resolution/differs/candidates; one ToolCoverage `__coverage__`.
/// Scenarios are the real ones from the 2026-09-13 cleanup: an npm codex
/// shadowed by a cask binary, dangling pnpm launchers left in npm's bin, a
/// legacy pnpm global dir, a pipx venv on a removed interpreter, a uv tool
/// with a missing entrypoint, brew-owned vs pip-installed site packages.
fn tools_fixtures() -> Vec<Finding> {
    struct Spec<'a> {
        manager: &'a str,
        root: &'a str,
        name: &'a str,
        version: Option<&'a str>,
        class: &'a str,
        detail: &'a str,
        severity: Severity,
    }
    fn tool(spec: Spec<'_>, extra: serde_json::Value) -> Finding {
        let Spec {
            manager,
            root,
            name,
            version,
            class,
            detail,
            severity,
        } = spec;
        let key = format!("{manager}:{root}:{name}");
        let mut meta = json!({
            "manager": manager,
            "layout": null,
            "name": name,
            "version": version,
            "identity_key": key,
            "root": root,
            "root_realpath": null,
            "install_dir": format!("{root}/{name}"),
            "runtime": null,
            "commands": [{ "name": name, "declared_target": null }],
            "launchers": [],
            "foreign_launchers": [],
            "resolution": { name: { "user_shell": null, "process": null, "status": "unknown", "shadowed_by": null, "candidates": [] } },
            "classifications": [{ "kind": class }],
            "primary_classification": class,
            "evidence": [],
            "project_refs": [],
            "project_coverage": null,
            "history": null,
            "completeness": { "level": "full", "missing": [] },
            "protected": null,
            "removal": { "native": null, "launcher_only": [], "refusals": [], "follow_up": [] },
            "manager_extra": {},
            "group": format!("{manager} ({})", root.replace("/Users/nicky", "~")),
        });
        if let (Some(base), Some(over)) = (meta.as_object_mut(), extra.as_object()) {
            for (k, v) in over {
                base.insert(k.clone(), v.clone());
            }
        }
        Finding::new(FindingKind::GlobalTool, &key, name)
            .detail(detail)
            .path(PathBuf::from(format!("{root}/{name}")))
            .severity(severity)
            .provenance("package metadata + launcher inspection")
            .meta(meta)
    }
    let native = |program: &str, args: &[&str]| -> Remedy {
        Remedy {
            label: format!(
                "Uninstall via {}",
                Path::new(program)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(program)
            ),
            command: RemedyCommand::Shell {
                program: program.to_string(),
                args: args.iter().map(|a| a.to_string()).collect(),
            },
            reclaims_bytes: None,
            destructive: true,
            alternative: false,
            guard: None,
        }
    };
    vec![
        tool(
            Spec {
                manager: "npm",
                root: "/opt/homebrew/lib/node_modules",
                name: "@openai/codex",
                version: Some("0.118.0"),
                class: "shadowed",
                detail: "shadowed — /opt/homebrew/bin/codex is the cask binary, not this npm copy",
                severity: Severity::Attention,
            },
            json!({
                "commands": [{ "name": "codex", "declared_target": "bin/codex.js" }],
                "launchers": [],
                "foreign_launchers": [{ "path": "/opt/homebrew/bin/codex", "owner": { "kind": "homebrew_cask", "token": "codex" } }],
                "resolution": { "codex": { "user_shell": "/opt/homebrew/bin/codex", "process": "/opt/homebrew/bin/codex", "status": "shadowed", "shadowed_by": "/opt/homebrew/bin/codex", "candidates": [["/opt/homebrew/bin/codex", { "kind": "homebrew_cask", "token": "codex" }]] } },
                "classifications": [{ "kind": "duplicate", "peers": ["brew_cask:codex"] }, { "kind": "shadowed", "by": "/opt/homebrew/bin/codex", "owner": { "kind": "homebrew_cask", "token": "codex" } }],
                "primary_classification": "shadowed",
                "removal": { "native": { "program": "/opt/homebrew/bin/npm", "args": ["uninstall", "-g", "@openai/codex"] }, "launcher_only": [], "refusals": [], "follow_up": ["the cask binary /opt/homebrew/bin/codex stays"] },
            }),
        )
        .size(48 * 1024 * 1024)
        .remedy(native("/opt/homebrew/bin/npm", &["uninstall", "-g", "@openai/codex"])),
        tool(
            Spec {
                manager: "npm",
                root: "/opt/homebrew/lib/node_modules",
                name: "pnpm",
                version: None,
                class: "broken",
                detail: "broken — launchers pn, pnpx, pnx dangle into a removed package",
                severity: Severity::Attention,
            },
            json!({
                "commands": [],
                "launchers": [
                    { "path": "/opt/homebrew/bin/pn", "kind": "symlink", "target": "../lib/node_modules/pnpm/pn", "target_exists": false, "owner": { "kind": "this_install" } },
                    { "path": "/opt/homebrew/bin/pnpx", "kind": "symlink", "target": "../lib/node_modules/pnpm/pnpx", "target_exists": false, "owner": { "kind": "this_install" } },
                    { "path": "/opt/homebrew/bin/pnx", "kind": "symlink", "target": "../lib/node_modules/pnpm/pnx", "target_exists": false, "owner": { "kind": "this_install" } }
                ],
                "classifications": [{ "kind": "broken", "reason": "3 launchers point at a package that is no longer installed" }],
                "primary_classification": "broken",
                "removal": { "native": null, "launcher_only": ["/opt/homebrew/bin/pn", "/opt/homebrew/bin/pnpx", "/opt/homebrew/bin/pnx"], "refusals": [], "follow_up": [] },
            }),
        )
        .remedy(Remedy {
            label: "Remove dangling launcher pn".to_string(),
            command: RemedyCommand::Trash { path: PathBuf::from("/opt/homebrew/bin/pn") },
            reclaims_bytes: None,
            destructive: true,
            alternative: false,
            guard: Some(Guard::Launcher { path: PathBuf::from("/opt/homebrew/bin/pn"), expected_target: Some(PathBuf::from("../lib/node_modules/pnpm/pn")), expect_dangling: true, owner_key: "npm:/opt/homebrew/lib/node_modules:pnpm".to_string() }),
        }),
        tool(
            Spec {
                manager: "pnpm",
                root: "/Users/nicky/Library/pnpm/global/5",
                name: "clawhub",
                version: Some("0.7.0"),
                class: "review",
                detail: "legacy pnpm layout 5 (pnpm@10.30.0 store) — current `pnpm ls -g` does not list it",
                severity: Severity::Info,
            },
            json!({
                "layout": "legacy-5",
                "commands": [{ "name": "clawhub", "declared_target": "dist/cli.js" }, { "name": "clawdhub", "declared_target": "dist/cli.js" }],
                "launchers": [
                    { "path": "/Users/nicky/Library/pnpm/clawhub", "kind": "sh_shim", "target": "/Users/nicky/Library/pnpm/global/5/node_modules/clawhub/dist/cli.js", "target_exists": true, "owner": { "kind": "this_install" } },
                    { "path": "/Users/nicky/Library/pnpm/clawdhub", "kind": "sh_shim", "target": "/Users/nicky/Library/pnpm/global/5/node_modules/clawhub/dist/cli.js", "target_exists": true, "owner": { "kind": "this_install" } }
                ],
                "resolution": { "clawhub": { "user_shell": "/Users/nicky/Library/pnpm/clawhub", "process": null, "status": "active_in_shell", "shadowed_by": null, "candidates": [] }, "clawdhub": { "user_shell": "/Users/nicky/Library/pnpm/clawdhub", "process": null, "status": "active_in_shell", "shadowed_by": null, "candidates": [] } },
                "classifications": [{ "kind": "review", "reason": "no project references; legacy layout not shown by the current pnpm" }],
                "manager_extra": { "layout_version": 5, "package_manager": "pnpm@10.30.0", "store_dir": "/Users/nicky/Library/pnpm/store/v10", "virtual_store_dir": "/Users/nicky/Library/pnpm/global/5/.pnpm", "matching_local_pnpm": "/Users/nicky/Library/pnpm/.tools/@pnpm+macos-arm64/10.30.0/bin/pnpm" },
                "removal": { "native": { "program": "/Users/nicky/Library/pnpm/.tools/@pnpm+macos-arm64/10.30.0/bin/pnpm", "args": ["remove", "-g", "clawhub", "--global-dir", "/Users/nicky/Library/pnpm/global/5", "--store-dir", "/Users/nicky/Library/pnpm/store/v10", "--virtual-store-dir", "/Users/nicky/Library/pnpm/global/5/.pnpm"] }, "launcher_only": ["/Users/nicky/Library/pnpm/clawhub", "/Users/nicky/Library/pnpm/clawdhub"], "refusals": [], "follow_up": ["never remove ~/Library/pnpm/global or the store wholesale"] },
            }),
        )
        .size(21 * 1024 * 1024)
        .remedy(native("/Users/nicky/Library/pnpm/.tools/@pnpm+macos-arm64/10.30.0/bin/pnpm", &["remove", "-g", "clawhub", "--global-dir", "/Users/nicky/Library/pnpm/global/5", "--store-dir", "/Users/nicky/Library/pnpm/store/v10", "--virtual-store-dir", "/Users/nicky/Library/pnpm/global/5/.pnpm"])),
        tool(
            Spec {
                manager: "cargo",
                root: "/Users/nicky/.cargo",
                name: "wasm-pack",
                version: Some("0.14.0"),
                class: "duplicate",
                detail: "duplicate — npm also installs wasm-pack 0.13.1, and that copy wins in the login shell",
                severity: Severity::Attention,
            },
            json!({
                "launchers": [{ "path": "/Users/nicky/.cargo/bin/wasm-pack", "kind": "regular_binary", "target": null, "target_exists": true, "owner": { "kind": "this_install" } }],
                "resolution": { "wasm-pack": { "user_shell": "/opt/homebrew/bin/wasm-pack", "process": "/Users/nicky/.cargo/bin/wasm-pack", "status": "shadowed", "shadowed_by": "/opt/homebrew/bin/wasm-pack", "candidates": [["/opt/homebrew/bin/wasm-pack", { "kind": "other_tool", "manager": "npm", "identity_key": "npm:/opt/homebrew/lib/node_modules:wasm-pack" }], ["/Users/nicky/.cargo/bin/wasm-pack", { "kind": "this_install" }]] } },
                "classifications": [{ "kind": "duplicate", "peers": ["npm:/opt/homebrew/lib/node_modules:wasm-pack"] }, { "kind": "shadowed", "by": "/opt/homebrew/bin/wasm-pack", "owner": { "kind": "other_tool", "manager": "npm", "identity_key": "npm:/opt/homebrew/lib/node_modules:wasm-pack" } }],
                "primary_classification": "duplicate",
                "removal": { "native": { "program": "cargo", "args": ["uninstall", "wasm-pack", "--root", "/Users/nicky/.cargo"] }, "launcher_only": [], "refusals": [], "follow_up": [] },
                "manager_extra": { "source": "registry+https://github.com/rust-lang/crates.io-index", "target": "aarch64-apple-darwin", "profile": "release" },
            }),
        )
        .size(12 * 1024 * 1024)
        .remedy(native("cargo", &["uninstall", "wasm-pack", "--root", "/Users/nicky/.cargo"])),
        tool(
            Spec {
                manager: "pipx",
                root: "/Users/nicky/.local/pipx/venvs",
                name: "rendercv",
                version: Some("1.17.0"),
                class: "broken",
                detail: "broken — venv interpreter /opt/homebrew/opt/python@3.13/bin/python3.13 no longer exists",
                severity: Severity::Attention,
            },
            json!({
                "runtime": { "kind": "python", "path": "/opt/homebrew/opt/python@3.13/bin/python3.13", "version": "3.13.7", "exists": false, "source": "pipx_metadata.json source_interpreter" },
                "launchers": [{ "path": "/Users/nicky/.local/bin/rendercv", "kind": "symlink", "target": "/Users/nicky/.local/pipx/venvs/rendercv/bin/rendercv", "target_exists": true, "owner": { "kind": "this_install" } }],
                "classifications": [{ "kind": "broken", "reason": "interpreter missing" }],
                "primary_classification": "broken",
                "removal": { "native": { "program": "pipx", "args": ["uninstall", "rendercv"] }, "launcher_only": ["/Users/nicky/.local/bin/rendercv"], "refusals": [], "follow_up": [] },
            }),
        )
        .size(180 * 1024 * 1024)
        .remedy(native("pipx", &["uninstall", "rendercv"])),
        tool(
            Spec {
                manager: "uv",
                root: "/Users/nicky/.local/share/uv/tools",
                name: "mcp-proxy",
                version: Some("0.12.0"),
                class: "review",
                detail: "entrypoint mcp-reverse-proxy has no launcher (removed); `uv tool upgrade` may recreate it",
                severity: Severity::Info,
            },
            json!({
                "runtime": { "kind": "python", "path": "/opt/homebrew/opt/python@3.14/bin", "version": "3.14.6", "exists": true, "source": "pyvenv.cfg home" },
                "commands": [{ "name": "mcp-proxy", "declared_target": "bin/mcp-proxy" }, { "name": "mcp-reverse-proxy", "declared_target": "bin/mcp-reverse-proxy" }],
                "launchers": [{ "path": "/Users/nicky/.local/bin/mcp-proxy", "kind": "symlink", "target": "/Users/nicky/.local/share/uv/tools/mcp-proxy/bin/mcp-proxy", "target_exists": true, "owner": { "kind": "this_install" } }],
                "resolution": { "mcp-proxy": { "user_shell": "/Users/nicky/.local/bin/mcp-proxy", "process": "/Users/nicky/.local/bin/mcp-proxy", "status": "active", "shadowed_by": null, "candidates": [] }, "mcp-reverse-proxy": { "user_shell": null, "process": null, "status": "not_on_path", "shadowed_by": null, "candidates": [] } },
                "classifications": [{ "kind": "review", "reason": "works; one entrypoint launcher missing" }],
                "manager_extra": { "requirements": ["mcp-proxy @ git+https://github.com/sparfenyuk/mcp-proxy"], "entrypoints_missing": ["mcp-reverse-proxy"] },
                "removal": { "native": { "program": "uv", "args": ["tool", "uninstall", "mcp-proxy"] }, "launcher_only": ["/Users/nicky/.local/bin/mcp-proxy"], "refusals": [], "follow_up": ["a future `uv tool upgrade mcp-proxy` may recreate mcp-reverse-proxy"] },
            }),
        )
        .size(64 * 1024 * 1024)
        .remedy(native("uv", &["tool", "uninstall", "mcp-proxy"])),
        tool(
            Spec {
                manager: "pip",
                root: "/opt/homebrew/lib/python3.14/site-packages",
                name: "requests",
                version: Some("2.32.5"),
                class: "review",
                detail: "pip-installed into Homebrew's python@3.14 site (INSTALLER: pip, no Cellar files)",
                severity: Severity::Info,
            },
            json!({
                "layout": "homebrew-3.14",
                "runtime": { "kind": "python", "path": "/opt/homebrew/bin/python3.14", "version": "3.14.7", "exists": true, "source": "site-packages path" },
                "commands": [],
                "resolution": {},
                "classifications": [{ "kind": "review", "reason": "manually installed; nothing in this site requires it" }],
                "manager_extra": { "installer": "pip", "requested": true, "homebrew_formula": null, "requires_dist": ["charset-normalizer", "idna", "urllib3", "certifi"], "required_by": [], "unevaluated_markers": [] },
                "removal": { "native": { "program": "/opt/homebrew/bin/python3.14", "args": ["-m", "pip", "uninstall", "-y", "--break-system-packages", "requests"] }, "launcher_only": [], "refusals": [], "follow_up": ["charset-normalizer, idna, urllib3 become unrequired; certifi stays (Homebrew-owned)"] },
            }),
        )
        .size(2 * 1024 * 1024)
        .remedy(native("/opt/homebrew/bin/python3.14", &["-m", "pip", "uninstall", "-y", "--break-system-packages", "requests"])),
        tool(
            Spec {
                manager: "pip",
                root: "/opt/homebrew/lib/python3.14/site-packages",
                name: "certifi",
                version: Some("2026.7.22"),
                class: "required",
                detail: "Homebrew-owned (Cellar/certifi) — required by python@3.14 tooling; no remedy",
                severity: Severity::Info,
            },
            json!({
                "layout": "homebrew-3.14",
                "commands": [],
                "resolution": {},
                "classifications": [{ "kind": "required", "by": ["brew_formula:certifi", "requests"] }],
                "protected": "Homebrew formula certifi owns these files",
                "manager_extra": { "installer": "brew", "requested": null, "homebrew_formula": "certifi", "requires_dist": [], "required_by": ["requests"], "unevaluated_markers": [] },
            }),
        ),
        Finding::new(FindingKind::CommandResolution, "pnpm", "pnpm")
            .detail("fish resolves ~/Library/pnpm/bin/pnpm; this process cannot resolve it (~/Library/pnpm/bin is not on its PATH)")
            .path(PathBuf::from("/Users/nicky/Library/pnpm/bin/pnpm"))
            .severity(Severity::Attention)
            .provenance("fish -lc 'string join : $PATH' (starts the login shell, which runs its startup files)")
            .meta(json!({
                "command": "pnpm",
                "user_shell": { "shell": "fish", "path": "/opt/homebrew/bin/fish" },
                "user_resolution": "/Users/nicky/Library/pnpm/bin/pnpm",
                "process_resolution": null,
                "differs": true,
                "candidates": [{ "path": "/Users/nicky/Library/pnpm/bin/pnpm", "target": null, "owner": { "kind": "pnpm_home" }, "installation": null }],
                "group": "Command resolution",
            })),
        Finding::new(FindingKind::ToolCoverage, "__coverage__", "Global tools coverage")
            .detail("npm ok · pnpm ok (2 layouts) · cargo ok · pipx ok · uv ok · pip ok (3 sites) · bun absent")
            .severity(Severity::Info)
            .provenance("filesystem metadata; login shell PATH via fish -lc")
            .coverage("projects: 41 scanned under ~/dev (not truncated); shell history evidence disabled")
            .meta(json!({
                "managers": {
                    "npm": { "status": "ok", "prefixes": ["/opt/homebrew", "/Users/nicky/Library/pnpm/nodejs/24.15.0"] },
                    "pnpm": { "status": "ok", "layouts": ["v11", "legacy-5"] },
                    "cargo": { "status": "ok" }, "pipx": { "status": "ok" }, "uv": { "status": "ok" },
                    "pip": { "status": "ok", "sites": 3 }, "bun": { "status": "absent" }
                },
                "shell": { "login_shell": "/opt/homebrew/bin/fish", "source": "fish -lc 'string join : $PATH'", "disclosure": "Starting the login shell executes its startup configuration." },
                "projects": { "roots": ["/Users/nicky/dev"], "scanned": 41, "truncated": false },
                "history": { "enabled": false },
                "group": "Coverage",
            })),
    ]
}

/// Mirrors `src/scan/fs.rs`: BuildArtifact (title `"{label} — {parent}"`,
/// meta stale/artifact/group=label, Trash), LargeFile (`"Large file — {name}"`,
/// Trash+Reveal), CacheDir/IosBackup (bare filename title, meta `{group}`
/// only), DiskCategory (durable, provenance+coverage).
fn fs_fixtures() -> Vec<Finding> {
    vec![
        Finding::new(
            FindingKind::BuildArtifact,
            "/Users/dev/code/cubby/node_modules",
            "node_modules — cubby",
        )
        .path("/Users/dev/code/cubby/node_modules")
        .detail("Build artifact (node_modules)")
        .severity(Severity::Reclaimable)
        .size(GIB + 200 * MIB)
        .last_used(ago(2))
        .meta(json!({ "stale": false, "artifact": "node_modules", "group": "node_modules" }))
        .remedy(trash(
            "/Users/dev/code/cubby/node_modules",
            Some(GIB + 200 * MIB),
        )),
        Finding::new(
            FindingKind::BuildArtifact,
            "/Users/dev/code/macaudit/target",
            "target — macaudit",
        )
        .path("/Users/dev/code/macaudit/target")
        .detail("Build artifact (target)")
        .severity(Severity::Reclaimable)
        .size(3 * GIB + 950 * MIB)
        .last_used(ago(45))
        .meta(json!({ "stale": true, "artifact": "target", "group": "target" }))
        .remedy(trash(
            "/Users/dev/code/macaudit/target",
            Some(3 * GIB + 950 * MIB),
        )),
        Finding::new(
            FindingKind::BuildArtifact,
            "/Users/dev/code/dataproj/.venv",
            ".venv — dataproj",
        )
        .path("/Users/dev/code/dataproj/.venv")
        .detail("Build artifact (.venv)")
        .severity(Severity::Reclaimable)
        .size(640 * MIB)
        .last_used(ago(400))
        .meta(json!({ "stale": true, "artifact": ".venv", "group": ".venv" }))
        .remedy(trash("/Users/dev/code/dataproj/.venv", Some(640 * MIB))),
        Finding::new(
            FindingKind::BuildArtifact,
            "/Users/dev/code/oldwebapp/build",
            "build — oldwebapp",
        )
        .path("/Users/dev/code/oldwebapp/build")
        .detail("Build artifact (build)")
        .severity(Severity::Reclaimable)
        .size(0)
        .last_used(ago(730))
        .meta(json!({ "stale": true, "artifact": "build", "group": "build" }))
        .remedy(trash("/Users/dev/code/oldwebapp/build", Some(0))),
        Finding::new(
            FindingKind::LargeFile,
            "/Users/dev/Movies/huge.mkv",
            "Large file — huge.mkv",
        )
        .path("/Users/dev/Movies/huge.mkv")
        .detail("Large loose file over the size threshold")
        .size(8 * GIB + 400 * MIB)
        .severity(Severity::Attention)
        .meta(json!({ "group": "Large files" }))
        .remedy(trash("/Users/dev/Movies/huge.mkv", Some(8 * GIB + 400 * MIB)))
        .remedy(reveal("/Users/dev/Movies/huge.mkv")),
        Finding::new(
            FindingKind::LargeFile,
            "/Users/dev/Downloads/backup.dmg",
            "Large file — backup.dmg",
        )
        .path("/Users/dev/Downloads/backup.dmg")
        .detail("Large loose file over the size threshold")
        .size(15 * GIB)
        .severity(Severity::Attention)
        .meta(json!({ "group": "Large files" }))
        .remedy(trash("/Users/dev/Downloads/backup.dmg", Some(15 * GIB)))
        .remedy(reveal("/Users/dev/Downloads/backup.dmg")),
        // A macOS package sized whole: never listed file-by-file, Reveal only.
        Finding::new(
            FindingKind::LargeFile,
            "/Users/dev/Pictures/Photos Library.photoslibrary",
            "Large package — Photos Library.photoslibrary",
        )
        .path("/Users/dev/Pictures/Photos Library.photoslibrary")
        .detail("Photos library (63.9 GiB); a macOS package managed by its app — shown for size only, not a cleanup candidate")
        .size(63 * GIB + 900 * MIB)
        .severity(Severity::Info)
        .provenance("du over the whole package; contents never listed individually")
        .meta(json!({ "group": "Data libraries", "package": "photoslibrary", "package_label": "Photos library" }))
        .remedy(reveal("/Users/dev/Pictures/Photos Library.photoslibrary")),
        Finding::new(
            FindingKind::CacheDir,
            "/Users/dev/Library/Developer/Xcode/DerivedData",
            "DerivedData",
        )
        .path("/Users/dev/Library/Developer/Xcode/DerivedData")
        .size(6 * GIB + 300 * MIB)
        .severity(Severity::Reclaimable)
        .meta(json!({ "group": "Caches" }))
        .remedy(trash(
            "/Users/dev/Library/Developer/Xcode/DerivedData",
            Some(6 * GIB + 300 * MIB),
        )),
        Finding::new(
            FindingKind::CacheDir,
            "/Users/dev/Library/Caches/com.apple.dt.Xcode",
            "com.apple.dt.Xcode",
        )
        .path("/Users/dev/Library/Caches/com.apple.dt.Xcode")
        .size(850 * MIB)
        .severity(Severity::Reclaimable)
        .meta(json!({ "group": "Caches" }))
        .remedy(trash(
            "/Users/dev/Library/Caches/com.apple.dt.Xcode",
            Some(850 * MIB),
        )),
        Finding::new(
            FindingKind::IosBackup,
            "/Users/dev/Library/Application Support/MobileSync/Backup/00008030-001A2D8E3699802E",
            "00008030-001A2D8E3699802E",
        )
        .path("/Users/dev/Library/Application Support/MobileSync/Backup/00008030-001A2D8E3699802E")
        .size(4 * GIB + 500 * MIB)
        .severity(Severity::Attention)
        .meta(json!({ "group": "iOS Backups" }))
        .remedy(reveal(
            "/Users/dev/Library/Application Support/MobileSync/Backup/00008030-001A2D8E3699802E",
        )),
        Finding::new(FindingKind::DiskCategory, "~/dev", "Development")
            .path("/Users/dev/dev")
            .detail("45.2 GiB on disk")
            .size(45 * GIB + 200 * MIB)
            .severity(Severity::Info)
            .provenance("exact directory walk; symlinks skipped, hard links deduplicated, mount points not crossed")
            .coverage("Measured exactly: 16210 files in 2222 folders.")
            .meta(json!({
                "group": "Disk allocation", "category": "Development", "entries": 18432,
                "files": 16210, "dirs": 2222, "errors": 0,
                "complete": true, "coverage": "Measured exactly: 16210 files in 2222 folders.",
            })),
    ]
}

/// The synthetic home tree behind the Disk fixtures, so `--fake` runs have
/// something to browse. Sizes agree with the fixtures where they overlap.
pub fn dir_tree() -> DirTree {
    fn dir(name: &str, own: &[(&str, u64)], children: Vec<DirNode>) -> DirNode {
        let mut node = DirNode {
            name: name.to_string(),
            ..DirNode::default()
        };
        for (file, size) in own {
            node.alloc += size;
            node.apparent += size;
            node.files += 1;
            node.top_files.push((file.to_string(), *size));
        }
        node.top_files.sort_by_key(|f| std::cmp::Reverse(f.1));
        node.top_files.truncate(3);
        for c in &children {
            node.alloc += c.alloc;
            node.apparent += c.apparent;
            node.files += c.files;
            node.dirs += 1 + c.dirs;
            node.errors += c.errors;
        }
        let mut children = children;
        children.sort_by(|a, b| b.alloc.cmp(&a.alloc).then_with(|| a.name.cmp(&b.name)));
        node.children = children;
        node
    }
    let node = dir(
        "/Users/dev",
        &[(".zsh_history", 180 * KIB)],
        vec![
            dir(
                "dev",
                &[],
                vec![
                    dir(
                        "cubby",
                        &[("README.md", 12 * KIB)],
                        vec![
                            dir(
                                "node_modules",
                                &[],
                                vec![dir(".pnpm", &[("lock", 2 * KIB)], vec![])],
                            )
                            .with_alloc(2 * GIB + 300 * MIB, 41_000),
                            dir(
                                "apps",
                                &[],
                                vec![dir(
                                    "usda-api",
                                    &[("usda.sqlite", 3 * GIB + 400 * MIB)],
                                    vec![],
                                )],
                            ),
                        ],
                    ),
                    dir(
                        "macaudit",
                        &[("Cargo.lock", 90 * KIB)],
                        vec![dir("target", &[], vec![]).with_alloc(6 * GIB + 900 * MIB, 22_000)],
                    ),
                    dir(
                        "dataproj",
                        &[("notebook.ipynb", 4 * MIB)],
                        vec![dir(".venv", &[], vec![]).with_alloc(GIB + 200 * MIB, 9_800)],
                    ),
                    dir(
                        "archive",
                        &[("backup-2019.tar.gz", 18 * GIB + 100 * MIB)],
                        vec![],
                    ),
                ],
            )
            .with_alloc(45 * GIB + 200 * MIB, 16_210),
            dir(
                "Library",
                &[],
                vec![
                    dir(
                        "Caches",
                        &[],
                        vec![
                            dir("com.apple.dt.Xcode", &[], vec![])
                                .with_alloc(3 * GIB + 200 * MIB, 5_400),
                            dir("Homebrew", &[], vec![]).with_alloc(GIB + 100 * MIB, 640),
                            dir("pip", &[], vec![]).with_alloc(800 * MIB, 2_100),
                        ],
                    ),
                    dir(
                        "Application Support",
                        &[],
                        vec![
                            dir(
                                "MobileSync",
                                &[],
                                vec![dir(
                                    "Backup",
                                    &[],
                                    vec![dir("00008030-001A2D8E3699802E", &[], vec![])
                                        .with_alloc(4 * GIB + 500 * MIB, 38_000)],
                                )],
                            ),
                            dir("Slack", &[], vec![]).with_alloc(900 * MIB, 3_300),
                        ],
                    ),
                    dir(
                        "Developer",
                        &[],
                        vec![dir(
                            "Xcode",
                            &[],
                            vec![dir("DerivedData", &[], vec![])
                                .with_alloc(12 * GIB + 400 * MIB, 210_000)],
                        )],
                    ),
                    dir("Mobile Documents", &[], vec![]).with_alloc(9 * GIB + 700 * MIB, 14_000),
                ],
            ),
            dir(
                "Movies",
                &[
                    ("wedding-raw.mov", 21 * GIB + 300 * MIB),
                    ("vacation.mp4", 2 * GIB),
                ],
                vec![],
            ),
            dir(
                "Downloads",
                &[
                    ("Xcode_16.xip", 7 * GIB + 200 * MIB),
                    ("ubuntu.iso", 4 * GIB + 700 * MIB),
                ],
                vec![],
            ),
            dir(
                "Documents",
                &[("thesis.pdf", 40 * MIB)],
                vec![dir("scans", &[], vec![]).with_alloc(2 * GIB + 100 * MIB, 1_900)],
            ),
            dir(
                "Pictures",
                &[],
                vec![dir("Photos Library.photoslibrary", &[], vec![])
                    .with_alloc(63 * GIB + 400 * MIB, 148_000)],
            ),
        ],
    );
    let top_files = vec![
        ("/Users/dev/Movies/wedding-raw.mov", 21 * GIB + 300 * MIB),
        (
            "/Users/dev/dev/archive/backup-2019.tar.gz",
            18 * GIB + 100 * MIB,
        ),
        ("/Users/dev/Downloads/Xcode_16.xip", 7 * GIB + 200 * MIB),
        ("/Users/dev/Downloads/ubuntu.iso", 4 * GIB + 700 * MIB),
        (
            "/Users/dev/dev/cubby/apps/usda-api/usda.sqlite",
            3 * GIB + 400 * MIB,
        ),
        ("/Users/dev/Movies/vacation.mp4", 2 * GIB),
    ]
    .into_iter()
    .map(|(p, alloc)| BigFile {
        path: PathBuf::from(p),
        alloc,
    })
    .collect();
    DirTree {
        root: PathBuf::from("/Users/dev"),
        files: node.files,
        dirs: node.dirs,
        bytes: node.alloc,
        errors: node.errors,
        node,
        top_files,
        complete: true,
        scanned_at: SystemTime::now(),
        elapsed: Duration::from_millis(6_400),
    }
}

trait WithAlloc {
    /// Pretend the subtree holds `alloc` bytes in `files` files without
    /// modelling them individually.
    fn with_alloc(self, alloc: u64, files: u64) -> Self;
}

impl WithAlloc for DirNode {
    fn with_alloc(mut self, alloc: u64, files: u64) -> Self {
        self.alloc += alloc;
        self.apparent += alloc;
        self.files += files;
        self
    }
}

/// Mirrors `src/scan/launchd.rs`: key = plist path, title = label, meta
/// label/program/program_arguments/running/domain/run_at_load/disabled. A
/// missing program binary is a Warning with bootout + Trash remedies.
fn launchd_fixtures() -> Vec<Finding> {
    let item = |path: &str,
                label: &str,
                program: &str,
                args: Vec<&str>,
                domain: &str,
                running: bool,
                run_at_load: bool| {
        Finding::new(FindingKind::LaunchdItem, path, label)
            .path(path)
            .detail(format!("{label} — {program}"))
            .severity(Severity::Info)
            .meta(json!({
                "label": label, "program": program, "program_arguments": args,
                "running": running, "domain": domain, "run_at_load": run_at_load,
                "disabled": false,
            }))
    };

    vec![
        item(
            "/Users/dev/Library/LaunchAgents/com.docker.helper.plist",
            "com.docker.helper",
            "/Applications/Docker.app/Contents/MacOS/com.docker.helper",
            vec!["/Applications/Docker.app/Contents/MacOS/com.docker.helper", "--launch"],
            "user_agent",
            true,
            true,
        ),
        item(
            "/Users/dev/Library/LaunchAgents/com.google.keystone.agent.plist",
            "com.google.keystone.agent",
            "/Users/dev/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/MacOS/GoogleSoftwareUpdateAgent",
            vec!["/Users/dev/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/MacOS/GoogleSoftwareUpdateAgent"],
            "user_agent",
            true,
            true,
        ),
        item(
            "/Library/LaunchAgents/com.adobe.acc.installer.v2.plist",
            "com.adobe.acc.installer.v2",
            "/Library/Application Support/Adobe/Adobe Desktop Common/ACC/AdobeCreativeCloud.app/Contents/MacOS/Adobe Creative Cloud",
            vec!["/Library/Application Support/Adobe/Adobe Desktop Common/ACC/AdobeCreativeCloud.app/Contents/MacOS/Adobe Creative Cloud"],
            "library_agent",
            false,
            false,
        ),
        item(
            "/Library/LaunchDaemons/com.microsoft.autoupdate.helper.plist",
            "com.microsoft.autoupdate.helper",
            "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/msupdate",
            vec!["/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/msupdate"],
            "library_daemon",
            true,
            true,
        ),
        item(
            "/Users/dev/Library/LaunchAgents/homebrew.mxcl.postgresql.plist",
            "homebrew.mxcl.postgresql",
            "/opt/homebrew/opt/postgresql@16/bin/postgres",
            vec!["/opt/homebrew/opt/postgresql@16/bin/postgres", "-D", "/opt/homebrew/var/postgresql@16"],
            "user_agent",
            true,
            true,
        ),
        {
            let path = "/Users/dev/Library/LaunchAgents/com.oldvendor.uninstalled.helper.plist";
            let program = "/Library/Application Support/OldVendor/helper";
            Finding::new(FindingKind::LaunchdItem, path, "com.oldvendor.uninstalled.helper")
                .path(path)
                .detail(
                    "com.oldvendor.uninstalled.helper: binary `/Library/Application Support/OldVendor/helper` \
                     referenced by this launchd item no longer exists on disk — likely an orphaned \
                     leftover from an uninstalled app.",
                )
                .severity(Severity::Warning)
                .meta(json!({
                    "label": "com.oldvendor.uninstalled.helper", "program": program,
                    "program_arguments": [program], "running": false, "domain": "user_agent",
                    "run_at_load": true, "disabled": false,
                }))
                .remedy(Remedy {
                    label: "Unload via `launchctl bootout` — do this first".to_string(),
                    command: RemedyCommand::Shell {
                        program: "launchctl".to_string(),
                        args: vec![
                            "bootout".to_string(),
                            "gui/501/com.oldvendor.uninstalled.helper".to_string(),
                        ],
                    },
                    reclaims_bytes: None,
                    destructive: true,
                    alternative: false,
                    guard: None,
                })
                .remedy(Remedy {
                    label: "Move plist to Trash — do this after unloading".to_string(),
                    command: RemedyCommand::Trash { path: PathBuf::from(path) },
                    reclaims_bytes: None,
                    destructive: true,
                    alternative: false,
                    guard: None,
                })
        },
        item(
            "/Users/dev/Library/LaunchAgents/com.spotify.webhelper.plist",
            "com.spotify.webhelper",
            "/Applications/Spotify.app/Contents/MacOS/SpotifyWebHelper",
            vec!["/Applications/Spotify.app/Contents/MacOS/SpotifyWebHelper"],
            "user_agent",
            true,
            true,
        ),
    ]
}

/// Mirrors `src/scan/shell_env.rs`: PathEntry meta entry/index/occurrences/
/// exists/shadowed_by, plus the `__shell_startup__` timing finding.
fn shell_env_fixtures() -> Vec<Finding> {
    let entry = |path: &str,
                 index: u64,
                 occurrences: u64,
                 exists: bool,
                 shadowed_by: Option<&str>,
                 remedy: Option<Remedy>| {
        let mut issues = Vec::new();
        if !exists {
            issues.push("directory does not exist".to_string());
        }
        if occurrences > 1 {
            issues.push(format!("duplicated {occurrences}x in PATH"));
        }
        if let Some(sd) = shadowed_by {
            issues.push(format!("shadowed by earlier system directory {sd}"));
        }
        let detail = if issues.is_empty() {
            format!("{path} — OK")
        } else {
            format!("{path} — {}", issues.join("; "))
        };
        let severity = if issues.is_empty() {
            Severity::Info
        } else {
            Severity::Attention
        };
        let mut f = Finding::new(FindingKind::PathEntry, path, path)
            .detail(detail)
            .path(path)
            .severity(severity)
            .provenance("/opt/homebrew/bin/fish -lc 'string join : $PATH'")
            .meta(json!({
                "entry": path, "index": index, "occurrences": occurrences,
                "exists": exists, "shadowed_by": shadowed_by,
                "shell": "fish", "from_login_shell": true,
                "in_process_path": path != "/Users/dev/Library/pnpm/bin",
                "group": "$PATH entries",
            }));
        if let Some(r) = remedy {
            f = f.remedy(r);
        }
        f
    };

    vec![
        entry("/usr/bin", 0, 1, true, None, None),
        entry("/Users/dev/.rvm/bin", 1, 1, true, Some("/usr/bin"), None),
        entry("/opt/homebrew/bin", 2, 1, true, None, None),
        entry("/opt/homebrew/sbin", 3, 1, true, None, None),
        entry("/usr/local/bin", 4, 2, true, None, None),
        entry("/Users/dev/Library/pnpm/bin", 6, 1, true, None, None),
        entry(
            "/Users/dev/bin",
            5,
            1,
            false,
            None,
            Some(Remedy {
                label: "Copy path to clipboard".to_string(),
                command: RemedyCommand::CopyToClipboard {
                    text: "/Users/dev/bin".to_string(),
                },
                reclaims_bytes: None,
                destructive: false,
                alternative: false,
                guard: None,
            }),
        ),
        Finding::new(
            FindingKind::PathEntry,
            "__shell_startup__",
            "Shell startup time",
        )
        .detail("Median fish startup: 1450ms across 3 run(s)")
        .severity(Severity::Attention)
        .provenance("/opt/homebrew/bin/fish -i -c exit ×3 (starts the login shell)")
        .meta(json!({
            "shell": "fish",
            "median_ms": 1450.0,
            "runs_ms": [1390.0, 1450.0, 1510.0],
            "group": "Startup",
        })),
        Finding::new(FindingKind::PathEntry, "__path_diff__", "Login shell vs process PATH")
            .detail("fish PATH has 1 entry this process lacks; this process has 1 the shell lacks")
            .severity(Severity::Attention)
            .provenance("/opt/homebrew/bin/fish -lc 'string join : $PATH' (Reading the login shell's PATH starts that shell (fish/zsh/bash -l), which executes its startup configuration.)")
            .coverage("Tools launched by an agent or app inherit the process PATH, not the login shell's; command resolution can differ between the two.")
            .meta(json!({
                "login_shell": "/opt/homebrew/bin/fish", "shell": "fish",
                "source": "/opt/homebrew/bin/fish -lc 'string join : $PATH'",
                "only_in_shell": ["/Users/dev/Library/pnpm/bin"],
                "only_in_process": ["/Users/dev/Library/pnpm"],
                "shell_entries": 7, "process_entries": 7, "notes": [],
                "group": "Comparison",
            })),
    ]
}

/// Mirrors `src/scan/runtimes.rs`: RuntimeVersion meta manager/runtime/
/// version/size_bytes (Trash remedy), a rustup toolchain, and one
/// multi-manager conflict finding.
fn runtimes_fixtures() -> Vec<Finding> {
    let version = |path: &str, manager: &str, runtime: &str, version: &str, size: u64| {
        Finding::new(
            FindingKind::RuntimeVersion,
            path,
            format!("{manager} {runtime} {version}"),
        )
        .detail(format!("{version} — {size} bytes on disk"))
        .path(path)
        .size(size)
        .severity(Severity::Info)
        .meta(json!({
            "manager": manager, "runtime": runtime, "version": version, "size_bytes": size,
        }))
        .remedy(trash(path, Some(size)))
    };

    vec![
        version(
            "/Users/dev/.nvm/versions/node/v20.11.1",
            "nvm",
            "node",
            "v20.11.1",
            180 * MIB,
        ),
        version(
            "/Users/dev/.nvm/versions/node/v18.16.0",
            "nvm",
            "node",
            "v18.16.0",
            150 * MIB,
        ),
        version(
            "/Users/dev/.pyenv/versions/3.11.4",
            "pyenv",
            "python",
            "3.11.4",
            310 * MIB,
        ),
        version(
            "/Users/dev/.pyenv/versions/3.9.13",
            "pyenv",
            "python",
            "3.9.13",
            290 * MIB,
        ),
        version(
            "/Users/dev/.rbenv/versions/3.2.2",
            "rbenv",
            "ruby",
            "3.2.2",
            220 * MIB,
        ),
        Finding::new(
            FindingKind::RuntimeVersion,
            "/Users/dev/.rustup/toolchains/stable-aarch64-apple-darwin",
            "rustup rust stable-aarch64-apple-darwin",
        )
        .detail(
            "stable-aarch64-apple-darwin — not the active default toolchain; consider \
             `rustup toolchain uninstall stable-aarch64-apple-darwin` if unused",
        )
        .path("/Users/dev/.rustup/toolchains/stable-aarch64-apple-darwin")
        .size(GIB + 200 * MIB)
        .severity(Severity::Reclaimable)
        .meta(json!({
            "manager": "rustup", "runtime": "rust", "version": "stable-aarch64-apple-darwin",
            "size_bytes": GIB + 200 * MIB, "is_default": false,
        })),
        Finding::new(
            FindingKind::RuntimeVersion,
            "conflict:node",
            "Multiple version managers for node",
        )
        .detail(
            "node is managed by more than one tool (fnm, nvm) — `which node` results \
                 depend on shell PATH order, which is a common source of confusion.",
        )
        .severity(Severity::Attention)
        .meta(json!({ "runtime": "node", "managers": ["fnm", "nvm"] })),
    ]
}

/// Mirrors `src/scan/docker.rs`: one DockerObject summary per type (Images/
/// Containers/Local Volumes/Build Cache), Reclaimable + prune remedy only
/// when reclaimable > 0, plus active-container observations.
fn docker_fixtures() -> Vec<Finding> {
    vec![
        Finding::new(
            FindingKind::DockerObject,
            "type:Images",
            "Docker Images — 4.2GB",
        )
        .detail("18 total, 6 active, 4.2GB used, 1.8GB reclaimable")
        .severity(Severity::Reclaimable)
        .size(1_800_000_000)
        .meta(json!({
            "type": "Images", "total_count": 18, "active": 6, "size": "4.2GB",
            "reclaimable": "1.8GB", "total_size_bytes": 4_200_000_000u64,
        }))
        .remedy(Remedy {
            label: "Remove unused images".to_string(),
            command: RemedyCommand::Shell {
                program: "docker".to_string(),
                args: vec!["image".to_string(), "prune".to_string(), "-f".to_string()],
            },
            reclaims_bytes: Some(1_800_000_000),
            destructive: true,
            alternative: false,
            guard: None,
        }),
        Finding::new(
            FindingKind::DockerObject,
            "type:Containers",
            "Docker Containers — 320MB",
        )
        .detail("9 total, 3 active, 320MB used, 210MB reclaimable")
        .severity(Severity::Reclaimable)
        .size(210_000_000)
        .meta(json!({
            "type": "Containers", "total_count": 9, "active": 3, "size": "320MB",
            "reclaimable": "210MB", "total_size_bytes": 320_000_000u64,
        }))
        .remedy(Remedy {
            label: "Remove stopped containers".to_string(),
            command: RemedyCommand::Shell {
                program: "docker".to_string(),
                args: vec![
                    "container".to_string(),
                    "prune".to_string(),
                    "-f".to_string(),
                ],
            },
            reclaims_bytes: Some(210_000_000),
            destructive: true,
            alternative: false,
            guard: None,
        }),
        Finding::new(
            FindingKind::DockerObject,
            "type:Local Volumes",
            "Docker Local Volumes — 1.1GB",
        )
        .detail("5 total, 2 active, 1.1GB used, 0B reclaimable")
        .severity(Severity::Info)
        .size(0)
        .meta(json!({
            "type": "Local Volumes", "total_count": 5, "active": 2, "size": "1.1GB",
            "reclaimable": "0B", "total_size_bytes": 1_100_000_000u64,
        })),
        Finding::new(
            FindingKind::DockerObject,
            "type:Build Cache",
            "Docker Build Cache — 2.6GB",
        )
        .detail("42 total, 0 active, 2.6GB used, 2.6GB reclaimable")
        .severity(Severity::Reclaimable)
        .size(2_600_000_000)
        .meta(json!({
            "type": "Build Cache", "total_count": 42, "active": 0, "size": "2.6GB",
            "reclaimable": "2.6GB", "total_size_bytes": 2_600_000_000u64,
        }))
        .remedy(Remedy {
            label: "Prune build cache".to_string(),
            command: RemedyCommand::Shell {
                program: "docker".to_string(),
                args: vec!["builder".to_string(), "prune".to_string(), "-f".to_string()],
            },
            reclaims_bytes: Some(2_600_000_000),
            destructive: true,
            alternative: false,
            guard: None,
        }),
        Finding::new(
            FindingKind::DockerObject,
            "container:a1b2c3d4",
            "cubby-postgres-1 — active container",
        )
        .detail("Up 3 hours · 4.2% CPU · 210.0 MiB RAM")
        .severity(Severity::Info)
        .meta(json!({
            "type": "active_container", "id": "a1b2c3d4", "name": "cubby-postgres-1",
            "status": "Up 3 hours", "cpu_percent": 4.2, "memory_bytes": 220 * MIB,
        })),
        Finding::new(
            FindingKind::DockerObject,
            "container:e5f6a7b8",
            "macaudit-redis-1 — active container",
        )
        .detail("Up 2 days · 118.5% CPU · 2.3 GiB RAM")
        .severity(Severity::Warning)
        .meta(json!({
            "type": "active_container", "id": "e5f6a7b8", "name": "macaudit-redis-1",
            "status": "Up 2 days", "cpu_percent": 118.5, "memory_bytes": 2 * GIB + 300 * MIB,
        })),
    ]
}

/// Mirrors `src/scan/ports.rs`: key `{pid}:{host}:{port}`, title
/// `"PID {pid} {cmd} — :{port}"`, always a copy-kill-command remedy plus
/// Reveal when the binary path resolved.
fn ports_fixtures() -> Vec<Finding> {
    let listener =
        |pid: u64, host: &str, port: u64, command: &str, user: &str, path: Option<&str>| {
            let key = format!("{pid}:{host}:{port}");
            let title = format!("PID {pid} {command} — :{port}");
            let mut f = Finding::new(FindingKind::PortListener, &key, title)
                .detail(format!(
                    "{command} (pid {pid}, user {user}) listening on {host}:{port}"
                ))
                .severity(Severity::Info)
                .meta(json!({
                    "pid": pid, "port": port, "command": command, "user": user, "host": host,
                }))
                .remedy(Remedy {
                    label: "Copy kill command".to_string(),
                    command: RemedyCommand::CopyToClipboard {
                        text: format!("kill {pid}"),
                    },
                    reclaims_bytes: None,
                    destructive: false,
                    alternative: false,
                    guard: None,
                });
            if let Some(path) = path {
                f = f.path(path).remedy(reveal(path));
            }
            f
        };

    vec![
        listener(
            1234,
            "*",
            3000,
            "node",
            "dev",
            Some("/Users/dev/.nvm/versions/node/v20.11.1/bin/node"),
        ),
        listener(
            5678,
            "*",
            5432,
            "postgres",
            "dev",
            Some("/opt/homebrew/opt/postgresql@16/bin/postgres"),
        ),
        listener(9012, "127.0.0.1", 6379, "redis-server", "dev", None),
        listener(
            3456,
            "*",
            8000,
            "python3",
            "dev",
            Some("/Users/dev/.pyenv/versions/3.11.4/bin/python3"),
        ),
        listener(789, "*", 2375, "com.docker.backend", "dev", None),
        listener(
            2233,
            "*",
            8080,
            "nginx",
            "dev",
            Some("/opt/homebrew/opt/nginx/bin/nginx"),
        ),
    ]
}

/// Mirrors `src/scan/git.rs`: key = repo root, title = dir name, meta
/// dirty/ahead/behind/stash_count/branch/has_upstream; severity is Attention
/// iff `dirty || ahead > 0 || (!has_upstream && last_used.is_some())`.
fn git_fixtures() -> Vec<Finding> {
    let repo = |root: &str,
                dirty: bool,
                ahead: u64,
                behind: u64,
                stash_count: u64,
                branch: &str,
                has_upstream: bool,
                detail: &str,
                severity: Severity,
                days_ago: u64,
                size: u64| {
        let name = root.rsplit('/').next().unwrap_or(root);
        Finding::new(FindingKind::GitRepo, root, name)
            .path(root)
            .detail(detail)
            .severity(severity)
            .size(size)
            .last_used(ago(days_ago))
            .meta(json!({
                "dirty": dirty, "ahead": ahead, "behind": behind, "stash_count": stash_count,
                "branch": branch, "has_upstream": has_upstream,
            }))
            .remedy(reveal(root))
    };

    vec![
        repo(
            "/Users/dev/code/macaudit",
            false,
            0,
            0,
            0,
            "main",
            true,
            "clean",
            Severity::Info,
            0,
            180 * MIB,
        ),
        repo(
            "/Users/dev/code/cubby",
            true,
            0,
            0,
            0,
            "main",
            true,
            "uncommitted changes",
            Severity::Attention,
            1,
            320 * MIB,
        ),
        repo(
            "/Users/dev/code/old-experiment",
            false,
            0,
            0,
            0,
            "main",
            false,
            "no upstream (nothing pushed)",
            Severity::Attention,
            200,
            40 * MIB,
        ),
        repo(
            "/Users/dev/code/website",
            false,
            3,
            0,
            0,
            "main",
            true,
            "3 unpushed",
            Severity::Attention,
            5,
            95 * MIB,
        ),
        repo(
            "/Users/dev/code/dotfiles",
            true,
            0,
            2,
            0,
            "main",
            true,
            "uncommitted changes, 2 behind",
            Severity::Attention,
            10,
            8 * MIB,
        ),
        repo(
            "/Users/dev/code/api-server",
            true,
            0,
            0,
            2,
            "main",
            true,
            "uncommitted changes, 2 stash(es)",
            Severity::Attention,
            3,
            210 * MIB,
        ),
        repo(
            "/Users/dev/code/learning-rust",
            false,
            0,
            0,
            0,
            "main",
            true,
            "clean",
            Severity::Info,
            400,
            25 * MIB,
        ),
    ]
}

/// Mirrors `src/scan/ios.rs` by construction — the findings come from the
/// scanner's own builders. Numbers are from a real 256 GB iPhone: 146 GB
/// purgeable behind 19.6 GB "free", and Spotify holding 38 GB of downloads.
fn ios_fixtures() -> Vec<Finding> {
    use crate::scan::ios::{app_finding, device_finding, AppUsage, DeviceInfo, DiskUsage};
    const UDID: &str = "00008150-001915442138401C";
    let info = DeviceInfo {
        name: "Nicky iPhone".to_string(),
        product_type: "iPhone18,1".to_string(),
        ios_version: "27.0".to_string(),
    };
    let usage = DiskUsage {
        capacity: 246_266_159_104,
        free: 19_632_939_008,
        available: 166_055_415_808,
    };
    let app =
        |bundle_id: &str, title: &str, app_type: &str, version: &str, s: u64, d: u64| AppUsage {
            bundle_id: bundle_id.to_string(),
            title: title.to_string(),
            app_type: app_type.to_string(),
            version: Some(version.to_string()),
            static_bytes: s,
            dynamic_bytes: d,
        };
    let apps = vec![
        app(
            "com.spotify.client",
            "Spotify",
            "User",
            "9.0.86",
            260_000_000,
            38_290_000_000,
        ),
        app(
            "com.zhiliaoapp.musically",
            "TikTok",
            "User",
            "41.2.0",
            990_000_000,
            3_270_000_000,
        ),
        app(
            "com.google.photos",
            "Google Photos",
            "User",
            "7.40",
            420_000_000,
            1_640_000_000,
        ),
        app(
            "com.burbn.instagram",
            "Instagram",
            "User",
            "389.0",
            590_000_000,
            1_390_000_000,
        ),
        app(
            "ai.polycam.polycam",
            "Polycam",
            "User",
            "7.0.0",
            510_000_000,
            1_330_000_000,
        ),
        app(
            "com.apple.mobilenotes",
            "Notes",
            "System",
            "4.11",
            20_000_000,
            1_640_000_000,
        ),
        app(
            "com.google.chrome.ios",
            "Chrome",
            "User",
            "140.0",
            390_000_000,
            900_000_000,
        ),
        app(
            "com.google.Maps",
            "Google Maps",
            "User",
            "25.36",
            460_000_000,
            780_000_000,
        ),
        app(
            "com.apple.mobilesafari",
            "Safari",
            "System",
            "27.0",
            2_000_000,
            690_000_000,
        ),
        app("com.tmobile.tlife", "T-Life", "User", "6.5", 650_000_000, 0),
    ];
    let mut out: Vec<Finding> = apps.iter().map(|a| app_finding(UDID, &info, a)).collect();
    out.push(device_finding(UDID, &info, usage, &apps));
    out
}

/// Mirrors `src/scan/simulator.rs`: `kind:"runtime"` (identifier/version/
/// build/available) and `kind:"device"` (udid/runtime/state/available,
/// sized) findings.
fn simulator_fixtures() -> Vec<Finding> {
    vec![
        Finding::new(
            FindingKind::Simulator,
            "com.apple.CoreSimulator.SimRuntime.iOS-17-4",
            "iOS 17.4 (build 21E213)",
        )
        .detail("runtime com.apple.CoreSimulator.SimRuntime.iOS-17-4, version 17.4, available")
        .severity(Severity::Info)
        .meta(json!({
            "kind": "runtime", "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-17-4",
            "version": "17.4", "build": "21E213", "available": true,
        })),
        Finding::new(
            FindingKind::Simulator,
            "com.apple.CoreSimulator.SimRuntime.iOS-16-4",
            "iOS 16.4 (build 20E247)",
        )
        .detail("runtime com.apple.CoreSimulator.SimRuntime.iOS-16-4, version 16.4, unavailable")
        .severity(Severity::Reclaimable)
        .meta(json!({
            "kind": "runtime", "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-16-4",
            "version": "16.4", "build": "20E247", "available": false,
        }))
        .remedy(Remedy {
            label: "Delete this runtime".to_string(),
            command: RemedyCommand::Shell {
                program: "xcrun".to_string(),
                args: vec![
                    "simctl".to_string(),
                    "runtime".to_string(),
                    "delete".to_string(),
                    "com.apple.CoreSimulator.SimRuntime.iOS-16-4".to_string(),
                ],
            },
            reclaims_bytes: None,
            destructive: true,
            alternative: false,
            guard: None,
        }),
        Finding::new(
            FindingKind::Simulator,
            "AAAA1111-0000-0000-0000-000000000001",
            "iPhone 15 — iOS 17.4",
        )
        .detail("Booted, udid AAAA1111-0000-0000-0000-000000000001")
        .severity(Severity::Info)
        .size(6 * GIB)
        .meta(json!({
            "kind": "device", "udid": "AAAA1111-0000-0000-0000-000000000001",
            "runtime": "com.apple.CoreSimulator.SimRuntime.iOS-17-4", "state": "Booted",
            "available": true,
        })),
        Finding::new(
            FindingKind::Simulator,
            "BBBB2222-0000-0000-0000-000000000002",
            "iPhone 14 — iOS 17.4",
        )
        .detail("Shutdown, udid BBBB2222-0000-0000-0000-000000000002")
        .severity(Severity::Info)
        .size(5 * GIB)
        .meta(json!({
            "kind": "device", "udid": "BBBB2222-0000-0000-0000-000000000002",
            "runtime": "com.apple.CoreSimulator.SimRuntime.iOS-17-4", "state": "Shutdown",
            "available": true,
        }))
        .remedy(Remedy {
            label: "Delete this simulator device".to_string(),
            command: RemedyCommand::Shell {
                program: "xcrun".to_string(),
                args: vec![
                    "simctl".to_string(),
                    "delete".to_string(),
                    "BBBB2222-0000-0000-0000-000000000002".to_string(),
                ],
            },
            reclaims_bytes: Some(5 * GIB),
            destructive: true,
            alternative: false,
            guard: None,
        }),
        Finding::new(
            FindingKind::Simulator,
            "CCCC3333-0000-0000-0000-000000000003",
            "iPad Air — iOS 16.4",
        )
        .detail("Shutdown, udid CCCC3333-0000-0000-0000-000000000003")
        .severity(Severity::Reclaimable)
        .size(4 * GIB)
        .meta(json!({
            "kind": "device", "udid": "CCCC3333-0000-0000-0000-000000000003",
            "runtime": "com.apple.CoreSimulator.SimRuntime.iOS-16-4", "state": "Shutdown",
            "available": false,
        }))
        .remedy(Remedy {
            label: "Delete this simulator device".to_string(),
            command: RemedyCommand::Shell {
                program: "xcrun".to_string(),
                args: vec![
                    "simctl".to_string(),
                    "delete".to_string(),
                    "CCCC3333-0000-0000-0000-000000000003".to_string(),
                ],
            },
            reclaims_bytes: Some(4 * GIB),
            destructive: true,
            alternative: false,
            guard: None,
        }),
        Finding::new(
            FindingKind::Simulator,
            "DDDD4444-0000-0000-0000-000000000004",
            "iPhone SE (3rd generation) — iOS 16.4",
        )
        .detail("Shutdown, udid DDDD4444-0000-0000-0000-000000000004")
        .severity(Severity::Reclaimable)
        .size(3 * GIB + 500 * MIB)
        .meta(json!({
            "kind": "device", "udid": "DDDD4444-0000-0000-0000-000000000004",
            "runtime": "com.apple.CoreSimulator.SimRuntime.iOS-16-4", "state": "Shutdown",
            "available": false,
        }))
        .remedy(Remedy {
            label: "Delete this simulator device".to_string(),
            command: RemedyCommand::Shell {
                program: "xcrun".to_string(),
                args: vec![
                    "simctl".to_string(),
                    "delete".to_string(),
                    "DDDD4444-0000-0000-0000-000000000004".to_string(),
                ],
            },
            reclaims_bytes: Some(3 * GIB + 500 * MIB),
            destructive: true,
            alternative: false,
            guard: None,
        }),
    ]
}

/// Mirrors `src/scan/ssh_keys.rs`: meta type/bits/age_days/has_config_entry/
/// has_private_key/comment/pubkey_path/private_key_path. A ≤2048-bit RSA key
/// older than 5 years is flagged Attention.
fn ssh_keys_fixtures() -> Vec<Finding> {
    let key = |priv_path: &str,
               key_type: &str,
               bits: Option<u32>,
               age_days: u64,
               has_config_entry: bool,
               comment: &str,
               severity: Severity,
               detail: &str| {
        let name = priv_path.rsplit('/').next().unwrap_or(priv_path);
        let pub_path = format!("{priv_path}.pub");
        Finding::new(FindingKind::SshKey, priv_path, name)
            .detail(detail)
            .path(priv_path)
            .severity(severity)
            .remedy(reveal(priv_path))
            .meta(json!({
                "type": key_type, "bits": bits, "age_days": age_days,
                "has_config_entry": has_config_entry, "has_private_key": true,
                "comment": comment, "pubkey_path": pub_path, "private_key_path": priv_path,
            }))
    };

    vec![
        key(
            "/Users/dev/.ssh/id_ed25519",
            "ssh-ed25519",
            None,
            120,
            true,
            "dev@MacBook-Pro.local",
            Severity::Info,
            "ssh-ed25519 key",
        ),
        key(
            "/Users/dev/.ssh/id_rsa",
            "ssh-rsa",
            Some(2048),
            2200,
            false,
            "dev@old-workstation",
            Severity::Attention,
            "ssh-rsa, 2048 bits key — 2048-bit RSA is weak by modern standards; 2200 days old; \
             no matching entry in ~/.ssh/config",
        ),
        key(
            "/Users/dev/.ssh/id_ecdsa",
            "ecdsa-sha2-nistp256",
            Some(256),
            60,
            true,
            "dev@MacBook-Pro.local",
            Severity::Info,
            "ecdsa-sha2-nistp256, 256 bits key",
        ),
        key(
            "/Users/dev/.ssh/github_actions_deploy",
            "ssh-ed25519",
            None,
            10,
            false,
            "github-actions-deploy",
            Severity::Info,
            "ssh-ed25519 key — no matching entry in ~/.ssh/config",
        ),
        key(
            "/Users/dev/.ssh/id_rsa_backup_server",
            "ssh-rsa",
            Some(4096),
            900,
            true,
            "dev@backup-server",
            Severity::Info,
            "ssh-rsa, 4096 bits key",
        ),
        key(
            "/Users/dev/.ssh/deploy_key_prod",
            "ssh-ed25519",
            None,
            30,
            true,
            "deploy@prod",
            Severity::Info,
            "ssh-ed25519 key",
        ),
    ]
}

/// Mirrors `src/scan/time_machine.rs`: one `TmDestination` (a failed, full
/// network destination), one `TmStaleMount` (an unmounted backup disk), one
/// `TmPurgeable` (upper-bound purgeable space), one `TmBackupEstimate`
/// (complete, fits quota but tight), three `TmExclusion` (fixed-path and
/// macOS-default), two `TmExclusionCandidate` (regenerable cache and cloud
/// sync), and three `LocalSnapshot`. Every finding carries `meta.group`
/// ("Backup" / "Backup set" / "Exclusions" / "Suggested exclusions" /
/// "Local snapshots") so the section's tree view groups them correctly.
fn time_machine_fixtures() -> Vec<Finding> {
    let dates = [
        ("2026-09-13-060000", "2026-09-13 06:00:00"),
        ("2026-09-12-060000", "2026-09-12 06:00:00"),
        ("2026-09-11-060000", "2026-09-11 06:00:00"),
    ];

    let snapshots = dates.into_iter().map(|(date, humanized)| {
        let name = format!("com.apple.TimeMachine.{date}.local");
        Finding::new(
            FindingKind::LocalSnapshot,
            &name,
            format!("Local snapshot {humanized}"),
        )
        .detail(format!(
            "Time Machine local snapshot {name}; macOS manages its purgeable space and \
                 does not report a reliable per-snapshot reclaimable size.",
        ))
        .severity(Severity::Reclaimable)
        .provenance("tmutil listlocalsnapshots /")
        .coverage("Presence is measured; reclaimable bytes are intentionally not estimated.")
        .meta(json!({
            "name": name, "date": date, "status": humanized, "group": "Local snapshots",
        }))
        .remedy(Remedy {
            label: "Delete local snapshot".to_string(),
            command: RemedyCommand::Shell {
                program: "tmutil".to_string(),
                args: vec!["deletelocalsnapshots".to_string(), date.to_string()],
            },
            reclaims_bytes: None,
            destructive: true,
            alternative: false,
            guard: None,
        })
    });

    vec![
        Finding::new(
            FindingKind::TmDestination,
            "146E01E3-B311-4132-9E56-918AA1A95509",
            "Time Machine – cantaloupe.local",
        )
        .path("/Volumes/Time Machine")
        .detail(
            "Backup failed with error 56 (destination full): cantaloupe.local has 50.0 GB \
             free of its 499 GB quota and hasn't completed a backup in 27 days.",
        )
        .size(449_101_406_208)
        .severity(Severity::Warning)
        .provenance("tmutil destinationinfo -X; defaults export com.apple.TimeMachine")
        .meta(json!({
            "status": "Failed (destination full) · 27d ago",
            "destination_id": "146E01E3-B311-4132-9E56-918AA1A95509",
            "kind": "Network",
            "network_url": "smb://user@cantaloupe._smb._tcp.local./Time%20Machine",
            "quota_bytes": 499_000_000_000u64,
            "bytes_used": 449_101_406_208u64,
            "bytes_available": 50_029_150_208u64,
            "result": 56,
            "result_label": "destination full",
            "last_backup": "2026-08-17 19:19",
            "last_backup_days": 27,
            "oldest_backup": "2026-08-17 09:47",
            "backup_count": 3,
            "attempt_count": 12,
            "last_attempt": "2026-09-12 18:37",
            "auto_backup": true,
            "auto_backup_interval_secs": 86_400,
            "mounted": true,
            "prefs_readable": true,
            "group": "Backup",
        }))
        .remedy(reveal("/Volumes/Time Machine")),
        Finding::new(
            FindingKind::TmStaleMount,
            "/Volumes/Backups of Fixture’s MacBook Air 2",
            "Backups of Fixture’s MacBook Air 2",
        )
        .path("/Volumes/Backups of Fixture’s MacBook Air 2")
        .detail(
            "A Time Machine backup disk that isn't currently mounted; its old backups are \
             inaccessible until it's reconnected.",
        )
        .severity(Severity::Attention)
        .meta(json!({ "status": "Not mounted", "group": "Backup" }))
        .remedy(Remedy {
            label: "Copy removal command".to_string(),
            command: RemedyCommand::CopyToClipboard {
                text: "sudo rmdir '/Volumes/Backups of Fixture’s MacBook Air 2'".to_string(),
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: false,
            guard: None,
        })
        .remedy(Remedy {
            alternative: true,
            ..reveal("/Volumes/Backups of Fixture’s MacBook Air 2")
        }),
        Finding::new(FindingKind::TmPurgeable, "purgeable", "Purgeable space")
            .detail(
                "Upper bound on reclaimable local-snapshot and other macOS-managed purgeable \
                 space; the OS may reclaim some of this automatically before you ever need to.",
            )
            .size(72_608_670_088)
            .severity(Severity::Info)
            .provenance("NSURLVolumeAvailableCapacityForImportantUsageKey minus real free space (osascript, Foundation only)")
            .meta(json!({
                "status": "upper bound",
                "macos_available_bytes": 241_009_959_304u64,
                "apfs_free_bytes": 168_401_289_216u64,
                "snapshot_count": 3,
                "group": "Local snapshots",
            }))
            .remedy(Remedy {
                label: "Thin local snapshots (aggressive)".to_string(),
                command: RemedyCommand::Shell {
                    program: "tmutil".to_string(),
                    args: vec![
                        "thinlocalsnapshots".to_string(),
                        "/".to_string(),
                        "9999999999999".to_string(),
                        "4".to_string(),
                    ],
                },
                reclaims_bytes: Some(72_608_670_088),
                destructive: true,
                alternative: false,
                guard: None,
            }),
        Finding::new(
            FindingKind::TmBackupEstimate,
            "estimate",
            "Estimated backup set",
        )
        .path("/Users/dev")
        .detail(
            "412 GB would be backed up (213 GB excluded); quota 499 GB → fits, but leaves \
                 under 20% headroom for history",
        )
        .size(412_000_000_000)
        .severity(Severity::Warning)
        .coverage("39 of 41 backup roots measured completely; 2 skipped (protected paths).")
        .meta(json!({
            "status": "complete",
            "included_bytes": 412_000_000_000u64,
            "excluded_bytes": 213_000_000_000u64,
            "data_used_bytes": 792_000_000_000u64,
            "quota_bytes": 499_000_000_000u64,
            "roots_total": 41,
            "roots_measured": 39,
            "roots_partial": 0,
            "roots_skipped": 2,
            "skipped_paths": ["~/Library/Mail", "~/Library/Safari"],
            "complete": true,
            "fits_quota": true,
            "group": "Backup set",
        })),
        Finding::new(FindingKind::TmExclusion, "/Users/dev/dev", "~/dev")
            .path("/Users/dev/dev")
            .detail("saves 108.0 GB on disk from backups")
            .size(108 * GIB)
            .severity(Severity::Info)
            .meta(json!({
                "status": "Excluded",
                "exclusion_kind": "fixed_path",
                "in_system_settings": true,
                "exists": true,
                "complete": true,
                "entries": 21_400,
                "group": "Exclusions",
            })),
        Finding::new(FindingKind::TmExclusion, "/Users/dev/.cache", "~/.cache")
            .path("/Users/dev/.cache")
            .detail("saves 23.0 GB on disk from backups")
            .size(23 * GIB)
            .severity(Severity::Info)
            .meta(json!({
                "status": "Excluded",
                "exclusion_kind": "fixed_path",
                "in_system_settings": true,
                "exists": true,
                "complete": true,
                "entries": 3_200,
                "group": "Exclusions",
            })),
        Finding::new(
            FindingKind::TmExclusion,
            "/Users/dev/Library/Caches",
            "~/Library/Caches",
        )
        .path("/Users/dev/Library/Caches")
        .detail("saves 20.0 GB on disk from backups")
        .size(20 * GIB)
        .severity(Severity::Info)
        .meta(json!({
            "status": "Excluded",
            "exclusion_kind": "macos_default",
            "in_system_settings": false,
            "exists": true,
            "complete": true,
            "entries": 58_000,
            "group": "Exclusions",
        })),
        Finding::new(
            FindingKind::TmExclusionCandidate,
            "/Users/dev/.cargo",
            "~/.cargo",
        )
        .path("/Users/dev/.cargo")
        .detail(
            "Rust toolchain and registry cache — regenerable by re-running `cargo build`; \
                 safe to exclude from backups",
        )
        .size(2 * GIB + 100 * MIB)
        .severity(Severity::Attention)
        .meta(json!({
            "status": "Included",
            "reason": "regenerable_cache",
            "complete": true,
            "entries": 9_800,
            "group": "Suggested exclusions",
        }))
        .remedy(Remedy {
            label: "Exclude from Time Machine".to_string(),
            command: RemedyCommand::Shell {
                program: "tmutil".to_string(),
                args: vec!["addexclusion".to_string(), "/Users/dev/.cargo".to_string()],
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: false,
            guard: None,
        })
        .remedy(Remedy {
            label: "Copy fixed-path exclusion command (shows in System Settings, needs admin)"
                .to_string(),
            command: RemedyCommand::CopyToClipboard {
                text: "sudo tmutil addexclusion -p '/Users/dev/.cargo'".to_string(),
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: true,
            guard: None,
        }),
        Finding::new(
            FindingKind::TmExclusionCandidate,
            "/Users/dev/Library/Mobile Documents",
            "~/Library/Mobile Documents",
        )
        .path("/Users/dev/Library/Mobile Documents")
        .detail("synced to a cloud provider — your call")
        .size(24 * GIB)
        .severity(Severity::Info)
        .meta(json!({
            "status": "Included",
            "reason": "cloud_synced",
            "complete": true,
            "entries": 15_200,
            "group": "Suggested exclusions",
        }))
        .remedy(Remedy {
            label: "Exclude from Time Machine".to_string(),
            command: RemedyCommand::Shell {
                program: "tmutil".to_string(),
                args: vec![
                    "addexclusion".to_string(),
                    "/Users/dev/Library/Mobile Documents".to_string(),
                ],
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: false,
            guard: None,
        })
        .remedy(Remedy {
            label: "Copy fixed-path exclusion command (shows in System Settings, needs admin)"
                .to_string(),
            command: RemedyCommand::CopyToClipboard {
                text: "sudo tmutil addexclusion -p '/Users/dev/Library/Mobile Documents'"
                    .to_string(),
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: true,
            guard: None,
        }),
    ]
    .into_iter()
    .chain(snapshots)
    .collect()
}

/// Streams a section's [`fixtures`] with a believable cadence: ~120ms between
/// emits, and — for the first finding that has a size — an initial unsized
/// emit followed by a sized re-emit ~200ms later (exercises upsert-by-id
/// deferred sizing, same as the real disk/runtime scanners).
pub struct FakeScanner {
    id: ScannerId,
}

impl FakeScanner {
    pub fn for_section(id: ScannerId) -> Self {
        FakeScanner { id }
    }
}

#[async_trait]
impl Scanner for FakeScanner {
    fn id(&self) -> ScannerId {
        self.id
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let findings = fixtures(self.id);
        let total = findings.len() as u64;
        ctx.progress("scanning…", 0, Some(total)).await;

        let deferred_idx = findings.iter().position(|f| f.size_bytes.is_some());
        let mut deferred_final: Option<Finding> = None;

        for (i, finding) in findings.into_iter().enumerate() {
            if ctx.cancelled() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
            if Some(i) == deferred_idx {
                let mut pending = finding.clone();
                pending.size_bytes = None;
                ctx.emit(pending).await;
                deferred_final = Some(finding);
            } else {
                ctx.emit(finding).await;
            }
            ctx.progress("scanning…", i as u64 + 1, Some(total)).await;
        }

        if let Some(full) = deferred_final {
            if !ctx.cancelled() {
                tokio::time::sleep(Duration::from_millis(200)).await;
                ctx.emit(full).await;
            }
        }
        if self.id == ScannerId::Fs && !ctx.cancelled() {
            let _ = ctx
                .tx
                .send(ScanEvent::DirTree {
                    scanner: ScannerId::Fs,
                    gen: ctx.gen,
                    tree: std::sync::Arc::new(dir_tree()),
                })
                .await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_section_has_enough_realistic_findings() {
        for &id in ScannerId::ALL {
            let findings = fixtures(id);
            assert!(
                findings.len() >= 6,
                "{id:?} only produced {} findings (want >= 6)",
                findings.len()
            );

            let mut seen = std::collections::HashSet::new();
            for f in &findings {
                assert!(
                    !f.meta.is_null(),
                    "{id:?} finding {:?} has no meta",
                    f.title
                );
                assert!(
                    seen.insert(f.id),
                    "{id:?} has a duplicate finding id (title {:?})",
                    f.title
                );
            }
        }
    }
}
