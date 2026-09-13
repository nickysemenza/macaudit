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

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

const MIB: u64 = 1024 * 1024;
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
        ScannerId::SshKeys => ssh_keys_fixtures(),
        ScannerId::TmSnapshots => tm_snapshots_fixtures(),
    }
}

/// Mirrors `src/scan/system.rs`: 4 SystemMetric findings (`role` one of
/// cpu/memory/swap/disk; disk alone is durable) plus a handful of
/// ProcessResource findings, all ephemeral.
fn system_fixtures() -> Vec<Finding> {
    vec![
        Finding::new(FindingKind::SystemMetric, "cpu-load", "CPU load")
            .detail("load average 6.42 / 4.10 / 3.05 across 8 cores")
            .severity(Severity::Attention)
            .ephemeral()
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
            .ephemeral()
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
            .ephemeral()
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
            .ephemeral()
            .meta(json!({
                "role": "process", "pid": 4821, "user": "dev", "cpu_percent": 12.4,
                "memory_percent": 1.1, "rss_bytes": 180 * MIB, "state": "S", "command": "node",
            })),
        Finding::new(FindingKind::ProcessResource, "512:Xcode", "Xcode (pid 512)")
            .detail("64.2% CPU · 2.1 GiB resident · dev · S")
            .severity(Severity::Attention)
            .ephemeral()
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
        .ephemeral()
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
        .ephemeral()
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

/// Mirrors `src/scan/brew.rs`: BrewFormula meta name/version/is_leaf/
/// dependencies/dependents/outdated/current_version, detail
/// `"leaf — {ver}"` / `"dependency — {ver}"`; BrewCask meta token/name/
/// version/app_paths/outdated/current_version, detail `"cask — {ver}"`.
fn brew_fixtures() -> Vec<Finding> {
    vec![
        Finding::new(FindingKind::BrewFormula, "ripgrep", "ripgrep")
            .detail("leaf — 14.1.0")
            .severity(Severity::Info)
            .meta(json!({
                "name": "ripgrep", "version": "14.1.0", "is_leaf": true,
                "dependencies": [], "dependents": [], "outdated": false,
                "current_version": null,
            })),
        Finding::new(FindingKind::BrewFormula, "jq", "jq")
            .detail("leaf — 1.7.1")
            .severity(Severity::Info)
            .meta(json!({
                "name": "jq", "version": "1.7.1", "is_leaf": true,
                "dependencies": ["oniguruma"], "dependents": [], "outdated": false,
                "current_version": null,
            })),
        Finding::new(FindingKind::BrewFormula, "openssl@3", "openssl@3")
            .detail("dependency — 3.3.1")
            .severity(Severity::Info)
            .meta(json!({
                "name": "openssl@3", "version": "3.3.1", "is_leaf": false,
                "dependencies": [], "dependents": ["ripgrep", "python@3.12"],
                "outdated": false, "current_version": null,
            })),
        Finding::new(FindingKind::BrewFormula, "python@3.12", "python@3.12")
            .detail("dependency — 3.12.3")
            .severity(Severity::Info)
            .meta(json!({
                "name": "python@3.12", "version": "3.12.3", "is_leaf": false,
                "dependencies": ["openssl@3"], "dependents": ["pyenv-build-helper"],
                "outdated": false, "current_version": null,
            })),
        Finding::new(FindingKind::BrewFormula, "wget", "wget")
            .detail("leaf — 1.21.4")
            .severity(Severity::Attention)
            .meta(json!({
                "name": "wget", "version": "1.21.4", "is_leaf": true,
                "dependencies": ["openssl@3"], "dependents": [], "outdated": true,
                "current_version": "1.24.5",
            }))
            .remedy(Remedy {
                label: "Upgrade to 1.24.5".to_string(),
                command: RemedyCommand::Shell {
                    program: "brew".to_string(),
                    args: vec!["upgrade".to_string(), "wget".to_string()],
                },
                reclaims_bytes: None,
                destructive: false,
            }),
        Finding::new(FindingKind::BrewCask, "docker", "docker")
            .detail("cask — 4.29.0")
            .severity(Severity::Info)
            .meta(json!({
                "token": "docker", "name": "docker", "version": "4.29.0",
                "app_paths": ["/Applications/Docker.app"], "outdated": false,
                "current_version": null,
            })),
        Finding::new(
            FindingKind::BrewCask,
            "visual-studio-code",
            "visual-studio-code",
        )
        .detail("cask — 1.89.1")
        .severity(Severity::Info)
        .meta(json!({
            "token": "visual-studio-code", "name": "visual-studio-code",
            "version": "1.89.1", "app_paths": ["/Applications/Visual Studio Code.app"],
            "outdated": false, "current_version": null,
        })),
        Finding::new(FindingKind::BrewCask, "rectangle", "rectangle")
            .detail("cask — 0.77")
            .severity(Severity::Attention)
            .meta(json!({
                "token": "rectangle", "name": "rectangle", "version": "0.77",
                "app_paths": ["/Applications/Rectangle.app"], "outdated": true,
                "current_version": "0.83",
            }))
            .remedy(Remedy {
                label: "Upgrade to 0.83".to_string(),
                command: RemedyCommand::Shell {
                    program: "brew".to_string(),
                    args: vec![
                        "upgrade".to_string(),
                        "--cask".to_string(),
                        "rectangle".to_string(),
                    ],
                },
                reclaims_bytes: None,
                destructive: false,
            }),
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
            .provenance("bounded local directory walk; symlinks skipped, hard links deduplicated per category")
            .coverage("Measured 18432 entries in the selected root.")
            .meta(json!({
                "group": "Disk allocation", "category": "Development", "entries": 18432,
                "complete": true, "coverage": "Measured 18432 entries in the selected root.",
            })),
    ]
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
                })
                .remedy(Remedy {
                    label: "Move plist to Trash — do this after unloading".to_string(),
                    command: RemedyCommand::Trash { path: PathBuf::from(path) },
                    reclaims_bytes: None,
                    destructive: true,
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
            .meta(json!({
                "entry": path, "index": index, "occurrences": occurrences,
                "exists": exists, "shadowed_by": shadowed_by,
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
            }),
        ),
        Finding::new(
            FindingKind::PathEntry,
            "__shell_startup__",
            "Shell startup time",
        )
        .detail("Median shell startup: 1450ms across 3 run(s)")
        .severity(Severity::Attention)
        .meta(json!({
            "median_ms": 1450.0,
            "runs_ms": [1390.0, 1450.0, 1510.0],
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
/// when reclaimable > 0, plus ephemeral active-container observations.
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
        }),
        Finding::new(
            FindingKind::DockerObject,
            "container:a1b2c3d4",
            "cubby-postgres-1 — active container",
        )
        .detail("Up 3 hours · 4.2% CPU · 210.0 MiB RAM")
        .severity(Severity::Info)
        .ephemeral()
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
        .ephemeral()
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

/// Mirrors `src/scan/tm_snapshots.rs`: title `"Local snapshot {date}"`, meta
/// name/date, Reclaimable with a `tmutil deletelocalsnapshots` remedy.
fn tm_snapshots_fixtures() -> Vec<Finding> {
    let dates = [
        ("2026-09-13-060000", "2026-09-13 06:00:00"),
        ("2026-09-12-060000", "2026-09-12 06:00:00"),
        ("2026-09-11-060000", "2026-09-11 06:00:00"),
        ("2026-09-10-060000", "2026-09-10 06:00:00"),
        ("2026-09-09-060000", "2026-09-09 06:00:00"),
        ("2026-09-08-060000", "2026-09-08 06:00:00"),
    ];

    dates
        .into_iter()
        .map(|(date, humanized)| {
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
            .meta(json!({ "name": name, "date": date }))
            .remedy(Remedy {
                label: "Delete local snapshot".to_string(),
                command: RemedyCommand::Shell {
                    program: "tmutil".to_string(),
                    args: vec!["deletelocalsnapshots".to_string(), date.to_string()],
                },
                reclaims_bytes: None,
                destructive: true,
            })
        })
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
