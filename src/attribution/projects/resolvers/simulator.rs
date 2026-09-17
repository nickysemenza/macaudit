//! Simulator app data (Bundle/Data containers) joined to a project via its
//! Xcode product bundle ids. `baseline()` claims each device once; nesting
//! (`accounting.rs`) automatically subtracts whatever a project claimed
//! underneath it.

use std::path::{Path, PathBuf};

use super::super::Project;
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER};
use crate::scan::walk::listing::{self, Kind};

/// The two container roots under a simulator device's data volume that hold
/// per-app storage.
const CONTAINER_KINDS: &[&str] = &["Bundle", "Data"];

pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    if project.bundle_ids.is_empty() {
        return Vec::new();
    }
    let owner = project.root.to_string_lossy().into_owned();
    let devices_dir = devices_dir(env);
    let Ok(devices) = listing::list(&devices_dir) else {
        return Vec::new();
    };

    let mut claims = Vec::new();
    for device_entry in &devices.entries {
        if device_entry.kind != Kind::Dir {
            continue;
        }
        let Some(udid) = device_entry.name.to_str() else {
            continue;
        };
        let device_dir = devices_dir.join(udid);
        let device_name = device_display_name(&device_dir);

        for kind in CONTAINER_KINDS {
            let apps_dir = device_dir
                .join("data/Containers")
                .join(kind)
                .join("Application");
            let Ok(apps) = listing::list(&apps_dir) else {
                continue;
            };
            for app_entry in &apps.entries {
                if app_entry.kind != Kind::Dir {
                    continue;
                }
                let Some(uuid) = app_entry.name.to_str() else {
                    continue;
                };
                let container_dir = apps_dir.join(uuid);
                let Some(bundle_id) = container_bundle_id(&container_dir, kind) else {
                    continue;
                };
                if !matches_bundle_id(&project.bundle_ids, &bundle_id) {
                    continue;
                }
                claims.push(
                    Claim::new(
                        container_dir,
                        owner.clone(),
                        EntryKind::Simulator,
                        EvidenceTier::Exact,
                        format!("installed in simulator {device_name}"),
                    )
                    .label(format!("{bundle_id} on {device_name}"))
                    .ecosystem("xcode"),
                );
            }
        }
    }
    claims
}

/// Every simulator device, claimed once — a project's containers nested
/// under it are subtracted automatically by `accounting::account`'s nesting
/// pass, so this needs no knowledge of which projects matched what.
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let devices_dir = devices_dir(env);
    let Ok(devices) = listing::list(&devices_dir) else {
        return Vec::new();
    };

    let mut claims = Vec::new();
    for entry in &devices.entries {
        if entry.kind != Kind::Dir {
            continue;
        }
        let Some(udid) = entry.name.to_str() else {
            continue;
        };
        let device_dir = devices_dir.join(udid);
        let name = device_display_name(&device_dir);
        let label = match device_runtime_label(&device_dir) {
            Some(runtime) => format!("{name} ({runtime})"),
            None => name,
        };
        claims.push(
            Claim::new(
                device_dir,
                BASELINE_OWNER,
                EntryKind::Simulator,
                EvidenceTier::EcosystemDefault,
                "simulator device",
            )
            .label(label)
            .baseline("xcode"),
        );
    }
    claims
}

fn devices_dir(env: &ResolveEnv<'_>) -> PathBuf {
    env.paths
        .home
        .join("Library/Developer/CoreSimulator/Devices")
}

/// The owning bundle id of one app container: `Data` containers carry it
/// directly in their metadata plist; `Bundle` containers only have the
/// `.app` itself, so fall back to its `Info.plist`.
fn container_bundle_id(container_dir: &Path, kind: &str) -> Option<String> {
    let metadata = container_dir.join(".com.apple.mobile_container_manager.metadata.plist");
    if let Ok(value) = plist::Value::from_file(&metadata) {
        if let Some(id) = value
            .as_dictionary()
            .and_then(|d| d.get("MCMMetadataIdentifier"))
            .and_then(|v| v.as_string())
        {
            return Some(id.to_string());
        }
    }
    if kind != "Bundle" {
        return None;
    }
    let listing = listing::list(container_dir).ok()?;
    for entry in &listing.entries {
        if entry.kind != Kind::Dir {
            continue;
        }
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        if !name.ends_with(".app") {
            continue;
        }
        let info_plist = container_dir.join(name).join("Info.plist");
        if let Ok(value) = plist::Value::from_file(&info_plist) {
            if let Some(id) = value
                .as_dictionary()
                .and_then(|d| d.get("CFBundleIdentifier"))
                .and_then(|v| v.as_string())
            {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// `id` matches a project bundle id exactly, or is an extension of one
/// (`<id>.<ext>`, e.g. a share extension or widget).
fn matches_bundle_id(project_ids: &[String], id: &str) -> bool {
    project_ids
        .iter()
        .any(|p| id == p || id.starts_with(&format!("{p}.")))
}

fn device_display_name(device_dir: &Path) -> String {
    plist::Value::from_file(device_dir.join("device.plist"))
        .ok()
        .and_then(|v| {
            v.as_dictionary()
                .and_then(|d| d.get("name"))
                .and_then(|v| v.as_string())
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            device_dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
}

/// A short runtime label (e.g. `iOS 17.0`) from `device.plist`'s `runtime`
/// identifier (`com.apple.CoreSimulator.SimRuntime.iOS-17-0`), for the
/// baseline row's `"<device name> (<runtime>)"` label.
fn device_runtime_label(device_dir: &Path) -> Option<String> {
    let value = plist::Value::from_file(device_dir.join("device.plist")).ok()?;
    let runtime = value
        .as_dictionary()?
        .get("runtime")
        .and_then(|v| v.as_string())?;
    Some(format_runtime_identifier(runtime))
}

fn format_runtime_identifier(runtime: &str) -> String {
    let Some((_, rest)) = runtime.rsplit_once("SimRuntime.") else {
        return runtime.to_string();
    };
    match rest.split_once('-') {
        // "iOS-17-0" -> platform "iOS", version "17-0" -> "17.0".
        Some((platform, version)) => format!("{platform} {}", version.replace('-', ".")),
        None => rest.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_bundle_id_accepts_an_exact_match_and_an_extension() {
        let ids = vec!["com.example.app".to_string()];
        assert!(matches_bundle_id(&ids, "com.example.app"));
        assert!(matches_bundle_id(&ids, "com.example.app.widget"));
        assert!(!matches_bundle_id(&ids, "com.example.other"));
        assert!(!matches_bundle_id(&ids, "com.example.appfoo"));
    }

    #[test]
    fn formats_a_simruntime_identifier() {
        assert_eq!(
            format_runtime_identifier("com.apple.CoreSimulator.SimRuntime.iOS-17-0"),
            "iOS 17.0"
        );
        assert_eq!(format_runtime_identifier("weird"), "weird");
    }
}
