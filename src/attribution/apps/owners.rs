//! App-axis owner discovery: Apps-section findings filtered to
//! `/Applications`, `~/Applications`, `/System/Applications` (nested helper
//! `.app`s folded into their outermost bundle), Homebrew casks folded into
//! their `.app`, Homebrew formulae/Homebrew itself from the Brew snapshot,
//! and global tools from the Tools snapshot.
//!
//! Owner keys must match `accounting::owner_from_key` for `Axis::AppStorage`
//! exactly (`src/attribution/accounting.rs`): a bundle id (or the `.app`
//! path when a bundle couldn't be read), `formula:<name>`, `tool:<name>`,
//! `"homebrew"`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::attribution::model::{Owner, OwnerKind, ResolveEnv};
use crate::model::{FindingKind, ScannerId};
use crate::scan::brew;

/// A `.app` bundle owner plus everything the linker (`linkers.rs`) needs
/// beyond the public `Owner`: other ids that also identify it (folded
/// nested helper bundles' bundle ids, a Homebrew cask token), and the
/// Info.plist fields `src/scan/apps.rs` reads for the name-match tier.
pub(crate) struct AppOwner {
    pub owner: Owner,
    /// Bundle ids of nested helper `.app`s folded into this one, plus any
    /// Homebrew cask token that installs it — matched case-insensitively
    /// alongside `owner.key` by the linker's exact-bundle-id tier.
    pub aliases: Vec<String>,
    /// Homebrew cask tokens that install this app (`claude`, `visual-studio-code`)
    /// — a *name*, so the linker matches them at the name tier, not as ids.
    pub cask_names: Vec<String>,
    pub bundle_name: Option<String>,
    pub display_name: Option<String>,
    pub executable: Option<String>,
}

/// A Homebrew formula owner.
pub(crate) struct FormulaOwner {
    pub owner: Owner,
    /// Executable names this formula installs — just the formula's own name
    /// when Brew's finding metadata carries no narrower bin list (see
    /// `discover_formulae`).
    pub bin_names: Vec<String>,
    /// Formulae that directly depend on this one (`meta.dependents` from
    /// `src/scan/brew.rs::formula_finding`) — used by `linkers.rs` to share
    /// a dependency's Cellar dir N ways with its dependents.
    pub dependents: Vec<String>,
}

/// A global dev-tool owner (npm/pnpm/cargo/pipx/uv/pip/bun install).
pub(crate) struct ToolOwner {
    pub owner: Owner,
    /// Extra paths this tool owns outright beyond `owner.path` — a
    /// pnpm-style manager's shared `store_dir`, when its finding's
    /// `manager_extra` carries one.
    pub extra_paths: Vec<PathBuf>,
}

/// Every App-axis owner, grouped by kind — the shape `candidates.rs` and
/// `linkers.rs` work over. `into_owners` flattens it to the plain
/// `Vec<Owner>` registry `accounting::account` takes.
pub(crate) struct Owners {
    pub apps: Vec<AppOwner>,
    pub formulae: Vec<FormulaOwner>,
    pub tools: Vec<ToolOwner>,
    pub homebrew: Option<Owner>,
}

/// Discover every App-axis owner in its rich, linker-ready form.
pub(crate) fn discover(env: &ResolveEnv<'_>) -> Owners {
    Owners {
        apps: discover_apps(env),
        formulae: discover_formulae(env),
        tools: discover_tools(env),
        homebrew: discover_homebrew(env),
    }
}

impl Owners {
    /// Flatten into the plain owner registry `accounting::account` takes.
    pub fn into_owners(self) -> Vec<Owner> {
        let mut out =
            Vec::with_capacity(self.apps.len() + self.formulae.len() + self.tools.len() + 1);
        out.extend(self.apps.into_iter().map(|a| a.owner));
        out.extend(self.formulae.into_iter().map(|f| f.owner));
        out.extend(self.tools.into_iter().map(|t| t.owner));
        out.extend(self.homebrew);
        out
    }
}

/// The three well-known app directories owners are restricted to (plan
/// "Decisions": App-axis owners) — `/System/Library/CoreServices` and
/// everything else is deliberately excluded. `Utilities` is listed before
/// its parent so the longest-prefix match below finds it first.
fn owner_roots(env: &ResolveEnv<'_>) -> Vec<PathBuf> {
    vec![
        PathBuf::from("/System/Applications/Utilities"),
        PathBuf::from("/System/Applications"),
        PathBuf::from("/Applications"),
        env.paths.expand("~/Applications"),
    ]
}

fn discover_apps(env: &ResolveEnv<'_>) -> Vec<AppOwner> {
    let roots = owner_roots(env);
    let mut top_level: BTreeMap<PathBuf, AppOwner> = BTreeMap::new();
    // Deferred to a second pass so the order `env.findings` happens to
    // return apps in never matters: an outer bundle finding can come either
    // before or after the helper bundles nested inside it.
    let mut nested_aliases: Vec<(PathBuf, String)> = Vec::new();

    for f in env.findings(ScannerId::Apps) {
        let Some(path) = &f.path else { continue };
        let Some(root) = roots.iter().find(|r| path.starts_with(r)) else {
            continue;
        };
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        // The outermost `.app` component: directly under the root, or one
        // plain folder down (`/Applications/Adobe Photoshop 2025/X.app`,
        // `/Applications/Utilities/X.app`). Deeper than that is a helper
        // bundle or a stray copy, not an installed application.
        let mut outer_rel = PathBuf::new();
        let mut found = false;
        for (i, comp) in rel.components().enumerate() {
            outer_rel.push(comp.as_os_str());
            if comp.as_os_str().to_string_lossy().ends_with(".app") {
                found = true;
                break;
            }
            if i >= 1 {
                break;
            }
        }
        if !found {
            continue;
        }
        let outer_path = root.join(&outer_rel);
        let bundle_id = f
            .meta
            .get("bundle_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        if *path == outer_path {
            // A top-level bundle: build its owner entry. `system_profiler`
            // listing the same bundle twice (a re-signed duplicate) is rare
            // but harmless — first one wins.
            top_level.entry(outer_path).or_insert_with(|| {
                let key = bundle_id
                    .clone()
                    .unwrap_or_else(|| path.to_string_lossy().into_owned());
                // The bundle's own file stem — what Finder shows in
                // /Applications ("Ableton Live 12 Lite", not CFBundleName's
                // "Live"); never carries a version, unlike `AppsScanner`'s
                // `"<name> <version>"` finding title.
                let name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| f.title.clone());
                AppOwner {
                    owner: Owner {
                        key,
                        kind: OwnerKind::App,
                        name,
                        path: Some(path.clone()),
                    },
                    aliases: Vec::new(),
                    cask_names: Vec::new(),
                    bundle_name: f
                        .meta
                        .get("bundle_name")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    display_name: f
                        .meta
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    executable: f
                        .meta
                        .get("executable")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                }
            });
        } else if let Some(bid) = bundle_id {
            nested_aliases.push((outer_path, bid));
        }
    }

    for (outer_path, alias) in nested_aliases {
        if let Some(owner) = top_level.get_mut(&outer_path) {
            owner.aliases.push(alias);
        }
    }

    // Homebrew casks: `app_paths` names the same `.app` an owner above is
    // already keyed by bundle id — fold the cask token in as a name
    // (casks fold into their .app), so the linker's name tier
    // also matches candidate dirs named after the cask.
    for f in env.findings(ScannerId::Brew) {
        if f.kind != FindingKind::BrewCask {
            continue;
        }
        let Some(app_paths) = f.meta.get("app_paths").and_then(|v| v.as_array()) else {
            continue;
        };
        let token = f
            .meta
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or(f.title.as_str());
        for p in app_paths {
            let Some(p) = p.as_str() else { continue };
            if let Some(owner) = top_level.get_mut(&PathBuf::from(p)) {
                if !owner.cask_names.iter().any(|a| a == token) {
                    owner.cask_names.push(token.to_string());
                }
            }
        }
    }

    top_level.into_values().collect()
}

fn discover_formulae(env: &ResolveEnv<'_>) -> Vec<FormulaOwner> {
    let prefix = brew::brew_prefix();
    env.findings(ScannerId::Brew)
        .iter()
        .filter(|f| f.kind == FindingKind::BrewFormula)
        .map(|f| {
            let name = f
                .meta
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(f.title.as_str())
                .to_string();
            let dependents: Vec<String> = f
                .meta
                .get("dependents")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let path = f
                .path
                .clone()
                .or_else(|| prefix.as_ref().map(|p| p.join("Cellar").join(&name)));
            FormulaOwner {
                owner: Owner {
                    key: format!("formula:{name}"),
                    kind: OwnerKind::Formula,
                    name: name.clone(),
                    path,
                },
                // `brew info --json=v2`'s formula entries carry no
                // "installed binaries" list (`formula_finding`'s meta in
                // `src/scan/brew.rs`) — the formula's own name is the only
                // reliable executable-name signal for the linker's
                // name-match tier.
                bin_names: vec![name],
                dependents,
            }
        })
        .collect()
}

fn discover_tools(env: &ResolveEnv<'_>) -> Vec<ToolOwner> {
    let mut by_name: BTreeMap<String, ToolOwner> = BTreeMap::new();
    for f in env.findings(ScannerId::Tools) {
        if f.kind != FindingKind::GlobalTool {
            continue;
        }
        let name = f
            .meta
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(f.title.as_str())
            .to_string();
        let root = f
            .meta
            .get("root")
            .and_then(|v| v.as_str())
            .map(PathBuf::from);
        let install_dir = f
            .meta
            .get("install_dir")
            .and_then(|v| v.as_str())
            .map(PathBuf::from);
        let store_dir = f
            .meta
            .get("manager_extra")
            .and_then(|m| m.get("store_dir"))
            .and_then(|v| v.as_str())
            .map(PathBuf::from);
        let path = install_dir.or(root);

        // Two `ToolInstall`s can share one tool name (e.g. pnpm resolved at
        // more than one root) — they're one owner (`tool:<name>`), so later
        // installs only contribute a path when the first didn't have one,
        // plus any new `store_dir`.
        let owner = by_name.entry(name.clone()).or_insert_with(|| ToolOwner {
            owner: Owner {
                key: format!("tool:{name}"),
                kind: OwnerKind::Tool,
                name: name.clone(),
                path: path.clone(),
            },
            extra_paths: Vec::new(),
        });
        if owner.owner.path.is_none() {
            owner.owner.path = path;
        }
        if let Some(store_dir) = store_dir {
            if !owner.extra_paths.contains(&store_dir) {
                owner.extra_paths.push(store_dir);
            }
        }
    }
    by_name.into_values().collect()
}

fn discover_homebrew(env: &ResolveEnv<'_>) -> Option<Owner> {
    let prefix = brew::brew_prefix();
    let has_brew_findings = env
        .findings(ScannerId::Brew)
        .iter()
        .any(|f| matches!(f.kind, FindingKind::BrewFormula | FindingKind::BrewCask));
    if prefix.is_none() && !has_brew_findings {
        return None;
    }
    Some(Owner {
        key: "homebrew".to_string(),
        kind: OwnerKind::Homebrew,
        name: "Homebrew".to_string(),
        path: prefix,
    })
}
