//! Globally visible Python packages, grouped by interpreter site and owner:
//!
//! - Homebrew sites (`<prefix>/lib/python3.X/site-packages`): a package whose
//!   metadata is symlinked into `Cellar/<formula>/` (or whose `INSTALLER` says
//!   `brew`) belongs to that formula; `INSTALLER: pip` with real files is a
//!   manual install — except Homebrew's own `pip`/`setuptools`/`wheel`
//!   bootstrap, which is protected. Manual installs get the exact
//!   `python3.X -m pip uninstall -y --break-system-packages <name>` (the
//!   override is shown per package, never applied silently, never in bulk).
//! - Apple's `/Library/Python/3.X` sites: inventory only, always protected.
//! - User sites (`~/Library/Python/3.X`, `~/.local/lib/python3.X`): the
//!   interpreter is only inferred, so the uninstall is offered as text to
//!   copy, not as an action.
//!
//! `Requires-Dist` is read from METADATA so a removal can say which
//! dependencies become unrequired versus stay required by other packages.
//! Markers other than `extra ==` are not evaluated (listed as unevaluated).
//! Project virtual environments are never inventoried here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::json;

use super::launchers;
use super::pymeta::{site_dist_infos, DistInfo};
use super::types::*;
use super::util::{file_name, list_dir};
use super::ProbeCtx;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SiteKind {
    Homebrew,
    Apple,
    User,
}

struct Site {
    path: PathBuf,
    kind: SiteKind,
    /// "3.14"
    py_version: String,
    interpreter: Option<PathBuf>,
    interpreter_inferred: bool,
    layout: String,
}

fn py_version_from(dir_name: &str) -> Option<String> {
    dir_name
        .strip_prefix("python")
        .filter(|v| v.starts_with('3'))
        .map(str::to_string)
        .or_else(|| dir_name.starts_with('3').then(|| dir_name.to_string()))
}

fn discover_sites(cx: &ProbeCtx) -> Vec<Site> {
    let mut sites = Vec::new();
    if let Some(prefix) = &cx.brew_prefix {
        for lib in list_dir(&prefix.join("lib")) {
            let name = file_name(&lib);
            let Some(v) = py_version_from(&name) else {
                continue;
            };
            let site = lib.join("site-packages");
            if !site.is_dir() {
                continue;
            }
            let opt = prefix.join(format!("opt/python@{v}/bin/python{v}"));
            let bin = prefix.join(format!("bin/python{v}"));
            let interpreter = [opt, bin].into_iter().find(|p| p.exists());
            sites.push(Site {
                path: site,
                kind: SiteKind::Homebrew,
                py_version: v.clone(),
                interpreter: interpreter
                    .clone()
                    .or_else(|| Some(prefix.join(format!("bin/python{v}")))),
                interpreter_inferred: interpreter.is_none(),
                layout: format!("homebrew-{v}"),
            });
        }
    }
    if cx.config.include_apple_python {
        for ver in list_dir(Path::new("/Library/Python")) {
            let v = file_name(&ver);
            let site = ver.join("site-packages");
            if site.is_dir() {
                sites.push(Site {
                    path: site,
                    kind: SiteKind::Apple,
                    py_version: v.clone(),
                    interpreter: Some(PathBuf::from("/usr/bin/python3")),
                    interpreter_inferred: true,
                    layout: format!("apple-{v}"),
                });
            }
        }
    }
    let home = &cx.paths.home;
    for ver in list_dir(&home.join("Library/Python")) {
        let v = file_name(&ver);
        let site = ver.join("lib/python/site-packages");
        if site.is_dir() {
            sites.push(Site {
                path: site,
                kind: SiteKind::User,
                py_version: v.clone(),
                interpreter: None,
                interpreter_inferred: true,
                layout: format!("user-{v}"),
            });
        }
    }
    for lib in list_dir(&home.join(".local/lib")) {
        let name = file_name(&lib);
        let Some(v) = py_version_from(&name) else {
            continue;
        };
        let site = lib.join("site-packages");
        if site.is_dir() {
            sites.push(Site {
                path: site,
                kind: SiteKind::User,
                py_version: v.clone(),
                interpreter: None,
                interpreter_inferred: true,
                layout: format!("user-local-{v}"),
            });
        }
    }
    for extra in &cx.config.python_sites {
        let site = cx.paths.expand(extra);
        if site.is_dir() && !sites.iter().any(|s| s.path == site) {
            let v = site
                .parent()
                .map(file_name)
                .and_then(|n| py_version_from(&n))
                .unwrap_or_else(|| "?".into());
            sites.push(Site {
                path: site,
                kind: SiteKind::User,
                py_version: v.clone(),
                interpreter: None,
                interpreter_inferred: true,
                layout: format!("configured-{v}"),
            });
        }
    }
    sites
}

const HOMEBREW_BOOTSTRAP: &[&str] = &["pip", "setuptools", "wheel"];

fn homebrew_formula_of(di: &DistInfo) -> Option<String> {
    let target = di.link_target.as_deref()?;
    match launchers::owner_from_path(target) {
        Some(Ownership::HomebrewFormula { name }) => Some(name),
        _ => None,
    }
}

fn site_installs(cx: &ProbeCtx, site: &Site) -> Vec<ToolInstall> {
    let infos = site_dist_infos(&site.path);
    let by_name: BTreeMap<String, &DistInfo> =
        infos.iter().map(|d| (d.normalized.clone(), d)).collect();
    // Reverse requirement index within this site (non-extra requirements).
    let mut required_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for d in &infos {
        for r in &d.requires {
            if r.extra_only || !by_name.contains_key(&r.name) {
                continue;
            }
            required_by
                .entry(r.name.clone())
                .or_default()
                .insert(d.normalized.clone());
        }
    }
    let bin_dir = site
        .path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|p| p.join("bin"));
    let interp_exists = site.interpreter.as_ref().map(|p| p.exists());
    let mut out = Vec::new();
    for d in &infos {
        let mut t = ToolInstall::new(Manager::Pip, site.path.clone(), d.name.clone());
        t.layout = Some(site.layout.clone());
        t.version = d.version.clone();
        t.install_dir = Some(d.dir.clone());
        t.runtime = Some(RuntimeRef {
            kind: "python",
            path: site.interpreter.clone(),
            version: Some(site.py_version.clone()),
            exists: interp_exists,
            source: if site.interpreter_inferred {
                "inferred from the site-packages path".into()
            } else {
                "<prefix>/opt/python@X.Y/bin".into()
            },
        });
        let formula = homebrew_formula_of(d);
        let installer = d.installer.clone();
        let brew_owned = formula.is_some() || installer.as_deref() == Some("brew");
        t.evidence(
            "manager_metadata",
            d.dir.display().to_string(),
            format!(
                "INSTALLER: {}; REQUESTED: {}{}",
                installer.as_deref().unwrap_or("(absent)"),
                if d.requested { "yes" } else { "no" },
                formula
                    .as_ref()
                    .map(|f| format!("; files linked from Cellar/{f}"))
                    .unwrap_or_default()
            ),
            Confidence::High,
        );
        // Commands: console_scripts + RECORD entries under ../bin/.
        let mut cmds: BTreeSet<String> = d.console_scripts.iter().cloned().collect();
        for p in &d.record_paths {
            if let Some(rest) = p.strip_prefix("../../../bin/") {
                if !rest.contains('/') {
                    cmds.insert(rest.to_string());
                }
            }
        }
        for c in cmds {
            let target = bin_dir.as_ref().map(|b| b.join(&c));
            if let Some(path) = &target {
                if let Some(mut l) = launchers::inspect(path) {
                    l.owner = Ownership::ThisInstall;
                    t.launchers.push(l);
                }
            }
            t.commands.push(DeclaredCommand {
                name: c,
                declared_target: target.map(|p| p.display().to_string()),
            });
        }
        let req_installed: Vec<String> = d
            .requires
            .iter()
            .filter(|r| !r.extra_only && by_name.contains_key(&r.name))
            .map(|r| r.name.clone())
            .collect();
        let unevaluated: Vec<String> = d
            .requires
            .iter()
            .filter(|r| !r.extra_only && r.marker.is_some())
            .map(|r| format!("{} ; {}", r.name, r.marker.clone().unwrap_or_default()))
            .collect();
        let needed_by: Vec<String> = required_by
            .get(&d.normalized)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        let mut becomes_unrequired = Vec::new();
        let mut still_required = Vec::new();
        for dep in &req_installed {
            let dep_info = by_name.get(dep).copied();
            let dep_brew = dep_info
                .map(|x| {
                    homebrew_formula_of(x).is_some()
                        || x.installer.as_deref() == Some("brew")
                        || (site.kind == SiteKind::Homebrew
                            && HOMEBREW_BOOTSTRAP.contains(&x.normalized.as_str()))
                })
                .unwrap_or(false);
            if dep_brew {
                still_required.push(format!("{dep} (Homebrew-owned, stays)"));
                continue;
            }
            let others: Vec<&String> = required_by
                .get(dep)
                .map(|s| s.iter().filter(|x| *x != &d.normalized).collect())
                .unwrap_or_default();
            if others.is_empty() {
                becomes_unrequired.push(dep.clone());
            } else {
                still_required.push(format!(
                    "{dep} (by {})",
                    others
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        match site.kind {
            SiteKind::Apple => t.protected = Some("Apple-provided Python site; never modified".into()),
            SiteKind::Homebrew if brew_owned => {
                t.protected = Some(format!(
                    "Homebrew formula {} owns these files; remove the formula instead",
                    formula.clone().unwrap_or_else(|| "(unknown)".into())
                ))
            }
            SiteKind::Homebrew if HOMEBREW_BOOTSTRAP.contains(&d.normalized.as_str()) => {
                t.protected = Some("Homebrew's python bootstrap (pip/setuptools/wheel); managed by the python formula".into())
            }
            SiteKind::Homebrew => {
                let interp = site.interpreter.clone();
                match interp {
                    Some(i) if i.exists() => {
                        t.removal.native = Some(NativeCommand {
                            program: i.display().to_string(),
                            args: vec![
                                "-m".into(),
                                "pip".into(),
                                "uninstall".into(),
                                "-y".into(),
                                "--break-system-packages".into(),
                                d.name.clone(),
                            ],
                            program_path: Some(i),
                        });
                        t.removal.follow_up.push(
                            "--break-system-packages is required because this site is Homebrew's externally managed environment; it applies to this one package only".into(),
                        );
                    }
                    _ => t.removal.refusals.push("the site's interpreter does not exist; cannot run pip for this site".into()),
                }
            }
            SiteKind::User => {
                t.removal.suggested_command = Some(format!(
                    "python{} -m pip uninstall {}",
                    site.py_version, d.name
                ));
                t.removal.refusals.push("interpreter for this user site is only inferred; the uninstall is offered as text, not run".into());
            }
        }
        if !becomes_unrequired.is_empty() {
            t.removal.follow_up.push(format!(
                "becomes unrequired: {}",
                becomes_unrequired.join(", ")
            ));
        }
        if !still_required.is_empty() {
            t.removal
                .follow_up
                .push(format!("still required: {}", still_required.join("; ")));
        }
        t.size_bytes = d.record_bytes;
        t.manager_extra = json!({
            "site": site.path,
            "site_kind": match site.kind { SiteKind::Homebrew => "homebrew", SiteKind::Apple => "apple", SiteKind::User => "user" },
            "interpreter": site.interpreter,
            "interpreter_inferred": site.interpreter_inferred,
            "installer": installer,
            "requested": d.requested,
            "homebrew_formula": formula,
            "requires_dist": req_installed,
            "required_by": needed_by,
            "becomes_unrequired": becomes_unrequired,
            "still_required": still_required,
            "unevaluated_markers": unevaluated,
        });
        out.push(t);
    }
    let _ = cx;
    out
}

pub fn probe(cx: &ProbeCtx) -> ProbeResult {
    let sites = discover_sites(cx);
    if sites.is_empty() {
        return ProbeResult::absent();
    }
    let mut installs = Vec::new();
    for site in &sites {
        installs.extend(site_installs(cx, site));
    }
    ProbeResult {
        installs,
        status: Some(ManagerStatus::Ok {
            detail: Some(format!(
                "{} site(s): {}",
                sites.len(),
                sites
                    .iter()
                    .map(|s| s.layout.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Paths, ToolsConfig};
    use crate::scan::global_tools::npm::tests::cx;
    use crate::scan::global_tools::pymeta::tests::mk_dist_info;
    use crate::scan::global_tools::shellpath::ShellPath;

    /// A Homebrew-like prefix with python@3.14: brew-owned certifi (Cellar
    /// symlinks), Homebrew's pip bootstrap (INSTALLER pip, no links), and
    /// manual pip installs requests → charset-normalizer, urllib3 (also
    /// needed by google-auth) — the audited Mac's situation.
    pub(crate) fn mk_brew_python(prefix: &Path) -> PathBuf {
        let site = prefix.join("lib/python3.14/site-packages");
        std::fs::create_dir_all(&site).unwrap();
        let interp_dir = prefix.join("opt/python@3.14/bin");
        std::fs::create_dir_all(&interp_dir).unwrap();
        std::fs::write(interp_dir.join("python3.14"), "").unwrap();
        std::fs::create_dir_all(prefix.join("bin")).unwrap();
        let cellar = prefix.join("Cellar/certifi/2026.7.22/lib/python3.14/site-packages");
        mk_dist_info(
            &site,
            "certifi",
            "2026.7.22",
            "brew",
            &[],
            &[],
            Some(&cellar),
        );
        mk_dist_info(&site, "pip", "26.2.1", "pip", &[], &["pip3"], None);
        mk_dist_info(
            &site,
            "requests",
            "2.32.5",
            "pip",
            &[
                "charset_normalizer (<4,>=2)",
                "urllib3",
                "certifi",
                "PySocks; extra == \"socks\"",
            ],
            &[],
            None,
        );
        mk_dist_info(
            &site,
            "charset_normalizer",
            "3.4.6",
            "pip",
            &[],
            &["normalizer"],
            None,
        );
        std::fs::write(prefix.join("bin/normalizer"), "#!/x\n").unwrap();
        mk_dist_info(&site, "urllib3", "2.6.3", "pip", &[], &[], None);
        mk_dist_info(
            &site,
            "google_auth",
            "2.49.1",
            "pip",
            &["urllib3", "rsa; python_version < \"3.8\""],
            &[],
            None,
        );
        site
    }

    #[test]
    fn ownership_protection_remedies_and_requires_closure() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let prefix = tmp.path().join("opt/homebrew");
        let site = mk_brew_python(&prefix);
        let config = ToolsConfig {
            include_apple_python: false,
            ..Default::default()
        };
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, Some(prefix.clone())));
        let by = |n: &str| {
            r.installs
                .iter()
                .find(|t| t.name == n)
                .unwrap_or_else(|| panic!("{n}"))
        };

        let certifi = by("certifi");
        assert!(certifi
            .protected
            .as_deref()
            .unwrap()
            .contains("Homebrew formula certifi"));
        assert!(certifi.removal.native.is_none());
        assert_eq!(certifi.manager_extra["homebrew_formula"], "certifi");
        assert_eq!(certifi.manager_extra["required_by"], json!(["requests"]));

        let pip = by("pip");
        assert!(pip.protected.as_deref().unwrap().contains("bootstrap"));

        let requests = by("requests");
        assert!(requests.protected.is_none());
        let native = requests.removal.native.as_ref().unwrap();
        assert_eq!(
            native.program,
            prefix
                .join("opt/python@3.14/bin/python3.14")
                .display()
                .to_string()
        );
        assert_eq!(
            native.args,
            [
                "-m",
                "pip",
                "uninstall",
                "-y",
                "--break-system-packages",
                "requests"
            ]
        );
        assert_eq!(
            requests.manager_extra["becomes_unrequired"],
            json!(["charset-normalizer"])
        );
        assert_eq!(
            requests.manager_extra["still_required"],
            json!([
                "urllib3 (by google-auth)",
                "certifi (Homebrew-owned, stays)"
            ])
        );
        assert_eq!(
            requests.manager_extra["requires_dist"],
            json!(["charset-normalizer", "urllib3", "certifi"])
        );
        assert_eq!(
            requests.identity_key(),
            format!("pip:{}:requests", site.display())
        );
        assert_eq!(requests.layout.as_deref(), Some("homebrew-3.14"));
        assert_eq!(requests.size_bytes, Some(100));

        let cn = by("charset_normalizer");
        assert_eq!(cn.commands[0].name, "normalizer");
        assert_eq!(cn.launchers.len(), 1);
        let ga = by("google_auth");
        assert_eq!(
            ga.manager_extra["unevaluated_markers"],
            json!(["rsa ; python_version < \"3.8\""])
        );
    }

    #[test]
    fn user_site_is_inventory_with_suggested_command_only() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let paths = Paths::from_home(home);
        let site = home.join("Library/Python/3.9/lib/python/site-packages");
        mk_dist_info(&site, "six", "1.16.0", "pip", &[], &[], None);
        let config = ToolsConfig {
            include_apple_python: false,
            ..Default::default()
        };
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        let six = &r.installs[0];
        assert!(six.removal.native.is_none());
        assert_eq!(
            six.removal.suggested_command.as_deref(),
            Some("python3.9 -m pip uninstall six")
        );
        assert_eq!(six.runtime.as_ref().unwrap().exists, None);
        assert_eq!(six.layout.as_deref(), Some("user-3.9"));
    }
}
