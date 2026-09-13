//! `cargo install`ed binaries from `<cargo_home>/.crates2.json` (with the
//! older `.crates.toml` as fallback). Launchers are the regular files in
//! `<cargo_home>/bin`; symlinks there that point at `rustup` are toolchain
//! proxies (cargo, rustc, …) and belong to rustup, not to a crate.

use std::path::Path;

use serde_json::json;

use super::launchers;
use super::types::*;
use super::util::{list_dir, read_json, read_toml};
use super::ProbeCtx;

/// `"name 1.2.3 (registry+https://…)"` → (name, version, source).
pub fn parse_install_key(key: &str) -> Option<(String, String, String)> {
    let mut parts = key.splitn(3, ' ');
    let name = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    let source = parts
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '(' || c == ')')
        .to_string();
    Some((name, version, source))
}

struct CrateRecord {
    name: String,
    version: String,
    source: String,
    bins: Vec<String>,
    extra: serde_json::Value,
}

fn read_crates2(path: &Path) -> Option<Vec<CrateRecord>> {
    let v = read_json(path)?;
    let installs = v.get("installs")?.as_object()?;
    let mut out = Vec::new();
    for (key, rec) in installs {
        let Some((name, version, source)) = parse_install_key(key) else {
            continue;
        };
        let bins = rec
            .get("bins")
            .and_then(|b| b.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let rustc = rec
            .get("rustc")
            .and_then(|r| r.as_str())
            .and_then(|r| r.lines().next())
            .map(str::to_string);
        out.push(CrateRecord {
            name,
            version,
            source,
            bins,
            extra: json!({
                "target": rec.get("target").cloned().unwrap_or(serde_json::Value::Null),
                "profile": rec.get("profile").cloned().unwrap_or(serde_json::Value::Null),
                "rustc": rustc,
                "features": rec.get("features").cloned().unwrap_or(serde_json::Value::Null),
            }),
        });
    }
    Some(out)
}

fn read_crates_toml(path: &Path) -> Option<Vec<CrateRecord>> {
    let v = read_toml(path)?;
    let v1 = v.get("v1")?.as_table()?;
    let mut out = Vec::new();
    for (key, bins) in v1 {
        let Some((name, version, source)) = parse_install_key(key) else {
            continue;
        };
        let bins = bins
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        out.push(CrateRecord {
            name,
            version,
            source,
            bins,
            extra: json!({}),
        });
    }
    Some(out)
}

pub fn probe(cx: &ProbeCtx) -> ProbeResult {
    let home = cx.paths.expand(&cx.config.cargo_home);
    if !home.is_dir() {
        return ProbeResult::absent();
    }
    let (records, source_file) = match read_crates2(&home.join(".crates2.json")) {
        Some(r) => (r, ".crates2.json"),
        None => match read_crates_toml(&home.join(".crates.toml")) {
            Some(r) => (r, ".crates.toml"),
            None => {
                return ProbeResult {
                    installs: Vec::new(),
                    status: Some(if home.join("bin").is_dir() {
                        ManagerStatus::Partial {
                            missing: vec!["no readable .crates2.json or .crates.toml".into()],
                        }
                    } else {
                        ManagerStatus::Absent
                    }),
                };
            }
        },
    };
    let bin_dir = home.join("bin");
    let mut installs = Vec::new();
    for rec in records {
        let mut t = ToolInstall::new(Manager::Cargo, home.clone(), rec.name.clone());
        t.version = Some(rec.version.clone());
        t.install_dir = Some(bin_dir.clone());
        t.evidence(
            "manager_metadata",
            home.join(source_file).display().to_string(),
            format!(
                "cargo install record {} {} ({})",
                rec.name, rec.version, rec.source
            ),
            Confidence::High,
        );
        let mut size = 0u64;
        for bin in &rec.bins {
            t.commands.push(DeclaredCommand {
                name: bin.clone(),
                declared_target: None,
            });
            let path = bin_dir.join(bin);
            match launchers::inspect(&path) {
                Some(mut l) if l.owner != Ownership::RustupProxy => {
                    l.owner = Ownership::ThisInstall;
                    if let Ok(m) = std::fs::metadata(&path) {
                        size += m.len();
                    }
                    t.launchers.push(l);
                }
                Some(_) => t
                    .completeness
                    .add(format!("{bin} is a rustup proxy, not this crate's binary")),
                None => t
                    .completeness
                    .add(format!("binary {} is missing", path.display())),
            }
        }
        t.size_bytes = (size > 0).then_some(size);
        t.removal.native = Some(NativeCommand {
            program: "cargo".into(),
            args: vec![
                "uninstall".into(),
                rec.name.clone(),
                "--root".into(),
                home.display().to_string(),
            ],
            program_path: None,
        });
        t.removal.launcher_only = t.launchers.iter().map(|l| l.path.clone()).collect();
        t.manager_extra = rec.extra;
        if let Some(o) = t.manager_extra.as_object_mut() {
            o.insert("source".into(), json!(rec.source));
        }
        installs.push(t);
    }
    // Proxies present but no crate claims them: informational only.
    let proxies: Vec<String> = list_dir(&bin_dir)
        .into_iter()
        .filter(|p| {
            launchers::inspect(p)
                .map(|l| l.owner == Ownership::RustupProxy)
                .unwrap_or(false)
        })
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
        .collect();
    ProbeResult {
        installs,
        status: Some(ManagerStatus::Ok {
            detail: Some(format!(
                "{source_file}; {} rustup proxies skipped",
                proxies.len()
            )),
        }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Paths, ToolsConfig};
    use crate::scan::global_tools::npm::tests::cx;
    use crate::scan::global_tools::shellpath::ShellPath;
    use std::os::unix::fs::{symlink, PermissionsExt};

    pub(crate) fn mk_cargo_home(home: &Path) {
        std::fs::create_dir_all(home.join("bin")).unwrap();
        std::fs::write(
            home.join(".crates2.json"),
            r#"{"installs": {
              "wasm-pack 0.14.0 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["wasm-pack"], "target": "aarch64-apple-darwin", "profile": "release", "rustc": "rustc 1.93.0 (abc 2026-01-19)\nbinary: rustc\n"},
              "cargo-machete 0.9.2 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["cargo-machete"]},
              "twiggy 0.7.0 (registry+https://github.com/rust-lang/crates.io-index)": {"bins": ["twiggy"]}
            }}"#,
        )
        .unwrap();
        for b in ["wasm-pack", "cargo-machete"] {
            let p = home.join("bin").join(b);
            std::fs::write(&p, "bin").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(home.join("bin/rustup"), "").unwrap();
        for proxy in ["cargo", "rustc"] {
            symlink("rustup", home.join("bin").join(proxy)).unwrap();
        }
    }

    #[test]
    fn crates2_parsed_rustup_proxies_excluded_missing_bin_partial() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        mk_cargo_home(&tmp.path().join(".cargo"));
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        let names: Vec<&str> = r.installs.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["cargo-machete", "twiggy", "wasm-pack"]);
        let wp = r.installs.iter().find(|t| t.name == "wasm-pack").unwrap();
        assert_eq!(wp.version.as_deref(), Some("0.14.0"));
        assert_eq!(wp.launchers.len(), 1);
        assert_eq!(wp.manager_extra["rustc"], "rustc 1.93.0 (abc 2026-01-19)");
        assert_eq!(wp.removal.native.as_ref().unwrap().args[0], "uninstall");
        let twiggy = r.installs.iter().find(|t| t.name == "twiggy").unwrap();
        assert!(twiggy.launchers.is_empty());
        assert_eq!(twiggy.completeness.level, "partial");
        assert!(
            matches!(r.status, Some(ManagerStatus::Ok { detail: Some(ref d) }) if d.contains("2 rustup proxies"))
        );
    }

    #[test]
    fn crates_toml_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let home = tmp.path().join(".cargo");
        mk_cargo_home(&home);
        std::fs::remove_file(home.join(".crates2.json")).unwrap();
        std::fs::write(
            home.join(".crates.toml"),
            "[v1]\n\"wasm-pack 0.14.0 (registry+https://github.com/rust-lang/crates.io-index)\" = [\"wasm-pack\"]\n",
        )
        .unwrap();
        let config = ToolsConfig::default();
        let shell = ShellPath::default();
        let r = probe(&cx(&paths, &config, &shell, None));
        assert_eq!(r.installs.len(), 1);
        assert_eq!(r.installs[0].name, "wasm-pack");
    }
}
