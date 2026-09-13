//! Python packaging metadata read straight from disk — `pyvenv.cfg`,
//! `*.dist-info/{METADATA,INSTALLER,RECORD,REQUESTED,entry_points.txt}`.
//! Nothing is imported or executed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use regex::Regex;

use super::launchers;
use super::util::{file_name, list_dir};

/// `key = value` pairs from a `pyvenv.cfg`.
pub fn pyvenv_cfg(venv: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(venv.join("pyvenv.cfg")) {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                out.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    out
}

/// PEP 503 normalisation: lowercase, runs of `-_.` → `-`.
pub fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_sep = false;
    for c in name.trim().chars() {
        if c == '-' || c == '_' || c == '.' {
            if !last_sep {
                out.push('-');
            }
            last_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            last_sep = false;
        }
    }
    out
}

/// One parsed `Requires-Dist` line.
#[derive(Debug, Clone, PartialEq)]
pub struct Requirement {
    pub name: String,
    /// `extra == "…"` markers mean optional; other markers are kept verbatim
    /// because they are not evaluated here.
    pub extra_only: bool,
    pub marker: Option<String>,
}

pub fn parse_requires_dist(line: &str) -> Option<Requirement> {
    let re = Regex::new(
        r#"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;]*?)\s*(?:;\s*(.*))?$"#,
    )
    .ok()?;
    let cap = re.captures(line)?;
    let marker = cap
        .get(4)
        .map(|m| m.as_str().trim().to_string())
        .filter(|m| !m.is_empty());
    let extra_only = marker
        .as_deref()
        .map(|m| m.contains("extra ==") || m.contains("extra=="))
        .unwrap_or(false);
    Some(Requirement {
        name: normalize_name(&cap[1]),
        extra_only,
        marker,
    })
}

#[derive(Debug, Clone, Default)]
pub struct DistInfo {
    pub dir: PathBuf,
    pub name: String,
    pub normalized: String,
    pub version: Option<String>,
    /// Contents of `INSTALLER` (e.g. `pip`, `brew`, `uv`), trimmed.
    pub installer: Option<String>,
    pub requested: bool,
    pub requires: Vec<Requirement>,
    /// `console_scripts` entry point names.
    pub console_scripts: Vec<String>,
    /// Files this package owns, relative to site-packages (from RECORD).
    pub record_paths: Vec<String>,
    /// Sum of RECORD sizes, when recorded.
    pub record_bytes: Option<u64>,
    /// Where the metadata files really live if they are symlinks (Homebrew
    /// links site-packages into the Cellar).
    pub link_target: Option<PathBuf>,
}

fn read_trimmed(p: &Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn read_dist_info(dir: &Path) -> Option<DistInfo> {
    let dname = file_name(dir);
    let stem = dname.strip_suffix(".dist-info")?;
    let (name_from_dir, version_from_dir) = match stem.split_once('-') {
        Some((n, v)) => (n.to_string(), Some(v.to_string())),
        None => (stem.to_string(), None),
    };
    let mut info = DistInfo {
        dir: dir.to_path_buf(),
        name: name_from_dir.clone(),
        normalized: normalize_name(&name_from_dir),
        version: version_from_dir,
        installer: read_trimmed(&dir.join("INSTALLER")),
        requested: dir.join("REQUESTED").exists(),
        ..Default::default()
    };
    if let Ok(text) = std::fs::read_to_string(dir.join("METADATA")) {
        for line in text.lines() {
            if line.is_empty() {
                break; // headers end at the first blank line
            }
            if let Some(v) = line.strip_prefix("Name:") {
                info.name = v.trim().to_string();
                info.normalized = normalize_name(v);
            } else if let Some(v) = line.strip_prefix("Version:") {
                info.version = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Requires-Dist:") {
                if let Some(r) = parse_requires_dist(v) {
                    info.requires.push(r);
                }
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(dir.join("entry_points.txt")) {
        let mut in_console = false;
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with('[') {
                in_console = l == "[console_scripts]";
                continue;
            }
            if in_console {
                if let Some((k, _)) = l.split_once('=') {
                    let k = k.trim();
                    if !k.is_empty() {
                        info.console_scripts.push(k.to_string());
                    }
                }
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(dir.join("RECORD")) {
        let mut total = 0u64;
        let mut any_size = false;
        for line in text.lines() {
            let mut parts = line.split(',');
            let Some(path) = parts.next() else { continue };
            if path.is_empty() {
                continue;
            }
            info.record_paths.push(path.to_string());
            let _hash = parts.next();
            if let Some(sz) = parts.next().and_then(|s| s.trim().parse::<u64>().ok()) {
                total += sz;
                any_size = true;
            }
        }
        info.record_bytes = any_size.then_some(total);
    }
    // Symlinked metadata: the dir itself, or its INSTALLER/METADATA file.
    for probe in [
        dir.to_path_buf(),
        dir.join("INSTALLER"),
        dir.join("METADATA"),
    ] {
        if let Ok(m) = std::fs::symlink_metadata(&probe) {
            if m.file_type().is_symlink() {
                let (_, last, _) = launchers::follow_chain(&probe);
                info.link_target = Some(last);
                break;
            }
        }
    }
    Some(info)
}

/// All `*.dist-info` directories in a site-packages dir.
pub fn site_dist_infos(site: &Path) -> Vec<DistInfo> {
    list_dir(site)
        .into_iter()
        .filter(|p| file_name(p).ends_with(".dist-info"))
        .filter_map(|p| read_dist_info(&p))
        .collect()
}

/// The single `<name>-<ver>.dist-info` version for a package inside a venv's
/// site-packages (`lib/python3.X/site-packages`).
pub fn venv_package_version(venv: &Path, package: &str) -> Option<String> {
    let want = normalize_name(package);
    for lib in list_dir(&venv.join("lib")) {
        let site = lib.join("site-packages");
        for di in site_dist_infos(&site) {
            if di.normalized == want {
                return di.version;
            }
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn requires_dist_parsing_splits_extras_and_markers() {
        let r = parse_requires_dist("charset_normalizer (<4,>=2)").unwrap();
        assert_eq!(r.name, "charset-normalizer");
        assert!(!r.extra_only);
        assert!(r.marker.is_none());
        let r = parse_requires_dist("PySocks!=1.5.7,>=1.5.6; extra == \"socks\"").unwrap();
        assert_eq!(r.name, "pysocks");
        assert!(r.extra_only);
        let r = parse_requires_dist("typing-extensions>=4; python_version < \"3.8\"").unwrap();
        assert!(!r.extra_only);
        assert_eq!(r.marker.as_deref(), Some("python_version < \"3.8\""));
        assert_eq!(normalize_name("Typing_Extensions"), "typing-extensions");
    }

    /// Write a dist-info dir. `installer` = INSTALLER contents; `cellar` =
    /// link the METADATA/INSTALLER files into that Cellar dir like Homebrew.
    pub(crate) fn mk_dist_info(
        site: &Path,
        name: &str,
        version: &str,
        installer: &str,
        requires: &[&str],
        scripts: &[&str],
        cellar: Option<&Path>,
    ) -> PathBuf {
        let dir = site.join(format!("{name}-{version}.dist-info"));
        std::fs::create_dir_all(&dir).unwrap();
        let mut meta = format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n");
        for r in requires {
            meta.push_str(&format!("Requires-Dist: {r}\n"));
        }
        meta.push_str("\nBody\n");
        let mut ep = String::new();
        if !scripts.is_empty() {
            ep.push_str("[console_scripts]\n");
            for s in scripts {
                ep.push_str(&format!("{s} = {name}:main\n"));
            }
        }
        let mut record =
            format!("{name}/__init__.py,sha256=abc,100\n{name}-{version}.dist-info/METADATA,,\n");
        for s in scripts {
            record.push_str(&format!("../../../bin/{s},sha256=x,50\n"));
        }
        match cellar {
            Some(cellar) => {
                let real = cellar.join(format!("{name}-{version}.dist-info"));
                std::fs::create_dir_all(&real).unwrap();
                std::fs::write(real.join("METADATA"), &meta).unwrap();
                std::fs::write(real.join("INSTALLER"), installer).unwrap();
                std::fs::write(real.join("RECORD"), &record).unwrap();
                std::fs::write(real.join("entry_points.txt"), &ep).unwrap();
                for f in ["METADATA", "INSTALLER", "RECORD", "entry_points.txt"] {
                    std::os::unix::fs::symlink(real.join(f), dir.join(f)).unwrap();
                }
            }
            None => {
                std::fs::write(dir.join("METADATA"), &meta).unwrap();
                std::fs::write(dir.join("INSTALLER"), installer).unwrap();
                std::fs::write(dir.join("RECORD"), &record).unwrap();
                std::fs::write(dir.join("entry_points.txt"), &ep).unwrap();
                std::fs::write(dir.join("REQUESTED"), "").unwrap();
            }
        }
        dir
    }

    #[test]
    fn dist_info_reads_metadata_record_and_link_target() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        let cellar = tmp
            .path()
            .join("Cellar/certifi/2026.7.22/lib/python3.14/site-packages");
        mk_dist_info(
            &site,
            "requests",
            "2.32.5",
            "pip",
            &["charset_normalizer (<4,>=2)", "PySocks; extra == \"socks\""],
            &[],
            None,
        );
        mk_dist_info(
            &site,
            "certifi",
            "2026.7.22",
            "brew",
            &[],
            &[],
            Some(&cellar),
        );
        let infos = site_dist_infos(&site);
        let req = infos.iter().find(|d| d.normalized == "requests").unwrap();
        assert_eq!(req.version.as_deref(), Some("2.32.5"));
        assert_eq!(req.installer.as_deref(), Some("pip"));
        assert!(req.requested);
        assert_eq!(req.requires.len(), 2);
        assert_eq!(req.record_bytes, Some(100));
        assert!(req.link_target.is_none());
        let cert = infos.iter().find(|d| d.normalized == "certifi").unwrap();
        assert_eq!(cert.installer.as_deref(), Some("brew"));
        assert!(cert
            .link_target
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("/Cellar/certifi/"));
        assert!(!cert.requested);
    }
}
