//! Launcher inspection: symlink chains, pnpm/npm `cmd-shim` scripts, and
//! ownership hints derived purely from paths (Homebrew Cellar/Caskroom,
//! rustup proxies). No launcher is ever executed.

use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use regex::Regex;

use super::types::{Launcher, LauncherKind, Ownership};

const MAX_HOPS: usize = 40;

/// Lexically normalise `.` and `..` without touching the filesystem, so a
/// dangling target still has a stable absolute form.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve `link`'s target one hop, relative to the link's directory.
pub fn read_link_abs(link: &Path) -> Option<PathBuf> {
    let target = std::fs::read_link(link).ok()?;
    let abs = if target.is_absolute() {
        target
    } else {
        link.parent().unwrap_or(Path::new("/")).join(target)
    };
    Some(normalize(&abs))
}

/// Follow a symlink chain to its end. Returns `(first_target, final_path,
/// final_exists)`; `first_target` is `None` for a non-symlink.
pub fn follow_chain(path: &Path) -> (Option<PathBuf>, PathBuf, bool) {
    let mut cur = path.to_path_buf();
    let mut first: Option<PathBuf> = None;
    for _ in 0..MAX_HOPS {
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => match read_link_abs(&cur) {
                Some(next) => {
                    if first.is_none() {
                        first = Some(next.clone());
                    }
                    cur = next;
                }
                None => return (first, cur, false),
            },
            Ok(_) => return (first, cur, true),
            Err(_) => return (first, cur, false),
        }
    }
    (first, cur, false)
}

pub fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Extract the file a `cmd-shim` style sh script launches. Newer shims end
/// with a `# cmd-shim-target=<path>` trailer; older ones only reference
/// `"$basedir/../global/…/bin/x.js"` in their `exec` lines.
pub fn parse_shim_target(text: &str, shim_dir: &Path) -> Option<PathBuf> {
    for line in text.lines().rev() {
        if let Some(rest) = line.trim().strip_prefix("# cmd-shim-target=") {
            let p = PathBuf::from(rest.trim());
            return Some(if p.is_absolute() {
                normalize(&p)
            } else {
                normalize(&shim_dir.join(p))
            });
        }
    }
    // The launched file is the `$basedir/...` argument that is not the node
    // binary itself: prefer a path under `node_modules/`, else the first
    // `$basedir/` reference that names a file with an extension.
    let re = Regex::new(r#"\$basedir/([^"'\s]+)"#).ok()?;
    let mut fallback = None;
    for cap in re.captures_iter(text) {
        let rel = &cap[1];
        if rel.contains("node_modules/") {
            return Some(normalize(&shim_dir.join(rel)));
        }
        if fallback.is_none()
            && rel
                .rsplit('/')
                .next()
                .map(|f| f.contains('.'))
                .unwrap_or(false)
        {
            fallback = Some(normalize(&shim_dir.join(rel)));
        }
    }
    fallback
}

/// Ownership implied by a resolved path alone.
pub fn owner_from_path(path: &Path) -> Option<Ownership> {
    let s = path.to_string_lossy();
    if let Some(idx) = s.find("/Caskroom/") {
        let rest = &s[idx + "/Caskroom/".len()..];
        let token = rest.split('/').next().unwrap_or("");
        if !token.is_empty() {
            return Some(Ownership::HomebrewCask {
                token: token.to_string(),
            });
        }
    }
    if let Some(idx) = s.find("/Cellar/") {
        let rest = &s[idx + "/Cellar/".len()..];
        let name = rest.split('/').next().unwrap_or("");
        if !name.is_empty() {
            return Some(Ownership::HomebrewFormula {
                name: name.to_string(),
            });
        }
    }
    if path.file_name().and_then(|n| n.to_str()) == Some("rustup") {
        return Some(Ownership::RustupProxy);
    }
    None
}

/// Inspect one launcher path. Ownership starts as whatever the path implies;
/// the orchestrator refines it against the discovered installations.
pub fn inspect(path: &Path) -> Option<Launcher> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        let (first, final_path, exists) = follow_chain(path);
        let owner = owner_from_path(&final_path)
            .or_else(|| first.as_deref().and_then(owner_from_path))
            .unwrap_or(Ownership::Unknown);
        return Some(Launcher {
            path: path.to_path_buf(),
            kind: LauncherKind::Symlink,
            target: first,
            target_exists: Some(exists),
            owner,
        });
    }
    if !meta.is_file() {
        return None;
    }
    // Read only the head: shims are small; a real binary is not text.
    let text = crate::scan::read_head(path, 16 * 1024).unwrap_or_default();
    if text.starts_with("#!") {
        if text.contains("basedir") || text.contains("cmd-shim") {
            let target = parse_shim_target(&text, path.parent().unwrap_or(Path::new("/")));
            let exists = target.as_ref().map(|t| t.exists());
            let owner = target
                .as_deref()
                .and_then(owner_from_path)
                .unwrap_or(Ownership::Unknown);
            return Some(Launcher {
                path: path.to_path_buf(),
                kind: LauncherKind::ShShim,
                target,
                target_exists: exists,
                owner,
            });
        }
        return Some(Launcher {
            path: path.to_path_buf(),
            kind: LauncherKind::Script,
            target: None,
            target_exists: None,
            owner: Ownership::Unknown,
        });
    }
    Some(Launcher {
        path: path.to_path_buf(),
        kind: LauncherKind::RegularBinary,
        target: None,
        target_exists: None,
        owner: Ownership::Unknown,
    })
}

/// Is `path` (or the file it links to) inside `dir`? Lexical after
/// normalisation — a dangling link that *declares* a target inside `dir`
/// still counts, which is what ownership needs.
pub fn under(path: &Path, dir: &Path) -> bool {
    normalize(path).starts_with(normalize(dir))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// The real `~/Library/pnpm/bin/wrangler` shim body (Windows branches
    /// elided), which references its target only via `$basedir`.
    pub(crate) const WRANGLER_SHIM: &str = r#"#!/bin/sh
# Resolve $0 through symlinks so basedir is the shim's real directory.
link="$0"
basedir=$(dirname "$(echo "$link" | sed -e 's,\\,/,g')")
if [ -x "$basedir/node" ]; then
  exec "$basedir/node"  "$basedir/../global/v11/48a1e292ffa7f3001739e6a3b1a5fb0f33b31832c7624173b4da21822328e203/node_modules/wrangler/bin/wrangler.js" "$@"
else
  exec node  "$basedir/../global/v11/48a1e292ffa7f3001739e6a3b1a5fb0f33b31832c7624173b4da21822328e203/node_modules/wrangler/bin/wrangler.js" "$@"
fi
"#;

    #[test]
    fn cmd_shim_trailer_wins_and_regex_falls_back() {
        let dir = Path::new("/home/u/Library/pnpm/bin");
        let with_trailer = format!("{WRANGLER_SHIM}# cmd-shim-target=/abs/target.js\n");
        assert_eq!(
            parse_shim_target(&with_trailer, dir).unwrap(),
            PathBuf::from("/abs/target.js")
        );
        assert_eq!(
            parse_shim_target(WRANGLER_SHIM, dir).unwrap(),
            PathBuf::from("/home/u/Library/pnpm/global/v11/48a1e292ffa7f3001739e6a3b1a5fb0f33b31832c7624173b4da21822328e203/node_modules/wrangler/bin/wrangler.js")
        );
    }

    #[test]
    fn dangling_symlink_detected_with_declared_target() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let link = bin.join("pn");
        symlink("../lib/node_modules/pnpm/pn", &link).unwrap();
        let l = inspect(&link).unwrap();
        assert_eq!(l.kind, LauncherKind::Symlink);
        assert_eq!(l.target_exists, Some(false));
        assert_eq!(
            l.target.unwrap(),
            normalize(&tmp.path().join("lib/node_modules/pnpm/pn"))
        );
    }

    #[test]
    fn cask_and_cellar_owner_parsing() {
        assert_eq!(
            owner_from_path(Path::new("/opt/homebrew/Caskroom/codex/0.153.4/bin/codex")),
            Some(Ownership::HomebrewCask {
                token: "codex".into()
            })
        );
        assert_eq!(
            owner_from_path(Path::new("/opt/homebrew/Cellar/ripgrep/14.1.0/bin/rg")),
            Some(Ownership::HomebrewFormula {
                name: "ripgrep".into()
            })
        );
        assert_eq!(
            owner_from_path(Path::new("/Users/u/.cargo/bin/rustup")),
            Some(Ownership::RustupProxy)
        );
        assert_eq!(owner_from_path(Path::new("/usr/bin/true")), None);
    }

    #[test]
    fn symlink_chain_resolves_relative_hops() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real/bin/tool");
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, "#!/bin/sh\n").unwrap();
        let mid = tmp.path().join("mid");
        symlink("real/bin/tool", &mid).unwrap();
        let link = tmp.path().join("bin/tool");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink("../mid", &link).unwrap();
        let (first, last, exists) = follow_chain(&link);
        assert_eq!(first.unwrap(), normalize(&tmp.path().join("mid")));
        assert_eq!(last, normalize(&real));
        assert!(exists);
        assert!(under(&last, tmp.path()));
        assert!(!under(&last, &tmp.path().join("other")));
    }

    #[test]
    fn shim_script_is_recognised() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("Library/pnpm/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let shim = bin.join("wrangler");
        std::fs::write(&shim, WRANGLER_SHIM).unwrap();
        let l = inspect(&shim).unwrap();
        assert_eq!(l.kind, LauncherKind::ShShim);
        assert_eq!(l.target_exists, Some(false));
        assert!(l
            .target
            .unwrap()
            .ends_with("node_modules/wrangler/bin/wrangler.js"));
    }
}
