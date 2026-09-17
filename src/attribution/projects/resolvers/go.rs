//! Go module cache and download cache from `go.sum`, with `!` path escaping.

use std::path::PathBuf;

use super::super::Project;
use crate::attribution::model::{Claim, EntryKind, EvidenceTier, ResolveEnv, BASELINE_OWNER};

/// `env.read_head`'s cap for a `go.sum` — a large module graph can run to a
/// few hundred KiB.
const MAX_GO_SUM_BYTES: usize = 2 * 1024 * 1024;

/// One `go.sum` line's module identity (the `/go.mod` suffix on the version
/// column, present on half of every module's two lines, is stripped so both
/// lines collapse to the same entry).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GoModule {
    path: String,
    version: String,
}

/// Resolve this resource kind's claims for `project`. Stub until its lane
/// lands (see the module doc for which chunk).
pub fn resolve(project: &Project, env: &ResolveEnv<'_>) -> Vec<Claim> {
    let Some(text) = env.read_head(&project.root.join("go.sum"), MAX_GO_SUM_BYTES) else {
        return Vec::new();
    };
    let modules = parse_go_sum(&text);
    if modules.is_empty() {
        return Vec::new();
    }

    let owner = project.root.to_string_lossy().into_owned();
    let mod_cache = go_mod_cache_dir(env);
    let mut claims = Vec::new();
    for module in &modules {
        let escaped = escape_module_path(&module.path);

        let mod_dir = mod_cache.join(format!("{escaped}@{}", module.version));
        if mod_dir.exists() {
            claims.push(
                Claim::new(
                    mod_dir,
                    &owner,
                    EntryKind::PackageCache,
                    EvidenceTier::Exact,
                    "go.sum",
                )
                .label(format!("{} {}", module.path, module.version)),
            );
        }

        let download_dir = mod_cache.join("cache/download").join(&escaped).join("@v");
        for ext in ["zip", "mod", "info"] {
            let f = download_dir.join(format!("{}.{ext}", module.version));
            if f.exists() {
                claims.push(
                    Claim::new(
                        f,
                        &owner,
                        EntryKind::PackageCache,
                        EvidenceTier::Exact,
                        "go.sum",
                    )
                    .label(format!("{} {}", module.path, module.version)),
                );
            }
        }
    }

    claims.into_iter().map(|c| c.ecosystem("go")).collect()
}

/// The shared build cache: every module cache directory the `GOMODCACHE`
/// (or, failing that, `GOPATH`) default points at.
pub fn baseline(env: &ResolveEnv<'_>) -> Vec<Claim> {
    let cache = env.paths.home.join("Library/Caches/go-build");
    if !cache.exists() {
        return Vec::new();
    }
    vec![Claim::new(
        cache,
        BASELINE_OWNER,
        EntryKind::Cache,
        EvidenceTier::EcosystemDefault,
        "Go build cache",
    )
    .label("go-build")
    .baseline("go")]
}

/// `GOMODCACHE`, else `$GOPATH/pkg/mod`, else `~/go/pkg/mod` — Go's own
/// default resolution order for where downloaded modules live.
fn go_mod_cache_dir(env: &ResolveEnv<'_>) -> PathBuf {
    if let Ok(v) = std::env::var("GOMODCACHE") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var("GOPATH") {
        if !v.is_empty() {
            return PathBuf::from(v).join("pkg/mod");
        }
    }
    env.paths.home.join("go/pkg/mod")
}

/// Parse `<module> <version>[/go.mod] <hash>` lines into deduplicated
/// module identities. Pure so it gets a direct test instead of a tempdir
/// fixture.
fn parse_go_sum(text: &str) -> Vec<GoModule> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(module), Some(raw_version)) = (parts.next(), parts.next()) else {
            continue;
        };
        let version = raw_version.strip_suffix("/go.mod").unwrap_or(raw_version);
        if module.is_empty() || version.is_empty() {
            continue;
        }
        let key = GoModule {
            path: module.to_string(),
            version: version.to_string(),
        };
        if seen.insert(key.clone()) {
            out.push(key);
        }
    }
    out
}

/// Go's module-cache path escaping: every uppercase letter becomes `!`
/// followed by its lowercase form (so the case-sensitive module path fits
/// on case-insensitive filesystems without collisions).
fn escape_module_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_path_escaping_matches_gos_own_scheme() {
        assert_eq!(
            escape_module_path("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        assert_eq!(escape_module_path("golang.org/x/text"), "golang.org/x/text");
    }

    #[test]
    fn parse_go_sum_dedupes_the_go_mod_suffixed_line() {
        let text = "\
github.com/BurntSushi/toml v1.2.1 h1:9F2/+DoOYIOksmaJ4dTKZ+g0k
github.com/BurntSushi/toml v1.2.1/go.mod h1:CxXYINrC8qIiEnFrOxCa9jNhW0nEDGGC
golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ARsyilvQ
";
        let modules = parse_go_sum(text);
        assert_eq!(
            modules,
            vec![
                GoModule {
                    path: "github.com/BurntSushi/toml".to_string(),
                    version: "v1.2.1".to_string(),
                },
                GoModule {
                    path: "golang.org/x/text".to_string(),
                    version: "v0.14.0".to_string(),
                },
            ]
        );
    }
}
