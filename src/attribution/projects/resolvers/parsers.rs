//! Pure parsers: `fn(&str) -> Vec<Key>` / `fn(&str) -> Option<String>`, with
//! no filesystem access, shared by `rules.rs`'s row definitions. Moved from
//! the 15 per-ecosystem files; tests moved with them.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::rules::Key;

// ---------------------------------------------------------------------
// Generic key=value / TOML-ish line parsing
// ---------------------------------------------------------------------

/// A `key = "value"`, `key = value`, or `key value` line's value, if `line`
/// starts with `key`. Generalises the strict-TOML `"key" = "quoted"` shape
/// (`Cargo.lock`, `rust-toolchain.toml`, `~/.rustup/settings.toml`) to also
/// cover mise's bare `node = "20"` and asdf/mise's `.tool-versions`
/// space-separated `nodejs 20.11.1` — one scanner for every "key, then a
/// separator, then a possibly-quoted value" shape this crate parses.
pub fn key_value_field(line: &str, key: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix(key)?;
    // The key must end here: `nodefoo` is not the key `node`.
    if !rest.starts_with(|c: char| c.is_whitespace() || c == '=') {
        return None;
    }
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    for quote in ['"', '\''] {
        if let Some(inner) = rest.strip_prefix(quote) {
            return inner.split_once(quote).map(|(value, _)| value.to_string());
        }
    }
    rest.split_whitespace().next().map(str::to_string)
}

/// The first non-empty, non-comment, non-section-header line of `text` — the
/// legacy bare-text form both `.nvmrc`-style single-value files and
/// `rust-toolchain` (no `.toml`) use.
pub fn first_bare_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
        .map(str::to_string)
}

/// Pass-through normaliser for pins that are used verbatim (rust channels).
pub fn identity(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// The winning candidate name for `Select::MaxSemver`: an exact match for
/// `pin` if present (rust's channel-only install, e.g. `stable`), else the
/// candidate with the highest semantic version among those that extend
/// `pin` at a `.`/`-` component boundary (`v24` matches `v24.15.0` but not
/// `v240.1.0`; `stable` matches `stable-aarch64-apple-darwin`). A candidate
/// that isn't semver-parseable once a leading `v` is stripped (a rust
/// host-triple suffix has no version component at all) loses to any
/// parseable one and otherwise falls back to a lexicographic comparison —
/// stable in the common case of one toolchain per channel.
pub fn newest_matching_version(pin: &str, candidates: &[String]) -> Option<String> {
    if candidates.iter().any(|c| c == pin) {
        return Some(pin.to_string());
    }
    let mut best: Option<(Option<semver::Version>, String)> = None;
    for candidate in candidates {
        let Some(rest) = candidate.strip_prefix(pin) else {
            continue;
        };
        if !(rest.is_empty() || rest.starts_with('.') || rest.starts_with('-')) {
            continue;
        }
        let stripped = candidate.strip_prefix('v').unwrap_or(candidate);
        let version = semver::Version::parse(stripped).ok();
        let better = match (&best, &version) {
            (None, _) => true,
            (Some((None, _)), Some(_)) => true,
            (Some((Some(b), _)), Some(v)) => v > b,
            (Some((Some(_), _)), None) => false,
            (Some((None, prev)), None) => candidate.as_str() > prev.as_str(),
        };
        if better {
            best = Some((version, candidate.clone()));
        }
    }
    best.map(|(_, name)| name)
}

// ---------------------------------------------------------------------
// node
// ---------------------------------------------------------------------

/// Normalise a version pin (`v24`, `24.1`, `20.11.1`) to `vMAJOR[.MINOR[.PATCH]]`.
/// `None` for anything that isn't a numeric version at all (`lts/*`,
/// `lts/iron`, `system`, `*`).
pub fn normalise_node_pin(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('.');
    let major = parts.next()?;
    if major.is_empty() || !major.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut out = format!("v{major}");
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            break;
        }
        out.push('.');
        out.push_str(part);
    }
    Some(out)
}

/// One `package-lock.json` package reference.
pub struct PackageRef {
    pub name: String,
    pub version: String,
}

/// `package-lock.json`'s `"node_modules/<name>": { "version": "x" }`
/// entries (lockfile v2/v3 shape).
pub fn package_lock(text: &str) -> Vec<PackageRef> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let Some(packages) = json.get("packages").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, val) in packages {
        let Some(after_prefix) = key.strip_prefix("node_modules/") else {
            continue;
        };
        // A nested dependency's key looks like
        // `node_modules/foo/node_modules/bar` — the package's own name is
        // whatever follows the *last* `node_modules/` segment.
        let name = after_prefix
            .rsplit("node_modules/")
            .next()
            .unwrap_or(after_prefix);
        let Some(version) = val.get("version").and_then(Value::as_str) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.push(PackageRef {
            name: name.to_string(),
            version: version.to_string(),
        });
    }
    out
}

/// `yarn.lock`'s `resolution: "<name>@npm:<version>"` lines — the most
/// reliable single line per entry (the header key line can list several
/// version ranges for one resolved package).
pub fn yarn_berry(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("resolution:") else {
            continue;
        };
        let spec = rest.trim().trim_matches('"');
        if let Some(parsed) = parse_npm_spec(spec) {
            out.push(parsed);
        }
    }
    out
}

/// `<name>@npm:<version>` → `(name, version)` — `None` for anything that
/// isn't a plain npm-registry resolution (patches, workspaces, git deps).
fn parse_npm_spec(spec: &str) -> Option<(String, String)> {
    let (name, version) = spec.split_once("@npm:")?;
    if name.is_empty() || version.is_empty() || version.contains('#') {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// `bun.lock`'s `"packages"` object: `{ "<name>": ["<name>@<version>", ...]
/// }`. `bun.lock` is JSONC (comments, trailing commas allowed) — a strict
/// parse is tried first since most files have neither, falling back to a
/// best-effort comment strip.
pub fn bun_lock(text: &str) -> Vec<(String, String)> {
    let json = serde_json::from_str::<Value>(text)
        .or_else(|_| serde_json::from_str::<Value>(&strip_line_comments(text)));
    let Ok(json) = json else {
        return Vec::new();
    };
    let Some(packages) = json.get("packages").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for val in packages.values() {
        let Some(spec) = val
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
        else {
            continue;
        };
        // The scoped-name case (`@scope/name@1.2.3`) needs the *last* `@`,
        // unlike npm's `@npm:` marker.
        if let Some((name, version)) = spec.rsplit_once('@') {
            if !name.is_empty() && !version.is_empty() {
                out.push((name.to_string(), version.to_string()));
            }
        }
    }
    out
}

/// Drop whole-line `//` comments (JSONC's other allowances — trailing
/// commas, block comments — aren't attempted; a file that needs them just
/// yields no claims, which is safe).
pub fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// An npm `integrity` field (`sha512-<base64>`) → the `content-v2` blob's
/// sharded path components (`sha512/<xx>/<yy>/<rest>`), npm's own on-disk
/// layout for cacache. `None` for anything not in that form.
pub fn npm_integrity_to_shard(integrity: &str) -> Option<(String, String, String)> {
    let b64 = integrity.strip_prefix("sha512-")?;
    let bytes = decode_base64(b64)?;
    let hex = hex_encode(&bytes);
    if hex.len() < 4 {
        return None;
    }
    Some((
        hex[0..2].to_string(),
        hex[2..4].to_string(),
        hex[4..].to_string(),
    ))
}

/// Standard-alphabet base64 decode — no `base64` dependency in this crate.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()) {
        let v = lut[b as usize];
        if v == 255 {
            return None;
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------
// rust / cargo
// ---------------------------------------------------------------------

struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
}

fn parse_cargo_lock(text: &str) -> Vec<LockPackage> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut source: Option<String> = None;
    let mut in_block = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                out.push(LockPackage {
                    name: n,
                    version: v,
                    source: source.take(),
                });
            }
            source = None;
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some(v) = key_value_field(trimmed, "name") {
            name = Some(v);
        } else if let Some(v) = key_value_field(trimmed, "version") {
            version = Some(v);
        } else if let Some(v) = key_value_field(trimmed, "source") {
            source = Some(v);
        }
    }
    if let (Some(n), Some(v)) = (name, version) {
        out.push(LockPackage {
            name: n,
            version: v,
            source,
        });
    }
    out
}

/// `Cargo.lock` packages with a real (non-git) `source` — registry crates.
pub fn cargo_lock_registry(text: &str) -> Vec<Key> {
    parse_cargo_lock(text)
        .into_iter()
        .filter(|p| matches!(&p.source, Some(s) if !s.is_empty() && !s.starts_with("git+")))
        .map(|p| Key {
            name: p.name,
            version: p.version,
            extra: None,
        })
        .collect()
}

/// `Cargo.lock` packages with a `git+` source — `extra` carries the
/// repository basename `~/.cargo/git/{checkouts,db}/<basename>-*` are keyed
/// on.
pub fn cargo_lock_git(text: &str) -> Vec<Key> {
    parse_cargo_lock(text)
        .into_iter()
        .filter_map(|p| {
            let src = p.source.as_deref()?;
            let basename = git_repo_basename(src.strip_prefix("git+")?)?;
            Some(Key {
                name: p.name,
                version: p.version,
                extra: Some(basename),
            })
        })
        .collect()
}

/// `<url>[?query]#<rev>` (already past the `git+` prefix) → the repository's
/// basename (`.git` suffix stripped).
fn git_repo_basename(rest: &str) -> Option<String> {
    let rest = rest.split('#').next()?;
    let rest = rest.split('?').next()?;
    let name = rest.rsplit('/').next()?;
    let name = name.strip_suffix(".git").unwrap_or(name);
    (!name.is_empty()).then(|| name.to_string())
}

/// `~/.rustup/settings.toml`'s `default_toolchain` value.
pub fn default_toolchain(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| key_value_field(line.trim(), "default_toolchain"))
}

/// Every `CARGO_TARGET_DIR=<value>` occurrence in `text` (any quoting, or
/// none).
pub fn extract_cargo_target_dir(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(idx) = rest.find("CARGO_TARGET_DIR=") {
        let after = &rest[idx + "CARGO_TARGET_DIR=".len()..];
        let value_end = after
            .find(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '|')
            .unwrap_or(after.len());
        let raw = &after[..value_end];
        let raw = raw.trim_matches('"').trim_matches('\'');
        if !raw.is_empty() {
            out.push(unwrap_shell_default(raw).to_string());
        }
        rest = &after[value_end..];
    }
    out
}

/// `${CARGO_TARGET_DIR:-<default>}` (the "respect an override, else use
/// this" idiom) → `<default>`; anything else passes through unchanged.
fn unwrap_shell_default(value: &str) -> &str {
    value
        .strip_prefix("${")
        .and_then(|v| v.strip_suffix('}'))
        .and_then(|v| v.split_once(":-"))
        .map(|(_, default)| default)
        .unwrap_or(value)
}

/// `package.json`'s `scripts` object's string values only — `scripts` is
/// where a redirected `CARGO_TARGET_DIR` realistically shows up.
pub fn cargo_target_dirs_in_package_json_scripts(text: &str) -> Vec<String> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let Some(scripts) = json.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    scripts
        .values()
        .filter_map(Value::as_str)
        .flat_map(extract_cargo_target_dir)
        .collect()
}

/// `.cargo/config.toml`'s `[build] target-dir`.
pub fn cargo_config_target_dir(text: &str) -> Option<String> {
    let table = toml::from_str::<toml::Table>(text).ok()?;
    table
        .get("build")?
        .get("target-dir")?
        .as_str()
        .map(str::to_string)
}

/// `$HOME`/`${HOME}`/`~` expansion, then relative-to-`project_root`
/// resolution.
pub fn expand_target_dir(value: &str, home: &Path, project_root: &Path) -> PathBuf {
    let home_str = home.to_string_lossy();
    let expanded = if let Some(rest) = value.strip_prefix("${HOME}") {
        format!("{home_str}{rest}")
    } else if let Some(rest) = value.strip_prefix("$HOME") {
        format!("{home_str}{rest}")
    } else if let Some(rest) = value.strip_prefix('~') {
        format!("{home_str}{rest}")
    } else {
        value.to_string()
    };
    let path = PathBuf::from(expanded);
    if path.is_absolute() {
        path
    } else {
        project_root.join(path)
    }
}

// ---------------------------------------------------------------------
// go
// ---------------------------------------------------------------------

/// Parse `<module> <version>[/go.mod] <hash>` lines into deduplicated
/// module identities.
pub fn go_sum(text: &str) -> Vec<Key> {
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
        let key = (module.to_string(), version.to_string());
        if seen.insert(key.clone()) {
            out.push(Key {
                name: key.0,
                version: key.1,
                extra: None,
            });
        }
    }
    out
}

/// Go's module-cache path escaping: every uppercase letter becomes `!`
/// followed by its lowercase form (so the case-sensitive module path fits
/// on case-insensitive filesystems without collisions).
pub fn escape_module_path(path: &str) -> String {
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

/// `GOMODCACHE`, else `$GOPATH/pkg/mod`, else `~/go/pkg/mod` — Go's own
/// default resolution order for where downloaded modules live.
pub fn go_module_cache_dir(home: &Path) -> PathBuf {
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
    home.join("go/pkg/mod")
}

// ---------------------------------------------------------------------
// swift
// ---------------------------------------------------------------------

/// One resolved dependency's identity + source location.
pub struct ResolvedPin {
    pub identity: String,
    pub location: String,
}

/// `Package.resolved` v1 (`{"object":{"pins":[{"package","repositoryURL"}]}}`)
/// and v2/v3 (`{"pins":[{"identity","location"}]}`).
pub fn package_resolved(text: &str) -> Vec<ResolvedPin> {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let version = json.get("version").and_then(Value::as_i64).unwrap_or(2);
    let pins = if version <= 1 {
        json.get("object").and_then(|o| o.get("pins"))
    } else {
        json.get("pins")
    };
    let Some(pins) = pins.and_then(Value::as_array) else {
        return Vec::new();
    };

    pins.iter()
        .filter_map(|p| {
            if version <= 1 {
                let identity = p.get("package").and_then(Value::as_str)?.to_string();
                let location = p.get("repositoryURL").and_then(Value::as_str)?.to_string();
                Some(ResolvedPin { identity, location })
            } else {
                let identity = p.get("identity").and_then(Value::as_str)?.to_string();
                let location = p.get("location").and_then(Value::as_str)?.to_string();
                Some(ResolvedPin { identity, location })
            }
        })
        .collect()
}

/// The repo name SwiftPM keys its cache directory by: the URL's last path
/// component with a trailing `.git`/`/` stripped.
pub fn swiftpm_repo_basename(url: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/').trim_end_matches(".git");
    trimmed
        .rsplit(['/', ':'])
        .next()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------
// brew
// ---------------------------------------------------------------------

pub enum BrewEntryKind {
    Formula,
    Cask,
}

/// `brew "name"` / `cask "name"` lines — `tap`/`mas`/anything else ignored.
pub fn brewfile(text: &str) -> Vec<(BrewEntryKind, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = brewfile_directive(line, "brew") {
            out.push((BrewEntryKind::Formula, name));
        } else if let Some(name) = brewfile_directive(line, "cask") {
            out.push((BrewEntryKind::Cask, name));
        }
    }
    out
}

/// `<keyword> "name"` / `<keyword> 'name'`, with a required word boundary
/// after the keyword so `brewsomething` doesn't match `brew`.
fn brewfile_directive(line: &str, keyword: &str) -> Option<String> {
    let rest = line.strip_prefix(keyword)?;
    let rest = rest.strip_prefix(' ')?;
    let rest = rest.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let after = &rest[quote.len_utf8()..];
    let end = after.find(quote)?;
    Some(after[..end].to_string())
}

// ---------------------------------------------------------------------
// agents (claude / codex)
// ---------------------------------------------------------------------

/// The first `"cwd":"…"` value anywhere in `text`, with minimal JSON
/// unescaping (`\/` and `\\`) — not a full JSON parser, since a session
/// head is read as raw bytes precisely to avoid parsing the whole record.
pub fn extract_cwd(text: &str) -> Option<String> {
    let idx = text.find("\"cwd\":\"")?;
    let rest = &text[idx + 7..];
    let end = find_unescaped_quote(rest)?;
    Some(unescape_json_minimal(&rest[..end]))
}

fn find_unescaped_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn unescape_json_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek().copied() {
                Some('/') => {
                    out.push('/');
                    chars.next();
                }
                Some('\\') => {
                    out.push('\\');
                    chars.next();
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                    chars.next();
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The Claude Code convention for a project's session directory name: every
/// `/` and `.` in the absolute path becomes `-`.
pub fn encode_claude_project_dir(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_value_field_handles_quoted_and_bare_forms() {
        assert_eq!(
            key_value_field(r#"name = "serde""#, "name"),
            Some("serde".to_string())
        );
        assert_eq!(
            key_value_field("nodejs 20.11.1", "nodejs"),
            Some("20.11.1".to_string())
        );
        assert_eq!(key_value_field("nodefoo 1", "node"), None);
    }

    #[test]
    fn newest_matching_version_picks_the_newest_within_the_pin() {
        let candidates = vec![
            "v24.2.0".to_string(),
            "v24.15.0".to_string(),
            "v20.1.0".to_string(),
            "v240.1.0".to_string(),
        ];
        assert_eq!(
            newest_matching_version("v24", &candidates),
            Some("v24.15.0".to_string())
        );
    }

    #[test]
    fn newest_matching_version_prefers_an_exact_match() {
        let candidates = vec![
            "stable-aarch64-apple-darwin".to_string(),
            "stable".to_string(),
        ];
        assert_eq!(
            newest_matching_version("stable", &candidates),
            Some("stable".to_string())
        );
    }

    #[test]
    fn newest_matching_version_falls_back_to_the_only_host_triple_match() {
        let candidates = vec!["stable-aarch64-apple-darwin".to_string()];
        assert_eq!(
            newest_matching_version("stable", &candidates),
            Some("stable-aarch64-apple-darwin".to_string())
        );
    }

    #[test]
    fn parses_package_lock_v3_packages_entries() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.21" },
                "node_modules/@scope/thing": { "version": "2.0.0" },
                "node_modules/foo/node_modules/lodash": { "version": "4.17.20" }
            }
        }"#;
        let mut got: Vec<(String, String)> = package_lock(text)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("@scope/thing".to_string(), "2.0.0".to_string()),
                ("lodash".to_string(), "4.17.20".to_string()),
                ("lodash".to_string(), "4.17.21".to_string()),
            ]
        );
    }

    #[test]
    fn parses_yarn_berry_resolution_lines() {
        let text = r#"
"lodash@npm:^4.17.21, lodash@npm:^4.17.4":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/abcd
  languageName: node
  linkType: hard

"@babel/core@npm:^7.20.0":
  version: 7.20.0
  resolution: "@babel/core@npm:7.20.0"
  languageName: node
  linkType: hard

"local-pkg@workspace:packages/local-pkg":
  version: 0.0.0-use.local
  resolution: "local-pkg@workspace:packages/local-pkg"
  languageName: unknown
  linkType: soft
"#;
        let mut got = yarn_berry(text);
        got.sort();
        assert_eq!(
            got,
            vec![
                ("@babel/core".to_string(), "7.20.0".to_string()),
                ("lodash".to_string(), "4.17.21".to_string()),
            ]
        );
    }

    #[test]
    fn normalise_node_pin_handles_major_only_and_dotted_forms() {
        assert_eq!(normalise_node_pin("v24"), Some("v24".to_string()));
        assert_eq!(normalise_node_pin("24.1"), Some("v24.1".to_string()));
        assert_eq!(normalise_node_pin("20.11.1"), Some("v20.11.1".to_string()));
    }

    #[test]
    fn normalise_node_pin_rejects_non_numeric_refs() {
        assert_eq!(normalise_node_pin("lts/*"), None);
        assert_eq!(normalise_node_pin("lts/iron"), None);
        assert_eq!(normalise_node_pin("system"), None);
        assert_eq!(normalise_node_pin(""), None);
    }

    #[test]
    fn base64_round_trips_a_known_npm_integrity_value() {
        // "hi" -> base64 "aGk=" -> bytes [0x68, 0x69].
        assert_eq!(decode_base64("aGk="), Some(vec![0x68, 0x69]));
        assert_eq!(hex_encode(&[0x68, 0x69]), "6869");
    }

    #[test]
    fn npm_integrity_to_shard_splits_the_hex_digest() {
        let (a, b, rest) = npm_integrity_to_shard("sha512-aGk=").unwrap();
        assert_eq!(format!("{a}{b}{rest}"), "6869");
    }

    #[test]
    fn parses_a_lockfile_with_a_registry_and_a_git_source() {
        let text = r#"
# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "cubby-core"
version = "0.1.0"
source = "git+https://github.com/nickysemenza/cubby-core.git?branch=main#deadbeef"

[[package]]
name = "cubby-ffi"
version = "0.1.0"
"#;
        let registry = cargo_lock_registry(text);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry[0].name, "serde");
        assert_eq!(registry[0].version, "1.0.210");

        let git = cargo_lock_git(text);
        assert_eq!(git.len(), 1);
        assert_eq!(git[0].name, "cubby-core");
        assert_eq!(git[0].extra.as_deref(), Some("cubby-core"));
    }

    #[test]
    fn channel_toml_form_is_a_key_value_field() {
        // `rust-toolchain.toml`'s form — the same generic scanner
        // `PinSource::TomlKey` uses for every `key = "value"` file.
        let text = "[toolchain]\nchannel = \"1.75.0\"\ncomponents = [\"rustfmt\"]\n";
        let channel = text
            .lines()
            .find_map(|l| key_value_field(l.trim(), "channel"));
        assert_eq!(channel, Some("1.75.0".to_string()));
    }

    #[test]
    fn channel_legacy_bare_form_is_the_first_bare_line() {
        // The legacy plain-text `rust-toolchain` (no `.toml`) form —
        // `PinSource::Line`'s fallback when `TomlKey` finds no `channel =`.
        let text = "stable-x86_64-apple-darwin\n";
        assert_eq!(
            first_bare_line(text),
            Some("stable-x86_64-apple-darwin".to_string())
        );
    }

    #[test]
    fn default_toolchain_parses_from_settings_toml() {
        let text = "default_host_triple = \"aarch64-apple-darwin\"\ndefault_toolchain = \"stable-aarch64-apple-darwin\"\nversion = \"12\"\n";
        assert_eq!(
            default_toolchain(text),
            Some("stable-aarch64-apple-darwin".to_string())
        );
    }

    #[test]
    fn extracts_cargo_target_dir_from_a_package_json_script_string() {
        let script = "CARGO_TARGET_DIR=$HOME/.cache/cubby/recipebridge-target wasm-pack build";
        assert_eq!(
            extract_cargo_target_dir(script),
            vec!["$HOME/.cache/cubby/recipebridge-target".to_string()]
        );
    }

    #[test]
    fn unwraps_the_shell_default_expansion_idiom() {
        let script = r#"CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/cubby/recipebridge-target}" wasm-pack build"#;
        assert_eq!(
            extract_cargo_target_dir(script),
            vec!["$HOME/.cache/cubby/recipebridge-target".to_string()]
        );
    }

    #[test]
    fn extracts_from_a_full_package_json_scripts_block() {
        let text = r#"{
            "name": "recipebridge",
            "scripts": {
                "wasm": "CARGO_TARGET_DIR=$HOME/.cache/cubby/recipebridge-target wasm-pack build",
                "build": "tsc"
            }
        }"#;
        assert_eq!(
            cargo_target_dirs_in_package_json_scripts(text),
            vec!["$HOME/.cache/cubby/recipebridge-target".to_string()]
        );
    }

    #[test]
    fn expands_home_variants_and_tilde() {
        let home = Path::new("/Users/nicky");
        let root = Path::new("/Users/nicky/dev/recipebridge");
        assert_eq!(
            expand_target_dir("$HOME/.cache/x", home, root),
            PathBuf::from("/Users/nicky/.cache/x")
        );
        assert_eq!(
            expand_target_dir("${HOME}/.cache/x", home, root),
            PathBuf::from("/Users/nicky/.cache/x")
        );
        assert_eq!(
            expand_target_dir("~/.cache/x", home, root),
            PathBuf::from("/Users/nicky/.cache/x")
        );
    }

    #[test]
    fn relative_target_dir_resolves_against_the_project_root() {
        let home = Path::new("/Users/nicky");
        let root = Path::new("/Users/nicky/dev/recipebridge");
        assert_eq!(
            expand_target_dir("build/target", home, root),
            PathBuf::from("/Users/nicky/dev/recipebridge/build/target")
        );
    }

    #[test]
    fn extracts_a_quoted_occurrence_too() {
        let text = r#"export CARGO_TARGET_DIR="/tmp/target" && cargo build"#;
        assert_eq!(
            extract_cargo_target_dir(text),
            vec!["/tmp/target".to_string()]
        );
    }

    #[test]
    fn module_path_escaping_matches_gos_own_scheme() {
        assert_eq!(
            escape_module_path("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
        assert_eq!(escape_module_path("golang.org/x/text"), "golang.org/x/text");
    }

    #[test]
    fn go_sum_dedupes_the_go_mod_suffixed_line() {
        let text = "\
github.com/BurntSushi/toml v1.2.1 h1:9F2/+DoOYIOksmaJ4dTKZ+g0k
github.com/BurntSushi/toml v1.2.1/go.mod h1:CxXYINrC8qIiEnFrOxCa9jNhW0nEDGGC
golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ARsyilvQ
";
        let modules = go_sum(text);
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "github.com/BurntSushi/toml");
        assert_eq!(modules[0].version, "v1.2.1");
        assert_eq!(modules[1].name, "golang.org/x/text");
    }

    #[test]
    fn parses_v2_pins() {
        let text = r#"{
            "version": 2,
            "pins": [
                { "identity": "swift-algorithms", "kind": "remoteSourceControl",
                  "location": "https://github.com/apple/swift-algorithms.git",
                  "state": { "revision": "abc", "version": "1.2.0" } }
            ]
        }"#;
        let pins = package_resolved(text);
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].identity, "swift-algorithms");
        assert_eq!(
            pins[0].location,
            "https://github.com/apple/swift-algorithms.git"
        );
    }

    #[test]
    fn parses_v1_pins() {
        let text = r#"{
            "object": {
                "pins": [
                    { "package": "swift-algorithms",
                      "repositoryURL": "https://github.com/apple/swift-algorithms.git",
                      "state": { "branch": null, "revision": "abc", "version": "1.2.0" } }
                ]
            },
            "version": 1
        }"#;
        let pins = package_resolved(text);
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].identity, "swift-algorithms");
    }

    #[test]
    fn swiftpm_repo_basename_strips_dot_git_and_trailing_slash() {
        assert_eq!(
            swiftpm_repo_basename("https://github.com/apple/swift-algorithms.git"),
            Some("swift-algorithms".to_string())
        );
        assert_eq!(
            swiftpm_repo_basename("https://github.com/apple/swift-algorithms/"),
            Some("swift-algorithms".to_string())
        );
    }

    #[test]
    fn swiftpm_repo_basename_handles_scp_style_urls() {
        assert_eq!(
            swiftpm_repo_basename("git@github.com:apple/swift-algorithms.git"),
            Some("swift-algorithms".to_string())
        );
    }

    #[test]
    fn parses_brew_and_cask_directives_and_ignores_others() {
        let text = "tap \"homebrew/cask\"\nbrew \"ripgrep\"\ncask 'visual-studio-code'\nmas \"Xcode\", id: 497799835\n";
        let entries: Vec<(bool, String)> = brewfile(text)
            .into_iter()
            .map(|(kind, name)| (matches!(kind, BrewEntryKind::Formula), name))
            .collect();
        assert_eq!(
            entries,
            vec![
                (true, "ripgrep".to_string()),
                (false, "visual-studio-code".to_string()),
            ]
        );
    }

    #[test]
    fn does_not_confuse_brewfoo_with_brew() {
        assert!(brewfile_directive("brewfoo \"x\"", "brew").is_none());
    }

    #[test]
    fn extract_cwd_finds_the_field_anywhere_in_the_head() {
        let text = r#"{"type":"user","cwd":"/Users/nicky/dev/cubby","other":1}"#;
        assert_eq!(
            extract_cwd(text),
            Some("/Users/nicky/dev/cubby".to_string())
        );
    }

    #[test]
    fn extract_cwd_unescapes_forward_slashes() {
        let text = r#"{"cwd":"\/Users\/nicky\/dev\/cubby"}"#;
        assert_eq!(
            extract_cwd(text),
            Some("/Users/nicky/dev/cubby".to_string())
        );
    }

    #[test]
    fn extract_cwd_is_none_when_absent() {
        assert_eq!(extract_cwd(r#"{"type":"user"}"#), None);
    }

    #[test]
    fn encode_claude_project_dir_maps_slashes_and_dots() {
        assert_eq!(
            encode_claude_project_dir(Path::new("/Users/nicky/dev/cubby")),
            "-Users-nicky-dev-cubby"
        );
        assert_eq!(
            encode_claude_project_dir(Path::new("/Users/nicky/dev/my.app")),
            "-Users-nicky-dev-my-app"
        );
    }
}
