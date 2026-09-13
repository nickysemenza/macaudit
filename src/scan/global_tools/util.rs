//! Small filesystem helpers shared by the manager probes. All read-only.

use std::path::{Path, PathBuf};

use serde_json::Value;

pub fn read_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Parse a TOML *document* (`toml::Value::from_str` parses a bare value).
pub fn read_toml(path: &Path) -> Option<toml::Table> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str::<toml::Table>(&text).ok()
}

/// Sorted directory entries (names only), empty when unreadable.
pub fn list_dir(path: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    v.sort();
    v
}

pub fn file_name(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}

/// `package.json` `bin` field → (command, relative target) pairs. A string
/// `bin` names one command after the package (scope stripped).
pub fn package_bins(pkg_json: &Value, package_name: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match pkg_json.get("bin") {
        Some(Value::String(target)) => {
            let cmd = package_name.rsplit('/').next().unwrap_or(package_name);
            out.push((cmd.to_string(), target.clone()));
        }
        Some(Value::Object(map)) => {
            for (cmd, target) in map {
                if let Some(t) = target.as_str() {
                    out.push((cmd.clone(), t.to_string()));
                }
            }
        }
        _ => {}
    }
    out.sort();
    out
}

/// Size of a directory tree on disk, bounded so a huge venv cannot stall the
/// scan; `None` when the walk was cut short.
pub fn bounded_size(path: &Path) -> Option<u64> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let r = crate::scan::sizing::du_blocks_bounded(path, 200_000, deadline, &|| false);
    r.complete.then_some(r.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn package_bins_handles_string_and_map() {
        assert_eq!(
            package_bins(&json!({"bin": "cli.js"}), "@openai/codex"),
            vec![("codex".to_string(), "cli.js".to_string())]
        );
        assert_eq!(
            package_bins(&json!({"bin": {"b": "b.js", "a": "a.js"}}), "x"),
            vec![
                ("a".to_string(), "a.js".to_string()),
                ("b".to_string(), "b.js".to_string())
            ]
        );
        assert!(package_bins(&json!({}), "x").is_empty());
    }
}
