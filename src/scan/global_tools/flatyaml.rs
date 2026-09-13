//! A deliberately tiny reader for flat `key: value` YAML documents — enough
//! for pnpm's `.modules.yaml` (top-level scalars) and fish's history file
//! (`- cmd: …` / `  when: …` pairs). No YAML crate is pulled in for this.

use std::collections::BTreeMap;

/// Top-level `key: value` scalars. Nested blocks and sequences are skipped;
/// quotes around values are stripped.
pub fn top_level_scalars(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with(' ')
            || line.starts_with('\t')
            || line.starts_with('#')
            || line.starts_with('-')
        {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        if v.is_empty() || v == "|" || v == ">" {
            continue;
        }
        out.insert(k.trim().to_string(), unquote(v));
    }
    out
}

/// Strip one layer of matching single/double quotes.
pub fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 {
        let first = v.as_bytes()[0];
        let last = v.as_bytes()[v.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return v[1..v.len() - 1].to_string();
        }
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pnpm_modules_yaml() {
        let text = "hoistPattern:\n  - '*'\nlayoutVersion: 5\nnodeLinker: isolated\npackageManager: pnpm@10.30.0\nstoreDir: /Users/n/Library/pnpm/store/v10\nvirtualStoreDir: ../.pnpm\nskipped: []\n";
        let m = top_level_scalars(text);
        assert_eq!(m["layoutVersion"], "5");
        assert_eq!(m["packageManager"], "pnpm@10.30.0");
        assert_eq!(m["virtualStoreDir"], "../.pnpm");
        assert_eq!(m["skipped"], "[]");
        assert!(!m.contains_key("hoistPattern"));
    }

    #[test]
    fn unquotes() {
        assert_eq!(unquote("'a b'"), "a b");
        assert_eq!(unquote("\"x\""), "x");
        assert_eq!(unquote("plain"), "plain");
    }
}
