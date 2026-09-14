//! Stamps the build with a version derived from git, so no version number has
//! to live in source. Resolution order:
//!
//!   1. `MACAUDIT_VERSION` in the environment — scripts/package.sh sets it to
//!      the release tag, so a release build reports exactly the tag.
//!   2. `git describe --tags --always --dirty`, minus the leading "v":
//!      "0.1.1" at a tag, "0.1.1-3-gabc1234-dirty" past one.
//!   3. `CARGO_PKG_VERSION` — the 0.0.0 floor in Cargo.toml, for a checkout
//!      with no git (a source tarball).
//!
//! Best-effort: never fails the build over version metadata. `--version` and
//! the HTTP User-Agent read the result via `env!("MACAUDIT_VERSION")`.

use std::path::Path;
use std::process::Command;

fn git_describe() -> Option<String> {
    let out = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.strip_prefix('v').unwrap_or(s).to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=MACAUDIT_VERSION");
    // Re-stamp after a commit, checkout or new tag; harmless when absent.
    for p in [".git/HEAD", ".git/refs/tags", ".git/packed-refs"] {
        if Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }

    let version = std::env::var("MACAUDIT_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(git_describe)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    println!("cargo:rustc-env=MACAUDIT_VERSION={version}");
}
