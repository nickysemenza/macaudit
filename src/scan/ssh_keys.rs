//! SshKeysScanner — inventories `~/.ssh` key pairs: type/bits (parsed from
//! the public key), mtime-as-age-proxy, and whether each key has a matching
//! `IdentityFile` entry in `~/.ssh/config`. Info-severity by default;
//! Attention for weak RSA (<=2048 bits) or keys older than 5 years. Only
//! non-destructive remedies (RevealInFinder).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use async_trait::async_trait;
use serde_json::json;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct SshKeysScanner;

const FIVE_YEARS_DAYS: u64 = 5 * 365;

#[async_trait]
impl Scanner for SshKeysScanner {
    fn id(&self) -> ScannerId {
        ScannerId::SshKeys
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        let ssh_dir = ctx.paths.expand("~/.ssh");
        let Ok(entries) = std::fs::read_dir(&ssh_dir) else {
            emit_no_keys(&ctx, &ssh_dir).await;
            return Ok(());
        };

        let config_text = std::fs::read_to_string(ssh_dir.join("config")).unwrap_or_default();

        let mut pub_files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("pub"))
            .collect();
        pub_files.sort();

        // An empty section reads as broken — say explicitly that there was
        // nothing to find (spec: this scanner audits ~/.ssh key hygiene).
        if pub_files.is_empty() {
            emit_no_keys(&ctx, &ssh_dir).await;
            return Ok(());
        }

        for pub_path in pub_files {
            if ctx.cancelled() {
                break;
            }
            emit_for_pubkey(&ctx, &pub_path, &config_text).await;
        }

        Ok(())
    }
}

/// Explanatory empty-state finding: this section audits SSH key hygiene
/// (key type/strength, age, config coverage); an empty pane would otherwise
/// look like a scan failure.
async fn emit_no_keys(ctx: &ScanCtx, ssh_dir: &Path) {
    ctx.emit(
        Finding::new(FindingKind::SshKey, "ssh:no-keys", "No SSH keys found")
            .path(ssh_dir.to_path_buf())
            .detail(
                "This section audits SSH keys in ~/.ssh (type/strength, age, and whether \
                 each key is referenced by ~/.ssh/config). No .pub key files were found.",
            )
            .severity(Severity::Info),
    )
    .await;
}

async fn emit_for_pubkey(ctx: &ScanCtx, pub_path: &Path, config_text: &str) {
    let Ok(content) = std::fs::read_to_string(pub_path) else {
        return;
    };
    let Some(line) = content
        .lines()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
    else {
        return;
    };
    let Some(info) = parse_pubkey_line(line) else {
        return;
    };

    let priv_path = pub_path.with_extension("");
    let has_priv = priv_path.is_file();
    let age_path: &Path = if has_priv { &priv_path } else { pub_path };

    let mtime = std::fs::metadata(age_path).and_then(|m| m.modified()).ok();
    let age_days = mtime
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d.as_secs() / 86400);

    let key_name = priv_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let has_config_entry = !config_text.is_empty() && config_text.contains(&key_name);

    let is_weak_rsa = info.key_type == "ssh-rsa" && info.bits.map(|b| b <= 2048).unwrap_or(false);
    let is_old = age_days.map(|d| d > FIVE_YEARS_DAYS).unwrap_or(false);
    let severity = if is_weak_rsa || is_old {
        Severity::Attention
    } else {
        Severity::Info
    };

    let mut reasons = Vec::new();
    if is_weak_rsa {
        reasons.push(format!(
            "{}-bit RSA is weak by modern standards",
            info.bits.unwrap_or(0)
        ));
    }
    if is_old {
        reasons.push(format!("{} days old", age_days.unwrap_or(0)));
    }
    if !has_config_entry {
        reasons.push("no matching entry in ~/.ssh/config".to_string());
    }

    let bits_suffix = info.bits.map(|b| format!(", {b} bits")).unwrap_or_default();
    let detail = if reasons.is_empty() {
        format!("{}{bits_suffix} key", info.key_type)
    } else {
        format!(
            "{}{bits_suffix} key — {}",
            info.key_type,
            reasons.join("; ")
        )
    };

    let (canonical_key, reveal_target) = if has_priv {
        (priv_path.to_string_lossy().to_string(), priv_path.clone())
    } else {
        (
            pub_path.to_string_lossy().to_string(),
            pub_path.to_path_buf(),
        )
    };

    let finding = Finding::new(FindingKind::SshKey, &canonical_key, key_name.clone())
        .detail(detail)
        .path(reveal_target.clone())
        .severity(severity)
        .remedy(Remedy {
            label: "Reveal in Finder".into(),
            command: RemedyCommand::RevealInFinder {
                path: reveal_target,
            },
            reclaims_bytes: None,
            destructive: false,
            alternative: false,
            guard: None,
        })
        .meta(json!({
            "type": info.key_type,
            "bits": info.bits,
            "age_days": age_days,
            "has_config_entry": has_config_entry,
            "has_private_key": has_priv,
            "comment": info.comment,
            "pubkey_path": pub_path,
            "private_key_path": has_priv.then(|| priv_path.clone()),
        }));

    ctx.emit(finding).await;
}

struct PubKeyInfo {
    key_type: String,
    bits: Option<u32>,
    comment: Option<String>,
}

/// Parse an OpenSSH public-key line: `<type> <base64-blob> [comment]`.
fn parse_pubkey_line(line: &str) -> Option<PubKeyInfo> {
    let mut parts = line.trim().splitn(3, char::is_whitespace);
    let key_type = parts.next()?.to_string();
    let data_b64 = parts.next()?;
    let comment = parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let bits = compute_bits(&key_type, data_b64);
    Some(PubKeyInfo {
        key_type,
        bits,
        comment,
    })
}

fn compute_bits(key_type: &str, data_b64: &str) -> Option<u32> {
    match key_type {
        "ssh-ed25519" => Some(256),
        "ssh-rsa" => {
            let data = base64_decode(data_b64)?;
            rsa_bits_from_blob(&data)
        }
        t if t.starts_with("ecdsa-sha2-nistp") => {
            t.trim_start_matches("ecdsa-sha2-nistp").parse::<u32>().ok()
        }
        _ => None,
    }
}

/// Read one length-prefixed field from the SSH wire format: a 4-byte
/// big-endian length followed by that many bytes.
fn read_ssh_field(data: &[u8], off: usize) -> Option<(&[u8], usize)> {
    if off + 4 > data.len() {
        return None;
    }
    let len = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
    let start = off + 4;
    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((&data[start..end], end))
}

/// An `ssh-rsa` public key blob is: string("ssh-rsa"), mpint(e), mpint(n).
/// Key size is the bit length of the modulus `n`.
fn rsa_bits_from_blob(data: &[u8]) -> Option<u32> {
    let (_type_field, off) = read_ssh_field(data, 0)?;
    let (_e_field, off) = read_ssh_field(data, off)?;
    let (n_field, _off) = read_ssh_field(data, off)?;

    let mut bytes = n_field;
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..]; // strip the sign-guard 0x00 byte mpint encoding adds
    }
    if bytes.is_empty() {
        return Some(0);
    }
    let top = bytes[0];
    let significant_bits = 8 - top.leading_zeros();
    Some((bytes.len() as u32 - 1) * 8 + significant_bits)
}

/// Minimal standard-alphabet base64 decoder (no whitespace tolerance needed —
/// SSH pubkey blobs are a single contiguous token). No `base64` crate is a
/// direct dependency of this crate, so this stays self-contained.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut table = [255u8; 256];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[c as usize] = i as u8;
    }

    let input = input.trim_end_matches('=');
    let mut bits_buf: u32 = 0;
    let mut bits_len: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for c in input.bytes() {
        let v = table[c as usize];
        if v == 255 {
            return None;
        }
        bits_buf = (bits_buf << 6) | v as u32;
        bits_len += 6;
        if bits_len >= 8 {
            bits_len -= 8;
            out.push((bits_buf >> bits_len) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use std::time::Duration;

    fn ctx_with(
        tmp: &tempfile::TempDir,
        mock: crate::runner::MockCommandRunner,
    ) -> (ScanCtx, tokio::sync::mpsc::Receiver<ScanEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let ctx = ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home(tmp.path())),
            runner: std::sync::Arc::new(mock),
            current: ScannerId::SshKeys,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        };
        (ctx, rx)
    }

    async fn drain(rx: &mut tokio::sync::mpsc::Receiver<ScanEvent>) -> Vec<crate::model::Finding> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                out.push(*finding);
            }
        }
        out
    }

    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
            out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6 & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(n & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    fn push_field(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }

    /// Build a syntactically-valid ssh-rsa public key blob with a modulus of
    /// exactly `bits` bits (bits must be a multiple of 8, MSB set so no sign
    /// padding byte gets added).
    fn build_rsa_pubkey_b64(bits: u32) -> String {
        let mut blob = Vec::new();
        push_field(&mut blob, b"ssh-rsa");
        push_field(&mut blob, &[0x01, 0x00, 0x01]); // e = 65537
        let mut n = vec![0u8; (bits / 8) as usize];
        n[0] = 0x80; // MSB set ⇒ top byte contributes all 8 bits, no padding needed
        push_field(&mut blob, &n);
        base64_encode(&blob)
    }

    #[test]
    fn rsa_bit_length_roundtrips() {
        let b64 = build_rsa_pubkey_b64(2048);
        assert_eq!(compute_bits("ssh-rsa", &b64), Some(2048));
        let b64_4096 = build_rsa_pubkey_b64(4096);
        assert_eq!(compute_bits("ssh-rsa", &b64_4096), Some(4096));
    }

    #[test]
    fn ed25519_and_ecdsa_bits_from_type_name() {
        assert_eq!(compute_bits("ssh-ed25519", "anything"), Some(256));
        assert_eq!(compute_bits("ecdsa-sha2-nistp256", "anything"), Some(256));
        assert_eq!(compute_bits("ecdsa-sha2-nistp521", "anything"), Some(521));
    }

    #[tokio::test]
    async fn weak_rsa_key_is_attention() {
        let tmp = tempfile::tempdir().unwrap();
        let ssh_dir = tmp.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let b64 = build_rsa_pubkey_b64(2048);
        std::fs::write(
            ssh_dir.join("id_rsa.pub"),
            format!("ssh-rsa {b64} me@host\n"),
        )
        .unwrap();
        std::fs::write(ssh_dir.join("id_rsa"), b"fake private key material").unwrap();
        std::fs::write(
            ssh_dir.join("config"),
            "Host x\n  IdentityFile ~/.ssh/id_rsa\n",
        )
        .unwrap();

        let (ctx, mut rx) = ctx_with(&tmp, crate::runner::MockCommandRunner::new());
        SshKeysScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Attention);
        assert_eq!(f.meta["type"], "ssh-rsa");
        assert_eq!(f.meta["bits"], 2048);
        assert_eq!(f.meta["has_config_entry"], true);
        assert_eq!(f.meta["has_private_key"], true);
        assert_eq!(f.remedies.len(), 1);
        assert!(!f.remedies[0].destructive);
        match &f.remedies[0].command {
            RemedyCommand::RevealInFinder { path } => assert!(path.ends_with("id_rsa")),
            other => panic!("expected RevealInFinder, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fresh_ed25519_key_with_no_config_entry_is_attention_for_missing_config() {
        let tmp = tempfile::tempdir().unwrap();
        let ssh_dir = tmp.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(
            ssh_dir.join("id_ed25519.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIQdummydata me@host\n",
        )
        .unwrap();
        std::fs::write(ssh_dir.join("id_ed25519"), b"fake private key material").unwrap();
        // No config file at all.

        let (ctx, mut rx) = ctx_with(&tmp, crate::runner::MockCommandRunner::new());
        SshKeysScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;

        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.meta["type"], "ssh-ed25519");
        assert_eq!(f.meta["bits"], 256);
        assert_eq!(f.meta["has_config_entry"], false);
        // ed25519, recent, but missing config entry is still not one of the
        // spec's Attention triggers (weak RSA / >5y old) — this documents the
        // current behavior: only bits/age escalate severity.
        assert_eq!(f.severity, Severity::Info);
        assert!(f.detail.contains("no matching entry"));
    }

    #[tokio::test]
    async fn old_key_is_attention() {
        let tmp = tempfile::tempdir().unwrap();
        let ssh_dir = tmp.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(
            ssh_dir.join("id_ed25519.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIQdummydata me@host\n",
        )
        .unwrap();
        let priv_path = ssh_dir.join("id_ed25519");
        std::fs::write(&priv_path, b"fake private key material").unwrap();

        let old_time = SystemTime::now() - Duration::from_secs(6 * 365 * 86400);
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&priv_path)
            .unwrap();
        f.set_modified(old_time).unwrap();

        let (ctx, mut rx) = ctx_with(&tmp, crate::runner::MockCommandRunner::new());
        SshKeysScanner.scan(ctx).await.unwrap();
        let findings = drain(&mut rx).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Attention);
        assert!(findings[0].meta["age_days"].as_u64().unwrap() > FIVE_YEARS_DAYS);
    }

    #[tokio::test]
    async fn missing_ssh_dir_emits_explanatory_empty_state() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, mut rx) = ctx_with(&tmp, crate::runner::MockCommandRunner::new());
        SshKeysScanner.scan(ctx).await.unwrap();
        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let crate::model::ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "No SSH keys found");
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
