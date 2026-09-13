//! PortsScanner (spec §3.8) — `lsof -nP -iTCP -sTCP:LISTEN` → one finding per
//! TCP listener. No destructive remedies: `RevealInFinder` on the resolved
//! binary (best-effort, via `ps -o comm=`) and `CopyToClipboard` with the
//! `kill <pid>` command.

use async_trait::async_trait;

use crate::model::{Finding, FindingKind, Remedy, RemedyCommand, ScannerId, Severity};
use crate::scan::{ScanCtx, Scanner};

#[derive(Default)]
pub struct PortsScanner;

#[async_trait]
impl Scanner for PortsScanner {
    fn id(&self) -> ScannerId {
        ScannerId::Ports
    }

    async fn scan(&self, ctx: ScanCtx) -> anyhow::Result<()> {
        // lsof exits 1 (with empty stdout) when no matching files are found —
        // that's a normal "nothing listening" result, not a failure. Only a
        // spawn error (missing binary) is treated as "tool unavailable".
        let out = match ctx
            .runner
            .run("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"], &ctx.token)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                ctx.emit(
                    Finding::new(
                        FindingKind::PortListener,
                        "lsof:unavailable",
                        "lsof not available",
                    )
                    .detail(e.to_string())
                    .severity(Severity::Info),
                )
                .await;
                return Ok(());
            }
        };

        for line in out.stdout_str().lines() {
            let Some(listener) = parse_listener_line(line) else {
                continue;
            };

            let binary_path = resolve_binary_path(&ctx, listener.pid).await;

            // Include host: a process commonly binds the same port on both IPv4
            // and IPv6 (two distinct sockets). Omitting host would give them the
            // same FindingId and the upsert would silently drop one.
            let key = format!("{}:{}:{}", listener.pid, listener.host, listener.port);
            let title = format!(
                "PID {} {} — :{}",
                listener.pid, listener.command, listener.port
            );
            let mut finding = Finding::new(FindingKind::PortListener, &key, title)
                .detail(format!(
                    "{} (pid {}, user {}) listening on {}",
                    listener.command, listener.pid, listener.user, listener.name
                ))
                .severity(Severity::Info)
                .meta(serde_json::json!({
                    "pid": listener.pid,
                    "port": listener.port,
                    "command": listener.command,
                    "user": listener.user,
                    "host": listener.host,
                }))
                .remedy(Remedy {
                    label: "Copy kill command".to_string(),
                    command: RemedyCommand::CopyToClipboard {
                        text: format!("kill {}", listener.pid),
                    },
                    reclaims_bytes: None,
                    destructive: false,
                    alternative: false,
                    guard: None,
                });

            if let Some(path) = binary_path {
                // The listener's path IS the process binary — show it in the
                // Path column, not just inside the reveal remedy.
                finding = finding.path(path.clone()).remedy(Remedy {
                    label: "Reveal in Finder".to_string(),
                    command: RemedyCommand::RevealInFinder { path: path.into() },
                    reclaims_bytes: None,
                    destructive: false,
                    alternative: false,
                    guard: None,
                });
            }

            ctx.emit(finding).await;
        }

        Ok(())
    }
}

struct Listener {
    command: String,
    pid: u32,
    user: String,
    host: String,
    port: u16,
    name: String,
}

/// Parse one data line of `lsof -nP -iTCP -sTCP:LISTEN` output. Header line
/// (`COMMAND ... NAME`) and malformed lines return `None`.
///
/// Columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME, where NAME is
/// itself `host:port (LISTEN)` and may contain spaces (the `(LISTEN)` suffix),
/// so only the first 8 whitespace tokens are fixed-width.
fn parse_listener_line(line: &str) -> Option<Listener> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with("COMMAND") {
        return None;
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 9 {
        return None;
    }
    let command = tokens[0].to_string();
    let pid: u32 = tokens[1].parse().ok()?;
    let user = tokens[2].to_string();
    // tokens[3..8] = FD TYPE DEVICE SIZE/OFF NODE — unused.
    let name_and_state = tokens[8..].join(" ");
    // Strip a trailing " (LISTEN)"/"(ESTABLISHED)" etc if present.
    let name = name_and_state
        .split(" (")
        .next()
        .unwrap_or(&name_and_state)
        .trim()
        .to_string();

    let (host, port_str) = name.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;

    Some(Listener {
        command,
        pid,
        user,
        host: host.to_string(),
        port,
        name,
    })
}

/// Best-effort resolution of a pid's full executable path via `ps -o comm=`.
/// Returns `None` if the lookup fails or is empty — the caller then simply
/// omits the RevealInFinder remedy.
async fn resolve_binary_path(ctx: &ScanCtx, pid: u32) -> Option<String> {
    let pid_str = pid.to_string();
    let out = ctx
        .runner
        .run("ps", &["-o", "comm=", "-p", &pid_str], &ctx.token)
        .await
        .ok()?;
    if !out.success() {
        return None;
    }
    let path = out.stdout_str().trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanEvent;
    use crate::runner::MockCommandRunner;

    const LSOF_FIXTURE: &str = "\
COMMAND   PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node    12345  nicky   22u  IPv6 0x1234567890abcd      0t0  TCP *:3000 (LISTEN)
postgres  678  nicky    7u  IPv4 0x0987654321abcd      0t0  TCP 127.0.0.1:5432 (LISTEN)
";

    fn ctx_with(mock: MockCommandRunner, tx: tokio::sync::mpsc::Sender<ScanEvent>) -> ScanCtx {
        ScanCtx {
            tx,
            token: tokio_util::sync::CancellationToken::new(),
            gen: 1,
            config: std::sync::Arc::new(crate::config::Config::default()),
            paths: std::sync::Arc::new(crate::config::Paths::from_home("/tmp/fh")),
            runner: std::sync::Arc::new(mock),
            current: crate::model::ScannerId::Ports,
            repo_tx: None,
            repo_rx: None,
            fs_discovery_only: false,
        }
    }

    #[tokio::test]
    async fn parses_listeners_and_resolves_binary() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new()
            .on("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"], LSOF_FIXTURE)
            .on(
                "ps",
                &["-o", "comm=", "-p", "12345"],
                "/usr/local/bin/node\n",
            )
            .on(
                "ps",
                &["-o", "comm=", "-p", "678"],
                "/usr/local/bin/postgres\n",
            );
        let ctx = ctx_with(mock, tx);
        PortsScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 2);

        let node = findings.iter().find(|f| f.meta["pid"] == 12345).unwrap();
        assert_eq!(node.title, "PID 12345 node — :3000");
        assert_eq!(node.meta["port"], 3000);
        assert_eq!(node.meta["host"], "*");
        assert!(node.remedies.iter().all(|r| !r.destructive));
        assert!(node.remedies.iter().any(|r| matches!(
            &r.command,
            RemedyCommand::CopyToClipboard { text } if text == "kill 12345"
        )));
        assert!(node.remedies.iter().any(|r| matches!(
            &r.command,
            RemedyCommand::RevealInFinder { path } if path.to_str() == Some("/usr/local/bin/node")
        )));

        let pg = findings.iter().find(|f| f.meta["pid"] == 678).unwrap();
        assert_eq!(pg.meta["host"], "127.0.0.1");
        assert_eq!(pg.meta["port"], 5432);
    }

    #[tokio::test]
    async fn missing_lsof_binary_emits_single_info_finding() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        // No response registered ⇒ errors, simulating a missing `lsof` binary.
        let mock = MockCommandRunner::new();
        let ctx = ctx_with(mock, tx);
        PortsScanner.scan(ctx).await.unwrap();

        let mut findings = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                findings.push(*finding);
            }
        }
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[tokio::test]
    async fn no_listeners_found_emits_nothing() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        // lsof exits 1 with empty stdout when nothing matches — not an error.
        let mock =
            MockCommandRunner::new().on_fail("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"], 1, "");
        let ctx = ctx_with(mock, tx);
        PortsScanner.scan(ctx).await.unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn header_line_is_skipped() {
        assert!(parse_listener_line(
            "COMMAND   PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME"
        )
        .is_none());
    }

    /// Regression: a process bound to the same port on IPv4 and IPv6 is two
    /// distinct sockets and must yield two distinct FindingIds — otherwise the
    /// upsert-by-id in every downstream sink silently drops one listener.
    #[tokio::test]
    async fn dual_stack_same_port_yields_distinct_ids() {
        const DUAL: &str = "\
COMMAND   PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
postgres  678  nicky    7u  IPv4 0x0987654321abcd      0t0  TCP 127.0.0.1:5432 (LISTEN)
postgres  678  nicky    8u  IPv6 0x0987654321abce      0t0  TCP [::1]:5432 (LISTEN)
";
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mock = MockCommandRunner::new()
            .on("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"], DUAL)
            .on(
                "ps",
                &["-o", "comm=", "-p", "678"],
                "/usr/local/bin/postgres\n",
            );
        let ctx = ctx_with(mock, tx);
        PortsScanner.scan(ctx).await.unwrap();

        let mut ids = std::collections::BTreeSet::new();
        while let Ok(ev) = rx.try_recv() {
            if let ScanEvent::Finding { finding, .. } = ev {
                ids.insert(finding.id);
            }
        }
        assert_eq!(ids.len(), 2, "IPv4 and IPv6 listeners must not collide");
    }
}
