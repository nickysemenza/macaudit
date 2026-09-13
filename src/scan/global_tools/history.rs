//! Optional shell-history evidence: *only* per-command invocation counts and
//! the most recent timestamp, and only for command names the scan already
//! knows. Raw history lines, arguments and anything that might be a secret
//! never leave this module. Disabled unless `[tools] shell_history_evidence`
//! is on, and a hit is supporting evidence, never a removal criterion.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct HistoryStat {
    pub count: u64,
    /// Unix seconds of the most recent invocation, when the file records it.
    pub last_used: Option<i64>,
}

fn first_command(cmd: &str) -> Option<String> {
    let mut tokens = cmd.split_whitespace();
    loop {
        let tok = tokens.next()?;
        if tok.contains('=')
            || matches!(
                tok,
                "sudo" | "env" | "time" | "nohup" | "exec" | "command" | "builtin"
            )
        {
            continue;
        }
        let name = tok.rsplit('/').next().unwrap_or(tok);
        return Some(name.to_string());
    }
}

fn note(
    stats: &mut BTreeMap<String, HistoryStat>,
    known: &BTreeSet<String>,
    cmd: &str,
    when: Option<i64>,
) {
    let Some(name) = first_command(cmd) else {
        return;
    };
    if !known.contains(&name) {
        return;
    }
    let s = stats.entry(name).or_default();
    s.count += 1;
    if let Some(w) = when {
        s.last_used = Some(s.last_used.map_or(w, |cur| cur.max(w)));
    }
}

/// zsh: `: <ts>:<dur>;<cmd>` (extended) or plain `<cmd>` lines.
pub fn parse_zsh(text: &str, known: &BTreeSet<String>, stats: &mut BTreeMap<String, HistoryStat>) {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(": ") {
            if let Some((ts, cmd)) = rest.split_once(';') {
                let when = ts
                    .split(':')
                    .next()
                    .and_then(|t| t.trim().parse::<i64>().ok());
                note(stats, known, cmd, when);
                continue;
            }
        }
        note(stats, known, line, None);
    }
}

/// fish: `- cmd: <cmd>` followed by `  when: <ts>`.
pub fn parse_fish(text: &str, known: &BTreeSet<String>, stats: &mut BTreeMap<String, HistoryStat>) {
    let mut pending: Option<String> = None;
    for line in text.lines() {
        if let Some(cmd) = line.strip_prefix("- cmd: ") {
            if let Some(prev) = pending.take() {
                note(stats, known, &prev, None);
            }
            pending = Some(cmd.to_string());
        } else if let Some(when) = line.trim_start().strip_prefix("when: ") {
            if let Some(cmd) = pending.take() {
                note(stats, known, &cmd, when.trim().parse::<i64>().ok());
            }
        }
    }
    if let Some(prev) = pending {
        note(stats, known, &prev, None);
    }
}

/// Aggregate over the standard history files under `home`.
pub fn aggregate(home: &Path, known: &BTreeSet<String>) -> BTreeMap<String, HistoryStat> {
    let mut stats = BTreeMap::new();
    if let Ok(text) = std::fs::read(home.join(".zsh_history")) {
        parse_zsh(&String::from_utf8_lossy(&text), known, &mut stats);
    }
    if let Ok(text) = std::fs::read(home.join(".local/share/fish/fish_history")) {
        parse_fish(&String::from_utf8_lossy(&text), known, &mut stats);
    }
    if let Ok(text) = std::fs::read(home.join(".bash_history")) {
        parse_zsh(&String::from_utf8_lossy(&text), known, &mut stats);
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_counts_and_dates_never_text() {
        let known: BTreeSet<String> = ["knip", "wrangler", "pnpm"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut stats = BTreeMap::new();
        parse_zsh(
            ": 1700000000:0;knip --strict SECRET=abc\n: 1700000500:0;sudo pnpm add -g x\nls -la\nknip\n",
            &known,
            &mut stats,
        );
        parse_fish(
            "- cmd: wrangler deploy --token hunter2\n  when: 1700009999\n- cmd: /usr/local/bin/knip\n  when: 1699999999\n- cmd: curl secret.example\n  when: 1\n",
            &known,
            &mut stats,
        );
        assert_eq!(stats["knip"].count, 3);
        assert_eq!(stats["knip"].last_used, Some(1700000000));
        assert_eq!(stats["pnpm"].count, 1);
        assert_eq!(stats["wrangler"].last_used, Some(1700009999));
        assert!(!stats.contains_key("ls"));
        assert!(!stats.contains_key("curl"));
        let json = serde_json::to_string(&stats).unwrap();
        assert!(!json.contains("hunter2") && !json.contains("SECRET") && !json.contains("deploy"));
    }
}
