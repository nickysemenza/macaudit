//! Live processes and listening ports whose cwd is inside the project, from
//! one shared `lsof -a -u $USER -d cwd -F pcn` pass (cached 60s — resolvers run
//! once per project, and this module can't tell how many projects will ask).
//!
//! `resolve()` always returns no claims: a process isn't a disk claim
//! `accounting.rs` can account bytes against, and every other resolver in
//! this crate runs synchronously (`fn(&Project, &ResolveEnv) -> Vec<Claim>`)
//! while shelling out is inherently async — so this module bypasses the
//! `CommandRunner`/`ScanCtx` seam other scanners use and drives `lsof`
//! directly via `std::process::Command` on a helper thread with a hard
//! timeout. `processes_for` is the real entry point: the scanner wiring
//! calls it while building each project's `Footprint` (`processes`/`ports`
//! fields), outside the `Claim` pipeline entirely.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::super::Project;
use crate::attribution::model::{Claim, Proc, ProcKind, ResolveEnv};
use crate::attribution::paths as attribution_paths;
use crate::model::ScannerId;

const LSOF_TIMEOUT: Duration = Duration::from_secs(8);
/// How long a cached `lsof` snapshot stays valid — resolvers run once per
/// discovered project in the same pass, so without this every project would
/// pay for its own `lsof` call.
const LSOF_CACHE_TTL: Duration = Duration::from_secs(60);

static LSOF_CACHE: Mutex<Option<(Instant, Vec<ProcRow>)>> = Mutex::new(None);

/// Never claims anything — see the module doc for why. Kept so `procs`
/// still satisfies every other resolver's `resolve(project, env) ->
/// Vec<Claim>` shape for `resolvers::mod::all`.
pub fn resolve(_project: &Project, _env: &ResolveEnv<'_>) -> Vec<Claim> {
    Vec::new()
}

/// The processes whose cwd is inside `project` (or one of its worktrees),
/// deduplicated by pid, plus every port from the Ports snapshot owned by one
/// of those pids.
pub fn processes_for(project: &Project, env: &ResolveEnv<'_>) -> (Vec<Proc>, Vec<u16>) {
    let rows = snapshot();
    let listening = listening_ports_by_pid(env);

    let mut procs = Vec::new();
    let mut ports: Vec<u16> = Vec::new();
    let mut seen_pids: HashSet<u32> = HashSet::new();

    for row in &rows {
        let cwd = attribution_paths::tree_path(&row.cwd);
        if !under_project(&cwd, project) {
            continue;
        }
        if !seen_pids.insert(row.pid) {
            continue;
        }
        let kind = classify(&row.command, row.pid, &listening);
        procs.push(Proc {
            pid: row.pid,
            name: row.command.clone(),
            kind,
            cwd: row.cwd.clone(),
        });
        if let Some(pid_ports) = listening.get(&row.pid) {
            ports.extend(pid_ports.iter().copied());
        }
    }
    ports.sort_unstable();
    ports.dedup();
    (procs, ports)
}

fn under_project(path: &Path, project: &Project) -> bool {
    path.starts_with(&project.root) || project.worktrees.iter().any(|wt| path.starts_with(wt))
}

fn classify(command: &str, pid: u32, listening: &HashMap<u32, Vec<u16>>) -> ProcKind {
    const SHELLS: &[&str] = &["zsh", "bash", "fish", "sh", "nu"];
    if SHELLS.contains(&command) {
        ProcKind::Shell
    } else if listening.get(&pid).is_some_and(|ports| !ports.is_empty()) {
        ProcKind::Server
    } else {
        ProcKind::Other
    }
}

fn listening_ports_by_pid(env: &ResolveEnv<'_>) -> HashMap<u32, Vec<u16>> {
    let mut map: HashMap<u32, Vec<u16>> = HashMap::new();
    for finding in env.findings(ScannerId::Ports) {
        let Some(pid) = finding.meta.get("pid").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(port) = finding.meta.get("port").and_then(|v| v.as_u64()) else {
            continue;
        };
        map.entry(pid as u32).or_default().push(port as u16);
    }
    map
}

/// One `lsof -F pcn` record: a pid, its command, and the cwd file descriptor
/// `lsof -d cwd` restricted the listing to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcRow {
    pid: u32,
    command: String,
    cwd: PathBuf,
}

fn snapshot() -> Vec<ProcRow> {
    let mut cache = LSOF_CACHE.lock().unwrap();
    if let Some((at, rows)) = cache.as_ref() {
        if at.elapsed() < LSOF_CACHE_TTL {
            return rows.clone();
        }
    }
    let rows = run_lsof();
    *cache = Some((Instant::now(), rows.clone()));
    rows
}

/// Runs `lsof` on a helper thread so a hung/blocked `lsof` can't stall the
/// (synchronous) resolver pass past `LSOF_TIMEOUT` — on any failure or
/// timeout this degrades silently to no processes, same as every other
/// best-effort external command in this crate.
fn run_lsof() -> Vec<ProcRow> {
    let Ok(user) = std::env::var("USER") else {
        return Vec::new();
    };
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let output = std::process::Command::new("lsof")
            // `-a` ANDs the selectors; without it lsof ORs `-u` and `-d`
            // and lists every open file of every process.
            .args(["-a", "-u", &user, "-d", "cwd", "-F", "pcn"])
            .output();
        let _ = tx.send(output);
    });
    match rx.recv_timeout(LSOF_TIMEOUT) {
        Ok(Ok(output)) => parse_lsof_pcn(&String::from_utf8_lossy(&output.stdout)),
        _ => Vec::new(),
    }
}

/// Parse `lsof -F pcn` output: repeating `p<pid>`/`c<command>` header lines
/// followed by one `n<path>` per matching open file (here, exactly the cwd,
/// since the caller passes `-d cwd`).
fn parse_lsof_pcn(output: &str) -> Vec<ProcRow> {
    let mut rows = Vec::new();
    let mut pid: Option<u32> = None;
    let mut command: Option<String> = None;
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let (tag, rest) = line.split_at(1);
        match tag {
            "p" => {
                pid = rest.parse().ok();
                command = None;
            }
            "c" => command = Some(rest.to_string()),
            "n" => {
                if let (Some(p), Some(c)) = (pid, command.clone()) {
                    rows.push(ProcRow {
                        pid: p,
                        command: c,
                        cwd: PathBuf::from(rest),
                    });
                }
            }
            _ => {}
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_process_one_cwd() {
        let output = "p1234\ncnode\nn/Users/dev/cubby\n";
        assert_eq!(
            parse_lsof_pcn(output),
            vec![ProcRow {
                pid: 1234,
                command: "node".to_string(),
                cwd: PathBuf::from("/Users/dev/cubby"),
            }]
        );
    }

    #[test]
    fn parses_multiple_processes() {
        let output = "p1\nczsh\nn/Users/dev/cubby\np2\ncnode\nn/Users/dev/other\n";
        assert_eq!(
            parse_lsof_pcn(output),
            vec![
                ProcRow {
                    pid: 1,
                    command: "zsh".to_string(),
                    cwd: PathBuf::from("/Users/dev/cubby"),
                },
                ProcRow {
                    pid: 2,
                    command: "node".to_string(),
                    cwd: PathBuf::from("/Users/dev/other"),
                },
            ]
        );
    }

    #[test]
    fn ignores_an_n_line_with_no_preceding_pid_or_command() {
        assert_eq!(parse_lsof_pcn("n/Users/dev/cubby\n"), Vec::new());
    }

    #[test]
    fn empty_output_yields_no_rows() {
        assert_eq!(parse_lsof_pcn(""), Vec::new());
    }

    #[test]
    fn classify_recognises_known_shells() {
        let listening = HashMap::new();
        assert_eq!(classify("zsh", 1, &listening), ProcKind::Shell);
        assert_eq!(classify("bash", 1, &listening), ProcKind::Shell);
    }

    #[test]
    fn classify_flags_a_port_owning_pid_as_server() {
        let mut listening = HashMap::new();
        listening.insert(42, vec![3000]);
        assert_eq!(classify("node", 42, &listening), ProcKind::Server);
        assert_eq!(classify("node", 43, &listening), ProcKind::Other);
    }
}
