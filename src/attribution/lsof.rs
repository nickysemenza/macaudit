//! One shared `lsof` snapshot for every consumer that needs "what files does
//! a running process have open": the Projects axis's live-process join
//! (`projects::resolvers::procs`) and the App Storage axis's tier-4 observed-
//! open evidence (`apps::linkers`). A single `lsof -F pcfn` pass, cached for
//! 60s (resolvers run once per project/candidate within the same resolve
//! pass, so without caching every one would pay for its own `lsof` call),
//! replaces the two separate `lsof` pipelines — and their two separate `-F`
//! parsers — both axes used to run.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::model::ResolveEnv;

/// How long a cached snapshot stays valid.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// One open file from `lsof -F pcfn`: the pid and command that opened it,
/// its file descriptor (`"cwd"`, a number, `"txt"`, ...), and the path
/// itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    pub pid: u32,
    pub command: String,
    pub fd: String,
    pub path: PathBuf,
}

static LSOF_CACHE: Mutex<Option<(Instant, Arc<Vec<OpenFile>>)>> = Mutex::new(None);

/// The current (cached) snapshot of every open file `lsof -a -u $USER -d
/// ^txt,^mem -F pcfn` reports — every file descriptor except the executable
/// text image and memory-mapped files, which are noisy and never a cwd or a
/// real "this app has X open" signal. Best-effort: `env.run_blocking`
/// failing (no Tokio runtime, `lsof` missing, timeout) degrades to an empty
/// snapshot, same as every other best-effort external command in this crate.
pub fn snapshot(env: &ResolveEnv<'_>) -> Arc<Vec<OpenFile>> {
    {
        let cache = LSOF_CACHE.lock().unwrap();
        if let Some((at, files)) = cache.as_ref() {
            if at.elapsed() < CACHE_TTL {
                return files.clone();
            }
        }
    }
    let user = std::env::var("USER").unwrap_or_default();
    let files = env
        .run_blocking(
            "lsof",
            &["-a", "-u", &user, "-d", "^txt,^mem", "-F", "pcfn"],
        )
        .map(|out| parse(&String::from_utf8_lossy(&out)))
        .unwrap_or_default();
    let files = Arc::new(files);
    *LSOF_CACHE.lock().unwrap() = Some((Instant::now(), files.clone()));
    files
}

/// Parse `lsof -F pcfn` output: a `p<pid>` line starts a process block,
/// `c<command>` names it, then each `f<fd>`/`n<path>` pair (`f` always
/// precedes its `n`) is one open file belonging to that process.
pub fn parse(output: &str) -> Vec<OpenFile> {
    let mut out = Vec::new();
    let mut pid: Option<u32> = None;
    let mut command: Option<String> = None;
    let mut fd: Option<String> = None;
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let (tag, rest) = line.split_at(1);
        match tag {
            "p" => {
                pid = rest.parse().ok();
                command = None;
                fd = None;
            }
            "c" => command = Some(rest.to_string()),
            "f" => fd = Some(rest.to_string()),
            "n" => {
                if let (Some(p), Some(c), Some(f)) = (pid, command.clone(), fd.clone()) {
                    out.push(OpenFile {
                        pid: p,
                        command: c,
                        fd: f,
                        path: PathBuf::from(rest),
                    });
                }
            }
            _ => {}
        }
    }
    out
}

/// The cwd (`fd == "cwd"`) of every process in `files`, by pid.
pub fn cwd_by_pid(files: &[OpenFile]) -> HashMap<u32, PathBuf> {
    files
        .iter()
        .filter(|f| f.fd == "cwd")
        .map(|f| (f.pid, f.path.clone()))
        .collect()
}

/// Every open file whose path is under (or equal to) `prefix`.
pub fn open_under<'a>(
    files: &'a [OpenFile],
    prefix: &'a Path,
) -> impl Iterator<Item = &'a OpenFile> {
    files.iter().filter(move |f| f.path.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One shell's cwd, one node process's cwd, and a third process with two
    /// regular open files — the union of what `procs.rs`'s old
    /// `parse_lsof_pcn` and `linkers.rs`'s old `parse_lsof_pn` tests covered,
    /// against the new `-F pcfn` record shape (`f` before every `n`).
    const FIXTURE: &str = "p1234\ncnode\nfcwd\nn/Users/dev/cubby\np456\nczsh\nfcwd\nn/Users/dev/other\np789\ncChrome\nf12\nn/Users/dev/Library/Caches/Foo\nf13\nn/tmp/x\n";

    #[test]
    fn parses_cwd_and_regular_fds_for_every_process() {
        let files = parse(FIXTURE);
        assert_eq!(
            files,
            vec![
                OpenFile {
                    pid: 1234,
                    command: "node".into(),
                    fd: "cwd".into(),
                    path: "/Users/dev/cubby".into(),
                },
                OpenFile {
                    pid: 456,
                    command: "zsh".into(),
                    fd: "cwd".into(),
                    path: "/Users/dev/other".into(),
                },
                OpenFile {
                    pid: 789,
                    command: "Chrome".into(),
                    fd: "12".into(),
                    path: "/Users/dev/Library/Caches/Foo".into(),
                },
                OpenFile {
                    pid: 789,
                    command: "Chrome".into(),
                    fd: "13".into(),
                    path: "/tmp/x".into(),
                },
            ]
        );
    }

    #[test]
    fn cwd_by_pid_only_keeps_cwd_entries() {
        let files = parse(FIXTURE);
        let map = cwd_by_pid(&files);
        assert_eq!(map.get(&1234), Some(&PathBuf::from("/Users/dev/cubby")));
        assert_eq!(map.get(&456), Some(&PathBuf::from("/Users/dev/other")));
        assert_eq!(map.get(&789), None);
    }

    #[test]
    fn open_under_filters_by_path_prefix() {
        let files = parse(FIXTURE);
        let under: Vec<&OpenFile> = open_under(&files, Path::new("/Users/dev/Library")).collect();
        assert_eq!(under.len(), 1);
        assert_eq!(under[0].pid, 789);
    }

    #[test]
    fn ignores_an_n_line_with_no_preceding_pid_command_or_fd() {
        assert_eq!(parse("n/Users/dev/cubby\n"), Vec::new());
    }

    #[test]
    fn empty_output_yields_no_files() {
        assert_eq!(parse(""), Vec::new());
    }
}
