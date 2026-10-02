//! Bounded, budget-owned `lsof` snapshots with no reuse across invocations.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::inventory::{MemoryBudget, Reservation};

use super::model::ResolveEnv;

const MAX_OPEN_FILES: usize = 65_536;
const MAX_USER_BYTES: usize = 4096;

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

#[derive(Debug)]
struct SnapshotData {
    files: Vec<OpenFile>,
    _memory: Reservation,
}

#[derive(Clone, Debug, Default)]
pub struct OpenFiles {
    data: Option<Arc<SnapshotData>>,
}

impl std::ops::Deref for OpenFiles {
    type Target = [OpenFile];
    fn deref(&self) -> &[OpenFile] {
        self.data.as_ref().map_or(&[], |data| &data.files)
    }
}

/// A fresh snapshot of every open file `lsof -a -u $USER -d
/// ^txt,^mem -F pcfn` reports — every file descriptor except the executable
/// text image and memory-mapped files, which are noisy and never a cwd or a
/// real "this app has X open" signal. Best-effort: `env.run_blocking`
/// failing (no Tokio runtime, `lsof` missing, timeout) degrades to an empty
/// snapshot, same as every other best-effort external command in this crate.
pub fn snapshot(env: &ResolveEnv<'_>) -> OpenFiles {
    let budget = env.paths.size_cache.memory_budget();
    let Ok(_user_memory) = budget.reserve(MAX_USER_BYTES) else {
        return OpenFiles::default();
    };
    let user = std::env::var("USER").unwrap_or_default();
    if user.len() > MAX_USER_BYTES {
        return OpenFiles::default();
    }
    let Some(output) = env.run_blocking(
        "lsof",
        &["-a", "-u", &user, "-d", "^txt,^mem", "-F", "pcfn"],
    ) else {
        return OpenFiles::default();
    };
    let Ok(_decode_memory) = budget.reserve(output.len().saturating_mul(3)) else {
        return OpenFiles::default();
    };
    parse_with_budget(&String::from_utf8_lossy(&output), &budget)
}

/// Parse `lsof -F pcfn` output: a `p<pid>` line starts a process block,
/// `c<command>` names it, then each `f<fd>`/`n<path>` pair (`f` always
/// precedes its `n`) is one open file belonging to that process.
fn records(output: &str, mut visit: impl FnMut(u32, &str, &str, &str)) {
    let mut pid: Option<u32> = None;
    let mut command: Option<&str> = None;
    let mut fd: Option<&str> = None;
    for line in output.lines() {
        let Some(rest) = line.get(1..) else {
            continue;
        };
        match line.as_bytes()[0] {
            b'p' => {
                pid = rest.parse().ok();
                command = None;
                fd = None;
            }
            b'c' => command = Some(rest),
            b'f' => fd = Some(rest),
            b'n' => {
                if let (Some(pid), Some(command), Some(fd)) = (pid, command, fd) {
                    visit(pid, command, fd, rest);
                }
            }
            _ => {}
        }
    }
}

fn parse_with_budget(output: &str, budget: &Arc<MemoryBudget>) -> OpenFiles {
    let mut count = 0usize;
    let mut bytes = Some(std::mem::size_of::<SnapshotData>() + 64);
    records(output, |_, command, fd, path| {
        count = count.saturating_add(1);
        bytes = bytes
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OpenFile>()))
            .and_then(|bytes| bytes.checked_add(command.len()))
            .and_then(|bytes| bytes.checked_add(fd.len()))
            .and_then(|bytes| bytes.checked_add(path.len()));
    });
    if count == 0 || count > MAX_OPEN_FILES {
        return OpenFiles::default();
    }
    let Some(bytes) = bytes else {
        return OpenFiles::default();
    };
    let Ok(memory) = budget.reserve(bytes) else {
        return OpenFiles::default();
    };
    let mut files = Vec::new();
    if files.try_reserve_exact(count).is_err() {
        return OpenFiles::default();
    }
    records(output, |pid, command, fd, path| {
        files.push(OpenFile {
            pid,
            command: command.to_owned(),
            fd: fd.to_owned(),
            path: PathBuf::from(path),
        });
    });
    OpenFiles {
        data: Some(Arc::new(SnapshotData {
            files,
            _memory: memory,
        })),
    }
}

#[cfg(test)]
fn parse(output: &str) -> OpenFiles {
    parse_with_budget(output, &MemoryBudget::shared())
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
            &*files,
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
            .as_slice()
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
        assert!(parse("n/Users/dev/cubby\n").is_empty());
    }

    #[test]
    fn empty_output_yields_no_files() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn snapshot_clones_retain_the_reservation_without_copying() {
        let budget = MemoryBudget::new(1 << 20);
        let files = parse_with_budget(FIXTURE, &budget);
        let charged = budget.used();
        assert!(charged > 0);
        let clone = files.clone();
        assert_eq!(budget.used(), charged);
        assert!(Arc::ptr_eq(
            files.data.as_ref().unwrap(),
            clone.data.as_ref().unwrap()
        ));
        drop(files);
        assert_eq!(clone.len(), 4);
        assert_eq!(budget.used(), charged);
        drop(clone);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn denied_budget_or_record_limit_produces_no_allocation() {
        let budget = MemoryBudget::new(1);
        assert!(parse_with_budget(FIXTURE, &budget).data.is_none());
        assert_eq!(budget.peak(), 0);
        let budget = MemoryBudget::new(1 << 20);
        let output = format!("p1\ncnode\nfcwd\n{}", "n/tmp\n".repeat(MAX_OPEN_FILES + 1));
        assert!(parse_with_budget(&output, &budget).data.is_none());
        assert_eq!(budget.peak(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn every_invocation_fetches_a_fresh_snapshot() {
        let mut fixture = crate::attribution::testutil::EnvFixture::new();
        let user = std::env::var("USER").unwrap_or_default();
        fixture.runner = crate::runner::MockCommandRunner::new().on(
            "lsof",
            &["-a", "-u", &user, "-d", "^txt,^mem", "-F", "pcfn"],
            FIXTURE,
        );
        let env = fixture.env();
        let first = snapshot(&env);
        let second = snapshot(&env);
        assert_eq!(&*first, &*second);
        assert!(!Arc::ptr_eq(
            first.data.as_ref().unwrap(),
            second.data.as_ref().unwrap()
        ));
        assert_eq!(fixture.runner.calls().len(), 2);
    }
}
