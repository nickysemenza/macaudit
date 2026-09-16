//! Time a walk of one root and print its totals.
//!
//!     cargo run --release --example walk_bench -- ~ [--stat]
//!
//! `--stat` forces the portable `read_dir` + `lstat` listing so the
//! `getattrlistbulk` fast path can be A/B'd on the same tree.
use macaudit::scan::walk::{walk, NoVisitor, WalkOptions};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let mut root: Option<PathBuf> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--stat" => macaudit::scan::walk::listing::force_stat(true),
            other => root = Some(PathBuf::from(other)),
        }
    }
    let root = root.unwrap_or_else(|| std::env::home_dir().expect("home"));
    let started = Instant::now();
    let r = walk(
        &root,
        WalkOptions {
            top_n: 10,
            ..WalkOptions::default()
        },
        &NoVisitor,
        None,
        &|| false,
    );
    let elapsed = started.elapsed();
    let rss = peak_rss_mb();
    println!(
        "{}: {} files, {} dirs, {:.2} GiB alloc ({:.2} GiB apparent), {} errors, {} entries, complete={}",
        root.display(),
        r.root.files,
        r.root.dirs,
        r.root.alloc as f64 / (1u64 << 30) as f64,
        r.root.apparent as f64 / (1u64 << 30) as f64,
        r.root.errors,
        r.entries,
        r.complete,
    );
    println!(
        "{:.2}s, {:.0} entries/s, peak RSS {rss} MB",
        elapsed.as_secs_f64(),
        r.entries as f64 / elapsed.as_secs_f64()
    );
    for f in &r.top_files {
        println!(
            "  {:>10.2} MiB  {}",
            f.alloc as f64 / (1u64 << 20) as f64,
            f.path.display()
        );
    }
}

fn peak_rss_mb() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    // macOS reports ru_maxrss in bytes.
    ru.ru_maxrss as u64 / (1 << 20)
}
