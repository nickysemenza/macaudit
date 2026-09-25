//! The internal FsScanner → GitScanner channel.
//!
//! The engine creates the pair and injects the ends via `ScanCtx` (FsScanner
//! gets `repo_tx`, GitScanner gets `repo_rx`) so neither scanner invents its own
//! type. Semantics:
//!
//! - FsScanner sends one `RepoDiscovery` per `.git` directory it finds, then
//!   drops `repo_tx` when its walk completes.
//! - GitScanner loops `recv().await` until the channel closes (`None`), which is
//!   guaranteed once FsScanner finishes (or if FsScanner isn't running this scan,
//!   the engine drops the sender immediately so GitScanner sees an empty stream).

use std::path::PathBuf;

use tokio::sync::mpsc;

/// A git repository discovered by the filesystem walk. `root` is the repo's
/// working-directory root (the parent of `.git`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoDiscovery {
    pub root: PathBuf,
}

pub type RepoSender = mpsc::UnboundedSender<RepoDiscovery>;
pub type RepoReceiver = mpsc::UnboundedReceiver<RepoDiscovery>;

/// Create the repo-discovery channel. Deliberately **unbounded**: the walker
/// sends from rayon threads, and GitScanner sizes each repo's `.git` with the
/// same walker on the same global rayon pool. With a bounded channel, a full
/// pipe parks every rayon thread in `send` while GitScanner's `du` waits for
/// a rayon thread to free up — a deadlock whenever the size cache is cold.
/// Repo counts are in the hundreds, so buffering them all is free.
pub fn repo_channel() -> (RepoSender, RepoReceiver) {
    mpsc::unbounded_channel()
}
