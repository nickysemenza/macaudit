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

pub type RepoSender = mpsc::Sender<RepoDiscovery>;
pub type RepoReceiver = mpsc::Receiver<RepoDiscovery>;

/// Create a bounded repo-discovery channel. Bounded so a slow GitScanner exerts
/// backpressure on the walker rather than buffering unboundedly.
pub fn repo_channel() -> (RepoSender, RepoReceiver) {
    mpsc::channel(256)
}
