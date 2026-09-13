//! The one tokio runtime behind every FFI call.
//!
//! `ScannerManager::start` and `cleanup::run_batch` spawn tasks, so they need
//! a runtime context; the app has none of its own. A process-global runtime
//! that is never dropped sidesteps `Runtime::drop` semantics (it blocks on
//! outstanding blocking tasks and panics when dropped from inside a runtime
//! thread — which is exactly where the last `Arc<Engine>` could be released,
//! via a listener callback).

use std::sync::OnceLock;

use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("macaudit")
            .build()
            .expect("tokio runtime")
    })
}
