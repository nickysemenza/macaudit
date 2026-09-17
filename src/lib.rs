//! macaudit — a "why is my Mac like this" audit engine.
//!
//! The library holds everything except terminal setup, so `macaudit scan --json`
//! and the test suite exercise the exact same engine the TUI drives (spec §5).

pub mod attribution;
pub mod brewgraph;
pub mod cleanup;
pub mod cli;
pub mod config;
pub mod correlate;
pub mod engine;
pub mod fake;
pub mod model;
pub mod net;
pub mod output;
pub mod registry;
pub mod remedy;
pub mod runner;
pub mod scan;
pub mod size_cache;
#[cfg(feature = "tui")]
pub mod ui;
