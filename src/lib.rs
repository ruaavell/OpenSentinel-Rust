//! OpenSentinel — lightweight, open-source antivirus scanner (Rust).
//!
//! Public library facade. The CLI binary (`main.rs`) and the integration
//! tests both link against this crate.

mod config;
mod detection;
mod error;
mod quarantine;
mod scanner;

pub use config::{Config, HeuristicSensitivity};
pub use detection::{load_signatures, Classification, Detection, Engine, Severity};
pub use error::{Error, ErrorKind, Result};
pub use quarantine::{
    list_quarantined, quarantine_add, quarantine_purge, quarantine_restore, QuarantineEntry,
};
pub use scanner::{hash_file, hash_stream, scan_paths, FileResult, Summary};

/// Construct an engine from an explicit config (used by the CLI and tests).
pub fn build_engine(cfg: &Config) -> Result<Engine> {
    detection::Engine::new(cfg)
}

/// Count outcomes in a result list.
pub fn summary_counts(results: &[FileResult]) -> SummaryCounts {
    let mut c = SummaryCounts::default();
    for r in results {
        match r {
            FileResult::Clean(_) => c.clean += 1,
            FileResult::Detected(_) => c.detected += 1,
            FileResult::Suspicious(_) => c.suspicious += 1,
            FileResult::Error(_) => c.errors += 1,
            FileResult::Skipped(_) => c.skipped += 1,
        }
    }
    c
}

#[derive(Default, Debug, Clone, Copy)]
pub struct SummaryCounts {
    pub clean: usize,
    pub detected: usize,
    pub suspicious: usize,
    pub errors: usize,
    pub skipped: usize,
}
