//! Subcommand modules. Each module owns its `*Args` struct (and any
//! nested `*Command` enum for further subcommands) plus a `pub async fn
//! run(...)` entry point.
//!
//! Every handler in Phase 1 returns `Err(anyhow!("unimplemented:
//! Phase N"))` until its phase lands. See issue #1 § CLI commands.

pub mod check;
pub mod destroy;
pub mod elf;
pub mod exec;
pub mod init;
pub mod keeper;
pub mod logs;
pub mod metrics;
pub mod pair;
pub mod push;
pub mod register;
pub mod rollback;
pub mod scale;
pub mod secrets;
pub mod status;
pub mod token;
pub mod update;
pub mod watch;

/// Helper returning a uniform `unimplemented` error with phase tag.
pub(crate) fn not_yet(phase: &str, what: &str) -> anyhow::Error {
    anyhow::anyhow!("unimplemented: {what} lands in {phase}")
}
