//! `dobby` binary — thin `clap` dispatch + tracing setup.
//!
//! All command logic lives in the `dobby-cli` crate. This binary's
//! only jobs are:
//!   1. Parse argv.
//!   2. Initialise `tracing_subscriber` from `RUST_LOG` (defaulting to `info`).
//!   3. Hand the parsed command to `dobby_cli::dispatch`.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = dobby_cli::Cli::parse();
    dobby_cli::dispatch(cli).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}
