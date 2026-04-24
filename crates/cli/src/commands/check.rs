//! `dobby check` — validate `dobby.toml` locally (no Keeper required) or
//! with `--remote` to cross-check against Keeper state. See issue #1 §
//! Config validation.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Also validate against Keeper (duplicate app name, `${VAR}` targets).
    #[arg(long)]
    pub remote: bool,

    /// Machine-readable JSON output for CI.
    #[arg(long)]
    pub json: bool,
}

pub async fn run(_args: CheckArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 2", "dobby check"))
}
