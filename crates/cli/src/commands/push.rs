//! `dobby push` — deploy an artefact. Either a GitHub Release tag or a
//! local file. See issue #1 § Deploy flow (detailed).

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("source").required(true).multiple(false)))]
pub struct PushArgs {
    /// App name.
    pub name: String,

    /// GitHub Release tag to deploy from.
    #[arg(long, value_name = "TAG", group = "source")]
    pub release: Option<String>,

    /// Local artefact path to upload.
    #[arg(long, value_name = "PATH", group = "source")]
    pub artifact: Option<std::path::PathBuf>,

    /// Restrict deploy to a single service (required with `--artifact`
    /// for multi-service apps; optional with `--release`).
    #[arg(long, value_name = "SVC")]
    pub service: Option<String>,
}

pub async fn run(_args: PushArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 2", "dobby push"))
}
