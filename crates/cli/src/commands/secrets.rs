//! `dobby secrets ...` — per-app secret management with version history.

use clap::{Args, Subcommand};

use super::not_yet;

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// Set (or bump version of) a secret key. Format: `KEY=VALUE`.
    Set(SetArgs),

    /// Bulk import from a `.env`-style file.
    Import(ImportArgs),

    /// List secret keys for an app (values masked).
    List(AppArgs),

    /// Delete a secret key (all versions).
    Delete(DeleteArgs),

    /// Print version history for a key.
    History(KeyArgs),

    /// Atomic pointer swap to a previous version.
    Rollback(RollbackArgs),

    /// Enforce `keep_versions` retention per key.
    Gc(GcArgs),
}

#[derive(Debug, Args)]
pub struct AppArgs {
    pub app: String,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    pub app: String,
    /// `KEY=VALUE` pair.
    pub kv: String,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    pub app: String,
    /// Path to `.env` file.
    pub file: std::path::PathBuf,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    pub app: String,
    pub key: String,
}

#[derive(Debug, Args)]
pub struct KeyArgs {
    pub app: String,
    pub key: String,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    pub app: String,
    pub key: String,
    /// Version number to restore (e.g. `v2`).
    #[arg(long = "to", value_name = "VERSION")]
    pub to: String,
}

#[derive(Debug, Args)]
pub struct GcArgs {
    pub app: String,
    /// Override the default `keep_versions` from `keeper.toml`.
    #[arg(long)]
    pub keep: Option<u32>,
}

pub async fn run(cmd: SecretsCommand) -> anyhow::Result<()> {
    let phase = "Phase 2";
    match cmd {
        SecretsCommand::Set(_) => Err(not_yet(phase, "dobby secrets set")),
        SecretsCommand::Import(_) => Err(not_yet(phase, "dobby secrets import")),
        SecretsCommand::List(_) => Err(not_yet(phase, "dobby secrets list")),
        SecretsCommand::Delete(_) => Err(not_yet(phase, "dobby secrets delete")),
        SecretsCommand::History(_) => Err(not_yet(phase, "dobby secrets history")),
        SecretsCommand::Rollback(_) => Err(not_yet(phase, "dobby secrets rollback")),
        SecretsCommand::Gc(_) => Err(not_yet(phase, "dobby secrets gc")),
    }
}
