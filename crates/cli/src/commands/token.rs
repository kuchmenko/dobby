//! `dobby token ...` — scoped CI tokens. Phase 4+.

use clap::{Args, Subcommand};

use super::not_yet;

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Create a new scoped Bearer token.
    Create(CreateArgs),
    /// List existing tokens (fingerprints only).
    List,
    /// Revoke a token by fingerprint or label.
    Revoke(RevokeArgs),
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Human-readable label.
    pub name: String,

    /// Token scope (e.g. `push:mm-eh`, `status`, `watch`).
    #[arg(long, value_name = "SCOPE")]
    pub scope: String,
}

#[derive(Debug, Args)]
pub struct RevokeArgs {
    pub name_or_fingerprint: String,
}

pub async fn run(cmd: TokenCommand) -> anyhow::Result<()> {
    let phase = "Phase 4";
    match cmd {
        TokenCommand::Create(_) => Err(not_yet(phase, "dobby token create")),
        TokenCommand::List => Err(not_yet(phase, "dobby token list")),
        TokenCommand::Revoke(_) => Err(not_yet(phase, "dobby token revoke")),
    }
}
