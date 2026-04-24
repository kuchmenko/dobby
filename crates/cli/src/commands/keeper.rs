//! `dobby keeper ...` — Keeper daemon lifecycle, bootstrap, backup, restore,
//! fingerprint display, key rotation. See issue #1 § CLI commands → Setup.

use clap::{Args, Subcommand};

use super::not_yet;

/// `dobby keeper <sub>` subcommands.
#[derive(Debug, Subcommand)]
pub enum KeeperCommand {
    /// Generate TLS CA + host cert, age keypair, bootstrap token; write
    /// skeleton `keeper.toml`; prompt for Proxmox API token, GitHub OAuth
    /// Device Flow, and backup passphrase. Runs once per Keeper LXC.
    Init(InitArgs),

    /// Start the Keeper daemon (tonic gRPC server + mDNS + embedded DNS).
    Start(StartArgs),

    /// Print the Keeper's TLS cert SHA-256 fingerprint for out-of-band
    /// pairing over an already-authenticated channel.
    ShowFingerprint,

    /// Rotate the Proxmox API token stored under
    /// `/etc/dobby/secrets/_system/proxmox_token.age`.
    SetProxmoxToken,

    /// Authenticate with GitHub via OAuth Device Flow (dobby3000 App).
    #[command(subcommand)]
    Auth(AuthProvider),

    /// Create a passphrase-encrypted archive of `/etc/dobby/`.
    Backup(BackupArgs),

    /// Restore from a passphrase-encrypted archive.
    Restore(RestoreArgs),

    /// Re-push dobby binary + re-issue mTLS cert to an existing LXC.
    Rebootstrap(RebootstrapArgs),

    /// Rotate the age master key (atomic shadow-directory swap).
    RotateSecretsKey,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Assume 'yes' to interactive prompts (non-interactive provisioning).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct StartArgs {}

#[derive(Debug, Subcommand)]
pub enum AuthProvider {
    /// GitHub OAuth Device Flow (required for Release Watcher).
    Github,
}

#[derive(Debug, Args)]
pub struct BackupArgs {
    /// Read passphrase from this env var.
    #[arg(long, value_name = "VAR", group = "passphrase")]
    pub passphrase_env: Option<String>,
    /// Read plaintext passphrase from this file.
    #[arg(long, value_name = "PATH", group = "passphrase")]
    pub passphrase_file: Option<std::path::PathBuf>,
    /// Read passphrase from stdin.
    #[arg(long, group = "passphrase")]
    pub passphrase_stdin: bool,
    /// Read age-ciphertext passphrase from a systemd credentials file.
    #[arg(long, value_name = "PATH", group = "passphrase")]
    pub passphrase_credentials_file: Option<std::path::PathBuf>,
    /// Raw passphrase (visible in `ps` — only for tests / escape hatch).
    #[arg(long, value_name = "VALUE", group = "passphrase")]
    pub passphrase: Option<String>,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// Path to the encrypted archive produced by `dobby keeper backup`.
    pub archive: std::path::PathBuf,
    /// Overwrite an existing non-empty `/etc/dobby/` tree.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RebootstrapArgs {
    /// App name of the managed LXC to rebootstrap.
    pub app: String,
}

pub async fn run(cmd: KeeperCommand) -> anyhow::Result<()> {
    match cmd {
        KeeperCommand::Init(_) => Err(not_yet("Phase 1", "dobby keeper init")),
        KeeperCommand::Start(_) => Err(not_yet("Phase 1", "dobby keeper start")),
        KeeperCommand::ShowFingerprint => Err(not_yet("Phase 1", "dobby keeper show-fingerprint")),
        KeeperCommand::SetProxmoxToken => Err(not_yet("Phase 1", "dobby keeper set-proxmox-token")),
        KeeperCommand::Auth(AuthProvider::Github) => {
            Err(not_yet("Phase 1", "dobby keeper auth github"))
        }
        KeeperCommand::Backup(_) => Err(not_yet("Phase 2", "dobby keeper backup")),
        KeeperCommand::Restore(_) => Err(not_yet("Phase 2", "dobby keeper restore")),
        KeeperCommand::Rebootstrap(_) => Err(not_yet("Phase 2", "dobby keeper rebootstrap")),
        KeeperCommand::RotateSecretsKey => {
            Err(not_yet("Phase 4", "dobby keeper rotate-secrets-key"))
        }
    }
}
