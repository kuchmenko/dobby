//! `dobby pair` — workstation pairs with a Keeper via mDNS (LAN) or an
//! explicit address (remote / hostile LAN). `--fingerprint` skips TOFU
//! and aborts on mismatch. See issue #1 § Network discovery (mDNS) and
//! Authentication.

use clap::Args;

use super::not_yet;

#[derive(Debug, Args)]
pub struct PairArgs {
    /// Explicit Keeper address (`host:port`). Omit to auto-discover via mDNS.
    pub address: Option<String>,

    /// One-time bootstrap token from `dobby keeper init`.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Expected TLS cert SHA-256 fingerprint. Skips the TOFU prompt.
    #[arg(long, value_name = "SHA256")]
    pub fingerprint: Option<String>,
}

pub async fn run(_args: PairArgs) -> anyhow::Result<()> {
    Err(not_yet("Phase 1", "dobby pair"))
}
