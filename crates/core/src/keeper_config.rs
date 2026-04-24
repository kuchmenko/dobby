//! `keeper.toml` — non-secret Keeper configuration on the Keeper LXC.
//!
//! Holds `[proxmox]`, `[network]` (incl. `keeper_ip`), `[registry]`,
//! `[watcher.<app>]`, `[timeouts]`, `[logging]`, `[dns]`, `[backup]`,
//! `[secrets]`. See issue #1 § State management.
//!
//! Phase 1 goal: round-trip skeleton written by `dobby keeper init`
//! with `[network].keeper_ip` populated from the observed eth0 IP.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeeperConfig {
    pub network: Network,
    // TODO(phase-1): proxmox, registry, watcher, dns, timeouts, backup, ...
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub bridge: String,
    pub subnet: String,
    pub static_range: String,
    pub keeper_ip: String,
    pub gateway: String,
    #[serde(default = "default_dns_upstream")]
    pub dns_upstream: String,
}

fn default_dns_upstream() -> String {
    "1.1.1.1".to_owned()
}
