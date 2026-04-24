//! `elf.toml` — non-secret Elf configuration inside each managed LXC.
//!
//! Holds Keeper gRPC address, mTLS cert paths, per-service state,
//! `[uid_allocation]` for per-service system users. See issue #1
//! § State management / Supply chain hardening.
//!
//! Phase 1 goal: minimal skeleton so `dobby elf start` can read it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfConfig {
    pub keeper: KeeperAddress,
    pub tls: TlsPaths,
    // TODO(phase-2): services, uid_allocation, watcher state
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeeperAddress {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsPaths {
    pub ca: String,
    pub cert: String,
    pub key: String,
}
