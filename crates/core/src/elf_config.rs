//! `elf.toml` — non-secret Elf configuration inside each managed LXC.
//!
//! Holds Keeper gRPC address, mTLS cert paths, per-service state,
//! `[uid_allocation]` for per-service system users. See issue #1
//! § State management / Supply chain hardening.
//!
//! Phase 1 goal: minimal skeleton so `dobby elf start` can read it.

use serde::{Deserialize, Serialize};

/// Non-secret configuration consumed by `dobby elf start`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfConfig {
    /// Keeper gRPC endpoint the Elf connects back to.
    pub keeper: KeeperAddress,
    /// Local filesystem paths to the CA, client certificate, and client key.
    pub tls: TlsPaths,
    // TODO(phase-2): services, uid_allocation, watcher state
}

/// Keeper network endpoint stored in `elf.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeeperAddress {
    /// DNS name or IP address of the Keeper gRPC listener.
    pub host: String,
    /// TCP port of the Keeper gRPC listener.
    pub port: u16,
}

/// mTLS material paths used by the Elf gRPC client/server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsPaths {
    /// CA certificate path used to trust the Keeper.
    pub ca: String,
    /// Elf certificate path presented to Keeper.
    pub cert: String,
    /// Elf private-key path paired with `cert`.
    pub key: String,
}
