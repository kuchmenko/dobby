//! Loading the persistent Keeper configuration written by
//! `dobby keeper init` and held under `<dir>/keeper.toml`.
//!
//! This module is a thin wrapper over `dobby_core::keeper_config`'s
//! parser — it adds the disk-IO step and uniform error reporting so
//! every failure mode mentions the path. The schema itself stays in
//! the core crate.

use std::path::{Path, PathBuf};

use dobby_core::keeper_config::KeeperConfig;

/// Errors loading `keeper.toml`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read the file from disk (missing, permission denied, …).
    #[error("reading keeper config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// File present but its TOML schema is malformed.
    #[error("parsing keeper config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Read `<dir>/keeper.toml` into a typed [`KeeperConfig`].
pub fn load(dir: &Path) -> Result<KeeperConfig, ConfigError> {
    let path = dir.join("keeper.toml");
    let raw = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
        path: path.clone(),
        source,
    })?;
    KeeperConfig::from_toml(&raw).map_err(|source| ConfigError::Parse {
        path: path.clone(),
        source,
    })
}

#[cfg(test)]
mod tests;
