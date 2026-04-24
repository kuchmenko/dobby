//! `dobby.toml` — the per-app deployment manifest.
//!
//! Defined by: `[app]`, `[container]`, `[environment]`, `[services.*]`,
//! `[proxy.*]`, `[health.*]`, `[sandbox.*]` sections. See issue #1
//! § dobby.toml — deployment manifest.
//!
//! Phase 1 goal: round-trip parsing of both sample manifests from the
//! issue (koban single-service, mm-eh multi-service) into typed Rust.

use serde::{Deserialize, Serialize};

/// Top-level manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub app: AppSection,
    // TODO(phase-1): container, environment, services, proxy, health, sandbox
}

/// `[app]` — identity and deploy trigger configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSection {
    pub name: String,
    pub repo: String,
    #[serde(default)]
    pub trigger: Option<String>,
    #[serde(default)]
    pub interval: Option<String>,
}
