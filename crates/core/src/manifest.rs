//! `dobby.toml` — the per-app deployment manifest.
//!
//! Shape matches issue #1 § dobby.toml — deployment manifest. Every
//! section is a distinct strongly-typed struct; `serde(deny_unknown_fields)`
//! on every struct turns typos into parse errors, not silent ignores
//! (matches the project's explicit-config preference).
//!
//! Parse is pure structural. Cycle detection, cross-reference validation,
//! and `${VAR}` interpolation of secret keys are separate concerns
//! (see `dobby check` and the secrets subsystem).
//!
//! Smart defaults (artifact name, binary path, health endpoint, …) are
//! applied AFTER parsing by [`Manifest::apply_defaults`] — keeps `parse`
//! honest about what was in the file versus what the convention layer
//! filled in.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ── entry point ──────────────────────────────────────────────────────────

/// Parse errors from `dobby.toml`.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// Failed to read the file from disk.
    #[error("reading manifest {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Failed to parse as TOML / apply struct schema.
    #[error("parsing manifest {path:?}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Parse a manifest from disk without applying smart defaults.
pub fn parse_file(path: &Path) -> Result<Manifest, ManifestError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ManifestError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_str(&raw, path)
}

/// Parse a manifest from a string. `path` is only used to label errors.
pub fn parse_str(raw: &str, path: &Path) -> Result<Manifest, ManifestError> {
    toml::from_str(raw).map_err(|e| ManifestError::Toml {
        path: path.to_path_buf(),
        source: e,
    })
}

// ── top-level ────────────────────────────────────────────────────────────

/// A parsed per-app manifest. Section ordering follows the issue body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub app: AppSection,

    #[serde(default)]
    pub container: Option<ContainerSection>,

    /// Shared environment variables. Each service opts in by name via
    /// `env_from`; there is no implicit broadcast.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,

    /// Service declarations — keyed by logical service name.
    #[serde(default)]
    pub services: BTreeMap<String, Service>,

    /// Explicit reverse-proxy route table. Only services listed here
    /// get a `<domain>.<app>.dobby` route.
    #[serde(default)]
    pub proxy: BTreeMap<String, ProxyEntry>,

    /// Per-service health-check overrides. Services without an entry
    /// use the cgroup-based process-alive default.
    #[serde(default)]
    pub health: BTreeMap<String, HealthEntry>,

    /// Per-service sandbox overrides. Services without an entry get
    /// the default FS + proc isolation (no network restriction).
    #[serde(default)]
    pub sandbox: BTreeMap<String, SandboxEntry>,
}

// ── [app] ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AppSection {
    pub name: String,
    /// `owner/repo` on GitHub.
    pub repo: String,

    /// Deploy trigger: `release` (default), `branch:<name>`, or none
    /// (manual `dobby push` only).
    #[serde(default)]
    pub trigger: Option<String>,

    /// Watcher poll interval (default `5m` when a trigger is set).
    #[serde(default)]
    pub interval: Option<String>,
}

// ── [container] ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContainerSection {
    pub template: String,
    pub cores: u32,
    /// Memory limit in MiB.
    pub memory: u32,
    /// Root-disk size in GiB.
    pub disk: u32,
}

// ── [services.<name>] ────────────────────────────────────────────────────

/// Service type. `None` ⇒ binary-from-repo (the default).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    /// Binary artefact built from this repo and deployed by Release Watcher.
    #[default]
    Binary,
    /// Pre-existing resource registered via `dobby register` (DNS-resolved, never modified).
    External,
    /// OCI image run under the native runtime (Phase 3).
    Container,
    /// apt-installed package managed by the native systemd unit.
    System,
}

/// A `[services.<name>]` block. Many fields are type-specific; the
/// `ServiceKind` enum gates which combinations are legal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Service {
    /// Service type. Absent in TOML means `binary`.
    #[serde(default, rename = "type")]
    pub kind: ServiceKind,

    // ── binary-only ────────────────────────────────────────────────────
    /// Override the artefact file name. Default: the service key.
    #[serde(default)]
    pub artifact: Option<String>,

    /// Override the systemd `ExecStart=`. Default:
    /// `/opt/<app>/<service>/current/<artifact>`.
    #[serde(default)]
    pub exec_start: Option<String>,

    // ── external-only ─────────────────────────────────────────────────
    /// External host (e.g. `postgres.dobby`).
    #[serde(default)]
    pub host: Option<String>,

    /// External port.
    #[serde(default)]
    pub port: Option<u16>,

    // ── container-only ────────────────────────────────────────────────
    /// OCI image reference (e.g. `prom/prometheus:latest`).
    #[serde(default)]
    pub image: Option<String>,

    /// Bind-mounts passed to the native runtime in `src:dst` form.
    #[serde(default)]
    pub volumes: Vec<String>,

    // ── system-only ───────────────────────────────────────────────────
    /// apt package name for `type = "system"`.
    #[serde(default)]
    pub package: Option<String>,

    // ── shared ────────────────────────────────────────────────────────
    /// Ports the service listens on. First entry is the proxy default.
    /// Binary services use integer form (e.g. `9100`); container
    /// services may use `"host:container"` mapping strings — the enum
    /// accepts either without ceremony.
    #[serde(default)]
    pub ports: Vec<PortSpec>,

    /// Start order gate: do not start this service until every listed
    /// dependency reports healthy.
    #[serde(default)]
    pub depends: Vec<String>,

    /// Opt-in subset of `[environment]` to inject into this service.
    #[serde(default)]
    pub env_from: Vec<String>,

    /// Service-specific literals (`KEY = "val"`) and interpolated
    /// secrets (`KEY = "${VAR}"`). Merged on top of `env_from`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,

    /// Per-service memory ceiling (MiB). Maps to systemd `MemoryMax=`.
    #[serde(default)]
    pub memory: Option<u32>,

    /// Per-service CPU ceiling (fractional cores). Maps to `CPUQuota=`.
    #[serde(default)]
    pub cpu: Option<f64>,

    /// systemd `Restart=` policy. Default `always`.
    #[serde(default)]
    pub restart: Option<RestartPolicy>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    #[default]
    Always,
    OnFailure,
    Never,
}

/// A port declaration. TOML: integer → [`PortSpec::Single`], string →
/// [`PortSpec::Mapping`]. The mapping form is only meaningful for
/// `type = "container"` services and conventionally takes `"host:container"`
/// form — semantic validation lives in `dobby check`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum PortSpec {
    Single(u16),
    Mapping(String),
}

impl PortSpec {
    /// The port number on the container / LXC interior that the service
    /// actually binds to. For mapping strings (`"host:container"`) this
    /// is the part after the colon.
    pub fn container_port(&self) -> Option<u16> {
        match self {
            Self::Single(p) => Some(*p),
            Self::Mapping(s) => s.split(':').next_back().and_then(|v| v.parse().ok()),
        }
    }
}

// ── [proxy.<name>] ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProxyEntry {
    /// Hostname segment — e.g. `domain = "explorer"` serves
    /// `explorer.<app>.dobby`.
    pub domain: String,
    /// Upstream port. Must be one of the service's `ports`; enforced by
    /// `dobby check` cross-validation, not at parse time.
    pub port: u16,
}

// ── [health.<name>] ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HealthEntry {
    /// HTTP GET path (e.g. `"/health"`). Mutually exclusive with `exec`.
    #[serde(default)]
    pub http: Option<String>,

    /// Explicit health-check port. Default: first entry in service's `ports`.
    #[serde(default)]
    pub port: Option<u16>,

    /// Shell command that must exit 0. Mutually exclusive with `http`.
    #[serde(default)]
    pub exec: Option<String>,

    /// Poll interval (e.g. `"15s"`). Default `30s`.
    #[serde(default)]
    pub interval: Option<String>,
}

// ── [sandbox.<name>] ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SandboxEntry {
    /// Network policy. `"restricted"` enables `IPAddressDeny=any` with an
    /// allowlist auto-derived from `depends` + `network_allow`.
    #[serde(default)]
    pub network: Option<String>,

    /// Additional `host:port` entries to permit when `network =
    /// "restricted"`. External dependencies live here.
    #[serde(default)]
    pub network_allow: Vec<String>,

    /// Additional writable paths (default: only the service's state dir).
    #[serde(default)]
    pub writable: Vec<String>,

    /// Disable `ProtectProc=invisible`. Needed for monitoring tools
    /// that read `/proc` broadly (e.g. node-exporter).
    #[serde(default)]
    pub protect_proc: Option<bool>,
}

// ── smart defaults ───────────────────────────────────────────────────────

/// Default watcher trigger applied when `[app].trigger` is absent.
pub const DEFAULT_TRIGGER: &str = "release";

/// Default watcher poll interval applied when `[app].interval` is absent.
pub const DEFAULT_INTERVAL: &str = "5m";

impl Manifest {
    /// Apply convention-over-configuration defaults in-place.
    ///
    /// Called by consumers that want post-parse values ready for
    /// systemd-unit generation / DNS registration / watcher setup.
    /// Keeps the raw parse tree honest (the result of `parse_str` only
    /// reflects what was literally in the TOML).
    ///
    /// App-level defaults applied here:
    /// - `trigger` → [`DEFAULT_TRIGGER`] when absent
    /// - `interval` → [`DEFAULT_INTERVAL`] when absent
    pub fn apply_defaults(&mut self) {
        apply_app_defaults(&mut self.app);
        let app = self.app.name.clone();
        for (svc_name, svc) in &mut self.services {
            apply_service_defaults(&app, svc_name, svc);
        }
    }
}

fn apply_app_defaults(app: &mut AppSection) {
    if app.trigger.is_none() {
        app.trigger = Some(DEFAULT_TRIGGER.to_owned());
    }
    if app.interval.is_none() {
        app.interval = Some(DEFAULT_INTERVAL.to_owned());
    }
}

fn apply_service_defaults(app: &str, name: &str, svc: &mut Service) {
    match svc.kind {
        ServiceKind::Binary => {
            if svc.artifact.is_none() {
                svc.artifact = Some(name.to_owned());
            }
            if svc.exec_start.is_none() {
                let artifact = svc
                    .artifact
                    .as_deref()
                    .expect("artifact was just populated above");
                svc.exec_start = Some(format!("/opt/{app}/{name}/current/{artifact}"));
            }
            if svc.restart.is_none() {
                svc.restart = Some(RestartPolicy::Always);
            }
        }
        ServiceKind::Container | ServiceKind::System | ServiceKind::External => {
            if svc.restart.is_none() && !matches!(svc.kind, ServiceKind::External) {
                svc.restart = Some(RestartPolicy::Always);
            }
        }
    }
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
