//! `keeper.toml` — non-secret Keeper configuration on the Keeper LXC.
//!
//! Holds `[proxmox]`, `[network]` (incl. `keeper_ip`), `[registry]`,
//! `[watcher.<app>]`, `[timeouts]`, `[logging]`, `[dns]`, `[backup]`,
//! `[secrets]`. See issue #1 § State management.
//!
//! Phase 1 deliverable: the `[network]` section populated by
//! `dobby keeper init`. Other sections are added as their owning
//! subsystems land.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Top-level Keeper configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeeperConfig {
    pub network: Network,
    // TODO(phase-1+): proxmox, registry, watcher, dns, timeouts, backup, ...
}

/// `[network]` — subnet, bridge, allocation range, Keeper's own IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Proxmox bridge name (`vmbr0` by convention).
    pub bridge: String,
    /// LAN subnet in CIDR form (e.g. `10.0.0.0/24`).
    pub subnet: String,
    /// Pool of IPs `dobby init` allocates from for managed LXCs,
    /// expressed as `first-last` (e.g. `10.0.0.200-10.0.0.250`).
    /// Must lie outside any DHCP pool on the LAN.
    pub static_range: String,
    /// Keeper LXC's own static IP — set once by the operator, never
    /// reallocated. Must sit OUTSIDE `static_range` to avoid
    /// collisions with init-allocated IPs. See issue #1 § Network
    /// configuration.
    pub keeper_ip: IpAddr,
    /// LAN gateway — the router on `bridge`.
    pub gateway: IpAddr,
    /// Upstream DNS forwarded to for non-`.dobby` queries.
    #[serde(default = "default_dns_upstream")]
    pub dns_upstream: IpAddr,
}

fn default_dns_upstream() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))
}

impl KeeperConfig {
    /// Serialise to TOML string for disk persistence.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Parse a `keeper.toml` blob.
    pub fn from_toml(raw: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(raw)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn sample() -> KeeperConfig {
        KeeperConfig {
            network: Network {
                bridge: "vmbr0".into(),
                subnet: "10.0.0.0/24".into(),
                static_range: "10.0.0.200-10.0.0.250".into(),
                keeper_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
                gateway: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dns_upstream: default_dns_upstream(),
            },
        }
    }

    #[test]
    fn round_trip_toml() {
        let c = sample();
        let s = c.to_toml().unwrap();
        let back = KeeperConfig::from_toml(&s).unwrap();
        assert_eq!(c.network.keeper_ip, back.network.keeper_ip);
        assert_eq!(c.network.gateway, back.network.gateway);
        assert_eq!(c.network.bridge, back.network.bridge);
    }

    #[test]
    fn toml_uses_string_form_for_ips() {
        let s = sample().to_toml().unwrap();
        // IPs should appear as quoted strings — TOML has no native IP.
        assert!(s.contains("keeper_ip = \"10.0.0.50\""), "toml: {s}");
        assert!(s.contains("gateway = \"10.0.0.1\""), "toml: {s}");
    }

    #[test]
    fn rejects_unknown_fields() {
        let src = r#"
            [network]
            bridge = "vmbr0"
            subnet = "10.0.0.0/24"
            static_range = "10.0.0.200-10.0.0.250"
            keeper_ip = "10.0.0.50"
            gateway = "10.0.0.1"
            bogus = "nope"
        "#;
        assert!(KeeperConfig::from_toml(src).is_err());
    }

    #[test]
    fn dns_upstream_defaults_to_cloudflare() {
        let src = r#"
            [network]
            bridge = "vmbr0"
            subnet = "10.0.0.0/24"
            static_range = "10.0.0.200-10.0.0.250"
            keeper_ip = "10.0.0.50"
            gateway = "10.0.0.1"
        "#;
        let c = KeeperConfig::from_toml(src).unwrap();
        assert_eq!(c.network.dns_upstream, default_dns_upstream());
    }
}
