use std::net::{IpAddr, Ipv4Addr};

use super::*;

fn write_minimal_keeper_toml(dir: &Path) {
    let toml = r#"
[network]
bridge = "vmbr0"
subnet = "10.0.0.0/24"
static_range = "10.0.0.200-10.0.0.250"
keeper_ip = "10.0.0.50"
gateway = "10.0.0.1"
dns_upstream = "1.1.1.1"
"#;
    std::fs::write(dir.join("keeper.toml"), toml).unwrap();
}

#[test]
fn loads_well_formed_config() {
    let tmp = tempfile::tempdir().unwrap();
    write_minimal_keeper_toml(tmp.path());
    let cfg = load(tmp.path()).unwrap();
    assert_eq!(
        cfg.network.keeper_ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))
    );
    assert_eq!(cfg.network.bridge, "vmbr0");
}

#[test]
fn read_error_carries_path() {
    let tmp = tempfile::tempdir().unwrap();
    let err = load(tmp.path()).unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, ConfigError::Read { .. }));
    assert!(msg.contains("keeper.toml"), "msg = {msg}");
}

#[test]
fn parse_error_carries_path() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("keeper.toml"), b"this is not toml ===").unwrap();
    let err = load(tmp.path()).unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, ConfigError::Parse { .. }));
    assert!(msg.contains("keeper.toml"), "msg = {msg}");
}
