use std::net::{IpAddr, Ipv4Addr};

use dobby_core::keeper_init;

use super::*;

fn keeper_init_request(dir: &Path) -> keeper_init::Request {
    keeper_init::Request {
        dir: dir.to_path_buf(),
        keeper_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
        gateway: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dns_upstream: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        subnet: "10.0.0.0/24".into(),
        static_range: "10.0.0.200-10.0.0.250".into(),
        bridge: "vmbr0".into(),
        force: false,
    }
}

#[test]
fn loads_identity_from_init_layout() {
    let tmp = tempfile::tempdir().unwrap();
    keeper_init::init(&keeper_init_request(tmp.path())).unwrap();
    // Should not panic / error — Identity::from_pem accepts the
    // exact output rcgen produces in keeper_init::tls.
    load_server_tls(tmp.path()).unwrap();
}

#[test]
fn missing_cert_reports_path() {
    let tmp = tempfile::tempdir().unwrap();
    let err = load_server_tls(tmp.path()).unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, TlsError::ReadCert { .. }));
    assert!(msg.contains("host.crt"), "msg = {msg}");
}

#[test]
fn missing_key_reports_path() {
    let tmp = tempfile::tempdir().unwrap();
    // Make tls/ + only the cert, leave the key absent.
    std::fs::create_dir_all(tmp.path().join("tls")).unwrap();
    std::fs::write(
        tmp.path().join("tls/host.crt"),
        b"-----BEGIN CERTIFICATE-----\n",
    )
    .unwrap();

    let err = load_server_tls(tmp.path()).unwrap_err();
    let msg = err.to_string();
    assert!(matches!(err, TlsError::ReadKey { .. }));
    assert!(msg.contains("host.key"), "msg = {msg}");
}
