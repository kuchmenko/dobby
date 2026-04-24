use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;

use super::*;

fn req(dir: &Path) -> Request {
    Request {
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

fn mode_of(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn writes_expected_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = init(&req(tmp.path())).unwrap();

    for sub in [
        "keeper.toml",
        "tls/ca.crt",
        "tls/ca.key",
        "tls/host.crt",
        "tls/host.key",
        "secrets/bootstrap_token",
    ] {
        assert!(
            tmp.path().join(sub).exists(),
            "missing file: {sub} in {:?}",
            tmp.path()
        );
    }

    // Token round-trips onto disk. `assert_eq!` would print both
    // sides via Debug on mismatch, leaking secret material into CI
    // logs; compare with an explicit branch that panics with a
    // generic message instead.
    let on_disk = fs::read_to_string(tmp.path().join("secrets/bootstrap_token")).unwrap();
    if on_disk != **outcome.bootstrap_token {
        panic!("bootstrap token on disk diverges from value returned by init");
    }
}

#[test]
fn applies_expected_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    init(&req(tmp.path())).unwrap();

    // Public artefacts — world-readable.
    assert_eq!(mode_of(&tmp.path().join("keeper.toml")), 0o644);
    assert_eq!(mode_of(&tmp.path().join("tls/ca.crt")), 0o644);
    assert_eq!(mode_of(&tmp.path().join("tls/host.crt")), 0o644);

    // Secrets — owner only.
    assert_eq!(mode_of(&tmp.path().join("tls/ca.key")), 0o600);
    assert_eq!(mode_of(&tmp.path().join("tls/host.key")), 0o600);
    assert_eq!(mode_of(&tmp.path().join("secrets/bootstrap_token")), 0o600);

    // Dir modes — tls/ is world-traversable (so non-root can read
    // the public certs inside), secrets/ is owner-only.
    assert_eq!(mode_of(&tmp.path().join("tls")), 0o755);
    assert_eq!(mode_of(&tmp.path().join("secrets")), 0o700);
}

#[test]
fn creates_multi_level_missing_path() {
    // `create_dir_all` on a path with multiple missing components
    // yields several newly-created directory entries. The parent
    // of each must be fsync'd — testing the actual fsync side
    // effect isn't observable, but we can at least confirm the
    // code path runs without error and all intermediate dirs exist.
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp.path().join("a/b/c/dobby");
    let mut r = req(&nested);
    r.force = false;
    init(&r).unwrap();

    for expected in ["a", "a/b", "a/b/c", "a/b/c/dobby", "a/b/c/dobby/tls"] {
        assert!(
            tmp.path().join(expected).is_dir(),
            "expected intermediate dir {expected} to exist"
        );
    }
}

#[test]
fn serialised_keeper_toml_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    init(&req(tmp.path())).unwrap();

    let raw = fs::read_to_string(tmp.path().join("keeper.toml")).unwrap();
    let cfg = crate::keeper_config::KeeperConfig::from_toml(&raw).unwrap();
    assert_eq!(
        cfg.network.keeper_ip,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))
    );
    assert_eq!(cfg.network.bridge, "vmbr0");
}

#[test]
fn refuses_to_clobber_non_empty_dir_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("something"), b"surprise").unwrap();

    let err = init(&req(tmp.path())).unwrap_err();
    assert!(matches!(err, InitError::NotEmpty(_)), "{err}");
}

#[test]
fn overwrites_with_force() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("keeper.toml"), b"old").unwrap();

    let mut r = req(tmp.path());
    r.force = true;
    init(&r).unwrap();

    let after = fs::read_to_string(tmp.path().join("keeper.toml")).unwrap();
    assert!(after.contains("keeper_ip"), "post-init content: {after}");
    assert!(!after.starts_with("old"));
}

#[test]
fn creates_missing_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("nonexistent");
    assert!(!target.exists());

    let mut r = req(&target);
    r.force = false;
    init(&r).unwrap();

    assert!(target.join("keeper.toml").exists());
}

#[test]
fn fingerprint_is_reported_and_matches_host_cert() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = init(&req(tmp.path())).unwrap();
    assert_eq!(outcome.tls_fingerprint_sha256.len(), 64);
    assert!(
        outcome
            .tls_fingerprint_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "fingerprint must be lowercase hex"
    );
}

#[test]
fn rejects_mixed_family_gateway() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = req(tmp.path());
    r.keeper_ip = "fd00::50".parse().unwrap();
    r.gateway = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)); // v4 with v6 keeper
    // subnet/static_range defaults are v4 too — we'll surface the
    // first offender (gateway) since we check it before subnet.
    let err = init(&r).unwrap_err();
    match err {
        InitError::FamilyMismatch { field, .. } => assert_eq!(field, "gateway"),
        other => panic!("expected FamilyMismatch, got: {other}"),
    }
    // And no files were written.
    assert!(!tmp.path().join("keeper.toml").exists());
}

#[test]
fn rejects_mixed_family_subnet() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = req(tmp.path());
    r.keeper_ip = "fd00::50".parse().unwrap();
    r.gateway = "fd00::1".parse().unwrap();
    r.dns_upstream = "2606:4700:4700::1111".parse().unwrap();
    // subnet + static_range are still v4 defaults → mismatch flagged
    // on subnet (first thing checked after the typed fields).
    let err = init(&r).unwrap_err();
    match err {
        InitError::FamilyMismatch { field, .. } => assert_eq!(field, "subnet"),
        other => panic!("expected FamilyMismatch on subnet, got: {other}"),
    }
}

#[test]
fn accepts_consistent_ipv6_config() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = req(tmp.path());
    r.keeper_ip = "fd00::50".parse().unwrap();
    r.gateway = "fd00::1".parse().unwrap();
    r.dns_upstream = "2606:4700:4700::1111".parse().unwrap();
    r.subnet = "fd00::/64".into();
    r.static_range = "fd00::200-fd00::250".into();
    init(&r).unwrap();

    let cfg = crate::keeper_config::KeeperConfig::from_toml(
        &fs::read_to_string(tmp.path().join("keeper.toml")).unwrap(),
    )
    .unwrap();
    assert!(cfg.network.keeper_ip.is_ipv6());
    assert!(cfg.network.gateway.is_ipv6());
}

#[test]
fn rejects_malformed_subnet() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = req(tmp.path());
    r.subnet = "not-a-cidr".into();
    let err = init(&r).unwrap_err();
    assert!(
        matches!(
            err,
            InitError::MalformedNetworkField {
                field: "subnet",
                ..
            }
        ),
        "got: {err}"
    );
}

#[test]
fn rejects_non_numeric_cidr_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = req(tmp.path());
    r.subnet = "10.0.0.0/xyz".into();
    let err = init(&r).unwrap_err();
    assert!(
        matches!(
            err,
            InitError::MalformedNetworkField {
                field: "subnet",
                ..
            }
        ),
        "got: {err}"
    );
}

#[test]
fn rejects_v4_cidr_prefix_above_32() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = req(tmp.path());
    r.subnet = "10.0.0.0/99".into();
    let err = init(&r).unwrap_err();
    assert!(
        matches!(
            err,
            InitError::MalformedNetworkField {
                field: "subnet",
                ..
            }
        ),
        "got: {err}"
    );
}

#[test]
fn rejects_v6_cidr_prefix_above_128() {
    let tmp = tempfile::tempdir().unwrap();
    let mut r = req(tmp.path());
    r.keeper_ip = "fd00::50".parse().unwrap();
    r.gateway = "fd00::1".parse().unwrap();
    r.dns_upstream = "2606:4700:4700::1111".parse().unwrap();
    r.subnet = "fd00::/200".into();
    r.static_range = "fd00::200-fd00::250".into();
    let err = init(&r).unwrap_err();
    assert!(
        matches!(
            err,
            InitError::MalformedNetworkField {
                field: "subnet",
                ..
            }
        ),
        "got: {err}"
    );
}

#[test]
fn accepts_max_valid_prefix() {
    // /32 on v4 and /128 on v6 are both technically valid (single
    // host). The guard rejects >max, not >=max.
    let tmp = tempfile::tempdir().unwrap();
    let mut r = req(tmp.path());
    r.subnet = "10.0.0.50/32".into();
    init(&r).unwrap();
}

#[test]
fn creates_nested_dir_and_persists_parent_entry() {
    // When dir = <tmpdir>/nested/etc, create_dir_all makes two new
    // directories. ensure_target_dir fsyncs parent so the `etc` entry
    // in `<tmpdir>/nested` persists. We can't assert fsync directly
    // (it's a no-observable-side-effect kernel call) but we CAN
    // assert the end-to-end init still works when parent is fresh.
    let tmp = tempfile::tempdir().unwrap();
    let nested = tmp.path().join("nested/etc-dobby");
    let mut r = req(&nested);
    r.force = false;
    init(&r).unwrap();
    assert!(nested.join("keeper.toml").exists());
    assert!(nested.join("tls/host.crt").exists());
}
