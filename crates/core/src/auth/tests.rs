use std::os::unix::fs::PermissionsExt;

use super::*;

#[test]
fn generated_keypair_signs_and_verifies() {
    let keypair = WorkstationKeypair::generate().unwrap();
    let pubkey = keypair.public_key_bytes();
    let message = b"hello dobby";
    let sig = keypair.sign(message);

    verify_signature(&pubkey, message, &sig).unwrap();
}

#[test]
fn signature_is_bound_to_message() {
    let keypair = WorkstationKeypair::generate().unwrap();
    let pubkey = keypair.public_key_bytes();
    let sig = keypair.sign(b"original");

    assert!(matches!(
        verify_signature(&pubkey, b"tampered", &sig),
        Err(AuthError::Signature)
    ));
}

#[test]
fn pair_challenge_is_bound_to_keeper_and_workstation() {
    let keypair = WorkstationKeypair::generate().unwrap();
    let pubkey = keypair.public_key_bytes();
    let mut fingerprint = [7u8; 32];
    let challenge = pair_challenge(&fingerprint, &pubkey);
    let sig = keypair.sign(&challenge);

    verify_signature(&pubkey, &challenge, &sig).unwrap();

    fingerprint[0] = 8;
    let changed = pair_challenge(&fingerprint, &pubkey);
    assert!(matches!(
        verify_signature(&pubkey, &changed, &sig),
        Err(AuthError::Signature)
    ));
}

#[test]
fn workstation_keypair_round_trips_on_disk_with_owner_only_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("dobby/key.ed25519");
    let keypair = WorkstationKeypair::generate().unwrap();
    let pubkey = keypair.public_key_bytes();

    save_workstation_keypair(&path, &keypair).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let loaded = load_or_create_workstation_keypair(&path).unwrap();
    assert_eq!(loaded.public_key_bytes(), pubkey);
}

#[test]
fn load_or_create_generates_missing_workstation_keypair() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("dobby/key.ed25519");

    let keypair = load_or_create_workstation_keypair(&path).unwrap();
    assert!(path.exists());

    let loaded = load_or_create_workstation_keypair(&path).unwrap();
    assert_eq!(loaded.public_key_bytes(), keypair.public_key_bytes());
}

#[test]
fn keeper_registry_round_trips_public_key_only() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("auth/workstations.toml");
    let keypair = WorkstationKeypair::generate().unwrap();
    let pubkey = keypair.public_key_bytes();

    let mut registry = KeeperAuthRegistry::default();
    registry.add_public_key(&pubkey);
    registry.bootstrap_token_consumed = true;
    save_keeper_registry(&path, &registry).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(raw.contains("bootstrap_token_consumed = true"));
    assert!(raw.contains("public_key"));
    assert!(!raw.contains("PRIVATE KEY"));

    let loaded = load_keeper_registry(&path).unwrap();
    assert!(loaded.bootstrap_token_consumed);
    assert!(loaded.contains_public_key(&pubkey));
}

#[test]
fn registry_rejects_unknown_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("auth/workstations.toml");
    let raw = r#"
        bootstrap_token_consumed = true
        bogus = "nope"
    "#;

    assert!(matches!(
        KeeperAuthRegistry::from_toml(&path, raw),
        Err(AuthError::Parse { .. })
    ));
}

#[test]
fn workstation_pairing_round_trips_strictly() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("pairing.toml");
    let pairing = WorkstationPairing {
        keeper_address: "127.0.0.1:8443".into(),
        tls_fingerprint_sha256: "a".repeat(64),
        workstation_pubkey: "b".repeat(64),
    };

    save_workstation_pairing(&path, &pairing).unwrap();
    let raw = std::fs::read_to_string(&path).unwrap();
    let loaded = WorkstationPairing::from_toml(&path, &raw).unwrap();
    assert_eq!(loaded, pairing);
}
