use std::net::{IpAddr, Ipv4Addr};

use super::*;

fn sample_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50))
}

#[test]
fn produces_non_empty_pem_blobs() {
    let a = generate(sample_ip()).unwrap();
    assert!(a.ca_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(a.ca_cert_pem.ends_with("-----END CERTIFICATE-----\n"));
    assert!(a.host_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(a.ca_key_pem.contains("PRIVATE KEY"));
    assert!(a.host_key_pem.contains("PRIVATE KEY"));
}

#[test]
fn fingerprint_is_lowercase_hex_of_length_64() {
    let a = generate(sample_ip()).unwrap();
    assert_eq!(a.host_fingerprint_sha256.len(), 64);
    assert!(
        a.host_fingerprint_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}

#[test]
fn each_generation_produces_distinct_keys() {
    let a = generate(sample_ip()).unwrap();
    let b = generate(sample_ip()).unwrap();
    assert_ne!(a.ca_cert_pem, b.ca_cert_pem);
    assert_ne!(&**a.ca_key_pem, &**b.ca_key_pem);
    assert_ne!(a.host_fingerprint_sha256, b.host_fingerprint_sha256);
}

#[test]
fn accepts_ipv6_keeper_address() {
    let ipv6: IpAddr = "fd00::50".parse().unwrap();
    let a = generate(ipv6).unwrap();
    assert!(!a.host_fingerprint_sha256.is_empty());
}
