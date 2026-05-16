//! TLS material generation for the Keeper daemon.
//!
//! `dobby keeper init` produces a self-signed CA plus a host
//! certificate signed by that CA. The CA stays on the Keeper LXC and
//! later signs per-Elf mTLS certs issued during `dobby init` bootstrap
//! (Phase 2). The host cert is what tonic presents on the `:8443`
//! gRPC endpoint for `CLI ↔ Keeper` traffic; the SHA-256 fingerprint
//! of its DER encoding is the identity the CLI pins during TOFU
//! pairing.
//!
//! See issue #1 § Authentication.
//!
//! **Phase 1 limitation** — `rcgen::KeyPair` does not implement
//! `ZeroizeOnDrop`; its internal serialized-DER buffer survives
//! until the allocator reclaims the page. We wrap the PEM
//! serialisations in `Zeroizing<String>` (which IS what lands in
//! the operator's file and in process memory when Keeper later
//! reads the keys back), but the in-function `ca_key` / `host_key`
//! keypairs themselves are not wiped. `rcgen`'s `zeroize` feature
//! would let us call `.zeroize()` manually, but `Issuer::new`
//! consumes the `ca_key` by value — zeroising it before the move
//! would break the subsequent `signed_by()`, and there's no
//! post-move handle to reach into. This is worth revisiting
//! alongside the privsep work in Phase 5.

use std::{net::IpAddr, str};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, string::Ia5String,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// All artefacts produced by [`generate`].
#[derive(Debug)]
pub struct TlsArtifacts {
    /// CA certificate (PEM, public).
    pub ca_cert_pem: String,
    /// CA private key (PEM). Zeroised on drop.
    pub ca_key_pem: Zeroizing<String>,
    /// Host (Keeper daemon) certificate, signed by the CA (PEM, public).
    pub host_cert_pem: String,
    /// Host private key (PEM). Zeroised on drop.
    pub host_key_pem: Zeroizing<String>,
    /// SHA-256 fingerprint of the host cert in DER form — what the CLI
    /// pins during TOFU pairing. Lowercase-hex string, no separators.
    pub host_fingerprint_sha256: String,
}

/// Errors from TLS material generation.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Something went wrong inside rcgen.
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    /// Certificate PEM was not valid UTF-8.
    #[error("certificate PEM is not UTF-8: {0}")]
    PemUtf8(#[from] str::Utf8Error),
    /// Certificate PEM did not contain a certificate block.
    #[error("certificate PEM does not contain a CERTIFICATE block")]
    MissingCertificateBlock,
    /// Certificate PEM base64 payload failed to decode.
    #[error("decoding certificate PEM base64: {0}")]
    PemBase64(#[from] base64::DecodeError),
    /// Fingerprint hex was not exactly 32 bytes.
    #[error("TLS SHA-256 fingerprint must be 64 lowercase hex chars")]
    InvalidFingerprintHex,
    /// Fingerprint hex failed to decode.
    #[error("decoding TLS SHA-256 fingerprint: {0}")]
    DecodeFingerprint(#[from] const_hex::FromHexError),
}

/// Compute the lowercase-hex SHA-256 fingerprint of a DER certificate.
#[must_use]
pub fn fingerprint_sha256_hex_from_der(cert_der: &[u8]) -> String {
    const_hex::encode(fingerprint_sha256_bytes_from_der(cert_der))
}

/// Compute the raw SHA-256 fingerprint bytes of a DER certificate.
#[must_use]
pub fn fingerprint_sha256_bytes_from_der(cert_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().into()
}

/// Compute the lowercase-hex SHA-256 fingerprint of the first
/// `CERTIFICATE` PEM block in `cert_pem`.
pub fn fingerprint_sha256_hex_from_pem(cert_pem: &[u8]) -> Result<String, TlsError> {
    Ok(const_hex::encode(fingerprint_sha256_bytes_from_pem(
        cert_pem,
    )?))
}

/// Compute the raw SHA-256 fingerprint bytes of the first
/// `CERTIFICATE` PEM block in `cert_pem`.
pub fn fingerprint_sha256_bytes_from_pem(cert_pem: &[u8]) -> Result<[u8; 32], TlsError> {
    let der = first_certificate_der_from_pem(cert_pem)?;
    Ok(fingerprint_sha256_bytes_from_der(&der))
}

/// Parse a lowercase-hex SHA-256 fingerprint into raw bytes.
pub fn parse_fingerprint_hex(fingerprint: &str) -> Result<[u8; 32], TlsError> {
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(TlsError::InvalidFingerprintHex);
    }
    const_hex::decode_to_array(fingerprint).map_err(TlsError::DecodeFingerprint)
}

fn first_certificate_der_from_pem(cert_pem: &[u8]) -> Result<Vec<u8>, TlsError> {
    let pem = str::from_utf8(cert_pem)?;
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let start = pem
        .find(start_marker)
        .ok_or(TlsError::MissingCertificateBlock)?
        + start_marker.len();
    let rest = &pem[start..];
    let end = rest
        .find(end_marker)
        .ok_or(TlsError::MissingCertificateBlock)?;

    let base64_payload: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    BASE64_STANDARD
        .decode(base64_payload)
        .map_err(TlsError::PemBase64)
}

/// Generate the CA + host cert for a Keeper listening on `keeper_ip`.
///
/// SANs on the host cert include `keeper_ip` itself plus the DNS names
/// `localhost` and `dobby-keeper` (the conventional LXC hostname in
/// the issue runbook). Adding SANs at init time means the cert doesn't
/// have to be reissued the first time the CLI pairs from a non-IP
/// address.
pub fn generate(keeper_ip: IpAddr) -> Result<TlsArtifacts, TlsError> {
    // ── CA ──────────────────────────────────────────────────────────
    let ca_key = KeyPair::generate()?;

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Dobby Keeper CA");
        dn.push(DnType::OrganizationName, "dobby");
        dn
    };
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_cert_pem = ca_cert.pem();
    // Wrap in `Zeroizing` at the exact call that surfaces the
    // plaintext PEM — no window where the raw bytes live in an
    // ordinary `String`.
    let ca_key_pem = Zeroizing::new(ca_key.serialize_pem());

    // `Issuer::new` takes ownership of the keypair; we've already
    // pulled the PEM serialisation out via the line above.
    let issuer = Issuer::new(ca_params, ca_key);

    // ── Host ────────────────────────────────────────────────────────
    let mut host_params = CertificateParams::default();
    host_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Dobby Keeper");
        dn.push(DnType::OrganizationName, "dobby");
        dn
    };
    host_params.use_authority_key_identifier_extension = true;
    host_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    host_params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        // Included because the same host cert ends up on the mTLS
        // client side when keeper calls into elves: see issue #1
        // § Communication protocol. Cheaper to include now than to
        // reissue later.
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    host_params.subject_alt_names = vec![
        SanType::IpAddress(keeper_ip),
        SanType::DnsName(Ia5String::try_from("localhost".to_owned())?),
        SanType::DnsName(Ia5String::try_from("dobby-keeper".to_owned())?),
    ];

    let host_key = KeyPair::generate()?;
    let host_cert = host_params.signed_by(&host_key, &issuer)?;

    let host_cert_pem = host_cert.pem();
    let host_key_pem = Zeroizing::new(host_key.serialize_pem());
    let host_der = host_cert.der().to_vec();

    // ── Fingerprint ─────────────────────────────────────────────────
    let host_fingerprint_sha256 = fingerprint_sha256_hex_from_der(&host_der);

    Ok(TlsArtifacts {
        ca_cert_pem,
        ca_key_pem,
        host_cert_pem,
        host_key_pem,
        host_fingerprint_sha256,
    })
}

#[cfg(test)]
mod tests;
