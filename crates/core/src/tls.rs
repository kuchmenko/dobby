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

use std::net::IpAddr;

use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
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
    let ca_key_pem_plain = ca_key.serialize_pem();

    // Wrap the CA private key serialisation in an `Issuer` so rcgen
    // can sign leaf certs with it. `Issuer` takes ownership of the
    // keypair; we've already read out `ca_key_pem_plain`.
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
        SanType::DnsName(Ia5String::try_from("localhost".to_owned()).expect("static")),
        SanType::DnsName(Ia5String::try_from("dobby-keeper".to_owned()).expect("static")),
    ];

    let host_key = KeyPair::generate()?;
    let host_cert = host_params.signed_by(&host_key, &issuer)?;

    let host_cert_pem = host_cert.pem();
    let host_key_pem_plain = host_key.serialize_pem();
    let host_der = host_cert.der().to_vec();

    let ca_key_pem = Zeroizing::new(ca_key_pem_plain);
    let host_key_pem = Zeroizing::new(host_key_pem_plain);

    // ── Fingerprint ─────────────────────────────────────────────────
    let mut hasher = Sha256::new();
    hasher.update(&host_der);
    let digest = hasher.finalize();
    let host_fingerprint_sha256 = const_hex::encode(digest);

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
