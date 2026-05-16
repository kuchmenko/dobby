//! Ed25519 key management and request signing.
//!
//! Workstations generate a key pair at `dobby pair` time (stored at
//! `~/.config/dobby/key.ed25519`, mode 0600) and register the public half
//! with the Keeper. Every future CLI gRPC call will carry an Ed25519
//! signature of the request payload so the Keeper can attribute actions
//! to a specific paired workstation.
//!
//! This module owns only the cryptographic and persistence primitives:
//! key generation, strict key parsing, Pair challenge construction,
//! signing / verification, and the Keeper-side workstation registry.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::state::{self, AtomicWriteError};

/// Raw Ed25519 public-key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 32;
/// Raw Ed25519 signature length in bytes.
pub const SIGNATURE_BYTES: usize = 64;

const PRIVATE_KEY_FILE_HEADER: &[u8] = b"dobby-ed25519-private-key-v1\n";
const PAIR_CHALLENGE_DOMAIN: &[u8] = b"dobby/v1/pair\n";

/// A workstation Ed25519 keypair. The private half never leaves the workstation.
pub struct WorkstationKeypair {
    signing_key: SigningKey,
}

impl std::fmt::Debug for WorkstationKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkstationKeypair")
            .field("public_key", &const_hex::encode(self.public_key_bytes()))
            .finish_non_exhaustive()
    }
}

/// On-disk pairing metadata stored on the workstation after `dobby pair`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkstationPairing {
    /// Keeper endpoint the workstation paired with.
    pub keeper_address: String,
    /// Pinned Keeper TLS certificate SHA-256 fingerprint, lowercase hex.
    pub tls_fingerprint_sha256: String,
    /// Workstation public key, lowercase hex.
    pub workstation_pubkey: String,
}

/// Keeper-side public-key registry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeeperAuthRegistry {
    /// Once true, the bootstrap token cannot enrol a different key.
    #[serde(default)]
    pub bootstrap_token_consumed: bool,
    /// Public keys of paired workstations.
    #[serde(default)]
    pub workstations: Vec<PairedWorkstation>,
}

/// One paired workstation entry. Only public material is persisted here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairedWorkstation {
    /// Ed25519 public key, lowercase hex.
    pub public_key: String,
}

/// Errors from auth key, signature, and registry operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// `OsRng` failed to provide randomness. Extremely rare.
    #[error("OS random source unavailable: {0}")]
    Rng(#[from] rand::rand_core::OsError),
    /// Public key had the wrong raw byte length.
    #[error("Ed25519 public key must be 32 bytes, got {actual}")]
    InvalidPublicKeyLength {
        /// Actual byte length supplied by the caller.
        actual: usize,
    },
    /// Signature had the wrong raw byte length.
    #[error("Ed25519 signature must be 64 bytes, got {actual}")]
    InvalidSignatureLength {
        /// Actual byte length supplied by the caller.
        actual: usize,
    },
    /// Ed25519 public key bytes were malformed.
    #[error("invalid Ed25519 public key")]
    InvalidPublicKey,
    /// Ed25519 signature did not verify.
    #[error("Ed25519 signature verification failed")]
    Signature,
    /// Private key file had the wrong header or length.
    #[error("invalid workstation private key file format")]
    InvalidPrivateKeyFile,
    /// Hex field failed to decode.
    #[error("decoding hex field: {0}")]
    DecodeHex(#[from] const_hex::FromHexError),
    /// TOML serialisation failed.
    #[error("serialising auth state: {0}")]
    Serialise(#[from] toml::ser::Error),
    /// TOML parsing failed.
    #[error("parsing auth state {path}: {source}")]
    Parse {
        /// File being parsed.
        path: PathBuf,
        /// TOML parse error.
        #[source]
        source: toml::de::Error,
    },
    /// Filesystem / atomic-write error.
    #[error(transparent)]
    Write(#[from] AtomicWriteError),
    /// Ambient filesystem error.
    #[error("{op} on {path}: {source}")]
    Io {
        /// Filesystem operation that failed.
        op: &'static str,
        /// Path the failed operation targeted.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
}

impl WorkstationKeypair {
    /// Generate a new workstation keypair from the kernel CSPRNG.
    pub fn generate() -> Result<Self, AuthError> {
        let mut seed = Zeroizing::new([0u8; PUBLIC_KEY_BYTES]);
        OsRng.try_fill_bytes(&mut *seed)?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    /// Parse a keypair from the raw 32-byte Ed25519 secret key seed.
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self, AuthError> {
        let seed: &[u8; PUBLIC_KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| AuthError::InvalidPrivateKeyFile)?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(seed),
        })
    }

    /// Return the raw 32-byte public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign arbitrary bytes with the workstation private key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_BYTES] {
        self.signing_key.sign(message).to_bytes()
    }

    fn to_private_key_file_bytes(&self) -> Zeroizing<Vec<u8>> {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        let mut out = Zeroizing::new(Vec::with_capacity(
            PRIVATE_KEY_FILE_HEADER.len() + PUBLIC_KEY_BYTES,
        ));
        out.extend_from_slice(PRIVATE_KEY_FILE_HEADER);
        out.extend_from_slice(seed.as_ref());
        out
    }
}

/// Build the deterministic bytes signed during Pair.
///
/// The challenge binds this workstation public key to this Keeper TLS
/// fingerprint. Signing it proves the caller controls the private key
/// corresponding to the public key it asks the Keeper to store.
#[must_use]
pub fn pair_challenge(
    tls_fingerprint_sha256: &[u8; 32],
    workstation_pubkey: &[u8; PUBLIC_KEY_BYTES],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PAIR_CHALLENGE_DOMAIN.len() + tls_fingerprint_sha256.len() + workstation_pubkey.len(),
    );
    out.extend_from_slice(PAIR_CHALLENGE_DOMAIN);
    out.extend_from_slice(tls_fingerprint_sha256);
    out.extend_from_slice(workstation_pubkey);
    out
}

/// Parse a raw public-key byte slice into a fixed-size array.
pub fn parse_public_key_bytes(bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_BYTES], AuthError> {
    bytes
        .try_into()
        .map_err(|_| AuthError::InvalidPublicKeyLength {
            actual: bytes.len(),
        })
}

/// Parse a raw signature byte slice into a fixed-size array.
pub fn parse_signature_bytes(bytes: &[u8]) -> Result<[u8; SIGNATURE_BYTES], AuthError> {
    bytes
        .try_into()
        .map_err(|_| AuthError::InvalidSignatureLength {
            actual: bytes.len(),
        })
}

/// Verify an Ed25519 signature over `message`.
pub fn verify_signature(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> Result<(), AuthError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| AuthError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| AuthError::Signature)
}

/// Load an existing workstation keypair, or generate and persist a new one.
pub fn load_or_create_workstation_keypair(path: &Path) -> Result<WorkstationKeypair, AuthError> {
    match fs::read(path) {
        Ok(raw) => parse_private_key_file(&raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let keypair = WorkstationKeypair::generate()?;
            save_workstation_keypair(path, &keypair)?;
            Ok(keypair)
        }
        Err(source) => Err(AuthError::Io {
            op: "read workstation private key",
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Persist a workstation keypair with mode 0600, creating the parent config dir as 0700.
pub fn save_workstation_keypair(
    path: &Path,
    keypair: &WorkstationKeypair,
) -> Result<(), AuthError> {
    ensure_parent_dir(path, 0o700)?;
    let bytes = keypair.to_private_key_file_bytes();
    state::atomic_write(path, bytes.as_ref(), 0o600)?;
    Ok(())
}

/// Load a Keeper auth registry. Missing file means no workstation has paired yet.
pub fn load_keeper_registry(path: &Path) -> Result<KeeperAuthRegistry, AuthError> {
    match fs::read_to_string(path) {
        Ok(raw) => KeeperAuthRegistry::from_toml(path, &raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KeeperAuthRegistry::default()),
        Err(source) => Err(AuthError::Io {
            op: "read Keeper auth registry",
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Persist a Keeper auth registry with mode 0600 under an owner-only directory.
pub fn save_keeper_registry(path: &Path, registry: &KeeperAuthRegistry) -> Result<(), AuthError> {
    ensure_parent_dir(path, 0o700)?;
    state::atomic_write(path, registry.to_toml()?.as_bytes(), 0o600)?;
    Ok(())
}

/// Persist workstation pairing metadata with mode 0600.
pub fn save_workstation_pairing(
    path: &Path,
    pairing: &WorkstationPairing,
) -> Result<(), AuthError> {
    ensure_parent_dir(path, 0o700)?;
    state::atomic_write(path, pairing.to_toml()?.as_bytes(), 0o600)?;
    Ok(())
}

impl WorkstationPairing {
    /// Serialise to TOML.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Parse workstation pairing TOML strictly.
    pub fn from_toml(path: &Path, raw: &str) -> Result<Self, AuthError> {
        toml::from_str(raw).map_err(|source| AuthError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

impl KeeperAuthRegistry {
    /// Return true if `public_key` is already registered.
    #[must_use]
    pub fn contains_public_key(&self, public_key: &[u8; PUBLIC_KEY_BYTES]) -> bool {
        let expected = const_hex::encode(public_key);
        self.workstations.iter().any(|w| w.public_key == expected)
    }

    /// Add `public_key` if absent.
    pub fn add_public_key(&mut self, public_key: &[u8; PUBLIC_KEY_BYTES]) {
        if !self.contains_public_key(public_key) {
            self.workstations.push(PairedWorkstation {
                public_key: const_hex::encode(public_key),
            });
        }
    }

    /// Serialise to TOML.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Parse Keeper auth registry TOML strictly.
    pub fn from_toml(path: &Path, raw: &str) -> Result<Self, AuthError> {
        let registry: Self = toml::from_str(raw).map_err(|source| AuthError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        for workstation in &registry.workstations {
            let decoded: [u8; PUBLIC_KEY_BYTES] =
                const_hex::decode_to_array(&workstation.public_key)?;
            let _ = VerifyingKey::from_bytes(&decoded).map_err(|_| AuthError::InvalidPublicKey)?;
        }
        Ok(registry)
    }
}

fn parse_private_key_file(raw: &[u8]) -> Result<WorkstationKeypair, AuthError> {
    let Some(seed) = raw.strip_prefix(PRIVATE_KEY_FILE_HEADER) else {
        return Err(AuthError::InvalidPrivateKeyFile);
    };
    WorkstationKeypair::from_private_key_bytes(seed)
}

fn ensure_parent_dir(path: &Path, mode: u32) -> Result<(), AuthError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| AuthError::Io {
            op: "resolve parent directory",
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no parent directory",
            ),
        })?;

    fs::create_dir_all(parent).map_err(|source| AuthError::Io {
        op: "mkdir -p",
        path: parent.to_path_buf(),
        source,
    })?;
    fs::set_permissions(parent, fs::Permissions::from_mode(mode)).map_err(|source| {
        AuthError::Io {
            op: "chmod parent directory",
            path: parent.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests;
