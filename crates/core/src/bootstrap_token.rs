//! One-time bootstrap tokens for `dobby pair`.
//!
//! `dobby keeper init` prints a single plaintext token to the operator,
//! but persists only `sha256(token)` under `secrets/bootstrap_token`.
//! The workstation presents the plaintext token on the first `dobby pair`
//! call; the Keeper verifies it, registers the workstation's Ed25519
//! key, and then marks the bootstrap token consumed in the auth registry
//! so it cannot enrol a second workstation.
//!
//! Format: `dby_boot_<48 hex chars>` — 24 bytes (192 bits) of
//! `OsRng` output. Prefix exists so the token is recognisable in logs
//! / tickets and grep-friendly, without leaking the actual entropy.
//! Stored hash format: `dby_boot_sha256_<64 hex chars>`.

use rand::{TryRngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Number of random bytes backing the token (192 bits).
const TOKEN_BYTES: usize = 24;

/// SHA-256 digest length in bytes.
const TOKEN_HASH_BYTES: usize = 32;

/// Fixed prefix so operators can visually identify a dobby bootstrap
/// token at a glance.
pub const TOKEN_PREFIX: &str = "dby_boot_";

/// Fixed prefix for the persisted token digest.
pub const TOKEN_HASH_PREFIX: &str = "dby_boot_sha256_";

/// Errors from bootstrap token generation.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// `OsRng` failed to provide randomness. Extremely rare (kernel
    /// CSPRNG exhaustion on boot).
    #[error("OS random source unavailable: {0}")]
    Rng(#[from] rand::rand_core::OsError),
}

/// Errors from token or token-hash parsing.
#[derive(Debug, thiserror::Error)]
pub enum TokenFormatError {
    /// Plaintext token did not match `dby_boot_<48 lowercase hex>`.
    #[error("bootstrap token must have format dby_boot_<48 lowercase hex chars>")]
    InvalidToken,
    /// Persisted token hash did not match `dby_boot_sha256_<64 lowercase hex>`.
    #[error("bootstrap token hash must have format dby_boot_sha256_<64 lowercase hex chars>")]
    InvalidHash,
    /// Persisted token hash hex failed to decode.
    #[error("decoding bootstrap token hash: {0}")]
    DecodeHash(#[from] const_hex::FromHexError),
}

/// Generate a fresh bootstrap token. Returns a zeroising wrapper so
/// callers can't accidentally leave the plaintext lingering after use.
pub fn generate() -> Result<Zeroizing<String>, TokenError> {
    let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
    OsRng.try_fill_bytes(&mut *bytes)?;

    let mut out = String::with_capacity(TOKEN_PREFIX.len() + TOKEN_BYTES * 2);
    out.push_str(TOKEN_PREFIX);
    // `bytes.as_ref()` borrows the entropy — `*bytes` would dereference
    // to an owned `[u8; 24]` (Copy), producing a second plaintext copy
    // outside the `Zeroizing` wrapper for the lifetime of the encode call.
    out.push_str(&const_hex::encode(bytes.as_ref()));
    Ok(Zeroizing::new(out))
}

/// Hash a plaintext bootstrap token into the persisted on-disk form.
///
/// The token is high-entropy random data, so a plain SHA-256 digest is
/// enough here: there is no low-entropy password for an attacker to
/// brute-force offline.
pub fn hash_for_storage(token: &str) -> Result<String, TokenFormatError> {
    validate_token(token)?;

    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(TOKEN_HASH_PREFIX.len() + TOKEN_HASH_BYTES * 2);
    out.push_str(TOKEN_HASH_PREFIX);
    out.push_str(&const_hex::encode(digest));
    Ok(out)
}

/// Constant-time verification of a presented token against the stored hash.
pub fn verify_against_hash(token: &str, stored_hash: &str) -> Result<bool, TokenFormatError> {
    validate_token(token)?;
    let expected = parse_hash(stored_hash)?;

    let actual = Sha256::digest(token.as_bytes());
    Ok(actual.as_slice().ct_eq(&expected).into())
}

fn validate_token(token: &str) -> Result<(), TokenFormatError> {
    let Some(hex_part) = token.strip_prefix(TOKEN_PREFIX) else {
        return Err(TokenFormatError::InvalidToken);
    };
    if hex_part.len() != TOKEN_BYTES * 2 || !is_lower_hex(hex_part) {
        return Err(TokenFormatError::InvalidToken);
    }
    Ok(())
}

fn parse_hash(stored_hash: &str) -> Result<[u8; TOKEN_HASH_BYTES], TokenFormatError> {
    let Some(hex_part) = stored_hash.strip_prefix(TOKEN_HASH_PREFIX) else {
        return Err(TokenFormatError::InvalidHash);
    };
    if hex_part.len() != TOKEN_HASH_BYTES * 2 || !is_lower_hex(hex_part) {
        return Err(TokenFormatError::InvalidHash);
    }
    const_hex::decode_to_array(hex_part).map_err(TokenFormatError::DecodeHash)
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests;
