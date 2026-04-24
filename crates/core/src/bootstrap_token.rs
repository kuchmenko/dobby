//! One-time bootstrap tokens for `dobby pair`.
//!
//! `dobby keeper init` writes a single token to `secrets/bootstrap_token`
//! and prints it to the operator. The workstation presents this token
//! on the first `dobby pair` call; the Keeper verifies it, registers
//! the workstation's ed25519 key, and then deletes the token so it
//! can't be reused. Rotating the token is a fresh `dobby keeper init
//! --reset-bootstrap-token` (Phase 2+, not in scope yet).
//!
//! Format: `dby_boot_<48 hex chars>` — 24 bytes (192 bits) of
//! `OsRng` output. Prefix exists so the token is recognisable in logs
//! / tickets and grep-friendly, without leaking the actual entropy.

use rand::{TryRngCore, rngs::OsRng};
use zeroize::Zeroizing;

/// Number of random bytes backing the token (192 bits).
const TOKEN_BYTES: usize = 24;

/// Fixed prefix so operators can visually identify a dobby bootstrap
/// token at a glance.
pub const TOKEN_PREFIX: &str = "dby_boot_";

/// Errors from bootstrap token generation.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// `OsRng` failed to provide randomness. Extremely rare (kernel
    /// CSPRNG exhaustion on boot).
    #[error("OS random source unavailable: {0}")]
    Rng(#[from] rand::rand_core::OsError),
}

/// Generate a fresh bootstrap token. Returns a zeroising wrapper so
/// callers can't accidentally leave the plaintext lingering after use.
pub fn generate() -> Result<Zeroizing<String>, TokenError> {
    let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
    OsRng.try_fill_bytes(&mut *bytes)?;

    let mut out = String::with_capacity(TOKEN_PREFIX.len() + TOKEN_BYTES * 2);
    out.push_str(TOKEN_PREFIX);
    out.push_str(&const_hex::encode(*bytes));
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests;
