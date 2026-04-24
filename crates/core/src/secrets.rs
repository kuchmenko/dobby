//! Secret material handling — age encryption at rest + `zeroize`-wrapped
//! in-memory plaintext.
//!
//! Decrypted secret bytes (age plaintext, mTLS private keys, GitHub
//! OAuth tokens, Proxmox API token) MUST be wrapped in
//! [`zeroize::Zeroizing`] on both the Keeper and Elf sides — the drop
//! glue overwrites the buffer so core dumps, OOM dumps, and swap do
//! not leak material. See issue #1 § Secrets management "Memory
//! hygiene".
//!
//! Phase 1 goal: typed wrapper newtypes + age encrypt / decrypt helpers.
//! Used by `dobby keeper init` (generate age key pair) and by every
//! call site that holds decrypted values.

use zeroize::Zeroizing;

/// Opaque secret plaintext bytes. Zeroised on drop.
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Opaque secret plaintext string. Zeroised on drop.
pub type SecretString = Zeroizing<String>;

// TODO(phase-1): age encrypt(pubkey, plaintext) → Vec<u8>
// TODO(phase-1): age decrypt(privkey, ciphertext) → SecretBytes
// TODO(phase-1): age::x25519::Identity generation helper
