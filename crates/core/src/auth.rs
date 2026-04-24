//! Ed25519 key management and request signing.
//!
//! Workstations generate a key pair at `dobby pair` time (stored at
//! `~/.config/dobby/key.ed25519`, mode 0600) and register the public half
//! with the Keeper. Every CLI gRPC call carries an ed25519 signature of
//! the request payload so the Keeper can attribute actions to a specific
//! paired workstation.
//!
//! Phase 1 goal: generate / load key pairs, sign / verify arbitrary
//! byte slices. The wire-level signing layer lands with the first
//! real Keeper RPC.

// TODO(phase-1): key pair generation, PEM serialisation, sign / verify
