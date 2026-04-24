//! Shared types and primitives used by every dobby mode.
//!
//! Phase 1 scope:
//!   - [`manifest`]       — `dobby.toml` parsing (unified service model)
//!   - [`keeper_config`]  — `keeper.toml` schema (registry, watcher, network)
//!   - [`elf_config`]     — `elf.toml` schema (services, UID allocation)
//!   - [`auth`]           — ed25519 signing / verification primitives
//!   - [`secrets`]        — age-encrypt/decrypt, zeroizing wrappers
//!   - [`state`]          — atomic TOML persistence (`tmp + rename`)
//!
//! Phase 1 deliverable for this crate is type signatures and module
//! structure — real logic lands per acceptance criterion in issue #1.

#![allow(dead_code)] // skeleton stubs — filled per-phase

pub mod auth;
pub mod elf_config;
pub mod keeper_config;
pub mod manifest;
pub mod secrets;
pub mod state;

pub use state::{AtomicWriteError, atomic_write};

pub mod bootstrap_token;
pub mod keeper_init;
pub mod tls;
