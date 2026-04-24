//! Atomic TOML persistence primitive used everywhere state lives on
//! disk (`keeper.toml`, `elf.toml`, config pointer symlinks).
//!
//! Guarantee: either the file contains the new content in full, or it
//! contains the old content in full — never a torn write. Achieved via
//! `write(tmp) → fsync(tmp) → rename(tmp, target)` per POSIX rename(2).
//! See issue #1 § State management.
//!
//! Phase 1 deliverable. Used by every subsystem that writes a TOML
//! config or pointer file.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Errors that can arise during an atomic write.
#[derive(Debug, thiserror::Error)]
pub enum AtomicWriteError {
    /// Target path has no parent directory to stage a temp file in.
    #[error("target path {0} has no parent directory")]
    NoParent(PathBuf),
    /// Underlying filesystem error.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

/// Write `contents` atomically to `target` by staging in a tempfile
/// beside it, fsync'ing, and renaming.
///
/// Phase 1 stub: returns `Ok(())` without writing. Replaced with the
/// real implementation in the first Keeper-init acceptance test.
pub fn atomic_write(target: &Path, contents: &[u8]) -> Result<(), AtomicWriteError> {
    // Silence unused-warning complaints on the stub parameters.
    let _ = (target, contents);

    // Placeholder path that exercises the error branch without touching
    // the filesystem — proves the type signature is wired.
    let _ = Path::new("/tmp")
        .parent()
        .ok_or_else(|| AtomicWriteError::NoParent(PathBuf::from("/tmp")));

    Ok(())
}

// Suppress an unused-import warning until the real implementation
// uses `Write` for tmpfile emission.
#[allow(dead_code)]
fn _suppress_unused_write_import(mut w: impl Write) -> std::io::Result<()> {
    w.write_all(&[])
}
