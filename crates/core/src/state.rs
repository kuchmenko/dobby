//! Atomic file writes — `tmp + fsync + rename`.
//!
//! The kernel guarantees `rename(2)` is atomic within a filesystem:
//! at any moment the target inode contains either the full old
//! content or the full new content, never a torn mix. We exploit
//! that by writing into a same-directory tempfile, fsync'ing its
//! contents, then renaming over the target. A crash between any two
//! of those steps leaves a consistent state — either the old target
//! plus an orphan tempfile (caller can GC), or the new target.
//!
//! See issue #1 § State management.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors that can arise during an atomic write.
#[derive(Debug, thiserror::Error)]
pub enum AtomicWriteError {
    /// Target path has no parent directory to stage a temp file in.
    #[error("target path {0} has no parent directory")]
    NoParent(PathBuf),
    /// Target file name is not a valid OS string.
    #[error("target path {0} has no file name component")]
    NoFileName(PathBuf),
    /// Underlying filesystem error. `op` describes the step.
    #[error("{op} failed on {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Write `contents` atomically to `target` with permission bits `mode`.
///
/// Steps:
/// 1. Create a tempfile `<target>.tmp-<pid>-<ts>` in the same directory,
///    opened with `create_new` (refuses to clobber) and the requested
///    `mode`.
/// 2. Write `contents` in full.
/// 3. `fsync(2)` the tempfile to flush buffers to disk.
/// 4. `rename(2)` the tempfile over `target` — atomic per POSIX.
///
/// If step 1–3 fails, the tempfile is removed (best-effort) before the
/// error is returned. Callers that want durability of the rename itself
/// should `fsync` the parent directory separately.
pub fn atomic_write(target: &Path, contents: &[u8], mode: u32) -> Result<(), AtomicWriteError> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| AtomicWriteError::NoParent(target.to_path_buf()))?;
    let filename = target
        .file_name()
        .ok_or_else(|| AtomicWriteError::NoFileName(target.to_path_buf()))?;

    let tmp = parent.join(tmp_name(filename));

    // Scope the File so it closes (flushing the user buffer) before we
    // rename — rename operates on the inode, but if we have an open
    // writable handle with buffered content we need to ensure we've
    // actually written everything. `sync_all` below pushes buffers to
    // disk, and the Drop after that just closes the fd.
    let err = (|| -> Result<(), AtomicWriteError> {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|source| AtomicWriteError::Io {
                op: "create tempfile",
                path: tmp.clone(),
                source,
            })?;

        f.write_all(contents)
            .map_err(|source| AtomicWriteError::Io {
                op: "write tempfile",
                path: tmp.clone(),
                source,
            })?;

        f.sync_all().map_err(|source| AtomicWriteError::Io {
            op: "fsync tempfile",
            path: tmp.clone(),
            source,
        })?;

        drop(f);
        Ok(())
    })();

    if let Err(e) = err {
        // Best-effort cleanup. Ignore secondary errors — the user
        // cares about the first failure.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    std::fs::rename(&tmp, target).map_err(|source| AtomicWriteError::Io {
        op: "rename tempfile into place",
        path: target.to_path_buf(),
        source,
    })?;

    Ok(())
}

/// Produce a tempfile name in the form `.<target>.tmp-<pid>-<nanos>`.
/// Uniqueness comes from the nanosecond timestamp + PID; if a collision
/// ever did happen, `create_new(true)` would bail and the caller would
/// retry by calling `atomic_write` again.
fn tmp_name(target: &std::ffi::OsStr) -> std::ffi::OsString {
    let mut s = std::ffi::OsString::with_capacity(target.len() + 32);
    s.push(".");
    s.push(target);
    s.push(".tmp-");
    s.push(std::process::id().to_string());
    s.push("-");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    s.push(nanos.to_string());
    s
}

#[cfg(test)]
mod tests;
