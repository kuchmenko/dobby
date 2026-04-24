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

use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

    // IIFE just to funnel `?`-errors from the four steps into one
    // `Result` we can pattern-match on for cleanup. No resource-lifecycle
    // tricks: `f` is closed naturally by `Drop` at the end of the block.
    //
    // Cleanup contract:
    //   - On error at any step (open / write / sync / rename), `tmp`
    //     may exist as an orphan → we remove it best-effort.
    //   - On success, `rename(2)` moved the inode from `tmp` to
    //     `target`; `tmp` no longer exists, so there's nothing to clean.
    //     That's why the cleanup branch is error-only.
    let result = (|| -> Result<(), AtomicWriteError> {
        // Open with a restrictive 0o600 first. `OpenOptions::mode` is
        // subject to the process's `umask(2)`: under a hardened umask
        // (0o077 common for root / systemd) a requested 0o644 would
        // silently narrow to 0o600, and we'd have no way to notice.
        // We re-apply the requested `mode` explicitly via
        // `set_permissions` (= `chmod(2)`, NOT affected by umask)
        // once the content is on disk — so the final bits are exactly
        // what the caller asked for, and the brief window where the
        // tempfile exists is as tight as possible.
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
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

        std::fs::set_permissions(&tmp, Permissions::from_mode(mode)).map_err(|source| {
            AtomicWriteError::Io {
                op: "chmod tempfile",
                path: tmp.clone(),
                source,
            }
        })?;

        std::fs::rename(&tmp, target).map_err(|source| AtomicWriteError::Io {
            op: "rename tempfile into place",
            path: target.to_path_buf(),
            source,
        })
    })();

    if result.is_err() {
        // Best-effort cleanup. Ignore secondary errors — the caller
        // wants the *first* failure, not a fallback error from the
        // cleanup path. `ENOENT` here is fine: the rename may have
        // succeeded despite returning error (it shouldn't, but we
        // guard against a pathological kernel).
        let _ = std::fs::remove_file(&tmp);
    }

    result
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
