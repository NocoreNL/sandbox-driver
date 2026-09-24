//! Filesystem support for ACA sandboxes: a native + exec hybrid.
//!
//! ACA exposes native REST endpoints for file content and stat/list
//! (`crate::client::AcaClient::fs_cat`/`fs_write`/`fs_stat`/`fs_ls`), so
//! `read`/`write`/`metadata`/`exists`/`list_dir` (at depth 1) call those
//! directly instead of deriving through `cat`/`stat`/`find` over exec —
//! unlike a provider with no native file API (see
//! `sandbox_driver::DerivedFs`). ACA has no native `mkdir`/`rm`/`mv`
//! endpoints, so `create_dir`/`delete`/`rename` still shell out via
//! `client.exec`.
//!
//! Per CONTROLLER RULING O (task-10-brief.md), this replaces the brief's
//! original all-exec/base64 sketch.

use std::io;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use sandbox_driver::{DirEntry, Error, FileKind, FileMetadata, Filesystem, Result};

use crate::client::{AcaApiError, AcaClient, aca_error};
use crate::exec::shq;

/// `Filesystem` facet for one ACA sandbox.
///
/// `workspace` is the sandbox's working directory, used to resolve
/// relative paths (see [`abspath`]) — mirrors `AcaExec::workspace`
/// (`crate::exec::AcaExec`).
pub struct AcaFs {
    pub client: Arc<AcaClient>,
    pub sandbox_id: String,
    pub workspace: String,
}

impl AcaFs {
    #[must_use]
    pub fn new(
        client: Arc<AcaClient>,
        sandbox_id: impl Into<String>,
        workspace: impl Into<String>,
    ) -> Self {
        Self {
            client,
            sandbox_id: sandbox_id.into(),
            workspace: workspace.into(),
        }
    }

    /// Resolve `path` against this sandbox's workspace. See [`abspath`].
    fn abspath(&self, path: &str) -> String {
        abspath(&self.workspace, path)
    }

    /// Run one exec-derived fs command (`create_dir`/`delete`/`rename` —
    /// ACA has no native endpoint for these) and turn a non-zero exit
    /// into an `Error::Io` carrying stderr.
    async fn exec_ok(&self, op: &'static str, command: String) -> Result<()> {
        let response = self
            .client
            .exec(&self.sandbox_id, &command)
            .await
            .map_err(aca_error)?;
        if response.exit_code == 0 {
            Ok(())
        } else {
            Err(Error::io(
                format!("{op} failed"),
                io::Error::other(format!(
                    "exit code {}: {}",
                    response.exit_code,
                    response.stderr.trim()
                )),
            ))
        }
    }
}

/// Join `path` against `workspace`.
///
/// Absolute paths (starting with `/`) pass through unchanged; relative
/// paths are resolved against `workspace`. Pure and free-standing so it's
/// directly unit-testable without constructing an [`AcaFs`].
#[must_use]
pub fn abspath(workspace: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("{workspace}/{path}")
    }
}

/// Classify an ACA file stat's `is_dir`/`is_symlink` flags into a
/// [`FileKind`]. Symlink takes priority (a symlink-to-directory reports
/// both flags) — else directory, else regular file. Pure — unit-tested
/// directly.
#[must_use]
pub fn file_kind(is_dir: bool, is_symlink: bool) -> FileKind {
    if is_symlink {
        FileKind::Symlink
    } else if is_dir {
        FileKind::Directory
    } else {
        FileKind::File
    }
}

#[async_trait]
impl Filesystem for AcaFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        let path = self.abspath(path);
        self.client
            .fs_cat(&self.sandbox_id, &path)
            .await
            .map_err(aca_error)
    }

    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        let path = self.abspath(path);
        // The trait's `write` creates parent directories.
        self.client
            .fs_write(&self.sandbox_id, &path, content, true)
            .await
            .map_err(aca_error)
    }

    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        let path = self.abspath(path);
        let command = if recursive {
            format!("rm -r -f {}", shq(&path))
        } else {
            format!("rm -f {}", shq(&path))
        };
        self.exec_ok("delete", command).await
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let path = self.abspath(path);
        match self.client.fs_stat(&self.sandbox_id, &path).await {
            Ok(_) => Ok(true),
            Err(AcaApiError::NotFound) => Ok(false),
            Err(error) => Err(aca_error(error)),
        }
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        let path = self.abspath(path);
        let stat = self
            .client
            .fs_stat(&self.sandbox_id, &path)
            .await
            .map_err(aca_error)?;
        let mut metadata = FileMetadata::new(file_kind(stat.is_dir, stat.is_symlink), stat.size);
        metadata.mode = Some(stat.mode);
        metadata.modified_at = u64::try_from(stat.modified_time)
            .ok()
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        Ok(metadata)
    }

    /// Depth 1 (immediate children — the common case) lists natively via
    /// `client.fs_ls`, which returns exactly one level. Any other depth
    /// (recursive, or the degenerate 0) has no native equivalent, so it
    /// falls back to `find`'s own `-maxdepth` over `client.exec` —
    /// mirroring `sandbox_driver::DerivedFs::list_dir`'s exec-derived
    /// convention (NUL-terminated records so a filename containing a
    /// newline or `|` survives intact).
    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        let path = self.abspath(path);
        if depth == 1 {
            let stats = self
                .client
                .fs_ls(&self.sandbox_id, &path)
                .await
                .map_err(aca_error)?;
            let mut entries: Vec<DirEntry> = stats
                .into_iter()
                .map(|stat| {
                    let mut entry =
                        DirEntry::new(stat.name, file_kind(stat.is_dir, stat.is_symlink));
                    entry.size = Some(stat.size);
                    entry
                })
                .collect();
            entries.sort_by(|a, b| a.path.cmp(&b.path));
            return Ok(entries);
        }

        let command = format!(
            "find {} -mindepth 1 -maxdepth {depth} -printf '%y|%s|%P\\0'",
            shq(&path)
        );
        let response = self
            .client
            .exec(&self.sandbox_id, &command)
            .await
            .map_err(aca_error)?;
        if response.exit_code != 0 {
            return Err(Error::io(
                "list_dir failed",
                io::Error::other(format!(
                    "exit code {}: {}",
                    response.exit_code,
                    response.stderr.trim()
                )),
            ));
        }
        let mut entries = Vec::new();
        for record in response.stdout.split('\0') {
            let mut fields = record.splitn(3, '|');
            let (Some(kind), Some(size), Some(name)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let kind = match kind {
                "f" => FileKind::File,
                "d" => FileKind::Directory,
                "l" => FileKind::Symlink,
                _ => FileKind::Other,
            };
            let mut entry = DirEntry::new(name.to_owned(), kind);
            entry.size = size.parse().ok();
            entries.push(entry);
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    async fn create_dir(&self, path: &str) -> Result<()> {
        let path = self.abspath(path);
        let command = format!("mkdir -p {}", shq(&path));
        self.exec_ok("create_dir", command).await
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from = self.abspath(from);
        let to = self.abspath(to);
        let command = format!("mv {} {}", shq(&from), shq(&to));
        self.exec_ok("rename", command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abspath_joins_relative_passes_absolute() {
        assert_eq!(abspath("/workspace", "a.txt"), "/workspace/a.txt");
        assert_eq!(abspath("/workspace", "/abs.txt"), "/abs.txt");
    }

    #[test]
    fn file_kind_prefers_symlink_then_dir_then_file() {
        assert!(matches!(file_kind(true, true), FileKind::Symlink));
        assert!(matches!(file_kind(true, false), FileKind::Directory));
        assert!(matches!(file_kind(false, false), FileKind::File));
    }
}
