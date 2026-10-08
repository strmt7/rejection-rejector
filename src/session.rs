use crate::vault::{InstanceLock, private_dir, write_new_private};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const RESTORE_MARKER_NAME: &str = ".restore-in-progress";
const RESTORE_MARKER: &[u8] = b"restore-in-progress:v1\n";

const MARKER_NAME: &str = ".runtime-session.json";
const FORMAT_VERSION: u32 = 1;
const MAX_MARKER_BYTES: u64 = 8 * 1024;

/// Must run under the workspace lock before opening/creating the normal vault.
/// Any leftover restore marker means the SQLite file set needs explicit recovery.
pub(crate) fn ensure_restore_complete(directory: &Path) -> Result<()> {
    match fs::symlink_metadata(directory.join(RESTORE_MARKER_NAME)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => anyhow::bail!(
            "An offline restore did not finish. Preserve this workspace and its recovery directory, then use explicit Recovery Mode; normal startup is blocked"
        ),
    }
}

fn sync_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

/// Called only by the explicitly authorized offline restore while holding its lock.
/// A valid leftover marker permits a retry, never ordinary application startup.
pub(crate) fn begin_restore_transaction(directory: &Path) -> Result<()> {
    let path = directory.join(RESTORE_MARKER_NAME);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_new_private(&path, RESTORE_MARKER)?;
            sync_directory(directory)?;
        }
        Err(error) => return Err(error.into()),
        Ok(_) => ensure!(
            read_bounded(&path)? == RESTORE_MARKER,
            "Restore transaction marker is invalid; preserve recovery files for inspection"
        ),
    }
    Ok(())
}

/// Clear only after the installed image or the entire rolled-back file set is valid.
/// There is intentionally no Drop cleanup: a crash/panic must retain this marker.
pub(crate) fn complete_restore_transaction(directory: &Path) -> Result<()> {
    let path = directory.join(RESTORE_MARKER_NAME);
    ensure!(
        read_bounded(&path)? == RESTORE_MARKER,
        "Restore transaction marker is missing or invalid"
    );
    fs::remove_file(path)?;
    sync_directory(directory)?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SessionMarker {
    format_version: u32,
    session_id: String,
    process_id: u32,
    app_version: String,
    started_at: DateTime<Utc>,
}

pub(crate) struct SessionLease {
    marker_path: PathBuf,
    session_id: String,
    previous_unclean: bool,
}

impl SessionLease {
    pub(crate) fn begin(directory: &Path) -> Result<Self> {
        private_dir(directory)?;
        ensure_restore_complete(directory)?;
        let marker_path = directory.join(MARKER_NAME);
        reject_symlink_if_present(&marker_path)?;
        let previous_unclean = marker_path.exists();

        let marker = SessionMarker {
            format_version: FORMAT_VERSION,
            session_id: uuid::Uuid::new_v4().to_string(),
            process_id: std::process::id(),
            app_version: env!("CARGO_PKG_VERSION").into(),
            started_at: Utc::now(),
        };
        write_marker(&marker_path, &marker)?;

        Ok(Self {
            marker_path,
            session_id: marker.session_id,
            previous_unclean,
        })
    }

    pub(crate) fn previous_unclean(&self) -> bool {
        self.previous_unclean
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        // Successful Engine teardown drops its workspace lock before this lease.
        // A failed Engine::open unwinds local variables in the reverse order and
        // still holds that lock: preserve its crash evidence. Taking the lock also
        // prevents an old lease from racing a newly starting worker's marker.
        let Some(directory) = self.marker_path.parent() else {
            return;
        };
        let Ok(_cleanup_lock) = InstanceLock::acquire(directory) else {
            return;
        };
        let Ok(bytes) = read_bounded(&self.marker_path) else {
            return;
        };
        let Ok(marker) = serde_json::from_slice::<SessionMarker>(&bytes) else {
            return;
        };
        if marker.session_id == self.session_id {
            let _ = fs::remove_file(&self.marker_path);
        }
    }
}

fn reject_symlink_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Runtime session marker must be a regular file, not a symlink"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn write_marker(path: &Path, marker: &SessionMarker) -> Result<()> {
    reject_symlink_if_present(path)?;
    let data = serde_json::to_vec(marker)?;
    ensure!(
        data.len() as u64 <= MAX_MARKER_BYTES,
        "Runtime session marker exceeds size limit"
    );
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("Cannot write {}", path.display()))?;
    file.write_all(&data)?;
    file.sync_all()?;
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    reject_symlink_if_present(path)?;
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.len() <= MAX_MARKER_BYTES,
        "Runtime session marker exceeds size limit"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_MARKER_BYTES,
        "Runtime session marker exceeds size limit"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_restore_blocks_startup_until_explicit_completion() {
        let directory = tempfile::tempdir().unwrap();
        ensure_restore_complete(directory.path()).unwrap();
        begin_restore_transaction(directory.path()).unwrap();
        assert!(SessionLease::begin(directory.path()).is_err());
        assert!(!directory.path().join(MARKER_NAME).exists());
        assert!(!directory.path().join("state.sqlite3").exists());
        // Explicit recovery may retry after a crash using the retained marker.
        begin_restore_transaction(directory.path()).unwrap();
        complete_restore_transaction(directory.path()).unwrap();
        ensure_restore_complete(directory.path()).unwrap();
        let lease = SessionLease::begin(directory.path()).unwrap();
        drop(lease);
        assert!(!directory.path().join(MARKER_NAME).exists());
    }

    #[test]
    fn malformed_restore_marker_cannot_be_ignored_or_cleared() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(RESTORE_MARKER_NAME);
        fs::write(&marker, b"incomplete write").unwrap();
        assert!(ensure_restore_complete(directory.path()).is_err());
        assert!(begin_restore_transaction(directory.path()).is_err());
        assert!(complete_restore_transaction(directory.path()).is_err());
        assert!(marker.exists());
        fs::remove_file(&marker).unwrap();
        fs::create_dir(&marker).unwrap();
        assert!(ensure_restore_complete(directory.path()).is_err());
        assert!(begin_restore_transaction(directory.path()).is_err());
    }

    #[test]
    fn clean_session_removes_marker() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(MARKER_NAME);
        {
            let lease = SessionLease::begin(directory.path()).unwrap();
            assert!(!lease.previous_unclean());
            assert!(marker.is_file());
        }
        assert!(!marker.exists());
    }

    #[test]
    fn abandoned_session_is_detected_and_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(MARKER_NAME);
        let first = SessionLease::begin(directory.path()).unwrap();
        std::mem::forget(first);

        let second = SessionLease::begin(directory.path()).unwrap();
        assert!(second.previous_unclean());
        let active: SessionMarker =
            serde_json::from_slice(&read_bounded(&marker).unwrap()).unwrap();
        assert_eq!(active.session_id, second.session_id);
        drop(second);
        assert!(!marker.exists());
    }

    #[test]
    fn malformed_existing_marker_is_still_fail_closed_as_unclean() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(MARKER_NAME);
        fs::write(&marker, b"not-json").unwrap();

        let lease = SessionLease::begin(directory.path()).unwrap();
        assert!(lease.previous_unclean());
        drop(lease);
        assert!(!marker.exists());
    }

    #[test]
    fn failed_startup_preserves_the_unclean_marker() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(MARKER_NAME);
        let lock = InstanceLock::acquire(directory.path()).unwrap();
        let lease = SessionLease::begin(directory.path()).unwrap();
        // An early return from Engine::open drops the lease while holding lock.
        drop(lease);
        assert!(marker.is_file());
        drop(lock);
        let recovered = SessionLease::begin(directory.path()).unwrap();
        assert!(recovered.previous_unclean());
        drop(recovered);
        assert!(!marker.exists());
    }

    #[test]
    fn normal_engine_field_drop_order_cleans_the_marker() {
        struct Runtime {
            _lock: InstanceLock,
            _session: SessionLease,
        }
        let directory = tempfile::tempdir().unwrap();
        let runtime = Runtime {
            _lock: InstanceLock::acquire(directory.path()).unwrap(),
            _session: SessionLease::begin(directory.path()).unwrap(),
        };
        drop(runtime);
        assert!(!directory.path().join(MARKER_NAME).exists());
    }

    #[test]
    fn old_lease_cannot_remove_a_successor_marker() {
        let directory = tempfile::tempdir().unwrap();
        let first = SessionLease::begin(directory.path()).unwrap();
        let successor_lock = InstanceLock::acquire(directory.path()).unwrap();
        let successor = SessionLease::begin(directory.path()).unwrap();
        drop(first);
        let bytes = read_bounded(&directory.path().join(MARKER_NAME)).unwrap();
        let marker: SessionMarker = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(marker.session_id, successor.session_id);
        drop(successor_lock);
        drop(successor);
        assert!(!directory.path().join(MARKER_NAME).exists());
    }

    #[test]
    fn directories_and_oversize_markers_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join(MARKER_NAME);
        fs::create_dir(&marker).unwrap();
        assert!(SessionLease::begin(directory.path()).is_err());
        fs::remove_dir(&marker).unwrap();
        fs::write(&marker, vec![b'x'; MAX_MARKER_BYTES as usize + 1]).unwrap();
        assert!(read_bounded(&marker).is_err());
    }
}
