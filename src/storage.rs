use anyhow::{Result, ensure};
use serde::Serialize;
use std::{fs, path::Path};

pub const MIN_RUNTIME_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;
pub const MIN_BACKUP_HEADROOM_BYTES: u64 = 512 * 1024 * 1024;
const BACKUP_FIXED_MARGIN_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StorageHealth {
    pub schema_version: u32,
    pub database_bytes: u64,
    pub wal_bytes: u64,
    pub shm_bytes: u64,
    pub workspace_database_bytes: u64,
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub runtime_required_bytes: u64,
    pub backup_required_bytes: u64,
    pub runtime_write_safe: bool,
    pub backup_safe: bool,
}

fn regular_file_bytes(path: &Path) -> Result<u64> {
    if !path.exists() {
        return Ok(0);
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "Workspace database files must not be symlinks"
    );
    ensure!(
        metadata.is_file(),
        "Workspace database path is not a regular file"
    );
    Ok(metadata.len())
}

pub fn required_headroom(database_bytes: u64, wal_bytes: u64, shm_bytes: u64) -> (u64, u64) {
    let workspace = database_bytes
        .saturating_add(wal_bytes)
        .saturating_add(shm_bytes);
    let runtime = MIN_RUNTIME_HEADROOM_BYTES
        .max(workspace.saturating_div(4).saturating_add(64 * 1024 * 1024));
    let backup = MIN_BACKUP_HEADROOM_BYTES.max(
        database_bytes
            .saturating_mul(2)
            .saturating_add(wal_bytes)
            .saturating_add(shm_bytes)
            .saturating_add(BACKUP_FIXED_MARGIN_BYTES),
    );
    (runtime, backup)
}

/// Privacy-safe filesystem headroom for the workspace volume.
///
/// These are conservative engineering guardrails, not availability SLOs.
/// A positive check cannot guarantee a later write succeeds because other
/// processes may consume disk space after measurement.
pub fn inspect(data_dir: &Path) -> Result<StorageHealth> {
    ensure!(data_dir.is_dir(), "Workspace data directory is missing");
    ensure!(
        !fs::symlink_metadata(data_dir)?.file_type().is_symlink(),
        "Workspace data directory must not be a symlink"
    );
    let database_bytes = regular_file_bytes(&data_dir.join("state.sqlite3"))?;
    let wal_bytes = regular_file_bytes(&data_dir.join("state.sqlite3-wal"))?;
    let shm_bytes = regular_file_bytes(&data_dir.join("state.sqlite3-shm"))?;
    let workspace_database_bytes = database_bytes
        .saturating_add(wal_bytes)
        .saturating_add(shm_bytes);
    let stats = fs2::statvfs(data_dir)?;
    let available_bytes = stats.available_space();
    let total_bytes = stats.total_space();
    let (runtime_required_bytes, backup_required_bytes) =
        required_headroom(database_bytes, wal_bytes, shm_bytes);
    Ok(StorageHealth {
        schema_version: 1,
        database_bytes,
        wal_bytes,
        shm_bytes,
        workspace_database_bytes,
        available_bytes,
        total_bytes,
        runtime_required_bytes,
        backup_required_bytes,
        runtime_write_safe: available_bytes >= runtime_required_bytes,
        backup_safe: available_bytes >= backup_required_bytes,
    })
}

pub fn ensure_runtime_write_headroom(data_dir: &Path) -> Result<StorageHealth> {
    let health = inspect(data_dir)?;
    ensure!(
        health.runtime_write_safe,
        "Insufficient storage headroom for durable application state: available={} bytes, required={} bytes",
        health.available_bytes,
        health.runtime_required_bytes
    );
    Ok(health)
}

pub fn ensure_backup_destination_headroom(
    destination_parent: &Path,
    required_bytes: u64,
) -> Result<()> {
    ensure!(
        destination_parent.is_dir(),
        "Backup parent directory is missing"
    );
    ensure!(
        !fs::symlink_metadata(destination_parent)?
            .file_type()
            .is_symlink(),
        "Backup parent directory must not be a symlink"
    );
    let available = fs2::available_space(destination_parent)?;
    ensure!(
        available >= required_bytes,
        "Insufficient storage headroom for verified backup: available={available} bytes, required={required_bytes} bytes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headroom_budget_is_bounded_and_grows_with_state() {
        let (small_runtime, small_backup) = required_headroom(1024, 0, 0);
        assert_eq!(small_runtime, MIN_RUNTIME_HEADROOM_BYTES);
        assert_eq!(small_backup, MIN_BACKUP_HEADROOM_BYTES);

        let gib = 1024 * 1024 * 1024;
        let (large_runtime, large_backup) = required_headroom(4 * gib, gib, 4096);
        assert!(large_runtime > MIN_RUNTIME_HEADROOM_BYTES);
        assert!(large_backup > MIN_BACKUP_HEADROOM_BYTES);
        assert!(large_backup > large_runtime);
    }

    #[test]
    fn workspace_measurement_is_privacy_safe_and_cross_platform() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("state.sqlite3"), vec![0u8; 4096]).unwrap();
        let health = inspect(root.path()).unwrap();
        assert_eq!(health.schema_version, 1);
        assert_eq!(health.database_bytes, 4096);
        assert!(health.total_bytes >= health.available_bytes);
        assert!(health.runtime_required_bytes >= MIN_RUNTIME_HEADROOM_BYTES);
        assert!(health.backup_required_bytes >= MIN_BACKUP_HEADROOM_BYTES);
    }
}
