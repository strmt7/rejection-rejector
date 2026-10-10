use crate::{
    config::Settings,
    store::Store,
    vault::{InstanceLock, RecoveryKeyEnvelope, Vault, private_dir, vault_id, write_new_private},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

mod restore;
use restore::restore_backup_with_vault;

const MANIFEST_NAME: &str = "backup-manifest.json";
const DATABASE_NAME: &str = "state.sqlite3";
const VAULT_ID_NAME: &str = "vault-id";
const RECOVERY_KEY_NAME: &str = "recovery-key.json";
const RESTORE_REARM_NAME: &str = ".restore-rearm-required";
const RESTORE_REARM_CONTENT: &[u8] = b"restore-rearm:v1\n";
const SCHEDULED_BACKUP_PREFIX: &str = "rejection-rejector-auto-";
pub const LAST_SCHEDULED_BACKUP_META: &str = "scheduled_backup_last_success";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub format_version: u32,
    pub app_version: String,
    pub created_at: DateTime<Utc>,
    pub schema_version: i64,
    pub database_file: String,
    pub database_sha256: String,
    pub vault_id_file: String,
    pub vault_id: String,
    #[serde(default)]
    pub audit_head: String,
    pub portable: bool,
    pub recovery_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreReport {
    pub format_version: u32,
    pub restored_at: DateTime<Utc>,
    pub source_backup_created_at: DateTime<Utc>,
    pub source_database_sha256: String,
    pub source_audit_head: String,
    pub restored_schema_version: i64,
    pub rollback_directory: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduledBackupStatus {
    pub schema_version: u32,
    pub enabled: bool,
    pub interval_hours: u16,
    pub keep: u8,
    pub last_success_at: Option<DateTime<Utc>>,
    pub age_seconds: Option<i64>,
    pub overdue: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupIsolationStatus {
    pub schema_version: u32,
    pub configured: bool,
    pub destination_exists: bool,
    pub distinct_failure_domain: Option<bool>,
    pub measurement: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryDrillReport {
    pub format_version: u32,
    pub drilled_at: DateTime<Utc>,
    pub source_backup_created_at: DateTime<Utc>,
    pub source_database_sha256: String,
    pub source_audit_head: String,
    pub restored_schema_version: i64,
    pub metadata_records: u64,
    pub item_records: u64,
    pub audit_events: u64,
    pub delivery_records: u64,
    pub isolated_restore_succeeded: bool,
    pub note: String,
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(crate::hex_lower(digest.finalize()))
}

fn read_small(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(path.is_file(), "{} is missing", path.display());
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "{} must not be a symlink",
        path.display()
    );
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.len() <= limit,
        "{} exceeds size limit",
        path.display()
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "{} exceeds size limit",
        path.display()
    );
    Ok(bytes)
}

/// An offline restore may bring back an old Automatic/sending permission.
/// The marker is created before replacing the live database and cleared only
/// after the next normal startup has durably disarmed delivery.
pub fn restore_rearm_required(directory: &Path) -> Result<bool> {
    let path = directory.join(RESTORE_REARM_NAME);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Restore reauthorization marker must be a regular file"
            );
            ensure!(
                read_small(&path, 64)? == RESTORE_REARM_CONTENT,
                "Restore reauthorization marker is malformed; refusing unattended startup"
            );
            Ok(true)
        }
    }
}

fn mark_restore_rearm_required(directory: &Path) -> Result<()> {
    if restore_rearm_required(directory)? {
        return Ok(());
    }
    write_new_private(&directory.join(RESTORE_REARM_NAME), RESTORE_REARM_CONTENT)
}

pub fn clear_restore_rearm_marker(directory: &Path) -> Result<()> {
    ensure!(
        restore_rearm_required(directory)?,
        "Restore reauthorization marker is missing or invalid"
    );
    fs::remove_file(directory.join(RESTORE_REARM_NAME))?;
    Ok(())
}

fn write_new_private_atomic(path: &Path, data: &[u8]) -> Result<()> {
    ensure!(!path.exists(), "{} already exists", path.display());
    let parent = path
        .parent()
        .filter(|candidate| !candidate.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    ensure!(
        !fs::symlink_metadata(parent)?.file_type().is_symlink(),
        "Private-file parent directory must not be a symlink"
    );

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(data)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| anyhow::Error::from(error.error))?;
    Ok(())
}

fn copy_private_new(source: &Path, destination: &Path) -> Result<()> {
    ensure!(source.is_file(), "{} is missing", source.display());
    ensure!(
        !fs::symlink_metadata(source)?.file_type().is_symlink(),
        "{} must not be a symlink",
        source.display()
    );
    let mut input = fs::File::open(source)?;
    copy_private_from_reader(&mut input, destination)
}

/// A read/write error must not leave a partial encrypted SQLite staging file.
/// Open with create_new before cleanup, so an existing destination is never removed.
fn copy_private_from_reader(input: &mut impl Read, destination: &Path) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(destination)?;
    let result = (|| -> Result<()> {
        std::io::copy(input, &mut output)?;
        output.flush()?;
        output.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(destination);
    }
    result
}

fn read_recovery_envelope(path: &Path) -> Result<RecoveryKeyEnvelope> {
    let bytes = read_small(path, 64 * 1024)?;
    serde_json::from_slice(&bytes).context("Recovery-key envelope is invalid")
}

fn verify_vault_marker(database: &Path, vault: &Vault) -> Result<()> {
    ensure!(database.is_file(), "Recovery database is missing");
    ensure!(
        !fs::symlink_metadata(database)?.file_type().is_symlink(),
        "Recovery database must not be a symlink"
    );
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let encrypted: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM meta WHERE name='vault_check'",
            [],
            |row| row.get(0),
        )
        .context("Recovery database vault marker is missing")?;
    let marker: String = vault.open_value("meta/vault_check", &encrypted)?;
    ensure!(
        marker == "rejection-rejector:v1",
        "Recovery key does not authenticate this database"
    );
    Ok(())
}

fn validate_bundle_files(directory: &Path) -> Result<(BackupManifest, PathBuf)> {
    ensure!(directory.is_dir(), "Backup directory is missing");
    ensure!(
        !fs::symlink_metadata(directory)?.file_type().is_symlink(),
        "Backup directory must not be a symlink"
    );
    let manifest_bytes = read_small(&directory.join(MANIFEST_NAME), 64 * 1024)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&manifest_bytes).context("Backup manifest is invalid")?;
    ensure!(
        matches!(manifest.format_version, 1 | 2),
        "Unsupported backup format"
    );
    ensure!(
        manifest.database_file == DATABASE_NAME && manifest.vault_id_file == VAULT_ID_NAME,
        "Backup manifest contains unexpected file names"
    );
    ensure!(!manifest.portable, "Unsupported portable-backup marker");

    let vault_id_bytes = read_small(&directory.join(VAULT_ID_NAME), 256)?;
    let vault_id = std::str::from_utf8(&vault_id_bytes)?.trim();
    ensure!(
        vault_id == manifest.vault_id && uuid::Uuid::parse_str(vault_id).is_ok(),
        "Backup vault identifier does not match its manifest"
    );

    let database = directory.join(DATABASE_NAME);
    ensure!(
        database.is_file() && !fs::symlink_metadata(&database)?.file_type().is_symlink(),
        "Backup database must be a regular file, not a symlink"
    );
    let actual_hash = sha256_file(&database)?;
    ensure!(
        actual_hash == manifest.database_sha256,
        "Backup database checksum mismatch"
    );
    Ok((manifest, database))
}

/// Create a same-vault backup atomically within the destination parent.
///
/// The database remains application-layer encrypted. The copied vault identifier
/// is not the master key; recovery on another machine still requires the original
/// OS credential-store key.
pub fn create_backup(store: &Store, data_dir: &Path, destination: &Path) -> Result<BackupManifest> {
    store.integrity_check()?;
    ensure!(!destination.exists(), "Backup destination already exists");
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    ensure!(
        !fs::symlink_metadata(parent)?.file_type().is_symlink(),
        "Backup parent directory must not be a symlink"
    );
    let workspace_storage = crate::storage::inspect(data_dir)?;
    crate::storage::ensure_backup_destination_headroom(
        parent,
        workspace_storage.backup_required_bytes,
    )?;

    let name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .context("Backup destination needs a valid directory name")?;
    ensure!(
        !name.is_empty() && name != "." && name != "..",
        "Invalid backup directory name"
    );
    let temporary = parent.join(format!(".{name}.partial-{}", uuid::Uuid::new_v4()));
    private_dir(&temporary)?;

    let result = (|| -> Result<BackupManifest> {
        let database = temporary.join(DATABASE_NAME);
        store.backup_to(&database)?;

        let vault_id_path = data_dir.join(VAULT_ID_NAME);
        let vault_id_bytes = read_small(&vault_id_path, 256)?;
        let vault_id = std::str::from_utf8(&vault_id_bytes)?.trim().to_owned();
        ensure!(
            uuid::Uuid::parse_str(&vault_id).is_ok(),
            "Current vault identifier is invalid"
        );
        write_new_private(&temporary.join(VAULT_ID_NAME), vault_id.as_bytes())?;

        let manifest = BackupManifest {
            format_version: 2,
            app_version: env!("CARGO_PKG_VERSION").into(),
            created_at: Utc::now(),
            schema_version: store.schema_version()?,
            database_file: DATABASE_NAME.into(),
            database_sha256: sha256_file(&database)?,
            vault_id_file: VAULT_ID_NAME.into(),
            vault_id,
            audit_head: store.audit_head()?,
            portable: false,
            recovery_note: "Same-vault backup. Restoring on another machine requires the original OS-protected master key; this directory does not contain that key.".into(),
        };
        write_new_private(
            &temporary.join(MANIFEST_NAME),
            &serde_json::to_vec_pretty(&manifest)?,
        )?;
        verify_backup(store, &temporary)?;
        Ok(manifest)
    })();

    match result {
        Ok(manifest) => {
            fs::rename(&temporary, destination)?;
            Ok(manifest)
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary);
            Err(error)
        }
    }
}

fn backup_same_filesystem(workspace: &Path, backup: &Path) -> Result<Option<bool>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Some(
            fs::metadata(workspace)?.dev() == fs::metadata(backup)?.dev(),
        ))
    }
    #[cfg(windows)]
    {
        use std::path::Component;
        fn volume_prefix(path: &Path) -> Result<Option<String>> {
            let canonical = fs::canonicalize(path)?;
            Ok(canonical
                .components()
                .find_map(|component| match component {
                    Component::Prefix(prefix) => {
                        Some(prefix.as_os_str().to_string_lossy().to_ascii_lowercase())
                    }
                    _ => None,
                }))
        }
        let workspace_prefix = volume_prefix(workspace)?;
        let backup_prefix = volume_prefix(backup)?;
        Ok(match (workspace_prefix, backup_prefix) {
            (Some(workspace), Some(backup)) => Some(workspace == backup),
            _ => None,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (workspace, backup);
        Ok(None)
    }
}

pub fn backup_isolation_status(
    data_dir: &Path,
    settings: &Settings,
) -> Result<BackupIsolationStatus> {
    if !settings.scheduled_backup_enabled || settings.scheduled_backup_directory.is_empty() {
        return Ok(BackupIsolationStatus {
            schema_version: 1,
            configured: false,
            destination_exists: false,
            distinct_failure_domain: None,
            measurement: "disabled",
        });
    }
    let destination = PathBuf::from(&settings.scheduled_backup_directory);
    if !destination.exists() {
        return Ok(BackupIsolationStatus {
            schema_version: 1,
            configured: true,
            destination_exists: false,
            distinct_failure_domain: None,
            measurement: "destination_missing",
        });
    }
    ensure!(
        destination.is_dir() && !fs::symlink_metadata(&destination)?.file_type().is_symlink(),
        "Scheduled backup destination must be a real directory"
    );
    let same = backup_same_filesystem(data_dir, &destination)?;
    Ok(BackupIsolationStatus {
        schema_version: 1,
        configured: true,
        destination_exists: true,
        distinct_failure_domain: same.map(|value| !value),
        measurement: if cfg!(unix) {
            "filesystem_device_id"
        } else if cfg!(windows) {
            "windows_volume_prefix"
        } else {
            "unsupported_platform"
        },
    })
}

pub fn scheduled_backup_status(
    store: &Store,
    settings: &Settings,
    now: DateTime<Utc>,
) -> Result<ScheduledBackupStatus> {
    let last_success_at: Option<DateTime<Utc>> = store.meta(LAST_SCHEDULED_BACKUP_META)?;
    let age_seconds = last_success_at.map(|at| now.signed_duration_since(at).num_seconds().max(0));
    let due_after = i64::from(settings.scheduled_backup_interval_hours) * 60 * 60;
    let overdue =
        settings.scheduled_backup_enabled && age_seconds.is_none_or(|age| age >= due_after);
    Ok(ScheduledBackupStatus {
        schema_version: 1,
        enabled: settings.scheduled_backup_enabled,
        interval_hours: settings.scheduled_backup_interval_hours,
        keep: settings.scheduled_backup_keep,
        last_success_at,
        age_seconds,
        overdue,
    })
}

pub fn prune_verified_scheduled_backups(
    store: &Store,
    parent: &Path,
    keep: usize,
) -> Result<usize> {
    ensure!(
        (2..=30).contains(&keep),
        "Scheduled backup retention is invalid"
    );
    if !parent.exists() {
        return Ok(0);
    }
    ensure!(parent.is_dir(), "Scheduled backup root is not a directory");
    ensure!(
        !fs::symlink_metadata(parent)?.file_type().is_symlink(),
        "Scheduled backup root must not be a symlink"
    );
    let mut candidates = Vec::<(DateTime<Utc>, PathBuf)>::new();
    let mut scanned = 0usize;
    for entry in fs::read_dir(parent)? {
        scanned = scanned.saturating_add(1);
        ensure!(
            scanned <= 512,
            "Scheduled backup root contains too many entries to prune safely"
        );
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(SCHEDULED_BACKUP_PREFIX) {
            continue;
        }
        if let Ok(manifest) = verify_backup(store, &path) {
            candidates.push((manifest.created_at, path));
        }
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
    let mut removed = 0usize;
    for (_, path) in candidates.into_iter().skip(keep) {
        fs::remove_dir_all(&path)?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

pub fn create_scheduled_backup(
    store: &mut Store,
    data_dir: &Path,
    settings: &Settings,
    now: DateTime<Utc>,
) -> Result<BackupManifest> {
    ensure!(
        settings.scheduled_backup_enabled,
        "Scheduled backups are not enabled"
    );
    settings.validate()?;
    let root = PathBuf::from(&settings.scheduled_backup_directory);
    fs::create_dir_all(&root)?;
    ensure!(
        !fs::symlink_metadata(&root)?.file_type().is_symlink(),
        "Scheduled backup root must not be a symlink"
    );
    let destination = root.join(format!(
        "{SCHEDULED_BACKUP_PREFIX}{}-{}",
        now.format("%Y%m%d-%H%M%S"),
        uuid::Uuid::new_v4().simple()
    ));
    let manifest = create_backup(store, data_dir, &destination)?;
    store.set_meta(LAST_SCHEDULED_BACKUP_META, &now)?;
    store.log(
        "backup.scheduled_succeeded",
        None,
        "Scheduled encrypted backup created and verified",
    )?;
    if prune_verified_scheduled_backups(store, &root, usize::from(settings.scheduled_backup_keep))
        .is_err()
    {
        store.log(
            "backup.retention_warning",
            None,
            "Scheduled backup succeeded but old verified backups could not be fully pruned",
        )?;
    }
    Ok(manifest)
}

/// Export a passphrase-wrapped master-key envelope for off-machine disaster recovery.
///
/// The output is intentionally separate from normal backups so organizations can
/// store encrypted data and its recovery credential in different locations.
pub fn export_recovery_key(
    data_dir: &Path,
    passphrase: &[u8],
    destination: &Path,
) -> Result<RecoveryKeyEnvelope> {
    ensure!(
        !destination.exists(),
        "Recovery-key destination already exists"
    );
    let live_database = data_dir.join(DATABASE_NAME);
    ensure!(
        live_database.is_file(),
        "Recovery-key export requires an existing workspace database"
    );
    let vault = Vault::open(data_dir)?;
    verify_vault_marker(&live_database, &vault)
        .context("Current workspace does not authenticate under the active vault key")?;
    let id = vault_id(data_dir)?;
    let envelope = vault.recovery_envelope(&id, passphrase)?;
    write_new_private_atomic(destination, &serde_json::to_vec_pretty(&envelope)?)?;
    Ok(envelope)
}

/// Prove a recovery-key envelope can unlock a specific backup without writing any
/// key material to the OS credential store.
pub fn verify_recovery_key_for_backup(
    backup_dir: &Path,
    recovery_key_file: &Path,
    passphrase: &[u8],
) -> Result<RecoveryKeyEnvelope> {
    let (manifest, database) = validate_bundle_files(backup_dir)?;
    let envelope = read_recovery_envelope(recovery_key_file)?;
    ensure!(
        envelope.vault_id == manifest.vault_id,
        "Recovery key belongs to a different vault"
    );
    let recovered = Vault::from_recovery_envelope(&envelope, passphrase)?;
    verify_vault_marker(&database, &recovered)?;
    Ok(envelope)
}

/// Install a previously verified recovery key into the local OS credential store.
///
/// Existing credentials are never replaced. If a live database already exists it
/// must authenticate under the recovered key before installation is attempted.
pub fn import_recovery_key_for_backup(
    data_dir: &Path,
    backup_dir: &Path,
    recovery_key_file: &Path,
    passphrase: &[u8],
) -> Result<RecoveryKeyEnvelope> {
    let envelope = verify_recovery_key_for_backup(backup_dir, recovery_key_file, passphrase)?;
    private_dir(data_dir)?;

    let id_path = data_dir.join(VAULT_ID_NAME);
    let created_vault_id = !id_path.exists();
    if created_vault_id {
        write_new_private(&id_path, envelope.vault_id.as_bytes())?;
    } else {
        ensure!(
            vault_id(data_dir)? == envelope.vault_id,
            "Workspace belongs to a different vault"
        );
    }

    let recovered = Vault::from_recovery_envelope(&envelope, passphrase)?;
    let live = data_dir.join(DATABASE_NAME);
    if live.exists()
        && let Err(error) = verify_vault_marker(&live, &recovered)
    {
        if created_vault_id {
            let _ = fs::remove_file(&id_path);
        }
        return Err(
            error.context("Existing workspace does not authenticate under the recovered vault key")
        );
    }

    if let Err(error) = recovered.install_os_key_if_missing(data_dir) {
        if created_vault_id {
            let _ = fs::remove_file(&id_path);
        }
        return Err(error);
    }
    Ok(envelope)
}

/// Restore a workspace from a portable recovery envelope without first opening
/// or creating the normal application vault.
///
/// The backup and wrapped key are authenticated in an isolated temporary
/// workspace before the target directory is touched. Only then is the target
/// locked, its vault identity checked, and (when needed) the recovered key
/// installed into the OS credential store before the transactional restore.
pub fn recover_workspace_from_backup(
    data_dir: &Path,
    backup_dir: &Path,
    recovery_key_file: &Path,
    passphrase: &[u8],
) -> Result<RestoreReport> {
    let (manifest, backup_database) = validate_bundle_files(backup_dir)?;
    let envelope = read_recovery_envelope(recovery_key_file)?;
    ensure!(
        envelope.vault_id == manifest.vault_id,
        "Recovery key belongs to a different vault"
    );
    let recovered = Vault::from_recovery_envelope(&envelope, passphrase)?;
    verify_vault_marker(&backup_database, &recovered)
        .context("Recovery key does not authenticate the selected backup")?;

    // Prove the full production restore path before mutating the requested target.
    let isolated = tempfile::tempdir().context("Cannot create isolated pre-recovery workspace")?;
    private_dir(isolated.path())?;
    write_new_private(
        &isolated.path().join(VAULT_ID_NAME),
        manifest.vault_id.as_bytes(),
    )?;
    restore_backup_with_vault(isolated.path(), backup_dir, &manifest, recovered.clone())
        .context("Portable recovery preflight failed in the isolated workspace")?;

    let _lock = InstanceLock::acquire(data_dir)?;
    private_dir(data_dir)?;
    let vault_id_path = data_dir.join(VAULT_ID_NAME);
    let created_vault_id = !vault_id_path.exists();
    if created_vault_id {
        write_new_private(&vault_id_path, manifest.vault_id.as_bytes())?;
    } else {
        ensure!(
            vault_id(data_dir)? == manifest.vault_id,
            "Target workspace belongs to a different vault"
        );
    }

    let live = data_dir.join(DATABASE_NAME);
    if live.exists() {
        verify_vault_marker(&live, &recovered).context(
            "Existing target database does not authenticate under the recovered vault key",
        )?;
    }

    #[cfg(any(windows, target_os = "macos"))]
    {
        match Vault::open(data_dir) {
            Ok(active) => {
                verify_vault_marker(&backup_database, &active).context(
                    "Existing OS credential does not authenticate the selected recovery backup",
                )?;
            }
            Err(_) => {
                if let Err(error) = recovered.install_os_key_if_missing(data_dir) {
                    if created_vault_id && !live.exists() {
                        let _ = fs::remove_file(&vault_id_path);
                    }
                    return Err(error);
                }
            }
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        // Linux deliberately has no OS-key import path. A matching
        // RR_VAULT_PASSPHRASE-derived vault must already be available.
        let active = Vault::open(data_dir)?;
        verify_vault_marker(&backup_database, &active)
            .context("Linux recovery requires the original RR_VAULT_PASSPHRASE for this vault")?;
    }

    restore_backup_with_vault(data_dir, backup_dir, &manifest, recovered)
        .context("Portable recovery could not install the validated backup")
}

/// Verify manifest, checksum, vault identity and SQLite structure without
/// modifying the backup database.
pub fn verify_backup(store: &Store, directory: &Path) -> Result<BackupManifest> {
    let (manifest, database) = validate_bundle_files(directory)?;
    let verification = store.verify_backup_file(&database)?;
    ensure!(
        verification.schema_version == manifest.schema_version,
        "Backup schema does not match its manifest"
    );
    if manifest.format_version >= 2 {
        let audit_head = verification
            .audit_head
            .context("Version 2 backup is missing an audit chain")?;
        ensure!(
            manifest.audit_head == audit_head,
            "Backup audit head does not match its manifest"
        );
    }
    Ok(manifest)
}

/// Restore a backup into a workspace while the desktop/worker is stopped.
///
/// This operation acquires the same exclusive instance lock as the application.
/// It stages and validates the backup before touching the live database, preserves
/// the previous SQLite/WAL/SHM files in a private rollback directory, and restores
/// them automatically if the final database cannot be opened and verified.
/// Exercise the production restore path in an isolated temporary workspace.
///
/// This never mutates the live database. It proves that the backup can be
/// restored, reopened, deeply authenticated and reconciled with its manifest
/// using the current vault key.
pub fn recovery_drill(data_dir: &Path, backup_dir: &Path) -> Result<RecoveryDrillReport> {
    let vault = Vault::open(data_dir)?;
    recovery_drill_with_vault(data_dir, backup_dir, vault)
}

fn recovery_drill_with_vault(
    data_dir: &Path,
    backup_dir: &Path,
    vault: Vault,
) -> Result<RecoveryDrillReport> {
    let (manifest, _) = validate_bundle_files(backup_dir)?;
    let current_vault_id = vault_id(data_dir)?;
    ensure!(
        current_vault_id == manifest.vault_id,
        "Backup vault identifier does not match this workspace"
    );

    let isolated =
        tempfile::tempdir().context("Cannot create isolated recovery-drill workspace")?;
    let drill_dir = isolated.path();
    private_dir(drill_dir)?;
    write_new_private(&drill_dir.join(VAULT_ID_NAME), manifest.vault_id.as_bytes())?;

    let restore = restore_backup_with_vault(drill_dir, backup_dir, &manifest, vault.clone())
        .context("Isolated recovery drill could not restore the backup")?;

    let restored_database = drill_dir.join(DATABASE_NAME);
    let restored = Store::open(&restored_database, vault)?;
    restored.integrity_check()?;
    let verification = restored.verify_backup_file(&restored_database)?;
    ensure!(
        verification.schema_version == restore.restored_schema_version,
        "Recovery drill restored an unexpected schema version"
    );
    if manifest.format_version >= 2 {
        ensure!(
            restored.contains_audit_anchor(&manifest.audit_head)?,
            "Recovery drill no longer contains the original backup audit head"
        );
    }

    Ok(RecoveryDrillReport {
        format_version: 1,
        drilled_at: Utc::now(),
        source_backup_created_at: manifest.created_at,
        source_database_sha256: manifest.database_sha256,
        source_audit_head: manifest.audit_head,
        restored_schema_version: restore.restored_schema_version,
        metadata_records: verification.metadata_records,
        item_records: verification.item_records,
        audit_events: verification.audit_events,
        delivery_records: verification.delivery_records,
        isolated_restore_succeeded: true,
        note: "Backup restored and deeply authenticated in an isolated temporary workspace; live state was not modified.".into(),
    })
}

pub fn restore_backup(data_dir: &Path, backup_dir: &Path) -> Result<RestoreReport> {
    let _lock = InstanceLock::acquire(data_dir)?;
    let (manifest, _) = validate_bundle_files(backup_dir)?;
    let vault_id_path = data_dir.join(VAULT_ID_NAME);
    let created_vault_id = !vault_id_path.exists();

    if created_vault_id {
        write_new_private(&vault_id_path, manifest.vault_id.as_bytes())?;
    } else {
        let current = std::str::from_utf8(&read_small(&vault_id_path, 256)?)?
            .trim()
            .to_owned();
        ensure!(
            current == manifest.vault_id,
            "Backup vault identifier does not match this workspace"
        );
    }

    let vault = match Vault::open(data_dir) {
        Ok(vault) => vault,
        Err(error) => {
            if created_vault_id {
                let _ = fs::remove_file(&vault_id_path);
            }
            return Err(error);
        }
    };
    restore_backup_with_vault(data_dir, backup_dir, &manifest, vault)
}

pub fn backup_manifest_path(directory: &Path) -> PathBuf {
    directory.join(MANIFEST_NAME)
}

pub fn recovery_key_default_path(directory: &Path) -> PathBuf {
    directory.join(RECOVERY_KEY_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::test_support::lock_credential_store;
    use crate::{
        types::{Source, Stub},
        vault::Vault,
    };
    use std::io::Write;

    #[test]
    fn restore_rearm_marker_is_durable_bounded_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!restore_rearm_required(dir.path()).unwrap());
        mark_restore_rearm_required(dir.path()).unwrap();
        assert!(restore_rearm_required(dir.path()).unwrap());
        mark_restore_rearm_required(dir.path()).unwrap();
        assert!(restore_rearm_required(dir.path()).unwrap());

        let marker = dir.path().join(RESTORE_REARM_NAME);
        fs::write(&marker, b"invalid").unwrap();
        assert!(restore_rearm_required(dir.path()).is_err());
        assert!(clear_restore_rearm_marker(dir.path()).is_err());
        fs::write(&marker, RESTORE_REARM_CONTENT).unwrap();
        clear_restore_rearm_marker(dir.path()).unwrap();
        assert!(!restore_rearm_required(dir.path()).unwrap());
    }

    #[test]
    fn backup_isolation_detects_same_failure_domain_for_local_fixture() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let backups = root.path().join("backups");
        private_dir(&data).unwrap();
        fs::create_dir_all(&backups).unwrap();
        let settings = Settings {
            scheduled_backup_enabled: true,
            scheduled_backup_directory: backups.to_string_lossy().into_owned(),
            ..Settings::default()
        };
        let status = backup_isolation_status(&data, &settings).unwrap();
        assert!(status.configured);
        assert!(status.destination_exists);
        if cfg!(any(unix, windows)) {
            assert_eq!(status.distinct_failure_domain, Some(false));
        }
    }

    #[test]
    fn scheduled_backup_retention_only_removes_verified_same_vault_backups() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let backups = root.path().join("backups");
        private_dir(&data).unwrap();
        fs::create_dir_all(&backups).unwrap();
        let vault_id = uuid::Uuid::new_v4().to_string();
        write_new_private(&data.join(VAULT_ID_NAME), vault_id.as_bytes()).unwrap();
        let vault = Vault::random();
        let mut store = Store::open(&data.join(DATABASE_NAME), vault).unwrap();

        let mut settings = Settings {
            scheduled_backup_enabled: true,
            scheduled_backup_directory: backups.to_string_lossy().into_owned(),
            scheduled_backup_keep: 2,
            ..Settings::default()
        };
        settings.validate().unwrap();

        for offset in 0..3 {
            create_scheduled_backup(
                &mut store,
                &data,
                &settings,
                Utc::now() + chrono::Duration::seconds(offset),
            )
            .unwrap();
        }
        let valid_count = fs::read_dir(&backups)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(SCHEDULED_BACKUP_PREFIX)
            })
            .count();
        assert_eq!(valid_count, 2);

        let unrelated = backups.join("do-not-delete");
        fs::create_dir_all(&unrelated).unwrap();
        prune_verified_scheduled_backups(&store, &backups, 2).unwrap();
        assert!(unrelated.is_dir());

        settings.scheduled_backup_enabled = false;
        let status = scheduled_backup_status(&store, &settings, Utc::now()).unwrap();
        assert!(!status.overdue);
    }

    #[test]
    fn interrupted_private_copy_removes_partial_file_but_never_an_existing_file() {
        struct OneChunkThenFailure {
            sent: bool,
        }
        impl std::io::Read for OneChunkThenFailure {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.sent {
                    return Err(std::io::Error::other("injected I/O failure"));
                }
                self.sent = true;
                buf[0] = b'X';
                Ok(1)
            }
        }

        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("stage.sqlite3");
        let mut reader = OneChunkThenFailure { sent: false };
        assert!(copy_private_from_reader(&mut reader, &destination).is_err());
        assert!(!destination.exists());

        fs::write(&destination, b"do not overwrite").unwrap();
        let mut reader = OneChunkThenFailure { sent: false };
        assert!(copy_private_from_reader(&mut reader, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"do not overwrite");
    }

    #[test]
    fn atomic_private_write_never_overwrites_an_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("recovery-key.json");
        write_new_private_atomic(&destination, b"first").unwrap();
        assert!(write_new_private_atomic(&destination, b"second").is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"first");
    }

    #[test]
    fn recovery_key_export_requires_an_existing_authenticated_workspace() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("empty-workspace");
        private_dir(&data).unwrap();
        let destination = root.path().join("recovery-key.json");
        assert!(
            export_recovery_key(&data, b"correct horse battery staple", &destination,).is_err()
        );
        assert!(!destination.exists());
        assert!(!data.join(VAULT_ID_NAME).exists());
    }

    #[test]
    fn wrapped_recovery_key_authenticates_the_backup_without_plaintext_key_export() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        private_dir(&data).unwrap();
        let vault_id_value = uuid::Uuid::new_v4().to_string();
        write_new_private(&data.join(VAULT_ID_NAME), vault_id_value.as_bytes()).unwrap();
        let vault = Vault::random();
        let store = Store::open(&data.join(DATABASE_NAME), vault.clone()).unwrap();

        let backup = root.path().join("backup");
        create_backup(&store, &data, &backup).unwrap();

        let passphrase = b"correct horse battery staple";
        let recovery_file = root.path().join("recovery-key.json");
        let envelope = vault
            .recovery_envelope(&vault_id_value, passphrase)
            .unwrap();
        write_new_private(
            &recovery_file,
            &serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();

        let verified = verify_recovery_key_for_backup(&backup, &recovery_file, passphrase).unwrap();
        assert_eq!(verified.vault_id, vault_id_value);
        assert!(
            verify_recovery_key_for_backup(
                &backup,
                &recovery_file,
                b"wrong passphrase but definitely long enough",
            )
            .is_err()
        );

        let serialized = fs::read(&recovery_file).unwrap();
        assert!(
            !serialized
                .windows(passphrase.len())
                .any(|window| window == passphrase)
        );
        assert!(
            !serialized
                .windows(b"secret".len())
                .any(|window| window == b"secret")
        );
    }

    #[test]
    fn recovery_drill_restores_without_mutating_live_workspace() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        private_dir(&data).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&data.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        let vault = Vault::random();
        let mut store = Store::open(&data.join(DATABASE_NAME), vault.clone()).unwrap();
        store
            .insert_stub(
                crate::types::Stub {
                    account: "me@example.com".into(),
                    provider_id: "drill-message".into(),
                    thread_id: "drill-thread".into(),
                    source: crate::types::Source::Gmail,
                },
                Utc::now(),
            )
            .unwrap();

        let backup = root.path().join("backup");
        let manifest = create_backup(&store, &data, &backup).unwrap();
        let live_hash_before = sha256_file(&data.join(DATABASE_NAME)).unwrap();

        let report = recovery_drill_with_vault(&data, &backup, vault).unwrap();
        assert!(report.isolated_restore_succeeded);
        assert_eq!(report.restored_schema_version, manifest.schema_version);
        assert_eq!(report.item_records, 1);
        assert_eq!(report.source_audit_head, manifest.audit_head);

        let live_hash_after = sha256_file(&data.join(DATABASE_NAME)).unwrap();
        assert_eq!(live_hash_before, live_hash_after);
    }

    #[test]
    fn restore_rejects_manifest_changes_before_modifying_target() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        private_dir(&source).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&source.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        let vault = Vault::random();
        let store = Store::open(&source.join(DATABASE_NAME), vault.clone()).unwrap();
        let backup = root.path().join("backup");
        let manifest = create_backup(&store, &source, &backup).unwrap();

        let target = root.path().join("target");
        private_dir(&target).unwrap();
        write_new_private(&target.join(VAULT_ID_NAME), id.as_bytes()).unwrap();

        let mut altered_manifest = manifest.clone();
        altered_manifest.recovery_note.push_str(" modified");
        fs::write(
            backup.join(MANIFEST_NAME),
            serde_json::to_vec_pretty(&altered_manifest).unwrap(),
        )
        .unwrap();

        assert!(restore_backup_with_vault(&target, &backup, &manifest, vault).is_err());
        assert!(!target.join(DATABASE_NAME).exists());
        assert!(!target.join("recovery").exists());
    }

    #[cfg(unix)]
    #[test]
    fn backup_validation_refuses_a_symlinked_database() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        private_dir(&source).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&source.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        let vault = Vault::random();
        let store = Store::open(&source.join(DATABASE_NAME), vault).unwrap();
        let backup = root.path().join("backup");
        create_backup(&store, &source, &backup).unwrap();

        let database = backup.join(DATABASE_NAME);
        let moved = root.path().join("outside.sqlite3");
        fs::rename(&database, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &database).unwrap();
        assert!(validate_bundle_files(&backup).is_err());
    }

    #[test]
    fn restore_replaces_state_and_preserves_rollback_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        private_dir(&data).unwrap();
        let vault_id = uuid::Uuid::new_v4().to_string();
        write_new_private(&data.join(VAULT_ID_NAME), vault_id.as_bytes()).unwrap();
        let vault = Vault::random();

        let backup = root.path().join("backup");
        {
            let mut store = Store::open(&data.join(DATABASE_NAME), vault.clone()).unwrap();
            store
                .insert_stub(
                    Stub {
                        account: "me@example.com".into(),
                        provider_id: "before-backup".into(),
                        thread_id: "thread-a".into(),
                        source: Source::Gmail,
                    },
                    Utc::now(),
                )
                .unwrap();
            let manifest = create_backup(&store, &data, &backup).unwrap();
            store
                .insert_stub(
                    Stub {
                        account: "me@example.com".into(),
                        provider_id: "after-backup".into(),
                        thread_id: "thread-b".into(),
                        source: Source::Gmail,
                    },
                    Utc::now(),
                )
                .unwrap();
            drop(store);

            let report =
                restore_backup_with_vault(&data, &backup, &manifest, vault.clone()).unwrap();
            assert_eq!(report.restored_schema_version, manifest.schema_version);
            assert!(report.rollback_directory.is_some());
            assert!(restore_rearm_required(&data).unwrap());
        }

        let restored = Store::open(&data.join(DATABASE_NAME), vault).unwrap();
        assert_eq!(restored.counts("me@example.com").unwrap().stored, 1);
        let before = Stub {
            account: "me@example.com".into(),
            provider_id: "before-backup".into(),
            thread_id: "thread-a".into(),
            source: Source::Gmail,
        };
        let after = Stub {
            account: "me@example.com".into(),
            provider_id: "after-backup".into(),
            thread_id: "thread-b".into(),
            source: Source::Gmail,
        };
        assert!(restored.contains(&before.id()).unwrap());
        assert!(!restored.contains(&after.id()).unwrap());
        assert!(data.join("recovery").is_dir());
    }

    #[test]
    fn backup_bundle_verifies_and_detects_tampering() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        private_dir(&data).unwrap();
        let vault_id = uuid::Uuid::new_v4().to_string();
        write_new_private(&data.join(VAULT_ID_NAME), vault_id.as_bytes()).unwrap();

        let vault = Vault::random();
        let mut store = Store::open(&data.join(DATABASE_NAME), vault).unwrap();
        store
            .insert_stub(
                Stub {
                    account: "me@example.com".into(),
                    provider_id: "backup1".into(),
                    thread_id: "thread1".into(),
                    source: Source::Gmail,
                },
                Utc::now(),
            )
            .unwrap();

        let destination = root.path().join("backup");
        let manifest = create_backup(&store, &data, &destination).unwrap();
        assert_eq!(manifest.vault_id, vault_id);
        assert_eq!(manifest.format_version, 2);
        assert_eq!(manifest.audit_head.len(), 64);
        assert!(!manifest.portable);
        verify_backup(&store, &destination).unwrap();
        assert!(backup_manifest_path(&destination).is_file());

        let database = destination.join(DATABASE_NAME);
        let mut file = fs::OpenOptions::new().append(true).open(&database).unwrap();
        file.write_all(b"tamper").unwrap();
        file.sync_all().unwrap();
        assert!(verify_backup(&store, &destination).is_err());
    }

    /// Creates a workspace with a vault identifier and one seeded stub record.
    /// Inputs: parent directory and workspace directory name. Output: workspace
    /// path, vault identifier, vault handle and an open store over the seeded
    /// database.
    fn seeded_workspace(root: &Path, name: &str) -> (PathBuf, String, Vault, Store) {
        let data = root.join(name);
        private_dir(&data).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&data.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        let vault = Vault::random();
        let mut store = Store::open(&data.join(DATABASE_NAME), vault.clone()).unwrap();
        store
            .insert_stub(
                Stub {
                    account: "me@example.com".into(),
                    provider_id: "seed-message".into(),
                    thread_id: "seed-thread".into(),
                    source: Source::Gmail,
                },
                Utc::now(),
            )
            .unwrap();
        (data, id, vault, store)
    }

    /// Why: if any step of backup creation fails, no half-written `.partial`
    /// staging directory may survive next to the destination; leftover staging
    /// data would look like a valid backup to operators and could leak partial
    /// database copies.
    /// Inputs: workspace whose vault identifier disappears before the copy.
    /// Output: error, no destination, and no `.partial-*` entry left behind.
    #[test]
    fn create_backup_failure_leaves_no_partial_staging_or_destination() {
        let root = tempfile::tempdir().unwrap();
        let (data, _id, _vault, store) = seeded_workspace(root.path(), "data");
        fs::remove_file(data.join(VAULT_ID_NAME)).unwrap();
        let destination = root.path().join("backup");
        let error = create_backup(&store, &data, &destination)
            .expect_err("backup without a vault identifier must fail");
        assert!(
            error.to_string().contains("vault-id"),
            "unexpected error: {error}"
        );
        assert!(!destination.exists());
        for entry in fs::read_dir(root.path()).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().contains(".partial-"),
                "partial staging directory leaked: {name:?}"
            );
        }
    }

    /// Why: the size limit on small metadata files is a security bound (it keeps
    /// parser inputs bounded); a file exactly at the limit must be accepted and
    /// one byte over must be refused, so an off-by-one regression is caught in
    /// both directions.
    /// Inputs: 100-byte file read with limits 100 and 99, plus a missing file.
    /// Output: exactly-limit read succeeds, over-limit and missing reads error.
    #[test]
    fn read_small_enforces_the_size_limit_exactly() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.json");
        fs::write(&path, vec![b'x'; 100]).unwrap();
        assert_eq!(read_small(&path, 100).unwrap().len(), 100);
        let error = read_small(&path, 99).expect_err("one byte over the limit must be refused");
        assert!(
            error.to_string().contains("exceeds size limit"),
            "unexpected error: {error}"
        );
        assert!(read_small(&root.path().join("missing"), 10).is_err());
    }

    /// Why: an I/O error while inspecting the restore-rearm marker must surface
    /// as an error; mapping it to "absent" would silently skip the mandatory
    /// delivery re-authorization after an offline restore.
    /// Inputs: paths whose metadata lookup fails with a non-NotFound error.
    /// Output: `restore_rearm_required` returns Err instead of Ok(false).
    #[test]
    fn restore_rearm_inspection_io_errors_are_not_treated_as_absent() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let broken = root.path().join("in<valid-name");
        #[cfg(unix)]
        let broken = {
            // A parent component that is a regular file yields ENOTDIR, which is
            // deliberately not the NotFound case handled as "absent".
            let file = root.path().join("plain-file");
            fs::write(&file, b"x").unwrap();
            file.join(RESTORE_REARM_NAME)
        };
        assert!(restore_rearm_required(&broken).is_err());
    }

    /// Why: backup isolation health must distinguish "configured but the
    /// destination does not exist yet" from a measured same-machine backup;
    /// reporting a missing destination as same-failure-domain would hide a real
    /// isolation gap behind a plausible-looking measurement.
    /// Inputs: enabled settings pointing at a non-existent directory.
    /// Output: configured=true, destination_exists=false, no domain verdict,
    /// measurement "destination_missing".
    #[test]
    fn backup_isolation_reports_a_missing_destination_without_measuring() {
        let root = tempfile::tempdir().unwrap();
        let (data, _id, _vault, _store) = seeded_workspace(root.path(), "data");
        let settings = Settings {
            scheduled_backup_enabled: true,
            scheduled_backup_directory: root
                .path()
                .join("not-created")
                .to_string_lossy()
                .into_owned(),
            ..Settings::default()
        };
        let status = backup_isolation_status(&data, &settings).unwrap();
        assert!(status.configured);
        assert!(!status.destination_exists);
        assert_eq!(status.distinct_failure_domain, None);
        assert_eq!(status.measurement, "destination_missing");
    }

    /// Why: scheduled-backup retention must only ever remove verified same-vault
    /// backup directories with the exact prefix; any widening (plain files,
    /// unrelated directories, non-UTF-8 names) would delete operator data, and
    /// the retention bound itself must fail closed at both ends of its range.
    /// Inputs: root containing a plain file, an unrelated directory and a
    /// non-UTF-8 directory; keep values 1, 2 and 31. Output: zero removals with
    /// every entry preserved, missing root a no-op, out-of-range keeps refused.
    #[test]
    fn prune_skips_unrelated_entries_and_enforces_retention_bounds() {
        let root = tempfile::tempdir().unwrap();
        let (_data, _id, _vault, store) = seeded_workspace(root.path(), "data");

        let missing = root.path().join("absent");
        assert_eq!(
            prune_verified_scheduled_backups(&store, &missing, 2).unwrap(),
            0
        );
        for keep in [1, 31] {
            assert!(
                prune_verified_scheduled_backups(&store, &missing, keep).is_err(),
                "keep={keep} must be refused"
            );
        }

        let backups = root.path().join("backups");
        fs::create_dir_all(&backups).unwrap();
        let plain = backups.join("notes.txt");
        fs::write(&plain, b"x").unwrap();
        let unrelated = backups.join("do-not-delete");
        fs::create_dir_all(&unrelated).unwrap();
        #[cfg(windows)]
        let weird_name = {
            use std::os::windows::ffi::OsStringExt;
            std::ffi::OsString::from_wide(&[0xD800])
        };
        #[cfg(unix)]
        let weird_name = {
            use std::os::unix::ffi::OsStringExt;
            std::ffi::OsString::from_vec(vec![0xFF])
        };
        let weird = backups.join(&weird_name);
        fs::create_dir(&weird).unwrap();

        assert_eq!(
            prune_verified_scheduled_backups(&store, &backups, 2).unwrap(),
            0
        );
        assert!(plain.is_file(), "plain files must never be pruned");
        assert!(
            unrelated.is_dir(),
            "unrelated directories must never be pruned"
        );
        assert!(
            weird.is_dir(),
            "non-UTF-8 names must be skipped, not deleted"
        );
    }

    /// Why: a successful scheduled backup must not turn into a failure (or a
    /// silent success) just because retention pruning cannot run; the operator
    /// must still get the fresh backup plus an audited retention warning.
    /// Inputs: backup root pre-filled with enough entries to exceed the prune
    /// scan bound. Output: backup created and verified, pruning refused without
    /// deleting anything, `backup.retention_warning` in the audit log.
    #[test]
    fn scheduled_backup_succeeds_and_warns_when_retention_pruning_fails() {
        let root = tempfile::tempdir().unwrap();
        let (data, vault_id_value, _vault, mut store) = seeded_workspace(root.path(), "data");
        let backups = root.path().join("backups");
        fs::create_dir_all(&backups).unwrap();
        for index in 0..513 {
            fs::write(backups.join(format!("noise-{index:03}")), b"x").unwrap();
        }
        let settings = Settings {
            scheduled_backup_enabled: true,
            scheduled_backup_directory: backups.to_string_lossy().into_owned(),
            scheduled_backup_keep: 2,
            ..Settings::default()
        };
        settings.validate().unwrap();

        let manifest = create_scheduled_backup(&mut store, &data, &settings, Utc::now()).unwrap();
        assert_eq!(manifest.vault_id, vault_id_value);
        let scheduled: Vec<_> = fs::read_dir(&backups)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(SCHEDULED_BACKUP_PREFIX)
            })
            .collect();
        assert_eq!(
            scheduled.len(),
            1,
            "the fresh backup must survive the failed prune"
        );
        assert_eq!(
            fs::read_dir(&backups).unwrap().count(),
            514,
            "a failed prune must not remove any entry"
        );
        let events = store.events(0, 1_000).unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "backup.retention_warning"),
            "retention failure must be surfaced in the audit log"
        );
        assert!(
            events
                .iter()
                .any(|event| event.kind == "backup.scheduled_succeeded")
        );
    }

    /// Why: restore is transactional — a backup whose bytes no longer match its
    /// manifest checksum must be rejected before the live workspace is touched;
    /// accepting it would install silently corrupted state. The mid-file flip
    /// also proves the checksum covers the whole database, not just a header.
    /// Inputs: backup with one middle byte flipped. Output: checksum error, live
    /// database bytes unchanged, no rollback directory, no rearm marker.
    #[test]
    fn restore_rejects_corrupted_backup_bytes_and_leaves_workspace_untouched() {
        let root = tempfile::tempdir().unwrap();
        let (data, _id, _vault, store) = seeded_workspace(root.path(), "data");
        let backup = root.path().join("backup");
        create_backup(&store, &data, &backup).unwrap();
        let database = backup.join(DATABASE_NAME);
        let mut bytes = fs::read(&database).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xFF;
        fs::write(&database, &bytes).unwrap();

        let before = fs::read(data.join(DATABASE_NAME)).unwrap();
        let error =
            restore_backup(&data, &backup).expect_err("corrupted backup bytes must be rejected");
        assert!(
            error.to_string().contains("checksum mismatch"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(data.join(DATABASE_NAME)).unwrap(), before);
        assert!(!data.join("recovery").exists());
        assert!(!restore_rearm_required(&data).unwrap());
    }

    /// Why: restoring into a workspace of a different vault must be refused
    /// before any file is written, and a restore that fails after temporarily
    /// minting a vault identifier must roll that identifier back — otherwise the
    /// failed workspace masquerades as an authentic one on the next run.
    /// Inputs: one target with a foreign vault identifier, one fresh target
    /// whose OS credential cannot be opened. Output: both restores fail without
    /// creating a database; the fresh target's minted identifier is removed.
    #[test]
    fn restore_backup_refuses_cross_vault_targets_and_cleans_up_minted_identity() {
        // Serialize OS credential-store access (see `vault::test_support`).
        let _lock = lock_credential_store();
        let root = tempfile::tempdir().unwrap();
        let (data, _id, _vault, store) = seeded_workspace(root.path(), "data");
        let backup = root.path().join("backup");
        create_backup(&store, &data, &backup).unwrap();

        let foreign = root.path().join("foreign");
        private_dir(&foreign).unwrap();
        let foreign_id = uuid::Uuid::new_v4().to_string();
        write_new_private(&foreign.join(VAULT_ID_NAME), foreign_id.as_bytes()).unwrap();
        let error =
            restore_backup(&foreign, &backup).expect_err("cross-vault restore must be refused");
        assert!(
            error.to_string().contains("does not match this workspace"),
            "unexpected error: {error}"
        );
        assert!(!foreign.join(DATABASE_NAME).exists());

        let fresh = root.path().join("fresh");
        private_dir(&fresh).unwrap();
        let error = restore_backup(&fresh, &backup)
            .expect_err("restore without an OS credential must fail closed");
        #[cfg(any(windows, target_os = "macos"))]
        assert!(
            error
                .to_string()
                .contains("Refusing to generate a replacement key"),
            "unexpected error: {error}"
        );
        assert!(
            !fresh.join(VAULT_ID_NAME).exists(),
            "a failed restore must not leave a minted vault identifier behind"
        );
        assert!(!fresh.join(DATABASE_NAME).exists());
    }

    /// Why: the manifest and recovery-key file names are part of the on-disk
    /// bundle contract; renaming them silently would break operator runbooks and
    /// cross-version recovery tooling.
    /// Inputs: arbitrary directory. Output: the two contracted paths.
    #[test]
    fn bundle_path_helpers_name_the_contract_members() {
        let dir = Path::new("/bundle");
        assert_eq!(
            backup_manifest_path(dir),
            Path::new("/bundle").join(MANIFEST_NAME)
        );
        assert_eq!(
            recovery_key_default_path(dir),
            Path::new("/bundle").join(RECOVERY_KEY_NAME)
        );
    }

    /// Why: a truncated recovery envelope (partial write, torn download) must be
    /// rejected as invalid before any Argon2 work or workspace mutation; a
    /// lenient parser could accept a partially attacker-controlled envelope.
    /// Inputs: envelope file cut to half its bytes. Output: verification errors
    /// as invalid envelope and the recovery entry point leaves the target
    /// directory completely untouched.
    #[test]
    fn truncated_recovery_envelope_bytes_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (data, id, vault, store) = seeded_workspace(root.path(), "data");
        let backup = root.path().join("backup");
        create_backup(&store, &data, &backup).unwrap();
        let passphrase = b"correct horse battery staple";
        let recovery_file = root.path().join("recovery-key.json");
        let envelope = vault.recovery_envelope(&id, passphrase).unwrap();
        write_new_private(
            &recovery_file,
            &serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();
        let full = fs::read(&recovery_file).unwrap();
        fs::write(&recovery_file, &full[..full.len() / 2]).unwrap();

        let error = verify_recovery_key_for_backup(&backup, &recovery_file, passphrase)
            .expect_err("a truncated envelope must be rejected");
        assert!(
            error
                .to_string()
                .contains("Recovery-key envelope is invalid"),
            "unexpected error: {error}"
        );

        let target = root.path().join("target");
        private_dir(&target).unwrap();
        assert!(
            recover_workspace_from_backup(&target, &backup, &recovery_file, passphrase).is_err()
        );
        assert!(!target.join(DATABASE_NAME).exists());
        assert!(!target.join(VAULT_ID_NAME).exists());
    }

    /// Why: the envelope's AEAD binds the wrapped key to the vault identifier as
    /// associated data; an envelope whose identity was rewritten to match the
    /// target backup must fail decryption even with the correct passphrase,
    /// otherwise stolen key material could be re-labelled to another vault.
    /// Inputs: envelope created for vault A with its identity rewritten to
    /// vault B, checked against vault B's backup with the correct passphrase.
    /// Output: authentication failure; nothing is verified or installed.
    #[test]
    fn recovery_envelope_bound_to_a_different_vault_identity_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (_data_a, id_a, vault_a, _store_a) = seeded_workspace(root.path(), "vault-a");
        let (data_b, id_b, _vault_b, store_b) = seeded_workspace(root.path(), "vault-b");
        let backup = root.path().join("backup-b");
        create_backup(&store_b, &data_b, &backup).unwrap();
        let passphrase = b"correct horse battery staple";

        let mut forged = vault_a.recovery_envelope(&id_a, passphrase).unwrap();
        forged.vault_id = id_b;
        let recovery_file = root.path().join("forged-recovery-key.json");
        write_new_private(&recovery_file, &serde_json::to_vec_pretty(&forged).unwrap()).unwrap();

        let error = verify_recovery_key_for_backup(&backup, &recovery_file, passphrase)
            .expect_err("an envelope bound to another identity must be rejected");
        assert!(
            error.to_string().contains("authentication failed"),
            "unexpected error: {error}"
        );
    }

    /// Attempts to create a file symlink, returning `None` where the OS forbids
    /// symlink creation without elevated privileges.
    /// Inputs: link path and its target path. Output: `Some(())` when the
    /// symlink was created, `None` when the platform refused.
    fn try_symlink(target: &Path, link: &Path) -> Option<()> {
        #[cfg(windows)]
        let result = std::os::windows::fs::symlink_file(target, link);
        #[cfg(unix)]
        let result = std::os::unix::fs::symlink(target, link);
        result.ok()
    }

    /// Why: symlinked metadata and source files are a documented attack on
    /// backup validation and staging (a link can point outside the bundle or at
    /// operator files); both bounded reads and private copies must reject
    /// symlinks outright instead of following them.
    /// Inputs: symlinked manifest-sized file and symlinked copy source.
    /// Output: both operations error with "must not be a symlink" and the copy
    /// creates no destination; skipped where the OS forbids unprivileged
    /// symlink creation.
    #[test]
    fn symlinked_metadata_and_sources_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside.txt");
        fs::write(&outside, b"outside").unwrap();
        let link = root.path().join("manifest.json");
        if try_symlink(&outside, &link).is_none() {
            return;
        }
        let error = read_small(&link, 64).expect_err("symlinked metadata must be refused");
        assert!(
            error.to_string().contains("must not be a symlink"),
            "unexpected error: {error}"
        );

        let copy_link = root.path().join("stage-source");
        assert!(try_symlink(&outside, &copy_link).is_some());
        let destination = root.path().join("stage.sqlite3");
        let error = copy_private_new(&copy_link, &destination)
            .expect_err("a symlinked copy source must be refused");
        assert!(
            error.to_string().contains("must not be a symlink"),
            "unexpected error: {error}"
        );
        assert!(!destination.exists());
    }

    /// Why: when a target workspace already holds a live database, recovery must
    /// prove that database authenticates under the recovered key before the
    /// replace phase; skipping the check could hand a foreign or planted
    /// database the authority of the recovered vault, and a failure here must
    /// abort with the live bytes untouched.
    /// Inputs: target whose vault identifier matches but whose live database was
    /// created under a different key. Output: authentication error before any
    /// replacement, live database preserved.
    #[test]
    fn recover_workspace_refuses_a_live_database_that_fails_authentication() {
        let root = tempfile::tempdir().unwrap();
        let (data, id, vault, store) = seeded_workspace(root.path(), "source");
        let backup = root.path().join("backup");
        create_backup(&store, &data, &backup).unwrap();
        let passphrase = b"correct horse battery staple";
        let recovery_file = root.path().join("recovery-key.json");
        let envelope = vault.recovery_envelope(&id, passphrase).unwrap();
        write_new_private(
            &recovery_file,
            &serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();

        let damaged = root.path().join("damaged-live");
        private_dir(&damaged).unwrap();
        write_new_private(&damaged.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        drop(Store::open(&damaged.join(DATABASE_NAME), Vault::random()).unwrap());
        let before = fs::read(damaged.join(DATABASE_NAME)).unwrap();

        let error = recover_workspace_from_backup(&damaged, &backup, &recovery_file, passphrase)
            .expect_err("a non-authenticating live database must abort the recovery");
        assert!(
            error.to_string().contains("does not authenticate"),
            "unexpected error: {error}"
        );
        assert_eq!(
            fs::read(damaged.join(DATABASE_NAME)).unwrap(),
            before,
            "the rejected recovery must leave the live database byte-identical"
        );
    }

    /// Removes a test credential from the OS credential store even when an
    /// assertion panics, so repeated runs never collide with stale keys.
    #[cfg(any(windows, target_os = "macos"))]
    struct CredentialCleanup(String);
    #[cfg(any(windows, target_os = "macos"))]
    impl Drop for CredentialCleanup {
        /// Deletes the credential bound to this test's vault identifier.
        /// Inputs: `self.0` holds the vault identifier used as account name.
        /// Output: none; deletion errors are ignored during teardown.
        fn drop(&mut self) {
            let _ = keyring::Entry::new("rejection-rejector.v1", &self.0)
                .and_then(|entry| entry.delete_credential());
        }
    }

    /// Why: the full recovery-key export path must work against a real
    /// OS-credential workspace: the exported envelope has to authenticate the
    /// backup, wrong passphrases must be rejected, and the same key must drive
    /// the drill and a transactional restore. Exercises the production export,
    /// drill and restore entry points end to end.
    /// Inputs: keyring-backed workspace with one stub record and its backup.
    /// Output: envelope round-trips, drill and restore succeed against the
    /// recovered state, and re-exporting never overwrites the existing file.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn recovery_key_export_roundtrip_drives_drill_and_transactional_restore() {
        // Serialize OS credential-store access (see `vault::test_support`).
        let _lock = lock_credential_store();
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        private_dir(&data).unwrap();
        let vault = Vault::open(&data).unwrap();
        let id = vault_id(&data).unwrap();
        let _cleanup = CredentialCleanup(id.clone());
        let mut store = Store::open(&data.join(DATABASE_NAME), vault).unwrap();
        store
            .insert_stub(
                Stub {
                    account: "me@example.com".into(),
                    provider_id: "export-message".into(),
                    thread_id: "export-thread".into(),
                    source: Source::Gmail,
                },
                Utc::now(),
            )
            .unwrap();
        let backup = root.path().join("backup");
        let manifest = create_backup(&store, &data, &backup).unwrap();

        let passphrase = b"correct horse battery staple";
        let recovery_file = root.path().join("recovery-key.json");
        let envelope = export_recovery_key(&data, passphrase, &recovery_file).unwrap();
        assert_eq!(envelope.vault_id, id);
        assert!(recovery_file.is_file());
        let serialized = fs::read(&recovery_file).unwrap();
        assert!(
            !serialized
                .windows(passphrase.len())
                .any(|w| w == passphrase)
        );
        assert!(
            export_recovery_key(&data, passphrase, &recovery_file).is_err(),
            "export must never overwrite an existing recovery-key file"
        );

        let verified = verify_recovery_key_for_backup(&backup, &recovery_file, passphrase).unwrap();
        assert_eq!(verified.vault_id, id);
        assert!(
            verify_recovery_key_for_backup(
                &backup,
                &recovery_file,
                b"wrong passphrase but definitely long enough"
            )
            .is_err()
        );

        let drill = recovery_drill(&data, &backup).unwrap();
        assert!(drill.isolated_restore_succeeded);
        assert_eq!(drill.source_database_sha256, manifest.database_sha256);

        let target = root.path().join("target");
        private_dir(&target).unwrap();
        write_new_private(&target.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        let report = restore_backup(&target, &backup).unwrap();
        assert_eq!(report.source_database_sha256, manifest.database_sha256);
        assert!(restore_rearm_required(&target).unwrap());
        let restored =
            Store::open(&target.join(DATABASE_NAME), Vault::open(&target).unwrap()).unwrap();
        assert_eq!(restored.counts("me@example.com").unwrap().stored, 1);
    }

    /// Why: recovery-key import must enforce vault identity end to end: a
    /// foreign workspace is refused, a live database that does not authenticate
    /// under the recovered key is refused, the OS credential is installed
    /// exactly once, and every refusal rolls back the temporarily minted vault
    /// identifier so failed workspaces cannot masquerade as authentic ones.
    /// Inputs: backup plus its envelope against four target directories.
    /// Output: cross-vault and non-authenticating imports error with cleanup;
    /// the clean import installs a credential that opens the backup key.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn import_recovery_key_for_backup_enforces_identity_and_rolls_back_failures() {
        // Serialize OS credential-store access (see `vault::test_support`).
        let _lock = lock_credential_store();
        let root = tempfile::tempdir().unwrap();
        let (data, id, vault, store) = seeded_workspace(root.path(), "source");
        let backup = root.path().join("backup");
        create_backup(&store, &data, &backup).unwrap();
        let passphrase = b"correct horse battery staple";
        let recovery_file = root.path().join("recovery-key.json");
        let envelope = vault.recovery_envelope(&id, passphrase).unwrap();
        write_new_private(
            &recovery_file,
            &serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();
        let _cleanup = CredentialCleanup(id.clone());

        let other = root.path().join("other-vault");
        private_dir(&other).unwrap();
        let other_id = uuid::Uuid::new_v4().to_string();
        write_new_private(&other.join(VAULT_ID_NAME), other_id.as_bytes()).unwrap();
        let error = import_recovery_key_for_backup(&other, &backup, &recovery_file, passphrase)
            .expect_err("import into a different vault must be refused");
        assert!(
            error.to_string().contains("different vault"),
            "unexpected error: {error}"
        );

        let mismatched = root.path().join("mismatched-live");
        private_dir(&mismatched).unwrap();
        drop(Store::open(&mismatched.join(DATABASE_NAME), Vault::random()).unwrap());
        let error =
            import_recovery_key_for_backup(&mismatched, &backup, &recovery_file, passphrase)
                .expect_err("a live database of another vault must refuse the import");
        assert!(
            error.to_string().contains("does not authenticate"),
            "unexpected error: {error}"
        );
        assert!(
            !mismatched.join(VAULT_ID_NAME).exists(),
            "a refused import must remove its minted vault identifier"
        );

        let clean = root.path().join("clean");
        private_dir(&clean).unwrap();
        let imported =
            import_recovery_key_for_backup(&clean, &backup, &recovery_file, passphrase).unwrap();
        assert_eq!(imported.vault_id, id);
        let installed = Vault::open(&clean).unwrap();
        let sealed = installed.seal("job:1", &"payload").unwrap();
        assert_eq!(
            vault.open_value::<String>("job:1", &sealed).unwrap(),
            "payload",
            "the installed OS credential must hold the recovered key"
        );

        let second = root.path().join("second");
        private_dir(&second).unwrap();
        let error = import_recovery_key_for_backup(&second, &backup, &recovery_file, passphrase)
            .expect_err("import must never overwrite an existing OS credential");
        assert!(
            error.to_string().contains("already exists"),
            "unexpected error: {error}"
        );
        assert!(
            !second.join(VAULT_ID_NAME).exists(),
            "a refused import must remove its minted vault identifier"
        );
    }

    /// Why: portable recovery must prove the whole restore in an isolated
    /// workspace first, then install the recovered OS credential only when none
    /// exists, and refuse targets of other vaults before writing anything. The
    /// two target scenarios also cover both credential-store branches: missing
    /// credential (install) and existing credential (must authenticate backup).
    /// Inputs: backup plus envelope; three target directories. Output: fresh
    /// target restored with key installation, same-vault target restored through
    /// the existing credential, foreign target untouched after refusal.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn recover_workspace_from_backup_installs_key_and_preserves_foreign_targets() {
        // Serialize OS credential-store access (see `vault::test_support`).
        let _lock = lock_credential_store();
        let root = tempfile::tempdir().unwrap();
        let (data, id, vault, store) = seeded_workspace(root.path(), "source");
        let backup = root.path().join("backup");
        let manifest = create_backup(&store, &data, &backup).unwrap();
        let passphrase = b"correct horse battery staple";
        let recovery_file = root.path().join("recovery-key.json");
        let envelope = vault.recovery_envelope(&id, passphrase).unwrap();
        write_new_private(
            &recovery_file,
            &serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();
        let _cleanup = CredentialCleanup(id.clone());

        let target = root.path().join("target");
        private_dir(&target).unwrap();
        let report =
            recover_workspace_from_backup(&target, &backup, &recovery_file, passphrase).unwrap();
        assert_eq!(report.source_database_sha256, manifest.database_sha256);
        assert_eq!(report.source_audit_head, manifest.audit_head);
        assert!(restore_rearm_required(&target).unwrap());
        let restored =
            Store::open(&target.join(DATABASE_NAME), Vault::open(&target).unwrap()).unwrap();
        assert_eq!(restored.counts("me@example.com").unwrap().stored, 1);

        let same_vault = root.path().join("same-vault");
        private_dir(&same_vault).unwrap();
        write_new_private(&same_vault.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        // A consistent image of the live database (the raw file alone would miss
        // WAL content) gives the target an existing same-key database to verify.
        store.backup_to(&same_vault.join(DATABASE_NAME)).unwrap();
        let report =
            recover_workspace_from_backup(&same_vault, &backup, &recovery_file, passphrase)
                .unwrap();
        assert_eq!(report.source_database_sha256, manifest.database_sha256);

        let foreign = root.path().join("foreign");
        private_dir(&foreign).unwrap();
        write_new_private(
            &foreign.join(VAULT_ID_NAME),
            uuid::Uuid::new_v4().to_string().as_bytes(),
        )
        .unwrap();
        let error = recover_workspace_from_backup(&foreign, &backup, &recovery_file, passphrase)
            .expect_err("portable recovery into another vault must be refused");
        assert!(
            error.to_string().contains("different vault"),
            "unexpected error: {error}"
        );
        assert!(!foreign.join(DATABASE_NAME).exists());
    }

    /// Why: when an OS credential already claims the target vault identifier but
    /// holds a different key, recovery must abort instead of installing the
    /// backup under a credential that cannot authenticate it; otherwise a
    /// planted or stale credential would be silently trusted as the recovered
    /// vault.
    /// Inputs: backup plus envelope of key K; target whose vault identifier
    /// matches but whose OS credential was minted for a different key.
    /// Output: authentication error from the credential check and no database
    /// installed in the target.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn recover_workspace_refuses_a_mismatched_os_credential() {
        // Serialize OS credential-store access (see `vault::test_support`).
        let _lock = lock_credential_store();
        let root = tempfile::tempdir().unwrap();
        let (data, id, vault, store) = seeded_workspace(root.path(), "source");
        let backup = root.path().join("backup");
        create_backup(&store, &data, &backup).unwrap();
        let passphrase = b"correct horse battery staple";
        let recovery_file = root.path().join("recovery-key.json");
        let envelope = vault.recovery_envelope(&id, passphrase).unwrap();
        write_new_private(
            &recovery_file,
            &serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();
        let _cleanup = CredentialCleanup(id.clone());

        // Mint an OS credential for the same vault identifier that holds an
        // unrelated key, then point the recovery at a matching target.
        let decoy = root.path().join("decoy");
        private_dir(&decoy).unwrap();
        write_new_private(&decoy.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        Vault::random().install_os_key_if_missing(&decoy).unwrap();

        let target = root.path().join("target");
        private_dir(&target).unwrap();
        write_new_private(&target.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        let error = recover_workspace_from_backup(&target, &backup, &recovery_file, passphrase)
            .expect_err("a mismatched OS credential must abort the recovery");
        assert!(
            error.to_string().contains("does not authenticate"),
            "unexpected error: {error}"
        );
        assert!(
            !target.join(DATABASE_NAME).exists(),
            "the rejected recovery must not install anything"
        );
    }
}
