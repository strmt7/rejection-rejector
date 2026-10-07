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
    Ok(format!("{:x}", digest.finalize()))
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
        verification.schema_version == manifest.schema_version,
        "Recovery drill restored an unexpected schema version"
    );
    if manifest.format_version >= 2 {
        ensure!(
            verification.audit_head.as_deref() == Some(manifest.audit_head.as_str()),
            "Recovery drill audit head differs from the backup manifest"
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

fn restore_backup_with_vault(
    data_dir: &Path,
    backup_dir: &Path,
    manifest: &BackupManifest,
    vault: Vault,
) -> Result<RestoreReport> {
    private_dir(data_dir)?;
    let (current_manifest, backup_database) = validate_bundle_files(backup_dir)?;
    ensure!(
        current_manifest == *manifest,
        "Backup manifest changed since the restore was authorized"
    );
    let current_vault_id = std::str::from_utf8(&read_small(&data_dir.join(VAULT_ID_NAME), 256)?)?
        .trim()
        .to_owned();
    ensure!(
        current_vault_id == manifest.vault_id,
        "Backup vault identifier does not match this workspace"
    );

    let nonce = uuid::Uuid::new_v4();
    let input_stage = data_dir.join(format!(".restore-input-{nonce}.sqlite3"));
    let candidate = data_dir.join(format!(".restore-candidate-{nonce}.sqlite3"));
    copy_private_new(&backup_database, &input_stage)?;

    let staging_result = (|| -> Result<i64> {
        ensure!(
            sha256_file(&input_stage)? == manifest.database_sha256,
            "Staged backup checksum changed after manifest verification"
        );
        let staged = Store::open(&input_stage, vault.clone())?;
        staged.integrity_check()?;
        let authenticated = staged.verify_backup_file(&input_stage)?;
        ensure!(
            authenticated.schema_version == manifest.schema_version,
            "Staged backup schema does not match the authorized manifest"
        );
        if manifest.format_version >= 2 {
            ensure!(
                authenticated.audit_head.as_deref() == Some(manifest.audit_head.as_str()),
                "Staged backup audit head does not match the authorized manifest"
            );
        }
        staged.backup_to(&candidate)?;
        let verified = staged.verify_backup_file(&candidate)?;
        ensure!(
            verified.schema_version == manifest.schema_version,
            "Restored candidate schema does not match the authorized manifest"
        );
        if manifest.format_version >= 2 {
            ensure!(
                verified.audit_head.as_deref() == Some(manifest.audit_head.as_str()),
                "Restored candidate audit head does not match the authorized manifest"
            );
        }
        Ok(verified.schema_version)
    })();
    let _ = fs::remove_file(input_stage.with_extension("sqlite3-wal"));
    let _ = fs::remove_file(input_stage.with_extension("sqlite3-shm"));
    let _ = fs::remove_file(&input_stage);
    let restored_schema_version = match staging_result {
        Ok(version) => version,
        Err(error) => {
            let _ = fs::remove_file(&candidate);
            return Err(error);
        }
    };

    let recovery_root = data_dir.join("recovery");
    private_dir(&recovery_root)?;
    let rollback_dir = recovery_root.join(format!(
        "pre-restore-{}-{nonce}",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    private_dir(&rollback_dir)?;

    // Persist a fail-closed startup marker before touching the live database.
    // If restoration is interrupted, the next normal startup must still
    // disarm any restored Automatic/sending authorization.
    mark_restore_rearm_required(data_dir)?;

    let live = data_dir.join(DATABASE_NAME);
    let live_wal = data_dir.join(format!("{DATABASE_NAME}-wal"));
    let live_shm = data_dir.join(format!("{DATABASE_NAME}-shm"));
    let files = [
        (&live, rollback_dir.join(DATABASE_NAME)),
        (&live_wal, rollback_dir.join(format!("{DATABASE_NAME}-wal"))),
        (&live_shm, rollback_dir.join(format!("{DATABASE_NAME}-shm"))),
    ];

    let mut moved = Vec::<(PathBuf, PathBuf)>::new();
    for (source, destination) in &files {
        if source.exists() {
            ensure!(
                !fs::symlink_metadata(source)?.file_type().is_symlink(),
                "Live database files must not be symlinks"
            );
            if let Err(error) = fs::rename(source, destination) {
                for (original, saved) in moved.iter().rev() {
                    let _ = fs::rename(saved, original);
                }
                let _ = fs::remove_file(&candidate);
                return Err(error.into());
            }
            moved.push(((*source).clone(), destination.clone()));
        }
    }

    if let Err(error) = fs::rename(&candidate, &live) {
        for (original, saved) in moved.iter().rev() {
            let _ = fs::rename(saved, original);
        }
        let _ = fs::remove_file(&candidate);
        return Err(error.into());
    }

    let final_validation = (|| -> Result<()> {
        let restored = Store::open(&live, vault.clone())?;
        restored.integrity_check()?;
        let verification = restored.verify_backup_file(&live)?;
        ensure!(
            verification.schema_version == restored_schema_version,
            "Restored schema changed unexpectedly"
        );
        if manifest.format_version >= 2 {
            ensure!(
                verification.audit_head.as_deref() == Some(manifest.audit_head.as_str()),
                "Restored database audit head differs from the authorized manifest"
            );
        }
        Ok(())
    })();

    if let Err(error) = final_validation {
        let failed = rollback_dir.join("failed-restored-state.sqlite3");
        let _ = fs::rename(&live, &failed);
        let _ = fs::remove_file(data_dir.join(format!("{DATABASE_NAME}-wal")));
        let _ = fs::remove_file(data_dir.join(format!("{DATABASE_NAME}-shm")));
        for (original, saved) in moved.iter().rev() {
            let _ = fs::rename(saved, original);
        }
        return Err(
            error.context("Restore validation failed; previous database files were rolled back")
        );
    }

    let mut report = RestoreReport {
        format_version: 1,
        restored_at: Utc::now(),
        source_backup_created_at: manifest.created_at,
        source_database_sha256: manifest.database_sha256.clone(),
        source_audit_head: manifest.audit_head.clone(),
        restored_schema_version,
        rollback_directory: (!moved.is_empty()).then(|| {
            rollback_dir
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("pre-restore")
                .to_owned()
        }),
        note: "Restore completed after staged same-vault authentication and post-install verification. Previous database files are retained under the recovery directory when present.".into(),
    };
    let report_path = rollback_dir.join("restore-report.json");
    if let Err(error) = serde_json::to_vec_pretty(&report)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| write_new_private(&report_path, &bytes))
    {
        report.note.push_str(&format!(
            " The optional local restore-report file could not be written: {error}"
        ));
    }
    Ok(report)
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
}
