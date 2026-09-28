use crate::{
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

fn copy_private_new(source: &Path, destination: &Path) -> Result<()> {
    ensure!(source.is_file(), "{} is missing", source.display());
    ensure!(
        !fs::symlink_metadata(source)?.file_type().is_symlink(),
        "{} must not be a symlink",
        source.display()
    );
    let mut input = fs::File::open(source)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    Ok(())
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
    if let Some(parent) = destination.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
        ensure!(
            !fs::symlink_metadata(parent)?.file_type().is_symlink(),
            "Recovery-key parent directory must not be a symlink"
        );
    }
    write_new_private(destination, &serde_json::to_vec_pretty(&envelope)?)?;
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
    let (_, backup_database) = validate_bundle_files(backup_dir)?;
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
        let staged = Store::open(&input_stage, vault.clone())?;
        staged.integrity_check()?;
        staged.verify_backup_file(&input_stage)?;
        staged.backup_to(&candidate)?;
        let verified = staged.verify_backup_file(&candidate)?;
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
