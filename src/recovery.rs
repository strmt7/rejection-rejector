use crate::{
    store::Store,
    vault::{private_dir, write_new_private},
};
use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const MANIFEST_NAME: &str = "backup-manifest.json";
const DATABASE_NAME: &str = "state.sqlite3";
const VAULT_ID_NAME: &str = "vault-id";

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

/// Verify manifest, checksum, vault identity and SQLite structure without
/// modifying the backup database.
pub fn verify_backup(store: &Store, directory: &Path) -> Result<BackupManifest> {
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

pub fn backup_manifest_path(directory: &Path) -> PathBuf {
    directory.join(MANIFEST_NAME)
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
