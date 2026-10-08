//! Restore from an authenticated source image; migration is isolated from live state.
use super::*;
use crate::store::DATABASE_SCHEMA_VERSION;

fn regular_or_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Live database files must be regular files, not symlinks"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn rollback_files(moved: &[(PathBuf, PathBuf)]) -> Result<()> {
    let mut failures = 0usize;
    for (original, saved) in moved.iter().rev() {
        if fs::rename(saved, original).is_err() {
            failures += 1;
        }
    }
    ensure!(
        failures == 0,
        "Automatic rollback was incomplete; preserve the recovery directory and stop the application"
    );
    Ok(())
}

pub(super) fn restore_backup_with_vault(
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

    // Validate the entire live file set before moving any member of that set.
    // symlink_metadata also detects dangling symlinks, unlike Path::exists.
    let live = data_dir.join(DATABASE_NAME);
    let live_wal = data_dir.join(format!("{DATABASE_NAME}-wal"));
    let live_shm = data_dir.join(format!("{DATABASE_NAME}-shm"));
    for path in [&live, &live_wal, &live_shm] {
        regular_or_absent(path)?;
    }

    // RAII cleanup includes SQLite sidecars and pre-migration images on every
    // failure. Neither the original bundle nor the live database is migrated.
    let staging = tempfile::Builder::new()
        .prefix(".restore-")
        .tempdir_in(data_dir)?;
    private_dir(staging.path())?;
    let input_stage = staging.path().join("input.sqlite3");
    let candidate = staging.path().join("candidate.sqlite3");
    copy_private_new(&backup_database, &input_stage)?;
    ensure!(
        sha256_file(&input_stage)? == manifest.database_sha256,
        "Staged backup checksum changed after manifest verification"
    );

    let (restored_schema_version, restored_audit_head) = {
        // A separate same-key probe verifies the ORIGINAL, read-only image.
        // Opening input_stage first would migrate it and invalidate its manifest.
        let probe = Store::open(&staging.path().join("probe.sqlite3"), vault.clone())?;
        let original = probe.verify_backup_file(&input_stage)?;
        ensure!(
            original.schema_version == manifest.schema_version,
            "Original backup schema does not match the authorized manifest"
        );
        if manifest.format_version >= 2 {
            ensure!(
                original.audit_head.as_deref() == Some(manifest.audit_head.as_str()),
                "Original backup audit head does not match the authorized manifest"
            );
        }
        drop(probe);

        let staged = Store::open(&input_stage, vault.clone())?;
        staged.integrity_check()?;
        ensure!(
            staged.schema_version()? == DATABASE_SCHEMA_VERSION,
            "Staged database was not migrated to the supported schema"
        );
        if manifest.format_version >= 2 {
            ensure!(
                staged.contains_audit_anchor(&manifest.audit_head)?,
                "Migration did not preserve the authorized audit history"
            );
        }
        let expected_head = staged.audit_head()?;
        staged.backup_to(&candidate)?;
        let verified = staged.verify_backup_file(&candidate)?;
        ensure!(
            verified.schema_version == DATABASE_SCHEMA_VERSION,
            "Restored candidate schema does not match the migrated source"
        );
        ensure!(
            verified.audit_head.as_deref() == Some(expected_head.as_str()),
            "Restored candidate audit head does not match the migrated source"
        );
        (verified.schema_version, expected_head)
    };

    let recovery_root = data_dir.join("recovery");
    private_dir(&recovery_root)?;
    let rollback_dir = recovery_root.join(format!(
        "pre-restore-{}-{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        uuid::Uuid::new_v4()
    ));
    private_dir(&rollback_dir)?;
    mark_restore_rearm_required(data_dir)?;

    let files = [
        (&live, rollback_dir.join(DATABASE_NAME)),
        (&live_wal, rollback_dir.join(format!("{DATABASE_NAME}-wal"))),
        (&live_shm, rollback_dir.join(format!("{DATABASE_NAME}-shm"))),
    ];
    let mut moved = Vec::<(PathBuf, PathBuf)>::new();
    let install = (|| -> Result<()> {
        for (source, destination) in &files {
            // Recheck at use as well, but route every failure through rollback.
            regular_or_absent(source)?;
            if source.exists() {
                fs::rename(source, destination)?;
                moved.push(((*source).clone(), destination.clone()));
            }
        }
        fs::rename(&candidate, &live)?;
        Ok(())
    })();
    if let Err(error) = install {
        rollback_files(&moved).context("Restore installation and rollback both failed")?;
        return Err(error.context("Restore installation failed; previous files restored"));
    }

    let final_validation = (|| -> Result<()> {
        let restored = Store::open(&live, vault.clone())?;
        restored.integrity_check()?;
        let verification = restored.verify_backup_file(&live)?;
        ensure!(
            verification.schema_version == restored_schema_version,
            "Restored schema changed unexpectedly"
        );
        ensure!(
            verification.audit_head.as_deref() == Some(restored_audit_head.as_str()),
            "Restored database audit head differs from the verified candidate"
        );
        if manifest.format_version >= 2 {
            ensure!(
                restored.contains_audit_anchor(&manifest.audit_head)?,
                "Restored database lost the original backup audit history"
            );
        }
        Ok(())
    })();

    if let Err(error) = final_validation {
        // Never overwrite originals with leftover WAL/SHM from a failed image.
        let quarantine = rollback_dir.join("failed-restored-image");
        private_dir(&quarantine)?;
        for (path, _) in &files {
            regular_or_absent(path)?;
            if path.exists() {
                let name = path.file_name().context("Invalid database filename")?;
                fs::rename(path, quarantine.join(name))
                    .context("Cannot quarantine failed restore; preserve recovery files")?;
            }
        }
        rollback_files(&moved).context("Restore validation and rollback both failed")?;
        return Err(error.context("Restore validation failed; previous files restored"));
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
        note: "Restore completed after original-image authentication, isolated migration and post-install verification. Previous database files are retained under the recovery directory when present; delivery must be reauthorized.".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path) -> (PathBuf, PathBuf, Vault, BackupManifest) {
        let data = root.join("data");
        let backup = root.join("backup");
        private_dir(&data).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&data.join(VAULT_ID_NAME), id.as_bytes()).unwrap();
        let vault = Vault::random();
        let mut store = Store::open(&data.join(DATABASE_NAME), vault.clone()).unwrap();
        store.set_meta("sentinel", &"preserve me").unwrap();
        store
            .log("test.seed", None, "Synthetic backup evidence")
            .unwrap();
        let manifest = create_backup(&store, &data, &backup).unwrap();
        (data, backup, vault, manifest)
    }

    fn schema_four_backup(backup: &Path, manifest: &mut BackupManifest) {
        let path = backup.join(DATABASE_NAME);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DROP TABLE processing_failures; PRAGMA user_version=4;")
            .unwrap();
        drop(conn);
        manifest.schema_version = 4;
        manifest.database_sha256 = sha256_file(&path).unwrap();
        fs::write(
            backup.join(MANIFEST_NAME),
            serde_json::to_vec_pretty(manifest).unwrap(),
        )
        .unwrap();
    }

    fn assert_no_staging(data: &Path) {
        for entry in fs::read_dir(data).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                assert!(!entry.file_name().to_string_lossy().starts_with(".restore-"));
            }
        }
    }

    #[test]
    fn schema_four_restore_migrates_without_mutating_the_backup() {
        let root = tempfile::tempdir().unwrap();
        let (data, backup, vault, mut manifest) = fixture(root.path());
        schema_four_backup(&backup, &mut manifest);
        let before = fs::read(backup.join(DATABASE_NAME)).unwrap();
        let report =
            restore_backup_with_vault(&data, &backup, &manifest, vault.clone()).unwrap();
        assert_eq!(report.source_database_sha256, manifest.database_sha256);
        assert_eq!(report.source_audit_head, manifest.audit_head);
        assert_eq!(report.restored_schema_version, DATABASE_SCHEMA_VERSION);
        assert_eq!(fs::read(backup.join(DATABASE_NAME)).unwrap(), before);
        let restored = Store::open(&data.join(DATABASE_NAME), vault).unwrap();
        assert_eq!(
            restored.meta::<String>("sentinel").unwrap().as_deref(),
            Some("preserve me")
        );
        assert!(restored.contains_audit_anchor(&manifest.audit_head).unwrap());
        assert_ne!(restored.audit_head().unwrap(), manifest.audit_head);
        assert!(restore_rearm_required(&data).unwrap());
        assert_no_staging(&data);
    }

    #[test]
    fn recovery_drill_accepts_supported_legacy_schema_and_leaves_live_bytes_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let (data, backup, vault, mut manifest) = fixture(root.path());
        schema_four_backup(&backup, &mut manifest);
        let before = fs::read(data.join(DATABASE_NAME)).unwrap();
        let report = recovery_drill_with_vault(&data, &backup, vault).unwrap();
        assert_eq!(report.restored_schema_version, DATABASE_SCHEMA_VERSION);
        assert!(report.isolated_restore_succeeded);
        assert_eq!(fs::read(data.join(DATABASE_NAME)).unwrap(), before);
        assert!(!restore_rearm_required(&data).unwrap());
    }

    #[test]
    fn incorrect_original_schema_or_audit_head_never_changes_live_state() {
        for change_schema in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let (data, backup, vault, mut manifest) = fixture(root.path());
            let before = fs::read(data.join(DATABASE_NAME)).unwrap();
            if change_schema {
                manifest.schema_version = 4;
            } else {
                manifest.audit_head = "f".repeat(64);
            }
            fs::write(
                backup.join(MANIFEST_NAME),
                serde_json::to_vec_pretty(&manifest).unwrap(),
            )
            .unwrap();
            assert!(restore_backup_with_vault(&data, &backup, &manifest, vault).is_err());
            assert_eq!(fs::read(data.join(DATABASE_NAME)).unwrap(), before);
            assert!(!restore_rearm_required(&data).unwrap());
            assert_no_staging(&data);
        }
    }

    #[test]
    fn unsafe_later_sidecar_is_rejected_before_moving_the_database() {
        let root = tempfile::tempdir().unwrap();
        let (data, backup, vault, manifest) = fixture(root.path());
        let before = fs::read(data.join(DATABASE_NAME)).unwrap();
        fs::create_dir(data.join(format!("{DATABASE_NAME}-shm"))).unwrap();
        assert!(restore_backup_with_vault(&data, &backup, &manifest, vault).is_err());
        assert_eq!(fs::read(data.join(DATABASE_NAME)).unwrap(), before);
        assert!(!data.join("recovery").exists());
        assert_no_staging(&data);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_live_sidecar_is_not_treated_as_absent() {
        let root = tempfile::tempdir().unwrap();
        let (data, backup, vault, manifest) = fixture(root.path());
        let before = fs::read(data.join(DATABASE_NAME)).unwrap();
        let sidecar = data.join(format!("{DATABASE_NAME}-wal"));
        std::os::unix::fs::symlink(data.join("missing"), &sidecar).unwrap();
        assert!(restore_backup_with_vault(&data, &backup, &manifest, vault).is_err());
        assert_eq!(fs::read(data.join(DATABASE_NAME)).unwrap(), before);
        assert_no_staging(&data);
    }

    #[test]
    fn rollback_restores_each_file_and_reports_missing_recovery_material() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        let saved = root.path().join("saved");
        fs::write(&saved, b"previous state").unwrap();
        rollback_files(&[(original.clone(), saved.clone())]).unwrap();
        assert_eq!(fs::read(&original).unwrap(), b"previous state");
        assert!(rollback_files(&[(original.clone(), saved)]).is_err());
        assert_eq!(fs::read(&original).unwrap(), b"previous state");
    }
}
