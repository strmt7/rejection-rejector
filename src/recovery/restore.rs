//! Restore from an authenticated source image; migration is isolated from live state.
use super::*;
use crate::store::DATABASE_SCHEMA_VERSION;

/// Enforce that a live database path is a regular file or absent.
///
/// Inputs: `path` — file path to check. Output: `Result<()>` — `Ok` when the
/// path is missing or is a regular non-symlink file; error for symlinks or
/// other file kinds.
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

/// Undo staged file moves after a failed operation.
///
/// Inputs: `moved` — (original, saved) path pairs in move order. Output:
/// `Result<()>` — `Ok` when every file is renamed back in reverse order; error
/// when any restore rename fails.
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

/// Test-only fault seam for the post-install validation step.
///
/// The post-install rollback path protects a candidate image that verifies in
/// staging but fails to reopen after installation. No natural input reaches it
/// (every image is checksummed and re-verified before the first rename), so
/// tests inject the failure here and assert the quarantine/rollback behavior.
#[cfg(test)]
pub(crate) mod failpoints {
    use std::cell::Cell;

    thread_local! {
        static FAIL_POST_INSTALL_VALIDATION: Cell<bool> = const { Cell::new(false) };
        static FAIL_INSTALL_RENAME: Cell<bool> = const { Cell::new(false) };
    }

    /// Run `body` with the post-install validation forced to fail on this thread.
    pub(crate) fn with_post_install_validation_failure<T>(body: impl FnOnce() -> T) -> T {
        FAIL_POST_INSTALL_VALIDATION.with(|flag| flag.set(true));
        let result = body();
        FAIL_POST_INSTALL_VALIDATION.with(|flag| flag.set(false));
        result
    }

    /// Whether the post-install validation must fail on this thread.
    pub(crate) fn post_install_validation_failing() -> bool {
        FAIL_POST_INSTALL_VALIDATION.with(|flag| flag.get())
    }

    /// Run `body` with the final install rename forced to fail on this thread.
    ///
    /// Why: the mid-install rollback path (every moved live file restored,
    /// the restore transaction completed, the failure named) is otherwise
    /// only reachable through a filesystem failure between the validated
    /// moves and the final rename — the platform trigger is a Windows
    /// share-lock refusal, so injecting it keeps the rollback semantics
    /// pinned on every platform.
    pub(crate) fn with_install_rename_failure<T>(body: impl FnOnce() -> T) -> T {
        FAIL_INSTALL_RENAME.with(|flag| flag.set(true));
        let result = body();
        FAIL_INSTALL_RENAME.with(|flag| flag.set(false));
        result
    }

    /// Whether the final install rename must fail on this thread.
    pub(crate) fn install_rename_failing() -> bool {
        FAIL_INSTALL_RENAME.with(|flag| flag.get())
    }
}

/// Persist the optional restore report next to the rollback material.
///
/// Inputs: `rollback_dir` — recovery directory for this restore; `report` —
/// report to persist. Output: none; a write failure is appended to
/// `report.note` so the restore itself still succeeds with full disclosure.
fn write_optional_restore_report(rollback_dir: &Path, report: &mut RestoreReport) {
    let report_path = rollback_dir.join("restore-report.json");
    if let Err(error) = serde_json::to_vec_pretty(report)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| write_new_private(&report_path, &bytes))
    {
        report.note.push_str(&format!(
            " The optional local restore-report file could not be written: {error}"
        ));
    }
}

/// Restore a validated backup bundle into the workspace using a supplied vault.
///
/// Inputs: `data_dir` — workspace data directory to restore into; `backup_dir`
/// — directory holding the backup bundle; `manifest` — backup manifest
/// describing the bundle; `vault` — vault used to authenticate the restored
/// material. Output: `Result<RestoreReport>` summarizing the restore; errors
/// when the bundle or vault fails validation.
pub(super) fn restore_backup_with_vault(
    data_dir: &Path,
    backup_dir: &Path,
    manifest: &BackupManifest,
    vault: Vault,
) -> Result<RestoreReport> {
    let (staging, input_stage, candidate) = stage_backup_input(data_dir, backup_dir, manifest)?;
    let live = data_dir.join(DATABASE_NAME);
    let live_wal = data_dir.join(format!("{DATABASE_NAME}-wal"));
    let live_shm = data_dir.join(format!("{DATABASE_NAME}-shm"));
    for path in [&live, &live_wal, &live_shm] {
        regular_or_absent(path)?;
    }
    let (restored_schema_version, restored_audit_head) =
        verify_staged_candidate(staging.path(), &input_stage, &candidate, manifest, &vault)?;

    let recovery_root = data_dir.join("recovery");
    private_dir(&recovery_root)?;
    let rollback_dir = recovery_root.join(format!(
        "pre-restore-{}-{}",
        Utc::now().format("%Y%m%d-%H%M%S"),
        uuid::Uuid::new_v4()
    ));
    private_dir(&rollback_dir)?;
    mark_restore_rearm_required(data_dir)?;
    crate::session::begin_restore_transaction(data_dir)?;

    let files = [
        (&live, rollback_dir.join(DATABASE_NAME)),
        (&live_wal, rollback_dir.join(format!("{DATABASE_NAME}-wal"))),
        (&live_shm, rollback_dir.join(format!("{DATABASE_NAME}-shm"))),
    ];
    let mut moved = Vec::<(PathBuf, PathBuf)>::new();
    let install = install_restored_image(&files, &mut moved, &candidate, &live);
    if let Err(error) = install {
        rollback_files(&moved).context("Restore installation and rollback both failed")?;
        crate::session::complete_restore_transaction(data_dir)?;
        return Err(error.context("Restore installation failed; previous files restored"));
    }

    let final_validation = validate_restored_image(
        &live,
        &vault,
        manifest,
        restored_schema_version,
        &restored_audit_head,
    );
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
        crate::session::complete_restore_transaction(data_dir)?;
        return Err(error.context("Restore validation failed; previous files restored"));
    }

    crate::session::complete_restore_transaction(data_dir)?;
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
    write_optional_restore_report(&rollback_dir, &mut report);
    Ok(report)
}

/// Stage the backup database into the workspace and authenticate it.
///
/// Inputs: `data_dir` — workspace directory; `backup_dir` — backup bundle;
/// `manifest` — authorized manifest. Output: `Result<(tempfile::TempDir,
/// PathBuf, PathBuf)>` — the staging directory, the staged original image
/// and the candidate image path.
fn stage_backup_input(
    data_dir: &Path,
    backup_dir: &Path,
    manifest: &BackupManifest,
) -> Result<(tempfile::TempDir, PathBuf, PathBuf)> {
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
    Ok((staging, input_stage, candidate))
}

/// Authenticate, migrate and verify the staged backup in isolation.
///
/// Inputs: `staging` — staging directory; `input_stage` — staged original
/// image; `candidate` — candidate image path; `manifest` — authorized
/// manifest; `vault` — workspace vault. Output: `Result<(i64, String)>` —
/// the restored schema version and the verified audit head.
fn verify_staged_candidate(
    staging: &Path,
    input_stage: &Path,
    candidate: &Path,
    manifest: &BackupManifest,
    vault: &Vault,
) -> Result<(i64, String)> {
    // A separate same-key probe verifies the ORIGINAL, read-only image.
    // Opening input_stage first would migrate it and invalidate its manifest.
    let probe = Store::open(&staging.join("probe.sqlite3"), vault.clone())?;
    let original = probe.verify_backup_file(input_stage)?;
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

    let staged = Store::open(input_stage, vault.clone())?;
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
    staged.backup_to(candidate)?;
    let verified = staged.verify_backup_file(candidate)?;
    ensure!(
        verified.schema_version == DATABASE_SCHEMA_VERSION,
        "Restored candidate schema does not match the migrated source"
    );
    ensure!(
        verified.audit_head.as_deref() == Some(expected_head.as_str()),
        "Restored candidate audit head does not match the migrated source"
    );
    Ok((verified.schema_version, expected_head))
}

/// Move the live database aside and install the verified candidate.
///
/// Inputs: `files` — live members to park in the rollback directory;
/// `moved` — completed moves, extended in place for rollback; `candidate` —
/// verified candidate image; `live` — live database path. Output:
/// `Result<()>` — `Ok` once the candidate is installed.
fn install_restored_image(
    files: &[(&PathBuf, PathBuf)],
    moved: &mut Vec<(PathBuf, PathBuf)>,
    candidate: &Path,
    live: &Path,
) -> Result<()> {
    for (source, destination) in files {
        // Recheck at use as well, but route every failure through rollback.
        regular_or_absent(source)?;
        if source.exists() {
            fs::rename(source, destination)?;
            moved.push(((*source).clone(), destination.clone()));
        }
    }
    #[cfg(test)]
    ensure!(
        !failpoints::install_rename_failing(),
        "Injected install failure"
    );
    fs::rename(candidate, live)?;
    Ok(())
}

/// Validate the installed image against the verified candidate.
///
/// Inputs: `live` — installed database path; `vault` — workspace vault;
/// `manifest` — authorized manifest; `restored_schema_version` — expected
/// schema version; `restored_audit_head` — expected audit head. Output:
/// `Result<()>` — `Ok` when the installed image matches exactly.
fn validate_restored_image(
    live: &Path,
    vault: &Vault,
    manifest: &BackupManifest,
    restored_schema_version: i64,
    restored_audit_head: &str,
) -> Result<()> {
    #[cfg(test)]
    ensure!(
        !failpoints::post_install_validation_failing(),
        "Injected post-install validation failure"
    );
    let restored = Store::open(live, vault.clone())?;
    restored.integrity_check()?;
    let verification = restored.verify_backup_file(live)?;
    ensure!(
        verification.schema_version == restored_schema_version,
        "Restored schema changed unexpectedly"
    );
    ensure!(
        verification.audit_head.as_deref() == Some(restored_audit_head),
        "Restored database audit head differs from the verified candidate"
    );
    if manifest.format_version >= 2 {
        ensure!(
            restored.contains_audit_anchor(&manifest.audit_head)?,
            "Restored database lost the original backup audit history"
        );
    }
    Ok(())
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
        let report = restore_backup_with_vault(&data, &backup, &manifest, vault.clone()).unwrap();
        assert_eq!(report.source_database_sha256, manifest.database_sha256);
        assert_eq!(report.source_audit_head, manifest.audit_head);
        assert_eq!(report.restored_schema_version, DATABASE_SCHEMA_VERSION);
        assert_eq!(fs::read(backup.join(DATABASE_NAME)).unwrap(), before);
        let restored = Store::open(&data.join(DATABASE_NAME), vault).unwrap();
        assert_eq!(
            restored.meta::<String>("sentinel").unwrap().as_deref(),
            Some("preserve me")
        );
        assert!(
            restored
                .contains_audit_anchor(&manifest.audit_head)
                .unwrap()
        );
        assert_ne!(restored.audit_head().unwrap(), manifest.audit_head);
        assert!(restore_rearm_required(&data).unwrap());
        crate::session::ensure_restore_complete(&data).unwrap();
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

    #[test]
    fn regular_or_absent_only_accepts_missing_or_regular_files() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fs::write(&file, b"x").unwrap();
        regular_or_absent(&file).unwrap();
        regular_or_absent(&root.path().join("missing")).unwrap();
    }

    /// A lookup failure other than "not found" must not be treated as absence,
    /// or an unreadable live sidecar could silently vanish from the pre-move
    /// validation and be left behind while the database is replaced.
    #[cfg(unix)]
    #[test]
    fn io_errors_below_a_regular_file_are_not_treated_as_absent() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert!(regular_or_absent(&file.join("child")).is_err());
    }

    /// Same contract as the unix case: a live entry whose metadata cannot even
    /// be queried (invalid Win32 name) aborts the restore instead of being
    /// skipped as absent.
    #[cfg(windows)]
    #[test]
    fn unqueryable_live_names_are_not_treated_as_absent() {
        let root = tempfile::tempdir().unwrap();
        assert!(regular_or_absent(&root.path().join("inva*lid")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn refused_sidecar_rename_rolls_back_the_moved_live_database() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = tempfile::tempdir().unwrap();
        let (data, backup, vault, manifest) = fixture(root.path());
        let wal = data.join(format!("{DATABASE_NAME}-wal"));
        fs::write(&wal, b"stale wal").unwrap();
        let before = fs::read(data.join(DATABASE_NAME)).unwrap();

        // Deny delete sharing on the sidecar: metadata validation still sees a
        // regular file, but the OS must refuse the rename into the rollback
        // directory mid-install, forcing the rollback of the moved database.
        let locked = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2) // FILE_SHARE_READ | FILE_SHARE_WRITE, deny delete
            .open(&wal)
            .unwrap();
        let error = restore_backup_with_vault(&data, &backup, &manifest, vault)
            .expect_err("a refused sidecar rename must abort the restore");
        assert!(
            error.to_string().contains("Restore installation failed"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(data.join(DATABASE_NAME)).unwrap(), before);
        assert_eq!(fs::read(&wal).unwrap(), b"stale wal");
        assert_no_staging(&data);
        crate::session::ensure_restore_complete(&data).unwrap();
        drop(locked);
    }

    /// The same mid-install rollback on every platform: when the filesystem
    /// refuses the final install rename, every moved live file must be put
    /// back, the restore transaction completed and the failure named.
    ///
    /// Why: the Windows share-lock test drives the OS-level trigger for
    /// this path; without an injected refusal the rollback semantics would
    /// only ever be asserted on one platform.
    #[test]
    fn injected_install_rename_failure_rolls_back_the_moved_live_files() {
        let root = tempfile::tempdir().unwrap();
        let (data, backup, vault, manifest) = fixture(root.path());
        let wal = data.join(format!("{DATABASE_NAME}-wal"));
        fs::write(&wal, b"stale wal").unwrap();
        let before = fs::read(data.join(DATABASE_NAME)).unwrap();

        let error = failpoints::with_install_rename_failure(|| {
            restore_backup_with_vault(&data, &backup, &manifest, vault)
        })
        .expect_err("a refused install rename must abort the restore");
        assert!(
            error.to_string().contains("Restore installation failed"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(data.join(DATABASE_NAME)).unwrap(), before);
        assert_eq!(fs::read(&wal).unwrap(), b"stale wal");
        assert_no_staging(&data);
        crate::session::ensure_restore_complete(&data).unwrap();
    }

    #[test]
    fn failed_post_install_validation_quarantines_and_rolls_back() {
        let root = tempfile::tempdir().unwrap();
        let (data, backup, vault, manifest) = fixture(root.path());
        let before = fs::read(data.join(DATABASE_NAME)).unwrap();

        let error = failpoints::with_post_install_validation_failure(|| {
            restore_backup_with_vault(&data, &backup, &manifest, vault)
        })
        .expect_err("the injected validation failure must abort the restore");
        assert!(
            error.to_string().contains("Restore validation failed"),
            "unexpected error: {error}"
        );
        // The failed restored image is quarantined so its leftover state can
        // never overwrite the originals, and the originals are back in place.
        assert_eq!(fs::read(data.join(DATABASE_NAME)).unwrap(), before);
        let recovery = data.join("recovery");
        let quarantined = std::fs::read_dir(&recovery)
            .unwrap()
            .filter(std::result::Result::is_ok)
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .any(|dir| {
                dir.join("failed-restored-image")
                    .join(DATABASE_NAME)
                    .exists()
            });
        assert!(quarantined, "failed restored image must be quarantined");
        assert_no_staging(&data);
        crate::session::ensure_restore_complete(&data).unwrap();
    }

    #[test]
    fn restore_report_write_failure_is_disclosed_in_the_note() {
        let root = tempfile::tempdir().unwrap();
        // A regular file where the report's parent directory must be makes the
        // optional report write fail; the restore result must disclose it.
        let blocked = root.path().join("not-a-directory");
        fs::write(&blocked, b"x").unwrap();
        let mut report = RestoreReport {
            format_version: 1,
            restored_at: Utc::now(),
            source_backup_created_at: Utc::now(),
            source_database_sha256: "a".repeat(64),
            source_audit_head: "b".repeat(64),
            restored_schema_version: 5,
            rollback_directory: None,
            note: "base note".into(),
        };
        write_optional_restore_report(&blocked, &mut report);
        assert!(
            report.note.contains("could not be written"),
            "note: {}",
            report.note
        );
    }
}
