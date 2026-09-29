use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use rejection_rejector::{
    api_auth, audit_anchor, build_info, config, engine::Engine, ollama::Ollama, policy, recovery,
    worker::Worker,
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;
#[derive(Parser)]
#[command(version, about = "Rejection Rejector headless tools")]
struct Args {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReadinessRequirement {
    Workspace,
    Mailbox,
    Analysis,
    Automatic,
}

impl ReadinessRequirement {
    fn satisfied(self, readiness: &rejection_rejector::readiness::RuntimeReadiness) -> bool {
        match self {
            Self::Workspace => readiness.workspace_ready,
            Self::Mailbox => readiness.mailbox_sync_ready,
            Self::Analysis => readiness.analysis_ready,
            Self::Automatic => readiness.automatic_dispatch_ready,
        }
    }
}

#[derive(Subcommand)]
enum Action {
    /// Run the scheduler using settings previously configured in the desktop application.
    Run,
    /// Print deterministic binary/source/dependency build identity without opening a workspace.
    BuildInfo,
    /// Print local settings and aggregate status, without message bodies or credentials.
    Status,
    /// Print a synthetic offline status; never connects to Gmail.
    Demo,
    /// Print a non-sensitive local readiness report for Gmail, Ollama and the pinned model.
    Doctor {
        /// Return a non-zero exit code unless this readiness level is satisfied.
        #[arg(long, value_enum)]
        require: Option<ReadinessRequirement>,
    },
    /// Rotate the local integration API bearer credential. GUI/worker must be closed.
    RotateApiToken,
    /// Print privacy-safe operational metrics for local monitoring.
    Metrics {
        /// Emit OpenMetrics 1.0 text instead of JSON.
        #[arg(long)]
        openmetrics: bool,
    },
    /// Evaluate the configured local model on the full synthetic recruiting pipeline.
    Evaluate {
        #[arg(long)]
        out: PathBuf,
    },
    /// Profile the configured local model with cold, warm-repeat and near-context synthetic passes.
    ProfileModel {
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare already-installed curated local models on the task-specific pipeline.
    CompareModels {
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify the active encrypted database structure and authenticated vault marker.
    Integrity,
    /// Checkpoint, VACUUM, optimize and re-verify the encrypted SQLite workspace.
    Compact,
    /// Create a checksum-bound same-vault backup directory. Existing paths are never overwritten.
    Backup {
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a backup directory against the active vault without modifying it.
    VerifyBackup { path: PathBuf },
    /// Restore and deeply verify a backup in an isolated temporary workspace.
    RecoveryDrill { path: PathBuf },
    /// Restore a verified same-vault backup. The GUI/worker must be closed.
    RestoreBackup {
        path: PathBuf,
        /// Destructive-operation acknowledgement; must be exactly RESTORE.
        #[arg(long)]
        confirm: String,
    },
    /// Export an Argon2id/XChaCha20-Poly1305 wrapped vault key for disaster recovery.
    ExportRecoveryKey {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Prove a recovery key unlocks a backup without modifying the OS credential store.
    VerifyRecoveryKey {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        recovery_key: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
    },
    /// Install a verified recovery key into the OS credential store without overwriting an existing key.
    ImportRecoveryKey {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        recovery_key: PathBuf,
        #[arg(long)]
        passphrase_file: PathBuf,
        /// Credential-store write acknowledgement; must be exactly IMPORT.
        #[arg(long)]
        confirm: String,
    },
    /// Export a privacy-safe local diagnostics JSON report. Nothing is uploaded.
    Diagnostics {
        #[arg(long)]
        out: PathBuf,
    },
    /// Export the current tamper-evident audit point for independent storage.
    AuditAnchor {
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify that the active workspace still extends a previously exported audit anchor.
    VerifyAuditAnchor { path: PathBuf },
    /// Print the effective administrator enterprise-policy status.
    PolicyStatus,
    /// Validate and summarize an enterprise policy file without applying it.
    ValidatePolicy { path: PathBuf },
}
fn recovery_passphrase(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(path.is_file(), "Recovery passphrase file is missing");
    ensure!(
        !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Recovery passphrase file must not be a symlink"
    );
    let metadata = std::fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "Recovery passphrase file must not be readable or writable by group/other users"
        );
    }
    ensure!(
        metadata.len() <= 4096,
        "Recovery passphrase file exceeds the 4 KiB safety limit"
    );
    let mut bytes =
        Zeroizing::new(std::fs::read(path).context("Cannot read recovery passphrase file")?);
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        bytes.pop();
    }
    ensure!(
        bytes.len() >= 20,
        "Recovery passphrase must be at least 20 bytes"
    );
    Ok(bytes)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if matches!(&args.command, Action::BuildInfo) {
        println!("{}", serde_json::to_string_pretty(&build_info::current())?);
        return Ok(());
    }
    let dir = args.data_dir.unwrap_or(config::data_dir()?);
    match args.command {
        Action::BuildInfo => unreachable!("BuildInfo is handled before workspace resolution"),
        Action::ValidatePolicy { path } => {
            let absolute = std::fs::canonicalize(&path)?;
            let loaded = policy::load_file(&absolute)?;
            println!("{}", serde_json::to_string_pretty(&loaded.status())?);
        }
        Action::PolicyStatus => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&e.enterprise_policy_status())?
            );
        }
        Action::Run => {
            let worker = Worker::spawn(dir, false);
            let stop = worker.stop.clone();
            let paused = worker.paused.clone();
            ctrlc::set_handler(move || {
                paused.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
            })?;
            println!(
                "Rejection Rejector worker running. Ctrl+C pauses dispatch and exits. Close the GUI before running this command."
            );
            while !worker.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(1));
                let s = worker.view();
                if s.fatal {
                    anyhow::bail!("{}", s.error);
                }
            }
        }
        Action::Metrics { openmetrics } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let metrics = rejection_rejector::metrics::collect(&e, chrono::Utc::now())?;
            if openmetrics {
                let runtime = rejection_rejector::runtime_log::performance_summary(&e.directory)?;
                print!(
                    "{}",
                    rejection_rejector::metrics::render_openmetrics_with_runtime(
                        &metrics, &runtime
                    )
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&metrics)?);
            }
        }
        Action::Doctor { require } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let database_integrity = e.db.integrity_check();
            let database_integrity_ok = database_integrity.is_ok();
            let database_message = database_integrity
                .as_ref()
                .map(|_| "SQLite and authenticated vault checks passed".to_string())
                .unwrap_or_else(|error| error.to_string());
            let database_bytes = std::fs::metadata(e.directory.join("state.sqlite3"))
                .ok()
                .map(|metadata| metadata.len());
            let storage = rejection_rejector::storage::inspect(&e.directory)?;
            let scheduled_backup = rejection_rejector::recovery::scheduled_backup_status(
                &e.db,
                &e.settings,
                chrono::Utc::now(),
            )?;
            let backup_isolation =
                rejection_rejector::recovery::backup_isolation_status(&e.directory, &e.settings)?;
            let readiness = rejection_rejector::readiness::assess(
                &e.settings,
                database_integrity_ok,
                storage.runtime_write_safe,
                e.connected(),
                e.send_scope(),
                false,
                false,
            );
            let local_ai = Ollama::new(&e.settings)?;
            let runtime_version = local_ai.runtime_version().ok();
            let ollama_healthy = runtime_version.is_some();
            let (installed, digest_matches, gpu_resident_now, model_message) = if ollama_healthy {
                match local_ai.inspect() {
                    Ok(info) => {
                        let digest_matches = e.settings.model_digest.as_ref() == Some(&info.digest);
                        match local_ai.residency(&info.digest) {
                            Ok(status) => (
                                info.installed,
                                digest_matches,
                                status.gpu_resident,
                                status.message,
                            ),
                            Err(error) => (
                                info.installed,
                                digest_matches,
                                false,
                                format!(
                                    "Model is installed but not currently qualified as GPU-resident: {error}"
                                ),
                            ),
                        }
                    }
                    Err(error) => (
                        false,
                        false,
                        false,
                        format!("Model inspection failed: {error}"),
                    ),
                }
            } else {
                (
                    false,
                    false,
                    false,
                    "Ollama is not reachable on the configured loopback address".into(),
                )
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "build": build_info::current(),
                    "configuration_readiness": readiness.clone(),
                    "enterprise_policy": e.enterprise_policy_status(),
                    "storage": storage,
                    "scheduled_backup": scheduled_backup,
                    "backup_isolation": backup_isolation,
                    "database": {
                        "integrity_ok": database_integrity_ok,
                        "schema_version": e.db.schema_version()?,
                        "bytes": database_bytes,
                        "message": database_message
                    },
                    "gmail": {
                        "connected_locally": e.connected(),
                        "send_scope_granted": e.send_scope(),
                        "sending_enabled": e.settings.sending_enabled
                    },
                    "schedule": {
                        "poll_hours": e.settings.poll_hours,
                        "lookback_days": e.settings.lookback_days
                    },
                    "mode": e.settings.mode,
                    "local_ai": {
                        "ollama_healthy": ollama_healthy,
                        "runtime_version": runtime_version,
                        "model": e.settings.model,
                        "digest_pinned": e.settings.model_digest.is_some(),
                        "installed_and_pin_matches": installed && digest_matches,
                        "gpu_resident_now": gpu_resident_now,
                        "message": model_message
                    },
                    "note": "gpu_resident_now is a point-in-time Ollama check; Qualify & pin performs the full classification/draft/verification pipeline."
                }))?
            );
            if let Some(requirement) = require {
                ensure!(
                    requirement.satisfied(&readiness),
                    "Requested readiness level {requirement:?} is not satisfied"
                );
            }
        }
        Action::RotateApiToken => {
            let mut e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let material = api_auth::rotate(&mut e.db)?;
            e.checkpoint_audit_protection()?;
            let token = material
                .plaintext_once
                .context("Token rotation did not return one-time plaintext")?;
            println!("{}", token.as_str());
            eprintln!(
                "Store this credential in the consuming application's OS-protected secret store. It cannot be revealed again; rotate it if lost."
            );
        }
        Action::Status | Action::Demo => {
            let demo = matches!(args.command, Action::Demo);
            let e = Engine::open(
                dir,
                demo,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"build":build_info::current(),"demo":demo,"connected":e.connected(),"mode":e.settings.mode,"sending_enabled":e.settings.sending_enabled,"poll_hours":e.settings.poll_hours,"lookback_days":e.settings.lookback_days,"model":e.settings.model,"counts":e.db.counts(&e.account)?,"enterprise_policy":e.enterprise_policy_status()})
                )?
            );
        }
        Action::Evaluate { out } => {
            let mut e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            e.evaluate_model_to(&out)?;
            println!(
                "Task-specific evaluation passed and qualification was stored: {}",
                out.display()
            );
        }
        Action::ProfileModel { out } => {
            let mut e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            e.profile_model_runtime_to(&out)?;
            println!("Local model runtime profile written to {}", out.display());
        }
        Action::CompareModels { out } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            rejection_rejector::evaluation::compare_installed(&e.settings, &out)?;
            println!(
                "Task-specific model comparison written to {}",
                out.display()
            );
        }
        Action::Integrity => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            e.db.integrity_check()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "schema_version": e.db.schema_version()?,
                    "note": "SQLite quick_check, foreign-key integrity and authenticated vault marker passed."
                }))?
            );
        }
        Action::Compact => {
            let mut e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let report = e.compact_database()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Action::Backup { out } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let manifest = recovery::create_backup(&e.db, &e.directory, &out)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Action::VerifyBackup { path } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let manifest = recovery::verify_backup(&e.db, &path)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Action::RecoveryDrill { path } => {
            let mut e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let report = recovery::recovery_drill(&e.directory, &path)?;
            e.db.log(
                "backup.drill_passed",
                None,
                &format!(
                    "Isolated recovery drill passed: schema={} metadata={} items={} audit_events={} deliveries={}",
                    report.restored_schema_version,
                    report.metadata_records,
                    report.item_records,
                    report.audit_events,
                    report.delivery_records
                ),
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Action::RestoreBackup { path, confirm } => {
            anyhow::ensure!(confirm == "RESTORE", "Restore requires --confirm RESTORE");
            let report = recovery::restore_backup(&dir, &path)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Action::ExportRecoveryKey {
            out,
            passphrase_file,
        } => {
            if let Some(loaded) = policy::load_optional()? {
                ensure!(
                    loaded.policy.allows_recovery_key_export(),
                    "Enterprise policy prohibits portable recovery-key export"
                );
            }
            let passphrase = recovery_passphrase(&passphrase_file)?;
            let envelope = recovery::export_recovery_key(&dir, &passphrase, &out)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "created": out,
                    "vault_id": envelope.vault_id,
                    "format_version": envelope.format_version,
                    "note": "Encrypted recovery key created. Store it separately from the backup and securely delete the passphrase file when appropriate."
                }))?
            );
        }
        Action::VerifyRecoveryKey {
            backup,
            recovery_key,
            passphrase_file,
        } => {
            let passphrase = recovery_passphrase(&passphrase_file)?;
            let envelope =
                recovery::verify_recovery_key_for_backup(&backup, &recovery_key, &passphrase)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "verified": true,
                    "vault_id": envelope.vault_id,
                    "format_version": envelope.format_version,
                    "note": "Recovery key authenticated the backup; no OS credential was modified."
                }))?
            );
        }
        Action::ImportRecoveryKey {
            backup,
            recovery_key,
            passphrase_file,
            confirm,
        } => {
            ensure!(
                confirm == "IMPORT",
                "Recovery-key import requires --confirm IMPORT"
            );
            let passphrase = recovery_passphrase(&passphrase_file)?;
            let envelope = recovery::import_recovery_key_for_backup(
                &dir,
                &backup,
                &recovery_key,
                &passphrase,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "imported": true,
                    "vault_id": envelope.vault_id,
                    "note": "Recovered key installed only after authenticating the backup. Existing OS credentials are never overwritten automatically."
                }))?
            );
        }
        Action::Diagnostics { out } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            rejection_rejector::diagnostics::write_report(&e, &out)?;
            println!(
                "Privacy-safe diagnostics written locally to {}. Review before sharing.",
                out.display()
            );
        }
        Action::AuditAnchor { out } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let anchor = audit_anchor::write_anchor(&e.db, &e.directory, &out)?;
            println!("{}", serde_json::to_string_pretty(&anchor)?);
        }
        Action::VerifyAuditAnchor { path } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            let anchor = audit_anchor::verify_anchor(&e.db, &e.directory, &path)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "verified": true,
                    "anchor": anchor,
                    "current_audit_head": e.db.audit_head()?,
                    "current_audit_sequence": e.db.latest_event_seq()?
                }))?
            );
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn recovery_passphrase_file_must_be_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("recovery-passphrase");
        std::fs::write(&path, b"correct horse battery staple\n").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(recovery_passphrase(&path).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let passphrase = recovery_passphrase(&path).unwrap();
        assert_eq!(passphrase.as_slice(), b"correct horse battery staple");
    }
}
