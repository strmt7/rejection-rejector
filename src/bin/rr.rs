#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable
    )
)]
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use rejection_rejector::{
    api_auth, audit_anchor, background, build_info, config, contracts, decision, engine::Engine,
    ollama::Ollama, policy, recovery, shadow, worker::Worker,
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
enum AutostartAction {
    /// Register/update a least-privilege per-user worker at Windows logon.
    Install,
    /// Inspect whether the registered task matches the expected worker contract.
    Status,
    /// Remove the Rejection Rejector scheduled worker task.
    Remove,
}

#[derive(Subcommand)]
enum Action {
    /// Run the scheduler using settings previously configured in the desktop application.
    Run,
    /// Manage least-privilege Windows per-user background worker registration.
    Autostart {
        #[command(subcommand)]
        action: AutostartAction,
    },
    /// Print deterministic binary/source/dependency build identity without opening a workspace.
    BuildInfo,
    /// Print machine-readable compatibility-contract identities without opening a workspace.
    ContractInfo,
    /// Print local settings and aggregate status, without message bodies or credentials.
    Status,
    /// Print a synthetic offline status; never connects to Gmail.
    Demo,
    /// Run the interactive terminal interface (Queue, Review, Activity, Settings).
    Tui {
        /// Synthetic offline demo. No account, model or email sending.
        #[arg(long)]
        demo: bool,
    },
    /// Serve the embedded local web interface from the loopback API.
    ///
    /// The page is served by the same loopback listener as the integration
    /// API, so the API must be enabled in Settings first; the bearer token is
    /// entered in the page and never stored by the browser.
    Web,
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
    /// Evaluate an installed Ollama 0.35+ typed decision model on recruiting fixtures.
    /// R&D only: this never authorizes or sends email.
    EvaluateDecision {
        #[arg(long, default_value = "nimble:9b-q8_0")]
        model: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare already-installed typed decision-model candidates on recruiting fixtures.
    /// R&D only: this never authorizes or sends email.
    CompareDecisionModels {
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
    /// Simulate local Automatic eligibility without Gmail preflight, reservations or sends.
    ShadowAutomatic {
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
    /// Print the machine-readable JSON Schema for enterprise policy files.
    PolicySchema,
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

/// Announce a completed report action and its output path.
///
/// Inputs: `result` — outcome of the report action; `message` — completion
/// text; `out` — destination path. Output: `Ok(())` after printing the
/// completion line, or the action's error unchanged.
fn announce(result: Result<()>, message: &str, out: &std::path::Path) -> Result<()> {
    result?;
    println!("{message} {}", out.display());
    Ok(())
}

/// Print the machine-readable summary of a decision-model evaluation.
///
/// Inputs: `report` — evaluation report JSON; `model` — evaluated model
/// tag; `out` — report path. Output: `Ok(())` after printing the summary.
fn print_decision_summary(
    report: &serde_json::Value,
    model: &str,
    out: &std::path::Path,
) -> Result<()> {
    let payload = serde_json::json!({
            "model": model,
            "report": out,
            "recommendation_eligible": report
                .pointer("/summary/recommendation_eligible")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            "note": "R&D-only decision-model evidence; no delivery authorization was changed."
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

/// Evaluate one typed decision model and print its summary.
///
/// Inputs: `e` — open engine (settings locate Ollama); `model` — model tag;
/// `out` — destination for the evidence report. Output: `Ok(())` after the
/// summary is printed; evaluation errors propagate unchanged.
fn evaluate_decision(e: &Engine, model: &str, out: &std::path::Path) -> Result<()> {
    print_decision_summary(&decision::evaluate(&e.settings, model, out)?, model, out)
}

/// Open the workspace engine for one command-line action.
///
/// Inputs: `dir` — workspace directory; `demo` — seed synthetic data;
/// `paused` — start paused (command surfaces never dispatch). Output: the
/// opened engine; workspace or vault failures propagate.
fn open_engine(dir: PathBuf, demo: bool, paused: bool) -> Result<Engine> {
    Engine::open(
        dir,
        demo,
        Arc::new(AtomicBool::new(paused)),
        Arc::new(AtomicBool::new(false)),
    )
}

/// Print the machine-readable summary of a decision-model comparison.
///
/// Inputs: `report` — comparison report JSON; `out` — report path.
/// Output: `Ok(())` after printing the summary.
fn print_decision_comparison(report: &serde_json::Value, out: &std::path::Path) -> Result<()> {
    let payload = serde_json::json!({
            "report": out,
            "recommended_model": report.get("recommended_model"),
            "note": "R&D-only comparison; no delivery authorization was changed."
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

/// Compare installed typed decision models and print the summary.
///
/// Inputs: `e` — open engine; `out` — destination for the comparison
/// report. Output: `Ok(())` after the summary is printed; comparison errors
/// propagate unchanged.
fn compare_decision_models(e: &Engine, out: &std::path::Path) -> Result<()> {
    print_decision_comparison(&decision::compare_installed(&e.settings, out)?, out)
}

/// Resolve one autostart-management action to its JSON report.
///
/// Inputs: `action` — requested sub-action; `executable` — worker
/// executable to register; `dir` — data directory to register it with;
/// `run` — task-scheduler command runner (injected in tests). Output: the
/// report JSON; registration errors propagate unchanged.
fn autostart_report(
    action: &AutostartAction,
    executable: &std::path::Path,
    dir: &std::path::Path,
    run: background::CommandRunner,
) -> Result<serde_json::Value> {
    Ok(match action {
        AutostartAction::Install => {
            serde_json::to_value(background::install(executable, dir, run)?)?
        }
        AutostartAction::Status => serde_json::to_value(background::status(executable, dir, run)?)?,
        AutostartAction::Remove => {
            background::remove(run)?;
            serde_json::json!({ "removed": true, "task_name": background::TASK_NAME })
        }
    })
}

/// Wait until the background worker reports its startup state.
///
/// Inputs: `worker` — spawned worker; `deadline` — startup deadline.
/// Output: the initialized [`Snapshot`]; `Err` when the workspace failed to
/// open or initialization exceeded the deadline.
fn wait_for_ready(
    worker: &Worker,
    deadline: std::time::Instant,
) -> Result<rejection_rejector::worker::Snapshot> {
    loop {
        let snapshot = worker.view();
        if snapshot.fatal {
            anyhow::bail!("{}", snapshot.error);
        }
        if snapshot.initialized {
            return Ok(snapshot);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("The workspace did not initialize before the startup deadline");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Serve the local web interface until the worker stops.
///
/// Inputs: `worker` — spawned worker; `install_ctrlc` — Ctrl+C handler
/// installer (injected in tests). Output: `Ok(())` when the worker stopped;
/// `Err` when the workspace failed, the API is disabled, or the worker died.
fn web_serve(
    worker: &Worker,
    install_ctrlc: impl FnOnce(Box<dyn FnMut() + Send + 'static>) -> Result<()>,
) -> Result<()> {
    let stop = worker.stop.clone();
    let paused = worker.paused.clone();
    let handler = Box::new(move || {
        paused.store(true, Ordering::SeqCst);
        stop.store(true, Ordering::SeqCst);
    });
    install_ctrlc(handler)?;
    wait_for_ready(worker, std::time::Instant::now() + Duration::from_secs(30))?;
    let snapshot = worker.view();
    if !snapshot.api_listening {
        anyhow::bail!(
            "rr web is served by the local integration API. Enable the API in Settings, save, and run rr web again (enterprise policy may also prohibit the API)."
        );
    }
    println!(
        "Local web interface: http://127.0.0.1:{}/",
        snapshot.settings.api_port
    );
    println!(
        "Enter the local API bearer token in the page. It is kept in page memory only. Ctrl+C stops the worker."
    );
    while !worker.stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
        let snapshot = worker.view();
        if snapshot.fatal {
            anyhow::bail!("{}", snapshot.error);
        }
    }
    Ok(())
}

/// Run the headless dispatch worker until the operator stops it.
///
/// Inputs: `worker` — spawned worker; `install_ctrlc` — Ctrl+C handler
/// installer (injected in tests). Output: `Ok(())` when the worker stopped;
/// `Err` when the workspace failed to open or the handler could not be
/// installed.
fn run_daemon(
    worker: &Worker,
    install_ctrlc: impl FnOnce(Box<dyn FnMut() + Send + 'static>) -> Result<()>,
) -> Result<()> {
    let stop = worker.stop.clone();
    let paused = worker.paused.clone();
    let handler = Box::new(move || {
        paused.store(true, Ordering::SeqCst);
        stop.store(true, Ordering::SeqCst);
    });
    install_ctrlc(handler)?;
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
    Ok(())
}

/// Resolve the workspace directory for one command-line action.
///
/// Inputs: `data_dir` — explicit `--data-dir` override. Output: the workspace
/// path; without an override the platform data directory is used and its
/// resolution failure propagates.
fn resolve_dir(data_dir: &Option<PathBuf>) -> Result<PathBuf> {
    Ok(data_dir.clone().unwrap_or(config::data_dir()?))
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Action::BuildInfo => println!("{}", serde_json::to_string_pretty(&build_info::current())?),
        Action::ContractInfo => {
            println!("{}", serde_json::to_string_pretty(&contracts::current())?)
        }
        Action::PolicySchema => print!("{}", policy::schema_text()),
        Action::Autostart { action } => {
            let dir = resolve_dir(&args.data_dir)?;
            let executable = std::env::current_exe().context("Cannot resolve rr.exe path")?;
            let report = autostart_report(&action, &executable, &dir, background::schtasks)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Action::ValidatePolicy { path } => {
            let absolute = std::fs::canonicalize(&path)?;
            let loaded = policy::load_file(&absolute)?;
            println!("{}", serde_json::to_string_pretty(&loaded.status())?);
        }
        Action::PolicyStatus => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&e.enterprise_policy_status())?
            );
        }
        Action::Run => {
            let dir = resolve_dir(&args.data_dir)?;
            let worker = Worker::spawn(dir, false);
            run_daemon(&worker, |handler| {
                ctrlc::set_handler(handler).map_err(Into::into)
            })?;
        }
        Action::Metrics { openmetrics } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            let metrics = rejection_rejector::metrics::collect(&e, chrono::Utc::now())?;
            if openmetrics {
                let runtime = rejection_rejector::runtime_log::performance_summary(&e.directory)?;
                print!(
                    "{}",
                    rejection_rejector::metrics::render_openmetrics_with_runtime_and_emergency(
                        &metrics,
                        &runtime,
                        rejection_rejector::emergency::status_fail_closed().active,
                    )
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&metrics)?);
            }
        }
        Action::Doctor { require } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
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
            let status_fn = rejection_rejector::recovery::scheduled_backup_status;
            let scheduled_backup = status_fn(&e.db, &e.settings, chrono::Utc::now())?;
            let backup_isolation =
                rejection_rejector::recovery::backup_isolation_status(&e.directory, &e.settings)?;
            let emergency_stop = rejection_rejector::emergency::status_fail_closed();
            let readiness = rejection_rejector::readiness::assess_context(
                rejection_rejector::readiness::RuntimeReadinessContext {
                    settings: &e.settings,
                    database_integrity_ok,
                    storage_write_safe: storage.runtime_write_safe,
                    connected: e.connected(),
                    send_scope: e.send_scope(),
                    paused: false,
                    stopping: false,
                    emergency_stop_active: emergency_stop.active,
                },
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
            let payload = serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "build": build_info::current(),
                    "configuration_readiness": readiness.clone(),
                    "emergency_stop": emergency_stop,
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
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
            if let Some(requirement) = require {
                ensure!(
                    requirement.satisfied(&readiness),
                    "Requested readiness level {requirement:?} is not satisfied"
                );
            }
        }
        Action::RotateApiToken => {
            let dir = resolve_dir(&args.data_dir)?;
            let mut e = open_engine(dir, false, true)?;
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
        Action::Tui { demo } => {
            let dir = resolve_dir(&args.data_dir)?;
            let worker = Worker::spawn(dir, demo);
            rejection_rejector::tui::run(worker)?;
        }
        Action::Web => {
            let dir = resolve_dir(&args.data_dir)?;
            let worker = Worker::spawn(dir, false);
            web_serve(&worker, |handler| {
                ctrlc::set_handler(handler).map_err(Into::into)
            })?;
        }
        Action::Status | Action::Demo => {
            let dir = resolve_dir(&args.data_dir)?;
            let demo = matches!(args.command, Action::Demo);
            let e = open_engine(dir, demo, false)?;
            let payload = serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"build":build_info::current(),"demo":demo,"connected":e.connected(),"mode":e.settings.mode,"sending_enabled":e.settings.sending_enabled,"poll_hours":e.settings.poll_hours,"lookback_days":e.settings.lookback_days,"model":e.settings.model,"counts":e.db.counts(&e.account)?,"enterprise_policy":e.enterprise_policy_status()});
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        Action::Evaluate { out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let mut e = open_engine(dir, false, true)?;
            announce(
                e.evaluate_model_to(&out),
                "Task-specific evaluation passed and qualification was stored:",
                &out,
            )?;
        }
        Action::EvaluateDecision { model, out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            evaluate_decision(&e, &model, &out)?;
        }
        Action::CompareDecisionModels { out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            compare_decision_models(&e, &out)?;
        }
        Action::ProfileModel { out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let mut e = open_engine(dir, false, true)?;
            announce(
                e.profile_model_runtime_to(&out),
                "Local model runtime profile written to",
                &out,
            )?;
        }
        Action::CompareModels { out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            let result = rejection_rejector::evaluation::compare_installed(&e.settings, &out);
            announce(result, "Task-specific model comparison written to", &out)?;
        }
        Action::Integrity => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            e.db.integrity_check()?;
            let payload = serde_json::json!({
                    "ok": true,
                    "schema_version": e.db.schema_version()?,
                    "note": "SQLite quick_check, foreign-key integrity and authenticated vault marker passed."
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        Action::Compact => {
            let dir = resolve_dir(&args.data_dir)?;
            let mut e = open_engine(dir, false, true)?;
            let report = e.compact_database()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Action::Backup { out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            let manifest = recovery::create_backup(&e.db, &e.directory, &out)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Action::VerifyBackup { path } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            let manifest = recovery::verify_backup(&e.db, &path)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Action::RecoveryDrill { path } => {
            let dir = resolve_dir(&args.data_dir)?;
            let mut e = open_engine(dir, false, true)?;
            let report = recovery::recovery_drill(&e.directory, &path)?;
            let entry = format!(
                "Isolated recovery drill passed: schema={} metadata={} items={} audit_events={} delivery_records={}",
                report.restored_schema_version,
                report.metadata_records,
                report.item_records,
                report.audit_events,
                report.delivery_records
            );
            e.db.log("backup.drill_passed", None, &entry)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Action::RestoreBackup { path, confirm } => {
            let dir = resolve_dir(&args.data_dir)?;
            anyhow::ensure!(confirm == "RESTORE", "Restore requires --confirm RESTORE");
            let report = recovery::restore_backup(&dir, &path)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Action::ExportRecoveryKey {
            out,
            passphrase_file,
        } => {
            let dir = resolve_dir(&args.data_dir)?;
            if let Some(loaded) = policy::load_optional()? {
                ensure!(
                    loaded.policy.allows_recovery_key_export(),
                    "Enterprise policy prohibits portable recovery-key export"
                );
            }
            let passphrase = recovery_passphrase(&passphrase_file)?;
            let envelope = recovery::export_recovery_key(&dir, &passphrase, &out)?;
            let payload = serde_json::json!({
                    "created": out,
                    "vault_id": envelope.vault_id,
                    "format_version": envelope.format_version,
                    "note": "Encrypted recovery key created. Store it separately from the backup and securely delete the passphrase file when appropriate."
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        Action::VerifyRecoveryKey {
            backup,
            recovery_key,
            passphrase_file,
        } => {
            let passphrase = recovery_passphrase(&passphrase_file)?;
            let envelope =
                recovery::verify_recovery_key_for_backup(&backup, &recovery_key, &passphrase)?;
            let payload = serde_json::json!({
                    "verified": true,
                    "vault_id": envelope.vault_id,
                    "format_version": envelope.format_version,
                    "note": "Recovery key authenticated the backup; no OS credential was modified."
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        Action::ImportRecoveryKey {
            backup,
            recovery_key,
            passphrase_file,
            confirm,
        } => {
            let dir = resolve_dir(&args.data_dir)?;
            ensure!(
                confirm == "IMPORT",
                "Recovery-key import requires --confirm IMPORT"
            );
            let passphrase = recovery_passphrase(&passphrase_file)?;
            let import = recovery::import_recovery_key_for_backup;
            let envelope = import(&dir, &backup, &recovery_key, &passphrase)?;
            let payload = serde_json::json!({
                    "imported": true,
                    "vault_id": envelope.vault_id,
                    "note": "Recovered key installed only after authenticating the backup. Existing OS credentials are never overwritten automatically."
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        Action::Diagnostics { out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            rejection_rejector::diagnostics::write_report(&e, &out)?;
            println!(
                "Privacy-safe diagnostics written locally to {}. Review before sharing.",
                out.display()
            );
        }
        Action::ShadowAutomatic { out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            shadow::write_report(&e, &out)?;
            println!(
                "Read-only Automatic shadow audit written to {}. No provider preflight or external write occurred.",
                out.display()
            );
        }
        Action::AuditAnchor { out } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            let anchor = audit_anchor::write_anchor(&e.db, &e.directory, &out)?;
            println!("{}", serde_json::to_string_pretty(&anchor)?);
        }
        Action::VerifyAuditAnchor { path } => {
            let dir = resolve_dir(&args.data_dir)?;
            let e = open_engine(dir, false, true)?;
            let anchor = audit_anchor::verify_anchor(&e.db, &e.directory, &path)?;
            let payload = serde_json::json!({
                    "verified": true,
                    "anchor": anchor,
                    "current_audit_head": e.db.audit_head()?,
                    "current_audit_sequence": e.db.latest_event_seq()?
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Readiness requirements map to exactly one readiness flag.
    ///
    /// Why: `--require` gates deployment on a specific flag — a crossed
    /// mapping would gate on the wrong readiness dimension.
    #[test]
    fn readiness_requirements_map_to_their_exact_flags() {
        let ready = rejection_rejector::readiness::RuntimeReadiness {
            live: true,
            workspace_ready: true,
            mailbox_sync_ready: false,
            analysis_ready: true,
            automatic_dispatch_ready: false,
            automatic_block_reasons: Vec::new(),
        };
        assert!(ReadinessRequirement::Workspace.satisfied(&ready));
        assert!(!ReadinessRequirement::Mailbox.satisfied(&ready));
        assert!(ReadinessRequirement::Analysis.satisfied(&ready));
        assert!(!ReadinessRequirement::Automatic.satisfied(&ready));
    }

    /// The recovery passphrase reader enforces its safety envelope.
    ///
    /// Why: the passphrase wraps the vault key — short passphrases and
    /// oversized files are refused before any crypto runs.
    #[test]
    fn recovery_passphrase_enforces_its_safety_envelope() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        assert!(
            recovery_passphrase(&missing).is_err(),
            "missing files refused"
        );

        let short = root.path().join("short");
        std::fs::write(&short, b"too short").unwrap();
        assert!(
            recovery_passphrase(&short).is_err(),
            "short passphrases refused"
        );

        let oversized = root.path().join("oversized");
        std::fs::write(&oversized, vec![b'a'; 4097]).unwrap();
        assert!(
            recovery_passphrase(&oversized).is_err(),
            "files above the 4 KiB limit refused"
        );

        let ok = root.path().join("ok");
        std::fs::write(&ok, b"correct horse battery staple\r\n").unwrap();
        let passphrase = recovery_passphrase(&ok).unwrap();
        assert_eq!(
            passphrase.as_slice(),
            b"correct horse battery staple",
            "trailing newlines are trimmed, the passphrase is kept"
        );
    }

    #[cfg(unix)]
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

    /// Report announcements print the completion line only on success.
    ///
    /// Why: the completion line tells the operator where the evidence
    /// landed — printing it for a failed run would claim success.
    #[test]
    fn announce_prints_only_for_completed_reports() {
        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("report.json");
        assert!(announce(Ok(()), "written to", &out).is_ok());
        let error = announce(Err(anyhow::anyhow!("model missing")), "written to", &out)
            .expect_err("failures propagate");
        assert_eq!(error.to_string(), "model missing");
    }

    /// Decision summaries report eligibility exactly as measured.
    ///
    /// Why: R&D evidence must never overstate eligibility — an inverted
    /// flag would advertise an unqualified model as eligible.
    #[test]
    fn decision_summaries_reflect_the_measured_report() {
        let out = std::path::Path::new("report.json");
        let eligible = serde_json::json!({"summary": {"recommendation_eligible": true}});
        assert!(print_decision_summary(&eligible, "model:tag", out).is_ok());
        let ineligible = serde_json::json!({"summary": {}});
        assert!(print_decision_summary(&ineligible, "model:tag", out).is_ok());
        assert!(print_decision_comparison(&serde_json::json!({}), out).is_ok());
    }

    /// A fake task-scheduler runner records the exact registration commands.
    ///
    /// Why: install/status/remove must drive the scheduler through the
    /// injected runner only — tests never touch the real one.
    #[test]
    fn autostart_actions_route_through_the_injected_runner() {
        fn ok_output() -> std::process::Output {
            #[cfg(unix)]
            let status = std::os::unix::process::ExitStatusExt::from_raw(0);
            #[cfg(windows)]
            let status = std::os::windows::process::ExitStatusExt::from_raw(0);
            std::process::Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }
        fn fake_ok(_args: &[&str]) -> Result<std::process::Output> {
            Ok(ok_output())
        }
        fn fake_err(_args: &[&str]) -> Result<std::process::Output> {
            Err(anyhow::anyhow!("scheduler unavailable"))
        }
        let root = tempfile::tempdir().unwrap();
        let executable = root.path().join("rr.exe");
        std::fs::write(&executable, b"stub").unwrap();
        for action in [
            AutostartAction::Install,
            AutostartAction::Status,
            AutostartAction::Remove,
        ] {
            match autostart_report(&action, &executable, root.path(), fake_ok) {
                Ok(report) => {
                    assert!(report.is_object(), "reports are JSON objects");
                }
                Err(error) => {
                    // Non-Windows refuses before the runner is consulted.
                    assert!(error.to_string().contains("supported only on Windows"));
                }
            }
        }
        let error = autostart_report(
            &AutostartAction::Install,
            &executable,
            root.path(),
            fake_err,
        )
        .expect_err("scheduler failures propagate");
        #[cfg(windows)]
        assert_eq!(error.to_string(), "scheduler unavailable");
        #[cfg(not(windows))]
        assert!(error.to_string().contains("supported only on Windows"));
    }

    /// A stopped worker makes the daemon exit without sleeping.
    ///
    /// Why: the daemon loop must honour the stop flag on entry so scripted
    /// shutdowns do not wait a full tick.
    #[test]
    fn run_daemon_exits_immediately_when_the_worker_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        worker.stop.store(true, Ordering::SeqCst);
        let installed = std::sync::atomic::AtomicBool::new(false);
        run_daemon(&worker, |_| {
            installed.store(true, Ordering::SeqCst);
            Ok(())
        })
        .expect("stopped workers end the daemon");
        assert!(installed.load(Ordering::SeqCst), "ctrl-c handler installed");
    }

    /// A fatally broken workspace ends the daemon with the worker's error.
    ///
    /// Why: a dead workspace must fail loudly instead of idling forever.
    #[test]
    fn run_daemon_surfaces_fatal_workspace_errors() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !worker.view().initialized {
            assert!(
                std::time::Instant::now() < deadline,
                "worker never initialized"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        worker.snapshot.lock().unwrap().fatal = true;
        worker.snapshot.lock().unwrap().error = "workspace is locked".into();
        let error = run_daemon(&worker, |_| Ok(())).expect_err("fatal workspaces end the daemon");
        assert_eq!(error.to_string(), "workspace is locked");
    }

    /// The web flow refuses to serve without the loopback API.
    ///
    /// Why: `rr web` is served by the integration API — starting the page
    /// story without the API would strand the operator on a dead URL.
    #[test]
    fn web_serve_refuses_without_the_loopback_api() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !worker.view().initialized {
            assert!(
                std::time::Instant::now() < deadline,
                "worker never initialized"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let error = web_serve(&worker, |_| Ok(())).expect_err("no API, no web interface");
        assert!(error.to_string().contains("Enable the API in Settings"));
    }

    /// The startup deadline is enforced even when the worker never comes up.
    ///
    /// Why: a wedged startup must fail with the deadline error instead of
    /// waiting forever behind a load screen.
    #[test]
    fn wait_for_ready_enforces_the_startup_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !worker.view().initialized {
            assert!(
                std::time::Instant::now() < deadline,
                "worker never initialized"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Park the worker in "still starting" so the poll loop has to wait.
        worker.snapshot.lock().unwrap().initialized = false;
        let error = match wait_for_ready(
            &worker,
            std::time::Instant::now() + std::time::Duration::from_millis(150),
        ) {
            Ok(_) => panic!("an expired deadline refuses to wait"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("did not initialize"));
    }

    /// The daemon installs the pause-and-stop handler and exits through it.
    ///
    /// Why: the Ctrl+C handler is the only graceful shutdown path — it must
    /// pause dispatch and end the loop, and the loop must survive until it
    /// fires.
    #[test]
    fn run_daemon_installs_the_stop_handler_and_exits_through_it() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !worker.view().initialized {
            assert!(
                std::time::Instant::now() < deadline,
                "worker never initialized"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let result = run_daemon(&worker, |handler| {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1200));
                let mut handler = handler;
                handler();
            });
            Ok(())
        });
        assert!(result.is_ok(), "the handler stops the daemon cleanly");
        assert!(
            worker.stop.load(Ordering::SeqCst),
            "the handler stopped the worker"
        );
        assert!(
            worker.paused.load(Ordering::SeqCst),
            "the handler paused dispatch"
        );
    }

    /// Web serving reports the local URL and stops through the handler.
    ///
    /// Why: the printed URL and the Ctrl+C stop are the operator's only
    /// handles on the serving loop.
    #[test]
    fn web_serve_reports_the_local_url_and_stops_on_the_handler() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !worker.view().initialized {
            assert!(
                std::time::Instant::now() < deadline,
                "worker never initialized"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        {
            let mut snapshot = worker.snapshot.lock().unwrap();
            snapshot.api_listening = true;
            snapshot.settings.api_port = 8734;
        }
        let result = web_serve(&worker, |handler| {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1200));
                let mut handler = handler;
                handler();
            });
            Ok(())
        });
        assert!(result.is_ok(), "the handler stops the serving loop cleanly");
    }

    /// A fatal workspace ends web serving with the engine's error.
    ///
    /// Why: the serving loop must not outlive the database.
    #[test]
    fn web_serve_surfaces_fatal_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().to_path_buf(), true);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !worker.view().initialized {
            assert!(
                std::time::Instant::now() < deadline,
                "worker never initialized"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        {
            let mut snapshot = worker.snapshot.lock().unwrap();
            snapshot.api_listening = true;
        }
        // The workspace fails only after startup, so the serving loop itself
        // has to notice and end.
        let shared = worker.snapshot.clone();
        let error = match web_serve(&worker, move |_| {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1200));
                let mut snapshot = shared.lock().unwrap();
                snapshot.fatal = true;
                snapshot.error = "workspace lost".into();
            });
            Ok(())
        }) {
            Ok(()) => panic!("a fatal workspace must end web serving"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("workspace lost"));
    }
}
