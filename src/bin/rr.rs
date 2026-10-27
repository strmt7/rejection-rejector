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
    /// Whether a readiness gate is satisfied by a runtime readiness report.
    ///
    /// Inputs: `readiness` — runtime readiness report to test. Output: `true` only
    /// when this gate's flag is ready.
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
    /// Run the task-qualification pipeline and pin the passing model.
    ///
    /// This is the scripted equivalent of the desktop Local AI "Qualify & pin"
    /// action; analysis and unattended dispatch stay blocked until it passes.
    Qualify {
        /// Also qualify the optional independent verifier model.
        #[arg(long)]
        verifier: bool,
    },
    /// Update local settings and print the effective result as JSON.
    ///
    /// Inputs: only the flags provided change; omitted fields keep their current
    /// values. Delivery state is never modified by this command.
    Configure {
        /// Email age window in days (1/3/7/14/28).
        #[arg(long)]
        lookback_days: Option<u8>,
        /// Background check interval in hours (1/2/4/8/24).
        #[arg(long)]
        poll_hours: Option<u8>,
        /// Local Ollama chat model tag.
        #[arg(long)]
        model: Option<String>,
        /// Reply signature block.
        #[arg(long)]
        signature: Option<String>,
        /// Enable the authenticated loopback integration API.
        #[arg(long)]
        api_enabled: Option<bool>,
        /// Loopback port for the integration API.
        #[arg(long)]
        api_port: Option<u16>,
    },
    /// Synchronize the connected mailbox once and print the count of new identities.
    Sync,
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
/// Read a recovery passphrase from a file.
///
/// Inputs: `path` — passphrase file. Output: `Result<Zeroizing<Vec<u8>>>` —
/// the file bytes; missing files, symlinks and out-of-envelope contents are
/// refused.
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
/// Inputs: `settings` — open workspace settings (they locate Ollama);
/// `model` — model tag; `out` — destination for the evidence report.
/// Output: `Ok(())` after the summary is printed; evaluation errors
/// propagate unchanged (no report is written when the runtime fails).
fn evaluate_decision(
    settings: &config::Settings,
    model: &str,
    out: &std::path::Path,
) -> Result<()> {
    print_decision_summary(&decision::evaluate(settings, model, out)?, model, out)
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
/// Inputs: `settings` — open workspace settings (they locate Ollama);
/// `out` — destination for the comparison report. Output: `Ok(())` after
/// printing the summary; comparison errors propagate unchanged.
fn compare_decision_models(settings: &config::Settings, out: &std::path::Path) -> Result<()> {
    print_decision_comparison(&decision::compare_installed(settings, out)?, out)
}

/// Compare installed curated models and print the summary.
///
/// Inputs: `settings` — open workspace settings (they locate Ollama);
/// `out` — destination for the comparison report. Output: `Ok(())` after
/// the report is announced; comparison errors propagate unchanged.
fn compare_models(settings: &config::Settings, out: &std::path::Path) -> Result<()> {
    announce(
        rejection_rejector::evaluation::compare_installed(settings, out),
        "Task-specific model comparison written to",
        out,
    )
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
/// Output: the initialized `Snapshot`; `Err` when the workspace failed to
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
    match data_dir {
        Some(dir) => Ok(dir.clone()),
        None => config::data_dir(),
    }
}

/// Run the `rr` command-line interface.
///
/// Inputs: none; parses command-line arguments. Output: `Ok(())` on success;
/// errors abort with a non-zero exit.
fn main() -> Result<()> {
    let args = Args::parse();
    let Args { data_dir, command } = args;
    dispatch(command, &data_dir)
}

/// Route one parsed subcommand to its dispatch group.
///
/// Inputs: `command` — parsed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::Run | Action::Tui { .. } | Action::Web | Action::Status | Action::Demo => {
            dispatch_runtime(command, data_dir)
        }
        Action::BuildInfo
        | Action::ContractInfo
        | Action::PolicySchema
        | Action::PolicyStatus
        | Action::ValidatePolicy { .. }
        | Action::Autostart { .. } => dispatch_info(command, data_dir),
        Action::Evaluate { .. }
        | Action::EvaluateDecision { .. }
        | Action::CompareDecisionModels { .. }
        | Action::ProfileModel { .. } => dispatch_model_evaluation(command, data_dir),
        Action::Qualify { .. } | Action::CompareModels { .. } | Action::Metrics { .. } => {
            dispatch_model_operations(command, data_dir)
        }
        Action::Configure { .. } | Action::Sync | Action::RotateApiToken => {
            dispatch_configuration(command, data_dir)
        }
        Action::Integrity
        | Action::Compact
        | Action::Diagnostics { .. }
        | Action::ShadowAutomatic { .. } => dispatch_database(command, data_dir),
        Action::Backup { .. }
        | Action::VerifyBackup { .. }
        | Action::RecoveryDrill { .. }
        | Action::RestoreBackup { .. } => dispatch_backup(command, data_dir),
        Action::ExportRecoveryKey { .. }
        | Action::VerifyRecoveryKey { .. }
        | Action::ImportRecoveryKey { .. } => dispatch_recovery_key(command, data_dir),
        Action::AuditAnchor { .. } | Action::VerifyAuditAnchor { .. } | Action::Doctor { .. } => {
            dispatch_audit(command, data_dir)
        }
    }
}

/// Route the runtime surface subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_runtime(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::Run => cmd_run(data_dir)?,
        Action::Tui { demo } => cmd_tui(demo, data_dir)?,
        Action::Web => cmd_web(data_dir)?,
        Action::Status | Action::Demo => cmd_status(&command, data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Route the build/policy inspection subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_info(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::BuildInfo => println!("{}", serde_json::to_string_pretty(&build_info::current())?),
        Action::ContractInfo => {
            println!("{}", serde_json::to_string_pretty(&contracts::current())?)
        }
        Action::PolicySchema => print!("{}", policy::schema_text()),
        Action::PolicyStatus => cmd_policy_status(data_dir)?,
        Action::ValidatePolicy { path } => cmd_validate_policy(path)?,
        Action::Autostart { action } => cmd_autostart(action, data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Route the model-evidence evaluation subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_model_evaluation(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::Evaluate { out } => cmd_evaluate(out, data_dir)?,
        Action::EvaluateDecision { model, out } => cmd_evaluate_decision(model, out, data_dir)?,
        Action::CompareDecisionModels { out } => cmd_compare_decision_models(out, data_dir)?,
        Action::ProfileModel { out } => cmd_profile_model(out, data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Route the model qualification/comparison subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_model_operations(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::Qualify { verifier } => cmd_qualify(verifier, data_dir)?,
        Action::CompareModels { out } => cmd_compare_models(out, data_dir)?,
        Action::Metrics { openmetrics } => cmd_metrics(openmetrics, data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Route the settings and credential subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_configuration(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::Configure {
            lookback_days,
            poll_hours,
            model,
            signature,
            api_enabled,
            api_port,
        } => cmd_configure(
            lookback_days,
            poll_hours,
            model,
            signature,
            api_enabled,
            api_port,
            data_dir,
        )?,
        Action::Sync => cmd_sync(data_dir)?,
        Action::RotateApiToken => cmd_rotate_api_token(data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Route the storage/maintenance subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_database(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::Integrity => cmd_integrity(data_dir)?,
        Action::Compact => cmd_compact(data_dir)?,
        Action::Diagnostics { out } => cmd_diagnostics(out, data_dir)?,
        Action::ShadowAutomatic { out } => cmd_shadow_automatic(out, data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Route the backup/restore subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_backup(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::Backup { out } => cmd_backup(out, data_dir)?,
        Action::VerifyBackup { path } => cmd_verify_backup(path, data_dir)?,
        Action::RecoveryDrill { path } => cmd_recovery_drill(path, data_dir)?,
        Action::RestoreBackup { path, confirm } => cmd_restore_backup(path, confirm, data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Route the recovery-key subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_recovery_key(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::ExportRecoveryKey {
            out,
            passphrase_file,
        } => cmd_export_recovery_key(out, passphrase_file, data_dir)?,
        Action::VerifyRecoveryKey {
            backup,
            recovery_key,
            passphrase_file,
        } => cmd_verify_recovery_key(backup, recovery_key, passphrase_file)?,
        Action::ImportRecoveryKey {
            backup,
            recovery_key,
            passphrase_file,
            confirm,
        } => cmd_import_recovery_key(backup, recovery_key, passphrase_file, confirm, data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Route the audit/doctor subcommands to their handlers.
///
/// Inputs: `command` — routed subcommand; `data_dir` — optional workspace
/// override. Output: `Result<()>` — the selected command's exit contract.
fn dispatch_audit(command: Action, data_dir: &Option<PathBuf>) -> Result<()> {
    match command {
        Action::AuditAnchor { out } => cmd_audit_anchor(out, data_dir)?,
        Action::VerifyAuditAnchor { path } => cmd_verify_audit_anchor(path, data_dir)?,
        Action::Doctor { require } => cmd_doctor(require, data_dir)?,
        other => dispatch(other, data_dir)?,
    }
    Ok(())
}

/// Execute the `rr run` scheduler daemon subcommand.
///
/// Inputs: `data_dir` — optional workspace override. Output: `Result<()>` —
/// unit on clean shutdown; propagated startup/worker failure.
fn cmd_run(data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let worker = Worker::spawn(dir, false);
    run_daemon(&worker, |handler| {
        ctrlc::set_handler(handler).map_err(Into::into)
    })?;
    Ok(())
}

/// Execute the `rr tui` subcommand.
///
/// Inputs: `demo` — synthetic offline mode; `data_dir` — optional workspace
/// override. Output: `Result<()>` — unit on exit; propagated terminal failure.
fn cmd_tui(demo: bool, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let worker = Worker::spawn(dir, demo);
    rejection_rejector::tui::run(worker)?;
    Ok(())
}

/// Execute the `rr web` loopback web-interface subcommand.
///
/// Inputs: `data_dir` — optional workspace override. Output: `Result<()>` —
/// unit on stop; propagated listener failure.
fn cmd_web(data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let worker = Worker::spawn(dir, false);
    web_serve(&worker, |handler| {
        ctrlc::set_handler(handler).map_err(Into::into)
    })?;
    Ok(())
}

/// Execute the `rr status` / `rr demo` reporting subcommands.
///
/// Inputs: `command` — routed subcommand (`Status` selects live, `Demo`
/// synthetic); `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the JSON status payload; propagated open/report failure.
fn cmd_status(command: &Action, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let demo = matches!(command, Action::Demo);
    let e = open_engine(dir, demo, false)?;
    let payload = serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"build":build_info::current(),"demo":demo,"connected":e.connected(),"mode":e.settings.mode,"sending_enabled":e.settings.sending_enabled,"poll_hours":e.settings.poll_hours,"lookback_days":e.settings.lookback_days,"model":e.settings.model,"counts":e.db.counts(&e.account)?,"enterprise_policy":e.enterprise_policy_status()});
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

/// Execute the `rr autostart` worker-registration subcommand.
///
/// Inputs: `action` — install/status/remove operation; `data_dir` — optional
/// workspace override. Output: `Result<()>` — prints the JSON report;
/// propagated scheduling failure.
fn cmd_autostart(action: AutostartAction, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let executable = std::env::current_exe().context("Cannot resolve rr.exe path")?;
    let report = autostart_report(&action, &executable, &dir, background::schtasks)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Execute the `rr validate-policy` subcommand.
///
/// Inputs: `path` — enterprise policy file. Output: `Result<()>` — prints the
/// policy status JSON; propagated parse/IO failure.
fn cmd_validate_policy(path: PathBuf) -> Result<()> {
    let absolute = std::fs::canonicalize(&path)?;
    let loaded = policy::load_file(&absolute)?;
    println!("{}", serde_json::to_string_pretty(&loaded.status())?);
    Ok(())
}

/// Execute the `rr policy-status` subcommand.
///
/// Inputs: `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the effective enterprise-policy status; propagated open failure.
fn cmd_policy_status(data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&e.enterprise_policy_status())?
    );
    Ok(())
}

/// Execute the `rr metrics` subcommand.
///
/// Inputs: `openmetrics` — emit OpenMetrics 1.0 text instead of JSON;
/// `data_dir` — optional workspace override. Output: `Result<()>` — prints the
/// metrics payload; propagated collection failure.
fn cmd_metrics(openmetrics: bool, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
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
    Ok(())
}

/// Execute the `rr doctor` readiness-report subcommand.
///
/// Inputs: `require` — optional readiness gate that must be satisfied;
/// `data_dir` — optional workspace override. Output: `Result<()>` — prints the
/// doctor JSON; fails when the requested gate is unsatisfied.
fn cmd_doctor(require: Option<ReadinessRequirement>, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
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
    Ok(())
}

/// Execute the `rr rotate-api-token` subcommand.
///
/// Inputs: `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the one-time plaintext token; propagated rotation failure.
fn cmd_rotate_api_token(data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
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
    Ok(())
}

// Model-evidence commands below need a reachable model runtime to
// take their success paths. Their positive paths are pinned by the
// model-command suites in tests/cli_workspace.rs, which must pin the
// workspace at a fake runtime through an in-process workspace open —
// only possible where an OS credential store exists (Windows). The
// headless lanes cover the fail-closed paths instead of fabricating
// evidence.
/// Execute the `rr evaluate` task-qualification subcommand.
///
/// Inputs: `out` — evaluation report path; `data_dir` — optional workspace
/// override. Output: `Result<()>` — writes and announces the report;
/// propagated evaluation failure.
fn cmd_evaluate(out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let mut e = open_engine(dir, false, true)?;
    announce(
        e.evaluate_model_to(&out),
        "Task-specific evaluation passed and qualification was stored:",
        &out,
    )?;
    Ok(())
}

/// Execute the `rr evaluate-decision` research subcommand.
///
/// Inputs: `model` — typed decision model tag; `out` — report path; `data_dir`
/// — optional workspace override. Output: `Result<()>` — writes the comparison;
/// propagated evaluation failure.
fn cmd_evaluate_decision(model: String, out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    evaluate_decision(&e.settings, &model, &out)?;
    Ok(())
}

/// Execute the `rr compare-decision-models` research subcommand.
///
/// Inputs: `out` — report path; `data_dir` — optional workspace override.
/// Output: `Result<()>` — writes the comparison; propagated failure.
fn cmd_compare_decision_models(out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    compare_decision_models(&e.settings, &out)?;
    Ok(())
}

/// Execute the `rr profile-model` runtime profiling subcommand.
///
/// Inputs: `out` — profile JSON path; `data_dir` — optional workspace override.
/// Output: `Result<()>` — writes and announces the profile; propagated failure.
fn cmd_profile_model(out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let mut e = open_engine(dir, false, true)?;
    announce(
        e.profile_model_runtime_to(&out),
        "Local model runtime profile written to",
        &out,
    )?;
    Ok(())
}

/// Execute the `rr qualify` smoke-qualification subcommand.
///
/// Inputs: `verifier` — also qualify the independent verifier model;
/// `data_dir` — optional workspace override. Output: `Result<()>` — prints the
/// qualification JSON; propagated qualification failure.
fn cmd_qualify(verifier: bool, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let mut e = open_engine(dir, false, true)?;
    e.qualify()?;
    if verifier {
        e.qualify_verifier()?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "qualified": true,
            "model": e.settings.model,
            "verifier_qualified": verifier,
        }))?
    );
    Ok(())
}

/// Execute the `rr configure` settings-update subcommand.
///
/// Inputs: the six optional field overrides (omitted fields keep their current
/// value); `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the effective settings JSON; propagated update failure.
fn cmd_configure(
    lookback_days: Option<u8>,
    poll_hours: Option<u8>,
    model: Option<String>,
    signature: Option<String>,
    api_enabled: Option<bool>,
    api_port: Option<u16>,
    data_dir: &Option<PathBuf>,
) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let mut e = open_engine(dir, false, true)?;
    let mut settings = e.settings.clone();
    if let Some(days) = lookback_days {
        settings.lookback_days = days;
    }
    if let Some(hours) = poll_hours {
        settings.poll_hours = hours;
    }
    if let Some(m) = model {
        settings.model = m;
    }
    if let Some(sig) = signature {
        settings.signature = sig;
    }
    if let Some(enabled) = api_enabled {
        settings.api_enabled = enabled;
    }
    if let Some(port) = api_port {
        settings.api_port = port;
    }
    e.update_settings(settings)?;
    println!("{}", serde_json::to_string_pretty(&e.settings)?);
    Ok(())
}

/// Execute the `rr sync` mailbox-synchronization subcommand.
///
/// Inputs: `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the new-identity count; propagated sync failure.
fn cmd_sync(data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let mut e = open_engine(dir, false, true)?;
    let inserted = e.synchronize()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "synchronized": true,
            "new_identities": inserted,
        }))?
    );
    Ok(())
}

/// Execute the `rr compare-models` bake-off subcommand.
///
/// Inputs: `out` — report path; `data_dir` — optional workspace override.
/// Output: `Result<()>` — writes the comparison; propagated failure.
fn cmd_compare_models(out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    compare_models(&e.settings, &out)?;
    Ok(())
}

/// Execute the `rr integrity` database-check subcommand.
///
/// Inputs: `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the integrity JSON; propagated check failure.
fn cmd_integrity(data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    e.db.integrity_check()?;
    let payload = serde_json::json!({
            "ok": true,
            "schema_version": e.db.schema_version()?,
            "note": "SQLite quick_check, foreign-key integrity and authenticated vault marker passed."
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

/// Execute the `rr compact` database-maintenance subcommand.
///
/// Inputs: `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the compaction report; propagated failure.
fn cmd_compact(data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let mut e = open_engine(dir, false, true)?;
    let report = e.compact_database()?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Execute the `rr backup` subcommand.
///
/// Inputs: `out` — backup destination directory; `data_dir` — optional
/// workspace override. Output: `Result<()>` — prints the backup manifest;
/// propagated backup failure.
fn cmd_backup(out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    let manifest = recovery::create_backup(&e.db, &e.directory, &out)?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

/// Execute the `rr verify-backup` subcommand.
///
/// Inputs: `path` — backup directory; `data_dir` — optional workspace override.
/// Output: `Result<()>` — prints the verification manifest; propagated failure.
fn cmd_verify_backup(path: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    let manifest = recovery::verify_backup(&e.db, &path)?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

/// Execute the `rr recovery-drill` subcommand.
///
/// Inputs: `path` — backup directory to drill against; `data_dir` — optional
/// workspace override. Output: `Result<()>` — logs and prints the drill
/// report; propagated restore/authentication failure.
fn cmd_recovery_drill(path: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
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
    Ok(())
}

/// Execute the `rr restore-backup` subcommand.
///
/// Inputs: `path` — backup directory; `confirm` — destructive-operation
/// acknowledgement (`RESTORE`); `data_dir` — optional workspace override.
/// Output: `Result<()>` — prints the restore report; propagated failure.
fn cmd_restore_backup(path: PathBuf, confirm: String, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    anyhow::ensure!(confirm == "RESTORE", "Restore requires --confirm RESTORE");
    let report = recovery::restore_backup(&dir, &path)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

/// Execute the `rr export-recovery-key` subcommand.
///
/// Inputs: `out` — wrapped-key destination; `passphrase_file` — passphrase
/// source; `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the envelope summary; propagated export failure.
fn cmd_export_recovery_key(
    out: PathBuf,
    passphrase_file: PathBuf,
    data_dir: &Option<PathBuf>,
) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
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
    Ok(())
}

/// Execute the `rr verify-recovery-key` subcommand.
///
/// Inputs: `backup` — backup directory; `recovery_key` — wrapped key envelope;
/// `passphrase_file` — passphrase source. Output: `Result<()>` — prints the
/// verification summary; propagated authentication failure.
fn cmd_verify_recovery_key(
    backup: PathBuf,
    recovery_key: PathBuf,
    passphrase_file: PathBuf,
) -> Result<()> {
    let passphrase = recovery_passphrase(&passphrase_file)?;
    let envelope = recovery::verify_recovery_key_for_backup(&backup, &recovery_key, &passphrase)?;
    let payload = serde_json::json!({
            "verified": true,
            "vault_id": envelope.vault_id,
            "format_version": envelope.format_version,
            "note": "Recovery key authenticated the backup; no OS credential was modified."
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

/// Execute the `rr import-recovery-key` subcommand.
///
/// Inputs: `backup` — backup directory; `recovery_key` — wrapped key envelope;
/// `passphrase_file` — passphrase source; `confirm` — acknowledgement
/// (`IMPORT`); `data_dir` — optional workspace override. Output: `Result<()>` —
/// prints the import summary; propagated failure.
fn cmd_import_recovery_key(
    backup: PathBuf,
    recovery_key: PathBuf,
    passphrase_file: PathBuf,
    confirm: String,
    data_dir: &Option<PathBuf>,
) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
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
    Ok(())
}

/// Execute the `rr diagnostics` subcommand.
///
/// Inputs: `out` — report destination; `data_dir` — optional workspace
/// override. Output: `Result<()>` — writes the redacted report; propagated
/// failure.
fn cmd_diagnostics(out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    rejection_rejector::diagnostics::write_report(&e, &out)?;
    println!(
        "Privacy-safe diagnostics written locally to {}. Review before sharing.",
        out.display()
    );
    Ok(())
}

/// Execute the `rr shadow-automatic` read-only audit subcommand.
///
/// Inputs: `out` — report destination; `data_dir` — optional workspace
/// override. Output: `Result<()>` — writes the shadow audit; propagated
/// failure.
fn cmd_shadow_automatic(out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    shadow::write_report(&e, &out)?;
    println!(
        "Read-only Automatic shadow audit written to {}. No provider preflight or external write occurred.",
        out.display()
    );
    Ok(())
}

/// Execute the `rr audit-anchor` export subcommand.
///
/// Inputs: `out` — anchor destination; `data_dir` — optional workspace
/// override. Output: `Result<()>` — prints the anchor; propagated failure.
fn cmd_audit_anchor(out: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    let anchor = audit_anchor::write_anchor(&e.db, &e.directory, &out)?;
    println!("{}", serde_json::to_string_pretty(&anchor)?);
    Ok(())
}

/// Execute the `rr verify-audit-anchor` subcommand.
///
/// Inputs: `path` — previously exported anchor; `data_dir` — optional
/// workspace override. Output: `Result<()>` — prints the verification
/// summary; propagated failure.
fn cmd_verify_audit_anchor(path: PathBuf, data_dir: &Option<PathBuf>) -> Result<()> {
    let dir = resolve_dir(data_dir)?;
    let e = open_engine(dir, false, true)?;
    let anchor = audit_anchor::verify_anchor(&e.db, &e.directory, &path)?;
    let payload = serde_json::json!({
            "verified": true,
            "anchor": anchor,
            "current_audit_head": e.db.audit_head()?,
            "current_audit_sequence": e.db.latest_event_seq()?
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
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
        // On unix the production gate refuses world-readable files before any
        // content checks, so test fixtures must be owner-private to exercise
        // the length/trim envelope itself (Windows has no POSIX mode gate).
        #[cfg(unix)]
        fn write_private(path: &std::path::Path, content: &[u8]) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(path, content).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(not(unix))]
        fn write_private(path: &std::path::Path, content: &[u8]) {
            std::fs::write(path, content).unwrap();
        }

        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        assert!(
            recovery_passphrase(&missing).is_err(),
            "missing files refused"
        );

        let short = root.path().join("short");
        write_private(&short, b"too short");
        assert!(
            recovery_passphrase(&short).is_err(),
            "short passphrases refused"
        );

        let oversized = root.path().join("oversized");
        write_private(&oversized, &vec![b'a'; 4097]);
        assert!(
            recovery_passphrase(&oversized).is_err(),
            "files above the 4 KiB limit refused"
        );

        let ok = root.path().join("ok");
        write_private(&ok, b"correct horse battery staple\r\n");
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

    /// Settings pinned to a closed loopback port.
    ///
    /// Why: a live Ollama may run on this machine; no test may depend on
    /// what is installed there (the same pin the model-command suite uses).
    fn offline_settings() -> config::Settings {
        config::Settings {
            ollama_url: "http://127.0.0.1:9".into(),
            signature: "Test Applicant".into(),
            ..Default::default()
        }
    }

    /// R&D decision evidence fails closed when the runtime is unreachable.
    ///
    /// Why: the evaluation helper must propagate the transport failure
    /// instead of writing an evidence report — a report written without a
    /// runtime would read like a model qualification to operator tooling.
    #[test]
    fn evaluate_decision_fails_closed_without_the_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("decision-evidence.json");
        evaluate_decision(&offline_settings(), "nimble:9b-q8_0", &out)
            .expect_err("an unreachable runtime cannot produce evidence");
        assert!(!out.exists(), "no evidence file is fabricated");
    }

    /// R&D model comparison degrades to per-candidate skips.
    ///
    /// Why: with no runtime reachable the comparison must still write its
    /// report with every candidate skipped and the recommendation empty —
    /// the "never authorizes, never invents a winner" note has to hold even
    /// for the empty case, and operator tooling consumes the report shape.
    #[test]
    fn compare_decision_models_reports_skips_and_never_invents_a_winner() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("decision-compare.json");
        compare_decision_models(&offline_settings(), &out).expect("skip-only comparison succeeds");
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(
            report.get("recommended_model"),
            Some(&serde_json::Value::Null)
        );
        let candidates = report
            .get("candidates")
            .and_then(serde_json::Value::as_array)
            .expect("candidates listed");
        assert!(!candidates.is_empty());
        assert!(
            candidates
                .iter()
                .all(|c| c.get("skipped") == Some(&serde_json::Value::Bool(true)))
        );
    }

    /// Task-specific model comparison degrades to skips the same way.
    ///
    /// Why: the "no runtime, no winner" contract must hold for the curated
    /// pipeline too: the report lands on disk with every candidate skipped
    /// and no eligible recommendation, never an invented winner.
    #[test]
    fn compare_models_reports_skips_and_no_eligible_recommendation() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("model-compare.json");
        compare_models(&offline_settings(), &out).expect("skip-only comparison succeeds");
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert!(
            report
                .pointer("/summary/recommendation_eligible")
                .and_then(serde_json::Value::as_bool)
                .is_none_or(|eligible| !eligible),
            "an unreachable runtime never recommends a model"
        );
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
        let error = wait_for_ready(
            &worker,
            std::time::Instant::now() + std::time::Duration::from_millis(150),
        )
        .err()
        .expect("an expired deadline refuses to wait");
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
        let error = web_serve(&worker, move |_| {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1200));
                let mut snapshot = shared.lock().unwrap();
                snapshot.fatal = true;
                snapshot.error = "workspace lost".into();
            });
            Ok(())
        })
        .expect_err("a fatal workspace must end web serving");
        assert!(error.to_string().contains("workspace lost"));
    }

    /// One live-workspace test fixture: holds the cross-test credential-store
    /// One live-workspace test fixture: holds the cross-test credential-store
    /// lock and deletes the workspace's OS vault credential on drop.
    ///
    /// Why: non-demo commands mint a Windows Credential Manager entry for the
    /// workspace key; without the shared file lock two test binaries race the
    /// credential store, and without the guard the store accumulates entries.
    struct Workspace {
        _lock: std::fs::File,
        temp: tempfile::TempDir,
    }

    impl Workspace {
        fn live() -> Self {
            let path = std::env::temp_dir().join("rr-test-credential-store.lock");
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&path)
                .expect("open credential-store test lock");
            fs2::FileExt::lock_exclusive(&lock).expect("credential-store test lock");
            Self {
                _lock: lock,
                temp: tempfile::tempdir().unwrap(),
            }
        }

        fn dir(&self) -> &std::path::Path {
            self.temp.path()
        }

        fn arg(&self) -> Option<PathBuf> {
            Some(self.temp.path().to_path_buf())
        }
    }

    impl Drop for Workspace {
        fn drop(&mut self) {
            #[cfg(windows)]
            if let Ok(id) = std::fs::read_to_string(self.temp.path().join("vault-id"))
                && let Ok(entry) = keyring::Entry::new("rejection-rejector.v1", id.trim())
            {
                let _ = entry.delete_credential();
            }
        }
    }

    /// The workspace override is honoured verbatim; without one the platform
    /// data directory is used.
    ///
    /// Why: `--data-dir` is what fleet tooling pins workspaces to — a silently
    /// substituted directory would run commands against the wrong workspace.
    #[test]
    fn resolve_dir_honours_the_explicit_override() {
        let explicit = PathBuf::from("some-workspace");
        assert_eq!(
            resolve_dir(&Some(explicit.clone())).unwrap(),
            explicit,
            "an explicit --data-dir is used verbatim"
        );
        assert_eq!(
            resolve_dir(&None).unwrap(),
            config::data_dir().unwrap(),
            "without an override the platform data directory is used"
        );
    }

    /// Misgrouped subcommands still reach their handlers through the dispatch
    /// fallbacks.
    ///
    /// Why: every dispatch group re-routes foreign commands through the
    /// central router; a broken fallback would turn a valid invocation into a
    /// silent no-op.
    #[test]
    fn misgrouped_subcommands_route_through_the_dispatch_fallbacks() {
        let workspace = Workspace::live();

        // Runtime group routes inspection commands on.
        dispatch_runtime(Action::BuildInfo, &None).expect("BuildInfo prints");

        // Info group routes demo reporting on.
        dispatch_info(Action::Demo, &workspace.arg()).expect("Demo prints");

        // Model-evaluation group routes metrics on.
        dispatch_model_evaluation(Action::Metrics { openmetrics: false }, &workspace.arg())
            .expect("metrics print");

        // Model-operations group routes integrity on.
        dispatch_model_operations(Action::Integrity, &workspace.arg()).expect("integrity passes");

        // Configuration group routes the shadow audit on.
        let shadow_out = workspace.dir().join("shadow.json");
        dispatch_configuration(
            Action::ShadowAutomatic {
                out: shadow_out.clone(),
            },
            &workspace.arg(),
        )
        .expect("shadow audit writes");
        assert!(shadow_out.is_file());

        // Database group routes settings updates on.
        dispatch_database(
            Action::Configure {
                lookback_days: Some(3),
                poll_hours: None,
                model: None,
                signature: None,
                api_enabled: None,
                api_port: None,
            },
            &workspace.arg(),
        )
        .expect("configure applies");

        // Backup group routes diagnostics on.
        let diagnostics_out = workspace.dir().join("diagnostics.json");
        dispatch_backup(
            Action::Diagnostics {
                out: diagnostics_out.clone(),
            },
            &workspace.arg(),
        )
        .expect("diagnostics write");
        assert!(diagnostics_out.is_file());

        // Recovery-key group routes compaction on.
        dispatch_recovery_key(Action::Compact, &workspace.arg()).expect("compaction passes");

        // Audit group routes backup creation on.
        let backup_dir = workspace.dir().join("fallback-backup");
        dispatch_audit(
            Action::Backup {
                out: backup_dir.clone(),
            },
            &workspace.arg(),
        )
        .expect("backup writes");
        assert!(backup_dir.is_dir());
    }

    /// Status reports for demo and live workspaces are produced without
    /// touching the mailbox.
    ///
    /// Why: `rr status` is the operator's health surface — it must work on a
    /// fresh, unconnected workspace instead of erroring.
    #[test]
    fn status_reports_demo_and_live_workspaces() {
        cmd_status(&Action::Demo, &None).expect("demo status prints");
        let workspace = Workspace::live();
        cmd_status(&Action::Status, &workspace.arg()).expect("live status prints");
    }

    /// Policy validation prints the parsed status for a real file and refuses
    /// missing paths with the file error.
    ///
    /// Why: operators validate policy files before deploying them; a missing
    /// file must fail loudly, never report a default-permitting status.
    #[test]
    fn validate_policy_reports_status_and_refuses_missing_files() {
        let workspace = Workspace::live();
        let path = workspace.dir().join("policy.json");
        std::fs::write(
            &path,
            br#"{"version":2,"policy_id":"corp.test","revision":1}"#,
        )
        .unwrap();
        cmd_validate_policy(path).expect("a valid policy file is summarized");

        let error = cmd_validate_policy(workspace.dir().join("missing.json"))
            .expect_err("missing policy files are refused");
        #[cfg(windows)]
        assert_eq!(
            error.to_string(),
            "The system cannot find the file specified. (os error 2)"
        );
        #[cfg(not(windows))]
        assert_eq!(error.to_string(), "No such file or directory (os error 2)");
    }

    /// Policy status, JSON/OpenMetrics metrics and the doctor report all
    /// print; `--require` fails closed with the exact unsatisfied gate.
    ///
    /// Why: readiness gates drive deployment automation — the failure text
    /// names the gate the operator must satisfy.
    #[test]
    fn status_metrics_and_doctor_reports_print_and_gate() {
        let workspace = Workspace::live();
        cmd_policy_status(&workspace.arg()).expect("policy status prints");
        cmd_metrics(false, &workspace.arg()).expect("JSON metrics print");
        cmd_metrics(true, &workspace.arg()).expect("OpenMetrics prints");
        cmd_doctor(None, &workspace.arg()).expect("the doctor report prints");

        let error = cmd_doctor(Some(ReadinessRequirement::Mailbox), &workspace.arg())
            .expect_err("an unsatisfied gate fails closed");
        assert_eq!(
            error.to_string(),
            "Requested readiness level Mailbox is not satisfied"
        );
    }

    /// The database, backup and drill commands round-trip on one workspace,
    /// and restore demands its exact confirmation token.
    ///
    /// Why: `rr restore-backup` replaces the live workspace — the confirmation
    /// token is the only thing standing between a mistyped command and data
    /// loss, so its refusal text is part of the safety contract.
    #[test]
    fn database_backup_and_drill_commands_round_trip() {
        let workspace = Workspace::live();
        cmd_integrity(&workspace.arg()).expect("integrity passes");
        cmd_compact(&workspace.arg()).expect("compaction passes");

        let backup_dir = workspace.dir().join("backup");
        cmd_backup(backup_dir.clone(), &workspace.arg()).expect("backup writes");
        assert!(backup_dir.is_dir());
        cmd_verify_backup(backup_dir.clone(), &workspace.arg()).expect("backup verifies");
        cmd_recovery_drill(backup_dir.clone(), &workspace.arg()).expect("drill passes");
        {
            // The drill success is audited in the workspace journal.
            let e = open_engine(workspace.arg().unwrap(), false, true).unwrap();
            let events = e.db.events(0, 500).unwrap();
            assert!(
                events.iter().any(|ev| ev.kind == "backup.drill_passed"),
                "the successful drill is audited"
            );
        }

        let error = cmd_restore_backup(backup_dir, "restore".into(), &workspace.arg())
            .expect_err("restore demands the exact token");
        assert_eq!(error.to_string(), "Restore requires --confirm RESTORE");
    }

    /// Diagnostics, the shadow audit and audit-anchor export/verify run
    /// read-only reports that land on disk.
    ///
    /// Why: these are the evidence surfaces an operator shares — they must be
    /// produced from a fresh workspace without a mailbox or model runtime.
    #[test]
    fn diagnostics_shadow_and_audit_anchor_reports_write() {
        let workspace = Workspace::live();

        let diagnostics_out = workspace.dir().join("diagnostics.json");
        cmd_diagnostics(diagnostics_out.clone(), &workspace.arg()).expect("diagnostics write");
        assert!(diagnostics_out.is_file());

        let shadow_out = workspace.dir().join("shadow.json");
        cmd_shadow_automatic(shadow_out.clone(), &workspace.arg()).expect("shadow audit writes");
        assert!(shadow_out.is_file());

        let anchor_out = workspace.dir().join("anchor.json");
        cmd_audit_anchor(anchor_out.clone(), &workspace.arg()).expect("anchor exports");
        assert!(anchor_out.is_file());
        cmd_verify_audit_anchor(anchor_out, &workspace.arg()).expect("anchor verifies");
    }

    /// Recovery-key commands enforce their confirmation tokens exactly.
    ///
    /// Why: `--confirm IMPORT` installs a key in the OS credential store —
    /// the token is the destructive-operation guard and its refusal text is
    /// pinned.
    #[test]
    fn recovery_key_import_demands_its_exact_confirmation_token() {
        let workspace = Workspace::live();
        let passphrase = workspace.dir().join("passphrase.txt");
        std::fs::write(&passphrase, b"correct horse battery staple").unwrap();

        let backup_dir = workspace.dir().join("key-backup");
        cmd_backup(backup_dir.clone(), &workspace.arg()).expect("backup writes");

        let envelope = workspace.dir().join("recovery.key");
        cmd_export_recovery_key(envelope.clone(), passphrase.clone(), &workspace.arg())
            .expect("the recovery key exports");
        assert!(envelope.is_file());
        cmd_verify_recovery_key(backup_dir.clone(), envelope.clone(), passphrase.clone())
            .expect("the recovery key authenticates the backup");

        let error = cmd_import_recovery_key(
            backup_dir,
            envelope,
            passphrase,
            "import".into(),
            &workspace.arg(),
        )
        .expect_err("import demands the exact token");
        assert_eq!(
            error.to_string(),
            "Recovery-key import requires --confirm IMPORT"
        );
    }

    /// Configure applies exactly the requested fields and refuses invalid
    /// values fail-closed without persisting them.
    ///
    /// Why: `rr configure` is scripted settings management — an out-of-range
    /// value must not overwrite a working configuration.
    #[test]
    fn configure_applies_requested_fields_and_refuses_invalid_values() {
        let workspace = Workspace::live();
        cmd_configure(
            Some(3),
            Some(2),
            None,
            Some("Test Applicant".to_string()),
            Some(true),
            Some(9_001),
            &workspace.arg(),
        )
        .expect("valid settings apply");
        {
            let e = open_engine(workspace.arg().unwrap(), false, true).unwrap();
            assert_eq!(e.settings.lookback_days, 3, "the lookback override applies");
            assert_eq!(e.settings.poll_hours, 2, "the poll override applies");
            assert_eq!(e.settings.signature, "Test Applicant");
            assert!(e.settings.api_enabled);
            assert_eq!(e.settings.api_port, 9_001);
        }

        let error = cmd_configure(Some(5), None, None, None, None, None, &workspace.arg())
            .expect_err("an out-of-window lookback is refused");
        assert_eq!(error.to_string(), "Lookback must be 1, 3, 7, 14 or 28 days");
        {
            let e = open_engine(workspace.arg().unwrap(), false, true).unwrap();
            assert_eq!(
                e.settings.lookback_days, 3,
                "the refused change left the previous value in place"
            );
        }
    }

    /// API token rotation succeeds repeatedly on one workspace.
    ///
    /// Why: rotation is the credential-recovery path — it must work on demand
    /// without a mailbox, and repeated rotation must keep the workspace
    /// consistent.
    #[test]
    fn rotate_api_token_rotates_the_local_api_credential() {
        let workspace = Workspace::live();
        cmd_rotate_api_token(&workspace.arg()).expect("first rotation prints a token");
        cmd_rotate_api_token(&workspace.arg()).expect("second rotation prints a token");
    }

    /// Model-evidence commands fail closed when the runtime is unreachable and
    /// never fabricate report files; comparison commands degrade to
    /// skip-only reports.
    ///
    /// Why: a report written without a runtime would read like a model
    /// qualification to operator tooling.
    #[test]
    fn model_commands_fail_closed_without_the_runtime() {
        let workspace = Workspace::live();
        {
            // Pin the workspace at a closed loopback port so no live Ollama
            // on this machine can satisfy the commands.
            let mut e = open_engine(workspace.arg().unwrap(), false, true).unwrap();
            e.settings.ollama_url = "http://127.0.0.1:9".into();
            e.db.set_meta("settings", &e.settings).unwrap();
        }

        let evaluate_out = workspace.dir().join("evaluate.json");
        cmd_evaluate(evaluate_out.clone(), &workspace.arg())
            .expect_err("evaluation needs a reachable runtime");
        assert!(!evaluate_out.exists(), "no evidence file is fabricated");

        let decision_out = workspace.dir().join("decision.json");
        cmd_evaluate_decision(
            "nimble:9b-q8_0".into(),
            decision_out.clone(),
            &workspace.arg(),
        )
        .expect_err("decision evidence needs a reachable runtime");
        assert!(!decision_out.exists(), "no evidence file is fabricated");

        let profile_out = workspace.dir().join("profile.json");
        cmd_profile_model(profile_out.clone(), &workspace.arg())
            .expect_err("profiling needs a reachable runtime");
        assert!(!profile_out.exists(), "no profile file is fabricated");

        cmd_qualify(false, &workspace.arg()).expect_err("qualification needs a reachable runtime");

        // Comparisons degrade to skip-only reports instead of inventing
        // winners.
        let compare_decision_out = workspace.dir().join("compare-decision.json");
        cmd_compare_decision_models(compare_decision_out.clone(), &workspace.arg())
            .expect("skip-only comparison succeeds");
        assert!(compare_decision_out.is_file());

        let compare_out = workspace.dir().join("compare.json");
        cmd_compare_models(compare_out.clone(), &workspace.arg())
            .expect("skip-only comparison succeeds");
        assert!(compare_out.is_file());

        // Synchronize without a connected mailbox fails closed.
        cmd_sync(&workspace.arg()).expect_err("sync needs a connected mailbox");
    }
}
