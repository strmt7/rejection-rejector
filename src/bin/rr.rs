use anyhow::Result;
use clap::{Parser, Subcommand};
use rejection_rejector::{config, engine::Engine, ollama::Ollama, worker::Worker};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
#[derive(Parser)]
#[command(version, about = "Rejection Rejector headless tools")]
struct Args {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Run the scheduler using settings previously configured in the desktop application.
    Run,
    /// Print local settings and aggregate status, without message bodies or credentials.
    Status,
    /// Print a synthetic offline status; never connects to Gmail.
    Demo,
    /// Print a non-sensitive local readiness report for Gmail, Ollama and the pinned model.
    Doctor,
    /// Evaluate the configured local model on the full synthetic recruiting pipeline.
    Evaluate {
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare already-installed curated local models on the task-specific pipeline.
    CompareModels {
        #[arg(long)]
        out: PathBuf,
    },
}
fn main() -> Result<()> {
    let args = Args::parse();
    let dir = args.data_dir.unwrap_or(config::data_dir()?);
    match args.command {
        Action::Run => {
            let worker = Worker::spawn(dir, false);
            let stop = worker.stop.clone();
            let paused = worker.paused.clone();
            ctrlc::set_handler(move || {
                paused.store(true, Ordering::SeqCst);
                stop.store(true, Ordering::SeqCst);
            })?;
            println!("Rejection Rejector worker running. Ctrl+C pauses dispatch and exits. Close the GUI before running this command.");
            while !worker.stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(1));
                let s = worker.view();
                if s.fatal {
                    anyhow::bail!("{}", s.error);
                }
            }
        }
        Action::Doctor => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
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
                    &serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"demo":demo,"connected":e.connected(),"mode":e.settings.mode,"sending_enabled":e.settings.sending_enabled,"poll_hours":e.settings.poll_hours,"lookback_days":e.settings.lookback_days,"model":e.settings.model,"counts":e.db.counts(&e.account)?})
                )?
            );
        }
        Action::Evaluate { out } => {
            let e = Engine::open(
                dir,
                false,
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(false)),
            )?;
            rejection_rejector::evaluation::run(&e.settings, &out)?;
            println!("Task-specific evaluation written to {}", out.display());
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
    }
    Ok(())
}
