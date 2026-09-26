use anyhow::Result;
use clap::{Parser, Subcommand};
use rejection_rejector::{config, engine::Engine, worker::Worker};
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
    /// Evaluate the configured local model on bundled synthetic fixtures (never sends email).
    Evaluate {
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
            println!("Evaluation written to {}", out.display());
        }
    }
    Ok(())
}
