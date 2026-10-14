//! `rr-train-monitor`: minimal always-minimized training monitor with a
//! live GPU utilization ceiling slider.
//!
//! Contract (this window must NEVER affect other applications):
//! - starts MINIMIZED and inactive (no popup, no focus steal),
//! - never sends focus/foreground/topmost commands,
//! - the only side effect outside its own window is an atomic write of the
//!   trainer's `duty.json` control file (pacing only: no driver, fan,
//!   clock or power interaction of any kind).
//!
//! Inputs: `--progress <path>` (the trainer's `progress.json`; the
//! `duty.json` control file is its sibling). Output: none (GUI process);
//! exits 0 on window close.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;

use rejection_rejector::train_monitor::{
    MIN_TARGET_PCT, ProgressSnapshot, SLIDER_MAX_PCT, STALE_AFTER_SECONDS, duty_path_for, now_unix,
    pacing_sleep_seconds, parse_progress, read_duty, write_duty,
};

/// Poll interval for the heartbeat and control files.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The monitor application state.
struct MonitorApp {
    progress_path: PathBuf,
    duty_path: PathBuf,
    snapshot: Option<ProgressSnapshot>,
    duty_target: f64,
    last_write: Option<f64>,
    last_poll: Instant,
    file_error: Option<String>,
    user_touched: bool,
}

impl MonitorApp {
    /// Create the app state.
    ///
    /// Input: path to the trainer's `progress.json`.
    /// Output: app state with the duty target seeded from the control
    /// file (100% = uncapped when absent).
    fn new(progress_path: PathBuf) -> Self {
        let duty_path = duty_path_for(&progress_path);
        // Fail-closed: no control file yet -> the operator ceiling, never
        // uncapped.
        let duty_target = read_duty(&duty_path).unwrap_or(SLIDER_MAX_PCT);
        Self {
            progress_path,
            duty_path,
            snapshot: None,
            duty_target,
            last_write: None,
            last_poll: Instant::now()
                .checked_sub(POLL_INTERVAL)
                .unwrap_or_else(Instant::now),
            file_error: None,
            user_touched: false,
        }
    }

    /// Re-read both files (throttled by the logic tick).
    fn poll(&mut self) {
        self.file_error = None;
        match std::fs::read_to_string(&self.progress_path) {
            Ok(raw) => self.snapshot = parse_progress(&raw),
            Err(_) => self.snapshot = None,
        }
        if let Some(pct) = read_duty(&self.duty_path) {
            self.duty_target = pct;
        }
    }
}

impl eframe::App for MonitorApp {
    /// Background tick: runs even while the window is hidden/minimised,
    /// so polling and the startup minimize never depend on repainting.
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Start MINIMIZED: no popup, no focus steal (the window is also
        // created with with_active(false) in main). The minimize is
        // re-sent every tick until the user interacts with the window:
        // window creation can race the first minimize (late presentation
        // on cold GPU-backend init) and the tracked "minimized" state in
        // both egui-winit and winit is updated OPTIMISTICALLY and must
        // not be trusted (egui-winit 0.36.2: `info.minimized = Some(v)`
        // regardless of the OS result). Enforcement ends on the first
        // USER INPUT (pointer/key/touch) so a deliberate restore by the
        // user is never fought.
        let touched = ctx.input(|i| {
            i.events.iter().any(|e| {
                matches!(
                    e,
                    egui::Event::PointerMoved { .. }
                        | egui::Event::PointerButton { .. }
                        | egui::Event::Key { .. }
                        | egui::Event::Touch { .. }
                )
            })
        });
        if touched {
            self.user_touched = true;
        }
        if !self.user_touched
            && let Some(win) = frame.winit_window()
        {
            win.set_minimized(true);
        }
        if self.last_poll.elapsed() >= POLL_INTERVAL {
            self.last_poll = Instant::now();
            self.poll();
        }
        ctx.request_repaint_after(POLL_INTERVAL);
    }

    /// Render one frame. Input: the window ui. Output: none.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("Rejection Rejector — training monitor");
            ui.add_space(4.0);

            match &self.snapshot {
                Some(snap) => {
                    ui.add(
                        egui::ProgressBar::new(snap.fraction())
                            .text(format!("{}/{} steps", snap.step, snap.total_steps)),
                    );
                    ui.add_space(4.0);
                    let loss_s = snap
                        .loss
                        .map(|l| format!("{l:.4}"))
                        .unwrap_or_else(|| "—".to_owned());
                    let rate = if snap.elapsed_seconds > 0.0 && snap.step > 0 {
                        format!(
                            "{:.1} steps/min",
                            snap.step as f64 / (snap.elapsed_seconds / 60.0)
                        )
                    } else {
                        "—".to_owned()
                    };
                    let eta = snap
                        .eta_minutes()
                        .map(|m| format!("{m:.0} min"))
                        .unwrap_or_else(|| "—".to_owned());
                    ui.label(format!("loss: {loss_s}    {rate}    ETA: {eta}"));
                    ui.label(format!("status: {}", snap.status));

                    let stale = snap.staleness(now_unix());
                    if stale > STALE_AFTER_SECONDS {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 80, 60),
                            format!("WARNING: heartbeat stale {stale:.0}s"),
                        );
                    }

                    // Live ceiling: the write below is the ONLY side
                    // effect of this application. The slider is capped at
                    // SLIDER_MAX_PCT (operator ceiling).
                    ui.add_space(6.0);
                    let slider = ui.add(
                        egui::Slider::new(&mut self.duty_target, MIN_TARGET_PCT..=SLIDER_MAX_PCT)
                            .text("GPU utilization ceiling %"),
                    );
                    if slider.changed() {
                        match write_duty(&self.duty_path, self.duty_target) {
                            Ok(()) => {
                                self.last_write = Some(self.duty_target);
                                self.file_error = None;
                            }
                            Err(e) => self.file_error = Some(format!("duty write failed: {e}")),
                        }
                    }
                    let applied = self
                        .last_write
                        .map(|p| format!("applied: {p:.0} %"))
                        .unwrap_or_else(|| format!("{} % (default)", SLIDER_MAX_PCT));
                    ui.label(format!(
                        "{applied} — applies within one step; pacing only, no hardware interaction"
                    ));

                    // Reference math so the operator can sanity-check the
                    // trade-off: off = on * (100 - t) / t.
                    if snap.step > 0 && snap.elapsed_seconds > 0.0 {
                        let on = snap.elapsed_seconds / snap.step as f64;
                        let off = pacing_sleep_seconds(on, self.duty_target);
                        ui.label(format!(
                            "pacing: {on:.1} s compute + {off:.1} s sleep per step"
                        ));
                    }
                }
                None => {
                    ui.label("waiting for trainer heartbeat…");
                }
            }

            if let Some(err) = &self.file_error {
                ui.colored_label(egui::Color32::from_rgb(220, 80, 60), err);
            }
        });
    }
}

/// Entry point.
///
/// Input: CLI arg `--progress <path>` (optional; default
/// `training-runs/mimo-9b-lora-v2data/progress.json`).
/// Output: process exit code (0 on clean close). The window is created
/// MINIMIZED and inactive: it never pops up and never steals focus.
fn main() -> eframe::Result {
    let mut progress = PathBuf::from("training-runs/mimo-9b-lora-v2data/progress.json");
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--progress" && i + 1 < args.len() {
            progress = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            i += 1;
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RR training monitor")
            .with_inner_size([420.0, 260.0])
            .with_min_inner_size([360.0, 220.0])
            .with_resizable(true)
            .with_active(false),
        ..Default::default()
    };
    eframe::run_native(
        "RR training monitor",
        options,
        Box::new(|_cc| Ok(Box::new(MonitorApp::new(progress)))),
    )
}
