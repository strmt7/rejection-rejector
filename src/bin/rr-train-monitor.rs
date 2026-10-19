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
    /// Inputs: path to the trainer's `progress.json`.
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
    ///
    /// Inputs: none (`&mut self`). Output: none — the progress snapshot and duty
    /// target are refreshed and any file error recorded.
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
    ///
    /// Inputs: `ctx` — egui context whose input events are inspected; `frame` — the
    /// enclosing frame. Output: none.
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
        // Not reachable in the headless lanes: `winit_window()` is `None`
        // without a real window (kittest frames carry none), so the
        // minimize call below is exercised only by the one manual GUI
        // smoke, never by automated runs (a live window steals focus).
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

    /// Render one frame.
    ///
    /// Inputs: `ui` — the window ui; `_frame` — the enclosing frame (unused).
    /// Output: none.
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

/// Default heartbeat path when `--progress` is not given.
const DEFAULT_PROGRESS: &str = "training-runs/mimo-9b-lora-v2data/progress.json";

/// Parse the monitor command line.
///
/// Inputs: full argv (program name at index 0). Output: the heartbeat path
/// to watch — `--progress <path>` wins (last occurrence), unknown tokens
/// are ignored, and a dangling `--progress` keeps the previously parsed
/// value instead of swallowing the next flag or crashing.
fn parse_progress_arg(args: &[String]) -> PathBuf {
    let mut progress = PathBuf::from(DEFAULT_PROGRESS);
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--progress" && i + 1 < args.len() {
            progress = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            i += 1;
        }
    }
    progress
}

/// The native window options.
///
/// Inputs: none. Output: [`eframe::NativeOptions`] for the monitor window:
/// the viewport is created with `with_active(false)` so it never becomes
/// the foreground window or steals focus from other applications.
fn monitor_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RR training monitor")
            .with_inner_size([420.0, 260.0])
            .with_min_inner_size([360.0, 220.0])
            .with_resizable(true)
            .with_active(false),
        ..Default::default()
    }
}

/// Entry point.
///
/// Inputs: CLI arg `--progress <path>` (optional; default
/// `training-runs/mimo-9b-lora-v2data/progress.json`).
/// Output: process exit code (0 on clean close). The window is created
/// MINIMIZED and inactive: it never pops up and never steals focus.
///
/// The `eframe::run_native` call is window-system code with no headless
/// path (the coverage lane has no display), so every decision `main`
/// composes is pinned through `parse_progress_arg`, `monitor_options` and
/// the headless app tests below; only the window creation itself is
/// exercised outside the test harness (one manual GUI smoke).
fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let progress = parse_progress_arg(&args);
    eframe::run_native(
        "RR training monitor",
        monitor_options(),
        Box::new(|_cc| Ok(Box::new(MonitorApp::new(progress)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::App as _;
    use eframe::egui::accesskit;

    /// Isolated fixture directory: the monitor must only ever touch files
    /// the caller named, so fixtures live in a temp dir, never the CWD.
    fn run_dir(name: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(name)
            .tempdir()
            .expect("fixture dir")
    }

    fn heartbeat_json(
        step: u64,
        total: u64,
        loss: Option<f64>,
        elapsed: f64,
        updated: f64,
    ) -> String {
        let loss = loss
            .map(|l| l.to_string())
            .unwrap_or_else(|| "null".to_owned());
        format!(
            r#"{{"step":{step},"total_steps":{total},"loss":{loss},"status":"running","elapsed_seconds":{elapsed},"updated_at_unix":{updated}}}"#
        )
    }

    /// Render real monitor frames headlessly through the same `logic` +
    /// `ui` entry the eframe runtime drives, and return the resulting
    /// AccessKit widget tree (the rendered text and widget bounds).
    ///
    /// Mirrors the gui.rs harness: egui emits an empty widget tree on the
    /// first pass after a state change, so each call runs the scripted
    /// pass and then one silent warm pass whose tree is complete.
    fn run_frame(
        app: &mut MonitorApp,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
    ) -> Vec<(accesskit::NodeId, accesskit::Node)> {
        // Widget trees are only generated when the integration asks for
        // them; the real eframe integration always does.
        ctx.enable_accesskit();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(420.0, 260.0));
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(screen),
                events,
                ..Default::default()
            },
            |root_ui| {
                let mut frame = eframe::Frame::_new_kittest();
                app.logic(root_ui.ctx(), &mut frame);
                app.ui(root_ui, &mut frame);
            },
        );
        out.textures_delta.clear();
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            },
            |root_ui| {
                let mut frame = eframe::Frame::_new_kittest();
                app.logic(root_ui.ctx(), &mut frame);
                app.ui(root_ui, &mut frame);
            },
        );
        out.textures_delta.clear();
        out.platform_output
            .accesskit_update
            .map(|update| update.nodes)
            .unwrap_or_default()
    }

    /// Render only the view (no background tick): for pinning frames the
    /// tick would tear down before the composition runs (e.g. a write
    /// error stays visible until the next poll clears it).
    fn view_frame(
        app: &mut MonitorApp,
        ctx: &egui::Context,
    ) -> Vec<(accesskit::NodeId, accesskit::Node)> {
        ctx.enable_accesskit();
        let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(420.0, 260.0));
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            },
            |root_ui| {
                let mut frame = eframe::Frame::_new_kittest();
                app.ui(root_ui, &mut frame);
            },
        );
        out.textures_delta.clear();
        let mut out = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(screen),
                ..Default::default()
            },
            |root_ui| {
                let mut frame = eframe::Frame::_new_kittest();
                app.ui(root_ui, &mut frame);
            },
        );
        out.textures_delta.clear();
        out.platform_output
            .accesskit_update
            .map(|update| update.nodes)
            .unwrap_or_default()
    }

    /// Every piece of visible text in a rendered frame.
    fn text_blob(tree: &[(accesskit::NodeId, accesskit::Node)]) -> String {
        tree.iter()
            .filter_map(|(_, node)| node.label().or_else(|| node.value()).map(str::to_owned))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Build the app against a fixture heartbeat and control file.
    fn fixture_app(dir: &std::path::Path, heartbeat: &str, duty: Option<&str>) -> MonitorApp {
        let progress = dir.join("progress.json");
        std::fs::write(&progress, heartbeat).expect("write heartbeat");
        if let Some(raw) = duty {
            std::fs::write(dir.join("duty.json"), raw).expect("write duty");
        }
        MonitorApp::new(progress)
    }

    // Why: startup must fail closed to the operator ceiling when no
    // control file exists (never silently run uncapped), honor a valid
    // control file when present, and locate duty.json next to the given
    // --progress path — the binary must never probe its CWD.
    #[test]
    fn startup_seeds_the_control_file_or_fails_closed_to_the_ceiling() {
        let dir = run_dir("rr_monitor_startup");
        let dir = dir.path();
        let mut app = fixture_app(dir, &heartbeat_json(1, 2, None, 0.0, 0.0), None);
        assert_eq!(app.duty_target, SLIDER_MAX_PCT);
        assert_eq!(app.duty_path, dir.join("duty.json"));
        assert!(!app.user_touched);

        app = fixture_app(
            dir,
            &heartbeat_json(1, 2, None, 0.0, 0.0),
            Some(r#"{"target_pct":35.0}"#),
        );
        assert_eq!(app.duty_target, 35.0);

        // A corrupt control file is treated like a missing one.
        std::fs::write(dir.join("duty.json"), "garbage").expect("corrupt duty");
        app = fixture_app(dir, &heartbeat_json(1, 2, None, 0.0, 0.0), None);
        assert_eq!(app.duty_target, SLIDER_MAX_PCT);
    }

    // Why: polling is the only place the app re-reads trainer state; it
    // must fail closed on a missing/corrupt heartbeat ("waiting for
    // trainer heartbeat…" rather than invented numbers) while keeping the
    // last duty target when the control file disappears or corrupts.
    #[test]
    fn poll_reflects_heartbeat_and_keeps_last_duty_across_gaps() {
        let dir = run_dir("rr_monitor_poll");
        let dir = dir.path();
        let mut app = fixture_app(
            dir,
            &heartbeat_json(5, 10, Some(0.25), 60.0, 1_700_000_000.0),
            Some(r#"{"target_pct":35.0}"#),
        );
        app.poll();
        let snap = app.snapshot.as_ref().expect("heartbeat parsed");
        assert_eq!((snap.step, snap.total_steps), (5, 10));
        assert_eq!(app.duty_target, 35.0);

        // Trainer exits: the heartbeat file disappears -> "no data".
        std::fs::remove_file(dir.join("progress.json")).expect("remove heartbeat");
        app.poll();
        assert!(app.snapshot.is_none());
        assert_eq!(app.duty_target, 35.0);

        // Control file corrupts -> keep the last valid target (the trainer
        // must never be throttled by a half-written read).
        std::fs::write(dir.join("duty.json"), "not json").expect("corrupt duty");
        app.poll();
        assert_eq!(app.duty_target, 35.0);
    }

    // Why: the minimize enforcement must end on the first real user input
    // (pointer/key/touch) so a deliberate restore is never fought, but
    // scroll/zoom traffic alone must NOT end it (it would let a stray
    // wheel event pop the window back up over other applications).
    #[test]
    fn minimize_enforcement_ends_only_on_pointer_key_or_touch() {
        let dir = run_dir("rr_monitor_input");
        let dir = dir.path();
        let mut app = fixture_app(dir, &heartbeat_json(1, 2, None, 0.0, 0.0), None);
        let ctx = egui::Context::default();

        run_frame(&mut app, &ctx, vec![egui::Event::Zoom(1.5)]);
        assert!(!app.user_touched, "zoom/scroll must not end enforcement");

        run_frame(
            &mut app,
            &ctx,
            vec![egui::Event::PointerMoved(egui::pos2(4.0, 4.0))],
        );
        assert!(app.user_touched, "a pointer move ends enforcement");
    }

    // Why: the background tick runs even while the window is hidden, and
    // re-polling at the 1s interval is what keeps the ceiling live; the
    // throttle must skip work between intervals and actually re-read both
    // files when the interval has elapsed.
    #[test]
    fn logic_tick_polls_on_the_interval_and_throttles_between() {
        let dir = run_dir("rr_monitor_tick");
        let dir = dir.path();
        let mut app = fixture_app(
            dir,
            &heartbeat_json(5, 10, Some(0.5), 60.0, 1_700_000_000.0),
            Some(r#"{"target_pct":35.0}"#),
        );
        let ctx = egui::Context::default();

        // Construction seeds back-dated last_poll, so the first frame polls.
        run_frame(&mut app, &ctx, Vec::new());
        assert_eq!(app.duty_target, 35.0);

        // Within the interval: no re-read, the trainer-side change waits.
        std::fs::write(dir.join("duty.json"), r#"{"target_pct":40.0}"#).expect("write duty");
        let tick = app.last_poll;
        run_frame(&mut app, &ctx, Vec::new());
        assert_eq!(app.last_poll, tick, "throttled frame must not re-poll");
        assert_eq!(app.duty_target, 35.0);

        // Once the interval has elapsed the new ceiling is picked up.
        app.last_poll = tick
            .checked_sub(POLL_INTERVAL * 2)
            .expect("instant before tick");
        run_frame(&mut app, &ctx, Vec::new());
        assert_eq!(app.duty_target, 40.0);
    }

    // Why: the live ceiling slider is the app's ONLY side effect — an
    // operator change must land in duty.json atomically and be reported,
    // a request above the operator cap must never reach the file (the
    // slider is bounded by SLIDER_MAX_PCT), and a failing write must be
    // surfaced instead of silently dropped.
    #[test]
    fn slider_change_writes_duty_atomically_and_surfaces_write_failures() {
        let dir = run_dir("rr_monitor_slider");
        let dir = dir.path();
        let mut app = fixture_app(
            dir,
            &heartbeat_json(5, 10, Some(0.5), 60.0, 1_700_000_000.0),
            None,
        );
        let ctx = egui::Context::default();

        let tree = run_frame(&mut app, &ctx, Vec::new());
        let slider = tree
            .iter()
            .find(|(_, node)| node.role() == accesskit::Role::Slider)
            .expect("ceiling slider rendered");
        let slider_id = slider.0;
        // The composed slider must be bounded by the documented contract.
        assert_eq!(slider.1.min_numeric_value(), Some(MIN_TARGET_PCT));
        assert_eq!(slider.1.max_numeric_value(), Some(SLIDER_MAX_PCT));

        let set_value = |pct: f64| {
            egui::Event::AccessKitActionRequest(accesskit::ActionRequest {
                action: accesskit::Action::SetValue,
                target_tree: accesskit::TreeId::ROOT,
                target_node: slider_id,
                data: Some(accesskit::ActionData::NumericValue(pct)),
            })
        };

        // Above the cap: the widget clamps, nothing is applied or written.
        run_frame(&mut app, &ctx, vec![set_value(85.0)]);
        assert_eq!(app.last_write, None);
        assert!(!dir.join("duty.json").exists());
        assert_eq!(app.duty_target, SLIDER_MAX_PCT);

        // In range: the ceiling lands in the control file and is reported.
        let tree = run_frame(&mut app, &ctx, vec![set_value(35.0)]);
        assert_eq!(app.duty_target, 35.0);
        assert_eq!(app.last_write, Some(35.0));
        assert_eq!(read_duty(&app.duty_path), Some(35.0));
        assert!(text_blob(&tree).contains("applied: 35 %"));
        assert!(
            !dir.join("duty.json.tmp").exists(),
            "atomic write leaves no tmp"
        );

        // Write failure (path inside a nonexistent directory): the error
        // must be shown, and the previous applied value must stay truthful.
        app.duty_path = dir.join("missing-dir").join("duty.json");
        let tree = run_frame(&mut app, &ctx, vec![set_value(40.0)]);
        let text = text_blob(&tree);
        assert!(text.contains("duty write failed:"), "got: {text}");
    }

    // Why: with no heartbeat yet the window must say so (no invented
    // numbers), and a write error from the previous frame must remain
    // visible until a write succeeds.
    #[test]
    fn waiting_view_shows_no_data_and_keeps_the_file_error_visible() {
        let dir = run_dir("rr_monitor_waiting");
        let dir = dir.path();
        let mut app = fixture_app(dir, &heartbeat_json(1, 2, None, 0.0, 0.0), None);
        std::fs::remove_file(dir.join("progress.json")).expect("remove heartbeat");
        app.poll();
        let ctx = egui::Context::default();

        app.file_error = Some("duty write failed: boom".to_owned());
        // View-only frame: the next background tick would clear the error
        // (poll resets it), so pin the composed state the operator can
        // actually see between the failed write and the next poll.
        let tree = view_frame(&mut app, &ctx);
        let text = text_blob(&tree);
        assert!(
            text.contains("waiting for trainer heartbeat…"),
            "got: {text}"
        );
        assert!(text.contains("duty write failed: boom"), "got: {text}");
    }

    // Why: the snapshot view is the operator's only instrument — every
    // derived line (loss/rate/ETA/status, the stale warning and the
    // pacing trade-off) must render the composed numbers from the
    // fixture, and the "--" placeholders must appear exactly when the
    // underlying rate cannot be computed (no steps, no elapsed time).
    #[test]
    fn snapshot_view_renders_composed_numbers_and_stale_warning() {
        let dir = run_dir("rr_monitor_snapshot");
        let dir = dir.path();
        // Fresh heartbeat with a computable rate and ETA.
        let mut app = fixture_app(
            dir,
            &heartbeat_json(5, 10, Some(0.5), 120.0, now_unix()),
            None,
        );
        app.poll();
        let ctx = egui::Context::default();
        let tree = run_frame(&mut app, &ctx, Vec::new());
        let text = text_blob(&tree);
        assert!(text.contains("5/10 steps"), "got: {text}");
        assert!(text.contains("loss: 0.5000"), "got: {text}");
        assert!(text.contains("2.5 steps/min"), "got: {text}");
        assert!(text.contains("ETA: 2 min"), "got: {text}");
        assert!(text.contains("status: running"), "got: {text}");
        assert!(!text.contains("WARNING"), "fresh heartbeat is not stale");
        // 120 s compute over 5 steps -> 24.0 s/step; at the seeded 50 %
        // ceiling the duty formula sleeps the same 24.0 s.
        assert!(
            text.contains("pacing: 24.0 s compute + 24.0 s sleep per step"),
            "got: {text}"
        );
        assert!(
            text.contains("50 % (default)"),
            "no write applied yet: {text}"
        );

        // No loss and no elapsed time: the derived lines are placeholders.
        let mut app = fixture_app(dir, &heartbeat_json(0, 10, None, 0.0, now_unix()), None);
        app.poll();
        let tree = run_frame(&mut app, &ctx, Vec::new());
        let text = text_blob(&tree);
        assert!(text.contains("loss: —"), "got: {text}");
        assert!(text.contains("ETA: —"), "got: {text}");

        // A stale heartbeat must carry the stall warning with its age.
        let mut app = fixture_app(
            dir,
            &heartbeat_json(5, 10, Some(0.5), 120.0, now_unix() - 500.0),
            None,
        );
        app.poll();
        let tree = run_frame(&mut app, &ctx, Vec::new());
        let text = text_blob(&tree);
        assert!(text.contains("WARNING: heartbeat stale 5"), "got: {text}");
    }

    // Why: argument handling must not depend on how the trainer spawns
    // the monitor — the default path is fixed, `--progress` overrides it,
    // unknown flags are skipped, and a dangling `--progress` can neither
    // swallow the next flag nor crash the process.
    #[test]
    fn progress_arg_defaults_overrides_and_never_takes_a_flag_as_path() {
        let s = |items: &[&str]| -> Vec<String> {
            std::iter::once("rr-train-monitor")
                .chain(items.iter().copied())
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(parse_progress_arg(&s(&[])), PathBuf::from(DEFAULT_PROGRESS));
        assert_eq!(
            parse_progress_arg(&s(&["--progress", "run/progress.json"])),
            PathBuf::from("run/progress.json")
        );
        // Last occurrence wins.
        assert_eq!(
            parse_progress_arg(&s(&["--progress", "a.json", "--progress", "b.json"])),
            PathBuf::from("b.json")
        );
        // Unknown tokens (including --progressX) are ignored, and a
        // dangling --progress keeps the previously parsed path.
        assert_eq!(
            parse_progress_arg(&s(&["--verbose", "--progressX", "x.json", "--progress"])),
            PathBuf::from(DEFAULT_PROGRESS)
        );
        assert_eq!(
            parse_progress_arg(&s(&["--progress", "a.json", "--progress"])),
            PathBuf::from("a.json")
        );
    }

    // Why: the window contract ("starts minimized and inactive, never
    // steals focus") is enforced by the composed viewport options; if a
    // builder call is dropped the monitor pops up over other applications.
    #[test]
    fn window_options_are_inactive_and_bounded() {
        let options = monitor_options();
        assert_eq!(
            options.viewport.title.as_deref(),
            Some("RR training monitor")
        );
        assert_eq!(options.viewport.active, Some(false), "must start inactive");
        assert_eq!(options.viewport.inner_size, Some(egui::vec2(420.0, 260.0)));
        assert_eq!(
            options.viewport.min_inner_size,
            Some(egui::vec2(360.0, 220.0))
        );
        assert_eq!(options.viewport.resizable, Some(true));
    }
}
