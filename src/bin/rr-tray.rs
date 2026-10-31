//! Windows system-tray shell for the Rejection Rejector local web console.
//!
//! `rr-tray` is the product's only native UI: one notification-area icon
//! with the tooltip "Rejection Rejector" and a menu (Open console, Check
//! mail now, Pause/Resume dispatch, Exit). No desktop application window is
//! ever shown. The shell wraps the exact worker + loopback API lifecycle
//! `rr web` starts (`rejection_rejector::startup`), so every menu action
//! travels the same command pipeline as the other surfaces and the first-run
//! API credential display works exactly like `rr web`. All
//! operating-system access goes through the safe `tray-icon` wrapper over
//! Shell_NotifyIconW plus the `winit` message loop; this file contains no
//! raw FFI. The workspace directory and API port come from the existing
//! configuration surface (`config::data_dir()` and the saved settings) —
//! nothing here is machine-specific.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable
    )
)]

use clap::Parser;

/// Run the `rr-tray` system-tray shell.
///
/// Inputs: none; parses the optional `--data-dir` workspace override.
/// Output: `Ok(())` on clean exit; startup or shutdown failures abort with a
/// non-zero exit.
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let dir = match args.data_dir {
        Some(dir) => dir,
        None => rejection_rejector::config::data_dir()?,
    };
    platform::run(dir)
}

/// Command-line surface of the tray shell.
///
/// Inputs: none (plain struct). Output: the optional workspace override,
/// mirroring the `rr` CLI's global `--data-dir`.
#[derive(clap::Parser)]
#[command(version, about = "Rejection Rejector system-tray shell")]
struct Args {
    /// Workspace directory override (defaults to the platform data directory).
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,
}

/// Pure tray presentation logic shared by the platform shell and its tests.
///
/// Inputs: none (module). Output: the menu identity mapping, the pause label
/// policy and the tray icon artwork — everything testable without a desktop.
#[cfg(any(windows, test))]
mod actions {
    /// Menu label of the pause action while dispatch is running.
    pub const PAUSE_LABEL: &str = "Pause dispatch";
    /// Menu label of the pause action while dispatch is paused.
    pub const RESUME_LABEL: &str = "Resume dispatch";
    /// Stable menu item id of the "Open console" action.
    pub const OPEN_CONSOLE_ID: &str = "open-console";
    /// Stable menu item id of the "Check mail now" action.
    pub const CHECK_NOW_ID: &str = "check-now";
    /// Stable menu item id of the "Pause/Resume dispatch" action.
    pub const TOGGLE_PAUSE_ID: &str = "toggle-pause";
    /// Stable menu item id of the "Exit" action.
    pub const EXIT_ID: &str = "exit";

    /// The action one tray menu item triggers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TrayAction {
        /// Open the local web console in the default browser.
        OpenConsole,
        /// Request one immediate mailbox check through the local API pipeline.
        CheckNow,
        /// Toggle the dispatch pause flag.
        TogglePause,
        /// Stop accepting work, drain the worker and exit.
        Exit,
    }

    /// Map one menu item id onto its tray action.
    ///
    /// Inputs: `id` — clicked menu item id. Output: `Option<TrayAction>` —
    /// the mapped action; `None` for unknown ids, which are ignored.
    pub fn action_for_id(id: &str) -> Option<TrayAction> {
        match id {
            OPEN_CONSOLE_ID => Some(TrayAction::OpenConsole),
            CHECK_NOW_ID => Some(TrayAction::CheckNow),
            TOGGLE_PAUSE_ID => Some(TrayAction::TogglePause),
            EXIT_ID => Some(TrayAction::Exit),
            _ => None,
        }
    }

    /// The pause/resume menu label for one dispatch pause state.
    ///
    /// Inputs: `paused` — current dispatch pause flag. Output: `&'static
    /// str` — the label describing what a click will do.
    pub fn pause_label(paused: bool) -> &'static str {
        if paused { RESUME_LABEL } else { PAUSE_LABEL }
    }

    /// Distance from one point to one line segment.
    ///
    /// Inputs: `(px, py)` — query point; `(ax, ay)`/`(bx, by)` — segment
    /// endpoints. Output: `f64` — the euclidean distance, zero on the
    /// segment.
    fn segment_distance(px: f64, py: f64, ax: f64, ay: f64, bx: f64, by: f64) -> f64 {
        let (dx, dy) = (bx - ax, by - ay);
        let length_squared = dx * dx + dy * dy;
        let t = if length_squared == 0.0 {
            0.0
        } else {
            (((px - ax) * dx + (py - ay) * dy) / length_squared).clamp(0.0, 1.0)
        };
        let (cx, cy) = (ax + t * dx, ay + t * dy);
        ((px - cx).powi(2) + (py - cy).powi(2)).sqrt()
    }

    /// Render the tray icon artwork: a rounded blue tile with a white check.
    ///
    /// Inputs: none. Output: `(pixels, width, height)` — a 32x32 RGBA buffer
    /// (row-major, straight alpha) ready for `Icon::from_rgba`.
    pub fn tray_icon_rgba() -> (Vec<u8>, u32, u32) {
        const SIZE: usize = 32;
        const HALF: f64 = 15.5;
        const RADIUS: f64 = 7.0;
        const THICKNESS: f64 = 2.4;
        let (blue, white) = ([31u8, 111, 235, 255], [255u8, 255, 255, 255]);
        let mut pixels = vec![0u8; SIZE * SIZE * 4];
        for y in 0..SIZE {
            for x in 0..SIZE {
                let (px, py) = (x as f64 + 0.5, y as f64 + 0.5);
                let (dx, dy) = ((px - 16.0).abs(), (py - 16.0).abs());
                let (qx, qy) = (dx - (HALF - RADIUS), dy - (HALF - RADIUS));
                let in_corner = qx > 0.0 && qy > 0.0 && qx * qx + qy * qy > RADIUS * RADIUS;
                if dx > HALF || dy > HALF || in_corner {
                    continue;
                }
                let on_check = segment_distance(px, py, 10.0, 17.0, 14.0, 21.5) <= THICKNESS
                    || segment_distance(px, py, 14.0, 21.5, 22.0, 11.5) <= THICKNESS;
                let color = if on_check { white } else { blue };
                let offset = (y * SIZE + x) * 4;
                pixels[offset..offset + 4].copy_from_slice(&color);
            }
        }
        (pixels, SIZE as u32, SIZE as u32)
    }

    /// The pure tray presentation contract.
    ///
    /// Why: menu ids must map one-to-one onto actions, the pause label must
    /// always describe the action a click takes (never the current state),
    /// and the icon pixels must satisfy `Icon::from_rgba`'s dimensions.
    /// Inputs: none. Output: none.
    #[test]
    fn tray_menu_identity_and_artwork_are_well_formed() {
        assert_eq!(
            action_for_id(OPEN_CONSOLE_ID),
            Some(TrayAction::OpenConsole)
        );
        assert_eq!(action_for_id(CHECK_NOW_ID), Some(TrayAction::CheckNow));
        assert_eq!(
            action_for_id(TOGGLE_PAUSE_ID),
            Some(TrayAction::TogglePause)
        );
        assert_eq!(action_for_id(EXIT_ID), Some(TrayAction::Exit));
        assert_eq!(action_for_id("open-console "), None, "ids match exactly");
        assert_eq!(action_for_id(""), None, "unknown ids map to no action");
        assert_eq!(pause_label(false), "Pause dispatch");
        assert_eq!(pause_label(true), "Resume dispatch");
        assert_ne!(pause_label(true), pause_label(false));
    }

    /// The icon artwork is a valid 32x32 RGBA buffer with a visible check.
    ///
    /// Why: `Icon::from_rgba` fails closed on dimension mismatches and a
    /// flat icon would render as an invisible tray presence.
    /// Inputs: none. Output: none.
    #[test]
    fn tray_icon_artwork_is_valid_rgba_with_a_visible_check() {
        let (pixels, width, height) = tray_icon_rgba();
        assert_eq!((width, height), (32, 32));
        assert_eq!(pixels.len(), 32 * 32 * 4, "four bytes per pixel");
        let at = |x: usize, y: usize| {
            let offset = (y * 32 + x) * 4;
            &pixels[offset..offset + 4]
        };
        assert_eq!(at(0, 0), &[0, 0, 0, 0], "the rounded corners stay clear");
        assert_eq!(
            at(4, 16),
            &[31, 111, 235, 255],
            "the tile is the brand blue"
        );
        assert_eq!(at(13, 19), &[255, 255, 255, 255], "the check mark is white");
    }
}

/// Platform shell: the Windows notification-area loop, or a clear refusal on
/// targets without one.
///
/// Inputs: none (module). Output: the `run` entry point used by `main`.
#[cfg(not(windows))]
mod platform {
    use std::path::PathBuf;

    /// Refuse to run where there is no notification area to own.
    ///
    /// Inputs: `_dir` — workspace directory (unused). Output:
    /// `Result<()>` — always `Err`: `rr-tray` is the Windows system-tray
    /// shell and no other target provides one in this product.
    pub fn run(_dir: PathBuf) -> anyhow::Result<()> {
        anyhow::bail!(
            "rr-tray is the Windows system-tray shell; this target has no notification-area integration"
        )
    }
}

/// The Windows notification-area shell.
#[cfg(windows)]
mod platform {
    use crate::actions::{self, TrayAction};
    use anyhow::{Context, Result};
    use rejection_rejector::{
        startup, web,
        worker::{Command, Worker},
    };
    use std::{
        path::PathBuf,
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };
    use tray_icon::{
        Icon, TrayIcon, TrayIconBuilder,
        menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
    };
    use winit::{
        application::ApplicationHandler,
        event::StartCause,
        event_loop::{ActiveEventLoop, ControlFlow, EventLoop},
    };

    /// Periodic worker-health tick for the message loop.
    const TICK: Duration = Duration::from_secs(2);
    /// Bounded grace period for the worker to drain at exit.
    const DRAIN: Duration = Duration::from_secs(20);

    /// Shell state: the shared worker, the console URL and the tray icon.
    struct Shell {
        /// Shared worker + loopback API server (the `rr web` lifecycle).
        worker: Worker,
        /// Local web-console base URL opened by the menu.
        base_url: String,
        /// Pause/resume menu item whose label tracks the pause flag.
        pause_item: MenuItem,
        /// Tray icon held for the lifetime of the shell; dropping it removes
        /// the icon from the notification area.
        _tray: TrayIcon,
    }

    impl Shell {
        /// Build the tray menu and icon around one started worker.
        ///
        /// Inputs: `worker` — started worker + API server; `base_url` — the
        /// console URL. Output: `Result<Shell>` — the live shell holding the
        /// tray icon; icon or menu failures propagate.
        fn build(worker: Worker, base_url: String) -> Result<Self> {
            let menu = Menu::new();
            let items = [
                (actions::OPEN_CONSOLE_ID, "Open console"),
                (actions::CHECK_NOW_ID, "Check mail now"),
                (actions::TOGGLE_PAUSE_ID, actions::PAUSE_LABEL),
                (actions::EXIT_ID, "Exit"),
            ];
            let mut pause_item = None;
            for (index, (id, label)) in items.iter().enumerate() {
                if index == 3 {
                    menu.append(&PredefinedMenuItem::separator())
                        .context("tray menu separator")?;
                }
                let item = MenuItem::with_id(MenuId::new(*id), *label, true, None);
                if index == 2 {
                    pause_item = Some(item.clone());
                }
                menu.append(&item).context("tray menu item")?;
            }
            let tray = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("Rejection Rejector")
                .with_icon(tray_icon()?)
                .build()
                .context("tray icon")?;
            Ok(Self {
                worker,
                base_url,
                pause_item: pause_item.context("pause menu item")?,
                _tray: tray,
            })
        }

        /// Run one selected menu action.
        ///
        /// Inputs: `event` — menu selection event; `elwt` — message-loop
        /// control. Output: none — the action is applied to the worker or the
        /// loop; unknown ids are ignored.
        fn on_menu_event(&mut self, event: MenuEvent, elwt: &ActiveEventLoop) {
            match actions::action_for_id(event.id.0.as_str()) {
                Some(TrayAction::OpenConsole) => self.open_console(),
                Some(TrayAction::CheckNow) => self.check_now(),
                Some(TrayAction::TogglePause) => self.toggle_pause(),
                Some(TrayAction::Exit) => self.exit(elwt),
                None => {}
            }
        }

        /// Open the local web console in the default browser.
        ///
        /// Inputs: none beyond the shell. Output: none — a browser failure is
        /// reported on the console and never ends the tray.
        fn open_console(&self) {
            match webbrowser::open(&self.base_url) {
                Ok(()) => println!("Opened the local web console at {}", self.base_url),
                Err(error) => eprintln!("Open console failed: {error}"),
            }
        }

        /// Request one immediate mailbox check through the local API pipeline.
        ///
        /// The request is parsed by the loopback API's own request parser and
        /// dispatched as the same `Command::ApiWrite` an authenticated
        /// `POST /v1/commands/check-now` delivers, so the shared write gates
        /// run exactly as for the web console. The tray is the API's host
        /// process, so the request enters that pipeline in-process; the
        /// bearer-token boundary authenticates remote clients, and the CLI's
        /// bearer-token pre-flight ran at startup.
        ///
        /// Inputs: none beyond the shell. Output: none — the result is
        /// printed on the console when the worker finishes.
        fn check_now(&self) {
            let request = match web::parse_write_request(web::CHECK_NOW_ROUTE, b"{}") {
                Ok(request) => request,
                Err(error) => {
                    eprintln!("Check mail now was refused by the local API parser: {error:?}");
                    return;
                }
            };
            let (reply, outcome) = crossbeam_channel::bounded(1);
            self.worker.command(Command::ApiWrite { request, reply });
            println!("Check mail now: mailbox check requested.");
            std::thread::spawn(move || {
                if let Ok(outcome) = outcome.recv() {
                    println!(
                        "Check mail now finished with HTTP {}: {}",
                        outcome.status, outcome.body
                    );
                }
            });
        }

        /// Toggle the dispatch pause flag exactly like the `rr tui` pause key.
        ///
        /// Inputs: none beyond the shell. Output: none — the worker's pause
        /// flag flips and the menu label follows.
        fn toggle_pause(&self) {
            let paused = self.worker.paused.load(Ordering::SeqCst);
            self.worker.paused.store(!paused, Ordering::SeqCst);
            self.sync_pause_label();
        }

        /// Refresh the pause/resume label from the worker's pause flag.
        ///
        /// Inputs: none beyond the shell. Output: none — the menu item always
        /// names the action a click will take.
        fn sync_pause_label(&self) {
            self.pause_item.set_text(actions::pause_label(
                self.worker.paused.load(Ordering::SeqCst),
            ));
        }

        /// Periodic worker-health tick for the message loop.
        ///
        /// Inputs: `elwt` — message-loop control. Output: none — a fatally
        /// failed worker ends the shell with its error; otherwise the pause
        /// label tracks the flag.
        fn tick(&mut self, elwt: &ActiveEventLoop) {
            let snapshot = self.worker.view();
            if snapshot.fatal {
                eprintln!("The workspace failed: {}", snapshot.error);
                self.worker.request_stop();
                elwt.exit();
                return;
            }
            self.sync_pause_label();
        }

        /// Stop accepting work, drain the worker and end the message loop.
        ///
        /// Inputs: `elwt` — message-loop control. Output: none — dispatch is
        /// paused, the listener stops accepting, the worker is drained within
        /// the grace period, the loop exits, and the tray icon is removed when
        /// the shell drops.
        fn exit(&mut self, elwt: &ActiveEventLoop) {
            self.worker.request_stop();
            if self.worker.shutdown(DRAIN) {
                println!("Worker drained; the tray icon is removed on exit.");
            } else {
                eprintln!(
                    "The worker did not drain within the grace period; exiting anyway (delivery state is durable)."
                );
            }
            elwt.exit();
        }
    }

    /// Render the tray icon from the pure artwork buffer.
    ///
    /// Inputs: none. Output: `Result<Icon>` — the notification-area icon;
    /// pixel-buffer rejection propagates.
    fn tray_icon() -> Result<Icon> {
        let (pixels, width, height) = actions::tray_icon_rgba();
        Icon::from_rgba(pixels, width, height)
            .map_err(|error| anyhow::anyhow!("tray icon artwork rejected: {error:?}"))
    }

    /// Message-loop application state for the tray shell.
    ///
    /// Inputs: none (plain struct). Output: the worker slot, console URL and
    /// the live [`Shell`] once the loop starts.
    struct ShellApp {
        /// Started worker waiting for the loop to take it.
        pending_worker: Option<Worker>,
        /// Local web-console base URL opened by the menu.
        base_url: String,
        /// Live shell once the tray icon exists.
        shell: Option<Shell>,
    }

    impl ShellApp {
        /// Keep the message loop on the periodic tick cadence.
        ///
        /// Inputs: `event_loop` — active loop. Output: none — the loop wakes
        /// at least every [`TICK`] so worker health is polled.
        fn set_ticker(&self, event_loop: &ActiveEventLoop) {
            event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + TICK));
        }
    }

    impl ApplicationHandler<MenuEvent> for ShellApp {
        /// Create the tray icon once the loop is really running — the
        /// documented tray-icon startup order.
        ///
        /// Inputs: `event_loop` — active loop; `cause` — wakeup cause.
        /// Output: none — the shell is built on the `Init` cause; an icon
        /// failure ends the loop with the error on the console.
        fn new_events(&mut self, event_loop: &ActiveEventLoop, cause: StartCause) {
            self.set_ticker(event_loop);
            if cause != StartCause::Init {
                return;
            }
            let Some(worker) = self.pending_worker.take() else {
                return;
            };
            match Shell::build(worker, self.base_url.clone()) {
                Ok(built) => {
                    self.shell = Some(built);
                    println!("Tray icon ready.");
                }
                Err(error) => {
                    eprintln!("Tray icon could not be created: {error:#}");
                    event_loop.exit();
                }
            }
        }

        /// Required resume callback; the shell owns no windows.
        ///
        /// Inputs: `event_loop` — active loop. Output: none.
        fn resumed(&mut self, event_loop: &ActiveEventLoop) {
            self.set_ticker(event_loop);
        }

        /// Window events never occur; the shell owns no windows.
        ///
        /// Inputs: `_event_loop` — active loop; `_window_id` — emitting
        /// window; `_event` — window event. Output: none.
        fn window_event(
            &mut self,
            _event_loop: &ActiveEventLoop,
            _window_id: winit::window::WindowId,
            _event: winit::event::WindowEvent,
        ) {
        }

        /// Run one forwarded menu selection.
        ///
        /// Inputs: `event_loop` — active loop; `event` — menu selection.
        /// Output: none — dispatched to the shell when it exists.
        fn user_event(&mut self, event_loop: &ActiveEventLoop, event: MenuEvent) {
            if let Some(shell) = self.shell.as_mut() {
                shell.on_menu_event(event, event_loop);
            }
        }

        /// Periodic worker-health tick between events.
        ///
        /// Inputs: `event_loop` — active loop. Output: none — forwarded to
        /// the shell when it exists.
        fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
            self.set_ticker(event_loop);
            if let Some(shell) = self.shell.as_mut() {
                shell.tick(event_loop);
            }
        }
    }

    /// Run the notification-area shell over one started worker.
    ///
    /// Inputs: `dir` — workspace directory. Output: `Result<()>` — unit on
    /// clean exit; propagated startup, icon or message-loop failure.
    pub fn run(dir: PathBuf) -> Result<()> {
        let worker = startup::start_api_worker(dir)?;
        let base_url = startup::console_base_url(&worker)?;
        println!("Local web console: {base_url}");
        println!(
            "Rejection Rejector is running in the notification area. Right-click its icon for the menu."
        );
        let event_loop: EventLoop<MenuEvent> = EventLoop::<MenuEvent>::with_user_event()
            .build()
            .context("message loop")?;
        let proxy = event_loop.create_proxy();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(event);
        }));
        let mut app = ShellApp {
            pending_worker: Some(worker),
            base_url,
            shell: None,
        };
        event_loop.run_app(&mut app).context("message loop")?;
        Ok(())
    }
}
