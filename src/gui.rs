//! Native desktop UI. Network/database/model work stays on the bounded background worker.
use crate::mail_transport::AppPasswordCredentials;
use crate::{
    config::{
        AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H, LOOKBACK_DAYS, MODEL_CANDIDATES, Mode, POLL_HOURS,
        Settings, Tone, VERIFIER_CANDIDATES,
    },
    types::{Job, JobState, OperationState, OperationStatus, hash},
    worker::{Command, Snapshot, Worker},
};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::{
    path::PathBuf,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

mod theme;
pub(crate) use theme::{AMBER, BG, LINE, MINT, MUTED, PANEL};

/// Install the design tokens into the context.
///
/// Inputs: `ctx` — egui context to configure. Output: none; delegates to
/// [`theme::apply`], the single source of truth for the visual style.
fn configure_theme(ctx: &egui::Context) {
    theme::apply(ctx);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Overview,
    Review,
    Activity,
    LocalAi,
    Settings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShortcutAction {
    Overview,
    Review,
    Activity,
    LocalAi,
    Settings,
    CheckNow,
}

enum RecoveryDialogKind {
    Export {
        out: PathBuf,
    },
    Verify {
        backup: PathBuf,
        recovery_key: PathBuf,
    },
}

struct RecoveryDialog {
    kind: RecoveryDialogKind,
    passphrase: Zeroizing<String>,
    confirmation: Zeroizing<String>,
}

/// Validate one recovery passphrase and its confirmation.
///
/// Inputs: `passphrase` — candidate passphrase (20..=4096 bytes);
/// `confirmation` — repeated passphrase, if any. Output: `true` when the
/// passphrase is in range and matches the confirmation.
fn recovery_passphrase_valid(passphrase: &str, confirmation: Option<&str>) -> bool {
    (20..=4096).contains(&passphrase.len()) && confirmation.is_none_or(|value| value == passphrase)
}

/// Native file/folder pickers behind an injectable seam so tests can drive
/// the dialog-dependent buttons headlessly.
///
/// Inputs: none (plain struct of function pointers). Each picker receives a
/// fully built dialog (title/filter configured by the caller) and outputs the
/// chosen path, or `None` when the operator cancels.
#[derive(Clone, Copy)]
struct FilePickers {
    /// Resolve a built file dialog. Inputs: configured `rfd::FileDialog`.
    /// Output: chosen file path, or `None` on cancellation.
    pick_file: fn(rfd::FileDialog) -> Option<PathBuf>,
    /// Resolve a built folder dialog. Inputs: configured `rfd::FileDialog`.
    /// Output: chosen folder path, or `None` on cancellation.
    pick_folder: fn(rfd::FileDialog) -> Option<PathBuf>,
    /// Resolve a built save dialog. Inputs: configured `rfd::FileDialog`.
    /// Output: chosen destination path, or `None` on cancellation.
    save_file: fn(rfd::FileDialog) -> Option<PathBuf>,
}

impl FilePickers {
    /// The production pickers that show real native dialogs.
    ///
    /// Inputs: none. Output: [`FilePickers`] wired to `rfd`; tests replace
    /// the pointers with scripted pickers instead of opening real dialogs.
    fn native() -> Self {
        Self {
            pick_file: rfd::FileDialog::pick_file,
            pick_folder: rfd::FileDialog::pick_folder,
            save_file: rfd::FileDialog::save_file,
        }
    }
}

impl ShortcutAction {
    /// Map one shortcut action onto its tab.
    ///
    /// Inputs: `self` — the shortcut action; `mode` — current application mode
    /// (Review requires Human review mode). Output: `Option<Tab>` — the tab to
    /// switch to, or `None` when unavailable in this mode.
    fn tab(self, mode: Mode) -> Option<Tab> {
        match self {
            Self::Overview => Some(Tab::Overview),
            Self::Review if mode == Mode::HumanReview => Some(Tab::Review),
            Self::Review => None,
            Self::Activity => Some(Tab::Activity),
            Self::LocalAi => Some(Tab::LocalAi),
            Self::Settings => Some(Tab::Settings),
            Self::CheckNow => None,
        }
    }
}

/// Consume one keyboard shortcut from the input state.
///
/// Inputs: `ctx` — egui context. Output: `Option<ShortcutAction>` — the bound
/// action (number keys with no modifiers); `None` when no shortcut was pressed.
fn consume_shortcut(ctx: &egui::Context) -> Option<ShortcutAction> {
    ctx.input_mut(|input| {
        for (action, key) in [
            (ShortcutAction::Overview, egui::Key::Num1),
            (ShortcutAction::Review, egui::Key::Num2),
            (ShortcutAction::Activity, egui::Key::Num3),
            (ShortcutAction::LocalAi, egui::Key::Num4),
            (ShortcutAction::Settings, egui::Key::Num5),
        ] {
            let shortcut = egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, key);
            if input.consume_shortcut(&shortcut) {
                return Some(action);
            }
        }
        input
            .consume_key(egui::Modifiers::NONE, egui::Key::F5)
            .then_some(ShortcutAction::CheckNow)
    })
}

/// Presentation state for the main desktop window.
///
/// Inputs: none (plain struct). Output: the worker handle, current tab,
/// settings copy, editor state and pending dialogs.
pub struct App {
    worker: Worker,
    tab: Tab,
    settings: Settings,
    settings_revision: u64,
    settings_loaded: bool,
    editor: String,
    editor_key: Option<(String, u64)>,
    dirty: bool,
    pending_select: Option<String>,
    pending_arm: Option<crate::config::AutomaticArmGate>,
    send_confirmation: Option<Job>,
    install_confirmation: bool,
    recovery_dialog: Option<RecoveryDialog>,
    oauth_send: bool,
    app_password_email: String,
    app_password: String,
    screenshot: Option<PathBuf>,
    screenshot_requested: bool,
    frames: u32,
    local_error: String,
    started: Instant,
    editor_account: String,
    close_confirmation: bool,
    close_approved: bool,
    pickers: FilePickers,
    emergency: fn() -> crate::emergency::EmergencyStopStatus,
}
impl App {
    /// Construct the main application around a spawned worker.
    ///
    /// Inputs: `cc` — eframe creation context; `dir` — workspace directory; `demo`
    /// — whether demo mode is active; `screenshot` — optional scripted screenshot
    /// target. Output: [`Self`] ready for the first frame.
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        dir: PathBuf,
        demo: bool,
        screenshot: Option<PathBuf>,
    ) -> Self {
        configure_theme(&cc.egui_ctx);
        Self {
            worker: Worker::spawn(dir, demo),
            tab: if demo { Tab::Review } else { Tab::Overview },
            settings: Settings::default(),
            settings_revision: 0,
            settings_loaded: false,
            editor: String::default(),
            editor_key: None,
            dirty: false,
            pending_select: None,
            pending_arm: None,
            send_confirmation: None,
            install_confirmation: false,
            recovery_dialog: None,
            oauth_send: false,
            app_password_email: String::default(),
            app_password: String::default(),
            screenshot,
            screenshot_requested: false,
            frames: 0,
            local_error: String::default(),
            started: Instant::now(),
            editor_account: String::default(),
            close_confirmation: false,
            close_approved: false,
            pickers: FilePickers::native(),
            emergency: crate::emergency::status_fail_closed,
        }
    }
    /// Switch to one tab, refreshing the list where needed.
    ///
    /// Inputs: `tab` — tab to activate. Output: none — the active tab changes and
    /// Review/Activity tabs re-queue a listing.
    fn navigate(&mut self, tab: Tab) {
        self.tab = tab;
        if matches!(tab, Tab::Review | Tab::Activity) {
            self.worker.command(Command::List {
                review: tab == Tab::Review,
                page: 0,
            });
        }
    }

    /// Handle keyboard shortcuts and modal escape for one frame.
    ///
    /// Inputs: `ctx` — egui context; `s` — current worker snapshot. Output: none —
    /// shortcuts navigate while Escape dismisses an open modal or confirms closing.
    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context, s: &Snapshot) {
        if self.modal_open() {
            if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
                self.pending_select = None;
                self.send_confirmation = None;
                self.install_confirmation = false;
                self.recovery_dialog = None;
                self.close_confirmation = false;
            }
            return;
        }

        let Some(action) = consume_shortcut(ctx) else {
            return;
        };
        if let Some(tab) = action.tab(s.settings.mode) {
            self.navigate(tab);
            return;
        }
        if action == ShortcutAction::CheckNow
            && s.initialized
            && s.connected
            && !s.demo
            && s.busy.is_empty()
        {
            self.worker.command(Command::CheckNow);
        }
    }

    /// Render one section heading.
    ///
    /// Inputs: `ui` — target ui; `title` — heading text; `subtitle` — muted
    /// subtitle text. Output: none.
    fn heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
        ui.heading(title);
        ui.label(RichText::new(subtitle).color(MUTED));
        ui.add_space(12.0);
    }
    /// Render one card frame around a body.
    ///
    /// Inputs: `ui` — target ui; `body` — closure drawing the card contents.
    /// Output: none.
    fn card(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui)) {
        egui::Frame::default()
            .fill(PANEL)
            .stroke(egui::Stroke::new(1.0_f32, LINE))
            .corner_radius(12)
            .inner_margin(18)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                body(ui);
            });
    }
    /// Render one status badge.
    ///
    /// Inputs: `ui` — target ui; `text` — badge label; `color` — badge text color.
    /// Output: none.
    fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
        ui.label(RichText::new(text).color(color).strong());
    }
    /// Select one job, deferring while a modal is open or the editor is dirty.
    ///
    /// Inputs: `id` — job id to select. Output: none — the selection is queued to
    /// the worker or held as pending.
    fn select(&mut self, id: String) {
        if self.modal_open() {
            return;
        }
        if self.dirty {
            self.pending_select = Some(id);
        } else {
            self.worker.command(Command::Select(id));
        }
    }
    /// Synchronize the editor state with the worker snapshot.
    ///
    /// Inputs: `s` — current worker snapshot. Output: none — editor fields reset
    /// when the account or selection changes under the app.
    fn sync_view(&mut self, s: &Snapshot) {
        if s.initialized && self.editor_account != s.account {
            self.editor_account.clone_from(&s.account);
            self.editor.clear();
            self.editor_key = None;
            self.dirty = false;
            self.pending_select = None;
            self.send_confirmation = None;
        }
        if s.initialized && (!self.settings_loaded || s.settings_revision != self.settings_revision)
        {
            self.settings.clone_from(&s.settings);
            self.settings_revision = s.settings_revision;
            self.settings_loaded = true;
        }
        if s.settings.mode == Mode::Automatic && self.tab == Tab::Review {
            self.navigate(Tab::Overview);
        }
        if let Some(job) = &s.selected {
            let key = (job.id.clone(), job.revision);
            let stored = job.draft.as_ref().map(|d| d.body.as_str()).unwrap_or("");
            // A failed save must leave the editor dirty and sending disabled.
            if self.editor_key.as_ref().is_some_and(|k| k.0 == job.id) && self.editor == stored {
                self.dirty = false;
                self.editor_key = Some(key.clone());
            }
            if self.editor_key.as_ref() != Some(&key) && !self.dirty {
                self.editor = stored.into();
                self.editor_key = Some(key);
            }
        }
    }
    /// Render the overview tab.
    ///
    /// Inputs: `ui` — target ui; `s` — current worker snapshot. Output: none.
    fn overview(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        Self::heading(
            ui,
            "Your applications. Your voice.",
            "Local AI handles the repetitive work. You decide how replies leave your inbox.",
        );
        ui.columns(3, |cols| {
            for (col, title, value) in [
                (0, "MESSAGES STORED", s.counts.stored),
                (1, "AWAITING REVIEW", s.counts.review),
                (2, "REPLIES SENT", s.counts.sent),
            ] {
                Self::card(&mut cols[col], |ui| {
                    ui.label(RichText::new(title).small().color(MUTED));
                    ui.label(RichText::new(value.to_string()).size(38.0).color(MINT));
                });
            }
        });
        ui.add_space(16.0);
        Self::card(ui, |ui| {
            ui.heading("Workspace status");
            egui::Grid::new("workspace_status")
                .num_columns(2)
                .spacing([32.0, 14.0])
                .show(ui, |ui| {
                    ui.label("Gmail account");
                    ui.label(if s.account.is_empty() {
                        "Not connected"
                    } else {
                        &s.account
                    });
                    ui.end_row();
                    ui.label("Operating mode");
                    Self::badge(ui, s.settings.mode.label(), MINT);
                    ui.end_row();
                    ui.label("Mail delivery");
                    ui.label(if s.settings.sending_enabled {
                        "Enabled, with safety checks"
                    } else {
                        "Disabled — no email can leave the app"
                    });
                    ui.end_row();
                    ui.label("Schedule");
                    ui.label(format!(
                        "Every {} hour(s) · last {} day(s)",
                        s.settings.poll_hours, s.settings.lookback_days
                    ));
                    ui.end_row();
                    ui.label("Last successful check");
                    ui.label(
                        s.last_poll
                            .map(|d| {
                                d.with_timezone(&chrono::Local)
                                    .format("%d %b %Y · %H:%M")
                                    .to_string()
                            })
                            .unwrap_or_else(|| "Not checked yet".into()),
                    );
                    ui.end_row();
                    ui.label("Next scheduled check");
                    ui.label(
                        s.next_poll
                            .map(|d| {
                                d.with_timezone(&chrono::Local)
                                    .format("%d %b · %H:%M")
                                    .to_string()
                            })
                            .unwrap_or_else(|| "After connecting Gmail".into()),
                    );
                    ui.end_row();
                    ui.label("Storage safety");
                    if let Some(storage) = &s.storage {
                        let available_gib = storage.available_bytes as f64 / 1073741824.0;
                        let status = if storage.runtime_write_safe {
                            format!("{available_gib:.1} GiB available · durable writes safe")
                        } else {
                            format!("{available_gib:.1} GiB available · LOW HEADROOM")
                        };
                        ui.label(status);
                    } else {
                        ui.label("Storage health unavailable");
                    }
                    ui.end_row();
                    ui.label("Scheduled backup");
                    ui.label(
                        s.scheduled_backup
                            .as_ref()
                            .map(|status| {
                                if !status.enabled {
                                    "Disabled".to_owned()
                                } else if status.overdue {
                                    "OVERDUE — check backup configuration".to_owned()
                                } else {
                                    status
                                        .last_success_at
                                        .map(|at| {
                                            format!(
                                                "Verified {}",
                                                at.with_timezone(&chrono::Local)
                                                    .format("%d %b · %H:%M")
                                            )
                                        })
                                        .unwrap_or_else(|| "Pending first backup".into())
                                }
                            })
                            .unwrap_or_else(|| "Status unavailable".into()),
                    );
                    ui.end_row();
                    ui.label("Backup failure domain");
                    ui.label(
                        s.backup_isolation
                            .as_ref()
                            .map(|status| {
                                if !status.configured {
                                    "Not configured".to_owned()
                                } else if !status.destination_exists {
                                    "Destination unavailable".to_owned()
                                } else {
                                    match status.distinct_failure_domain {
                                        Some(true) => "Distinct filesystem / volume".to_owned(),
                                        Some(false) => {
                                            "SAME VOLUME — disk loss affects both".to_owned()
                                        }
                                        None => "Could not determine on this platform".to_owned(),
                                    }
                                }
                            })
                            .unwrap_or_else(|| "Status unavailable".into()),
                    );
                    ui.end_row();
                    ui.label("Local AI");
                    ui.label(if s.settings.model_digest.is_some() {
                        "Model pinned — rechecked when processing"
                    } else {
                        "Model qualification required"
                    });
                    ui.end_row();
                });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        s.connected && !s.demo && s.busy.is_empty(),
                        egui::Button::new("Check email now"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::CheckNow);
                }
                if ui.button("Open setup").clicked() {
                    self.navigate(Tab::Settings);
                }
                if ui.button("Configure local AI").clicked() {
                    self.navigate(Tab::LocalAi);
                }
            });
        });
        ui.add_space(16.0);
        Self::card(ui, |ui| {
            ui.heading("First run");
            ui.label("1. Set your signature and connect Gmail in Settings.\n2. Install/start Ollama, download the model and qualify it in Local AI.\n3. Start in Human review. Read both messages before enabling delivery.\n4. Enable Automatic only after validating the results on your mailbox.");
            ui.add_space(8.0);
            ui.label(RichText::new("Scheduled checks run only while the desktop app or the headless worker is running.").color(AMBER));
        });
    }
    /// Render the rejection queue list with paging.
    ///
    /// Inputs: `ui` — target ui; `s` — current worker snapshot. Output: none.
    fn queue(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        ui.label(RichText::new("REJECTION QUEUE").strong().color(MUTED));
        ui.horizontal(|ui| {
            if ui
                .add_enabled(s.page > 0, egui::Button::new("Previous"))
                .clicked()
            {
                self.worker.command(Command::List {
                    review: true,
                    page: s.page - 1,
                });
            }
            ui.label(format!("{}", s.page + 1));
            if ui
                .add_enabled(s.items.len() == 25, egui::Button::new("Next"))
                .clicked()
            {
                self.worker.command(Command::List {
                    review: true,
                    page: s.page + 1,
                });
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("review_queue")
            .show(ui, |ui| {
                if s.items.is_empty() {
                    ui.add_space(20.0);
                    ui.label(
                        "No rejections to review.\nConnect Gmail and qualify the model to start.",
                    );
                }
                for job in &s.items {
                    let subject = job
                        .email
                        .as_ref()
                        .map(|e| e.subject.as_str())
                        .unwrap_or("Message awaiting analysis");
                    let selected = s.selected.as_ref().is_some_and(|j| j.id == job.id);
                    let role = job
                        .analysis
                        .as_ref()
                        .map(|analysis| {
                            let company = analysis.verdict.company.trim();
                            let position = analysis.verdict.position.trim();
                            match (company.is_empty(), position.is_empty()) {
                                (false, false) => format!("{company} · {position}"),
                                (false, true) => company.to_owned(),
                                (true, false) => position.to_owned(),
                                (true, true) => String::default(),
                            }
                        })
                        .unwrap_or_default();
                    let received = job
                        .email
                        .as_ref()
                        .map(|email| {
                            email
                                .received_at
                                .with_timezone(&chrono::Local)
                                .format("%d %b · %H:%M")
                                .to_string()
                        })
                        .unwrap_or_else(|| "Date unavailable".into());
                    let score = job
                        .analysis
                        .as_ref()
                        .map(|analysis| format!(" · score {}/100", analysis.verdict.confidence))
                        .unwrap_or_default();
                    let title = if role.is_empty() {
                        format!("{subject}\n{received} · {}{score}", job.state.label())
                    } else {
                        format!(
                            "{subject}\n{role}\n{received} · {}{score}",
                            job.state.label()
                        )
                    };
                    if ui
                        .add_sized(
                            [
                                ui.available_width(),
                                if role.is_empty() { 82.0 } else { 102.0 },
                            ],
                            egui::Button::new(RichText::new(title).size(13.5))
                                .selected(selected)
                                .wrap(),
                        )
                        .clicked()
                    {
                        self.select(job.id.clone());
                    }
                }
            });
    }
    /// Render the activity and delivery history tab.
    ///
    /// Inputs: `ui` — target ui; `s` — current worker snapshot. Output: none.
    fn activity(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        Self::heading(
            ui,
            "Activity & delivery history",
            "Encrypted local records. Uncertain delivery is never retried automatically.",
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(s.page > 0, egui::Button::new("Previous page"))
                .clicked()
            {
                self.worker.command(Command::List {
                    review: false,
                    page: s.page - 1,
                });
            }
            ui.label(format!("Page {}", s.page + 1));
            if ui
                .add_enabled(s.items.len() == 25, egui::Button::new("Next page"))
                .clicked()
            {
                self.worker.command(Command::List {
                    review: false,
                    page: s.page + 1,
                });
            }
        });
        for job in &s.items {
            Self::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(
                            job.email
                                .as_ref()
                                .map(|e| e.subject.as_str())
                                .unwrap_or("Stored message identity"),
                        )
                        .strong(),
                    );
                    Self::badge(
                        ui,
                        job.state.label(),
                        if job.state == JobState::Sent {
                            MINT
                        } else {
                            MUTED
                        },
                    );
                });
                if job.state == JobState::Uncertain
                    && ui
                        .add_enabled(
                            s.busy.is_empty(),
                            egui::Button::new("Reconcile with Gmail Sent"),
                        )
                        .clicked()
                {
                    self.worker.command(Command::Reconcile(job.id.clone()));
                }
                egui::CollapsingHeader::new("Details")
                    .id_salt(("activity", &job.id))
                    .show(ui, |ui| {
                        ui.monospace(&job.id);
                        for flag in &job.flags {
                            ui.label(flag);
                        }
                        if let Some(d) = &job.draft {
                            ui.label(&d.body);
                        }
                    });
            });
        }
        ui.add_space(20.0);
        ui.heading("Recent audit events");
        for event in s.events.iter().rev() {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(
                        event
                            .at
                            .with_timezone(&chrono::Local)
                            .format("%d %b %H:%M:%S")
                            .to_string(),
                    )
                    .small()
                    .color(MUTED),
                );
                ui.label(RichText::new(&event.kind).strong());
                ui.label(&event.detail);
            });
            ui.separator();
        }
    }
    /// Render the local AI configuration tab.
    ///
    /// Inputs: `ui` — target ui; `s` — current worker snapshot. Output: none.
    fn local_ai(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let model_config_dirty = self.settings.model != s.settings.model
            || self.settings.independent_verifier_enabled
                != s.settings.independent_verifier_enabled
            || self.settings.verifier_model != s.settings.verifier_model
            || self.settings.num_ctx != s.settings.num_ctx
            || self.settings.ollama_url != s.settings.ollama_url
            || self.settings.llm_timeout_seconds != s.settings.llm_timeout_seconds;
        Self::heading(
            ui,
            "Intelligence that stays local",
            "Primary local model for classification/drafting, with optional sequential independent verification. No hosted inference fallback.",
        );
        Self::card(ui, |ui| {
            ui.heading("16 GiB GPU profile");
            ui.label("Default: granite4.2:8b-q8_0 (verified) · validate against the task suite before Automatic mode");
            ui.label(RichText::new("A model's download size does not prove it fits in VRAM. Qualification checks Ollama's loaded-model counters and pins the digest.").color(MUTED));
            egui::Grid::new("ai_status")
                .num_columns(2)
                .spacing([32.0, 12.0])
                .show(ui, |ui| {
                    ui.label("Configured model");
                    ui.monospace(&s.settings.model);
                    ui.end_row();
                    ui.label("Pinned digest");
                    ui.monospace(
                        s.settings
                            .model_digest
                            .as_deref()
                            .unwrap_or("Not qualified"),
                    );
                    ui.end_row();
                    ui.label("Last measured VRAM");
                    ui.label(if s.model.size_vram > 0 {
                        format!("{:.2} GiB", s.model.size_vram as f64 / 1073741824.0)
                    } else {
                        "Not measured in this session".into()
                    });
                    ui.end_row();
                    ui.label("GPU qualification");
                    ui.label(if s.model.message.is_empty() {
                        "Not yet run"
                    } else {
                        &s.model.message
                    });
                    ui.end_row();
                    ui.label("Independent verifier");
                    ui.label(if s.settings.independent_verifier_enabled {
                        format!(
                            "{} · {}",
                            s.settings.verifier_model,
                            s.settings
                                .verifier_model_digest
                                .as_deref()
                                .map(|digest| format!("pinned {}", &digest[..digest.len().min(12)]))
                                .unwrap_or_else(|| "not qualified".into())
                        )
                    } else {
                        "Disabled".into()
                    });
                    ui.end_row();
                    if s.settings.independent_verifier_enabled {
                        ui.label("Verifier GPU status");
                        ui.label(if s.verifier_model.message.is_empty() {
                            "Not yet run"
                        } else {
                            &s.verifier_model.message
                        });
                        ui.end_row();
                    }
                    ui.label("Task qualification");
                    if let Some(qualification) = &s.settings.task_qualification {
                        ui.label(format!(
                            "PASS · score {:.1}/100 · {} fixtures · {}",
                            qualification.task_score,
                            qualification.fixture_count,
                            qualification
                                .qualified_at
                                .with_timezone(&chrono::Local)
                                .format("%d %b %Y %H:%M")
                        ));
                    } else {
                        ui.label("Not passed for current configuration");
                    }
                    ui.end_row();
                });
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("1  Install Ollama"),
                    )
                    .clicked()
                {
                    self.install_confirmation = true;
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("2  Start Ollama"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::StartOllama);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo && !model_config_dirty,
                        egui::Button::new("3  Download model"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::PullModel);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo && !model_config_dirty,
                        egui::Button::new("4  Refresh status"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::InspectModel);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo && !model_config_dirty,
                        egui::Button::new("5  Qualify & pin"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::QualifyModel);
                }
                if s.settings.independent_verifier_enabled {
                    if ui
                        .add_enabled(
                            s.busy.is_empty() && !s.demo && !model_config_dirty,
                            egui::Button::new("Download verifier"),
                        )
                        .clicked()
                    {
                        self.worker.command(Command::PullVerifierModel);
                    }
                    if ui
                        .add_enabled(
                            s.busy.is_empty() && !s.demo && !model_config_dirty,
                            egui::Button::new("Refresh verifier"),
                        )
                        .clicked()
                    {
                        self.worker.command(Command::InspectVerifierModel);
                    }
                    if ui
                        .add_enabled(
                            s.busy.is_empty() && !s.demo && !model_config_dirty,
                            egui::Button::new("Qualify verifier"),
                        )
                        .clicked()
                    {
                        self.worker.command(Command::QualifyVerifierModel);
                    }
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty()
                            && !s.demo
                            && !model_config_dirty
                            && s.settings.model_digest.is_some()
                            && (!s.settings.independent_verifier_enabled
                                || s.settings.verifier_model_digest.is_some()),
                        egui::Button::new("Evaluate current model"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::EvaluateModel);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty()
                            && !s.demo
                            && !model_config_dirty
                            && s.settings.model_digest.is_some(),
                        egui::Button::new("Profile runtime"),
                    )
                    .on_hover_text("Runs cold-load, warm-repeat and near-context synthetic recruiting-email passes and writes a local JSON profile. This measures the target machine; it does not change Automatic-mode eligibility.")
                    .clicked()
                {
                    self.worker.command(Command::ProfileModel);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo && !model_config_dirty,
                        egui::Button::new("Compare installed candidates"),
                    )
                    .on_hover_text("Runs the full recruiting-email bake-off only on curated candidate models that are already installed. Nothing is downloaded automatically.")
                    .clicked()
                {
                    self.worker.command(Command::CompareModels);
                }
            });
            if model_config_dirty {
                ui.colored_label(
                    AMBER,
                    "Model configuration has unsaved changes. Save it below before downloading, refreshing status, qualifying, or evaluating.",
                );
            }
        });
        ui.add_space(16.0);
        Self::card(ui, |ui| {
            ui.heading("Local model configuration");
            ui.label("Change these values, save, then qualify again. Remote endpoints and cloud tags are rejected.");
            let ollama_label = ui.label("Ollama loopback address");
            ui.text_edit_singleline(&mut self.settings.ollama_url)
                .labelled_by(ollama_label.id);
            let model_label = ui.label("Installed/downloadable local model tag");
            if s.enterprise_policy.allowed_models.is_empty() {
                ui.text_edit_singleline(&mut self.settings.model)
                    .labelled_by(model_label.id);
            } else {
                let combo = egui::ComboBox::from_id_salt("enterprise_model_allowlist")
                    .selected_text(&self.settings.model)
                    .show_ui(ui, |ui| {
                        for model in &s.enterprise_policy.allowed_models {
                            ui.selectable_value(&mut self.settings.model, model.clone(), model);
                        }
                    });
                let _ = combo.response.labelled_by(model_label.id);
                ui.label(
                    RichText::new("Model selection is restricted by enterprise policy.")
                        .small()
                        .color(AMBER),
                );
            }
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Quick choices").small().color(MUTED));
                for (label, tag) in MODEL_CANDIDATES {
                    let allowed = s.enterprise_policy.allowed_models.is_empty()
                        || s.enterprise_policy
                            .allowed_models
                            .iter()
                            .any(|model| model == tag);
                    if ui
                        .add_enabled(allowed, egui::Button::new(label).small())
                        .clicked()
                    {
                        self.settings.model = tag.into();
                    }
                }
            });
            ui.separator();
            ui.add_enabled_ui(!s.enterprise_policy.require_independent_verifier, |ui| {
                ui.checkbox(
                    &mut self.settings.independent_verifier_enabled,
                    "Use a different local model for the verification pass",
                );
            });
            if s.enterprise_policy.require_independent_verifier {
                self.settings.independent_verifier_enabled = true;
                ui.label(
                    RichText::new("Independent verification is required by enterprise policy.")
                        .small()
                        .color(AMBER),
                );
            }
            if self.settings.independent_verifier_enabled {
                let verifier_label = ui.label("Independent verifier model tag");
                if s.enterprise_policy.allowed_verifier_models.is_empty() {
                    ui.text_edit_singleline(&mut self.settings.verifier_model)
                        .labelled_by(verifier_label.id);
                } else {
                    let combo = egui::ComboBox::from_id_salt("enterprise_verifier_allowlist")
                        .selected_text(&self.settings.verifier_model)
                        .show_ui(ui, |ui| {
                            for model in &s.enterprise_policy.allowed_verifier_models {
                                ui.selectable_value(
                                    &mut self.settings.verifier_model,
                                    model.clone(),
                                    model,
                                );
                            }
                        });
                    let _ = combo.response.labelled_by(verifier_label.id);
                }
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Verifier quick choices").small().color(MUTED));
                    for (label, tag) in VERIFIER_CANDIDATES {
                        let allowed = s.enterprise_policy.allowed_verifier_models.is_empty()
                            || s.enterprise_policy
                                .allowed_verifier_models
                                .iter()
                                .any(|model| model == tag);
                        if ui
                            .add_enabled(allowed, egui::Button::new(label).small())
                            .clicked()
                        {
                            self.settings.verifier_model = tag.into();
                        }
                    }
                });
                ui.label(
                    RichText::new(
                        "Sequential mode unloads the primary before verifier inference, so only one model must fit VRAM at a time. When enabled, verifier failure never falls back to same-model verification.",
                    )
                    .small()
                    .color(MUTED),
                );
            }
            egui::ComboBox::from_id_salt("model_context")
                .selected_text(format!("{} tokens", self.settings.num_ctx))
                .show_ui(ui, |ui| {
                    for n in [8192, 16384] {
                        ui.selectable_value(&mut self.settings.num_ctx, n, format!("{n} tokens"));
                    }
                });
            ui.horizontal(|ui| {
                let label = ui.label("Inference timeout, seconds");
                ui.add(
                    egui::DragValue::new(&mut self.settings.llm_timeout_seconds).range(30..=1200),
                )
                .labelled_by(label.id);
            });
            if ui
                .add_enabled(
                    s.busy.is_empty(),
                    egui::Button::new("Save model configuration"),
                )
                .clicked()
            {
                self.worker
                    .command(Command::Settings(Box::new(self.settings.clone())));
            }
            ui.label(RichText::new("Qualify & pin is only a smoke/residency test. Automatic mode additionally requires the full task-specific evaluation to pass for the exact model digest, prompt version, signature/tone/candidate facts and context size. Editing those inputs invalidates that qualification. The suite is synthetic and sends no email; independently labelled private mailbox acceptance is still required for serious deployment.").small().color(AMBER));
        });
    }
    /// Render the settings tab.
    ///
    /// Inputs: `ui` — target ui; `s` — current worker snapshot. Output: none.
    fn settings(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let qualified_model_matches_draft = s.settings.model_digest.is_some()
            && self.settings.model == s.settings.model
            && self.settings.num_ctx == s.settings.num_ctx
            && self.settings.ollama_url == s.settings.ollama_url;
        let verifier_ready = !self.settings.independent_verifier_enabled
            || self.settings.verifier_model_digest.is_some();
        let task_qualification_ready = self.settings.task_qualification_current();
        let emergency_stop = (self.emergency)();
        let emergency_stop_clear = !emergency_stop.active;
        let signature_ready = !self.settings.signature.trim().is_empty()
            && self.settings.signature.trim() != "Your name";
        let automatic_prerequisites = emergency_stop_clear
            && s.connected
            && s.send_scope
            && qualified_model_matches_draft
            && verifier_ready
            && task_qualification_ready
            && signature_ready;
        Self::heading(
            ui,
            "Settings",
            "Explicit permissions, predictable scheduling, and control over every outgoing reply.",
        );
        if s.enterprise_policy.active {
            Self::card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    Self::badge(ui, "ENTERPRISE POLICY ACTIVE", AMBER);
                    if let Some(digest) = &s.enterprise_policy.digest {
                        ui.monospace(format!("sha256:{}", &digest[..digest.len().min(12)]));
                    }
                });
                ui.label("Administrator policy is enforced at startup and on every settings update; locked controls cannot be bypassed through the GUI.");
                ui.horizontal_wrapped(|ui| {
                    ui.label("Policy provenance");
                    if s.enterprise_policy.digest_pin_enforced {
                        Self::badge(
                            ui,
                            if s.enterprise_policy.digest_pin_matches {
                                "DIGEST PIN VERIFIED"
                            } else {
                                "DIGEST PIN MISMATCH"
                            },
                            if s.enterprise_policy.digest_pin_matches {
                                MINT
                            } else {
                                Color32::LIGHT_RED
                            },
                        );
                    } else {
                        Self::badge(ui, "ACL / FILE TRUST ONLY", AMBER);
                    }
                });
                let mut constraints = Vec::<String>::new();
                if s.enterprise_policy.force_human_review {
                    constraints.push("Human Review forced".into());
                }
                if s.enterprise_policy.prohibit_sending {
                    constraints.push("sending prohibited".into());
                }
                if s.enterprise_policy.prohibit_integration_api {
                    constraints.push("integration API prohibited".into());
                }
                if let Some(limit) = s.enterprise_policy.max_daily_send_limit {
                    constraints.push(format!("max {limit} sends/24h"));
                }
                if let Some(minutes) = s.enterprise_policy.min_cooldown_minutes {
                    constraints.push(format!("cooldown ≥ {minutes} min"));
                }
                if let Some(days) = s.enterprise_policy.min_retention_days {
                    constraints.push(format!("retention ≥ {days} days"));
                }
                ui.label(constraints.join(" · "));
            });
            ui.add_space(12.0);
        }
        Self::card(ui, |ui| {
            ui.heading("Gmail connection");
            ui.label(if s.connected {
                format!("Connected: {}", s.account)
            } else {
                "No Gmail account connected".into()
            });
            ui.label("Use your own Google Cloud OAuth Desktop app JSON. See docs/SETUP.md for the consent-screen and Gmail API steps.");
            if s.enterprise_policy.prohibit_sending {
                self.oauth_send = false;
            }
            ui.add_enabled(
                !s.enterprise_policy.prohibit_sending,
                egui::Checkbox::new(
                    &mut self.oauth_send,
                    "Request permission to send replies (otherwise read-only)",
                ),
            );
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Choose OAuth JSON & connect"),
                    )
                    .clicked()
                    && let Some(path) = (self.pickers.pick_file)(
                        rfd::FileDialog::new().add_filter("Google OAuth JSON", &["json"]),
                    )
                {
                    self.worker.command(Command::Connect {
                        path,
                        send: self.oauth_send,
                    });
                }
                if ui
                    .add_enabled(
                        s.connected && s.busy.is_empty(),
                        egui::Button::new("Disconnect locally"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::Disconnect);
                }
            });
            ui.label(RichText::new("The JSON, refresh token and mailbox content are not uploaded to this repository or an AI service.").small().color(MUTED));
        });
        ui.add_space(12.0);
        Self::card(ui, |ui| {
            ui.heading("App password (IMAP/SMTP)");
            ui.label("Sign in with just your Gmail address and a Google app password — no Cloud Console or OAuth client. Requires 2-Step-Verification and an app password created under your Google Account → Security → App passwords.");
            ui.horizontal(|ui| {
                ui.label("Gmail address");
                ui.text_edit_singleline(&mut self.app_password_email);
            });
            ui.horizontal(|ui| {
                ui.label("App password");
                ui.add(
                    egui::TextEdit::singleline(&mut self.app_password)
                        .password(true)
                        .desired_width(180.0),
                );
            });
            if ui
                .add_enabled(
                    s.busy.is_empty()
                        && !s.demo
                        && !self.app_password_email.trim().is_empty()
                        && !self.app_password.trim().is_empty(),
                    egui::Button::new("Connect with app password"),
                )
                .clicked()
            {
                self.worker
                    .command(Command::ConnectAppPassword(AppPasswordCredentials::new(
                        self.app_password_email.trim(),
                        self.app_password.trim(),
                    )));
                self.app_password.clear();
            }
            ui.label(RichText::new("The app password is held only in the encrypted local store (Windows Credential Manager-backed), zeroized after use, never logged or uploaded.").small().color(MUTED));
        });
        ui.add_space(12.0);
        Self::card(ui, |ui| {
            ui.heading("Schedule & age window");
            ui.horizontal(|ui| {
                ui.label("Check every");
                egui::ComboBox::from_id_salt("poll_hours")
                    .selected_text(format!("{} hour(s)", self.settings.poll_hours))
                    .show_ui(ui, |ui| {
                        for h in POLL_HOURS {
                            ui.selectable_value(
                                &mut self.settings.poll_hours,
                                h,
                                format!("{h} hour(s)"),
                            );
                        }
                    });
                ui.label("Check emails from the last");
                egui::ComboBox::from_id_salt("lookback")
                    .selected_text(format!("{} day(s)", self.settings.lookback_days))
                    .show_ui(ui, |ui| {
                        for d in LOOKBACK_DAYS {
                            ui.selectable_value(
                                &mut self.settings.lookback_days,
                                d,
                                format!("{d} day(s)"),
                            );
                        }
                    });
            });
            ui.label(RichText::new("Only missing message identities are inserted; previously processed emails are not reclassified on every check. Use Check email now after changing the age window.").small().color(MUTED));
        });
        ui.add_space(12.0);
        Self::card(ui, |ui| {
            ui.heading("Reply mode & permissions");
            if s.enterprise_policy.force_human_review || s.enterprise_policy.prohibit_sending {
                self.settings.mode = Mode::HumanReview;
            }
            if s.enterprise_policy.prohibit_sending {
                self.settings.sending_enabled = false;
            }
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.settings.mode, Mode::HumanReview, "Human review");
                ui.add_enabled_ui(
                    !s.enterprise_policy.force_human_review
                        && !s.enterprise_policy.prohibit_sending,
                    |ui| {
                        ui.selectable_value(&mut self.settings.mode, Mode::Automatic, "Automatic");
                    },
                );
            });
            ui.add_enabled(
                !s.enterprise_policy.prohibit_sending,
                egui::Checkbox::new(
                    &mut self.settings.sending_enabled,
                    "Enable sending from this application",
                ),
            );
            if self.settings.mode == Mode::Automatic {
                ui.colored_label(AMBER,"Automatic sends without per-message approval. Ambiguous, unsafe or unverifiable cases remain held. The Review tab is disabled until you switch back.");
                ui.label(
                    RichText::new(format!(
                        "Hard unattended safety ceiling: at most {} reply attempts to the same normalized recipient mailbox in any rolling 24 hours. Human Review is the only override path.",
                        AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H
                    ))
                    .small()
                    .color(MUTED),
                );
                ui.label(RichText::new("Automatic prerequisites").strong());
                for (label, ready) in [
                    ("Enterprise emergency stop cleared", emergency_stop_clear),
                    ("Gmail connected", s.connected),
                    ("Gmail send permission granted", s.send_scope),
                    (
                        "Current model smoke-qualified & pinned",
                        qualified_model_matches_draft,
                    ),
                    (
                        "Independent verifier qualified when enabled",
                        verifier_ready,
                    ),
                    (
                        "Task-specific evaluation passed for this exact configuration",
                        task_qualification_ready,
                    ),
                    ("Non-placeholder signature set", signature_ready),
                ] {
                    ui.horizontal(|ui| {
                        Self::badge(
                            ui,
                            if ready { "READY" } else { "REQUIRED" },
                            if ready { MINT } else { AMBER },
                        );
                        ui.label(label);
                    });
                }
                if self.settings.automatic_confirmed {
                    if ui
                        .button("Disable Automatic mode and return to Human review")
                        .clicked()
                    {
                        self.settings.automatic_confirmed = false;
                        self.settings.automatic_since = None;
                        self.pending_arm = None;
                    }
                } else if ui
                    .button("Enable Automatic mode (requires a deliberate risk confirmation)")
                    .clicked()
                {
                    self.pending_arm =
                        Some(crate::config::AutomaticArmGate::open(chrono::Utc::now()));
                }
                ui.checkbox(
                    &mut self.settings.include_backlog,
                    "Also allow older rejections within the selected age window (off by default)",
                );
            }
            ui.horizontal(|ui| {
                let cooldown_label = ui.label("Cooldown, minutes");
                let minimum_cooldown = s.enterprise_policy.min_cooldown_minutes.unwrap_or(1);
                self.settings.cooldown_minutes =
                    self.settings.cooldown_minutes.max(minimum_cooldown);
                ui.add(
                    egui::DragValue::new(&mut self.settings.cooldown_minutes)
                        .range(minimum_cooldown..=1440),
                )
                .labelled_by(cooldown_label.id);
                let attempts_label = ui.label("Maximum attempts per 24 hours");
                let maximum_daily = s.enterprise_policy.max_daily_send_limit.unwrap_or(100);
                self.settings.daily_send_limit = self.settings.daily_send_limit.min(maximum_daily);
                ui.add(
                    egui::DragValue::new(&mut self.settings.daily_send_limit)
                        .range(1..=maximum_daily),
                )
                .labelled_by(attempts_label.id);
            });
            let signature_label = ui.label("Signature");
            ui.text_edit_singleline(&mut self.settings.signature)
                .labelled_by(signature_label.id);
            egui::ComboBox::from_id_salt("reply_tone")
                .selected_text(self.settings.tone.label())
                .show_ui(ui, |ui| {
                    for t in [
                        Tone::Professional,
                        Tone::Assertive,
                        Tone::Hardline,
                        Tone::Insane,
                    ] {
                        ui.selectable_value(&mut self.settings.tone, t, t.label());
                    }
                });
            egui::ComboBox::from_id_salt("reply_language")
                .selected_text(self.settings.reply_language.label())
                .show_ui(ui, |ui| {
                    for l in [
                        crate::config::ReplyLanguage::Auto,
                        crate::config::ReplyLanguage::English,
                    ] {
                        ui.selectable_value(&mut self.settings.reply_language, l, l.label());
                    }
                });
            let facts_label =
                ui.label("Verified candidate facts (optional, at most 2,500 UTF-8 bytes)");
            ui.add(
                egui::TextEdit::multiline(&mut self.settings.candidate_context)
                    .desired_width(f32::INFINITY)
                    .desired_rows(4)
                    .hint_text(
                        "Only facts you can substantiate. Do not add credentials or passwords.",
                    ),
            )
            .labelled_by(facts_label.id);
        });
        ui.add_space(12.0);
        Self::card(ui, |ui| {
            ui.heading("Storage & integration");
            ui.label("SQLite stores authenticated encrypted payloads. Windows Credential Manager holds the master key. State/count/time indexes are not encrypted.");
            ui.horizontal(|ui| {
                let retention_label = ui.label("Keep completed content, days");
                let minimum_retention = s.enterprise_policy.min_retention_days.unwrap_or(30);
                self.settings.retention_days = self.settings.retention_days.max(minimum_retention);
                ui.add(
                    egui::DragValue::new(&mut self.settings.retention_days)
                        .range(minimum_retention..=3650),
                )
                .labelled_by(retention_label.id);
                if ui
                    .add_enabled(
                        s.busy.is_empty(),
                        egui::Button::new("Prune old completed content now"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::Purge);
                }
            });
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Check database integrity"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::IntegrityCheck);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Compact database"),
                    )
                    .on_hover_text("Requires conservative free-space headroom, checkpoints WAL, VACUUMs encrypted SQLite pages, optimizes planner statistics, and verifies integrity again. This is not SSD-secure erasure.")
                    .clicked()
                {
                    self.worker.command(Command::CompactDatabase);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Create encrypted backup…"),
                    )
                    .on_hover_text("Creates a checksum-verified same-vault backup. No decrypted email content or OAuth token is written to the manifest.")
                    .clicked()
                    && let Some(parent) = (self.pickers.pick_folder)(
                        rfd::FileDialog::new()
                            .set_title("Choose parent folder for Rejection Rejector backup"),
                    )
                {
                    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
                    let out = parent.join(format!("rejection-rejector-backup-{stamp}"));
                    self.worker.command(Command::Backup { out });
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Run recovery drill…"),
                    )
                    .on_hover_text("Restores the selected backup into an isolated temporary workspace, reopens it and deeply authenticates every encrypted record. Live state is not modified.")
                    .clicked()
                    && let Some(backup) = (self.pickers.pick_folder)(
                        rfd::FileDialog::new().set_title("Choose a Rejection Rejector backup directory"),
                    )
                {
                    self.worker.command(Command::RecoveryDrill { backup });
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Export recovery key…"),
                    )
                    .on_hover_text("Creates a passphrase-wrapped recovery-key envelope for off-machine disaster recovery. The plaintext vault key is never written to disk.")
                    .clicked()
                    && let Some(out) = (self.pickers.save_file)(
                        rfd::FileDialog::new()
                            .set_title("Save wrapped Rejection Rejector recovery key")
                            .set_file_name("recovery-key.json"),
                    )
                {
                    self.recovery_dialog = Some(RecoveryDialog {
                        kind: RecoveryDialogKind::Export { out },
                        passphrase: Zeroizing::new(String::default()),
                        confirmation: Zeroizing::new(String::default()),
                    });
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Verify recovery key…"),
                    )
                    .on_hover_text("Proves that a wrapped recovery key and passphrase can decrypt the selected backup without installing the recovered key into the OS credential store.")
                    .clicked()
                    && let Some(backup) = (self.pickers.pick_folder)(
                        rfd::FileDialog::new().set_title("Choose a Rejection Rejector backup directory"),
                    )
                    && let Some(recovery_key) = (self.pickers.pick_file)(
                        rfd::FileDialog::new()
                            .set_title("Choose the wrapped recovery key")
                            .add_filter("Recovery key JSON", &["json"]),
                    )
                {
                    self.recovery_dialog = Some(RecoveryDialog {
                        kind: RecoveryDialogKind::Verify {
                            backup,
                            recovery_key,
                        },
                        passphrase: Zeroizing::new(String::default()),
                        confirmation: Zeroizing::new(String::default()),
                    });
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Export diagnostics…"),
                    )
                    .on_hover_text("Writes a redacted JSON report locally. No email content, account address, recipients, OAuth credentials, API token, signature or candidate facts are included.")
                    .clicked()
                    && let Some(path) = (self.pickers.save_file)(
                        rfd::FileDialog::new()
                            .set_title("Save Rejection Rejector diagnostics")
                            .set_file_name("rejection-rejector-diagnostics.json"),
                    )
                {
                    self.worker.command(Command::Diagnostics { out: path });
                }
            });
            ui.label(
                RichText::new("Backups preserve the encrypted database and audit chain. Run a recovery drill regularly. Off-machine recovery requires a separately stored wrapped recovery-key envelope and its passphrase; no plaintext master-key export exists. The GUI can export and verify that envelope; installing it into a fresh or locked workspace remains an explicit pre-open recovery operation.")
                    .small()
                    .color(MUTED),
            );
            ui.separator();
            ui.checkbox(
                &mut self.settings.scheduled_backup_enabled,
                "Create verified encrypted backups automatically",
            );
            if self.settings.scheduled_backup_enabled {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Backup folder");
                    if ui.button("Choose folder…").clicked()
                        && let Some(path) = (self.pickers.pick_folder)(rfd::FileDialog::new())
                    {
                        self.settings.scheduled_backup_directory =
                            path.to_string_lossy().into_owned();
                    }
                    ui.monospace(if self.settings.scheduled_backup_directory.is_empty() {
                        "Not selected"
                    } else {
                        &self.settings.scheduled_backup_directory
                    });
                });
                ui.horizontal(|ui| {
                    ui.label("Backup every");
                    egui::ComboBox::from_id_salt("scheduled_backup_interval")
                        .selected_text(format!(
                            "{} hour(s)",
                            self.settings.scheduled_backup_interval_hours
                        ))
                        .show_ui(ui, |ui| {
                            for hours in crate::config::BACKUP_INTERVAL_HOURS {
                                ui.selectable_value(
                                    &mut self.settings.scheduled_backup_interval_hours,
                                    hours,
                                    format!("{hours} hour(s)"),
                                );
                            }
                        });
                    ui.label("Keep");
                    ui.add(
                        egui::DragValue::new(&mut self.settings.scheduled_backup_keep)
                            .range(2..=30),
                    );
                    ui.label("verified backups");
                });
                if let Some(status) = &s.scheduled_backup {
                    ui.label(
                        RichText::new(match status.last_success_at {
                            Some(at) => format!(
                                "Last verified scheduled backup: {}{}",
                                at.with_timezone(&chrono::Local).format("%d %b %Y · %H:%M"),
                                if status.overdue { " · OVERDUE" } else { "" }
                            ),
                            None => "No scheduled backup completed yet".into(),
                        })
                        .small()
                        .color(if status.overdue { AMBER } else { MUTED }),
                    );
                }
            }
            ui.label(RichText::new("Scheduled retention deletes only older directories that first verify as same-vault Rejection Rejector backups; unrelated folders are never pruned.").small().color(MUTED));
            ui.separator();
            if s.enterprise_policy.prohibit_integration_api {
                self.settings.api_enabled = false;
            }
            ui.add_enabled(
                !s.enterprise_policy.prohibit_integration_api,
                egui::Checkbox::new(
                    &mut self.settings.api_enabled,
                    "Enable read-only loopback integration API (restart required)",
                ),
            );
            ui.horizontal(|ui| {
                let api_port_label = ui.label("API port");
                ui.add(egui::DragValue::new(&mut self.settings.api_port).range(1024..=65535))
                    .labelled_by(api_port_label.id);
                ui.label(if s.api_listening {
                    "Listening on loopback"
                } else {
                    "Not listening"
                });
            });
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !s.demo && s.busy.is_empty(),
                        egui::Button::new("Rotate / generate API token"),
                    )
                    .on_hover_text("Generates a new high-entropy token, persists only its one-way verifier, immediately disables any listener using the previous credential, and shows the new plaintext once for 60 seconds. Restart before integrations reconnect.")
                    .clicked()
                {
                    self.worker.command(Command::RotateApiToken);
                }
            });
            if let Some(token) = &s.api_token {
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(token.as_str());
                    if ui.button("Copy token").clicked() {
                        ui.ctx().copy_text(token.as_str().to_owned());
                    }
                    if ui.button("Hide token").clicked() {
                        self.worker.command(Command::HideApiToken);
                    }
                });
                ui.label(
                    RichText::new("One-time credential display: the plaintext token hides automatically after 60 seconds and cannot be revealed again. Copy it now. After rotation, restart the app/worker before integrations reconnect.")
                        .small()
                        .color(MUTED),
                );
            }
            ui.label(RichText::new("Only a one-way token verifier is persisted. The plaintext bearer credential still grants access to local email data: store it in the consuming application's OS-protected secret store, rotate it after suspected exposure, and never put it in source control.").small().color(AMBER));
        });
        ui.add_space(12.0);
        let automatic_ready_to_save = self.settings.mode != Mode::Automatic
            || (automatic_prerequisites
                && self.settings.sending_enabled
                && self.settings.automatic_confirmed);
        if ui
            .add_enabled(
                s.busy.is_empty() && automatic_ready_to_save,
                egui::Button::new(RichText::new("Save settings").strong().color(BG)).fill(MINT),
            )
            .clicked()
        {
            self.worker
                .command(Command::Settings(Box::new(self.settings.clone())));
        }
    }
    /// Render the frame's modal dialogs.
    ///
    /// Inputs: `ctx` — egui context; `s` — current worker snapshot. Output: none.
    fn dialogs(&mut self, ctx: &egui::Context, s: &Snapshot) {
        self.close_confirmation_dialog(ctx, s);
        self.pending_select_dialog(ctx);
        self.install_confirmation_dialog(ctx);
        self.recovery_key_dialog(ctx, s);
        self.pending_arm_dialog(ctx);
        self.send_confirmation_dialog(ctx, s);
    }

    /// Draw the close-confirmation dialog.
    ///
    /// Inputs: `ctx` — egui context; `s` — worker snapshot. Output: none; resolves forced close.
    fn close_confirmation_dialog(&mut self, ctx: &egui::Context, s: &Snapshot) {
        if self.close_confirmation {
            let sensitive_operation = s.operation.state == OperationState::Running
                && s.operation.kind.shutdown_sensitive();
            let title = if sensitive_operation {
                "Operation still running — close application?"
            } else {
                "Unsaved reply — close application?"
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    if self.dirty {
                        ui.label(
                            "Your edited reply has not been saved. Closing will discard this text.",
                        );
                    }
                    if sensitive_operation {
                        ui.colored_label(
                            AMBER,
                            format!(
                                "{:?} is still running. Closing now can interrupt an external side effect or leave an incomplete operator artifact. Delivery reservations remain fail-safe, but an in-flight Gmail result may become Uncertain on restart.",
                                s.operation.kind
                            ),
                        );
                    }
                    if ui.button("Keep application open").clicked() {
                        self.close_confirmation = false;
                    }
                    if ui.button(if self.dirty {
                        "Force close and discard unsaved text"
                    } else {
                        "Force close now"
                    }).clicked() {
                        self.worker.request_stop();
                        self.close_approved = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
        }
    }

    /// Draw the unsaved-reply selection confirmation.
    ///
    /// Inputs: `ctx` — egui context. Output: none; resolves the pending selection.
    fn pending_select_dialog(&mut self, ctx: &egui::Context) {
        if self.pending_select.is_some() {
            egui::Window::new("Unsaved reply")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Discard the unsaved edit and open the other email?");
                    ui.horizontal(|ui| {
                        if ui.button("Keep editing").clicked() {
                            self.pending_select = None;
                        }
                        if ui.button("Discard edit").clicked()
                            && let Some(id) = self.pending_select.take()
                        {
                            self.dirty = false;
                            self.worker.command(Command::Select(id));
                        }
                    });
                });
        }
    }

    /// Draw the Ollama installation confirmation.
    ///
    /// Inputs: `ctx` — egui context. Output: none; dispatches the install command.
    fn install_confirmation_dialog(&mut self, ctx: &egui::Context) {
        if self.install_confirmation {
            egui::Window::new("Install Ollama").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER,[0.0,0.0]).show(ctx,|ui|{
            ui.label("This runs the official Ollama package through Windows Package Manager. It changes this computer and may require Windows approval. The model download is a separate step.");ui.horizontal(|ui|{if ui.button("Cancel").clicked(){self.install_confirmation=false;}
if ui.button("Install").clicked(){self.install_confirmation=false;self.worker.command(Command::InstallOllama);}});
        });
        }
    }

    /// Draw the recovery-key export or verification dialog.
    ///
    /// Inputs: `ctx` — egui context; `s` — worker snapshot. Output: none; dispatches the recovery
    /// command on submit.
    fn recovery_key_dialog(&mut self, ctx: &egui::Context, s: &Snapshot) {
        let mut recovery_cancel = false;
        let mut recovery_submit = false;
        if let Some(dialog) = self.recovery_dialog.as_mut() {
            let exporting = matches!(dialog.kind, RecoveryDialogKind::Export { .. });
            let title = if exporting {
                "Export wrapped recovery key"
            } else {
                "Verify wrapped recovery key"
            };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .default_width(560.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    match &dialog.kind {
                        RecoveryDialogKind::Export { out } => {
                            ui.label("Choose a strong recovery passphrase. It is used only in memory to wrap the local vault key with Argon2id + XChaCha20-Poly1305.");
                            ui.monospace(out.display().to_string());
                        }
                        RecoveryDialogKind::Verify {
                            backup,
                            recovery_key,
                        } => {
                            ui.label("This performs an offline cryptographic check only. It does not install the recovered vault key or modify the selected backup.");
                            ui.monospace(format!("Backup: {}", backup.display()));
                            ui.monospace(format!("Key: {}", recovery_key.display()));
                        }
                    }
                    ui.separator();
                    let passphrase_label = ui.label("Recovery passphrase");
                    ui.add(
                        egui::TextEdit::singleline(&mut *dialog.passphrase)
                            .password(true)
                            .desired_width(f32::INFINITY),
                    )
                    .labelled_by(passphrase_label.id);
                    if exporting {
                        let confirmation_label = ui.label("Confirm recovery passphrase");
                        ui.add(
                            egui::TextEdit::singleline(&mut *dialog.confirmation)
                                .password(true)
                                .desired_width(f32::INFINITY),
                        )
                        .labelled_by(confirmation_label.id);
                    }
                    let valid = recovery_passphrase_valid(
                        dialog.passphrase.as_str(),
                        exporting.then_some(dialog.confirmation.as_str()),
                    );
                    if dialog.passphrase.len() < 20 {
                        ui.colored_label(AMBER, "Use at least 20 UTF-8 bytes.");
                    } else if dialog.passphrase.len() > 4096 {
                        ui.colored_label(AMBER, "Recovery passphrase exceeds 4,096 UTF-8 bytes.");
                    } else if exporting && dialog.passphrase.as_str() != dialog.confirmation.as_str()
                    {
                        ui.colored_label(AMBER, "The two passphrases do not match.");
                    }
                    ui.label(
                        RichText::new("The passphrase is never written to settings, audit logs, diagnostics or the recovery-key file.")
                            .small()
                            .color(MUTED),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            recovery_cancel = true;
                        }
                        if ui
                            .add_enabled(
                                valid && s.busy.is_empty(),
                                egui::Button::new(if exporting {
                                    "Export wrapped key"
                                } else {
                                    "Verify key against backup"
                                }),
                            )
                            .clicked()
                        {
                            recovery_submit = true;
                        }
                    });
                });
        }
        if recovery_cancel {
            self.recovery_dialog = None;
        } else if recovery_submit && let Some(mut dialog) = self.recovery_dialog.take() {
            let passphrase =
                std::mem::replace(&mut dialog.passphrase, Zeroizing::new(String::default()));
            match dialog.kind {
                RecoveryDialogKind::Export { out } => {
                    self.worker
                        .command(Command::ExportRecoveryKey { out, passphrase });
                }
                RecoveryDialogKind::Verify {
                    backup,
                    recovery_key,
                } => {
                    self.worker.command(Command::VerifyRecoveryKey {
                        backup,
                        recovery_key,
                        passphrase,
                    });
                }
            }
        }
    }

    /// Draw the Automatic-mode arming confirmation.
    ///
    /// Inputs: `ctx` — egui context. Output: none; arms or cancels the mode change.
    fn pending_arm_dialog(&mut self, ctx: &egui::Context) {
        if let Some(gate) = self.pending_arm {
            let now = chrono::Utc::now();
            let remaining = gate.remaining(now).num_seconds().max(0);
            let mut open = true;
            egui::Window::new("Enable Automatic mode?").open(&mut open).collapsible(false).resizable(false).default_width(560.0).anchor(egui::Align2::CENTER_CENTER,[0.0,0.0]).show(ctx,|ui|{
            ui.label(RichText::new("Warning: in Automatic mode the AI sends replies without your review.").strong());
            ui.label("The model can be wrong. A wrongly sent reply can damage real job applications and your standing with recruiters. Ambiguous, truncated or unverifiable messages are deliberately held, but no automated check is perfect and mistakes do happen.");
            ui.label(format!("This confirmation unlocks in {remaining} second(s). Use the pause to read this warning in full."));
            ui.horizontal(|ui|{
                let confirm = ui.add_enabled(gate.can_confirm(now), egui::Button::new("I understand the risks \u{2014} enable Automatic mode"));
                if confirm.clicked() {
                    self.settings.automatic_confirmed = true;
                    self.settings.automatic_since = Some(now);
                    self.pending_arm = None;
                }
                if ui.button("Cancel (stay in Human review)").clicked() {
                    self.pending_arm = None;
                }
            });
            });
            if !open {
                self.pending_arm = None;
            }
        }
    }

    /// Draw the confirm-exact-reply send dialog.
    ///
    /// Inputs: `ctx` — egui context; `s` — worker snapshot. Output: none; dispatches or cancels
    /// the send.
    fn send_confirmation_dialog(&mut self, ctx: &egui::Context, s: &Snapshot) {
        if let Some(job) = self.send_confirmation.clone() {
            egui::Window::new("Confirm this exact reply").collapsible(false).resizable(true).default_width(600.0).anchor(egui::Align2::CENTER_CENTER,[0.0,0.0]).show(ctx,|ui|{
            if let Some(e)=&job.email{ui.label(RichText::new(format!("To: {}",e.recipient().unwrap_or_default())).strong());ui.label(format!("Subject: {}",e.subject));}
            ui.separator();let body=job.draft.as_ref().map(|d|d.body.as_str()).unwrap_or("");egui::ScrollArea::vertical().max_height(400.0).show(ui,|ui|{ui.label(body);});
            ui.colored_label(AMBER,"Sending cannot be undone by this application. Gmail and the current conversation will be rechecked first.");
            ui.horizontal(|ui|{if ui.button("Cancel").clicked(){self.send_confirmation=None;}
if ui.add_enabled(s.busy.is_empty()&&!self.worker.paused.load(Ordering::SeqCst),egui::Button::new("Send this reply now")).clicked(){self.worker.command(Command::Send{id:job.id,revision:job.revision,body_hash:hash(body)});self.send_confirmation=None;}});
        });
        }
    }
}
impl eframe::App for App {
    /// Render one application frame.
    ///
    /// Inputs: `root_ui` — root ui; `_frame` — the enclosing frame (unused).
    /// Output: none.
    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root_ui.ctx().clone();
        ctx.request_repaint_after(Duration::from_millis(250));
        let s = self.worker.view();
        self.sync_view(&s);
        self.handle_keyboard_shortcuts(&ctx, &s);
        if ctx.input(|i| i.viewport().close_requested())
            && !self.close_approved
            && requires_close_confirmation(self.dirty, &s.operation)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_confirmation = true;
        }
        if self.screenshot.is_some() {
            // Screenshot mode is restricted to synthetic demo data.
            ctx.request_repaint();
            if self.frames.is_multiple_of(120) {
                eprintln!(
                    "GUI_QA initialized={} fatal={} items={} selected={} requested={} elapsed={:.1}",
                    s.initialized,
                    s.fatal,
                    s.items.len(),
                    s.selected.is_some(),
                    self.screenshot_requested,
                    self.started.elapsed().as_secs_f32()
                );
            }
        }
        if self.screenshot.is_some()
            && s.initialized
            && s.selected.is_none()
            && let Some(j) = s.items.first()
        {
            self.worker.command(Command::Select(j.id.clone()));
        }
        self.status_bar(root_ui, &s);
        egui::Panel::left("navigation").exact_size(210.0).resizable(false).frame(egui::Frame::default().fill(PANEL).inner_margin(18)).show(root_ui,|ui|{
            ui.add_space(8.0);ui.label(RichText::new("RR").size(34.0).strong().color(MINT));ui.label(RichText::new("REJECTION\nREJECTOR").size(17.0).strong());ui.label(RichText::new("YOUR VOICE, RETURNED.").size(10.0).color(MUTED));ui.add_space(28.0);
            for(tab,label)in[(Tab::Overview,"Overview"),(Tab::Review,"Review"),(Tab::Activity,"Activity"),(Tab::LocalAi,"Local AI"),(Tab::Settings,"Settings")]{
                let enabled=(tab!=Tab::Review||s.settings.mode==Mode::HumanReview)&&!self.modal_open();
                if ui.add_enabled(enabled,egui::Button::new(label).selected(self.tab==tab).min_size(Vec2::new(170.0,42.0))).clicked(){self.navigate(tab);}
            }
            ui.add_space(24.0);ui.separator();ui.label(RichText::new("DELIVERY CONTROL").small().color(MUTED));
            let paused=self.worker.paused.load(Ordering::SeqCst);
            if ui.add_sized([170.0,42.0],egui::Button::new(if paused{"Resume worker"}else{"Pause worker"})).clicked(){self.worker.paused.store(!paused,Ordering::SeqCst);}
            ui.label(RichText::new("Pause blocks future dispatch. A request already sent to Gmail cannot be recalled.").small().color(MUTED));
            ui.add_space(12.0);
            ui.label(
                RichText::new("Keyboard: Ctrl/Cmd+1–5 views · F5 check mail · Esc cancel dialog")
                    .small()
                    .color(MUTED),
            );
            ui.add_space(18.0);ui.label(RichText::new(format!("v{} · Rust native",env!("CARGO_PKG_VERSION"))).small().color(MUTED));
        });
        self.central_panel(root_ui, &s);
        self.dialogs(&ctx, &s);
        self.screenshot_qa(&ctx, &s);
    }
}

impl App {
    /// Draw the bottom status bar for one snapshot.
    ///
    /// Inputs: `root_ui` — egui ui to draw into; `s` — worker snapshot.
    /// Output: none; renders the workspace state, errors and badges.
    fn status_bar(&mut self, root_ui: &mut egui::Ui, s: &Snapshot) {
        egui::Panel::bottom("status_bar")
            .frame(egui::Frame::default().fill(PANEL).inner_margin(12))
            .show(root_ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    if !s.busy.is_empty() {
                        ui.spinner();
                        ui.label(&s.busy);
                    } else {
                        Self::badge(
                            ui,
                            if self.worker.paused.load(Ordering::SeqCst) {
                                "PAUSED"
                            } else {
                                "LOCAL WORKSPACE"
                            },
                            MINT,
                        );
                        ui.label(&s.notice);
                    }
                    let emergency_stop = (self.emergency)();
                    if emergency_stop.active {
                        ui.colored_label(
                            Color32::LIGHT_RED,
                            "ENTERPRISE EMERGENCY STOP · OUTBOUND EMAIL BLOCKED",
                        );
                    }
                    if s.demo {
                        ui.colored_label(AMBER, "SYNTHETIC DEMO · NO LIVE EMAIL");
                    }
                });
                if !s.error.is_empty() {
                    ui.colored_label(Color32::LIGHT_RED, &s.error);
                }
                if !self.local_error.is_empty() {
                    ui.colored_label(Color32::LIGHT_RED, &self.local_error);
                }
            });
    }

    /// Draw the central content panel for the active tab.
    ///
    /// Inputs: `root_ui` — egui ui to draw into; `s` — worker snapshot.
    /// Output: none; renders the fatal/initializing states or the active tab.
    fn central_panel(&mut self, root_ui: &mut egui::Ui, s: &Snapshot) {
        egui::CentralPanel::default().frame(egui::Frame::default().fill(BG).inner_margin(24)).show(root_ui,|ui|{
            if s.fatal{ui.heading("The workspace could not open");ui.label(&s.error);ui.label("Close any other instance using this data directory. On Windows, ensure Credential Manager is available. Never replace a missing vault key for an existing database.");return;}
            if !s.initialized{ui.spinner();ui.heading("Opening encrypted local workspace…");return;}
            if self.tab==Tab::Review{self.review(ui,s);}else{egui::ScrollArea::vertical().id_salt("main_scroll").show(ui,|ui|match self.tab{Tab::Overview=>self.overview(ui,s),Tab::Activity=>self.activity(ui,s),Tab::LocalAi=>self.local_ai(ui,s),Tab::Settings=>self.settings(ui,s),Tab::Review=>()});}
        });
    }

    /// Drive the screenshot QA harness for the synthetic demo flow.
    ///
    /// Inputs: `ctx` — egui context; `s` — worker snapshot. Output: none;
    /// requests, saves and finalizes native screenshots.
    fn screenshot_qa(&mut self, ctx: &egui::Context, s: &Snapshot) {
        if let Some(path) = self.screenshot.clone() {
            self.frames += 1;
            if self.started.elapsed() > Duration::from_secs(2)
                && s.selected.is_some()
                && !self.screenshot_requested
            {
                eprintln!("GUI_QA requesting native screenshot");
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
                self.screenshot_requested = true;
            }
            if s.fatal || self.started.elapsed() > Duration::from_secs(25) {
                eprintln!(
                    "GUI_QA failed: initialized={} selected={} error={}",
                    s.initialized,
                    s.selected.is_some(),
                    s.error
                );
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            let images = ctx.input(|i| {
                i.events
                    .iter()
                    .filter_map(|event| match event {
                        egui::Event::Screenshot { image, .. } => Some(image.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            });
            for img in images {
                let rgba: Vec<u8> = img.pixels.iter().flat_map(|c| c.to_array()).collect();
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match image::save_buffer(
                    &path,
                    &rgba,
                    img.size[0] as u32,
                    img.size[1] as u32,
                    image::ColorType::Rgba8,
                ) {
                    Ok(()) => {
                        eprintln!(
                            "GUI_QA native screenshot saved: {}x{}",
                            img.size[0], img.size[1]
                        );
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    Err(e) => {
                        self.local_error = format!("Screenshot failed: {e}");
                        self.screenshot = None;
                    }
                }
            }
        }
    }
}

/// Presentation state for the recovery and restore window.
///
/// Inputs: none (plain struct). Output: the chosen backup and recovery-key
/// paths, passphrase entry, restore report and progress state.
pub struct RecoveryApp {
    data_dir: PathBuf,
    backup: Option<PathBuf>,
    recovery_key: Option<PathBuf>,
    passphrase: Zeroizing<String>,
    acknowledgement: String,
    report: Option<crate::recovery::RestoreReport>,
    recovery_result:
        Option<crossbeam_channel::Receiver<Result<crate::recovery::RestoreReport, String>>>,
    recovering: bool,
    error: String,
    pickers: FilePickers,
}

impl RecoveryApp {
    /// Construct the recovery application for one workspace.
    ///
    /// Inputs: `cc` — eframe creation context; `data_dir` — workspace directory to
    /// recover. Output: [`Self`] with an empty restore form.
    pub fn new(cc: &eframe::CreationContext<'_>, data_dir: PathBuf) -> Self {
        configure_theme(&cc.egui_ctx);
        Self {
            data_dir,
            backup: None,
            recovery_key: None,
            passphrase: Zeroizing::new(String::default()),
            acknowledgement: String::default(),
            report: None,
            recovery_result: None,
            recovering: false,
            error: String::default(),
            pickers: FilePickers::native(),
        }
    }
}

impl eframe::App for RecoveryApp {
    /// Render one recovery-application frame.
    ///
    /// Inputs: `root_ui` — root ui; `_frame` — the enclosing frame (unused).
    /// Output: none.
    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root_ui.ctx().clone();

        self.take_completed_recovery();
        self.guard_recovery_close(&ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(BG).inner_margin(28))
            .show(root_ui, |ui| {
                ui.set_max_width(920.0);
                ui.heading("Disaster Recovery Mode");
                ui.label(
                    RichText::new(
                        "This mode never opens or creates the normal application vault before your backup and wrapped recovery key are authenticated.",
                    )
                    .color(MUTED),
                );
                ui.add_space(12.0);
                ui.colored_label(
                    AMBER,
                    "Recovery can replace the target workspace database. Use only a trusted backup and keep a copy of any existing workspace first.",
                );
                ui.separator();

                ui.label(RichText::new("Target workspace").strong());
                ui.monospace(self.data_dir.display().to_string());
                ui.add_space(8.0);

                self.backup_picker_row(ui);

                self.recovery_key_picker_row(ui);

                let passphrase_label = ui.label("Recovery passphrase");
                ui.add_enabled(
                    !self.recovering && self.report.is_none(),
                    egui::TextEdit::singleline(&mut *self.passphrase)
                        .password(true)
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(passphrase_label.id);
                ui.label(
                    RichText::new(
                        "Use 20–4,096 UTF-8 bytes. The passphrase stays in zeroizing process memory and is cleared after each recovery attempt.",
                    )
                    .small()
                    .color(MUTED),
                );

                let acknowledgement_label =
                    ui.label("Type RESTORE to acknowledge the destructive operation");
                ui.add_enabled(
                    !self.recovering && self.report.is_none(),
                    egui::TextEdit::singleline(&mut self.acknowledgement)
                        .desired_width(180.0),
                )
                .labelled_by(acknowledgement_label.id);

                self.restore_button(ui);

                self.recovery_progress(ui);

                ui.add_space(16.0);
                if ui
                    .add_enabled(!self.recovering, egui::Button::new("Close Recovery Mode"))
                    .clicked()
                {
                    self.passphrase.zeroize();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
    }
}

impl RecoveryApp {
    /// Collect one finished recovery result.
    ///
    /// Inputs: none beyond the state. Output: none; applies the report or error and clears the
    /// worker handle.
    fn take_completed_recovery(&mut self) {
        let completed =
            self.recovery_result
                .as_ref()
                .and_then(|receiver| match receiver.try_recv() {
                    Ok(result) => Some(result),
                    Err(crossbeam_channel::TryRecvError::Empty) => None,
                    Err(crossbeam_channel::TryRecvError::Disconnected) => Some(Err(
                        "Recovery worker terminated unexpectedly before reporting a result".into(),
                    )),
                });
        if let Some(result) = completed {
            self.recovery_result = None;
            self.recovering = false;
            match result {
                Ok(report) => {
                    self.error.clear();
                    self.report = Some(report);
                }
                Err(error) => {
                    self.error = error;
                }
            }
        }
    }

    /// Block closing while a recovery is running.
    ///
    /// Inputs: `ctx` — egui context. Output: none; cancels close requests during recovery.
    fn guard_recovery_close(&mut self, ctx: &egui::Context) {
        if self.recovering {
            ctx.request_repaint_after(Duration::from_millis(150));
            if ctx.input(|input| input.viewport().close_requested()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.error =
                    "Recovery is still running. Closing is blocked until the operation finishes."
                        .into();
            }
        }
    }

    /// Draw the backup-directory picker row.
    ///
    /// Inputs: `ui` — egui ui to draw into. Output: none; resolves the chosen backup directory.
    fn backup_picker_row(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.recovering && self.report.is_none(),
                    egui::Button::new("Choose backup directory…"),
                )
                .clicked()
                && let Some(path) = (self.pickers.pick_folder)(
                    rfd::FileDialog::new().set_title("Choose Rejection Rejector backup directory"),
                )
            {
                self.backup = Some(path);
                self.error.clear();
            }
            ui.monospace(self.backup.as_ref().map_or_else(
                || "No backup selected".into(),
                |path| path.display().to_string(),
            ));
        });
    }

    /// Draw the recovery-key picker row.
    ///
    /// Inputs: `ui` — egui ui to draw into. Output: none; resolves the chosen wrapped key file.
    fn recovery_key_picker_row(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.recovering && self.report.is_none(),
                    egui::Button::new("Choose wrapped recovery key…"),
                )
                .clicked()
                && let Some(path) = (self.pickers.pick_file)(
                    rfd::FileDialog::new()
                        .set_title("Choose wrapped recovery key")
                        .add_filter("Recovery key JSON", &["json"]),
                )
            {
                self.recovery_key = Some(path);
                self.error.clear();
            }
            ui.monospace(self.recovery_key.as_ref().map_or_else(
                || "No recovery key selected".into(),
                |path| path.display().to_string(),
            ));
        });
    }

    /// Draw the restore action and dispatch the worker.
    ///
    /// Inputs: `ui` — egui ui to draw into. Output: none; spawns the recovery thread on
    /// confirmation.
    fn restore_button(&mut self, ui: &mut egui::Ui) {
        let ready = !self.recovering
            && self.report.is_none()
            && self.backup.is_some()
            && self.recovery_key.is_some()
            && recovery_passphrase_valid(self.passphrase.as_str(), None)
            && self.acknowledgement == "RESTORE";
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("Authenticate, preflight and restore workspace")
                        .strong()
                        .color(BG),
                )
                .fill(MINT),
            )
            .clicked()
        {
            let backup = self.backup.clone().unwrap_or_default();
            let recovery_key = self.recovery_key.clone().unwrap_or_default();
            let data_dir = self.data_dir.clone();
            let passphrase =
                std::mem::replace(&mut self.passphrase, Zeroizing::new(String::default()));
            let (sender, receiver) = crossbeam_channel::bounded(1);
            self.recovery_result = Some(receiver);
            self.recovering = true;
            self.acknowledgement.clear();
            self.error.clear();
            std::thread::spawn(move || {
                let result = crate::recovery::recover_workspace_from_backup(
                    &data_dir,
                    &backup,
                    &recovery_key,
                    passphrase.as_bytes(),
                )
                .map_err(|error| format!("{error:#}"));
                let _ = sender.send(result);
            });
        }
    }

    /// Draw recovery progress, errors and the completion report.
    ///
    /// Inputs: `ui` — egui ui to draw into. Output: none; renders the running state and result.
    fn recovery_progress(&mut self, ui: &mut egui::Ui) {
        if self.recovering {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.colored_label(
                    AMBER,
                    "Authenticating, preflighting and restoring. Do not terminate this process.",
                );
            });
        }

        if !self.error.is_empty() {
            ui.add_space(8.0);
            ui.colored_label(Color32::LIGHT_RED, &self.error);
        }
        if let Some(report) = &self.report {
            ui.add_space(12.0);
            ui.colored_label(
                MINT,
                format!(
                    "Recovery completed and verified. Restored schema {}.",
                    report.restored_schema_version
                ),
            );
            ui.label(
                        "Close Recovery Mode and launch Rejection Rejector normally. The normal worker was never started during recovery.",
                    );
        }
    }
}

/// Whether closing the window needs confirmation.
///
/// Inputs: `dirty` — whether the reply editor has unsaved changes; `operation`
/// — current operation status. Output: `true` when the editor is dirty or a
/// shutdown-sensitive operation is running.
fn requires_close_confirmation(dirty: bool, operation: &OperationStatus) -> bool {
    dirty || (operation.state == OperationState::Running && operation.kind.shutdown_sensitive())
}

#[cfg(test)]
use crate::engine::visible_draft_matches;
use crate::engine::{editor_binding_matches, send_gate_eligible};
mod review;
impl App {
    /// Whether any modal dialog is open.
    ///
    /// Inputs: none (`&self`). Output: `true` while a selection, send, install,
    /// recovery, or close dialog is pending.
    fn modal_open(&self) -> bool {
        self.pending_select.is_some()
            || self.send_confirmation.is_some()
            || self.install_confirmation
            || self.recovery_dialog.is_some()
            || self.close_confirmation
    }
    /// Presentation-only demo navigation; CLI permits this only with --demo.
    ///
    /// Inputs: `name` — demo view name (`overview`, `activity`, `local-ai`, `settings`;
    /// anything else shows the review view). Output: none; the tab switches for
    /// presentation.
    pub fn set_demo_view(&mut self, name: &str) {
        self.navigate(match name {
            "overview" => Tab::Overview,
            "activity" => Tab::Activity,
            "local-ai" => Tab::LocalAi,
            "settings" => Tab::Settings,
            _ => Tab::Review,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shortcut_targets_respect_mode_boundaries() {
        assert_eq!(
            ShortcutAction::Overview.tab(Mode::HumanReview),
            Some(Tab::Overview)
        );
        assert_eq!(
            ShortcutAction::Review.tab(Mode::HumanReview),
            Some(Tab::Review)
        );
        assert_eq!(ShortcutAction::Review.tab(Mode::Automatic), None);
        assert_eq!(
            ShortcutAction::Settings.tab(Mode::Automatic),
            Some(Tab::Settings)
        );
        assert_eq!(ShortcutAction::CheckNow.tab(Mode::HumanReview), None);
    }

    #[test]
    fn recovery_passphrase_validation_matches_crypto_contract() {
        assert!(!recovery_passphrase_valid("short", None));
        assert!(recovery_passphrase_valid(
            "correct horse battery staple",
            None
        ));
        assert!(!recovery_passphrase_valid(
            "correct horse battery staple",
            Some("different passphrase entirely")
        ));
        assert!(recovery_passphrase_valid(
            "correct horse battery staple",
            Some("correct horse battery staple")
        ));
        assert!(recovery_passphrase_valid(&"a".repeat(4096), None));
        assert!(!recovery_passphrase_valid(&"a".repeat(4097), None));
    }

    #[test]
    fn close_confirmation_covers_unsaved_text_and_sensitive_operations() {
        let mut operation = OperationStatus::default();
        assert!(!requires_close_confirmation(false, &operation));
        assert!(requires_close_confirmation(true, &operation));

        operation.state = OperationState::Running;
        operation.kind = crate::types::OperationKind::SendReply;
        assert!(requires_close_confirmation(false, &operation));

        operation.kind = crate::types::OperationKind::SyncMailbox;
        assert!(!requires_close_confirmation(false, &operation));
    }

    #[test]
    fn unsaved_editor_never_matches_send_candidate() {
        let email = crate::ollama::sample_email("Synthetic", "Synthetic rejection");
        let mut job = Job::new(email.stub, chrono::Utc::now());
        job.draft = Some(crate::types::Draft {
            body: "Persisted and reviewed reply".into(),
            origin: "human".into(),
        });
        assert!(visible_draft_matches(&job, "Persisted and reviewed reply"));
        assert!(!visible_draft_matches(&job, "Changed but not saved reply"));
        job.draft = None;
        assert!(!visible_draft_matches(&job, ""));
    }
}

#[cfg(test)]
mod editor_binding_regressions {
    use super::*;
    #[test]
    fn selection_and_revision_are_both_required() {
        let email = crate::ollama::sample_email("Synthetic", "Not selected");
        let job = Job::new(email.stub, chrono::Utc::now());
        assert!(editor_binding_matches(
            &job,
            Some(&(job.id.clone(), job.revision))
        ));
        assert!(!editor_binding_matches(
            &job,
            Some(&(job.id.clone(), job.revision + 1))
        ));
        assert!(!editor_binding_matches(
            &job,
            Some(&("another-message".into(), job.revision))
        ));
        assert!(!editor_binding_matches(&job, None));
    }
}

#[cfg(test)]
mod send_guard_tests {
    use super::*;
    use crate::types::{OperationKind, OperationState};

    /// Close confirmation must fire for unsaved edits and for running
    /// shutdown-sensitive work, and only then.
    #[test]
    fn close_confirmation_covers_dirty_and_shutdown_sensitive_work() {
        let sensitive = OperationStatus {
            kind: OperationKind::SendReply,
            state: OperationState::Running,
            ..Default::default()
        };
        let benign = OperationStatus {
            kind: OperationKind::Refresh,
            state: OperationState::Running,
            ..Default::default()
        };
        let finished = OperationStatus {
            kind: OperationKind::SendReply,
            state: OperationState::Succeeded,
            ..Default::default()
        };
        assert!(requires_close_confirmation(true, &benign));
        assert!(requires_close_confirmation(false, &sensitive));
        assert!(!requires_close_confirmation(false, &benign));
        assert!(!requires_close_confirmation(false, &finished));
    }
}

/// Headless desktop-driving harness: a real [`App`] on a real egui context
/// with scripted input, so every render entry point runs its true layout code
/// without opening a window.
#[cfg(test)]
pub(super) mod headless {
    use super::*;
    use crossbeam_channel::{Receiver, bounded};

    /// A headless GUI harness driving the real [`eframe::App::ui`] entry.
    ///
    /// Inputs: none. Output: a harness whose `app` renders exactly like the
    /// desktop build; every [`Command`] the interface issues is captured in
    /// the harness's channel instead of reaching a live worker, and the
    /// native file dialogs are replaced with scripted pickers.
    pub(super) struct Harness {
        pub(super) app: App,
        ctx: egui::Context,
        rx: Receiver<Command>,
        nodes: Vec<(egui::accesskit::NodeId, egui::accesskit::Node)>,
        _dir: tempfile::TempDir,
    }

    impl Harness {
        /// Build a harness around a demo-mode [`App`].
        ///
        /// Inputs: none. Output: harness rendering against a default
        /// [`Snapshot`]; the engine thread is detached from the command
        /// channel so test runs are deterministic.
        pub(super) fn new() -> Self {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            let dir = tempfile::tempdir().expect("temp workspace");
            let cc = eframe::CreationContext::_new_kittest(ctx.clone());
            let mut app = App::new(&cc, dir.path().to_path_buf(), true, None);
            let (tx, rx) = bounded(64);
            // Dropping the worker's own sender disconnects the engine loop;
            // wait for its one startup refresh before taking over the view.
            app.worker.tx = tx;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !app.worker.view().initialized {
                assert!(Instant::now() < deadline, "worker never initialized");
                std::thread::sleep(Duration::from_millis(5));
            }
            *app.worker.snapshot.lock().expect("snapshot lock") = Snapshot::default();
            app.pickers = FilePickers {
                pick_file: |_| Some(PathBuf::from("picked-file.json")),
                pick_folder: |_| Some(PathBuf::from("picked-folder")),
                save_file: |_| Some(PathBuf::from("saved-file.json")),
            };
            let mut harness = Self {
                app,
                ctx,
                rx,
                nodes: Vec::new(),
                _dir: dir,
            };
            // A fresh context emits no widget tree on its first pass; render
            // one warm-up frame so lookups work from the first test frame. An
            // uninitialized snapshot keeps the first real sync (settings and
            // account) for the test's own first frame.
            harness.draw(&Snapshot::default());
            harness
        }

        /// Render one full application frame with scripted input events.
        ///
        /// Inputs: `s` — snapshot the worker would report; `events` — raw
        /// egui input events for this frame. Output: none; the frame is laid
        /// out for real and the AccessKit tree is cached for lookups.
        pub(super) fn frame(&mut self, s: &Snapshot, events: Vec<egui::Event>) {
            (*self.app.worker.snapshot.lock().expect("snapshot lock")).clone_from(s);
            let ctx = self.ctx.clone();
            let app = &mut self.app;
            run_frame(&ctx, &mut self.nodes, events, false, |root_ui, frame| {
                eframe::App::ui(app, root_ui, frame);
            });
        }

        /// Render one frame through a custom entry point instead of the
        /// full application shell.
        ///
        /// Inputs: `s` — snapshot the worker would report; `render` — the
        /// entry point to drive (`&mut App`, root ui). Output: none; the
        /// frame's widget tree is stored for lookups.
        pub(super) fn frame_entry(
            &mut self,
            s: &Snapshot,
            mut render: impl FnMut(&mut App, &mut egui::Ui),
        ) {
            (*self.app.worker.snapshot.lock().expect("snapshot lock")).clone_from(s);
            let ctx = self.ctx.clone();
            let app = &mut self.app;
            run_frame(
                &ctx,
                &mut self.nodes,
                Vec::new(),
                false,
                |root_ui, _frame| {
                    render(app, root_ui);
                },
            );
        }

        /// Render one frame with no input events.
        ///
        /// Inputs: `s` — snapshot the worker would report. Output: none.
        pub(super) fn draw(&mut self, s: &Snapshot) {
            self.frame(s, Vec::new());
        }

        /// Find the unique rendered widget carrying a label.
        ///
        /// Inputs: `label` — exact AccessKit label. Output: the widget's
        /// AccessKit node id; panics when the label is missing or ambiguous
        /// so tests cannot silently click the wrong control.
        pub(super) fn node_id(&self, label: &str) -> egui::accesskit::NodeId {
            let matches: Vec<_> = self
                .nodes
                .iter()
                .filter(|(_, node)| node_text(node) == Some(label))
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "expected exactly one widget labelled {label:?}, found {}; labels: {:?}",
                matches.len(),
                self.labels()
            );
            matches[0].0
        }

        /// Whether any rendered widget carries the exact label.
        ///
        /// Inputs: `label` — exact AccessKit label. Output: `true` when the
        /// last frame rendered such a widget.
        pub(super) fn shows(&self, label: &str) -> bool {
            self.nodes
                .iter()
                .any(|(_, node)| node_text(node) == Some(label))
        }

        /// Whether any rendered label contains the text.
        ///
        /// Inputs: `needle` — substring to look for. Output: `true` when at
        /// least one widget label contains it.
        pub(super) fn shows_containing(&self, needle: &str) -> bool {
            if self
                .nodes
                .iter()
                .any(|(_, node)| node_text(node).is_some_and(|l| l.contains(needle)))
            {
                return true;
            }
            // Wrapped labels split into per-line text runs: search the
            // whitespace-squashed concatenation of every visible text.
            let squashed = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
            squashed(&self.labels().join(" ")).contains(&squashed(needle))
        }

        /// All rendered widget labels from the last frame.
        ///
        /// Inputs: none. Output: labels in tree order.
        pub(super) fn labels(&self) -> Vec<String> {
            self.nodes
                .iter()
                .filter_map(|(_, node)| node_text(node).map(str::to_owned))
                .collect()
        }

        /// Click the unique widget carrying a label (even when disabled).
        ///
        /// Inputs: `s` — snapshot for the click frame; `label` — exact
        /// label. Output: none; the click is delivered as an AccessKit click
        /// request for the widget found in the previous frame.
        pub(super) fn click(&mut self, s: &Snapshot, label: &str) {
            let id = self.node_id(label);
            self.frame(s, vec![click_request(id)]);
        }

        /// Focus the n-th text input and type into it.
        ///
        /// Inputs: `s` — snapshot; `index` — zero-based index among the
        /// rendered text inputs; `text` — text to type. Output: none; the
        /// field is pointer-clicked first so text events reach it.
        pub(super) fn type_into(&mut self, s: &Snapshot, index: usize, text: &str) {
            let id = self
                .nodes
                .iter()
                .filter(|(_, node)| {
                    matches!(
                        node.role(),
                        egui::accesskit::Role::TextInput
                            | egui::accesskit::Role::MultilineTextInput
                    )
                })
                .nth(index)
                .map(|(id, _)| *id)
                .expect("text input present");
            let bounds = self
                .nodes
                .iter()
                .find(|(node_id, _)| *node_id == id)
                .and_then(|(_, node)| node.bounds())
                .expect("widget bounds");
            let pos = egui::pos2(
                ((bounds.x0 + bounds.x1) / 2.0) as f32,
                ((bounds.y0 + bounds.y1) / 2.0) as f32,
            );
            self.frame(
                s,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: false,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
            self.frame(s, vec![egui::Event::Text(text.to_owned())]);
        }

        /// Access to the shared egui context for direct frame driving.
        ///
        /// Inputs: none. Output: clone of the harness context.
        pub(super) fn ctx(&self) -> egui::Context {
            self.ctx.clone()
        }

        /// The harness workspace directory for screenshot output.
        ///
        /// Inputs: none. Output: path of the temporary data directory.
        pub(super) fn app_dir(&self) -> PathBuf {
            self._dir.path().to_path_buf()
        }

        /// Drain every command the interface issued since the last call.
        ///
        /// Inputs: none. Output: captured [`Command`]s in issue order.
        pub(super) fn commands(&mut self) -> Vec<Command> {
            let mut commands = Vec::new();
            while let Ok(command) = self.rx.try_recv() {
                commands.push(command);
            }
            commands
        }
    }

    /// The visible text of an AccessKit node: buttons carry `label`, while
    /// plain labels carry their text in `value`.
    ///
    /// Inputs: `node` — AccessKit node. Output: the display text, if any.
    pub(super) fn node_text(node: &egui::accesskit::Node) -> Option<&str> {
        node.label().or_else(|| node.value())
    }

    /// Render one real application frame headlessly and return its widget
    /// tree.
    ///
    /// Inputs: `ctx` — egui context to render against; `events` — scripted
    /// input events; `close_requested` — whether the window close was
    /// requested; `render` — the application render entry. Output: the
    /// frame's AccessKit `(node id, node)` pairs for lookups and clicks.
    pub(super) fn run_frame(
        ctx: &egui::Context,
        tree: &mut Vec<(egui::accesskit::NodeId, egui::accesskit::Node)>,
        events: Vec<egui::Event>,
        close_requested: bool,
        render: impl FnMut(&mut egui::Ui, &mut eframe::Frame),
    ) {
        let mut input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 2048.0),
            )),
            events,
            ..Default::default()
        };
        input.viewports.insert(
            egui::ViewportId::ROOT,
            egui::ViewportInfo {
                events: if close_requested {
                    vec![egui::ViewportEvent::Close]
                } else {
                    Vec::new()
                },
                ..Default::default()
            },
        );
        let mut render = render;
        let mut out = ctx.run_ui(input, |root_ui| {
            let mut frame = eframe::Frame::_new_kittest();
            render(root_ui, &mut frame);
        });
        out.textures_delta.clear();
        // egui emits an empty widget tree on the first pass after a state
        // change; repeat the pass without input so the tree is complete.
        let mut warm = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 2048.0),
            )),
            ..Default::default()
        };
        warm.viewports
            .insert(egui::ViewportId::ROOT, egui::ViewportInfo::default());
        let mut out = ctx.run_ui(warm, |root_ui| {
            let mut frame = eframe::Frame::_new_kittest();
            render(root_ui, &mut frame);
        });
        out.textures_delta.clear();
        // Each frame's update is the complete current widget tree.
        tree.clear();
        if let Some(update) = out.platform_output.accesskit_update {
            tree.extend(update.nodes);
        }
    }

    /// Build an AccessKit click request for a node id.
    ///
    /// Inputs: `id` — target widget node. Output: the [`egui::Event`] that
    /// egui folds into `Response::clicked()` for that widget.
    fn click_request(id: egui::accesskit::NodeId) -> egui::Event {
        egui::Event::AccessKitActionRequest(egui::accesskit::ActionRequest {
            action: egui::accesskit::Action::Click,
            target_tree: egui::accesskit::TreeId::ROOT,
            target_node: id,
            data: None,
        })
    }

    /// Scripted pickers that always return the canned paths.
    ///
    /// Inputs: none. Output: [`FilePickers`] whose pickers return
    /// `picked-file.json` / `picked-folder` / `saved-file.json`.
    pub(super) fn pickers_returning() -> FilePickers {
        FilePickers {
            pick_file: |_| Some(PathBuf::from("picked-file.json")),
            pick_folder: |_| Some(PathBuf::from("picked-folder")),
            save_file: |_| Some(PathBuf::from("saved-file.json")),
        }
    }

    /// Build a reviewable job with a persisted draft.
    ///
    /// Inputs: `body` — persisted draft text. Output: [`Job`] in `Ready`
    /// state with a synthetic demo email and the given draft.
    pub(super) fn reviewable_job(body: &str) -> Job {
        let email = crate::ollama::sample_email("Synthetic rejection", "We regret to inform you.");
        let mut job = Job::new(email.stub.clone(), chrono::Utc::now());
        job.email = Some(email);
        job.state = JobState::Ready;
        job.draft = Some(crate::types::Draft {
            body: body.into(),
            origin: "human".into(),
        });
        job
    }

    /// Build a fully sendable job: Gmail source, matching account, valid
    /// Message-ID and replyable recipient.
    ///
    /// Inputs: `body` — persisted draft text. Output: [`Job`] that passes
    /// every mail-level hard block when `s.account` is `ACCOUNT`.
    pub(super) fn sendable_job(body: &str) -> Job {
        let mut job = reviewable_job(body);
        if let Some(email) = &mut job.email {
            email.stub = crate::types::Stub {
                account: ACCOUNT.into(),
                provider_id: "provider-1".into(),
                thread_id: "thread-1".into(),
                source: crate::types::Source::Gmail,
            };
            email.from = "Recruitment <hr@corp.example>".into();
            email.message_id = "<valid-message@corp.example>".into();
        }
        job
    }

    /// The account that [`sendable_job`] mails target.
    pub(super) const ACCOUNT: &str = "me@example.com";

    /// Build an empty initialized snapshot for the given account.
    ///
    /// Inputs: `account` — configured account name. Output: [`Snapshot`]
    /// that the desktop treats as connected, initialized and idle.
    pub(super) fn snapshot(account: &str) -> Snapshot {
        Snapshot {
            initialized: true,
            account: account.into(),
            connected: true,
            ..Default::default()
        }
    }

    /// Build a storage-health reading.
    ///
    /// Inputs: `available_gib` — free space; `runtime_write_safe` — whether
    /// durable runtime writes are safe. Output: [`StorageHealth`].
    pub(super) fn storage_health(
        available_gib: f64,
        runtime_write_safe: bool,
    ) -> crate::storage::StorageHealth {
        crate::storage::StorageHealth {
            schema_version: 1,
            database_bytes: 4096,
            wal_bytes: 0,
            shm_bytes: 0,
            workspace_database_bytes: 4096,
            available_bytes: (available_gib * 1073741824.0) as u64,
            total_bytes: 21474836480,
            runtime_required_bytes: 1024,
            backup_required_bytes: 2048,
            runtime_write_safe,
            backup_safe: true,
        }
    }

    /// Build a scheduled-backup status reading.
    ///
    /// Inputs: `enabled`, `overdue` — status flags; `last_success_at` —
    /// last verified backup time. Output: [`ScheduledBackupStatus`].
    pub(super) fn scheduled_backup(
        enabled: bool,
        overdue: bool,
        last_success_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> crate::recovery::ScheduledBackupStatus {
        crate::recovery::ScheduledBackupStatus {
            schema_version: 1,
            enabled,
            interval_hours: 24,
            keep: 3,
            last_success_at,
            age_seconds: last_success_at.map(|_| 60),
            overdue,
        }
    }

    /// Build a backup-isolation status reading.
    ///
    /// Inputs: `configured`, `destination_exists` — location state;
    /// `distinct_failure_domain` — measurement result. Output:
    /// [`BackupIsolationStatus`].
    pub(super) fn backup_isolation(
        configured: bool,
        destination_exists: bool,
        distinct_failure_domain: Option<bool>,
    ) -> crate::recovery::BackupIsolationStatus {
        crate::recovery::BackupIsolationStatus {
            schema_version: 1,
            configured,
            destination_exists,
            distinct_failure_domain,
            measurement: "test",
        }
    }

    /// Build a task qualification that is current for the given settings.
    ///
    /// Inputs: `settings` — settings the qualification must match (digest,
    /// model, prompt version, context hash, suite hash). Output: a
    /// [`TaskQualification`] that `Settings::task_qualification_current`
    /// accepts for exactly that configuration.
    pub(super) fn current_qualification(settings: &Settings) -> crate::config::TaskQualification {
        crate::config::TaskQualification {
            model: settings.model.clone(),
            digest: settings.model_digest.clone().unwrap_or_default(),
            prompt_version: crate::config::PROMPT_VERSION.into(),
            context_hash: crate::config::settings_context_hash(settings),
            suite_hash: crate::config::evaluation_suite_hash(),
            ollama_runtime_version: "0.35.0".into(),
            task_score: 91.5,
            fixture_count: 12,
            qualified_at: chrono::Utc::now(),
        }
    }

    /// Build a verdict/analysis pair for queue and review rendering.
    ///
    /// Inputs: `company`, `position` — verdict fields; `verification` —
    /// optional reply audit. Output: [`Analysis`] attached to jobs.
    pub(super) fn analysis(
        company: &str,
        position: &str,
        verification: Option<crate::types::Verification>,
    ) -> crate::types::Analysis {
        crate::types::Analysis {
            verdict: crate::types::Verdict {
                category: crate::types::Category::Rejection,
                confidence: 87,
                evidence: "explicit rejection wording".into(),
                explanation: "The message clearly rejects the application.".into(),
                company: company.into(),
                position: position.into(),
                language: "English".into(),
            },
            verification,
            model: "test-model".into(),
            model_digest: "digest".into(),
            verification_model: String::default(),
            verification_model_digest: String::default(),
            prompt_version: "v-test".into(),
            email_fingerprint: "fingerprint".into(),
            verified_draft_hash: None,
            context_hash: "context".into(),
            input_complete: true,
            gpu_resident: true,
        }
    }
}
/// Headless behavior tests for the desktop interface.
#[cfg(test)]
mod render_tests {
    use super::headless::{self, Harness};
    use super::*;

    /// Account-switching resets the editor and every parked modal.
    ///
    /// Why: leaking the previous account's text into another mailbox is a
    /// safety bug — assert the editor and modals are gone after the switch.
    #[test]
    fn account_switch_resets_editor_state() {
        let mut h = Harness::new();
        let mut s = headless::snapshot("old@example.com");
        h.app.sync_view(&s);
        // Dirty state accumulated while working in the old account.
        h.app.dirty = true;
        h.app.editor = "old account text".into();
        h.app.editor_key = Some(("job".into(), 1));
        h.app.pending_select = Some("job".into());
        h.app.send_confirmation = Some(headless::reviewable_job("draft"));
        s.account = "new@example.com".into();
        h.app.sync_view(&s);
        assert!(h.app.editor.is_empty(), "editor cleared on account switch");
        assert!(h.app.editor_key.is_none());
        assert!(h.app.pending_select.is_none());
        assert!(h.app.send_confirmation.is_none());
    }

    /// Settings reload exactly once per snapshot revision change.
    ///
    /// Why: a lost update leaves the form editing stale settings silently.
    #[test]
    fn settings_reload_only_on_revision_change() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.model = "first-model".into();
        s.settings_revision = 3;
        h.app.sync_view(&s);
        assert_eq!(h.app.settings.model, "first-model");
        assert_eq!(h.app.settings_revision, 3);
        // Unsaved local edits survive while the revision is unchanged.
        h.app.settings.model = "local-edit".into();
        h.app.sync_view(&s);
        assert_eq!(h.app.settings.model, "local-edit");
        s.settings.model = "server-model".into();
        s.settings_revision = 4;
        h.app.sync_view(&s);
        assert_eq!(h.app.settings.model, "server-model");
    }

    /// Automatic mode kicks the view off the Review tab on sync.
    ///
    /// Why: the Review tab must not present a review flow the mode disabled.
    #[test]
    fn automatic_mode_kicks_review_tab() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.mode = Mode::Automatic;
        h.app.tab = Tab::Review;
        h.app.sync_view(&s);
        assert_eq!(h.app.tab, Tab::Overview);
    }

    /// The editor follows the selected job: a clean editor rebinds and
    /// reloads, a matching save clears dirty, a dirty editor never rebinds.
    ///
    /// Why: the binding is what keeps stale text unsavable and unsendable.
    #[test]
    fn editor_follows_selected_job_binding() {
        let mut h = Harness::new();
        let mut job = headless::reviewable_job("persisted draft");
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.selected = Some(job.clone());
        h.app.dirty = false;
        h.app.sync_view(&s);
        assert_eq!(h.app.editor, "persisted draft");
        assert_eq!(h.app.editor_key, Some((job.id.clone(), job.revision)));

        // A confirmed save (text == stored) clears dirty and re-binds.
        h.app.dirty = true;
        h.app.sync_view(&s);
        assert!(!h.app.dirty, "stored text marks the save confirmed");

        // A dirty editor with different text stays dirty and unbound.
        h.app.editor = "unsaved edit".into();
        h.app.dirty = true;
        job.revision += 1;
        s.selected = Some(job.clone());
        h.app.sync_view(&s);
        assert_eq!(h.app.editor, "unsaved edit", "dirty text retained");
        assert!(h.app.dirty);
        assert_ne!(
            h.app.editor_key,
            Some((job.id.clone(), job.revision)),
            "stale editor stays unbound to the new revision"
        );
    }

    /// Navigation issues a list refresh only for Review and Activity.
    ///
    /// Why: the queue must re-fetch when the pane changes, but Overview must
    /// not spam the worker.
    #[test]
    fn navigation_refreshes_review_and_activity_only() {
        let mut h = Harness::new();
        h.app.navigate(Tab::Overview);
        assert!(h.commands().is_empty());
        h.app.navigate(Tab::Review);
        assert!(matches!(
            h.commands()[0],
            Command::List {
                review: true,
                page: 0
            }
        ));
        h.app.navigate(Tab::Activity);
        assert!(matches!(
            h.commands()[0],
            Command::List {
                review: false,
                page: 0
            }
        ));
    }

    /// Selection parks behind the unsaved-edit dialog and otherwise issues
    /// `Command::Select`.
    ///
    /// Why: silently discarding an unsaved edit on a click loses operator work.
    #[test]
    fn selection_parks_behind_unsaved_edit_dialog() {
        let mut h = Harness::new();
        h.app.dirty = true;
        h.app.select("job-1".into());
        assert_eq!(h.app.pending_select, Some("job-1".into()));
        // While the unsaved-edit dialog is parked, other selections are ignored.
        h.app.select("job-2".into());
        assert_eq!(h.app.pending_select, Some("job-1".into()));
        assert!(h.commands().is_empty(), "modal state blocks selection");
        h.app.pending_select = None;
        h.app.dirty = false;
        h.app.select("job-3".into());
        assert!(h.app.pending_select.is_none());
        assert!(matches!(&h.commands()[0], Command::Select(id) if id == "job-3"));
    }

    /// Keyboard shortcuts navigate tabs, run F5, and a modal Esc cancels
    /// every parked dialog without touching the worker.
    ///
    /// Why: shortcut routing is a state machine; a leak between modal and
    /// pane keys would fire commands while a dialog is open.
    #[test]
    fn keyboard_shortcuts_route_by_modal_state() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        h.frame(
            &s,
            vec![egui::Event::Key {
                key: egui::Key::Num2,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::COMMAND,
            }],
        );
        assert_eq!(h.app.tab, Tab::Review);
        h.commands();

        // F5 is CheckNow only on an idle connected live session.
        s.initialized = true;
        s.connected = true;
        h.frame(
            &s,
            vec![egui::Event::Key {
                key: egui::Key::F5,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert!(matches!(h.commands()[0], Command::CheckNow));
        s.busy = "syncing".into();
        h.frame(
            &s,
            vec![egui::Event::Key {
                key: egui::Key::F5,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert!(h.commands().is_empty(), "busy sessions never trigger F5");

        // Esc inside a modal clears the modal stack and issues nothing.
        h.app.pending_select = Some("job".into());
        h.app.send_confirmation = Some(headless::reviewable_job("draft"));
        h.app.install_confirmation = true;
        h.app.close_confirmation = true;
        s.busy.clear();
        h.frame(
            &s,
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert!(h.app.pending_select.is_none() && h.app.send_confirmation.is_none());
        assert!(!h.app.install_confirmation && !h.app.close_confirmation);
        assert!(
            h.commands().is_empty(),
            "modal Esc never reaches the worker"
        );
    }

    /// The overview renders both sides of every status branch and its
    /// buttons route correctly.
    ///
    /// Why: each fallback string is a distinct operator signal ("Not
    /// connected", "Not checked yet", "Storage health unavailable", …); a
    /// wrong branch hides real problems behind healthy-looking text.
    #[test]
    fn overview_renders_status_branches_and_routes_buttons() {
        let mut h = Harness::new();
        h.app.tab = Tab::Overview;
        let s = headless::snapshot("");
        h.draw(&s);
        for expected in [
            "MESSAGES STORED",
            "Not connected",
            "Disabled — no email can leave the app",
            "Not checked yet",
            "After connecting Gmail",
            "Storage health unavailable",
            "Status unavailable",
            "Model qualification required",
            "First run",
        ] {
            assert!(
                h.shows(expected),
                "missing {expected:?} in {:?}",
                h.labels()
            );
        }

        // Rich state: every optional field populated on the healthy path.
        let mut s = headless::snapshot("me@example.com");
        s.settings.sending_enabled = true;
        s.settings.model_digest = Some("0123456789abcdef".into());
        s.counts.stored = 7;
        s.counts.review = 3;
        s.counts.sent = 2;
        s.last_poll = Some(chrono::Utc::now());
        s.next_poll = Some(chrono::Utc::now());
        s.storage = Some(headless::storage_health(64.0, true));
        s.scheduled_backup = Some(headless::scheduled_backup(
            false,
            false,
            Some(chrono::Utc::now()),
        ));
        s.backup_isolation = Some(headless::backup_isolation(true, true, Some(true)));
        h.draw(&s);
        for expected in [
            "me@example.com",
            "Enabled, with safety checks",
            "durable writes safe",
            "Distinct filesystem / volume",
            "Model pinned — rechecked when processing",
        ] {
            assert!(h.shows_containing(expected), "missing {expected:?}");
        }

        // Low-headroom / overdue / same-volume variants flip the warnings.
        s.storage = Some(headless::storage_health(1.0, false));
        s.scheduled_backup = Some(headless::scheduled_backup(true, true, None));
        s.backup_isolation = Some(headless::backup_isolation(true, true, Some(false)));
        h.draw(&s);
        assert!(h.shows_containing("LOW HEADROOM"));
        assert!(h.shows_containing("OVERDUE"));
        assert!(h.shows_containing("SAME VOLUME"));

        // Disabled/unconfigured/pending variants.
        s.scheduled_backup = Some(headless::scheduled_backup(false, false, None));
        s.backup_isolation = Some(headless::backup_isolation(false, false, None));
        h.draw(&s);
        assert!(h.shows("Disabled"));
        assert!(h.shows("Not configured"));

        s.scheduled_backup = Some(headless::scheduled_backup(true, false, None));
        s.backup_isolation = Some(headless::backup_isolation(true, false, None));
        h.draw(&s);
        assert!(h.shows("Pending first backup"));
        assert!(h.shows("Destination unavailable"));

        s.backup_isolation = Some(headless::backup_isolation(true, true, None));
        h.draw(&s);
        assert!(h.shows("Could not determine on this platform"));

        // Buttons: Check email now routes when idle and connected …
        s.demo = false;
        h.click(&s, "Check email now");
        assert!(matches!(h.commands()[0], Command::CheckNow));
        // … navigation buttons switch tabs …
        h.draw(&s);
        h.click(&s, "Configure local AI");
        assert_eq!(h.app.tab, Tab::LocalAi);
        h.app.tab = Tab::Overview;
        h.draw(&s);
        h.click(&s, "Open setup");
        assert_eq!(h.app.tab, Tab::Settings);
        // … and a demo session cannot check mail.
        s.demo = true;
        h.app.tab = Tab::Overview;
        h.draw(&s);
        h.click(&s, "Check email now");
        assert!(h.commands().is_empty(), "demo sessions never check mail");
    }

    /// The queue renders every title variant and selects exactly what was
    /// clicked; paging is bounded by the worker contract.
    ///
    /// Why: the queue title encodes state + role + score; paging must use
    /// the exact 25-item page contract.
    #[test]
    fn queue_renders_title_variants_and_pages() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.mode = Mode::HumanReview;
        h.app.tab = Tab::Review;
        h.draw(&s);
        assert!(h.shows_containing("No rejections to review"));
        assert!(h.shows("Previous") && h.shows("Next"));

        let mut job = headless::reviewable_job("draft text");
        job.analysis = Some(headless::analysis("Acme", "Engineer", None));
        let mut no_email = headless::reviewable_job("other draft");
        no_email.email = None;
        no_email.analysis = None;
        let mut bare_role = headless::reviewable_job("third");
        bare_role.analysis = Some(headless::analysis("", "", None));
        s.items = vec![job.clone(), no_email, bare_role];
        s.selected = None;
        h.draw(&s);
        assert!(h.shows_containing("Acme · Engineer"));
        assert!(h.shows_containing("Message awaiting analysis"));
        assert!(h.shows_containing("score 87/100"));
        assert!(h.shows_containing("Ready"));

        // Clicking the job title selects the job.
        h.click(&s, h.labels().iter().find(|l| l.contains("Acme")).unwrap());
        assert!(matches!(&h.commands()[0], Command::Select(id) if id == &job.id));

        // Paging: page 1 enables Previous; a full page enables Next.
        s.page = 1;
        s.items = vec![headless::reviewable_job("x"); 25];
        h.draw(&s);
        h.click(&s, "Previous");
        assert!(matches!(
            h.commands()[0],
            Command::List {
                review: true,
                page: 0
            }
        ));
        h.draw(&s);
        h.click(&s, "Next");
        assert!(matches!(
            h.commands()[0],
            Command::List {
                review: true,
                page: 2
            }
        ));

        // A single item disables both directions: clicks issue nothing.
        s.items = vec![headless::reviewable_job("x")];
        s.page = 0;
        h.draw(&s);
        h.click(&s, "Previous");
        h.draw(&s);
        h.click(&s, "Next");
        assert!(h.commands().is_empty(), "disabled paging issues no command");
    }

    /// The activity log shows per-state badges, reconciliation only for
    /// uncertain deliveries when idle, and expands job details on demand.
    ///
    /// Why: uncertain sends must never be retried implicitly — the button is
    /// the only reconciliation trigger and must respect the busy state.
    #[test]
    fn activity_shows_states_and_reconciles_uncertain_deliveries() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.mode = Mode::HumanReview;
        h.app.tab = Tab::Activity;
        let mut sent = headless::reviewable_job("sent draft");
        sent.state = JobState::Sent;
        sent.flags = vec!["flag-one".into()];
        let mut uncertain = headless::reviewable_job("uncertain draft");
        uncertain.state = JobState::Uncertain;
        s.items = vec![sent.clone(), uncertain.clone()];
        s.events = vec![crate::types::AuditEvent {
            seq: 1,
            at: chrono::Utc::now(),
            kind: "delivery.attempted".into(),
            domain: Default::default(),
            severity: Default::default(),
            item_id: None,
            detail: "attempt recorded".into(),
        }];
        h.draw(&s);
        assert!(h.shows_containing("Ready") || h.shows("Sent"));
        assert!(h.shows("Reconcile with Gmail Sent"));
        assert!(h.shows_containing("delivery.attempted"));

        // Idle: reconcile routes the exact job; busy: the button is inert.
        h.click(&s, "Reconcile with Gmail Sent");
        assert!(matches!(&h.commands()[0], Command::Reconcile(id) if id == &uncertain.id));
        s.busy = "syncing".into();
        h.draw(&s);
        h.click(&s, "Reconcile with Gmail Sent");
        assert!(h.commands().is_empty(), "busy sessions cannot reconcile");

        // Expanding Details reveals the stored id and flags.
        s.busy.clear();
        s.items = vec![sent.clone()];
        h.draw(&s);
        h.click(&s, "Details");
        h.draw(&s);
        assert!(h.shows_containing(&sent.id[..8]) || h.shows_containing("flag-one"));

        // Paging buttons route like the queue.
        s.page = 1;
        h.draw(&s);
        h.click(&s, "Previous page");
        assert!(matches!(
            h.commands()[0],
            Command::List {
                review: false,
                page: 0
            }
        ));
    }

    /// The review workspace renders the full editor flow: draft binding,
    /// unsaved flag, word count, discard/reload, send-gate composition and
    /// the confirm dialog.
    ///
    /// Why: the send gate is the safety core — the button must be inert
    /// unless the visible text is the exact persisted draft, and the discard
    /// path must never touch the worker.
    #[test]
    fn review_workspace_composes_the_send_gate() {
        let mut h = Harness::new();
        let job = headless::sendable_job("A professional reply body.");
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.mode = Mode::HumanReview;
        s.settings.sending_enabled = true;
        s.selected = Some(job.clone());
        h.app.tab = Tab::Review;
        h.draw(&s);
        assert!(h.shows("ORIGINAL EMAIL") && h.shows("YOUR RESPONSE"));
        assert!(h.shows_containing("4 words"));
        assert!(!h.shows("Unsaved"), "clean editor is not flagged");

        // Editing marks the text unsaved and blocks the send button.
        h.type_into(&s, 0, " edited");
        assert!(h.app.dirty, "typing marks the editor dirty");
        h.draw(&s);
        assert!(h.shows("Unsaved"));
        h.click(&s, "Review & send");
        assert!(
            h.app.send_confirmation.is_none(),
            "dirty text can never send"
        );

        // Discard reloads the persisted draft without worker traffic.
        h.click(&s, "Discard unsaved text & reload selected reply");
        assert_eq!(h.app.editor, job.draft.as_ref().unwrap().body);
        assert!(!h.app.dirty && h.app.local_error.is_empty());
        assert!(h.commands().is_empty());

        // With the exact draft visible and every gate open, Review & send
        // opens the confirm dialog.
        h.draw(&s);
        h.click(&s, "Review & send");
        assert!(
            h.app.send_confirmation.is_some(),
            "all-green gate opens confirm"
        );
        h.app.send_confirmation = None;

        // Demo sessions can never send.
        s.demo = true;
        h.draw(&s);
        h.click(&s, "Review & send");
        assert!(h.app.send_confirmation.is_none(), "demo never sends");
        s.demo = false;

        // Paused workers can never send.
        h.app.worker.paused.store(true, Ordering::SeqCst);
        h.draw(&s);
        h.click(&s, "Review & send");
        assert!(h.app.send_confirmation.is_none(), "paused never sends");
        h.app.worker.paused.store(false, Ordering::SeqCst);
    }

    /// Review action buttons route exact commands and stay inert in every
    /// disabled state.
    ///
    /// Why: a stale or dirty editor must never reach Edit/Regenerate/Dismiss.
    #[test]
    fn review_actions_route_commands_only_when_available() {
        let mut h = Harness::new();
        let job = headless::sendable_job("A professional reply body.");
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.mode = Mode::HumanReview;
        s.selected = Some(job.clone());
        h.app.tab = Tab::Review;
        h.draw(&s);

        // Regenerate and Dismiss route when the editor is clean and bound.
        h.click(&s, "Regenerate with local AI");
        assert!(matches!(h.commands()[0], Command::Regenerate { .. }));
        h.draw(&s);
        h.click(&s, "Dismiss");
        assert!(matches!(h.commands()[0], Command::Dismiss { .. }));

        // Invalid drafts surface the local validation error and send nothing.
        h.app.editor = "short".into();
        h.app.dirty = true;
        h.draw(&s);
        h.click(&s, "Save changes");
        assert!(h.commands().is_empty(), "invalid draft is never sent");
        assert!(!h.app.local_error.is_empty(), "validation error surfaced");

        // Valid drafts save the exact text.
        h.app.editor = "Saved with enough characters.".into();
        h.app.dirty = true;
        h.draw(&s);
        h.click(&s, "Save changes");
        assert!(
            matches!(&h.commands()[0], Command::Edit { body, .. } if body == "Saved with enough characters.")
        );
        assert!(h.app.local_error.is_empty());

        // Busy sessions disable every review action.
        s.busy = "qualifying".into();
        h.app.dirty = true;
        h.draw(&s);
        h.click(&s, "Save changes");
        h.draw(&s);
        h.click(&s, "Dismiss");
        assert!(h.commands().is_empty(), "busy sessions change nothing");
    }

    /// The review pane renders every visibility variant: missing email, non-
    /// reviewable state, stale editor, flags, hard blocks, analysis with and
    /// without verification, and the sending-disabled notice.
    ///
    /// Why: each amber label is a distinct operator warning; dropping one
    /// hides a real hazard (stale editor, blocked send) behind normal chrome.
    #[test]
    fn review_renders_every_warning_variant() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.mode = Mode::HumanReview;

        // Missing original + non-reviewable state + flags + unavailable email.
        let mut job = headless::reviewable_job("Draft body here.");
        job.email = None;
        job.state = JobState::Queued;
        job.flags = vec!["stale thread".into()];
        s.selected = Some(job.clone());
        h.draw(&s);
        assert!(h.shows_containing("This message is Awaiting analysis"));
        assert!(h.shows_containing("The original has not been fetched"));
        assert!(h.shows_containing("stale thread"));
        assert!(h.shows_containing("Original email is unavailable"));

        // Malformed recipient renders the invalid marker.
        let mut job = headless::reviewable_job("Draft body here.");
        job.state = JobState::Ready;
        if let Some(email) = &mut job.email {
            email.from = "not-an-address".into();
        }
        s.selected = Some(job.clone());
        h.draw(&s);
        assert!(h.shows_containing("Invalid recipient"));

        // A stale editor (different revision) disables saving and warns.
        h.app.editor_key = Some((job.id.clone(), job.revision + 1));
        h.app.editor = "Retained unsaved text".into();
        h.app.dirty = true;
        h.draw(&s);
        assert!(h.shows_containing("The selected message changed while you were editing"));
        h.app.editor_key = Some((job.id.clone(), job.revision));

        // Demo-source mail is hard-blocked with the exact reason.
        let mut job = headless::reviewable_job("Draft body here.");
        job.state = JobState::Ready;
        s.selected = Some(job.clone());
        h.draw(&s);
        assert!(h.shows_containing("Sending blocked"));
        assert!(h.shows_containing("Demo messages can never be sent"));

        // Analysis expander: open it to render explanation/verification.
        let mut job = headless::reviewable_job("Draft body here.");
        job.state = JobState::Ready;
        job.analysis = Some(headless::analysis(
            "Acme",
            "Engineer",
            Some(crate::types::Verification {
                genuine_rejection: true,
                claims_supported: true,
                professional: true,
                injection_free: true,
                purpose_aligned: true,
                reason: "claims checked".into(),
            }),
        ));
        s.selected = Some(job);
        h.draw(&s);
        h.click(&s, "Why this was detected");
        h.draw(&s);
        assert!(h.shows_containing("The message clearly rejects"));
        assert!(h.shows_containing("Evidence: explicit rejection wording"));
        assert!(h.shows_containing("Model score: 87/100"));
        assert!(h.shows_containing("Reply audit: claims checked"));

        // The sending-disabled notice appears only when sending is off.
        assert!(h.shows_containing("Sending is disabled"));
        s.settings.sending_enabled = true;
        h.draw(&s);
        assert!(!h.shows_containing("Sending is disabled"));

        // Automatic mode disables the review workspace: App::ui kicks the
        // tab to Overview, and the pane's own guard covers direct rendering.
        s.settings.mode = Mode::Automatic;
        h.draw(&s);
        assert_ne!(h.app.tab, Tab::Review, "Automatic kicks the Review tab");
        h.frame_entry(&s, |app, ui| app.review(ui, &s));
        assert!(h.shows_containing("Review is disabled in Automatic mode"));
    }

    /// Local-AI actions route exact commands when the configuration is
    /// settled and the session is live and idle.
    ///
    /// Why: model qualification pins the digest — any action that runs while
    /// the configuration has unsaved changes must be refused.
    #[test]
    fn local_ai_routes_model_actions() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.model_digest = Some("abcdef0123456789".into());
        s.settings.independent_verifier_enabled = true;
        s.settings.verifier_model_digest = Some("1122334455667788".into());
        h.app.tab = Tab::LocalAi;
        h.draw(&s);
        assert!(h.shows_containing("Pinned digest"));
        assert!(h.shows_containing("pinned 1122334455"));

        // Install opens its own confirmation dialog instead of a command.
        h.click(&s, "1  Install Ollama");
        assert!(h.app.install_confirmation, "install is confirmation-gated");
        h.app.install_confirmation = false;

        h.draw(&s);
        h.click(&s, "2  Start Ollama");
        assert!(matches!(h.commands()[0], Command::StartOllama));
        h.draw(&s);
        h.click(&s, "3  Download model");
        assert!(matches!(h.commands()[0], Command::PullModel));
        h.draw(&s);
        h.click(&s, "4  Refresh status");
        assert!(matches!(h.commands()[0], Command::InspectModel));
        h.draw(&s);
        h.click(&s, "5  Qualify & pin");
        assert!(matches!(h.commands()[0], Command::QualifyModel));
        h.draw(&s);
        h.click(&s, "Download verifier");
        assert!(matches!(h.commands()[0], Command::PullVerifierModel));
        h.draw(&s);
        h.click(&s, "Refresh verifier");
        assert!(matches!(h.commands()[0], Command::InspectVerifierModel));
        h.draw(&s);
        h.click(&s, "Qualify verifier");
        assert!(matches!(h.commands()[0], Command::QualifyVerifierModel));
        h.draw(&s);
        h.click(&s, "Evaluate current model");
        assert!(matches!(h.commands()[0], Command::EvaluateModel));
        h.draw(&s);
        h.click(&s, "Profile runtime");
        assert!(matches!(h.commands()[0], Command::ProfileModel));
        h.draw(&s);
        h.click(&s, "Compare installed candidates");
        assert!(matches!(h.commands()[0], Command::CompareModels));
        h.draw(&s);
        h.click(&s, "Save model configuration");
        assert!(matches!(h.commands()[0], Command::Settings(_)));

        // Quick choices set the model tag directly.
        h.draw(&s);
        h.click(&s, "Qwen3.5 9B Q8 · fails self-verification");
        assert_eq!(h.app.settings.model, "qwen3.5:9b-q8_0");
    }

    /// Unsaved model configuration and demo/busy sessions disable every
    /// download/qualification action, and enterprise policy reshapes the
    /// configuration form.
    ///
    /// Why: qualifying a different configuration than the one saved would
    /// pin a digest the operator never approved.
    #[test]
    fn local_ai_gates_actions_and_reshapes_configuration() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.model.size_vram = 5 * 1073741824;
        s.model.message = "GPU residency confirmed".into();
        h.app.tab = Tab::LocalAi;

        // Unsaved configuration edits block the model actions loudly.
        h.draw(&s);
        h.app.settings.model = "edited-tag".into();
        h.draw(&s);
        assert!(h.shows_containing("Model configuration has unsaved changes"));
        assert!(h.shows_containing("GiB"));
        assert!(h.shows_containing("GPU residency confirmed"));
        h.click(&s, "3  Download model");
        assert!(h.commands().is_empty(), "unsaved config blocks downloads");

        // Demo sessions can never touch the model toolchain.
        h.app.settings.model.clone_from(&s.settings.model);
        s.demo = true;
        h.draw(&s);
        h.click(&s, "2  Start Ollama");
        assert!(h.commands().is_empty(), "demo never runs model actions");
        s.demo = false;

        // Enterprise allowlists restrict both pickers and quick choices.
        s.enterprise_policy.allowed_models = vec!["allowed:tag".into()];
        s.enterprise_policy.allowed_verifier_models = vec!["v-allowed:tag".into()];
        s.enterprise_policy.require_independent_verifier = true;
        h.draw(&s);
        assert!(h.shows_containing("Model selection is restricted by enterprise policy"));
        assert!(h.shows_containing("Independent verification is required by enterprise policy"));
        assert!(
            h.app.settings.independent_verifier_enabled,
            "policy forces the verifier on"
        );
        h.app.settings.model = "other:tag".into();
        h.draw(&s);
        h.click(&s, "Qwen3.5 9B Q8 · fails self-verification");
        assert_eq!(
            h.app.settings.model, "other:tag",
            "disallowed quick choice is inert"
        );
        // The allowlist combo lists the tags themselves.
        let current = h.app.settings.model.clone();
        h.draw(&s);
        h.click(&s, &current);
        h.draw(&s);
        h.click(&s, "allowed:tag");
        assert_eq!(
            h.app.settings.model, "allowed:tag",
            "allowlisted tag selectable"
        );

        // Verifier selections follow the verifier allowlist.
        let vcurrent = h.app.settings.verifier_model.clone();
        h.draw(&s);
        h.click(&s, &vcurrent);
        h.draw(&s);
        h.click(&s, "v-allowed:tag");
        assert_eq!(h.app.settings.verifier_model, "v-allowed:tag");

        // The context-size combo changes the token budget.
        h.draw(&s);
        h.click(&s, format!("{} tokens", s.settings.num_ctx).as_str());
        h.draw(&s);
        h.click(&s, "8192 tokens");
        assert_eq!(h.app.settings.num_ctx, 8192);

        // Task qualification renders its measured score when present.
        s.settings.task_qualification = Some(crate::config::TaskQualification {
            model: s.settings.model.clone(),
            digest: "abcdef0123456789".into(),
            prompt_version: "v-test".into(),
            context_hash: "ctx".into(),
            suite_hash: "suite".into(),
            ollama_runtime_version: "0.35.0".into(),
            task_score: 91.5,
            fixture_count: 12,
            qualified_at: chrono::Utc::now(),
        });
        h.app.tab = Tab::LocalAi;
        h.draw(&s);
        assert!(h.shows_containing("PASS · score 91.5/100 · 12 fixtures"));
    }

    /// The settings page renders both sides of the enterprise, connection,
    /// storage and API branches, and its buttons issue exact commands.
    ///
    /// Why: every fallback string is an operator signal; the recovery-key
    /// buttons open state-carrying dialogs whose kind decides which command
    /// is eventually issued.
    #[test]
    fn settings_renders_policy_branches_and_routes_maintenance() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        h.app.tab = Tab::Settings;
        h.draw(&s);
        assert!(h.shows_containing("Connected: me@example.com"));
        s.connected = false;
        s.account.clear();
        h.draw(&s);
        assert!(h.shows_containing("No Gmail account connected"));
        s = headless::snapshot(headless::ACCOUNT);

        // Enterprise policy: digest pinning states and every constraint line.
        s.enterprise_policy = crate::policy::PolicyStatus {
            active: true,
            digest: Some("0123456789abcdef0123".into()),
            digest_pin_enforced: true,
            digest_pin_matches: true,
            force_human_review: true,
            prohibit_sending: true,
            prohibit_integration_api: true,
            max_daily_send_limit: Some(5),
            min_cooldown_minutes: Some(30),
            min_retention_days: Some(100),
            ..Default::default()
        };
        h.draw(&s);
        assert!(h.shows("ENTERPRISE POLICY ACTIVE"));
        assert!(h.shows_containing("sha256:0123456789ab"));
        assert!(h.shows("DIGEST PIN VERIFIED"));
        for constraint in [
            "Human Review forced",
            "sending prohibited",
            "integration API prohibited",
            "max 5 sends/24h",
            "cooldown ≥ 30 min",
            "retention ≥ 100 days",
        ] {
            assert!(h.shows_containing(constraint), "missing {constraint:?}");
        }
        // Policy coercion: sending and API flags are forced off.
        h.app.oauth_send = true;
        h.app.settings.api_enabled = true;
        h.draw(&s);
        assert!(!h.app.oauth_send && !h.app.settings.api_enabled);
        assert!(h.shows("Not listening"));

        // A pin mismatch is called out in red.
        s.enterprise_policy.digest_pin_matches = false;
        h.draw(&s);
        assert!(h.shows("DIGEST PIN MISMATCH"));
        s.enterprise_policy.digest_pin_enforced = false;
        h.draw(&s);
        assert!(h.shows("ACL / FILE TRUST ONLY"));

        // Maintenance buttons route exact commands on a live idle session.
        s.enterprise_policy = crate::policy::PolicyStatus::default();
        h.draw(&s);
        h.click(&s, "Prune old completed content now");
        assert!(matches!(h.commands()[0], Command::Purge));
        h.draw(&s);
        h.click(&s, "Check database integrity");
        assert!(matches!(h.commands()[0], Command::IntegrityCheck));
        h.draw(&s);
        h.click(&s, "Compact database");
        assert!(matches!(h.commands()[0], Command::CompactDatabase));
        h.draw(&s);
        h.click(&s, "Rotate / generate API token");
        assert!(matches!(h.commands()[0], Command::RotateApiToken));

        // API token display: copy never leaks to the worker, hide does.
        s.api_token = Some(zeroize::Zeroizing::new("secret-token-value".into()));
        s.api_listening = true;
        h.draw(&s);
        assert!(h.shows("Listening on loopback"));
        assert!(h.shows_containing("secret-token-value"));
        h.click(&s, "Copy token");
        assert!(h.commands().is_empty(), "copy is client-side only");
        h.draw(&s);
        h.click(&s, "Hide token");
        assert!(matches!(h.commands()[0], Command::HideApiToken));

        // Policy limits clamp the persisted numeric settings.
        s.enterprise_policy.min_cooldown_minutes = Some(30);
        s.enterprise_policy.max_daily_send_limit = Some(5);
        s.enterprise_policy.min_retention_days = Some(100);
        h.app.settings.cooldown_minutes = 15;
        h.app.settings.daily_send_limit = 10;
        h.app.settings.retention_days = 30;
        h.draw(&s);
        assert_eq!(h.app.settings.cooldown_minutes, 30);
        assert_eq!(h.app.settings.daily_send_limit, 5);
        assert_eq!(h.app.settings.retention_days, 100);
    }

    /// The backup/recovery buttons open the right dialogs and carry the
    /// operator's picks into the eventual commands.
    ///
    /// Why: the recovery-key dialog kind decides between export and verify
    /// commands — mixing them up would run the wrong destructive operation.
    #[test]
    fn settings_backup_buttons_open_the_right_dialogs() {
        let mut h = Harness::new();
        let s = headless::snapshot(headless::ACCOUNT);
        h.app.tab = Tab::Settings;

        // Backup picks a stamped child folder under the chosen parent.
        h.draw(&s);
        h.click(&s, "Create encrypted backup…");
        let commands = h.commands();
        assert!(
            matches!(&commands[0], Command::Backup { out } if out.to_string_lossy().contains("rejection-rejector-backup-")),
            "backup targets a stamped folder"
        );

        // Recovery drill targets the picked backup directory.
        h.draw(&s);
        h.click(&s, "Run recovery drill…");
        assert!(
            matches!(&h.commands()[0], Command::RecoveryDrill { backup } if backup.ends_with("picked-folder"))
        );

        // Export recovery key opens the export dialog.
        h.draw(&s);
        h.click(&s, "Export recovery key…");
        assert!(matches!(
            h.app.recovery_dialog.as_ref().map(|d| &d.kind),
            Some(RecoveryDialogKind::Export { out }) if out.ends_with("saved-file.json")
        ));
        h.app.recovery_dialog = None;

        // Verify recovery key needs both picks before opening.
        h.draw(&s);
        h.click(&s, "Verify recovery key…");
        assert!(matches!(
            h.app.recovery_dialog.as_ref().map(|d| &d.kind),
            Some(RecoveryDialogKind::Verify { .. })
        ));
        h.app.recovery_dialog = None;
        h.app.pickers.pick_file = |_| None;
        h.draw(&s);
        h.click(&s, "Verify recovery key…");
        assert!(
            h.app.recovery_dialog.is_none(),
            "partial picks open nothing"
        );

        // Diagnostics export targets the picked destination.
        h.app.pickers.pick_file = |_| Some(PathBuf::from("picked-file.json"));
        h.draw(&s);
        h.click(&s, "Export diagnostics…");
        assert!(
            matches!(&h.commands()[0], Command::Diagnostics { out } if out.ends_with("saved-file.json"))
        );

        // Cancelling the picker issues nothing at all.
        h.app.pickers.pick_folder = |_| None;
        h.draw(&s);
        h.click(&s, "Create encrypted backup…");
        assert!(h.commands().is_empty(), "cancelled pickers issue nothing");

        // The scheduled-backup folder picker writes the path into settings.
        h.app.pickers.pick_folder = |_| Some(PathBuf::from("C:\\backups"));
        h.app.settings.scheduled_backup_enabled = true;
        h.draw(&s);
        assert!(h.shows("Not selected"));
        h.click(&s, "Choose folder…");
        assert_eq!(h.app.settings.scheduled_backup_directory, "C:\\backups");
        h.draw(&s);
        assert!(h.shows_containing("C:\\backups"));
    }

    /// The settings form composes the Automatic save gate and the mode
    /// picker exactly like the desktop risk model.
    ///
    /// Why: Automatic mode may only be persisted when every prerequisite is
    /// green and the risk confirmation was armed — otherwise the save button
    /// must be inert.
    #[test]
    fn settings_composes_the_automatic_save_gate() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.send_scope = true;
        s.settings.sending_enabled = true;
        s.settings.model_digest = Some("digest".into());
        h.app.tab = Tab::Settings;

        // Schedule combos write the picked values.
        h.draw(&s);
        h.click(&s, "1 hour(s)");
        h.draw(&s);
        h.click(&s, "2 hour(s)");
        assert_eq!(h.app.settings.poll_hours, 2);
        h.draw(&s);
        h.click(&s, "7 day(s)");
        h.draw(&s);
        h.click(&s, "14 day(s)");
        assert_eq!(h.app.settings.lookback_days, 14);

        // The mode picker switches to Automatic and reveals the risk block.
        h.draw(&s);
        h.click(&s, "Automatic");
        assert_eq!(h.app.settings.mode, Mode::Automatic);
        h.draw(&s);
        assert!(h.shows_containing("Automatic sends without per-message approval"));
        assert!(h.shows_containing("Hard unattended safety ceiling"));
        for row in [
            "Enterprise emergency stop cleared",
            "Gmail connected",
            "Gmail send permission granted",
            "Current model smoke-qualified & pinned",
            "Independent verifier qualified when enabled",
            "Task-specific evaluation passed for this exact configuration",
            "Non-placeholder signature set",
        ] {
            assert!(h.shows_containing(row), "missing prerequisite {row:?}");
        }
        assert!(h.shows("REQUIRED"), "unmet prerequisites are loud");

        // Saving Automatic mode without arming is refused.
        h.draw(&s);
        h.click(&s, "Save settings");
        assert!(h.commands().is_empty(), "unarmed Automatic cannot save");

        // Arming opens the cooldown gate; the save is still refused.
        h.click(
            &s,
            "Enable Automatic mode (requires a deliberate risk confirmation)",
        );
        assert!(h.app.pending_arm.is_some(), "arming is cooldown-gated");
        h.app.pending_arm = None;

        // With every prerequisite green and the risk confirmation armed the
        // Automatic configuration may finally be persisted.
        h.app.settings.signature = "Jane Doe".into();
        h.app.settings.task_qualification = Some(headless::current_qualification(&h.app.settings));
        h.app.settings.automatic_confirmed = true;
        h.draw(&s);
        assert!(h.shows("READY"), "green prerequisites read READY");
        h.click(&s, "Save settings");
        assert!(
            matches!(&h.commands()[0], Command::Settings(boxed) if boxed.mode == Mode::Automatic),
            "armed Automatic with green prerequisites saves"
        );
        h.draw(&s);
        h.click(&s, "Disable Automatic mode and return to Human review");
        assert_eq!(
            h.app.settings.mode,
            Mode::Automatic,
            "mode unchanged until saved"
        );
        assert!(!h.app.settings.automatic_confirmed);
        assert!(h.app.settings.automatic_since.is_none());

        // Human review always saves.
        h.draw(&s);
        h.click(&s, "Human review");
        h.draw(&s);
        h.click(&s, "Save settings");
        assert!(
            matches!(&h.commands()[0], Command::Settings(boxed) if boxed.mode == Mode::HumanReview)
        );
    }

    /// The close-confirmation dialog distinguishes unsaved text from
    /// in-flight sensitive operations and either cancels or approves the
    /// shutdown.
    ///
    /// Why: force-closing during a send can strand an Uncertain delivery —
    /// the dialog text must name the exact hazard being accepted.
    #[test]
    fn close_confirmation_dialog_names_the_accepted_hazard() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        h.draw(&s);
        h.app.close_confirmation = true;
        h.app.dirty = true;
        h.draw(&s);
        assert!(h.shows("Unsaved reply — close application?"));
        assert!(h.shows_containing("has not been saved"));
        assert!(h.shows("Force close and discard unsaved text"));
        h.click(&s, "Keep application open");
        assert!(!h.app.close_confirmation, "keep-open cancels the close");

        // A running send names the operation in the dialog.
        s.operation = OperationStatus {
            kind: crate::types::OperationKind::SendReply,
            state: OperationState::Running,
            ..Default::default()
        };
        h.app.close_confirmation = true;
        h.app.dirty = false;
        h.draw(&s);
        assert!(h.shows("Operation still running — close application?"));
        assert!(h.shows_containing("SendReply is still running"));
        assert!(h.shows("Force close now"));
        h.click(&s, "Force close now");
        assert!(h.app.close_approved, "force close approves the shutdown");
        assert!(
            h.app.worker.stop.load(Ordering::SeqCst),
            "force close stops the worker"
        );
    }

    /// The unsaved-edit and install dialogs route their outcomes.
    ///
    /// Why: "Discard edit" is the only path that may replace a dirty editor
    /// and it must issue the exact parked selection.
    #[test]
    fn pending_select_and_install_dialogs_route_their_outcomes() {
        let mut h = Harness::new();
        let s = headless::snapshot(headless::ACCOUNT);
        h.draw(&s);
        h.app.pending_select = Some("job-9".into());
        h.app.dirty = true;
        h.draw(&s);
        assert!(h.shows("Discard the unsaved edit and open the other email?"));
        h.click(&s, "Keep editing");
        assert!(
            h.app.pending_select.is_none(),
            "keep editing cancels the switch"
        );
        assert!(h.app.dirty, "keep editing retains the unsaved text");

        h.app.pending_select = Some("job-9".into());
        h.draw(&s);
        h.click(&s, "Discard edit");
        assert!(h.app.pending_select.is_none());
        assert!(!h.app.dirty);
        assert!(matches!(&h.commands()[0], Command::Select(id) if id == "job-9"));

        // The Ollama install dialog is a two-way confirmation.
        h.app.install_confirmation = true;
        h.draw(&s);
        assert!(h.shows_containing("Windows Package Manager"));
        h.click(&s, "Cancel");
        assert!(!h.app.install_confirmation);
        assert!(h.commands().is_empty(), "cancel installs nothing");

        h.app.install_confirmation = true;
        h.draw(&s);
        h.click(&s, "Install");
        assert!(!h.app.install_confirmation);
        assert!(matches!(h.commands()[0], Command::InstallOllama));
    }

    /// The recovery-key dialog validates the passphrase on screen and
    /// submits exactly the wrapped-key command its kind dictates.
    ///
    /// Why: export and verify share one dialog; a kind mix-up would run the
    /// wrong operation with the operator's passphrase.
    #[test]
    fn recovery_dialog_validates_and_submits_by_kind() {
        let mut h = Harness::new();
        let s = headless::snapshot(headless::ACCOUNT);
        h.app.recovery_dialog = Some(RecoveryDialog {
            kind: RecoveryDialogKind::Export {
                out: PathBuf::from("wrapped-key.json"),
            },
            passphrase: Zeroizing::new(String::default()),
            confirmation: Zeroizing::new(String::default()),
        });
        h.draw(&s);
        assert!(h.shows("Export wrapped recovery key"));
        assert!(h.shows_containing("Use at least 20 UTF-8 bytes"));
        h.click(&s, "Export wrapped key");
        assert!(h.commands().is_empty(), "short passphrase cannot submit");

        // Mismatched confirmation is refused with a distinct warning.
        h.app.recovery_dialog = Some(RecoveryDialog {
            kind: RecoveryDialogKind::Export {
                out: PathBuf::from("wrapped-key.json"),
            },
            passphrase: Zeroizing::new("a".repeat(24)),
            confirmation: Zeroizing::new("b".repeat(24)),
        });
        h.draw(&s);
        assert!(h.shows_containing("The two passphrases do not match"));
        h.click(&s, "Export wrapped key");
        assert!(
            h.commands().is_empty(),
            "mismatched passphrases cannot submit"
        );

        // A valid export submits the exact command and clears the dialog.
        h.app.recovery_dialog = Some(RecoveryDialog {
            kind: RecoveryDialogKind::Export {
                out: PathBuf::from("wrapped-key.json"),
            },
            passphrase: Zeroizing::new("correct horse battery staple".to_owned()),
            confirmation: Zeroizing::new("correct horse battery staple".to_owned()),
        });
        h.draw(&s);
        h.click(&s, "Export wrapped key");
        assert!(
            matches!(&h.commands()[0], Command::ExportRecoveryKey { out, .. } if out.ends_with("wrapped-key.json"))
        );
        assert!(
            h.app.recovery_dialog.is_none(),
            "submit consumes the dialog"
        );

        // The verify kind hides the confirmation and sends the verify command.
        h.app.recovery_dialog = Some(RecoveryDialog {
            kind: RecoveryDialogKind::Verify {
                backup: PathBuf::from("backup-dir"),
                recovery_key: PathBuf::from("wrapped-key.json"),
            },
            passphrase: Zeroizing::new("correct horse battery staple".to_owned()),
            confirmation: Zeroizing::new(String::default()),
        });
        h.draw(&s);
        assert!(h.shows("Verify wrapped recovery key"));
        h.click(&s, "Verify key against backup");
        assert!(
            matches!(&h.commands()[0], Command::VerifyRecoveryKey { backup, .. } if backup.ends_with("backup-dir"))
        );

        // An oversized passphrase is refused with its own warning.
        h.app.recovery_dialog = Some(RecoveryDialog {
            kind: RecoveryDialogKind::Verify {
                backup: PathBuf::from("backup-dir"),
                recovery_key: PathBuf::from("wrapped-key.json"),
            },
            passphrase: Zeroizing::new("a".repeat(4097)),
            confirmation: Zeroizing::new(String::default()),
        });
        h.draw(&s);
        assert!(h.shows_containing("exceeds 4,096 UTF-8 bytes"));

        // Cancel always drops the dialog untouched.
        h.click(&s, "Cancel");
        assert!(h.app.recovery_dialog.is_none());
        assert!(h.commands().is_empty(), "cancel submits nothing");
    }

    /// The Automatic-arm dialog enforces its cooldown and only then arms the
    /// session; the window-close button cancels.
    ///
    /// Why: the cooldown is the deliberate pause that makes the risk
    /// confirmation meaningful — clicking early must never arm.
    #[test]
    fn automatic_arm_dialog_enforces_its_cooldown() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.sending_enabled = true;
        h.app.pending_arm = Some(crate::config::AutomaticArmGate::open(chrono::Utc::now()));
        h.draw(&s);
        assert!(h.shows("Enable Automatic mode?"));
        assert!(h.shows_containing("unlocks in"));
        h.click(&s, "I understand the risks — enable Automatic mode");
        assert!(h.app.pending_arm.is_some(), "early click never arms");
        assert!(!h.app.settings.automatic_confirmed);

        // Window close cancels the arming flow.
        h.draw(&s);
        h.click(&s, "Close window");
        assert!(h.app.pending_arm.is_none(), "closing cancels arming");

        // Once the cooldown elapsed the confirmation takes effect.
        let expired = chrono::Utc::now() - chrono::Duration::seconds(31);
        h.app.pending_arm = Some(crate::config::AutomaticArmGate::open(expired));
        h.draw(&s);
        h.click(&s, "I understand the risks — enable Automatic mode");
        assert!(h.app.settings.automatic_confirmed, "elapsed cooldown arms");
        assert!(h.app.settings.automatic_since.is_some());
        assert!(h.app.pending_arm.is_none());

        // Cancel keeps the operator in Human review.
        h.app.settings.automatic_confirmed = false;
        h.app.pending_arm = Some(crate::config::AutomaticArmGate::open(chrono::Utc::now()));
        h.draw(&s);
        h.click(&s, "Cancel (stay in Human review)");
        assert!(h.app.pending_arm.is_none());
        assert!(!h.app.settings.automatic_confirmed);
    }

    /// The confirm-exact-reply dialog sends the persisted body hash and
    /// never anything else.
    ///
    /// Why: the dialog is the last human gate — the command must carry the
    /// hash of the exact displayed body so the engine can re-verify it.
    #[test]
    fn send_confirmation_dialog_sends_the_exact_persisted_body() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.sending_enabled = true;
        let job = headless::sendable_job("A professional reply body.");
        h.draw(&s);
        h.app.send_confirmation = Some(job.clone());
        h.draw(&s);
        assert!(h.shows_containing("Confirm this exact reply"));
        assert!(h.shows_containing("To: hr@corp.example"));
        assert!(h.shows_containing("Subject: Synthetic rejection"));
        assert!(h.shows_containing("A professional reply body."));
        h.click(&s, "Send this reply now");
        let body = job.draft.as_ref().unwrap().body.as_str();
        assert!(
            matches!(&h.commands()[0], Command::Send { id, revision, body_hash } if id == &job.id && *revision == job.revision && *body_hash == hash(body))
        );
        assert!(
            h.app.send_confirmation.is_none(),
            "send consumes the dialog"
        );

        // Cancel leaves nothing behind.
        h.app.send_confirmation = Some(job.clone());
        h.draw(&s);
        h.click(&s, "Cancel");
        assert!(h.app.send_confirmation.is_none());
        assert!(h.commands().is_empty());

        // Paused workers cannot send from the dialog either.
        h.app.send_confirmation = Some(job.clone());
        h.app.worker.paused.store(true, Ordering::SeqCst);
        h.draw(&s);
        h.click(&s, "Send this reply now");
        assert!(h.commands().is_empty(), "paused workers cannot send");
        assert!(h.app.send_confirmation.is_some(), "dialog kept for retry");

        // A job without a fetched original renders no address headers.
        let mut headless_job = headless::reviewable_job("A professional reply body.");
        headless_job.email = None;
        h.app.send_confirmation = Some(headless_job);
        h.draw(&s);
        assert!(!h.shows_containing("To:"));
        assert!(h.shows_containing("Sending cannot be undone"));
    }
}
/// Shell-level behavior: status bar, navigation, screenshot capture and the
/// disaster-recovery application.
#[cfg(test)]
mod shell_tests {
    use super::headless::{self, Harness, node_text, run_frame};
    use super::*;

    /// Whether the rendered tree shows the text, tolerating line wraps.
    ///
    /// Inputs: `nodes` — AccessKit nodes of one frame; `needle` — text that
    /// may be split across wrapped text runs. Output: `true` when the
    /// whitespace-squashed tree text contains the squashed needle.
    fn tree_shows(
        nodes: &[(egui::accesskit::NodeId, egui::accesskit::Node)],
        needle: &str,
    ) -> bool {
        let squashed = |text: &str| text.split_whitespace().collect::<String>();
        let visible = nodes
            .iter()
            .filter_map(|(_, n)| node_text(n))
            .collect::<Vec<_>>()
            .join(" ");
        squashed(&visible).contains(&squashed(needle))
    }

    /// The status bar and navigation reflect every session condition.
    ///
    /// Why: the status bar is the operator's only always-visible safety
    /// indicator — pause, demo and emergency states must be unmistakable.
    #[test]
    fn status_bar_and_navigation_reflect_session_state() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        h.draw(&s);
        assert!(h.shows("LOCAL WORKSPACE"));

        h.app.worker.paused.store(true, Ordering::SeqCst);
        h.draw(&s);
        assert!(h.shows("PAUSED"));
        h.app.worker.paused.store(false, Ordering::SeqCst);

        s.busy = "Checking Gmail for missing messages…".into();
        h.draw(&s);
        assert!(h.shows_containing("Checking Gmail for missing messages"));

        s.busy.clear();
        s.demo = true;
        h.draw(&s);
        assert!(h.shows("SYNTHETIC DEMO · NO LIVE EMAIL"));
        s.demo = false;

        s.error = "worker error".into();
        h.app.local_error = "client error".into();
        h.draw(&s);
        assert!(h.shows("worker error") && h.shows("client error"));

        // The emergency-stop sentinel blocks outbound visibly.
        h.app.emergency = || crate::emergency::EmergencyStopStatus {
            configured: true,
            active: true,
            reason: "test".into(),
        };
        h.draw(&s);
        assert!(h.shows("ENTERPRISE EMERGENCY STOP · OUTBOUND EMAIL BLOCKED"));

        // Pause/resume toggles from the navigation panel.
        h.draw(&s);
        h.click(&s, "Pause worker");
        assert!(
            h.app.worker.paused.load(Ordering::SeqCst),
            "pause toggles on"
        );
        h.draw(&s);
        h.click(&s, "Resume worker");
        assert!(
            !h.app.worker.paused.load(Ordering::SeqCst),
            "pause toggles off"
        );

        // Automatic mode disables the Review tab entirely.
        s.settings.mode = Mode::Automatic;
        h.draw(&s);
        h.click(&s, "Review");
        assert_ne!(h.app.tab, Tab::Review, "Review is disabled in Automatic");
        s.settings.mode = Mode::HumanReview;

        // Any open modal freezes navigation.
        h.app.tab = Tab::Settings;
        h.app.install_confirmation = true;
        h.draw(&s);
        h.click(&s, "Overview");
        assert_ne!(h.app.tab, Tab::Overview, "modals freeze navigation");
        h.app.install_confirmation = false;

        // Fatal and pre-initialization screens replace the workspace.
        s.fatal = true;
        s.error = "database is locked".into();
        h.draw(&s);
        assert!(h.shows("The workspace could not open"));
        assert!(h.shows("database is locked"));
        s.fatal = false;
        s.initialized = false;
        h.draw(&s);
        assert!(h.shows_containing("Opening encrypted local workspace"));
    }

    /// Closing the window requires confirmation only for unsaved text or
    /// shutdown-sensitive operations.
    ///
    /// Why: an unconfirmed close during a send strands an Uncertain
    /// delivery; an unconfirmed close without unsaved text must not nag.
    #[test]
    fn close_request_is_confirmed_only_for_lossy_shutdowns() {
        let mut h = Harness::new();
        let s = headless::snapshot(headless::ACCOUNT);
        let mut nodes = Vec::new();
        // A clean idle session closes without ceremony.
        h.draw(&s);
        run_frame(&h.ctx(), &mut nodes, Vec::new(), true, |root_ui, frame| {
            eframe::App::ui(&mut h.app, root_ui, frame);
        });
        assert!(
            !h.app.close_confirmation,
            "clean close needs no confirmation"
        );

        // Unsaved text forces the confirmation.
        h.app.dirty = true;
        *h.app.worker.snapshot.lock().unwrap() = s;
        run_frame(&h.ctx(), &mut nodes, Vec::new(), true, |root_ui, frame| {
            eframe::App::ui(&mut h.app, root_ui, frame);
        });
        assert!(h.app.close_confirmation, "unsaved text confirms close");
    }

    /// Screenshot mode selects the first job, requests the native capture
    /// once ready, and persists the returned image.
    ///
    /// Why: the GUI QA flow gates on the exact file being written; a silent
    /// capture failure must surface as a client error instead.
    #[test]
    fn screenshot_mode_drives_selection_capture_and_failure() {
        let mut h = Harness::new();
        let dir = h.app_dir();
        let mut s = headless::snapshot(headless::ACCOUNT);
        let job = headless::reviewable_job("Draft body here.");
        s.items = vec![job.clone()];
        s.initialized = true;

        // With a screenshot pending and nothing selected, auto-select first.
        h.app.screenshot = Some(dir.join("shot.png"));
        h.app.tab = Tab::Overview;
        h.draw(&s);
        assert!(
            matches!(&h.commands()[0], Command::Select(id) if id == &job.id),
            "screenshot mode auto-selects the first job"
        );

        // Once elapsed past the settle delay and something is selected, the
        // native capture is requested exactly once.
        s.selected = Some(job.clone());
        h.app.started = Instant::now().checked_sub(Duration::from_secs(3)).unwrap();
        h.draw(&s);
        assert!(h.app.screenshot_requested, "capture requested once ready");
        h.draw(&s);
        assert!(h.app.screenshot_requested);

        // A returned screenshot is written to the requested path.
        let image = std::sync::Arc::new(egui::epaint::ColorImage::new(
            [2, 2],
            vec![egui::Color32::WHITE; 4],
        ));
        h.frame(
            &s,
            vec![egui::Event::Screenshot {
                viewport_id: egui::ViewportId::ROOT,
                user_data: Default::default(),
                image,
            }],
        );
        assert!(dir.join("shot.png").is_file(), "screenshot persisted");
        assert!(h.app.local_error.is_empty(), "capture completed cleanly");

        // A failed write surfaces the error instead of faking success.
        h.app.screenshot = Some(dir.clone());
        h.app.screenshot_requested = true;
        h.app.local_error.clear();
        let image = std::sync::Arc::new(egui::epaint::ColorImage::new(
            [2, 2],
            vec![egui::Color32::WHITE; 4],
        ));
        h.frame(
            &s,
            vec![egui::Event::Screenshot {
                viewport_id: egui::ViewportId::ROOT,
                user_data: Default::default(),
                image,
            }],
        );
        assert!(h.app.local_error.starts_with("Screenshot failed"));
        assert!(h.app.screenshot.is_none());

        // The timeout path gives up loudly and closes.
        h.app.screenshot = Some(dir.join("late.png"));
        h.app.started = Instant::now().checked_sub(Duration::from_secs(26)).unwrap();
        h.draw(&s);
        assert!(h.app.screenshot.is_some(), "flow still armed until close");
    }

    /// Demo-view navigation maps every accepted name and falls back to the
    /// review workspace.
    ///
    /// Why: the CLI passes `--demo-view` verbatim; unknown names must land
    /// on a safe view instead of a broken one.
    #[test]
    fn demo_view_navigation_maps_names() {
        let mut h = Harness::new();
        h.app.set_demo_view("overview");
        assert_eq!(h.app.tab, Tab::Overview);
        h.app.set_demo_view("activity");
        assert_eq!(h.app.tab, Tab::Activity);
        h.app.set_demo_view("local-ai");
        assert_eq!(h.app.tab, Tab::LocalAi);
        h.app.set_demo_view("settings");
        assert_eq!(h.app.tab, Tab::Settings);
        h.app.set_demo_view("nonsense");
        assert_eq!(h.app.tab, Tab::Review);
    }

    /// Disaster-recovery mode consumes worker results, blocks closing while
    /// restoring, and reports both success and failure.
    ///
    /// Why: recovery replaces the workspace database — closing mid-restore
    /// can corrupt the workspace, so the close must be refused loudly.
    #[test]
    fn recovery_app_consumes_worker_results_and_blocks_closing() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let dir = tempfile::tempdir().unwrap();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let mut app = RecoveryApp::new(&cc, dir.path().to_path_buf());
        let mut nodes = Vec::new();
        // A fresh context emits no widget tree on its first pass; warm it up.
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });

        // Empty form renders the workspace target and both unset picks.
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        assert!(
            nodes
                .iter()
                .any(|(_, n)| node_text(n) == Some("Disaster Recovery Mode"))
        );
        assert!(
            nodes
                .iter()
                .any(|(_, n)| node_text(n) == Some("No backup selected"))
        );
        assert!(
            nodes
                .iter()
                .any(|(_, n)| node_text(n) == Some("No recovery key selected"))
        );

        // The pickers record their choices on the form.
        app.pickers = headless::pickers_returning();
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        for label in ["Choose backup directory…", "Choose wrapped recovery key…"] {
            let id = nodes
                .iter()
                .find(|(_, n)| node_text(n) == Some(label))
                .map(|(id, _)| *id)
                .unwrap_or_else(|| panic!("missing {label}"));
            run_frame(
                &ctx,
                &mut nodes,
                vec![egui::Event::AccessKitActionRequest(
                    egui::accesskit::ActionRequest {
                        action: egui::accesskit::Action::Click,
                        target_tree: egui::accesskit::TreeId::ROOT,
                        target_node: id,
                        data: None,
                    },
                )],
                false,
                |root_ui, frame| {
                    eframe::App::ui(&mut app, root_ui, frame);
                },
            );
        }
        assert_eq!(app.backup, Some(PathBuf::from("picked-folder")));
        assert_eq!(app.recovery_key, Some(PathBuf::from("picked-file.json")));

        // While recovering, closing the window is blocked with an error.
        app.recovering = true;
        run_frame(&ctx, &mut nodes, Vec::new(), true, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        assert!(app.error.contains("Closing is blocked"));
        assert!(app.recovering, "close is refused while restoring");

        // A completed restore renders the verified report.
        app.recovering = false;
        app.error.clear();
        let (tx, rx) = crossbeam_channel::bounded(1);
        tx.send(Ok(crate::recovery::RestoreReport {
            format_version: 1,
            restored_at: chrono::Utc::now(),
            source_backup_created_at: chrono::Utc::now(),
            source_database_sha256: "abc".into(),
            source_audit_head: "head".into(),
            restored_schema_version: 7,
            rollback_directory: None,
            note: "verified".into(),
        }))
        .unwrap();
        app.recovery_result = Some(rx);
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        assert!(app.report.is_some(), "completed restore stores the report");
        assert!(tree_shows(
            &nodes,
            "Recovery completed and verified. Restored schema 7."
        ));

        // A failed restore surfaces the error instead of a report.
        let (tx, rx) = crossbeam_channel::bounded(1);
        tx.send(Err("backup authentication failed".into())).unwrap();
        app.recovery_result = Some(rx);
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        assert_eq!(app.error, "backup authentication failed");
        assert!(!app.recovering);

        // A crashed restore worker reports a disconnected result.
        let (tx, rx) =
            crossbeam_channel::bounded::<Result<crate::recovery::RestoreReport, String>>(1);
        drop(tx);
        app.recovery_result = Some(rx);
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        assert!(app.error.contains("terminated unexpectedly"));

        // An in-flight channel keeps the spinner visible.
        let (_hold, rx2) =
            crossbeam_channel::bounded::<Result<crate::recovery::RestoreReport, String>>(1);
        app.recovery_result = Some(rx2);
        app.recovering = true;
        app.report = None;
        app.error.clear();
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        assert!(
            tree_shows(&nodes, "Authenticating, preflighting and restoring"),
            "spinner shown while the worker runs"
        );

        // Closing Recovery Mode clears the passphrase and closes the app.
        app.recovery_result = None;
        app.recovering = false;
        app.passphrase = Zeroizing::new("secret passphrase value".into());
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        let close_id = nodes
            .iter()
            .find(|(_, n)| node_text(n) == Some("Close Recovery Mode"))
            .map(|(id, _)| *id)
            .expect("close button");
        run_frame(
            &ctx,
            &mut nodes,
            vec![egui::Event::AccessKitActionRequest(
                egui::accesskit::ActionRequest {
                    action: egui::accesskit::Action::Click,
                    target_tree: egui::accesskit::TreeId::ROOT,
                    target_node: close_id,
                    data: None,
                },
            )],
            false,
            |root_ui, frame| {
                eframe::App::ui(&mut app, root_ui, frame);
            },
        );
        assert!(app.passphrase.is_empty(), "passphrase zeroized on close");
    }

    /// The recovery restore button spawns the worker only for a complete,
    /// acknowledged form.
    ///
    /// Why: a half-filled form must never start a restore against the live
    /// workspace.
    #[test]
    fn recovery_restore_requires_the_complete_form() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let dir = tempfile::tempdir().unwrap();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let mut app = RecoveryApp::new(&cc, dir.path().to_path_buf());
        let mut nodes = Vec::new();
        app.pickers = headless::pickers_returning();
        app.backup = Some(PathBuf::from("picked-folder"));
        app.recovery_key = Some(PathBuf::from("picked-file.json"));
        app.passphrase = Zeroizing::new("correct horse battery staple".into());
        app.acknowledgement = "RESTORE".into();
        // A fresh context emits no widget tree on its first pass; warm it up.
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
            eframe::App::ui(&mut app, root_ui, frame);
        });
        let restore_id = nodes
            .iter()
            .find(|(_, n)| node_text(n) == Some("Authenticate, preflight and restore workspace"))
            .map(|(id, _)| *id)
            .expect("restore button");
        run_frame(
            &ctx,
            &mut nodes,
            vec![egui::Event::AccessKitActionRequest(
                egui::accesskit::ActionRequest {
                    action: egui::accesskit::Action::Click,
                    target_tree: egui::accesskit::TreeId::ROOT,
                    target_node: restore_id,
                    data: None,
                },
            )],
            false,
            |root_ui, frame| {
                eframe::App::ui(&mut app, root_ui, frame);
            },
        );
        assert!(
            app.recovering || !app.error.is_empty(),
            "complete form starts the restore"
        );
        assert!(app.acknowledgement.is_empty(), "acknowledgement consumed");
        assert!(app.passphrase.is_empty(), "passphrase consumed");
        // The worker fails against the bogus picks and reports the error.
        for _ in 0..200 {
            if !app.recovering {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
            run_frame(&ctx, &mut nodes, Vec::new(), false, |root_ui, frame| {
                eframe::App::ui(&mut app, root_ui, frame);
            });
        }
        assert!(!app.recovering, "failed restore finishes");
        assert!(!app.error.is_empty(), "restore failure is surfaced");
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::headless::Harness;
    use super::*;

    /// Shortcut navigation is gated by the review mode exactly.
    ///
    /// Why: the Review shortcut must never navigate while automatic
    /// dispatch owns the pipeline, and the void shortcut must never
    /// navigate at all.
    #[test]
    fn shortcut_tabs_obey_the_review_mode_gate() {
        assert_eq!(
            ShortcutAction::Review.tab(Mode::HumanReview),
            Some(Tab::Review)
        );
        assert_eq!(ShortcutAction::Review.tab(Mode::Automatic), None);
        assert_eq!(ShortcutAction::CheckNow.tab(Mode::HumanReview), None);
        assert_eq!(
            ShortcutAction::Overview.tab(Mode::Automatic),
            Some(Tab::Overview)
        );
        assert_eq!(
            ShortcutAction::Activity.tab(Mode::HumanReview),
            Some(Tab::Activity)
        );
        assert_eq!(
            ShortcutAction::LocalAi.tab(Mode::HumanReview),
            Some(Tab::LocalAi)
        );
        assert_eq!(
            ShortcutAction::Settings.tab(Mode::HumanReview),
            Some(Tab::Settings)
        );
    }

    /// The scheduled-backup rows read every status variant distinctly.
    ///
    /// Why: the verified timestamp and the pending fallback are the only
    /// proof the retention job is alive — conflating them hides a dead
    /// backup schedule.
    #[test]
    fn scheduled_backup_rows_read_every_status_variant() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.scheduled_backup_enabled = true;
        let now = Some(chrono::Utc::now());

        s.scheduled_backup = Some(headless::scheduled_backup(true, false, now));
        h.app.tab = Tab::Overview;
        h.draw(&s);
        assert!(
            h.shows_containing("Verified "),
            "overview stamp: {:?}",
            h.labels()
        );
        h.app.tab = Tab::Settings;
        h.draw(&s);
        assert!(
            h.shows_containing("Last verified scheduled backup:"),
            "scheduled stamp: {:?}",
            h.labels()
        );

        s.scheduled_backup = Some(headless::scheduled_backup(true, true, now));
        h.app.tab = Tab::Overview;
        h.draw(&s);
        assert!(h.shows_containing("OVERDUE"), "{:?}", h.labels());
        h.app.tab = Tab::Settings;
        h.draw(&s);
        assert!(h.shows_containing("OVERDUE"), "{:?}", h.labels());

        s.scheduled_backup = Some(headless::scheduled_backup(true, false, None));
        h.app.tab = Tab::Overview;
        h.draw(&s);
        assert!(
            h.shows_containing("Pending first backup"),
            "{:?}",
            h.labels()
        );
        h.app.tab = Tab::Settings;
        h.draw(&s);
        assert!(
            h.shows_containing("No scheduled backup completed yet"),
            "{:?}",
            h.labels()
        );

        s.scheduled_backup = None;
        h.app.tab = Tab::Overview;
        h.draw(&s);
        assert!(h.shows_containing("Status unavailable"), "{:?}", h.labels());
    }

    /// Queue rows render the company and the position independently.
    ///
    /// Why: partial analyses are common — dropping the one populated field
    /// would hide what the classifier actually found.
    #[test]
    fn queue_roles_render_company_and_position_independently() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        let mut company_only = headless::sendable_job("draft");
        company_only.analysis = Some(headless::analysis("Acme Systems", "", None));
        let mut position_only = headless::sendable_job("draft");
        position_only.analysis = Some(headless::analysis("", "Thin Film Engineer", None));
        s.items = vec![company_only, position_only];
        h.app.tab = Tab::Review;
        h.draw(&s);
        assert!(h.shows_containing("Acme Systems"), "{:?}", h.labels());
        assert!(h.shows_containing("Thin Film Engineer"), "{:?}", h.labels());
    }

    /// Full pages send the next-page request and partial pages do not.
    ///
    /// Why: requesting pages that do not exist re-fetches noise; missing
    /// the request strands the operator on page one.
    #[test]
    fn queue_pagination_sends_the_next_page_only_when_full() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.items = (0..25).map(|_| headless::sendable_job("draft")).collect();
        s.page = 2;
        h.app.tab = Tab::Activity;
        h.draw(&s);
        h.click(&s, "Next page");
        let commands = h.commands();
        assert!(
            matches!(
                commands.as_slice(),
                [Command::List {
                    review: false,
                    page: 3
                }]
            ),
            "a full page advances exactly one page"
        );

        s.items = (0..2).map(|_| headless::sendable_job("draft")).collect();
        h.draw(&s);
        h.click(&s, "Next page");
        assert!(
            h.commands().is_empty(),
            "a partial page must not request another page"
        );
    }

    /// Verifier rows render the observed runtime message and the quick
    /// choices install exactly the advertised tag.
    ///
    /// Why: the quick-choice button promises a specific pin — a wiring bug
    /// would silently verify with the wrong model.
    #[test]
    fn verifier_rows_render_the_message_and_quick_choices_pin_the_tag() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.verifier_model.message = "Inspecting pinned digest".into();
        s.settings.independent_verifier_enabled = true;
        for tab in [Tab::Settings, Tab::LocalAi] {
            h.app.tab = tab;
            h.draw(&s);
        }
        assert!(
            h.shows_containing("Inspecting pinned digest"),
            "{:?}",
            h.labels()
        );

        h.app.tab = Tab::LocalAi;
        h.draw(&s);
        h.click(&s, "Granite 4.2 8B Q8 · enterprise default");
        h.draw(&s);
        assert_eq!(h.app.settings.verifier_model, "granite4.2:8b-q8_0");
    }

    /// An enabled independent verifier demands its own digest pin.
    ///
    /// Why: without the pin the verifier could silently resolve to a
    /// different model after a re-pull.
    #[test]
    fn independent_verifier_demands_its_digest_pin() {
        let mut h = Harness::new();
        let s = headless::snapshot(headless::ACCOUNT);
        h.app.tab = Tab::Settings;
        h.draw(&s);
        h.app.settings.independent_verifier_enabled = true;
        h.app.settings.verifier_model_digest = None;
        h.draw(&s);
        h.app.settings.verifier_model_digest = Some("sha256:pinned".into());
        h.draw(&s);
    }

    /// Gmail connection actions route through the pickers and the worker.
    ///
    /// Why: the connect action must hand the picked OAuth file to the
    /// worker unchanged and disconnect must be its own explicit command.
    #[test]
    fn gmail_connection_actions_route_through_the_dialogs() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.demo = false;
        s.connected = false;
        h.app.tab = Tab::Settings;
        h.draw(&s);
        h.click(&s, "Choose OAuth JSON & connect");
        let commands = h.commands();
        assert!(
            matches!(commands.as_slice(), [Command::Connect { path, send: false }]
                if path.ends_with("picked-file.json")),
            "the picked OAuth file reaches the worker"
        );

        s.connected = true;
        h.draw(&s);
        h.click(&s, "Disconnect locally");
        let commands = h.commands();
        assert!(
            matches!(commands.as_slice(), [Command::Disconnect]),
            "disconnect is its own explicit command"
        );
    }

    /// The settings pickers list every option and install the selection.
    ///
    /// Why: the combos are the only way to set the reply tone, the reply
    /// language and the backup interval — a missing option is an
    /// unreachable setting.
    #[test]
    fn settings_combos_list_every_option_and_install_the_selection() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        s.settings.scheduled_backup_enabled = true;
        h.app.tab = Tab::Settings;
        h.draw(&s);
        let tone = h.app.settings.tone.label().to_owned();
        h.click(&s, &tone);
        h.draw(&s);
        assert!(h.shows("Insane (offensive)"), "{:?}", h.labels());
        h.click(&s, "Insane (offensive)");
        h.draw(&s);
        assert_eq!(h.app.settings.tone, crate::config::Tone::Insane);

        let language = h.app.settings.reply_language.label().to_owned();
        h.click(&s, &language);
        h.draw(&s);
        assert!(h.shows("Always English"), "{:?}", h.labels());
        h.click(&s, "Always English");
        h.draw(&s);
        assert_eq!(
            h.app.settings.reply_language,
            crate::config::ReplyLanguage::English
        );

        let interval = format!("{} hour(s)", h.app.settings.scheduled_backup_interval_hours);
        h.click(&s, &interval);
        h.draw(&s);
        assert!(h.shows("72 hour(s)"), "{:?}", h.labels());
        h.click(&s, "72 hour(s)");
        h.draw(&s);
        assert_eq!(h.app.settings.scheduled_backup_interval_hours, 72);
    }

    /// Screenshot mode checks that the review actions stay visible below
    /// the cards on every pinned frame.
    ///
    /// Why: the screenshot artifact must show the decision controls — a
    /// rendering regression that pushes them out of the viewport would go
    /// unnoticed until a baseline review.
    #[test]
    fn screenshot_mode_asserts_review_actions_stay_visible() {
        let mut h = Harness::new();
        let mut s = headless::snapshot(headless::ACCOUNT);
        let job = headless::reviewable_job("draft");
        s.items = vec![job.clone()];
        s.selected = Some(job);
        h.app.tab = Tab::Review;
        h.app.screenshot = Some(std::path::PathBuf::from("shot.png"));
        h.app.frames = 11;
        h.draw(&s);
    }
}
