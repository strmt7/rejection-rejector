//! Native desktop UI. Network/database/model work stays on the bounded background worker.
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

const BG: Color32 = Color32::from_rgb(15, 20, 28);
const PANEL: Color32 = Color32::from_rgb(22, 29, 39);
const LINE: Color32 = Color32::from_rgb(47, 59, 74);
const MINT: Color32 = Color32::from_rgb(103, 225, 186);
const MUTED: Color32 = Color32::from_rgb(150, 167, 187);
const AMBER: Color32 = Color32::from_rgb(245, 193, 103);

fn configure_theme(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.override_text_color = Some(Color32::from_rgb(222, 231, 240));
    style.visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(34, 44, 58);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(47, 65, 79);
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = BG;
    style.visuals.faint_bg_color = PANEL;
    style.visuals.selection.bg_fill = Color32::from_rgb(29, 81, 72);
    style.visuals.selection.stroke = egui::Stroke::new(1.0_f32, MINT);
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, LINE);
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(34, 44, 58);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(47, 65, 79);
    style.spacing.item_spacing = Vec2::new(12.0, 12.0);
    style.spacing.button_padding = Vec2::new(14.0, 9.0);
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(15.0));
    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(27.0));
    style
        .text_styles
        .insert(egui::TextStyle::Small, egui::FontId::proportional(12.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(14.0));
    ctx.set_style_of(egui::Theme::Dark, style);
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

fn recovery_passphrase_valid(passphrase: &str, confirmation: Option<&str>) -> bool {
    passphrase.len() >= 20 && confirmation.is_none_or(|value| value == passphrase)
}

impl ShortcutAction {
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
    send_confirmation: Option<Job>,
    install_confirmation: bool,
    recovery_dialog: Option<RecoveryDialog>,
    oauth_send: bool,
    screenshot: Option<PathBuf>,
    screenshot_requested: bool,
    frames: u32,
    local_error: String,
    started: Instant,
    editor_account: String,
    close_confirmation: bool,
    close_approved: bool,
}
impl App {
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
            editor: String::new(),
            editor_key: None,
            dirty: false,
            pending_select: None,
            send_confirmation: None,
            install_confirmation: false,
            recovery_dialog: None,
            oauth_send: false,
            screenshot,
            screenshot_requested: false,
            frames: 0,
            local_error: String::new(),
            started: Instant::now(),
            editor_account: String::new(),
            close_confirmation: false,
            close_approved: false,
        }
    }
    fn navigate(&mut self, tab: Tab) {
        self.tab = tab;
        if matches!(tab, Tab::Review | Tab::Activity) {
            self.worker.command(Command::List {
                review: tab == Tab::Review,
                page: 0,
            });
        }
    }

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

    fn heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
        ui.heading(title);
        ui.label(RichText::new(subtitle).color(MUTED));
        ui.add_space(12.0);
    }
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
    fn badge(ui: &mut egui::Ui, text: &str, color: Color32) {
        ui.label(RichText::new(text).color(color).strong());
    }
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
    fn sync_view(&mut self, s: &Snapshot) {
        if s.initialized && self.editor_account != s.account {
            self.editor_account = s.account.clone();
            self.editor.clear();
            self.editor_key = None;
            self.dirty = false;
            self.pending_select = None;
            self.send_confirmation = None;
        }
        if s.initialized && (!self.settings_loaded || s.settings_revision != self.settings_revision)
        {
            self.settings = s.settings.clone();
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
                                (true, true) => String::new(),
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
            ui.label("Provisional default: qwen3.5:9b-q8_0 · validate against the task suite before Automatic mode");
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
    fn settings(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let qualified_model_matches_draft = s.settings.model_digest.is_some()
            && self.settings.model == s.settings.model
            && self.settings.num_ctx == s.settings.num_ctx
            && self.settings.ollama_url == s.settings.ollama_url;
        let verifier_ready = !self.settings.independent_verifier_enabled
            || self.settings.verifier_model_digest.is_some();
        let task_qualification_ready = self.settings.task_qualification_current();
        let emergency_stop = crate::emergency::status_fail_closed();
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
                    && let Some(path) = rfd::FileDialog::new()
                        .add_filter("Google OAuth JSON", &["json"])
                        .pick_file()
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
                ui.checkbox(
                    &mut self.settings.automatic_confirmed,
                    "I authorize automatic replies that pass the app's checks",
                );
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
                    for t in [Tone::Firm, Tone::Strong, Tone::Reconsideration] {
                        ui.selectable_value(&mut self.settings.tone, t, t.label());
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
                    && let Some(parent) = rfd::FileDialog::new()
                        .set_title("Choose parent folder for Rejection Rejector backup")
                        .pick_folder()
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
                    && let Some(backup) = rfd::FileDialog::new()
                        .set_title("Choose a Rejection Rejector backup directory")
                        .pick_folder()
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
                    && let Some(out) = rfd::FileDialog::new()
                        .set_title("Save wrapped Rejection Rejector recovery key")
                        .set_file_name("recovery-key.json")
                        .save_file()
                {
                    self.recovery_dialog = Some(RecoveryDialog {
                        kind: RecoveryDialogKind::Export { out },
                        passphrase: Zeroizing::new(String::new()),
                        confirmation: Zeroizing::new(String::new()),
                    });
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Verify recovery key…"),
                    )
                    .on_hover_text("Proves that a wrapped recovery key and passphrase can decrypt the selected backup without installing the recovered key into the OS credential store.")
                    .clicked()
                    && let Some(backup) = rfd::FileDialog::new()
                        .set_title("Choose a Rejection Rejector backup directory")
                        .pick_folder()
                    && let Some(recovery_key) = rfd::FileDialog::new()
                        .set_title("Choose the wrapped recovery key")
                        .add_filter("Recovery key JSON", &["json"])
                        .pick_file()
                {
                    self.recovery_dialog = Some(RecoveryDialog {
                        kind: RecoveryDialogKind::Verify {
                            backup,
                            recovery_key,
                        },
                        passphrase: Zeroizing::new(String::new()),
                        confirmation: Zeroizing::new(String::new()),
                    });
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Export diagnostics…"),
                    )
                    .on_hover_text("Writes a redacted JSON report locally. No email content, account address, recipients, OAuth credentials, API token, signature or candidate facts are included.")
                    .clicked()
                    && let Some(path) = rfd::FileDialog::new()
                        .set_title("Save Rejection Rejector diagnostics")
                        .set_file_name("rejection-rejector-diagnostics.json")
                        .save_file()
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
                        && let Some(path) = rfd::FileDialog::new().pick_folder()
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
    fn dialogs(&mut self, ctx: &egui::Context, s: &Snapshot) {
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
        if self.install_confirmation {
            egui::Window::new("Install Ollama").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER,[0.0,0.0]).show(ctx,|ui|{
            ui.label("This runs the official Ollama package through Windows Package Manager. It changes this computer and may require Windows approval. The model download is a separate step.");ui.horizontal(|ui|{if ui.button("Cancel").clicked(){self.install_confirmation=false;}
if ui.button("Install").clicked(){self.install_confirmation=false;self.worker.command(Command::InstallOllama);}});
        });
        }
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
                std::mem::replace(&mut dialog.passphrase, Zeroizing::new(String::new()));
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
                    let emergency_stop = crate::emergency::status_fail_closed();
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
        egui::CentralPanel::default().frame(egui::Frame::default().fill(BG).inner_margin(24)).show(root_ui,|ui|{
            if s.fatal{ui.heading("The workspace could not open");ui.label(&s.error);ui.label("Close any other instance using this data directory. On Windows, ensure Credential Manager is available. Never replace a missing vault key for an existing database.");return;}
            if !s.initialized{ui.spinner();ui.heading("Opening encrypted local workspace…");return;}
            if self.tab==Tab::Review{self.review(ui,&s);}else{egui::ScrollArea::vertical().id_salt("main_scroll").show(ui,|ui|match self.tab{Tab::Overview=>self.overview(ui,&s),Tab::Activity=>self.activity(ui,&s),Tab::LocalAi=>self.local_ai(ui,&s),Tab::Settings=>self.settings(ui,&s),Tab::Review=>()});}
        });
        self.dialogs(&ctx, &s);
        if let Some(path) = self.screenshot.clone() {
            self.frames += 1;
            if self.started.elapsed() > Duration::from_secs(2)
                && s.selected.is_some()
                && !self.screenshot_requested
            {
                eprintln!("GUI_QA requesting native screenshot");
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
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
}

impl RecoveryApp {
    pub fn new(cc: &eframe::CreationContext<'_>, data_dir: PathBuf) -> Self {
        configure_theme(&cc.egui_ctx);
        Self {
            data_dir,
            backup: None,
            recovery_key: None,
            passphrase: Zeroizing::new(String::new()),
            acknowledgement: String::new(),
            report: None,
            recovery_result: None,
            recovering: false,
            error: String::new(),
        }
    }
}

impl eframe::App for RecoveryApp {
    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root_ui.ctx().clone();

        let completed = self.recovery_result.as_ref().and_then(|receiver| {
            match receiver.try_recv() {
                Ok(result) => Some(result),
                Err(crossbeam_channel::TryRecvError::Empty) => None,
                Err(crossbeam_channel::TryRecvError::Disconnected) => Some(Err(
                    "Recovery worker terminated unexpectedly before reporting a result".into(),
                )),
            }
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
        if self.recovering {
            ctx.request_repaint_after(Duration::from_millis(150));
            if ctx.input(|input| input.viewport().close_requested()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.error =
                    "Recovery is still running. Closing is blocked until the operation finishes."
                        .into();
            }
        }

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

                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            !self.recovering && self.report.is_none(),
                            egui::Button::new("Choose backup directory…"),
                        )
                        .clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .set_title("Choose Rejection Rejector backup directory")
                            .pick_folder()
                    {
                        self.backup = Some(path);
                        self.error.clear();
                    }
                    ui.monospace(
                        self.backup
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "No backup selected".into()),
                    );
                });

                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            !self.recovering && self.report.is_none(),
                            egui::Button::new("Choose wrapped recovery key…"),
                        )
                        .clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .set_title("Choose wrapped recovery key")
                            .add_filter("Recovery key JSON", &["json"])
                            .pick_file()
                    {
                        self.recovery_key = Some(path);
                        self.error.clear();
                    }
                    ui.monospace(
                        self.recovery_key
                            .as_ref()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "No recovery key selected".into()),
                    );
                });

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
                        "The passphrase remains only in zeroizing process memory and is cleared after every recovery attempt.",
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

                let ready = !self.recovering
                    && self.report.is_none()
                    && self.backup.is_some()
                    && self.recovery_key.is_some()
                    && self.passphrase.len() >= 20
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
                    let backup = self.backup.clone();
                    let recovery_key = self.recovery_key.clone();
                    match (backup, recovery_key) {
                        (Some(backup), Some(recovery_key)) => {
                            let data_dir = self.data_dir.clone();
                            let passphrase = std::mem::replace(
                                &mut self.passphrase,
                                Zeroizing::new(String::new()),
                            );
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
                        _ => {
                            self.error = "Recovery selections are incomplete".into();
                        }
                    }
                }

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

fn requires_close_confirmation(dirty: bool, operation: &OperationStatus) -> bool {
    dirty || (operation.state == OperationState::Running && operation.kind.shutdown_sensitive())
}

/// Only the exact persisted draft is a valid GUI send candidate.
fn visible_draft_matches(job: &Job, text: &str) -> bool {
    job.draft.as_ref().is_some_and(|d| d.body == text)
}
mod review;
impl App {
    fn modal_open(&self) -> bool {
        self.pending_select.is_some()
            || self.send_confirmation.is_some()
            || self.install_confirmation
            || self.recovery_dialog.is_some()
            || self.close_confirmation
    }
    /// Presentation-only demo navigation; CLI permits this only with --demo.
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
fn editor_binding_matches(job: &Job, key: Option<&(String, u64)>) -> bool {
    key.is_some_and(|(id, revision)| id == &job.id && *revision == job.revision)
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
