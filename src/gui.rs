//! Native desktop UI. Network/database/model work stays on the bounded background worker.
use crate::{
    config::{Mode, Settings, Tone, LOOKBACK_DAYS, POLL_HOURS},
    types::{hash, Job, JobState},
    worker::{Command, Snapshot, Worker},
};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::{
    path::PathBuf,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

const BG: Color32 = Color32::from_rgb(15, 20, 28);
const PANEL: Color32 = Color32::from_rgb(22, 29, 39);
const LINE: Color32 = Color32::from_rgb(47, 59, 74);
const MINT: Color32 = Color32::from_rgb(103, 225, 186);
const MUTED: Color32 = Color32::from_rgb(150, 167, 187);
const AMBER: Color32 = Color32::from_rgb(245, 193, 103);
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Review,
    Activity,
    LocalAi,
    Settings,
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
        let mut style = (*cc.egui_ctx.style()).clone();
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
        cc.egui_ctx.set_style(style);
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
                            [ui.available_width(), if role.is_empty() { 82.0 } else { 102.0 }],
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
        Self::heading(ui,"Intelligence that stays local","One Ollama model for detection, drafting and a separate verification pass. No hosted inference fallback.");
        Self::card(ui, |ui| {
            ui.heading("16 GiB GPU profile");
            ui.label("Recommended: qwen3.5:9b · 8,192-token context · one loaded model");
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
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("3  Download model"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::PullModel);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("4  Refresh status"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::InspectModel);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("5  Qualify & pin"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::QualifyModel);
                }
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo && s.settings.model_digest.is_some(),
                        egui::Button::new("Evaluate synthetic suite"),
                    )
                    .clicked()
                {
                    self.worker.command(Command::EvaluateModel);
                }
            });
        });
        ui.add_space(16.0);
        Self::card(ui, |ui| {
            ui.heading("Local model configuration");
            ui.label("Change these values, save, then qualify again. Remote endpoints and cloud tags are rejected.");
            ui.label("Ollama loopback address");
            ui.text_edit_singleline(&mut self.settings.ollama_url);
            ui.label("Installed/downloadable local model tag");
            ui.text_edit_singleline(&mut self.settings.model);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Quick choices").small().color(MUTED));
                for (label, tag) in [
                    ("Qwen3.5 9B · recommended", "qwen3.5:9b"),
                    ("gpt-oss 20B · high reasoning / tight VRAM", "gpt-oss:20b"),
                    ("Gemma 4 12B QAT · conservative", "gemma4:12b-it-qat"),
                ] {
                    if ui.small_button(label).clicked() {
                        self.settings.model = tag.into();
                    }
                }
            });
            egui::ComboBox::from_id_salt("model_context")
                .selected_text(format!("{} tokens", self.settings.num_ctx))
                .show_ui(ui, |ui| {
                    for n in [8192, 16384] {
                        ui.selectable_value(&mut self.settings.num_ctx, n, format!("{n} tokens"));
                    }
                });
            ui.horizontal(|ui| {
                ui.label("Inference timeout, seconds");
                ui.add(
                    egui::DragValue::new(&mut self.settings.llm_timeout_seconds).range(30..=1200),
                );
            });
            if ui
                .add_enabled(
                    s.busy.is_empty(),
                    egui::Button::new("Save model configuration"),
                )
                .clicked()
            {
                self.worker
                    .command(Command::Settings(self.settings.clone()));
            }
            ui.label(RichText::new("Qualification is a smoke test and an Ollama-reported residency check, not proof of peak whole-device memory or best-in-class accuracy. The evaluation button writes a timestamped JSON report into this app's local data directory; it uses synthetic fixtures only and sends no email. Test on your actual GPU and mailbox before using Automatic.").small().color(AMBER));
        });
    }
    fn settings(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        let qualified_model_matches_draft = s.settings.model_digest.is_some()
            && self.settings.model == s.settings.model
            && self.settings.num_ctx == s.settings.num_ctx
            && self.settings.ollama_url == s.settings.ollama_url;
        let signature_ready = !self.settings.signature.trim().is_empty()
            && self.settings.signature.trim() != "Your name";
        let automatic_prerequisites =
            s.connected && s.send_scope && qualified_model_matches_draft && signature_ready;
        Self::heading(
            ui,
            "Settings",
            "Explicit permissions, predictable scheduling, and control over every outgoing reply.",
        );
        Self::card(ui, |ui| {
            ui.heading("Gmail connection");
            ui.label(if s.connected {
                format!("Connected: {}", s.account)
            } else {
                "No Gmail account connected".into()
            });
            ui.label("Use your own Google Cloud OAuth Desktop app JSON. See docs/SETUP.md for the consent-screen and Gmail API steps.");
            ui.checkbox(
                &mut self.oauth_send,
                "Request permission to send replies (otherwise read-only)",
            );
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        s.busy.is_empty() && !s.demo,
                        egui::Button::new("Choose OAuth JSON & connect"),
                    )
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Google OAuth JSON", &["json"])
                        .pick_file()
                    {
                        self.worker.command(Command::Connect {
                            path,
                            send: self.oauth_send,
                        });
                    }
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
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.settings.mode, Mode::HumanReview, "Human review");
                ui.selectable_value(&mut self.settings.mode, Mode::Automatic, "Automatic");
            });
            ui.checkbox(
                &mut self.settings.sending_enabled,
                "Enable sending from this application",
            );
            if self.settings.mode == Mode::Automatic {
                ui.colored_label(AMBER,"Automatic sends without per-message approval. Ambiguous, unsafe or unverifiable cases remain held. The Review tab is disabled until you switch back.");
                ui.label(RichText::new("Automatic prerequisites").strong());
                for (label, ready) in [
                    ("Gmail connected", s.connected),
                    ("Gmail send permission granted", s.send_scope),
                    (
                        "Current model configuration qualified & pinned",
                        qualified_model_matches_draft,
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
                ui.label("Cooldown, minutes");
                ui.add(egui::DragValue::new(&mut self.settings.cooldown_minutes).range(1..=1440));
                ui.label("Maximum attempts per 24 hours");
                ui.add(egui::DragValue::new(&mut self.settings.daily_send_limit).range(1..=100));
            });
            ui.label("Signature");
            ui.text_edit_singleline(&mut self.settings.signature);
            egui::ComboBox::from_id_salt("reply_tone")
                .selected_text(self.settings.tone.label())
                .show_ui(ui, |ui| {
                    for t in [Tone::Firm, Tone::Strong, Tone::Reconsideration] {
                        ui.selectable_value(&mut self.settings.tone, t, t.label());
                    }
                });
            ui.label("Verified candidate facts (optional, at most 2,500 UTF-8 bytes)");
            ui.add(
                egui::TextEdit::multiline(&mut self.settings.candidate_context)
                    .desired_width(f32::INFINITY)
                    .desired_rows(4)
                    .hint_text(
                        "Only facts you can substantiate. Do not add credentials or passwords.",
                    ),
            );
        });
        ui.add_space(12.0);
        Self::card(ui, |ui| {
            ui.heading("Storage & integration");
            ui.label("SQLite stores authenticated encrypted payloads. Windows Credential Manager holds the master key. State/count/time indexes are not encrypted.");
            ui.horizontal(|ui| {
                ui.label("Keep completed content, days");
                ui.add(egui::DragValue::new(&mut self.settings.retention_days).range(30..=3650));
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
            ui.checkbox(
                &mut self.settings.api_enabled,
                "Enable read-only loopback integration API (restart required)",
            );
            ui.horizontal(|ui| {
                ui.label("API port");
                ui.add(egui::DragValue::new(&mut self.settings.api_port).range(1024..=65535));
                ui.label(if s.api_listening {
                    "Listening on loopback"
                } else {
                    "Not listening"
                });
            });
            if ui.button("Reveal API token for integration").clicked() {
                self.worker.command(Command::RevealApiToken);
            }
            if let Some(token) = &s.api_token {
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(token);
                    if ui.button("Copy token").clicked() {
                        ui.ctx().copy_text(token.clone());
                    }
                    if ui.button("Hide token").clicked() {
                        self.worker.command(Command::HideApiToken);
                    }
                });
                ui.label(
                    RichText::new("The on-screen token hides automatically after 60 seconds.")
                        .small()
                        .color(MUTED),
                );
            }
            ui.label(RichText::new("A copied token grants access to your local email data. Keep it private; never put it in source control.").small().color(AMBER));
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
                .command(Command::Settings(self.settings.clone()));
        }
    }
    fn dialogs(&mut self, ctx: &egui::Context, s: &Snapshot) {
        if self.close_confirmation {
            egui::Window::new("Unsaved reply — close application?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(
                        "Your edited reply has not been saved. Closing will discard this text.",
                    );
                    if ui.button("Keep editing").clicked() {
                        self.close_confirmation = false;
                    }
                    if ui.button("Discard unsaved text and close").clicked() {
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
                        if ui.button("Discard edit").clicked() {
                            if let Some(id) = self.pending_select.take() {
                                self.dirty = false;
                                self.worker.command(Command::Select(id));
                            }
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
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(250));
        let s = self.worker.view();
        self.sync_view(&s);
        if ctx.input(|i| i.viewport().close_requested()) && self.dirty && !self.close_approved {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_confirmation = true;
        }
        if self.screenshot.is_some() {
            // Screenshot mode is restricted to synthetic demo data.
            ctx.request_repaint();
            if self.frames.is_multiple_of(120) {
                eprintln!("GUI_QA initialized={} fatal={} items={} selected={} requested={} elapsed={:.1}",s.initialized,s.fatal,s.items.len(),s.selected.is_some(),self.screenshot_requested,self.started.elapsed().as_secs_f32());
            }
        }
        if self.screenshot.is_some() && s.initialized && s.selected.is_none() {
            if let Some(j) = s.items.first() {
                self.worker.command(Command::Select(j.id.clone()));
            }
        }
        egui::TopBottomPanel::bottom("status_bar")
            .frame(egui::Frame::default().fill(PANEL).inner_margin(12))
            .show(ctx, |ui| {
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
        egui::SidePanel::left("navigation").exact_width(210.0).resizable(false).frame(egui::Frame::default().fill(PANEL).inner_margin(18)).show(ctx,|ui|{
            ui.add_space(8.0);ui.label(RichText::new("RR").size(34.0).strong().color(MINT));ui.label(RichText::new("REJECTION\nREJECTOR").size(17.0).strong());ui.label(RichText::new("YOUR VOICE, RETURNED.").size(10.0).color(MUTED));ui.add_space(28.0);
            for(tab,label)in[(Tab::Overview,"Overview"),(Tab::Review,"Review"),(Tab::Activity,"Activity"),(Tab::LocalAi,"Local AI"),(Tab::Settings,"Settings")]{
                let enabled=(tab!=Tab::Review||s.settings.mode==Mode::HumanReview)&&!self.modal_open();
                if ui.add_enabled(enabled,egui::Button::new(label).selected(self.tab==tab).min_size(Vec2::new(170.0,42.0))).clicked(){self.navigate(tab);}
            }
            ui.add_space(24.0);ui.separator();ui.label(RichText::new("DELIVERY CONTROL").small().color(MUTED));
            let paused=self.worker.paused.load(Ordering::SeqCst);
            if ui.add_sized([170.0,42.0],egui::Button::new(if paused{"Resume worker"}else{"Pause worker"})).clicked(){self.worker.paused.store(!paused,Ordering::SeqCst);}
            ui.label(RichText::new("Pause blocks future dispatch. A request already sent to Gmail cannot be recalled.").small().color(MUTED));
            ui.add_space(18.0);ui.label(RichText::new(format!("v{} · Rust native",env!("CARGO_PKG_VERSION"))).small().color(MUTED));
        });
        egui::CentralPanel::default().frame(egui::Frame::default().fill(BG).inner_margin(24)).show(ctx,|ui|{
            if s.fatal{ui.heading("The workspace could not open");ui.label(&s.error);ui.label("Close any other instance using this data directory. On Windows, ensure Credential Manager is available. Never replace a missing vault key for an existing database.");return;}
            if !s.initialized{ui.spinner();ui.heading("Opening encrypted local workspace…");return;}
            if self.tab==Tab::Review{self.review(ui,&s);}else{egui::ScrollArea::vertical().id_salt("main_scroll").show(ui,|ui|match self.tab{Tab::Overview=>self.overview(ui,&s),Tab::Activity=>self.activity(ui,&s),Tab::LocalAi=>self.local_ai(ui,&s),Tab::Settings=>self.settings(ui,&s),Tab::Review=>()});}
        });
        self.dialogs(ctx, &s);
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
