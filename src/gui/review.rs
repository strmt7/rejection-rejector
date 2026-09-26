//! Scrollable review workspace; editor actions are bound to message ID and revision.
use super::*;

impl App {
    pub(super) fn review(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        Self::heading(ui, "Review before you reply", "Read the original, refine your response, and send only the exact version you approve.");
        if s.settings.mode != Mode::HumanReview {
            ui.label("Review is disabled in Automatic mode. Change the mode in Settings.");
            return;
        }
        let height = (ui.available_height() - 8.0).max(300.0);
        let queue_width = (ui.available_width() * 0.22).clamp(205.0, 255.0);
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(Vec2::new(queue_width, height), egui::Layout::top_down(egui::Align::Min), |ui| self.queue(ui, s));
            ui.separator();
            egui::ScrollArea::vertical().id_salt("review_details").max_height(height).auto_shrink([false, false]).show(ui, |ui| {
                let Some(job) = s.selected.as_ref() else {
                    ui.add_space(32.0);
                    ui.heading("Select a message");
                    ui.label("Your original email and editable response will appear here.");
                    return;
                };
                let bound = editor_binding_matches(job, self.editor_key.as_ref());
                let available = bound && s.busy.is_empty() && job.state.reviewable() && !self.modal_open();
                let body_height = (height - 270.0).clamp(170.0, 310.0);
                if !job.state.reviewable() {
                    ui.colored_label(AMBER, format!("This message is {}. Select another item.", job.state.label()));
                }
                ui.columns(2, |cols| {
                    Self::card(&mut cols[0], |ui| {
                        ui.set_min_height(body_height + 150.0);
                        ui.label(RichText::new("ORIGINAL EMAIL").small().color(MUTED));
                        if let Some(email) = &job.email {
                            ui.add(egui::Label::new(RichText::new(&email.subject).strong().size(18.0)).wrap());
                            ui.add(egui::Label::new(RichText::new(&email.from).color(MUTED)).wrap());
                            ui.label(RichText::new(email.received_at.with_timezone(&chrono::Local).format("%d %b %Y · %H:%M").to_string()).small().color(MUTED));
                            ui.separator();
                            egui::ScrollArea::vertical().id_salt("original_body").max_height(body_height).show(ui, |ui| {
                                ui.add(egui::Label::new(&email.text).wrap().selectable(true));
                            });
                        } else {
                            ui.label("The original has not been fetched. Regenerate to retry processing.");
                        }
                    });
                    Self::card(&mut cols[1], |ui| {
                        ui.set_min_height(body_height + 150.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("YOUR RESPONSE").small().color(MUTED));
                            if self.dirty { ui.colored_label(AMBER, "Unsaved"); }
                        });
                        ui.add(egui::Label::new(RichText::new("Assertive. Specific. Professional.").strong().size(18.0)).wrap());
                        if let Some(email) = &job.email {
                            ui.add(egui::Label::new(RichText::new(format!("To: {}", email.recipient().unwrap_or_else(|_| "Invalid recipient".into()))).color(MUTED)).wrap());
                        }
                        ui.separator();
                        egui::ScrollArea::vertical().id_salt("reply_body").max_height(body_height).show(ui, |ui| {
                            let response = ui.add_enabled(available, egui::TextEdit::multiline(&mut self.editor).desired_width(f32::INFINITY).desired_rows(10).font(egui::TextStyle::Body));
                            if response.changed() { self.dirty = true; }
                        });
                        ui.label(RichText::new(format!("{} words", self.editor.split_whitespace().count())).small().color(MUTED));
                    });
                });
                if !bound {
                    ui.colored_label(AMBER, "The selected message changed while you were editing. Your text is retained, but cannot be saved or sent to this message.");
                }
                if self.dirty && !self.modal_open() && ui.button("Discard unsaved text & reload selected reply").clicked() {
                    self.editor = job.draft.as_ref().map(|d| d.body.clone()).unwrap_or_default();
                    self.editor_key = Some((job.id.clone(), job.revision));
                    self.dirty = false;
                    self.local_error.clear();
                }
                if let Some(a) = &job.analysis {
                    ui.collapsing("Why this was detected", |ui| {
                        ui.label(&a.verdict.explanation);
                        ui.label(format!("Evidence: {}", a.verdict.evidence));
                        ui.label(format!("Model score: {}/100 (not a calibrated probability)", a.verdict.confidence));
                        if let Some(v) = &a.verification { ui.label(format!("Reply audit: {}", v.reason)); }
                    });
                }
                for flag in &job.flags { ui.colored_label(AMBER, flag); }
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(available && self.dirty, egui::Button::new("Save changes")).clicked() {
                        match crate::mail::validate_draft(&self.editor) {
                            Ok(()) => {
                                self.local_error.clear();
                                self.worker.command(Command::Edit { id: job.id.clone(), revision: job.revision, body: self.editor.clone() });
                            },
                            Err(error) => self.local_error = error.to_string(),
                        }
                    }
                    if ui.add_enabled(available && !self.dirty && !s.demo, egui::Button::new("Regenerate with local AI")).clicked() {
                        self.worker.command(Command::Regenerate { id: job.id.clone(), revision: job.revision });
                    }
                    if ui.add_enabled(available && !self.dirty, egui::Button::new("Dismiss")).clicked() {
                        self.worker.command(Command::Dismiss { id: job.id.clone(), revision: job.revision });
                    }
                    let can_send = available && !self.dirty && visible_draft_matches(job, &self.editor) && s.settings.sending_enabled && !s.demo && !self.worker.paused.load(Ordering::SeqCst);
                    if ui.add_enabled(can_send, egui::Button::new(RichText::new("Review & send").color(BG).strong()).fill(MINT)).clicked() {
                        self.send_confirmation = Some(job.clone());
                    }
                });
                if !s.settings.sending_enabled {
                    ui.label(RichText::new("Sending is disabled. Enable it explicitly in Settings after connecting Gmail with send permission.").small().color(MUTED));
                }
            });
        });
    }
}
