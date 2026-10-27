//! Scrollable review workspace; editor actions are bound to message ID and revision.
use super::*;

impl App {
    /// Draw the Review tab for one worker snapshot.
    ///
    /// Inputs: `ui` — egui ui to draw into; `s` — worker snapshot to present.
    /// Output: none; the review flow is laid out for the current mode.
    pub(super) fn review(&mut self, ui: &mut egui::Ui, s: &Snapshot) {
        Self::heading(
            ui,
            "Review before you reply",
            "Read the original, refine your response, and send only the exact version you approve.",
        );
        if s.settings.mode != Mode::HumanReview {
            ui.label("Review is disabled in Automatic mode. Change the mode in Settings.");
            return;
        }
        let height = (ui.available_height() - 8.0).max(300.0);
        let queue_width = (ui.available_width() * 0.22).clamp(205.0, 255.0);
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(Vec2::new(queue_width, height), egui::Layout::top_down(egui::Align::Min), |ui| self.queue(ui, s));
            ui.separator();
            // A ScrollArea inherits its parent's layout. Explicitly leave the
            // outer horizontal queue layout before rendering stacked details.
            ui.allocate_ui_with_layout(Vec2::new(ui.available_width(), height), egui::Layout::top_down(egui::Align::Min), |ui| {
            egui::ScrollArea::vertical().id_salt("review_details").max_height(height).auto_shrink([false, false]).show(ui, |ui| {
                let Some(job) = s.selected.as_ref() else {
                    ui.add_space(32.0);
                    ui.heading("Select a message");
                    ui.label("Your original email and editable response will appear here.");
                    return;
                };
                let bound = editor_binding_matches(job, self.editor_key.as_ref());
                let available = bound && s.busy.is_empty() && job.state.reviewable() && !self.modal_open();
                let body_height = (height - 320.0).clamp(140.0, 250.0);
                if !job.state.reviewable() {
                    ui.colored_label(AMBER, format!("This message is {}. Select another item.", job.state.label()));
                }
            let cards = self.review_cards(ui, job, body_height, available);
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
                let send_blocks = job
                    .email
                    .as_ref()
                    .map(|email| crate::mail::hard_blocks(email, &s.account))
                    .unwrap_or_else(|| vec!["Original email is unavailable".into()]);
                if !send_blocks.is_empty() {
                    ui.colored_label(
                        AMBER,
                        format!("Sending blocked: {}", send_blocks.join("; ")),
                    );
                }
            let actions = self.review_actions(ui, job, bound, &send_blocks, s, available);
                if self.screenshot.is_some() && self.frames > 10 {
                    let geometry = (cards.rect, actions.rect, ui.clip_rect());
                    let detail = format!(
                        "cards={:?}, actions={:?}, viewport={:?}",
                        geometry.0, geometry.1, geometry.2
                    );
                    assert!(
                        review_actions_visible(geometry.0, geometry.1, geometry.2),
                        "Review controls are not below the cards and visible: {detail}"
                    );
                }
                if !s.settings.sending_enabled {
                    ui.label(RichText::new("Sending is disabled. Enable it explicitly in Settings after connecting Gmail with send permission.").small().color(MUTED));
                }
            });
            });
        });
    }

    /// Draw the two review cards: original email and reply editor.
    ///
    /// Inputs: `ui` — egui ui to draw into; `job` — selected job; `body_height` — body viewport
    /// height; `available` — whether editing is available. Output: `egui::Response` — the cards
    /// scope response for geometry checks.
    fn review_cards(
        &mut self,
        ui: &mut egui::Ui,
        job: &Job,
        body_height: f32,
        available: bool,
    ) -> egui::Response {
        ui.scope(|ui| {
            ui.columns(2, |cols| {
                Self::card(&mut cols[0], |ui| {
                    ui.set_min_height(body_height + 125.0);
                    ui.label(RichText::new("ORIGINAL EMAIL").small().color(MUTED));
                    if let Some(email) = &job.email {
                        ui.add(
                            egui::Label::new(RichText::new(&email.subject).strong().size(18.0))
                                .wrap(),
                        );
                        ui.add(egui::Label::new(RichText::new(&email.from).color(MUTED)).wrap());
                        ui.label(
                            RichText::new(
                                email
                                    .received_at
                                    .with_timezone(&chrono::Local)
                                    .format("%d %b %Y · %H:%M")
                                    .to_string(),
                            )
                            .small()
                            .color(MUTED),
                        );
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .id_salt("original_body")
                            .max_height(body_height)
                            .show(ui, |ui| {
                                ui.add(egui::Label::new(&email.text).wrap().selectable(true));
                            });
                    } else {
                        ui.label(
                            "The original has not been fetched. Regenerate to retry processing.",
                        );
                    }
                });
                Self::card(&mut cols[1], |ui| {
                    ui.set_min_height(body_height + 125.0);
                    let response_label_id = ui
                        .horizontal_wrapped(|ui| {
                            let label =
                                ui.label(RichText::new("YOUR RESPONSE").small().color(MUTED));
                            if self.dirty {
                                ui.colored_label(AMBER, "Unsaved");
                            }
                            label.id
                        })
                        .inner;
                    ui.add(
                        egui::Label::new(
                            RichText::new("Assertive. Specific. Professional.")
                                .strong()
                                .size(18.0),
                        )
                        .wrap(),
                    );
                    if let Some(email) = &job.email {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "To: {}",
                                    email
                                        .recipient()
                                        .unwrap_or_else(|_| "Invalid recipient".into())
                                ))
                                .color(MUTED),
                            )
                            .wrap(),
                        );
                    }
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt("reply_body")
                        .max_height(body_height)
                        .show(ui, |ui| {
                            let response = ui
                                .add_enabled(
                                    available,
                                    egui::TextEdit::multiline(&mut self.editor)
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(10)
                                        .font(egui::TextStyle::Body),
                                )
                                .labelled_by(response_label_id);
                            if response.changed() {
                                self.dirty = true;
                            }
                        });
                    ui.label(
                        RichText::new(format!("{} words", self.editor.split_whitespace().count()))
                            .small()
                            .color(MUTED),
                    );
                });
            });
        })
        .response
    }

    /// Draw the review action row and its send gate.
    ///
    /// Inputs: `ui` — egui ui to draw into; `job` — selected job; `bound` — whether the editor is
    /// bound to the job; `send_blocks` — mail-level sending blocks; `s` — worker snapshot;
    /// `available` — whether actions are available. Output: `egui::Response` — the actions row
    /// response for geometry checks.
    fn review_actions(
        &mut self,
        ui: &mut egui::Ui,
        job: &Job,
        bound: bool,
        send_blocks: &[String],
        s: &Snapshot,
        available: bool,
    ) -> egui::Response {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(available && self.dirty, egui::Button::new("Save changes"))
                .clicked()
            {
                match crate::mail::validate_draft(&self.editor) {
                    Ok(()) => {
                        self.local_error.clear();
                        self.worker.command(Command::Edit {
                            id: job.id.clone(),
                            revision: job.revision,
                            body: self.editor.clone(),
                        });
                    }
                    Err(error) => self.local_error = error.to_string(),
                }
            }
            if ui
                .add_enabled(
                    available && !self.dirty && !s.demo,
                    egui::Button::new("Regenerate with local AI"),
                )
                .clicked()
            {
                self.worker.command(Command::Regenerate {
                    id: job.id.clone(),
                    revision: job.revision,
                });
            }
            if ui
                .add_enabled(available && !self.dirty, egui::Button::new("Dismiss"))
                .clicked()
            {
                self.worker.command(Command::Dismiss {
                    id: job.id.clone(),
                    revision: job.revision,
                });
            }
            let can_send = !self.modal_open()
                && send_gate_eligible(
                    job,
                    &crate::engine::SendGateContext {
                        editor_text: &self.editor,
                        editor_bound: bound,
                        dirty: self.dirty,
                        hard_blocks: send_blocks,
                        busy: !s.busy.is_empty(),
                        sending_enabled: s.settings.sending_enabled,
                        demo: s.demo,
                        paused: self.worker.paused.load(Ordering::SeqCst),
                    },
                );
            if ui
                .add_enabled(
                    can_send,
                    egui::Button::new(RichText::new("Review & send").color(BG).strong()).fill(MINT),
                )
                .clicked()
            {
                self.send_confirmation = Some(job.clone());
            }
        })
        .response
    }
}

/// Actual screenshot runs call this on rendered widget rectangles, not mock coordinates.
///
/// Inputs: `cards` — rect of the review cards; `actions` — rect of the actions
/// row; `clip` — visible clip rect. Output: `bool` — `true` when the actions
/// row sits fully below the cards and inside the clip.
fn review_actions_visible(cards: egui::Rect, actions: egui::Rect, clip: egui::Rect) -> bool {
    actions.top() >= cards.bottom() - 1.0 && clip.contains_rect(actions.shrink(0.5))
}
#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn actions_must_be_below_cards_and_inside_viewport() {
        let cards = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(500.0, 300.0));
        let clip = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(500.0, 500.0));
        let below = egui::Rect::from_min_max(egui::pos2(0.0, 320.0), egui::pos2(450.0, 360.0));
        assert!(review_actions_visible(cards, below, clip));
        assert!(!review_actions_visible(
            cards,
            below.translate(egui::vec2(600.0, 0.0)),
            clip
        ));
        assert!(!review_actions_visible(
            cards,
            below.translate(egui::vec2(0.0, -100.0)),
            clip
        ));
        assert!(!review_actions_visible(
            cards,
            below.translate(egui::vec2(0.0, 200.0)),
            clip
        ));
    }
}
