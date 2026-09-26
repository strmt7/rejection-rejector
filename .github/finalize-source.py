from pathlib import Path
files = {}
def get(p):
    if p not in files: files[p] = Path(p).read_text()
    return files[p]
def replace(p, before, after):
    text = get(p)
    assert text.count(before) == 1, (p, before[:100], text.count(before))
    files[p] = text.replace(before, after)
def append(p, text): files[p] = get(p) + text
replace('src/mail.rs', 'for name in ["from", "reply-to", "message-id"] {', 'for name in ["from", "reply-to", "message-id", "subject", "auto-submitted"] {')
replace('src/mail.rs', '    let raw = format!("From: {account}', '    validate_job_identity(job)?;\n    let raw = format!("From: {account}')
append('src/mail.rs', '''
pub fn validate_job_identity(job: &Job) -> Result<()> {
    let email = job.email.as_ref().ok_or_else(|| anyhow::anyhow!("Original email is missing"))?;
    ensure!(job.id == job.stub.id() && job.id == email.stub.id()
        && job.stub.account == email.stub.account
        && job.stub.provider_id == email.stub.provider_id
        && job.stub.thread_id == email.stub.thread_id
        && job.stub.source == email.stub.source,
        "Queue, message or conversation identity mismatch; reload before replying");
    Ok(())
}
''')
replace('src/engine.rs', '        let body = &job.draft.as_ref().context("Draft is missing")?.body;', '        mail::validate_job_identity(&job)?;\n        let body = &job.draft.as_ref().context("Draft is missing")?.body;')
replace('src/engine.rs', '        for message in thread.messages {', '        ensure!(thread.messages.iter().any(|m| m.id == job.stub.provider_id), "Original message is no longer in the conversation");\n        for message in thread.messages {')
replace('src/engine.rs', '    let mut reasons = Vec::new();', '    let mut reasons = Vec::new();\n    if mail::validate_job_identity(job).is_err() { reasons.push("Queue/message identity mismatch".into()); }')
replace('src/oauth.rs', '    let q: HashMap<_, _> = pairs.into_iter().collect();', '    ensure!(pairs.iter().filter(|(k, _)| k == "code").count() == 1, "Exactly one OAuth authorization code is required");\n    let q: HashMap<_, _> = pairs.into_iter().collect();')
append('src/oauth.rs', '''
#[cfg(test)]
mod callback_regressions {
    #[test]
    fn duplicated_authorization_codes_are_rejected() {
        assert!(super::callback_code("/callback?state=s&code=a&code=b", "s").is_err());
    }
}
''')
replace('src/ollama.rs', '"candidate_facts":self.settings.candidate_context,"proposed_reply":body', '"candidate_facts":self.settings.candidate_context,"trusted_signature":self.settings.signature,"proposed_reply":body')
g='src/gui.rs'
s = get(g)
a = s.index('    fn review(')
b = s.index('    fn activity(', a)
files[g] = s[:a]+s[b:]
replace(g, '    started: Instant,', '    started: Instant,\n    editor_account: String,\n    close_confirmation: bool,\n    close_approved: bool,')
replace(g, '            started: Instant::now(),', '            started: Instant::now(),\n            editor_account: String::new(),\n            close_confirmation: false,\n            close_approved: false,')
replace(g, '        style.visuals.panel_fill = BG;', '        style.visuals.override_text_color = Some(Color32::from_rgb(222, 231, 240));\n        style.visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(34, 44, 58);\n        style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(47, 65, 79);\n        style.visuals.panel_fill = BG;')
replace(g, '    fn select(&mut self, id: String) {', '    fn select(&mut self, id: String) {\n        if self.modal_open() { return; }')
replace(g, '    fn sync_view(&mut self, s: &Snapshot) {', '''    fn sync_view(&mut self, s: &Snapshot) {
        if s.initialized && self.editor_account != s.account {
            self.editor_account = s.account.clone();
            self.editor.clear(); self.editor_key = None; self.dirty = false;
            self.pending_select = None; self.send_confirmation = None;
        }''')
replace(g, 'let enabled=tab!=Tab::Review||s.settings.mode==Mode::HumanReview;', 'let enabled=(tab!=Tab::Review||s.settings.mode==Mode::HumanReview)&&!self.modal_open();')
replace(g, '        self.sync_view(&s);', '''        self.sync_view(&s);
        if ctx.input(|i| i.viewport().close_requested()) && self.dirty && !self.close_approved {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_confirmation = true;
        }''')
replace(g, '    fn dialogs(&mut self, ctx: &egui::Context, s: &Snapshot) {', '''    fn dialogs(&mut self, ctx: &egui::Context, s: &Snapshot) {
        if self.close_confirmation {
            egui::Window::new("Unsaved reply — close application?").collapsible(false).resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                    ui.label("Your edited reply has not been saved. Closing will discard this text.");
                    if ui.button("Keep editing").clicked() { self.close_confirmation = false; }
                    if ui.button("Discard unsaved text and close").clicked() {
                        self.close_approved = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
        }''')
append(g, '''
mod review;
impl App {
    fn modal_open(&self) -> bool {
        self.pending_select.is_some() || self.send_confirmation.is_some()
            || self.install_confirmation || self.close_confirmation
    }
    /// Presentation-only demo navigation; CLI permits this only with --demo.
    pub fn set_demo_view(&mut self, name: &str) {
        self.navigate(match name {
            "overview" => Tab::Overview, "activity" => Tab::Activity,
            "local-ai" => Tab::LocalAi, "settings" => Tab::Settings,
            _ => Tab::Review,
        });
    }
}
fn editor_binding_matches(job: &Job, key: Option<&(String, u64)>) -> bool {
    key.is_some_and(|(id, revision)| id == &job.id && *revision == job.revision)
}
#[cfg(test)]
mod editor_binding_regressions {
    use super::*;
    #[test]
    fn selection_and_revision_are_both_required() {
        let email = crate::ollama::sample_email("Synthetic", "Not selected");
        let job = Job::new(email.stub, chrono::Utc::now());
        assert!(editor_binding_matches(&job, Some(&(job.id.clone(), job.revision))));
        assert!(!editor_binding_matches(&job, Some(&(job.id.clone(), job.revision + 1))));
        assert!(!editor_binding_matches(&job, Some(&("another-message".into(), job.revision))));
        assert!(!editor_binding_matches(&job, None));
    }
}
''')
for p, text in files.items(): Path(p).write_text(text)
print('Applied and checked transformations:', ', '.join(files))
