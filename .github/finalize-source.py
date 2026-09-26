"""Apply exact reviewed Rust edits once; the preparation job removes this script."""
from pathlib import Path

def replace(path, before, after):
    p = Path(path)
    text = p.read_text()
    assert text.count(before) == 1, (path, before[:120], text.count(before))
    p.write_text(text.replace(before, after))

replace('src/mail.rs', 'for name in ["from", "reply-to", "message-id"] {', 'for name in ["from", "reply-to", "message-id", "subject", "auto-submitted"] {')
replace('src/mail.rs', '    let raw = format!("From: {account}', '    validate_job_identity(job)?;\n    let raw = format!("From: {account}')
with Path('src/mail.rs').open('a') as f:
    f.write('''
/// Bind the queue record, original email and conversation before preparing a reply.
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
with Path('src/oauth.rs').open('a') as f:
    f.write('''
#[cfg(test)]
mod callback_regressions {
    #[test]
    fn duplicated_authorization_codes_are_rejected() {
        assert!(super::callback_code("/callback?state=s&code=a&code=b", "s").is_err());
    }
}
''')
replace('src/ollama.rs', '"candidate_facts":self.settings.candidate_context,"proposed_reply":body', '"candidate_facts":self.settings.candidate_context,"trusted_signature":self.settings.signature,"proposed_reply":body')
# Disable editing and all state-changing review actions when an asynchronous selection
# or revision update no longer corresponds to the text visible in the editor.
replace('src/gui.rs', 'let editable = job.state.reviewable() && s.busy.is_empty();', 'let editable = job.state.reviewable() && s.busy.is_empty() && editor_binding_matches(job, self.editor_key.as_ref());')
replace('src/gui.rs', 'let available = s.busy.is_empty() && job.state.reviewable();', '''let available = s.busy.is_empty() && job.state.reviewable()
                    && editor_binding_matches(job, self.editor_key.as_ref());
                if !editor_binding_matches(job, self.editor_key.as_ref()) {
                    ui.colored_label(AMBER, "The selected message changed while you were editing. Your text is retained, but cannot be saved or sent to this message.");
                }
                if self.dirty && ui.button("Discard unsaved text & reload selected reply").clicked() {
                    self.editor = job.draft.as_ref().map(|d|d.body.clone()).unwrap_or_default();
                    self.editor_key = Some((job.id.clone(), job.revision));
                    self.dirty = false;
                }''')
with Path('src/gui.rs').open('a') as f:
    f.write('''
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
