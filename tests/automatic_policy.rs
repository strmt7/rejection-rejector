//! Pure-policy regression tests: no network, credentials, live model or email sending.
use chrono::{DateTime, Duration, Utc};
use rejection_rejector::{
    config::{Mode, Settings, PROMPT_VERSION},
    engine::auto_blocks,
    ollama,
    types::*,
};

fn eligible() -> (Job, Settings, DateTime<Utc>) {
    let now = Utc::now();
    let settings = Settings {
        mode: Mode::Automatic,
        sending_enabled: true,
        automatic_confirmed: true,
        automatic_since: Some(now - Duration::days(2)),
        signature: "Test Applicant".into(),
        model_digest: Some("a".repeat(64)),
        ..Settings::default()
    };
    settings.validate().unwrap();
    let mut email = ollama::sample_email(
        "Your engineer application",
        "We have decided not to move forward with your application.",
    );
    email.stub.source = Source::Gmail;
    email.stub.account = "candidate@example.com".into();
    email.from = "recruitment@example.com".into();
    email.received_at = now - Duration::hours(1);
    let draft = Draft {
        body: "Please explain the specific criteria behind this decision and how my experience was assessed.".into(),
        origin: "ollama-v1".into(),
    };
    let analysis = Analysis {
        verdict: Verdict {
            category: Category::Rejection,
            confidence: 99,
            evidence: email.text.clone(),
            explanation: "Explicit current hiring rejection".into(),
            company: String::new(),
            position: "Engineer".into(),
            language: "en".into(),
        },
        verification: Some(Verification {
            genuine_rejection: true,
            claims_supported: true,
            professional: true,
            injection_free: true,
            reason: "Synthetic passing audit".into(),
        }),
        model: settings.model.clone(),
        model_digest: settings.model_digest.clone().unwrap(),
        prompt_version: PROMPT_VERSION.into(),
        email_fingerprint: email.fingerprint(),
        verified_draft_hash: Some(hash(&draft.body)),
        context_hash: ollama::context_hash(&settings),
        input_complete: true,
        gpu_resident: true,
    };
    let mut job = Job::new(email.stub.clone(), now - Duration::hours(1));
    job.state = JobState::Ready;
    job.email = Some(email);
    job.analysis = Some(analysis);
    job.draft = Some(draft);
    job.drafted_at = Some(now - Duration::minutes(30));
    (job, settings, now)
}

fn held(change: impl FnOnce(&mut Job, &mut Settings, DateTime<Utc>)) {
    let (mut job, mut settings, now) = eligible();
    change(&mut job, &mut settings, now);
    assert!(!auto_blocks(&job, &settings, "candidate@example.com", now).is_empty());
}

#[test]
fn fully_qualified_synthetic_candidate_passes_policy_only() {
    let (job, settings, now) = eligible();
    assert!(auto_blocks(&job, &settings, "candidate@example.com", now).is_empty());
}
#[test]
fn no_automatic_consent_holds() {
    held(|_, s, _| s.automatic_confirmed = false);
}
#[test]
fn changed_draft_holds() {
    held(|j, _, _| {
        j.draft
            .as_mut()
            .unwrap()
            .body
            .push_str(" An unverified claim.")
    });
}
#[test]
fn human_edit_never_inherits_automatic_approval() {
    held(|j, _, _| j.draft.as_mut().unwrap().origin = "human".into());
}
#[test]
fn changed_candidate_facts_hold() {
    held(|_, s, _| s.candidate_context = "New unverified profile".into());
}
#[test]
fn changed_model_digest_holds() {
    held(|_, s, _| s.model_digest = Some("b".repeat(64)));
}
#[test]
fn truncated_input_holds() {
    held(|j, _, _| j.analysis.as_mut().unwrap().input_complete = false);
}
#[test]
fn non_gpu_resident_analysis_holds() {
    held(|j, _, _| j.analysis.as_mut().unwrap().gpu_resident = false);
}
#[test]
fn failed_verification_holds() {
    held(|j, _, _| {
        j.analysis
            .as_mut()
            .unwrap()
            .verification
            .as_mut()
            .unwrap()
            .claims_supported = false
    });
}
#[test]
fn cooldown_holds() {
    held(|j, _, now| j.drafted_at = Some(now));
}
#[test]
fn backlog_requires_separate_permission() {
    held(|_, s, now| s.automatic_since = Some(now));
}
#[test]
fn no_reply_recipient_holds() {
    held(|j, _, _| j.email.as_mut().unwrap().from = "no-reply@example.com".into());
}
#[test]
fn different_reply_to_holds() {
    held(|j, _, _| j.email.as_mut().unwrap().reply_to = Some("other@example.com".into()));
}
#[test]
fn lists_and_loops_hold() {
    held(|j, _, _| {
        j.email
            .as_mut()
            .unwrap()
            .headers
            .insert("list-id".into(), vec!["list.example.com".into()]);
    });
    held(|j, _, _| {
        j.email
            .as_mut()
            .unwrap()
            .headers
            .insert("auto-submitted".into(), vec!["auto-replied".into()]);
    });
}
#[test]
fn automatically_generated_incoming_mail_requires_human_review() {
    held(|j, _, _| {
        j.email
            .as_mut()
            .unwrap()
            .headers
            .insert("auto-submitted".into(), vec!["auto-generated".into()]);
    });
}

#[test]
fn spam_and_trashed_mail_hold() {
    held(|j, _, _| j.email.as_mut().unwrap().labels.push("SPAM".into()));
    held(|j, _, _| j.email.as_mut().unwrap().labels.push("TRASH".into()));
}
