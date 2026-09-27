//! Pure-policy regression tests: no network, credentials, live model or email sending.
use chrono::{DateTime, Duration, Utc};
use rejection_rejector::{
    config::{settings_context_hash, Mode, Settings, TaskQualification, PROMPT_VERSION},
    engine::{auto_blocks, automatic_policy, AutomaticPolicyCode},
    ollama,
    types::*,
};

fn eligible() -> (Job, Settings, DateTime<Utc>) {
    let now = Utc::now();
    let mut settings = Settings {
        mode: Mode::Automatic,
        sending_enabled: true,
        automatic_confirmed: true,
        automatic_since: Some(now - Duration::days(2)),
        signature: "Test Applicant".into(),
        model_digest: Some("a".repeat(64)),
        ..Settings::default()
    };
    settings.task_qualification = Some(TaskQualification {
        model: settings.model.clone(),
        digest: settings.model_digest.clone().unwrap(),
        prompt_version: PROMPT_VERSION.into(),
        context_hash: settings_context_hash(&settings),
        task_score: 100.0,
        fixture_count: 32,
        qualified_at: now - Duration::hours(2),
    });
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
            purpose_aligned: true,
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
fn policy_reason_codes_are_stable_and_machine_readable() {
    let (job, mut settings, now) = eligible();
    settings.automatic_confirmed = false;
    let decision = automatic_policy(&job, &settings, "candidate@example.com", now);
    assert!(!decision.eligible);
    assert!(decision
        .blocks
        .iter()
        .any(|block| block.code == AutomaticPolicyCode::AutomaticModeNotArmed));
    let json = serde_json::to_value(&decision).unwrap();
    assert!(json["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|block| block["code"] == "automatic_mode_not_armed"));
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
fn stale_task_qualification_holds() {
    held(|_, s, _| {
        s.task_qualification.as_mut().unwrap().context_hash = "b".repeat(64);
    });
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
fn generic_non_substantive_reply_holds() {
    held(|j, _, _| {
        j.analysis
            .as_mut()
            .unwrap()
            .verification
            .as_mut()
            .unwrap()
            .purpose_aligned = false
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
fn model_only_rejection_without_clear_language_is_held() {
    held(|j, _, _| {
        let email = j.email.as_mut().unwrap();
        email.subject = "Application update".into();
        email.text = "Thank you for your interest. We have completed our review and have an update regarding your application.".into();
        let analysis = j.analysis.as_mut().unwrap();
        analysis.verdict.category = Category::Rejection;
        analysis.verdict.confidence = 99;
        analysis.verdict.evidence = "We have completed our review".into();
        analysis.email_fingerprint = email.fingerprint();
    });
}

#[test]
fn quoted_old_rejection_does_not_authorize_automatic_reply() {
    held(|j, _, _| {
        let email = j.email.as_mut().unwrap();
        email.subject = "Interview invitation".into();
        email.text = "We would like to invite you to an interview.\nOn Tuesday Recruiter wrote:\nWe have decided not to move forward with your application.".into();
        let analysis = j.analysis.as_mut().unwrap();
        analysis.verdict.category = Category::Rejection;
        analysis.verdict.confidence = 99;
        analysis.verdict.evidence =
            "We have decided not to move forward with your application.".into();
        analysis.email_fingerprint = email.fingerprint();
    });
}

#[test]
fn replyable_auto_generated_rejection_can_still_pass_automatic_policy() {
    let (mut job, settings, now) = eligible();
    job.email
        .as_mut()
        .unwrap()
        .headers
        .insert("auto-submitted".into(), vec!["auto-generated".into()]);
    assert!(auto_blocks(&job, &settings, "candidate@example.com", now).is_empty());
}

#[test]
fn automatic_reply_loop_marker_requires_human_review() {
    held(|j, _, _| {
        j.email
            .as_mut()
            .unwrap()
            .headers
            .insert("auto-submitted".into(), vec!["auto-replied".into()]);
    });
}

#[test]
fn spam_and_trashed_mail_hold() {
    held(|j, _, _| j.email.as_mut().unwrap().labels.push("SPAM".into()));
    held(|j, _, _| j.email.as_mut().unwrap().labels.push("TRASH".into()));
}
