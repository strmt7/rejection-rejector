//! Shared deterministic test fixtures: a scriptable loopback HTTP server and
//! canned Ollama/Gmail protocol responses. Test-only (`#[cfg(test)]` module).
// Fixture surface is consumed incrementally by each module's tests; members
// unused by one build configuration are still exercised by the full suite.
#![allow(dead_code)]
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;
use tiny_http::{Header, Response, Server};

/// One route observation: method-qualified path plus parsed JSON body when present.
pub(crate) type Call = (String, Option<Value>);

/// Scriptable loopback HTTP server for deterministic protocol tests.
///
/// The responder receives `(route, body)` and returns `Some(json)` to answer
/// 200 with that JSON document, or `None` for a 404. Every accepted request is
/// recorded in [`MockServer::calls`] so tests can assert exact wire traffic.
pub(crate) struct MockServer {
    pub url: String,
    pub calls: Arc<Mutex<Vec<Call>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    /// Start a mock server whose responses are produced by `responder`.
    pub(crate) fn new(
        responder: impl Fn(&str, Option<Value>) -> Option<Value> + Send + 'static,
    ) -> Self {
        Self::new_raw(move |route, body| {
            responder(route, body).map(|value| (200, value.to_string()))
        })
    }

    /// Start a mock server answering with exact raw bodies (streaming/NDJSON).
    ///
    /// The responder returns `Some((status, body))` for an exact response or
    /// `None` for a 404.
    pub(crate) fn new_raw(
        responder: impl Fn(&str, Option<Value>) -> Option<(u16, String)> + Send + 'static,
    ) -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let calls: Arc<Mutex<Vec<Call>>> = Arc::new(Mutex::new(Vec::new()));
        let flag = stop.clone();
        let log = calls.clone();
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(50)) else {
                    continue;
                };
                let route = request.url().split('?').next().unwrap_or("").to_owned();
                let mut raw = String::new();
                let _ = request.as_reader().read_to_string(&mut raw);
                let body = if raw.is_empty() {
                    None
                } else {
                    serde_json::from_str(&raw).ok()
                };
                let answer = responder(&route, body.clone());
                log.lock().unwrap().push((route, body));
                let response = match answer {
                    Some((status, text)) => Response::from_string(text)
                        .with_status_code(status)
                        .with_header(
                            Header::from_bytes("Content-Type", "application/json").unwrap(),
                        ),
                    None => Response::from_string("not found").with_status_code(404),
                };
                let _ = request.respond(response);
            }
        });
        Self {
            url,
            calls,
            stop,
            handle: Some(handle),
        }
    }

    /// Routes seen so far, in order.
    pub(crate) fn routes(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(route, _)| route.clone())
            .collect()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Canned `/api/version` answer for a supported runtime.
pub(crate) fn version_ok() -> Value {
    json!({"version": "0.35.1"})
}

/// Canned `/api/tags` answer advertising `model` with a fixed digest.
pub(crate) fn tags_for(model: &str, digest: &str) -> Value {
    json!({"models": [{"name": model, "digest": digest, "size": 7_200_000_000u64}]})
}

/// Canned `/api/show` answer passing local capability checks for drafting.
pub(crate) fn show_ok() -> Value {
    json!({
        "details": {"format": "gguf"},
        "model_info": {"general.architecture": "gemma4"},
        "capabilities": ["completion", "thinking"]
    })
}

/// Canned `/api/show` answer for a decision-only R&D model.
pub(crate) fn show_decision_only() -> Value {
    json!({
        "details": {"format": "gguf"},
        "model_info": {"general.architecture": "gemma4"},
        "capabilities": ["decision"]
    })
}

/// Canned `/api/ps` answer reporting full GPU residency.
pub(crate) fn ps_resident(model: &str, digest: &str) -> Value {
    json!({"models": [{"name": model, "digest": digest, "size": 7_200_000_000u64, "size_vram": 7_200_000_000u64, "context_length": 32768}]})
}

/// Canned OAuth token exchange answer with a stable refresh token.
pub(crate) fn token_ok(scope: &str) -> Value {
    json!({
        "access_token": "test-access-token",
        "expires_in": 3600,
        "refresh_token": "test-refresh-token",
        "scope": scope
    })
}

/// Build a Gmail profile answer for `address`.
pub(crate) fn gmail_profile(address: &str) -> Value {
    json!({"emailAddress": address})
}

/// The RFC 2822 message-id style provider ids accepted by `validate_id`.
pub(crate) fn provider_id(n: u64) -> String {
    format!("msg{:022}", n)
}

// ---------------------------------------------------------------------------
// Queue/job fixtures for dispatch-state tests.
// ---------------------------------------------------------------------------
use crate::config::{
    AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H, PROMPT_VERSION, Settings, evaluation_suite_hash,
    settings_context_hash,
};
use crate::types::{
    Analysis, Category, Draft, Email, Job, JobState, Source, Stub, Verdict, Verification, hash,
};
use chrono::{DateTime, Utc};

/// A sendable synthetic Gmail rejection email bound to `account`.
pub(crate) fn gmail_email(account: &str, n: u64, subject: &str, text: &str) -> Email {
    gmail_email_to(account, n, &format!("hr{n}@example.invalid"), subject, text)
}

/// Like [`gmail_email`] but with an explicit sender mailbox, so tests can share
/// or separate recipient rate-limit buckets independently of provider ids.
pub(crate) fn gmail_email_to(
    account: &str,
    n: u64,
    recipient: &str,
    subject: &str,
    text: &str,
) -> Email {
    let key = uuid::Uuid::new_v4().simple().to_string();
    Email {
        stub: Stub {
            account: account.to_owned(),
            provider_id: provider_id(n),
            thread_id: format!("thread{:022}", n),
            source: Source::Gmail,
        },
        from: format!("Recruitment <{recipient}>"),
        reply_to: None,
        subject: subject.into(),
        text: text.into(),
        received_at: Utc::now(),
        message_id: format!("<{key}@example.invalid>"),
        references: vec![],
        headers: Default::default(),
        labels: vec![],
        body_complete: true,
    }
}

/// A conflict-free draft body that ends with the trusted signature.
pub(crate) fn draft_body(signature: &str) -> String {
    format!(
        "Dear Recruitment Team,\n\nI would appreciate an individualized explanation of the specific criteria behind this decision and how my relevant experience was assessed against the advertised requirements. Please share the concrete evaluation notes for each stage, the relative weighting of the listed qualifications, and the specific areas where my background was judged insufficient for this particular position.\n\nRegards,\n{}",
        signature.trim()
    )
}

/// Analysis provenance bound to `settings` and `email`, verifying `body`.
pub(crate) fn verified_analysis(settings: &Settings, email: &Email, body: &str) -> Analysis {
    Analysis {
        verdict: Verdict {
            category: Category::Rejection,
            confidence: 99,
            evidence: "We have decided not to move forward with your application.".into(),
            explanation: "Explicit negative hiring decision".into(),
            company: String::new(),
            position: String::new(),
            language: "en".into(),
        },
        verification: Some(Verification {
            genuine_rejection: true,
            claims_supported: true,
            professional: true,
            injection_free: true,
            purpose_aligned: true,
            reason: "Synthetic verification result".into(),
        }),
        model: settings.model.clone(),
        model_digest: settings.model_digest.clone().unwrap_or_default(),
        verification_model: String::new(),
        verification_model_digest: String::new(),
        prompt_version: PROMPT_VERSION.into(),
        email_fingerprint: email.fingerprint(),
        verified_draft_hash: Some(hash(body)),
        context_hash: crate::ollama::context_hash(settings),
        input_complete: true,
        gpu_resident: true,
    }
}

/// Arm `settings` for unattended dispatch with a current task qualification.
///
/// `model_digest` is pinned first, so the computed qualification is current
/// against the returned configuration.
pub(crate) fn arm_automatic(settings: &mut Settings) {
    settings.mode = crate::config::Mode::Automatic;
    settings.sending_enabled = true;
    settings.automatic_confirmed = true;
    settings.include_backlog = true;
    settings.automatic_since = Some(Utc::now());
    settings.model_digest = Some("a".repeat(64));
    settings.signature = "Test Applicant".into();
    settings.task_qualification = Some(crate::config::TaskQualification {
        model: settings.model.clone(),
        digest: settings.model_digest.clone().unwrap(),
        prompt_version: PROMPT_VERSION.into(),
        context_hash: settings_context_hash(settings),
        suite_hash: evaluation_suite_hash(),
        ollama_runtime_version: "0.35.1".into(),
        task_score: 96.0,
        fixture_count: 40,
        qualified_at: Utc::now(),
    });
}

/// A job that passes `automatic_policy` with zero blocks under `settings`.
///
/// `settings` must be armed via [`arm_automatic`]. The cooldown is satisfied by
/// dating the draft an hour before `now`. `n` selects the provider identity and
/// thus the recipient mailbox (`hr{n}@example.invalid`).
pub(crate) fn eligible_job(settings: &Settings, account: &str, n: u64, now: DateTime<Utc>) -> Job {
    let email = gmail_email(
        account,
        n,
        "Your application — R&D Engineer",
        "Thank you for applying. We have decided not to move forward with your application.",
    );
    let body = draft_body(&settings.signature);
    let mut job = Job::new(email.stub.clone(), now);
    job.email = Some(email);
    job.analysis = Some(verified_analysis(
        settings,
        job.email.as_ref().unwrap(),
        &body,
    ));
    job.draft = Some(Draft {
        body,
        origin: "ollama-v1".into(),
    });
    job.drafted_at = Some(now - chrono::Duration::hours(1));
    job.state = JobState::Ready;
    job
}

/// The per-recipient automatic burst limit, re-exported for assertions.
pub(crate) fn recipient_limit() -> u64 {
    u64::from(AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H)
}

/// Process-wide stand-in for the Ollama installer command.
///
/// Worker dispatch runs commands on its own thread, so the substitution must
/// be global rather than thread-local; only the `Command::InstallOllama`
/// dispatch test arms it, and it is always cleared when the body returns.
type Installer = fn() -> anyhow::Result<()>;

static INSTALLER: Mutex<Option<Installer>> = Mutex::new(None);

/// Run `body` with `runner` substituted for the Ollama installer. The
/// substitution is dropped even when `body` panics, so a failing test cannot
/// leak it into another test.
pub(crate) fn with_installer<T>(runner: Installer, body: impl FnOnce() -> T) -> T {
    struct ClearOnDrop;
    impl Drop for ClearOnDrop {
        fn drop(&mut self) {
            *INSTALLER.lock().unwrap() = None;
        }
    }
    *INSTALLER.lock().unwrap() = Some(runner);
    let _clear = ClearOnDrop;
    body()
}

/// The installer stand-in armed by `with_installer`, if any.
pub(crate) fn installer_override() -> Option<Installer> {
    *INSTALLER.lock().unwrap()
}
