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
    ///
    /// Inputs: `responder` — maps `(path, body)` to a JSON answer, or `None` for a
    /// 404. Output: [`Self`] listening on an ephemeral loopback port.
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
    ///
    /// Inputs: `responder` — maps `(path, body)` to `Some((status, body))` for an
    /// exact response or `None` for a 404. Output: [`Self`] listening on an
    /// ephemeral loopback port.
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
                let mut raw = String::default();
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
    ///
    /// Inputs: none. Output: `Vec<String>` of the routes seen so far, in order.
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
///
/// Inputs: none. Output: [`Value`] — the canned version answer.
pub(crate) fn version_ok() -> Value {
    json!({"version": "0.35.1"})
}

/// Canned `/api/tags` answer advertising `model` with a fixed digest.
///
/// Inputs: `model` — model name to advertise; `digest` — digest to report.
/// Output: [`Value`] — the canned tags answer.
pub(crate) fn tags_for(model: &str, digest: &str) -> Value {
    json!({"models": [{"name": model, "digest": digest, "size": 7_200_000_000u64}]})
}

/// Canned `/api/show` answer passing local capability checks for drafting.
///
/// Inputs: none. Output: [`Value`] — the canned show answer.
pub(crate) fn show_ok() -> Value {
    json!({
        "details": {"format": "gguf"},
        "model_info": {"general.architecture": "gemma4"},
        "capabilities": ["completion", "thinking"]
    })
}

/// Canned OAuth token exchange answer with a stable refresh token.
///
/// Inputs: `scope` — OAuth scope string to echo. Output: [`Value`] — the
/// canned token exchange answer.
pub(crate) fn token_ok(scope: &str) -> Value {
    json!({
        "access_token": "test-access-token",
        "expires_in": 3600,
        "refresh_token": "test-refresh-token",
        "scope": scope
    })
}

/// Build a Gmail profile answer for `address`.
///
/// Inputs: `address` — mailbox address to report. Output: [`Value`] — the
/// canned profile answer.
pub(crate) fn gmail_profile(address: &str) -> Value {
    json!({"emailAddress": address, "historyId": "1"})
}

/// The RFC 2822 message-id style provider ids accepted by `validate_id`.
///
/// Inputs: `n` — sequence number distinguishing ids. Output: [`String`]
/// provider id.
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
///
/// Inputs: `account` — account key; `n` — provider id sequence number; `subject`
/// — message subject; `text` — message body. Output: [`Email`] ready for
/// analysis.
pub(crate) fn gmail_email(account: &str, n: u64, subject: &str, text: &str) -> Email {
    gmail_email_to(account, n, &format!("hr{n}@example.invalid"), subject, text)
}

/// Like [`gmail_email`] but with an explicit sender mailbox, so tests can share
/// or separate recipient rate-limit buckets independently of provider ids.
///
/// Inputs: `account` — account key; `n` — provider id sequence number; `recipient`
/// — explicit sender mailbox; `subject` — message subject; `text` — message
/// body. Output: [`Email`] like [`gmail_email`] with a chosen sender.
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
        headers: std::collections::BTreeMap::default(),
        labels: vec![],
        body_complete: true,
        security_headers_complete: true,
    }
}

/// A conflict-free draft body that ends with the trusted signature.
///
/// Inputs: `signature` — trusted signature the body must end with. Output: [`String`]
/// draft body.
pub(crate) fn draft_body(signature: &str) -> String {
    format!(
        "Dear Recruitment Team,\n\nI would appreciate an individualized explanation of the specific criteria behind this decision and how my relevant experience was assessed against the advertised requirements. Please share the concrete evaluation notes for each stage, the relative weighting of the listed qualifications, and the specific areas where my background was judged insufficient for this particular position.\n\nRegards,\n{}",
        signature.trim()
    )
}

/// Analysis provenance bound to `settings` and `email`, verifying `body`.
///
/// Inputs: `settings` — settings supplying provenance; `email` — message the
/// analysis belongs to; `body` — draft body the analysis verifies. Output: [`Analysis`]
/// bound to those inputs.
pub(crate) fn verified_analysis(settings: &Settings, email: &Email, body: &str) -> Analysis {
    Analysis {
        verdict: Verdict {
            category: Category::Rejection,
            confidence: 99,
            evidence: "We have decided not to move forward with your application.".into(),
            explanation: "Explicit negative hiring decision".into(),
            company: String::default(),
            position: String::default(),
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
        verification_model: String::default(),
        verification_model_digest: String::default(),
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
///
/// Inputs: `settings` — settings to arm in place. Output: none.
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
///
/// Inputs: `settings` — settings armed via [`arm_automatic`]; `account` —
/// account key; `n` — provider id sequence number; `now` — decision time.
/// Output: [`Job`] that passes [`automatic_policy`] with zero blocks.
pub(crate) fn eligible_job(settings: &Settings, account: &str, n: u64, now: DateTime<Utc>) -> Job {
    eligible_job_to(settings, account, n, &format!("hr{n}@example.invalid"), now)
}

/// Like [`eligible_job`] but with an explicit sender mailbox, so several jobs
/// can share one recipient and exercise the per-recipient burst limit.
///
/// Inputs: `settings` — settings armed via [`arm_automatic`]; `account` —
/// account key; `n` — provider id sequence number; `recipient` — explicit
/// sender mailbox; `now` — decision time. Output: [`Job`] built like [`eligible_job`]
/// with a chosen sender.
pub(crate) fn eligible_job_to(
    settings: &Settings,
    account: &str,
    n: u64,
    recipient: &str,
    now: DateTime<Utc>,
) -> Job {
    let email = gmail_email_to(
        account,
        n,
        recipient,
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
///
/// Inputs: none. Output: `u64` per-recipient automatic burst limit.
pub(crate) fn recipient_limit() -> u64 {
    u64::from(AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H)
}

/// Seam invocations observed in this process.
///
/// Why: on Windows/macOS the seam body is a no-op (the OS credential store
/// answers), so deleting the call in callers was an unkillable mutant there.
/// The counter makes arming observable on every platform and `live_engine`
/// asserts it moved before any live open.
static HEADLESS_SEAM_CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Install the documented headless vault input for tests that open a live
/// (non-demo) workspace.
///
/// Why: `Vault::open` derives the workspace key from `RR_VAULT_PASSPHRASE`
/// (docs/SETUP.md) on hosts without an OS credential store and from the OS
/// credential store on Windows and macOS. In-process tests cannot carry the
/// seam `tests/cli_workspace.rs` attaches to spawned commands, and mutating the
/// process environment mid-run would race concurrent environment readers in
/// parallel tests, so the vault keeps a one-shot test seam instead. The
/// installed value is constant and installation is idempotent, so worker threads opening the same vault on their own threads derive the same key.
/// Arm the documented headless vault seam where the platform needs it.
///
/// Inputs: none. Output: none; on non-Windows/macOS the process gains the
/// documented `RR_VAULT_PASSPHRASE` derivation input, and every platform
/// records the arming for test observation.
pub(crate) fn headless_vault_seam() {
    HEADLESS_SEAM_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    crate::vault::test_support::install_headless_passphrase();
}

/// Seam invocations observed so far.
///
/// Inputs: none. Output: count of `headless_vault_seam` calls in-process.
pub(crate) fn headless_vault_seam_calls() -> u32 {
    HEADLESS_SEAM_CALLS.load(std::sync::atomic::Ordering::SeqCst)
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
///
/// Inputs: `runner` — installer stand-in to arm; `body` — code to run with the
/// substitution. Output: the value `body` returns; the substitution is always
/// dropped.
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
///
/// Inputs: none. Output: `Option<Installer>` — the armed stand-in, if any.
pub(crate) fn installer_override() -> Option<Installer> {
    *INSTALLER.lock().unwrap()
}

// ---------------------------------------------------------------------------
// Thread-scoped runtime seams.
//
// Enterprise policy loading, the dispatch emergency stop, the protected audit
// checkpoint and the OAuth login all read process-wide state or launch real
// processes. Each seam below substitutes one of them only for the thread that
// arms it (`with_*` guards restore the previous value even on panic), so
// parallel tests never observe each other's substitutions and the production
// fallthrough stays byte-for-byte the real one.
// ---------------------------------------------------------------------------
use crate::oauth::Credentials;
use crate::policy::LoadedPolicy;
use std::cell::RefCell;

/// A scripted stand-in for a fail-closed runtime gate.
pub(crate) type Gate = std::sync::Arc<dyn Fn() -> anyhow::Result<()> + Send + Sync>;

/// A scripted stand-in for the enterprise policy loader; each call may answer
/// a different policy so reload transitions are observable.
pub(crate) type PolicyLoader = std::sync::Arc<dyn Fn() -> Option<LoadedPolicy> + Send + Sync>;

#[derive(Default)]
struct Seams {
    policy: Option<PolicyLoader>,
    dispatch: Option<Gate>,
    audit: Option<Gate>,
    login: Option<(Credentials, String, String)>,
    interval: Option<std::time::Duration>,
    endpoints: Option<(String, String)>,
}

thread_local! {
    static SEAMS: RefCell<Seams> = RefCell::new(Seams::default());
}

/// Process-wide seam set waiting for the next worker thread to adopt it.
static PENDING: Mutex<Option<Seams>> = Mutex::new(None);

/// Arm every seam for the worker thread the surrounding test is about to
/// spawn, plus the worker-loop timer interval override (zero makes every
/// scheduled operation fire on each loop iteration).
///
/// Inputs: the substitution set; `body` runs while the seams are pending for
/// the next thread that calls [`adopt_seams`]. Output: `body`'s result. The
/// pending set is restored afterwards even on panic.
pub(crate) fn arm_worker_seams<T>(
    policy: Option<PolicyLoader>,
    dispatch: Option<Gate>,
    audit: Option<Gate>,
    login: Option<(Credentials, String, String)>,
    interval: Option<std::time::Duration>,
    endpoints: Option<(String, String)>,
    body: impl FnOnce() -> T,
) -> T {
    let previous = PENDING.lock().unwrap().replace(Seams {
        policy,
        dispatch,
        audit,
        login,
        interval,
        endpoints,
    });
    let _restore = Restore(Some(|| {
        *PENDING.lock().unwrap() = previous;
    }));
    body()
}

/// Move the pending seam set onto the calling thread. The worker loop calls
/// this at thread start so tests can script its enterprise checks and timers.
///
/// Inputs: none. Output: none; the pending seam set is moved onto the calling
/// thread.
pub(crate) fn adopt_seams() {
    if let Some(seams) = PENDING.lock().unwrap().take() {
        SEAMS.with(|s| *s.borrow_mut() = seams);
    }
}

/// The worker-loop timer interval override armed for this thread, if any.
///
/// Inputs: none. Output: `Option<Duration>` — the armed interval override, if
/// any.
pub(crate) fn worker_interval_override() -> Option<std::time::Duration> {
    SEAMS.with(|s| s.borrow().interval)
}

/// The provider-endpoint stand-in armed for this thread, if any.
///
/// Inputs: none. Output: `Option<(String, String)>` — the armed endpoint pair,
/// if any.
pub(crate) fn gmail_endpoints() -> Option<(String, String)> {
    SEAMS.with(|s| s.borrow().endpoints.clone())
}

struct Restore<T: FnOnce()>(Option<T>);
impl<T: FnOnce()> Drop for Restore<T> {
    fn drop(&mut self) {
        if let Some(restore) = self.0.take() {
            restore();
        }
    }
}

/// Run `body` with `policy::load_optional()` substituted by `loaded`.
///
/// Inputs: `loaded` — policy answer to substitute; `body` — code to run with
/// the substitution. Output: the value `body` returns.
pub(crate) fn with_policy<T>(loaded: Option<LoadedPolicy>, body: impl FnOnce() -> T) -> T {
    with_policy_loader(std::sync::Arc::new(move || loaded.clone()), body)
}

/// Run `body` with `policy::load_optional()` substituted by a scriptable
/// loader, so successive loads can answer different policies.
///
/// Inputs: `loader` — scriptable policy loader to substitute; `body` — code to
/// run with the substitution. Output: the value `body` returns.
pub(crate) fn with_policy_loader<T>(loader: PolicyLoader, body: impl FnOnce() -> T) -> T {
    let previous = SEAMS.with(|s| s.borrow_mut().policy.replace(loader));
    let _restore = Restore(Some(|| {
        SEAMS.with(|s| s.borrow_mut().policy = previous);
    }));
    body()
}

/// The policy-loader stand-in armed for this thread, if any.
///
/// Inputs: none. Output: `Option<PolicyLoader>` — the armed loader stand-in,
/// if any.
pub(crate) fn policy_loader() -> Option<PolicyLoader> {
    SEAMS.with(|s| s.borrow().policy.clone())
}

/// Run `body` with the enterprise emergency stop substituted by `gate`.
///
/// Inputs: `gate` — emergency-stop stand-in; `body` — code to run with the
/// substitution. Output: the value `body` returns.
pub(crate) fn with_dispatch_gate<T>(gate: Gate, body: impl FnOnce() -> T) -> T {
    let previous = SEAMS.with(|s| s.borrow_mut().dispatch.replace(gate));
    let _restore = Restore(Some(|| {
        SEAMS.with(|s| s.borrow_mut().dispatch = previous);
    }));
    body()
}

/// The emergency-stop stand-in armed for this thread, if any.
///
/// Inputs: none. Output: `Option<Gate>` — the armed stand-in, if any.
pub(crate) fn dispatch_gate() -> Option<Gate> {
    SEAMS.with(|s| s.borrow().dispatch.clone())
}

/// Run `body` with the protected audit checkpoint substituted by `gate`.
///
/// Inputs: `gate` — audit-checkpoint stand-in; `body` — code to run with the
/// substitution. Output: the value `body` returns.
pub(crate) fn with_audit_gate<T>(gate: Gate, body: impl FnOnce() -> T) -> T {
    let previous = SEAMS.with(|s| s.borrow_mut().audit.replace(gate));
    let _restore = Restore(Some(|| {
        SEAMS.with(|s| s.borrow_mut().audit = previous);
    }));
    body()
}

/// The audit-checkpoint stand-in armed for this thread, if any.
///
/// Inputs: none. Output: `Option<Gate>` — the armed stand-in, if any.
pub(crate) fn audit_gate() -> Option<Gate> {
    SEAMS.with(|s| s.borrow().audit.clone())
}

/// Run `body` with the OAuth login exchanged for canned credentials bound to
/// mock `root`/`token_url` endpoints, so `Engine::connect` can complete its
/// full connection flow without a browser or Google.
///
/// Inputs: `creds` — canned OAuth credentials; `root` — mock API root; `token_url`
/// — mock token endpoint; `body` — code to run with the substitution. Output:
/// the value `body` returns.
pub(crate) fn with_login<T>(
    creds: Credentials,
    root: &str,
    token_url: &str,
    body: impl FnOnce() -> T,
) -> T {
    let previous = SEAMS.with(|s| {
        s.borrow_mut()
            .login
            .replace((creds, root.to_owned(), token_url.to_owned()))
    });
    let _restore = Restore(Some(|| {
        SEAMS.with(|s| s.borrow_mut().login = previous);
    }));
    body()
}

/// The login stand-in armed for this thread, if any.
///
/// Inputs: none. Output: `Option<(Credentials, String, String)>` — the armed
/// login stand-in, if any.
pub(crate) fn login_override() -> Option<(Credentials, String, String)> {
    SEAMS.with(|s| s.borrow().login.clone())
}

// ---------------------------------------------------------------------------
// Gmail wire fixtures for provider preflights.
// ---------------------------------------------------------------------------
use base64::Engine as _;

/// The Gmail message resource whose parsed form reproduces `email` exactly.
///
/// Inputs: `email` — synthetic message identity and content. Output: the
/// `/messages/{id}` JSON body (base64url RFC 2822 payload included), so a
/// fetch-time fingerprint check sees the same message that was queued.
pub(crate) fn gmail_resource(email: &Email) -> Value {
    let mime = format!(
        "From: {}\r\nSubject: {}\r\nMessage-ID: {}\r\n\r\n{}",
        email.from, email.subject, email.message_id, email.text
    );
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mime.as_bytes());
    json!({
        "id": email.stub.provider_id,
        "threadId": email.stub.thread_id,
        "internalDate": email.received_at.timestamp_millis().to_string(),
        "labelIds": email.labels,
        "raw": raw,
    })
}

/// The Gmail thread resource containing exactly `email` at its timestamp.
///
/// Inputs: `email` — the single message the thread contains. Output: [`Value`]
/// — the canned thread resource.
pub(crate) fn gmail_thread(email: &Email) -> Value {
    json!({"messages": [{
        "id": email.stub.provider_id,
        "internalDate": email.received_at.timestamp_millis().to_string(),
        "labelIds": ["INBOX"],
    }]})
}

/// Provider outcome scripted for the outbound send endpoint.
pub(crate) enum SendOutcome {
    /// Accept the send request and answer `id` as the delivered message.
    Deliver(String),
    /// Definitively reject the request (HTTP 400): nothing was accepted.
    Reject,
    /// Return an ambiguous server failure (HTTP 503): delivery uncertain.
    Uncertain,
}

// Uncovered-by-design lines in the mocks below carry no product signal:
// the `None` / `_ => None` route fallbacks answer 404 for wire routes the
// protocol never uses — they fire only if a test's client starts speaking
// a protocol the product does not, which is what they guard against.
/// A scripted Gmail API covering token refresh, profile, message and thread
/// fetches, Sent search and one send governed by `outcome`.
///
/// Inputs: `account` — connected mailbox; `emails` — messages served for their
/// provider/thread ids; `outcome` — scripted send result. Output: a running
/// [`MockServer`] whose routes mirror the Gmail client's wire protocol.
pub(crate) fn gmail_server(account: &str, emails: Vec<Email>, outcome: SendOutcome) -> MockServer {
    let account = account.to_owned();
    MockServer::new_raw(move |route, _body| {
        let answer = |status: u16, value: Value| Some((status, value.to_string()));
        if route == "/" {
            return answer(200, token_ok("test-scope"));
        }
        if route == "/profile" {
            return answer(200, gmail_profile(&account));
        }
        if route == "/messages/send" {
            return match &outcome {
                SendOutcome::Deliver(id) => answer(200, json!({"id": id})),
                SendOutcome::Reject => {
                    answer(400, json!({"error": {"status": "INVALID_ARGUMENT"}}))
                }
                SendOutcome::Uncertain => answer(503, json!({"error": {"status": "UNAVAILABLE"}})),
            };
        }
        if route == "/messages" {
            return answer(200, json!({"messages": []}));
        }
        if route == "/history" {
            return answer(200, json!({"history": [], "historyId": "42"}));
        }
        if let Some(id) = route.strip_prefix("/messages/") {
            return emails
                .iter()
                .find(|e| e.stub.provider_id == id)
                .and_then(|e| answer(200, gmail_resource(e)));
        }
        if let Some(id) = route.strip_prefix("/threads/") {
            return emails
                .iter()
                .find(|e| e.stub.thread_id == id)
                .and_then(|e| answer(200, gmail_thread(e)));
        }
        None
    })
}

// ---------------------------------------------------------------------------
// Local model-runtime fixtures.
// ---------------------------------------------------------------------------

/// A deterministic loaded policy for startup/reload flows.
///
/// Inputs: `digest` — the content identity the engine compares across
/// reloads; `policy` — the constraint document. Output: a [`LoadedPolicy`]
/// with no external signature controls.
pub(crate) fn loaded_policy(digest: &str, policy: crate::policy::EnterprisePolicy) -> LoadedPolicy {
    LoadedPolicy {
        policy,
        digest: digest.into(),
        expected_digest: None,
        signature_enforced: false,
        signature_verified: false,
        signer_key_sha256: None,
    }
}

/// Verdict content quoting `evidence` verbatim (rejection evidence must be an
/// exact quote from the current input).
///
/// Inputs: `evidence` — exact quote from the current input. Output: [`Value`]
/// — the canned rejection verdict.
pub(crate) fn verdict(evidence: &str) -> Value {
    json!({"category":"rejection","confidence":99,"evidence":evidence,
        "explanation":"Explicit negative hiring decision","company":"","position":"","language":"en"})
}

/// Verdict content for a non-rejection `category` (`opportunity`, `other`,
/// `uncertain`) — no evidence quote is required.
///
/// Inputs: `category` — non-rejection category (`opportunity`, `other`, `uncertain`).
/// Output: [`Value`] — the canned verdict.
pub(crate) fn verdict_category(category: &str) -> Value {
    json!({"category":category,"confidence":50,"evidence":"",
        "explanation":"Fixture classification","company":"","position":"","language":"en"})
}

/// Verification content passing every local reply check.
///
/// Inputs: none. Output: [`Value`] — the canned verification content.
pub(crate) fn verification_ok() -> Value {
    json!({"genuine_rejection":true,"claims_supported":true,"professional":true,
        "injection_free":true,"purpose_aligned":true,"reason":"Synthetic verification result"})
}

/// A scriptable local Ollama runtime whose loaded-model state follows the wire
/// protocol (`keep_alive: 0` unloads, other generations load), with
/// classification answers produced by `classify` and canned draft and
/// verification replies signed with `signature`.
///
/// Inputs: `models` — `(name, digest)` pairs the runtime reports as loaded; `signature`
/// — signature answer for drafting; `classify` — maps a request body to a
/// classification answer. Output: [`MockServer`] scripted as a local Ollama
/// runtime.
pub(crate) fn ollama_runtime(
    models: Vec<(String, String)>,
    signature: &str,
    classify: impl Fn(&Value) -> Value + Send + Sync + 'static,
) -> MockServer {
    let state: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let loaded = state.clone();
    let digests: std::collections::HashMap<String, String> = models.iter().cloned().collect();
    let signature = signature.to_owned();
    MockServer::new(move |route, body| {
        let body = body.unwrap_or_else(|| json!({}));
        let model = body["model"].as_str().unwrap_or("").to_owned();
        match route {
            "/api/version" => Some(version_ok()),
            "/api/tags" => Some(json!({"models": models
                .iter()
                .map(|(name, digest)| json!({"name": name, "digest": digest, "size": 7_200_000_000u64}))
                .collect::<Vec<_>>()})),
            "/api/show" => Some(show_ok()),
            "/api/ps" => {
                let current = loaded.lock().unwrap().clone();
                Some(match current {
                    Some(name) => json!({"models": [{
                        "name": name,
                        "digest": digests.get(&name).cloned().unwrap_or_default(),
                        "size": 7_200_000_000u64,
                        "size_vram": 7_200_000_000u64,
                        "context_length": 32768u32
                    }]}),
                    None => json!({"models": []}),
                })
            }
            "/api/generate" => {
                if body["keep_alive"] == json!(0) {
                    *loaded.lock().unwrap() = None;
                } else {
                    *loaded.lock().unwrap() = Some(model);
                }
                Some(json!({"done": true, "prompt_eval_count": 4, "eval_count": 1}))
            }
            "/api/chat" => {
                *loaded.lock().unwrap() = Some(model);
                let payload: Value =
                    serde_json::from_str(body["messages"][1]["content"].as_str().unwrap_or("{}"))
                        .unwrap_or_else(|_| json!({}));
                let content = if payload.get("proposed_reply").is_some() {
                    verification_ok()
                } else if payload.get("tone").is_some() {
                    json!({"body": draft_body(&signature)})
                } else {
                    classify(&payload)
                };
                Some(
                    json!({"model":"m","message":{"role":"assistant","content":content.to_string()},
                    "done":true,"done_reason":"stop","prompt_eval_count":100,"eval_count":100}),
                )
            }
            _ => None,
        }
    })
}
