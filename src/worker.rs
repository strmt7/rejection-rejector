use crate::{
    config::Settings,
    engine::{Engine, automatic_policy},
    oauth,
    ollama::{self, ModelStatus, Ollama},
    types::*,
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use crossbeam_channel::{Receiver, Sender, bounded};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default)]
pub struct Snapshot {
    pub initialized: bool,
    pub fatal: bool,
    pub busy: String,
    pub notice: String,
    pub error: String,
    pub operation: OperationStatus,
    pub enterprise_policy: crate::policy::PolicyStatus,
    pub settings: Settings,
    pub settings_revision: u64,
    pub account: String,
    pub connected: bool,
    pub send_scope: bool,
    pub demo: bool,
    pub counts: Counts,
    pub model: ModelStatus,
    pub last_poll: Option<DateTime<Utc>>,
    pub next_poll: Option<DateTime<Utc>>,
    pub items: Vec<Job>,
    pub selected: Option<Job>,
    pub events: Vec<AuditEvent>,
    pub page: u32,
    pub review_only: bool,
    pub api_token: Option<String>,
    pub api_token_expires: Option<Instant>,
    pub api_listening: bool,
}
pub enum Command {
    Refresh,
    CheckNow,
    Connect {
        path: PathBuf,
        send: bool,
    },
    Disconnect,
    Settings(Box<Settings>),
    InstallOllama,
    StartOllama,
    PullModel,
    InspectModel,
    QualifyModel,
    EvaluateModel,
    CompareModels,
    IntegrityCheck,
    Backup {
        out: PathBuf,
    },
    Diagnostics {
        out: PathBuf,
    },
    List {
        review: bool,
        page: u32,
    },
    Select(String),
    Edit {
        id: String,
        revision: u64,
        body: String,
    },
    Regenerate {
        id: String,
        revision: u64,
    },
    Dismiss {
        id: String,
        revision: u64,
    },
    Send {
        id: String,
        revision: u64,
        body_hash: String,
    },
    Reconcile(String),
    Purge,
    RevealApiToken,
    HideApiToken,
    Api {
        path: String,
        reply: Sender<Value>,
    },
}

impl Command {
    fn kind(&self) -> OperationKind {
        match self {
            Self::Refresh => OperationKind::Refresh,
            Self::CheckNow => OperationKind::SyncMailbox,
            Self::Connect { .. } => OperationKind::ConnectGmail,
            Self::Disconnect => OperationKind::DisconnectGmail,
            Self::Settings(_) => OperationKind::UpdateSettings,
            Self::InstallOllama => OperationKind::InstallOllama,
            Self::StartOllama => OperationKind::StartOllama,
            Self::PullModel => OperationKind::PullModel,
            Self::InspectModel => OperationKind::InspectModel,
            Self::QualifyModel => OperationKind::QualifyModel,
            Self::EvaluateModel => OperationKind::EvaluateModel,
            Self::CompareModels => OperationKind::CompareModels,
            Self::IntegrityCheck => OperationKind::IntegrityCheck,
            Self::Backup { .. } => OperationKind::Backup,
            Self::Diagnostics { .. } => OperationKind::Diagnostics,
            Self::List { .. } => OperationKind::ListItems,
            Self::Select(_) => OperationKind::SelectItem,
            Self::Edit { .. } => OperationKind::EditDraft,
            Self::Regenerate { .. } => OperationKind::RegenerateDraft,
            Self::Dismiss { .. } => OperationKind::DismissItem,
            Self::Send { .. } => OperationKind::SendReply,
            Self::Reconcile(_) => OperationKind::ReconcileDelivery,
            Self::Purge => OperationKind::PurgeRetention,
            Self::RevealApiToken => OperationKind::RevealApiToken,
            Self::HideApiToken => OperationKind::HideApiToken,
            Self::Api { .. } => OperationKind::ApiRequest,
        }
    }
}

pub struct Worker {
    pub tx: Sender<Command>,
    pub snapshot: Arc<Mutex<Snapshot>>,
    pub paused: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
}
impl Worker {
    pub fn spawn(dir: PathBuf, demo: bool) -> Self {
        let (tx, rx) = bounded(32);
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let paused = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, p, c, sender) = (snapshot.clone(), paused.clone(), stop.clone(), tx.clone());
        std::thread::spawn(move || {
            let panic_pause = p.clone();
            let panic_stop = c.clone();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Engine::open(dir, demo, p, c.clone())
                    .and_then(|engine| run(engine, rx, s.clone(), sender))
            }));
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(error)) => set_worker_fatal(&s, format!("{error:#}")),
                Err(_) => {
                    panic_pause.store(true, Ordering::SeqCst);
                    panic_stop.store(true, Ordering::SeqCst);
                    set_worker_fatal(
                        &s,
                        "Background worker crashed unexpectedly. Delivery is paused and this process must be restarted.".into(),
                    );
                }
            }
        });
        Self {
            tx,
            snapshot,
            paused,
            stop,
        }
    }
    pub fn command(&self, command: Command) {
        let kind = command.kind();
        if self.tx.try_send(command).is_err()
            && let Ok(mut s) = self.snapshot.lock()
        {
            let message = "Command queue is busy. Wait for the current operation to finish.";
            s.error = message.into();
            s.operation = OperationStatus {
                kind,
                state: OperationState::Failed,
                code: Some("worker_queue_busy".into()),
                retryable: true,
                message: message.into(),
                started_at: None,
                finished_at: Some(Utc::now()),
            };
        }
    }
    pub fn view(&self) -> Snapshot {
        self.snapshot.lock().map(|s| s.clone()).unwrap_or_default()
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.paused.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn set_worker_fatal(shared: &Arc<Mutex<Snapshot>>, message: String) {
    if let Ok(mut view) = shared.lock() {
        view.error = message.clone();
        view.fatal = true;
        view.busy.clear();
        view.operation = OperationStatus {
            kind: OperationKind::Idle,
            state: OperationState::Failed,
            code: Some("worker_fatal".into()),
            retryable: false,
            message,
            started_at: None,
            finished_at: Some(Utc::now()),
        };
    }
}

fn refresh(
    e: &Engine,
    shared: &Arc<Mutex<Snapshot>>,
    selected: Option<&str>,
    review: bool,
    page: u32,
) -> Result<()> {
    let counts = e.db.counts(&e.account)?;
    let items = e.db.list(&e.account, review, page, 25)?;
    let last = e.last_poll()?;
    let events = e.db.events((e.db.latest_event_seq()? - 60).max(0), 60)?;
    let selected = selected.and_then(|id| e.owned(id).ok());
    let mut s = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("UI state lock failed"))?;
    s.initialized = true;
    s.account = e.account.clone();
    s.connected = e.connected();
    s.send_scope = e.send_scope();
    s.demo = e.demo;
    s.enterprise_policy = e.enterprise_policy_status();
    s.settings = e.settings.clone();
    s.counts = counts;
    s.model = e.model.clone();
    s.last_poll = last;
    s.next_poll = last.map(|t| t + chrono::Duration::seconds(e.settings.interval_seconds()));
    s.items = items;
    s.events = events;
    s.selected = selected;
    s.page = page;
    s.review_only = review;
    Ok(())
}
fn begin_operation(shared: &Arc<Mutex<Snapshot>>, kind: OperationKind, text: &str) {
    if let Ok(mut s) = shared.lock() {
        let now = Utc::now();
        s.busy = text.into();
        s.operation = OperationStatus {
            kind,
            state: OperationState::Running,
            code: None,
            retryable: false,
            message: text.into(),
            started_at: Some(now),
            finished_at: None,
        };
    }
}

fn busy(shared: &Arc<Mutex<Snapshot>>, text: &str) {
    if let Ok(mut s) = shared.lock() {
        s.busy = text.into();
        if s.operation.state == OperationState::Running {
            s.operation.message = text.into();
        }
    }
}

fn report(shared: &Arc<Mutex<Snapshot>>, kind: OperationKind, result: &Result<()>) {
    if let Ok(mut s) = shared.lock() {
        s.busy.clear();
        let finished_at = Some(Utc::now());
        match result {
            Ok(()) => {
                s.error.clear();
                s.notice = "Operation completed.".into();
                s.operation = OperationStatus {
                    kind,
                    state: OperationState::Succeeded,
                    code: None,
                    retryable: false,
                    message: s.notice.clone(),
                    started_at: s.operation.started_at,
                    finished_at,
                };
            }
            Err(e) => {
                let message = format!("{e:#}");
                s.error = message.clone();
                s.notice.clear();
                s.operation = OperationStatus {
                    kind,
                    state: OperationState::Failed,
                    code: Some(kind.failure_code().into()),
                    retryable: kind.retryable(),
                    message,
                    started_at: s.operation.started_at,
                    finished_at,
                };
            }
        }
    }
}
fn report_silent_success(shared: &Arc<Mutex<Snapshot>>, kind: OperationKind, message: &str) {
    if let Ok(mut s) = shared.lock() {
        s.busy.clear();
        s.error.clear();
        s.operation = OperationStatus {
            kind,
            state: OperationState::Succeeded,
            code: None,
            retryable: false,
            message: message.into(),
            started_at: s.operation.started_at,
            finished_at: Some(Utc::now()),
        };
    }
}

fn bounded_backoff(base_seconds: u64, failures: u32, cap_seconds: u64) -> Duration {
    let shift = failures.saturating_sub(1).min(6);
    Duration::from_secs(base_seconds.saturating_mul(1u64 << shift).min(cap_seconds))
}

fn run(
    mut e: Engine,
    rx: Receiver<Command>,
    shared: Arc<Mutex<Snapshot>>,
    sender: Sender<Command>,
) -> Result<()> {
    let mut selected: Option<String> = None;
    let mut review = true;
    let mut page = 0;
    refresh(&e, &shared, None, review, page)?;
    let api_disabled = Arc::new(AtomicBool::new(false));
    if e.settings.api_enabled && !e.demo {
        let token: String = match e.db.meta("api_token")? {
            Some(t) => t,
            None => {
                let t = oauth::secret();
                e.db.set_meta("api_token", &t)?;
                t
            }
        };
        match crate::api::start(
            e.settings.api_port,
            token,
            sender,
            e.stop.clone(),
            api_disabled.clone(),
        ) {
            Ok(()) => {
                if let Ok(mut s) = shared.lock() {
                    s.api_listening = true;
                }
            }
            Err(error) => {
                if let Ok(mut s) = shared.lock() {
                    s.error = format!("Integration API did not start: {error}");
                }
            }
        }
    }
    let mut sync_retry = Instant::now();
    let mut auto_due = Instant::now();
    let mut process_due = Instant::now();
    let mut retention_due = Instant::now() + Duration::from_secs(60);
    let mut policy_due = Instant::now() + Duration::from_secs(30);
    let mut process_failures = 0u32;
    let mut automatic_failures = 0u32;
    let mut retention_failures = 0u32;
    let mut policy_failures = 0u32;
    while !e.stop.load(Ordering::SeqCst) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(Command::Api { path, reply }) => {
                let operation = shared
                    .lock()
                    .ok()
                    .map(|snapshot| snapshot.operation.clone());
                let data = api_query_with_operation(&e, &path, operation.as_ref())
                    .unwrap_or_else(|_| json!({"error":"Invalid request or unavailable resource"}));
                let _ = reply.try_send(data);
            }
            Ok(command) => {
                let operation = command.kind();
                begin_operation(&shared, operation, "Working locally…");
                let mut settings_changed = false;
                let result: Result<()> = match command {
                    Command::Refresh => Ok(()),
                    Command::CheckNow => {
                        busy(&shared, "Checking Gmail for missing messages…");
                        e.synchronize().map(|_| ())
                    }
                    Command::Connect { path, send } => {
                        busy(
                            &shared,
                            "Complete Google sign-in in your browser. This expires after five minutes.",
                        );
                        let r = e.connect(&path, send);
                        settings_changed = r.is_ok();
                        r
                    }
                    Command::Disconnect => {
                        selected = None;
                        settings_changed = true;
                        e.disconnect()
                    }
                    Command::Settings(s) => {
                        let r = e.update_settings(*s);
                        settings_changed = r.is_ok();
                        r
                    }
                    Command::InstallOllama => {
                        busy(
                            &shared,
                            "Running the Ollama installer. Approve its Windows prompts.",
                        );
                        ollama::install()
                    }
                    Command::StartOllama => Ollama::new(&e.settings).and_then(|o| o.start()),
                    Command::PullModel => {
                        busy(&shared, "Downloading the selected local model…");
                        Ollama::new(&e.settings)
                            .and_then(|o| o.pull(&e.stop, |p| busy(&shared, &p)))
                    }
                    Command::InspectModel => {
                        busy(&shared, "Refreshing local model status…");
                        e.inspect_model_status()
                    }
                    Command::QualifyModel => {
                        busy(
                            &shared,
                            "Running a local model smoke test and checking GPU residency…",
                        );
                        let r = e.qualify();
                        settings_changed = r.is_ok();
                        r
                    }
                    Command::EvaluateModel => {
                        busy(
                            &shared,
                            "Running the full task-specific local model evaluation…",
                        );
                        e.evaluate_model().map(|_| ())
                    }
                    Command::CompareModels => {
                        busy(
                            &shared,
                            "Comparing installed candidate models on the recruiting-email pipeline…",
                        );
                        e.compare_models().map(|_| ())
                    }
                    Command::IntegrityCheck => {
                        busy(&shared, "Checking encrypted database integrity…");
                        e.db.integrity_check()
                    }
                    Command::Backup { out } => {
                        busy(
                            &shared,
                            "Creating and verifying encrypted same-vault backup…",
                        );
                        crate::recovery::create_backup(&e.db, &e.directory, &out).map(|_| ())
                    }
                    Command::Diagnostics { out } => {
                        busy(&shared, "Writing privacy-safe diagnostics locally…");
                        crate::diagnostics::write_report(&e, &out)
                    }
                    Command::List { review: r, page: p } => {
                        review = r;
                        page = p;
                        Ok(())
                    }
                    Command::Select(id) => {
                        selected = Some(id);
                        Ok(())
                    }
                    Command::Edit { id, revision, body } => e.edit(&id, revision, body),
                    Command::Regenerate { id, revision } => e.regenerate(&id, revision),
                    Command::Dismiss { id, revision } => e.dismiss(&id, revision),
                    Command::Send {
                        id,
                        revision,
                        body_hash,
                    } => {
                        busy(
                            &shared,
                            "Rechecking the conversation and sending your confirmed reply…",
                        );
                        e.send(&id, revision, &body_hash, false)
                    }
                    Command::Reconcile(id) => e.reconcile(&id),
                    Command::Purge => e.db.purge(e.settings.retention_days).map(|_| ()),
                    Command::RevealApiToken => {
                        let t = e.db.meta::<String>("api_token")?;
                        if let Ok(mut s) = shared.lock() {
                            s.api_token = t;
                            s.api_token_expires = s
                                .api_token
                                .as_ref()
                                .map(|_| Instant::now() + Duration::from_secs(60));
                        }
                        Ok(())
                    }
                    Command::HideApiToken => {
                        if let Ok(mut s) = shared.lock() {
                            s.api_token = None;
                            s.api_token_expires = None;
                        }
                        Ok(())
                    }
                    Command::Api { .. } => Err(anyhow::anyhow!(
                        "Internal API command reached the wrong dispatcher"
                    )),
                };
                if settings_changed && let Ok(mut s) = shared.lock() {
                    s.settings_revision += 1;
                }
                report(&shared, operation, &result);
                refresh(&e, &shared, selected.as_deref(), review, page)?;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }
        if let Ok(mut snapshot) = shared.lock()
            && snapshot
                .api_token_expires
                .is_some_and(|until| Instant::now() >= until)
        {
            snapshot.api_token = None;
            snapshot.api_token_expires = None;
        }
        if !e.demo && Instant::now() >= policy_due {
            begin_operation(
                &shared,
                OperationKind::EnterprisePolicyReload,
                "Checking administrator enterprise policy…",
            );
            let result = e.reload_enterprise_policy();
            match result {
                Ok(changed) => {
                    policy_failures = 0;
                    policy_due = Instant::now() + Duration::from_secs(60);
                    if changed {
                        let completed: Result<()> = Ok(());
                        report(&shared, OperationKind::EnterprisePolicyReload, &completed);
                        if e.enterprise_policy_status().prohibit_integration_api
                            && !api_disabled.swap(true, Ordering::SeqCst)
                            && let Ok(mut snapshot) = shared.lock()
                        {
                            snapshot.api_listening = false;
                        }
                        if let Ok(mut snapshot) = shared.lock() {
                            snapshot.settings_revision =
                                snapshot.settings_revision.saturating_add(1);
                        }
                        refresh(&e, &shared, selected.as_deref(), review, page)?;
                    } else {
                        report_silent_success(
                            &shared,
                            OperationKind::EnterprisePolicyReload,
                            "Enterprise policy unchanged",
                        );
                    }
                }
                Err(error) => {
                    policy_failures = policy_failures.saturating_add(1);
                    policy_due = Instant::now() + bounded_backoff(15, policy_failures, 5 * 60);
                    e.paused.store(true, Ordering::SeqCst);
                    let failed: Result<()> = Err(error);
                    report(&shared, OperationKind::EnterprisePolicyReload, &failed);
                }
            }
        }

        if !e.demo && Instant::now() >= retention_due {
            begin_operation(
                &shared,
                OperationKind::PurgeRetention,
                "Applying local retention policy to completed content…",
            );
            let result = e.db.purge(e.settings.retention_days).map(|_| ());
            report(&shared, OperationKind::PurgeRetention, &result);
            if result.is_ok() {
                retention_failures = 0;
                retention_due = Instant::now() + Duration::from_secs(24 * 60 * 60);
            } else {
                retention_failures = retention_failures.saturating_add(1);
                retention_due =
                    Instant::now() + bounded_backoff(15 * 60, retention_failures, 60 * 60);
            }
            refresh(&e, &shared, selected.as_deref(), review, page)?;
        }
        if e.paused.load(Ordering::SeqCst) || e.demo || !e.connected() {
            continue;
        }
        let now = Utc::now();
        if Instant::now() >= sync_retry
            && e.last_poll()?.is_none_or(|t| {
                now.signed_duration_since(t).num_seconds() >= e.settings.interval_seconds()
            })
        {
            begin_operation(
                &shared,
                OperationKind::SyncMailbox,
                "Scheduled Gmail check: fetching only missing identities…",
            );
            let result = e.synchronize().map(|_| ());
            report(&shared, OperationKind::SyncMailbox, &result);
            sync_retry =
                Instant::now() + Duration::from_secs(if result.is_ok() { 30 } else { 300 });
            refresh(&e, &shared, selected.as_deref(), review, page)?;
        }
        if Instant::now() >= process_due
            && e.settings.model_digest.is_some()
            && e.db.next_queued(&e.account, Utc::now())?.is_some()
        {
            begin_operation(
                &shared,
                OperationKind::AnalyzeQueuedMail,
                "Local AI: classifying, drafting and checking one new email…",
            );
            let result = e.process_one().map(|_| ());
            report(&shared, OperationKind::AnalyzeQueuedMail, &result);
            if result.is_ok() {
                process_failures = 0;
                process_due = Instant::now() + Duration::from_secs(1);
            } else {
                process_failures = process_failures.saturating_add(1);
                process_due = Instant::now() + bounded_backoff(30, process_failures, 5 * 60);
            }
            refresh(&e, &shared, selected.as_deref(), review, page)?;
        }
        if Instant::now() >= auto_due {
            begin_operation(
                &shared,
                OperationKind::AutomaticDispatch,
                "Evaluating automatic dispatch policy…",
            );
            let result = e.automatic_tick();
            match &result {
                Ok(_) => {
                    automatic_failures = 0;
                    auto_due = Instant::now() + Duration::from_secs(30);
                }
                Err(_) => {
                    automatic_failures = automatic_failures.saturating_add(1);
                    auto_due = Instant::now() + bounded_backoff(30, automatic_failures, 10 * 60);
                }
            }
            let refresh_after_tick = !matches!(result, Ok(false));
            if matches!(result, Ok(false)) {
                report_silent_success(
                    &shared,
                    OperationKind::AutomaticDispatch,
                    "No eligible automatic reply",
                );
            } else {
                report(
                    &shared,
                    OperationKind::AutomaticDispatch,
                    &result.map(|_| ()),
                );
            }
            if refresh_after_tick {
                refresh(&e, &shared, selected.as_deref(), review, page)?;
            }
        }
    }
    Ok(())
}
fn unique_query(url: &url::Url) -> Result<std::collections::BTreeMap<String, String>> {
    let mut query = std::collections::BTreeMap::new();
    for (key, value) in url.query_pairs() {
        let key = key.into_owned();
        ensure!(
            query.insert(key.clone(), value.into_owned()).is_none(),
            "Duplicate query parameter: {key}"
        );
    }
    Ok(query)
}

fn validate_api_item_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid item identifier"
    );
    Ok(())
}

fn api_query(e: &Engine, path: &str) -> Result<Value> {
    api_query_with_operation(e, path, None)
}

fn api_query_with_operation(
    e: &Engine,
    path: &str,
    operation: Option<&OperationStatus>,
) -> Result<Value> {
    let u = url::Url::parse(&format!("http://127.0.0.1{path}"))?;
    ensure!(
        u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
            && u.host_str() == Some("127.0.0.1"),
        "Invalid local API request target"
    );
    let query = unique_query(&u)?;
    match u.path() {
        "/v1/capabilities" => {
            ensure!(
                query.is_empty(),
                "Capabilities endpoint takes no query parameters"
            );
            Ok(json!({
                "api_version": crate::api::API_VERSION,
                "application_version": env!("CARGO_PKG_VERSION"),
                "read_only": true,
                "mail_provider": "gmail",
                "modes": ["human_review", "automatic"],
                "features": {
                    "encrypted_local_store": true,
                    "incremental_sync": true,
                    "local_ollama": true,
                    "review_queue": true,
                    "automatic_policy": true,
                    "automatic_policy_reason_codes": true,
                    "delivery_reconciliation": true,
                    "events": true,
                    "openapi_3_1": true,
                    "direct_liveness": true,
                    "database_integrity": true,
                    "tamper_evident_audit_chain": true,
                    "external_audit_anchor": true,
                    "verified_backup_bundle": true,
                    "task_model_bakeoff": true,
                    "typed_operation_status": true,
                    "enterprise_policy": true
                },
                "poll_hours": crate::config::POLL_HOURS,
                "lookback_days": crate::config::LOOKBACK_DAYS
            }))
        }
        "/v1/health" => {
            ensure!(
                query.is_empty(),
                "Health endpoint takes no query parameters"
            );
            let integrity_ok = e.db.integrity_check().is_ok();
            let paused = e.paused.load(Ordering::SeqCst);
            let stopping = e.stop.load(Ordering::SeqCst);
            let readiness = crate::readiness::assess(
                &e.settings,
                integrity_ok,
                e.connected(),
                e.send_scope(),
                paused,
                stopping,
            );
            Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "healthy": readiness.workspace_ready,
                "readiness": readiness,
                "database": {
                    "integrity_ok": integrity_ok,
                    "schema_version": e.db.schema_version()?,
                    "audit_head": e.db.audit_head()?
                },
                "gmail": {
                    "connected": e.connected(),
                    "send_scope": e.send_scope()
                },
                "worker": {
                    "paused": paused,
                    "stopping": stopping,
                    "operation": operation
                },
                "enterprise_policy": e.enterprise_policy_status(),
                "mode": e.settings.mode,
                "sending_enabled": e.settings.sending_enabled,
                "model": {
                    "configured": e.settings.model,
                    "digest_pinned": e.settings.model_digest.is_some()
                },
                "counts": e.db.counts(&e.account)?,
                "last_poll": e.last_poll()?
            }))
        }
        "/v1/audit/anchor" => {
            ensure!(
                query.is_empty(),
                "Audit anchor endpoint takes no query parameters"
            );
            e.db.verify_audit_chain()?;
            Ok(json!({
                "algorithm": "sha256-chain-v1",
                "head": e.db.audit_head()?,
                "verified": true
            }))
        }
        "/v1/audit/contains" => {
            ensure!(
                query.keys().all(|key| key == "head"),
                "Audit contains endpoint accepts only head"
            );
            let head = query
                .get("head")
                .context("Audit contains endpoint requires head")?;
            Ok(json!({
                "head": head,
                "known": e.db.contains_audit_anchor(head)?
            }))
        }
        "/v1/status" => {
            ensure!(
                query.is_empty(),
                "Status endpoint takes no query parameters"
            );
            Ok(
                json!({"version":env!("CARGO_PKG_VERSION"),"account":e.account,"connected":e.connected(),"paused":e.paused.load(Ordering::SeqCst),"mode":e.settings.mode,"sending_enabled":e.settings.sending_enabled,"counts":e.db.counts(&e.account)?,"last_poll":e.last_poll()?,"operation":operation,"enterprise_policy":e.enterprise_policy_status()}),
            )
        }
        "/v1/items" => {
            ensure!(
                query.keys().all(|key| key == "page"),
                "Items endpoint accepts only page"
            );
            let page = query
                .get("page")
                .map(|v| v.parse::<u32>())
                .transpose()?
                .unwrap_or(0);
            ensure!(page <= 1_000_000, "Page is outside supported range");
            Ok(json!({"page":page,"page_size":25,"items":e.db.list(&e.account,false,page,25)?}))
        }
        "/v1/events" => {
            ensure!(
                query.keys().all(|key| key == "after"),
                "Events endpoint accepts only after"
            );
            let after = query
                .get("after")
                .map(|v| v.parse::<i64>())
                .transpose()?
                .unwrap_or(0);
            Ok(json!({"events":e.db.events(after.max(0),100)?}))
        }
        path if path.starts_with("/v1/items/") && path.ends_with("/automatic-policy") => {
            ensure!(
                query.is_empty(),
                "Automatic-policy endpoint takes no query parameters"
            );
            let id = path
                .trim_start_matches("/v1/items/")
                .trim_end_matches("/automatic-policy")
                .trim_end_matches('/');
            validate_api_item_id(id)?;
            let job = e.owned(id)?;
            Ok(serde_json::to_value(automatic_policy(
                &job,
                &e.settings,
                &e.account,
                Utc::now(),
            ))?)
        }
        path if path.starts_with("/v1/items/") => {
            ensure!(query.is_empty(), "Item endpoint takes no query parameters");
            let id = path.trim_start_matches("/v1/items/");
            validate_api_item_id(id)?;
            Ok(serde_json::to_value(e.owned(id)?)?)
        }
        _ => Err(anyhow::anyhow!("Unknown API route")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn openapi_contract_covers_every_public_v1_route() {
        let spec: serde_json::Value = serde_json::from_str(crate::api::OPENAPI_DOCUMENT).unwrap();
        let paths = spec["paths"].as_object().unwrap();
        for expected in [
            "/v1/live",
            "/v1/openapi.json",
            "/v1/capabilities",
            "/v1/health",
            "/v1/status",
            "/v1/items",
            "/v1/items/{id}",
            "/v1/events",
            "/v1/audit/anchor",
            "/v1/audit/contains",
        ] {
            assert!(paths.contains_key(expected), "OpenAPI missing {expected}");
        }
        assert_eq!(paths.len(), 10);
        assert_eq!(spec["openapi"], "3.1.0");
    }

    #[test]
    fn capabilities_are_versioned_and_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let health = api_query(&engine, "/v1/health").unwrap();
        assert_eq!(health["healthy"], true);
        assert_eq!(health["database"]["integrity_ok"], true);
        assert_eq!(health["enterprise_policy"]["active"], false);
        assert!(health.get("account").is_none());

        let value = api_query(&engine, "/v1/capabilities").unwrap();
        assert_eq!(value["api_version"], crate::api::API_VERSION);
        assert_eq!(value["read_only"], true);
        assert_eq!(value["mail_provider"], "gmail");
        assert_eq!(
            value["poll_hours"],
            serde_json::json!(crate::config::POLL_HOURS)
        );
    }

    #[test]
    fn health_exposes_typed_operation_status_when_available() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let operation = OperationStatus {
            kind: OperationKind::Backup,
            state: OperationState::Failed,
            code: Some("backup_failed".into()),
            retryable: true,
            message: "Synthetic failure".into(),
            started_at: Some(Utc::now()),
            finished_at: Some(Utc::now()),
        };
        let health = api_query_with_operation(&engine, "/v1/health", Some(&operation)).unwrap();
        assert_eq!(health["worker"]["operation"]["kind"], "backup");
        assert_eq!(health["worker"]["operation"]["state"], "failed");
        assert_eq!(health["worker"]["operation"]["code"], "backup_failed");
        assert_eq!(health["worker"]["operation"]["retryable"], true);
    }

    #[test]
    fn integration_query_parser_rejects_duplicates_and_unknown_parameters() {
        let url = url::Url::parse("http://127.0.0.1/v1/items?page=1&page=2").unwrap();
        assert!(unique_query(&url).is_err());

        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert!(api_query(&engine, "/v1/health?extra=1").is_err());
        assert!(api_query(&engine, "/v1/status?extra=1").is_err());
        assert!(api_query(&engine, "/v1/items?page=1&extra=2").is_err());
        assert!(api_query(&engine, "/v1/events?after=0&after=1").is_err());
    }

    #[test]
    fn automatic_policy_api_returns_stable_reason_codes() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let job = engine
            .db
            .list(&engine.account, true, 0, 25)
            .unwrap()
            .remove(0);
        let value = api_query(&engine, &format!("/v1/items/{}/automatic-policy", job.id)).unwrap();
        assert_eq!(value["eligible"], false);
        let codes = value["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|block| block["code"].as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"automatic_mode_not_armed"));
    }

    #[test]
    fn audit_anchor_api_supports_external_rollback_detection() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        let first = api_query(&engine, "/v1/audit/anchor").unwrap();
        let head = first["head"].as_str().unwrap().to_owned();
        assert_eq!(head.len(), 64);
        engine
            .db
            .log("test.anchor.advance", None, "advance")
            .unwrap();

        let contains = api_query(&engine, &format!("/v1/audit/contains?head={head}")).unwrap();
        assert_eq!(contains["known"], true);
        assert_ne!(
            api_query(&engine, "/v1/audit/anchor").unwrap()["head"],
            head
        );
        assert!(api_query(&engine, "/v1/audit/contains?head=not-a-hash").is_err());
    }

    #[test]
    fn integration_item_ids_have_exact_hash_shape() {
        assert!(validate_api_item_id(&"a".repeat(64)).is_ok());
        for id in ["", "abc", &"g".repeat(64), &"a".repeat(65)] {
            assert!(validate_api_item_id(id).is_err());
        }
    }

    #[test]
    fn retention_retry_backoff_stays_bounded() {
        assert_eq!(
            bounded_backoff(15 * 60, 1, 60 * 60),
            Duration::from_secs(15 * 60)
        );
        assert_eq!(
            bounded_backoff(15 * 60, 4, 60 * 60),
            Duration::from_secs(60 * 60)
        );
        assert_eq!(
            bounded_backoff(15 * 60, 20, 60 * 60),
            Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn retry_backoff_is_bounded_and_resets_by_caller() {
        assert_eq!(bounded_backoff(30, 1, 300), Duration::from_secs(30));
        assert_eq!(bounded_backoff(30, 2, 300), Duration::from_secs(60));
        assert_eq!(bounded_backoff(30, 4, 300), Duration::from_secs(240));
        assert_eq!(bounded_backoff(30, 20, 300), Duration::from_secs(300));
    }

    #[test]
    fn demo_worker_initializes_and_publishes_selection() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().into(), true);
        let start = Instant::now();
        let first = loop {
            let s = worker.view();
            assert!(!s.fatal, "{}", s.error);
            if s.initialized {
                assert_eq!(s.items.len(), 3);
                break s.items[0].id.clone();
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "Worker did not initialize"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        worker.command(Command::Select(first.clone()));
        loop {
            let s = worker.view();
            assert!(!s.fatal, "{}", s.error);
            if let Some(job) = s.selected {
                assert_eq!(job.id, first);
                assert!(job.draft.is_some());
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "Worker did not publish selection"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
