use crate::{
    config::Settings,
    engine::{Engine, automatic_policy},
    oauth,
    ollama::{self, ModelStatus, Ollama},
    runtime_log::{RuntimeEvent, RuntimeJournal},
    types::*,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
use zeroize::Zeroizing;

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
    pub storage: Option<crate::storage::StorageHealth>,
    pub scheduled_backup: Option<crate::recovery::ScheduledBackupStatus>,
    pub model: ModelStatus,
    pub last_poll: Option<DateTime<Utc>>,
    pub next_poll: Option<DateTime<Utc>>,
    pub items: Vec<Job>,
    pub selected: Option<Job>,
    pub events: Vec<AuditEvent>,
    pub page: u32,
    pub review_only: bool,
    pub api_token: Option<Zeroizing<String>>,
    pub api_token_expires: Option<Instant>,
    pub api_listening: bool,
}

#[derive(Clone)]
pub struct WorkerPulse {
    inner: Arc<Mutex<WorkerPulseState>>,
}

#[derive(Clone, Debug)]
struct WorkerPulseState {
    last_progress_at: DateTime<Utc>,
    current_operation: OperationKind,
    operation_started_at: Option<DateTime<Utc>>,
}

impl WorkerPulse {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(WorkerPulseState {
                last_progress_at: Utc::now(),
                current_operation: OperationKind::Idle,
                operation_started_at: None,
            })),
        }
    }

    fn begin(&self, kind: OperationKind) {
        if let Ok(mut state) = self.inner.lock() {
            let now = Utc::now();
            state.last_progress_at = now;
            state.current_operation = kind;
            state.operation_started_at = Some(now);
        }
    }

    fn progress(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.last_progress_at = Utc::now();
        }
    }

    fn finish(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.last_progress_at = Utc::now();
            state.current_operation = OperationKind::Idle;
            state.operation_started_at = None;
        }
    }

    fn idle_tick(&self) {
        if let Ok(mut state) = self.inner.lock()
            && state.current_operation == OperationKind::Idle
        {
            state.last_progress_at = Utc::now();
        }
    }

    pub fn snapshot(&self, now: DateTime<Utc>) -> WorkerLiveness {
        let Ok(state) = self.inner.lock() else {
            return WorkerLiveness {
                schema_version: 1,
                worker_responsive: false,
                last_progress_at: now,
                progress_age_seconds: 0,
                current_operation: OperationKind::Idle,
                operation_started_at: None,
                operation_age_seconds: None,
                stall_budget_seconds: 0,
            };
        };
        let progress_age_seconds = now
            .signed_duration_since(state.last_progress_at)
            .num_seconds()
            .max(0);
        let operation_age_seconds = state
            .operation_started_at
            .map(|started| now.signed_duration_since(started).num_seconds().max(0));
        let stall_budget_seconds = state.current_operation.stall_budget_seconds();
        WorkerLiveness {
            schema_version: 1,
            worker_responsive: progress_age_seconds <= stall_budget_seconds as i64,
            last_progress_at: state.last_progress_at,
            progress_age_seconds,
            current_operation: state.current_operation,
            operation_started_at: state.operation_started_at,
            operation_age_seconds,
            stall_budget_seconds,
        }
    }
}

impl Default for WorkerPulse {
    fn default() -> Self {
        Self::new()
    }
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
    RecoveryDrill {
        backup: PathBuf,
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
    RotateApiToken,
    Api {
        path: String,
        reply: Sender<Value>,
    },
    OpenMetrics {
        reply: Sender<String>,
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
            Self::RecoveryDrill { .. } => OperationKind::RecoveryDrill,
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
            Self::RotateApiToken => OperationKind::RotateApiToken,
            Self::Api { .. } | Self::OpenMetrics { .. } => OperationKind::ApiRequest,
        }
    }
}

pub struct Worker {
    pub tx: Sender<Command>,
    pub snapshot: Arc<Mutex<Snapshot>>,
    pub paused: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
    pub pulse: WorkerPulse,
    join: Option<std::thread::JoinHandle<()>>,
}
impl Worker {
    pub fn spawn(dir: PathBuf, demo: bool) -> Self {
        let (tx, rx) = bounded(32);
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let paused = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let pulse = WorkerPulse::new();
        let journal = if demo {
            None
        } else {
            RuntimeJournal::open(&dir).ok()
        };
        if let Some(journal) = &journal {
            let _ = journal.record_event(RuntimeEvent::ProcessStarted);
        }
        let (s, p, c, sender, worker_pulse) = (
            snapshot.clone(),
            paused.clone(),
            stop.clone(),
            tx.clone(),
            pulse.clone(),
        );
        let join = std::thread::spawn(move || {
            let panic_pause = p.clone();
            let panic_stop = c.clone();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Engine::open(dir, demo, p, c.clone()).and_then(|engine| {
                    run(
                        engine,
                        rx,
                        s.clone(),
                        sender,
                        journal.clone(),
                        worker_pulse.clone(),
                    )
                })
            }));
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if let Some(journal) = &journal {
                        let _ = journal.record_event(RuntimeEvent::WorkerStartupFailed);
                    }
                    set_worker_fatal(&s, format!("{error:#}"));
                }
                Err(_) => {
                    if let Some(journal) = &journal {
                        let _ = journal.record_event(RuntimeEvent::WorkerPanicked);
                    }
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
            pulse,
            join: Some(join),
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
                operation_id: Some(uuid::Uuid::new_v4().to_string()),
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

    pub fn request_stop(&self) {
        self.paused.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
    }

    /// Request shutdown and wait only for a bounded grace period.
    ///
    /// Long blocking provider/model calls are intentionally not waited forever.
    /// Delivery ambiguity is handled by the durable reservation state machine.
    pub fn shutdown(&mut self, timeout: Duration) -> bool {
        self.request_stop();
        let deadline = Instant::now() + timeout;
        while self
            .join
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        if self
            .join
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
        {
            if let Some(handle) = self.join.take() {
                let _ = handle.join();
            }
            true
        } else {
            false
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.shutdown(Duration::from_secs(2));
    }
}

fn set_worker_fatal(shared: &Arc<Mutex<Snapshot>>, message: String) {
    if let Ok(mut view) = shared.lock() {
        view.error = message.clone();
        view.fatal = true;
        view.busy.clear();
        view.operation = OperationStatus {
            operation_id: Some(uuid::Uuid::new_v4().to_string()),
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
    s.storage = crate::storage::inspect(&e.directory).ok();
    s.scheduled_backup =
        crate::recovery::scheduled_backup_status(&e.db, &e.settings, Utc::now()).ok();
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
fn begin_operation(
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    kind: OperationKind,
    text: &str,
) {
    pulse.begin(kind);
    if let Ok(mut s) = shared.lock() {
        let now = Utc::now();
        s.busy = text.into();
        s.operation = OperationStatus {
            operation_id: Some(uuid::Uuid::new_v4().to_string()),
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

fn record_current_operation(journal: &Option<RuntimeJournal>, shared: &Arc<Mutex<Snapshot>>) {
    let Some(journal) = journal else {
        return;
    };
    if let Ok(snapshot) = shared.lock() {
        let _ = journal.record_operation_status(&snapshot.operation);
    }
}

fn busy(shared: &Arc<Mutex<Snapshot>>, pulse: &WorkerPulse, text: &str) {
    pulse.progress();
    if let Ok(mut s) = shared.lock() {
        s.busy = text.into();
        if s.operation.state == OperationState::Running {
            s.operation.message = text.into();
        }
    }
}

fn report(
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    kind: OperationKind,
    result: &Result<()>,
) {
    pulse.finish();
    if let Ok(mut s) = shared.lock() {
        s.busy.clear();
        let finished_at = Some(Utc::now());
        match result {
            Ok(()) => {
                s.error.clear();
                s.notice = "Operation completed.".into();
                s.operation = OperationStatus {
                    operation_id: s.operation.operation_id.clone(),
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
                    operation_id: s.operation.operation_id.clone(),
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
fn report_silent_success(
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    kind: OperationKind,
    message: &str,
) {
    pulse.finish();
    if let Ok(mut s) = shared.lock() {
        s.busy.clear();
        s.error.clear();
        s.operation = OperationStatus {
            operation_id: s.operation.operation_id.clone(),
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

fn rotate_api_token(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    api_disabled: &Arc<AtomicBool>,
) -> Result<()> {
    let replacement = Zeroizing::new(oauth::secret());
    e.db.change_meta(
        &[("api_token", json!(replacement.as_str()))],
        &[],
        "security.api_token_rotated",
        "Integration API token rotated; active listener disabled until restart",
    )?;
    api_disabled.store(true, Ordering::SeqCst);
    if let Ok(mut snapshot) = shared.lock() {
        snapshot.api_listening = false;
        snapshot.api_token = Some(replacement);
        snapshot.api_token_expires = Some(Instant::now() + Duration::from_secs(60));
    }
    Ok(())
}

fn operation_state_for_result<T, E>(result: &std::result::Result<T, E>) -> OperationState {
    if result.is_ok() {
        OperationState::Succeeded
    } else {
        OperationState::Failed
    }
}

fn protect_audit_boundary<T>(engine: &Engine, result: Result<T>) -> Result<T> {
    match engine.checkpoint_audit_protection() {
        Ok(()) => result,
        Err(anchor_error) => {
            engine.paused.store(true, Ordering::SeqCst);
            match result {
                Ok(_) => Err(anchor_error
                    .context("OS-protected audit checkpoint failed; worker paused fail-closed")),
                Err(operation_error) => Err(anyhow::anyhow!(
                    "Operation failed: {operation_error:#}; OS-protected audit checkpoint also failed: {anchor_error:#}. Worker paused fail-closed"
                )),
            }
        }
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
    journal: Option<RuntimeJournal>,
    pulse: WorkerPulse,
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
            pulse.clone(),
        ) {
            Ok(()) => {
                if let Some(journal) = &journal {
                    let _ = journal.record_event(RuntimeEvent::ApiListenerStarted);
                }
                if let Ok(mut s) = shared.lock() {
                    s.api_listening = true;
                }
            }
            Err(error) => {
                if let Some(journal) = &journal {
                    let _ = journal.record_event(RuntimeEvent::ApiListenerFailed);
                }
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
    let mut scheduled_backup_due = Instant::now() + Duration::from_secs(60);
    let mut policy_due = Instant::now() + Duration::from_secs(30);
    let mut process_failures = 0u32;
    let mut automatic_failures = 0u32;
    let mut retention_failures = 0u32;
    let mut scheduled_backup_failures = 0u32;
    let mut policy_failures = 0u32;
    while !e.stop.load(Ordering::SeqCst) {
        pulse.idle_tick();
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
            Ok(Command::OpenMetrics { reply }) => {
                let data = crate::metrics::collect(&e, Utc::now())
                    .map(|snapshot| crate::metrics::render_openmetrics(&snapshot));
                if let Ok(text) = data {
                    let _ = reply.try_send(text);
                }
            }
            Ok(command) => {
                let operation = command.kind();
                begin_operation(&shared, &pulse, operation, "Working locally…");
                record_current_operation(&journal, &shared);
                let mut settings_changed = false;
                let operation_result: Result<()> = match command {
                    Command::Refresh => Ok(()),
                    Command::CheckNow => {
                        busy(&shared, &pulse, "Checking Gmail for missing messages…");
                        e.synchronize().map(|_| ())
                    }
                    Command::Connect { path, send } => {
                        busy(
                            &shared,
                            &pulse,
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
                            &pulse,
                            "Running the Ollama installer. Approve its Windows prompts.",
                        );
                        ollama::install()
                    }
                    Command::StartOllama => Ollama::new(&e.settings).and_then(|o| o.start()),
                    Command::PullModel => {
                        busy(&shared, &pulse, "Downloading the selected local model…");
                        Ollama::new(&e.settings)
                            .and_then(|o| o.pull(&e.stop, |p| busy(&shared, &pulse, &p)))
                    }
                    Command::InspectModel => {
                        busy(&shared, &pulse, "Refreshing local model status…");
                        e.inspect_model_status()
                    }
                    Command::QualifyModel => {
                        busy(
                            &shared,
                            &pulse,
                            "Running a local model smoke test and checking GPU residency…",
                        );
                        let r = e.qualify();
                        settings_changed = r.is_ok();
                        r
                    }
                    Command::EvaluateModel => {
                        busy(
                            &shared,
                            &pulse,
                            "Running the full task-specific local model evaluation…",
                        );
                        e.evaluate_model().map(|_| ())
                    }
                    Command::CompareModels => {
                        busy(
                            &shared,
                            &pulse,
                            "Comparing installed candidate models on the recruiting-email pipeline…",
                        );
                        e.compare_models().map(|_| ())
                    }
                    Command::IntegrityCheck => {
                        busy(&shared, &pulse, "Checking encrypted database integrity…");
                        e.db.integrity_check()
                    }
                    Command::Backup { out } => {
                        busy(
                            &shared,
                            &pulse,
                            "Creating and verifying encrypted same-vault backup…",
                        );
                        crate::recovery::create_backup(&e.db, &e.directory, &out).map(|_| ())
                    }
                    Command::RecoveryDrill { backup } => {
                        busy(
                            &shared,
                            &pulse,
                            "Restoring backup in an isolated temporary workspace and deeply verifying it…",
                        );
                        let report = crate::recovery::recovery_drill(&e.directory, &backup)?;
                        e.db.log(
                            "backup.drill_passed",
                            None,
                            &format!(
                                "Isolated recovery drill passed: schema={} metadata={} items={} audit_events={} deliveries={}",
                                report.restored_schema_version,
                                report.metadata_records,
                                report.item_records,
                                report.audit_events,
                                report.delivery_records
                            ),
                        )
                    }
                    Command::Diagnostics { out } => {
                        busy(&shared, &pulse, "Writing privacy-safe diagnostics locally…");
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
                            &pulse,
                            "Rechecking the conversation and sending your confirmed reply…",
                        );
                        e.send(&id, revision, &body_hash, false)
                    }
                    Command::Reconcile(id) => e.reconcile(&id),
                    Command::Purge => e.db.purge(e.settings.retention_days).map(|_| ()),
                    Command::RevealApiToken => {
                        let t = e.db.meta::<String>("api_token")?.map(Zeroizing::new);
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
                    Command::RotateApiToken => rotate_api_token(&mut e, &shared, &api_disabled),
                    Command::Api { .. } | Command::OpenMetrics { .. } => Err(anyhow::anyhow!(
                        "Internal API command reached the wrong dispatcher"
                    )),
                };
                let result = protect_audit_boundary(&e, operation_result);
                if settings_changed {
                    scheduled_backup_due = Instant::now();
                    if let Ok(mut s) = shared.lock() {
                        s.settings_revision += 1;
                    }
                }
                report(&shared, &pulse, operation, &result);
                record_current_operation(&journal, &shared);
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
                &pulse,
                OperationKind::EnterprisePolicyReload,
                "Checking administrator enterprise policy…",
            );
            record_current_operation(&journal, &shared);
            let operation_result = e.reload_enterprise_policy();
            let result = protect_audit_boundary(&e, operation_result);
            match result {
                Ok(changed) => {
                    policy_failures = 0;
                    policy_due = Instant::now() + Duration::from_secs(60);
                    if changed {
                        let completed: Result<()> = Ok(());
                        report(
                            &shared,
                            &pulse,
                            OperationKind::EnterprisePolicyReload,
                            &completed,
                        );
                        record_current_operation(&journal, &shared);
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
                            &pulse,
                            OperationKind::EnterprisePolicyReload,
                            "Enterprise policy unchanged",
                        );
                        record_current_operation(&journal, &shared);
                    }
                }
                Err(error) => {
                    policy_failures = policy_failures.saturating_add(1);
                    policy_due = Instant::now() + bounded_backoff(15, policy_failures, 5 * 60);
                    e.paused.store(true, Ordering::SeqCst);
                    let failed: Result<()> = Err(error);
                    report(
                        &shared,
                        &pulse,
                        OperationKind::EnterprisePolicyReload,
                        &failed,
                    );
                    record_current_operation(&journal, &shared);
                }
            }
        }

        if !e.demo && Instant::now() >= retention_due {
            begin_operation(
                &shared,
                &pulse,
                OperationKind::PurgeRetention,
                "Applying local retention policy to completed content…",
            );
            record_current_operation(&journal, &shared);
            let operation_result = e.db.purge(e.settings.retention_days).map(|_| ());
            let result = protect_audit_boundary(&e, operation_result);
            report(&shared, &pulse, OperationKind::PurgeRetention, &result);
            record_current_operation(&journal, &shared);
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
        if !e.demo && Instant::now() >= scheduled_backup_due {
            let status = crate::recovery::scheduled_backup_status(&e.db, &e.settings, Utc::now())?;
            if status.overdue {
                begin_operation(
                    &shared,
                    &pulse,
                    OperationKind::Backup,
                    "Creating scheduled encrypted backup…",
                );
                record_current_operation(&journal, &shared);
                let settings = e.settings.clone();
                let directory = e.directory.clone();
                let operation_result = crate::recovery::create_scheduled_backup(
                    &mut e.db,
                    &directory,
                    &settings,
                    Utc::now(),
                )
                .map(|_| ());
                let result = protect_audit_boundary(&e, operation_result);
                report(&shared, &pulse, OperationKind::Backup, &result);
                record_current_operation(&journal, &shared);
                if result.is_ok() {
                    scheduled_backup_failures = 0;
                    scheduled_backup_due = Instant::now() + Duration::from_secs(60 * 60);
                } else {
                    scheduled_backup_failures = scheduled_backup_failures.saturating_add(1);
                    scheduled_backup_due = Instant::now()
                        + bounded_backoff(15 * 60, scheduled_backup_failures, 2 * 60 * 60);
                }
                refresh(&e, &shared, selected.as_deref(), review, page)?;
            } else {
                scheduled_backup_failures = 0;
                scheduled_backup_due = Instant::now() + Duration::from_secs(60 * 60);
            }
        } else if !e.settings.scheduled_backup_enabled {
            scheduled_backup_due = Instant::now() + Duration::from_secs(60);
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
                &pulse,
                OperationKind::SyncMailbox,
                "Scheduled Gmail check: fetching only missing identities…",
            );
            record_current_operation(&journal, &shared);
            let operation_result = e.synchronize().map(|_| ());
            let result = protect_audit_boundary(&e, operation_result);
            report(&shared, &pulse, OperationKind::SyncMailbox, &result);
            record_current_operation(&journal, &shared);
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
                &pulse,
                OperationKind::AnalyzeQueuedMail,
                "Local AI: classifying, drafting and checking one new email…",
            );
            record_current_operation(&journal, &shared);
            let operation_result = e.process_one().map(|_| ());
            let result = protect_audit_boundary(&e, operation_result);
            report(&shared, &pulse, OperationKind::AnalyzeQueuedMail, &result);
            record_current_operation(&journal, &shared);
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
                &pulse,
                OperationKind::AutomaticDispatch,
                "Evaluating automatic dispatch policy…",
            );
            record_current_operation(&journal, &shared);
            let operation_result = e.automatic_tick();
            let result = protect_audit_boundary(&e, operation_result);
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
            let automatic_state = operation_state_for_result(&result);
            if matches!(result, Ok(false)) {
                report_silent_success(
                    &shared,
                    &pulse,
                    OperationKind::AutomaticDispatch,
                    "No eligible automatic reply",
                );
            } else {
                report(
                    &shared,
                    &pulse,
                    OperationKind::AutomaticDispatch,
                    &result.map(|_| ()),
                );
            }
            let _ = automatic_state;
            record_current_operation(&journal, &shared);
            if refresh_after_tick {
                refresh(&e, &shared, selected.as_deref(), review, page)?;
            }
        }
    }
    if let Some(journal) = &journal {
        let _ = journal.record_event(RuntimeEvent::ProcessStopped);
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

fn encode_item_cursor(cursor: &ItemCursor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor)?))
}

fn decode_item_cursor(value: &str) -> Result<ItemCursor> {
    ensure!(
        !value.is_empty()
            && value.len() <= 1024
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "Invalid item-feed cursor encoding"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| anyhow::anyhow!("Invalid item-feed cursor encoding"))?;
    ensure!(bytes.len() <= 768, "Item-feed cursor exceeds size limit");
    let cursor: ItemCursor =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Invalid item-feed cursor"))?;
    ensure!(
        cursor.snapshot_rowid >= 0
            && cursor.last_rowid > 0
            && cursor.last_rowid <= cursor.snapshot_rowid,
        "Invalid item-feed cursor"
    );
    Ok(cursor)
}

fn validate_api_item_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid item identifier"
    );
    Ok(())
}

#[cfg(test)]
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
                "api_contract_sha256": crate::api::openapi_sha256(),
                "application_version": env!("CARGO_PKG_VERSION"),
                "build": crate::build_info::current(),
                "settings_format_version": crate::config::SETTINGS_FORMAT_VERSION,
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
                    "storage_pressure_guard": true,
                    "tamper_evident_audit_chain": true,
                    "external_audit_anchor": true,
                    "os_protected_audit_anchor": true,
                    "verified_backup_bundle": true,
                    "scheduled_verified_backups": true,
                    "portable_recovery_key_envelope": true,
                    "task_model_bakeoff": true,
                    "typed_operation_status": true,
                    "typed_audit_events": true,
                    "privacy_safe_metrics": true,
                    "openmetrics_1_0": true,
                    "privacy_minimal_runtime_journal": true,
                    "snapshot_cursor_item_feed": true,
                    "enterprise_policy": true,
                    "enterprise_policy_digest_pin": true,
                    "enterprise_policy_ed25519_signature": true
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
            let storage = crate::storage::inspect(&e.directory)?;
            let scheduled_backup =
                crate::recovery::scheduled_backup_status(&e.db, &e.settings, Utc::now())?;
            let paused = e.paused.load(Ordering::SeqCst);
            let stopping = e.stop.load(Ordering::SeqCst);
            let readiness = crate::readiness::assess(
                &e.settings,
                integrity_ok,
                storage.runtime_write_safe,
                e.connected(),
                e.send_scope(),
                paused,
                stopping,
            );
            let counts = e.db.counts(&e.account)?;
            let policy_status = e.enterprise_policy_status();
            let external_audit_anchor_configured =
                std::env::var_os(crate::audit_anchor::AUDIT_ANCHOR_ENV).is_some();
            let os_protected_audit_anchor_required = crate::audit_anchor::os_anchor_required()?;
            let independent_audit_anchor_configured =
                external_audit_anchor_configured || os_protected_audit_anchor_required;
            let operational = crate::readiness::operational_indicators(
                crate::readiness::OperationalContext {
                    settings: &e.settings,
                    counts: &counts,
                    last_poll: e.last_poll()?,
                    database_integrity_ok: integrity_ok,
                    storage_write_safe: storage.runtime_write_safe,
                    scheduled_backup_overdue: scheduled_backup.overdue,
                    connected: e.connected(),
                    now: Utc::now(),
                },
            );
            Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "settings_format_version": e.settings.settings_format_version,
                "healthy": readiness.workspace_ready,
                "readiness": readiness,
                "operational": operational,
                "storage": storage,
                "scheduled_backup": scheduled_backup,
                "database": {
                    "integrity_ok": integrity_ok,
                    "schema_version": e.db.schema_version()?,
                    "audit_head": e.db.audit_head()?
                },
                "runtime_log": crate::runtime_log::status(&e.directory).ok(),
                "gmail": {
                    "connected": e.connected(),
                    "send_scope": e.send_scope()
                },
                "worker": {
                    "paused": paused,
                    "stopping": stopping,
                    "operation": operation
                },
                "enterprise_policy": policy_status,
                "audit_protection": {
                    "policy_requires_independent_anchor": policy_status.require_external_audit_anchor,
                    "external_file_anchor_configured": external_audit_anchor_configured,
                    "os_protected_anchor_required": os_protected_audit_anchor_required,
                    "independent_anchor_configured": independent_audit_anchor_configured
                },
                "mode": e.settings.mode,
                "sending_enabled": e.settings.sending_enabled,
                "model": {
                    "configured": e.settings.model,
                    "digest_pinned": e.settings.model_digest.is_some()
                },
                "counts": counts,
                "last_poll": e.last_poll()?
            }))
        }
        "/v1/audit/anchor" => {
            ensure!(
                query.is_empty(),
                "Audit anchor endpoint takes no query parameters"
            );
            let anchor = crate::audit_anchor::current(&e.db, &e.directory)?;
            Ok(json!({
                "algorithm": "sha256-chain-v1",
                "head": anchor.audit_head,
                "sequence": anchor.audit_sequence,
                "workspace_fingerprint": anchor.workspace_fingerprint,
                "verified": true,
                "anchor": anchor
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
        "/v1/metrics" => {
            ensure!(
                query.is_empty(),
                "Metrics endpoint takes no query parameters"
            );
            Ok(serde_json::to_value(crate::metrics::collect(
                e,
                Utc::now(),
            )?)?)
        }
        "/v1/status" => {
            ensure!(
                query.is_empty(),
                "Status endpoint takes no query parameters"
            );
            Ok(
                json!({"version":env!("CARGO_PKG_VERSION"),"settings_format_version":e.settings.settings_format_version,"account":e.account,"connected":e.connected(),"paused":e.paused.load(Ordering::SeqCst),"mode":e.settings.mode,"sending_enabled":e.settings.sending_enabled,"counts":e.db.counts(&e.account)?,"last_poll":e.last_poll()?,"operation":operation,"enterprise_policy":e.enterprise_policy_status()}),
            )
        }
        "/v1/item-feed" => {
            ensure!(
                query
                    .keys()
                    .all(|key| matches!(key.as_str(), "cursor" | "limit")),
                "Item-feed endpoint accepts only cursor and limit"
            );
            let limit = query
                .get("limit")
                .map(|value| value.parse::<u32>())
                .transpose()?
                .unwrap_or(25);
            ensure!((1..=100).contains(&limit), "Item-feed limit must be 1..100");
            let cursor = query
                .get("cursor")
                .map(|value| decode_item_cursor(value))
                .transpose()?;
            let page =
                e.db.list_cursor(&e.account, false, cursor.as_ref(), limit)?;
            let next_cursor = page
                .next_cursor
                .as_ref()
                .map(encode_item_cursor)
                .transpose()?;
            Ok(json!({
                "schema_version": 1,
                "items": page.items,
                "next_cursor": next_cursor
            }))
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
            "/v1/item-feed",
            "/v1/items/{id}",
            "/v1/items/{id}/automatic-policy",
            "/v1/events",
            "/v1/audit/anchor",
            "/v1/audit/contains",
            "/v1/metrics",
            "/v1/metrics/openmetrics",
        ] {
            assert!(paths.contains_key(expected), "OpenAPI missing {expected}");
        }
        assert_eq!(paths.len(), 14);
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
        assert!(health["runtime_log"].is_object());
        assert_eq!(health["database"]["integrity_ok"], true);
        assert_eq!(health["enterprise_policy"]["active"], false);
        assert_eq!(
            health["audit_protection"]["independent_anchor_configured"],
            false
        );
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
        let operation_id = uuid::Uuid::new_v4().to_string();
        let operation = OperationStatus {
            operation_id: Some(operation_id.clone()),
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
        assert_eq!(health["worker"]["operation"]["operation_id"], operation_id);
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
        assert!(api_query(&engine, "/v1/metrics?extra=1").is_err());
        assert!(api_query(&engine, "/v1/item-feed?extra=1").is_err());
        assert!(api_query(&engine, "/v1/item-feed?limit=0").is_err());
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
        crate::vault::private_dir(dir.path()).unwrap();
        crate::vault::write_new_private(
            &dir.path().join("vault-id"),
            uuid::Uuid::new_v4().to_string().as_bytes(),
        )
        .unwrap();
        let mut engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        let first = api_query(&engine, "/v1/audit/anchor").unwrap();
        let head = first["head"].as_str().unwrap().to_owned();
        let sequence = first["sequence"].as_i64().unwrap();
        let workspace_fingerprint = first["workspace_fingerprint"].as_str().unwrap();
        assert_eq!(head.len(), 64);
        assert!(sequence >= 0);
        assert_eq!(workspace_fingerprint.len(), 64);
        assert_eq!(first["anchor"]["audit_head"], head);
        assert_eq!(first["anchor"]["audit_sequence"], sequence);
        assert_eq!(
            first["anchor"]["workspace_fingerprint"],
            workspace_fingerprint
        );
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
    fn item_feed_cursor_codec_is_bounded_and_round_trips() {
        for snapshot_rowid in 1..=128 {
            for last_rowid in 1..=snapshot_rowid {
                let cursor = ItemCursor {
                    snapshot_rowid,
                    last_rowid,
                };
                let encoded = encode_item_cursor(&cursor).unwrap();
                assert!(encoded.len() <= 1024);
                assert_eq!(decode_item_cursor(&encoded).unwrap(), cursor);
            }
        }

        for cursor in [
            ItemCursor {
                snapshot_rowid: 0,
                last_rowid: 1,
            },
            ItemCursor {
                snapshot_rowid: 5,
                last_rowid: 0,
            },
            ItemCursor {
                snapshot_rowid: 5,
                last_rowid: 6,
            },
            ItemCursor {
                snapshot_rowid: -1,
                last_rowid: 1,
            },
        ] {
            let encoded = encode_item_cursor(&cursor).unwrap();
            assert!(decode_item_cursor(&encoded).is_err(), "{cursor:?}");
        }

        assert!(decode_item_cursor("").is_err());
        assert!(decode_item_cursor("%%%").is_err());
        assert!(decode_item_cursor("YQ==").is_err());
        assert!(decode_item_cursor(&"a".repeat(1025)).is_err());
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
    fn api_token_rotation_revokes_listener_and_never_logs_secret() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let old = "OLD_API_TOKEN_CANARY_SHOULD_NOT_SURVIVE_1234567890".to_string();
        engine.db.set_meta("api_token", &old).unwrap();

        let shared = Arc::new(Mutex::new(Snapshot {
            api_listening: true,
            ..Snapshot::default()
        }));
        let disabled = Arc::new(AtomicBool::new(false));
        rotate_api_token(&mut engine, &shared, &disabled).unwrap();

        assert!(disabled.load(Ordering::SeqCst));
        let stored: String = engine.db.meta("api_token").unwrap().unwrap();
        assert_ne!(stored, old);
        assert!(stored.len() >= 40);

        let snapshot = shared.lock().unwrap();
        assert!(!snapshot.api_listening);
        assert_eq!(
            snapshot.api_token.as_ref().map(|token| token.as_str()),
            Some(stored.as_str())
        );
        drop(snapshot);

        let events = engine.db.events(0, 100).unwrap();
        let event = events
            .iter()
            .find(|event| event.kind == "security.api_token_rotated")
            .unwrap();
        assert_eq!(event.domain, AuditDomain::Security);
        assert_eq!(event.severity, AuditSeverity::Security);
        assert!(!event.detail.contains(&old));
        assert!(!event.detail.contains(&stored));
    }

    #[test]
    fn result_state_mapping_is_consistent_for_scheduled_and_user_operations() {
        let ok: Result<bool> = Ok(false);
        let err: Result<bool> = Err(anyhow::anyhow!("synthetic failure"));
        assert_eq!(operation_state_for_result(&ok), OperationState::Succeeded);
        assert_eq!(operation_state_for_result(&err), OperationState::Failed);
    }

    #[test]
    fn worker_pulse_distinguishes_idle_health_from_stalled_operation() {
        let pulse = WorkerPulse::new();
        let now = Utc::now();
        let idle = pulse.snapshot(now);
        assert!(idle.worker_responsive);
        assert_eq!(idle.current_operation, OperationKind::Idle);
        assert_eq!(idle.stall_budget_seconds, 10);

        pulse.begin(OperationKind::SendReply);
        let running = pulse.snapshot(Utc::now());
        assert!(running.worker_responsive);
        assert_eq!(running.current_operation, OperationKind::SendReply);
        assert!(running.operation_started_at.is_some());

        let stalled = pulse.snapshot(
            Utc::now()
                + chrono::Duration::seconds(
                    OperationKind::SendReply.stall_budget_seconds() as i64 + 1,
                ),
        );
        assert!(!stalled.worker_responsive);
        assert!(
            stalled.progress_age_seconds > OperationKind::SendReply.stall_budget_seconds() as i64
        );

        pulse.finish();
        let recovered = pulse.snapshot(Utc::now());
        assert!(recovered.worker_responsive);
        assert_eq!(recovered.current_operation, OperationKind::Idle);
        assert!(recovered.operation_started_at.is_none());
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
        let mut worker = Worker::spawn(dir.path().into(), true);
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
        assert!(worker.shutdown(Duration::from_secs(2)));
    }
}
