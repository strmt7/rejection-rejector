use crate::{
    api_auth,
    config::{AutomaticArmGate, Mode, Settings},
    engine::{Engine, automatic_policy},
    ollama::{self, ModelStatus, Ollama},
    retry::{CircuitTransition, RetryGate},
    runtime_log::{RuntimeEvent, RuntimeJournal, RuntimeSignal},
    types::*,
    web::{self, WriteOutcome, WriteRequest},
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
    pub backup_isolation: Option<crate::recovery::BackupIsolationStatus>,
    pub model: ModelStatus,
    pub verifier_model: ModelStatus,
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
    /// Create a worker pulse in its idle state.
    ///
    /// Inputs: none. Output: [`Self`] tracking progress from the current time.
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

    /// Build the liveness snapshot reported to readers.
    ///
    /// Inputs: `now` — evaluation time. Output: [`WorkerLiveness`] (unresponsive
    /// when the state lock is poisoned).
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
    PullVerifierModel,
    InspectVerifierModel,
    QualifyVerifierModel,
    EvaluateModel,
    ProfileModel,
    CompareModels,
    IntegrityCheck,
    CompactDatabase,
    Backup {
        out: PathBuf,
    },
    RecoveryDrill {
        backup: PathBuf,
    },
    ExportRecoveryKey {
        out: PathBuf,
        passphrase: Zeroizing<String>,
    },
    VerifyRecoveryKey {
        backup: PathBuf,
        recovery_key: PathBuf,
        passphrase: Zeroizing<String>,
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
    /// State-changing web command received by the loopback API (`rr web`).
    ///
    /// The request is already payload-validated by [`web::parse_write_request`];
    /// the worker applies the shared safety gates and executes it against the
    /// engine exactly like the matching interactive command.
    ApiWrite {
        request: WriteRequest,
        reply: Sender<WriteOutcome>,
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
            Self::PullModel | Self::PullVerifierModel => OperationKind::PullModel,
            Self::InspectModel | Self::InspectVerifierModel => OperationKind::InspectModel,
            Self::QualifyModel | Self::QualifyVerifierModel => OperationKind::QualifyModel,
            Self::EvaluateModel => OperationKind::EvaluateModel,
            Self::ProfileModel => OperationKind::ProfileModel,
            Self::CompareModels => OperationKind::CompareModels,
            Self::IntegrityCheck => OperationKind::IntegrityCheck,
            Self::CompactDatabase => OperationKind::CompactDatabase,
            Self::Backup { .. } => OperationKind::Backup,
            Self::RecoveryDrill { .. } => OperationKind::RecoveryDrill,
            Self::ExportRecoveryKey { .. } => OperationKind::RecoveryKeyExport,
            Self::VerifyRecoveryKey { .. } => OperationKind::RecoveryKeyVerify,
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
            Self::ApiWrite { request, .. } => request.operation_kind(),
        }
    }
}

/// Rejected commands must never mask a running operation. In particular a
/// queue overflow may not make an in-flight Gmail send appear safe to interrupt.
fn report_unqueued_command(snapshot: &mut Snapshot, kind: OperationKind, disconnected: bool) {
    let (message, code, retryable) = if disconnected {
        (
            "Background worker is disconnected. Restart the application.",
            "worker_disconnected",
            false,
        )
    } else {
        (
            "Command queue is full. Wait for the current operation to finish.",
            "worker_queue_busy",
            true,
        )
    };
    snapshot.error = message.into();
    if snapshot.operation.state == OperationState::Running {
        return;
    }
    snapshot.operation = OperationStatus {
        operation_id: Some(uuid::Uuid::new_v4().to_string()),
        kind,
        state: OperationState::Failed,
        code: Some(code.into()),
        retryable,
        message: message.into(),
        started_at: None,
        finished_at: Some(Utc::now()),
    };
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
    /// Spawn the background worker thread for one workspace.
    ///
    /// Inputs: `dir` — workspace directory; `demo` — whether demo mode is active.
    /// Output: [`Self`] handle with command channel and shared snapshot.
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
            // Test seam: the thread adopts any scripted enterprise checks and
            // timer intervals armed by the spawning test before doing any
            // fail-closed runtime work.
            #[cfg(test)]
            crate::test_support::adopt_seams();
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
    /// Queue one worker command.
    ///
    /// Inputs: `command` — command to enqueue. Output: none; rejected commands are
    /// surfaced through the worker state rather than silently dropped.
    pub fn command(&self, command: Command) {
        let kind = command.kind();
        let disconnected = match self.tx.try_send(command) {
            Ok(()) => return,
            Err(crossbeam_channel::TrySendError::Full(_)) => false,
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => true,
        };
        if let Ok(mut snapshot) = self.snapshot.lock() {
            report_unqueued_command(&mut snapshot, kind, disconnected);
        }
    }
    /// The latest shared worker snapshot.
    ///
    /// Inputs: none. Output: [`Snapshot`] (the default snapshot when the state
    /// lock is poisoned).
    pub fn view(&self) -> Snapshot {
        self.snapshot.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Request a graceful worker stop.
    ///
    /// Inputs: none. Output: none; the pause and stop flags are set.
    pub fn request_stop(&self) {
        self.paused.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
    }

    /// Request shutdown and wait only for a bounded grace period.
    ///
    /// Long blocking provider/model calls are intentionally not waited forever.
    /// Delivery ambiguity is handled by the durable reservation state machine.
    ///
    /// Inputs: `timeout` — bounded grace period. Output: `true` when the worker
    /// thread joined within the grace period.
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
    s.backup_isolation = crate::recovery::backup_isolation_status(&e.directory, &e.settings).ok();
    s.model = e.model.clone();
    s.verifier_model = e.verifier_model.clone();
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

/// Run the Ollama installer for `Command::InstallOllama`.
///
/// Tests substitute a stand-in through
/// `crate::test_support::with_installer` so the dispatch arm can be
/// exercised without spawning the real installer, which prompts for
/// elevation on the host.
fn install_ollama() -> anyhow::Result<()> {
    #[cfg(test)]
    {
        if let Some(runner) = crate::test_support::installer_override() {
            return runner();
        }
    }
    ollama::install()
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

fn classify_operation_failure(kind: OperationKind, error: &anyhow::Error) -> (String, bool) {
    if let Some(dispatch) = error.downcast_ref::<crate::engine::DispatchFailure>() {
        return (
            dispatch.operation_code().to_owned(),
            dispatch.retryable_for_operator(),
        );
    }
    if let Some(fetch) = error.downcast_ref::<crate::gmail::FetchFailure>() {
        return match fetch.kind {
            crate::gmail::FetchFailureKind::Infrastructure => {
                ("retryable_gmail_fetch".into(), true)
            }
            crate::gmail::FetchFailureKind::MalformedMessage => {
                ("review_required_malformed_message".into(), false)
            }
        };
    }
    (kind.failure_code().into(), kind.retryable())
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
                let (code, retryable) = classify_operation_failure(kind, e);
                s.error = message.clone();
                s.notice.clear();
                s.operation = OperationStatus {
                    operation_id: s.operation.operation_id.clone(),
                    kind,
                    state: OperationState::Failed,
                    code: Some(code),
                    retryable,
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
    let material = api_auth::rotate(&mut e.db)?;
    let replacement = material
        .plaintext_once
        .context("Rotated API credential did not return one-time plaintext")?;
    api_disabled.store(true, Ordering::SeqCst);
    if let Ok(mut snapshot) = shared.lock() {
        snapshot.api_listening = false;
        snapshot.api_token = Some(replacement);
        snapshot.api_token_expires = Some(Instant::now() + Duration::from_secs(60));
    }
    Ok(())
}

/// Read the shared snapshot's current operation status.
///
/// Inputs: `shared` — shared UI state. Output: the latest [`OperationStatus`]
/// for a write response (the default status when the state lock is poisoned).
fn current_operation(shared: &Arc<Mutex<Snapshot>>) -> OperationStatus {
    shared
        .lock()
        .map(|snapshot| snapshot.operation.clone())
        .unwrap_or_default()
}

/// Map an engine refusal onto the stable write error contract.
///
/// Inputs: `kind` — operation kind being executed; `error` — engine refusal.
/// Output: [`web::WriteError`] whose `code` and `retryable` flag follow the
/// same stable worker-failure semantics as every other operation surface.
fn engine_write_error(kind: OperationKind, error: &anyhow::Error) -> web::WriteError {
    let (code, retryable) = classify_operation_failure(kind, error);
    web::WriteError {
        status: if retryable { 503 } else { 409 },
        code,
        message: error.to_string(),
        retryable,
    }
}

/// Shared worker bookkeeping one executed web write runs through.
///
/// Inputs: none (plain struct). Output: the operation-state handles plus the
/// current list view a post-write refresh restores.
struct WriteContext<'a> {
    /// Shared UI state written by the operation lifecycle.
    shared: &'a Arc<Mutex<Snapshot>>,
    /// Worker liveness probe updated alongside the UI state.
    pulse: &'a WorkerPulse,
    /// Privacy-minimal runtime journal recording operation lifecycles.
    journal: &'a Option<RuntimeJournal>,
    /// Message id currently selected in the list view.
    selected: Option<&'a str>,
    /// Whether the list view shows reviewable messages only.
    review: bool,
    /// Current list page.
    page: u32,
}

/// Finish one executed web write with the shared operation machinery.
///
/// Inputs: `e` — engine owning the workspace; `context` — worker
/// bookkeeping and list view; `kind` — operation kind; `result` — engine
/// outcome. Output: [`WriteOutcome`] carrying the typed operation status on
/// success or the stable error envelope on refusal; the audit-boundary
/// checkpoint, operation report and view refresh run exactly as for
/// interactive commands.
fn report_write(
    e: &Engine,
    context: &WriteContext<'_>,
    kind: OperationKind,
    result: Result<()>,
) -> WriteOutcome {
    let result = protect_audit_boundary(e, result);
    report(context.shared, context.pulse, kind, &result);
    record_current_operation(context.journal, context.shared);
    let _ = refresh(
        e,
        context.shared,
        context.selected,
        context.review,
        context.page,
    );
    match result {
        Ok(()) => WriteOutcome::accepted(&current_operation(context.shared)),
        Err(error) => WriteOutcome::error(&engine_write_error(kind, &error)),
    }
}

/// Execute one validated web write against the engine.
///
/// Inputs: `e` — engine owning the workspace; `request` — parsed write
/// request; `arm_gate` — server-side Automatic-arm cooldown state mutated in
/// place; `context` — worker bookkeeping and list view. Output:
/// [`WriteOutcome`] for the HTTP response — pure gate rejections come back
/// typed without recording an operation (nothing was touched), executed
/// writes run through the same begin/report/audit-boundary/refresh sequence
/// as the interactive commands they mirror. The gates themselves live in
/// [`web`] so they are unit testable and identical to the desktop and
/// terminal rules.
fn handle_api_write(
    e: &mut Engine,
    request: &WriteRequest,
    arm_gate: &mut Option<AutomaticArmGate>,
    context: &WriteContext<'_>,
) -> WriteOutcome {
    let now = Utc::now();
    let kind = request.operation_kind();
    let not_found = || {
        web::WriteError::reject(
            404,
            web::CODE_ITEM_NOT_FOUND,
            "No message with that identifier exists in this workspace",
        )
    };
    match request {
        WriteRequest::EditDraft { id, revision, body } => {
            let job = match e.owned(id) {
                Ok(job) => job,
                Err(_) => return WriteOutcome::error(&not_found()),
            };
            if let Err(error) = web::guard_edit(&job, *revision, body, e.settings.mode) {
                return WriteOutcome::error(&error);
            }
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Saving your edited reply…",
            );
            let result = e.edit(id, *revision, body.clone());
            report_write(e, context, kind, result)
        }
        WriteRequest::Regenerate { id, revision } => {
            let job = match e.owned(id) {
                Ok(job) => job,
                Err(_) => return WriteOutcome::error(&not_found()),
            };
            if let Err(error) = web::guard_regenerate(&job, *revision, e.settings.mode, e.demo) {
                return WriteOutcome::error(&error);
            }
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Requesting a fresh local analysis…",
            );
            let result = e.regenerate(id, *revision);
            report_write(e, context, kind, result)
        }
        WriteRequest::Dismiss { id, revision } => {
            let job = match e.owned(id) {
                Ok(job) => job,
                Err(_) => return WriteOutcome::error(&not_found()),
            };
            if let Err(error) = web::guard_dismiss(&job, *revision) {
                return WriteOutcome::error(&error);
            }
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Dismissing the message…",
            );
            let result = e.dismiss(id, *revision);
            report_write(e, context, kind, result)
        }
        WriteRequest::Send {
            id,
            revision,
            confirm_reply,
        } => {
            let job = match e.owned(id) {
                Ok(job) => job,
                Err(_) => return WriteOutcome::error(&not_found()),
            };
            let blocks = crate::tui::hard_blocks_for(&job, &e.account);
            let busy = context
                .shared
                .lock()
                .map(|snapshot| {
                    !snapshot.busy.is_empty() || snapshot.operation.state == OperationState::Running
                })
                .unwrap_or(false);
            let runtime = web::SendRuntime {
                hard_blocks: &blocks,
                busy,
                sending_enabled: e.settings.sending_enabled,
                demo: e.demo,
                paused: e.paused.load(Ordering::SeqCst),
            };
            let send = web::SendRequest {
                id: id.as_str(),
                revision: *revision,
                confirm_reply: confirm_reply.as_str(),
            };
            if let Err(error) = web::guard_send(&job, &send, &runtime) {
                return WriteOutcome::error(&error);
            }
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Rechecking the conversation and sending your confirmed reply…",
            );
            let result = e.send(id, *revision, &hash(confirm_reply), false);
            report_write(e, context, kind, result)
        }
        WriteRequest::UpdateSettings {
            mode,
            tone,
            reply_language,
            sending_enabled,
        } => {
            let candidate =
                web::merge_settings(&e.settings, *mode, *tone, *reply_language, *sending_enabled);
            if let Err(error) = web::guard_settings(&candidate) {
                return WriteOutcome::error(&error);
            }
            begin_operation(context.shared, context.pulse, kind, "Updating settings…");
            let result = e.update_settings(candidate);
            let mut outcome = report_write(e, context, kind, result);
            outcome.merge_payload(web::settings_view(&e.settings));
            outcome
        }
        WriteRequest::AutomaticArm { action } => match action {
            web::AutomaticArmAction::Open => {
                let gate = AutomaticArmGate::open(now);
                *arm_gate = Some(gate);
                WriteOutcome::accepted_with(json!({"arm": web::arm_gate_view(&gate, now)}))
            }
            web::AutomaticArmAction::Cancel => {
                *arm_gate = None;
                WriteOutcome::accepted_with(json!({"arm": Value::Null}))
            }
            web::AutomaticArmAction::Confirm => {
                let view = match web::guard_arm_confirm(arm_gate.as_ref(), now) {
                    Ok(view) => view,
                    Err(error) => return WriteOutcome::error(&error),
                };
                let mut candidate = e.settings.clone();
                candidate.mode = Mode::Automatic;
                candidate.automatic_confirmed = true;
                candidate.automatic_since = Some(now);
                if let Err(error) = web::guard_settings(&candidate) {
                    return WriteOutcome::error(&error);
                }
                begin_operation(
                    context.shared,
                    context.pulse,
                    kind,
                    "Enabling Automatic mode after the risk confirmation…",
                );
                let result = e.update_settings(candidate);
                let mut outcome = report_write(e, context, kind, result);
                if outcome.status < 400 {
                    *arm_gate = None;
                    outcome = WriteOutcome::accepted_with(json!({"arm": view}));
                    outcome.merge_payload(web::settings_view(&e.settings));
                }
                outcome
            }
        },
    }
}

fn operation_state_for_result<T, E>(result: &std::result::Result<T, E>) -> OperationState {
    if result.is_ok() {
        OperationState::Succeeded
    } else {
        OperationState::Failed
    }
}

fn protect_audit_boundary<T>(engine: &Engine, result: Result<T>) -> Result<T> {
    protect_audit_boundary_with(&engine.paused, result, engine.checkpoint_audit_protection())
}

/// Combine an operation result with a protected-audit checkpoint outcome.
///
/// Inputs: `paused` — fail-closed worker pause flag; `result` — operation
/// outcome; `checkpoint` — protected-audit checkpoint outcome. Output: the
/// operation result when the checkpoint succeeded; otherwise an error that
/// names both failures and pauses the worker fail-closed.
fn protect_audit_boundary_with<T>(
    paused: &AtomicBool,
    result: Result<T>,
    checkpoint: Result<()>,
) -> Result<T> {
    match checkpoint {
        Ok(()) => result,
        Err(anchor_error) => {
            paused.store(true, Ordering::SeqCst);
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

fn record_circuit_transition(
    journal: &Option<RuntimeJournal>,
    transition: CircuitTransition,
    opened: RuntimeSignal,
    closed: RuntimeSignal,
) {
    let Some(journal) = journal else {
        return;
    };
    let event = match transition {
        CircuitTransition::Opened => Some(opened),
        CircuitTransition::Closed => Some(closed),
        CircuitTransition::None => None,
    };
    if let Some(event) = event {
        let _ = journal.record_signal(event);
    }
}

/// The interval a scheduled worker operation waits before running again.
///
/// Inputs: `default` — production cadence. Output: the effective cadence;
/// tests adopt a zero override through `crate::test_support` so every
/// scheduled operation fires on each loop iteration.
fn worker_interval(default: Duration) -> Duration {
    #[cfg(test)]
    if let Some(interval) = crate::test_support::worker_interval_override() {
        return interval;
    }
    default
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
    // Server-side cooldown gate for the web Automatic-arm flow; the 30-second
    // wait lives here, never in the page.
    let mut arm_gate: Option<AutomaticArmGate> = None;
    refresh(&e, &shared, None, review, page)?;
    let api_disabled = Arc::new(AtomicBool::new(false));
    if e.settings.api_enabled && !e.demo {
        let material = api_auth::load_or_create(&mut e.db)?;
        if let Some(token) = material.plaintext_once
            && let Ok(mut snapshot) = shared.lock()
        {
            snapshot.api_token = Some(token);
            snapshot.api_token_expires =
                Some(Instant::now() + worker_interval(Duration::from_secs(60)));
        }
        match crate::api::start_with_verifier(
            e.settings.api_port,
            material.verifier,
            sender,
            e.stop.clone(),
            api_disabled.clone(),
            pulse.clone(),
        ) {
            Ok(_) => {
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
    let now_instant = Instant::now();
    let mut gmail_gate = RetryGate::new(
        now_instant,
        Duration::from_secs(30),
        Duration::from_secs(15 * 60),
        3,
        Duration::from_secs(10 * 60),
    );
    let mut local_ai_gate = RetryGate::new(
        now_instant,
        Duration::from_secs(30),
        Duration::from_secs(10 * 60),
        4,
        Duration::from_secs(5 * 60),
    );
    let mut auto_due = Instant::now();
    let mut retention_due = Instant::now() + worker_interval(Duration::from_secs(60));
    let mut scheduled_backup_due = Instant::now() + worker_interval(Duration::from_secs(60));
    let mut policy_due = Instant::now() + worker_interval(Duration::from_secs(30));
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
            Ok(Command::ApiWrite { request, reply }) => {
                let context = WriteContext {
                    shared: &shared,
                    pulse: &pulse,
                    journal: &journal,
                    selected: selected.as_deref(),
                    review,
                    page,
                };
                let outcome = handle_api_write(&mut e, &request, &mut arm_gate, &context);
                let _ = reply.try_send(outcome);
            }
            Ok(Command::OpenMetrics { reply }) => {
                let data = crate::metrics::collect(&e, Utc::now()).and_then(|snapshot| {
                    let runtime = crate::runtime_log::performance_summary(&e.directory)?;
                    Ok(
                        crate::metrics::render_openmetrics_with_runtime_and_emergency(
                            &snapshot,
                            &runtime,
                            crate::emergency::status_fail_closed().active,
                        ),
                    )
                });
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
                        let result = e.synchronize().map(|_| ());
                        if result.is_ok() {
                            let transition = gmail_gate.success(Instant::now());
                            record_circuit_transition(
                                &journal,
                                transition,
                                RuntimeSignal::GmailCircuitOpened,
                                RuntimeSignal::GmailCircuitClosed,
                            );
                        }
                        result
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
                        install_ollama()
                    }
                    Command::StartOllama => Ollama::new(&e.settings).and_then(|o| o.start()),
                    Command::PullModel => {
                        busy(&shared, &pulse, "Downloading the selected local model…");
                        Ollama::new(&e.settings)
                            .and_then(|o| o.pull(&e.stop, |p| busy(&shared, &pulse, &p)))
                    }
                    Command::PullVerifierModel => {
                        busy(
                            &shared,
                            &pulse,
                            "Downloading the independent verifier model…",
                        );
                        Ollama::new(&e.settings)
                            .and_then(|o| o.pull_verifier(&e.stop, |p| busy(&shared, &pulse, &p)))
                    }
                    Command::InspectModel => {
                        busy(&shared, &pulse, "Refreshing local model status…");
                        e.inspect_model_status()
                    }
                    Command::InspectVerifierModel => {
                        busy(&shared, &pulse, "Refreshing independent verifier status…");
                        e.inspect_verifier_model_status()
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
                    Command::QualifyVerifierModel => {
                        busy(
                            &shared,
                            &pulse,
                            "Qualifying the independent verifier and checking sequential GPU residency…",
                        );
                        let r = e.qualify_verifier();
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
                    Command::ProfileModel => {
                        busy(
                            &shared,
                            &pulse,
                            "Profiling cold, warm-repeat and near-context local model behavior…",
                        );
                        e.profile_model_runtime().map(|_| ())
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
                    Command::CompactDatabase => {
                        busy(
                            &shared,
                            &pulse,
                            "Checkpointing, compacting and verifying encrypted SQLite state…",
                        );
                        e.compact_database().map(|_| ())
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
                    Command::ExportRecoveryKey { out, passphrase } => {
                        busy(
                            &shared,
                            &pulse,
                            "Wrapping the vault key for offline disaster recovery…",
                        );
                        let result = crate::recovery::export_recovery_key(
                            &e.directory,
                            passphrase.as_bytes(),
                            &out,
                        )
                        .map(|_| ());
                        if result.is_ok() {
                            e.db.log(
                                "recovery.key_exported",
                                None,
                                "Passphrase-wrapped recovery key exported",
                            )?;
                        }
                        result
                    }
                    Command::VerifyRecoveryKey {
                        backup,
                        recovery_key,
                        passphrase,
                    } => {
                        busy(
                            &shared,
                            &pulse,
                            "Authenticating the recovery key against the selected encrypted backup…",
                        );
                        let result = crate::recovery::verify_recovery_key_for_backup(
                            &backup,
                            &recovery_key,
                            passphrase.as_bytes(),
                        )
                        .map(|_| ());
                        if result.is_ok() {
                            e.db.log(
                                "recovery.key_verified",
                                None,
                                "Recovery key authenticated against an encrypted backup",
                            )?;
                        }
                        result
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
                    // A rejected reveal is a typed operation failure, never a
                    // reason to tear down the whole background worker.
                    Command::RevealApiToken => Err(anyhow::anyhow!(
                        "Existing API credentials are intentionally non-recoverable. Rotate the API token to receive a new plaintext credential once."
                    )),
                    Command::HideApiToken => {
                        if let Ok(mut s) = shared.lock() {
                            s.api_token = None;
                            s.api_token_expires = None;
                        }
                        Ok(())
                    }
                    Command::RotateApiToken => rotate_api_token(&mut e, &shared, &api_disabled),
                    Command::Api { .. }
                    | Command::OpenMetrics { .. }
                    | Command::ApiWrite { .. } => Err(anyhow::anyhow!(
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
                    policy_due = Instant::now() + worker_interval(Duration::from_secs(60));
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
                    policy_due = Instant::now()
                        + worker_interval(bounded_backoff(15, policy_failures, 5 * 60));
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
                retention_due = Instant::now() + worker_interval(Duration::from_secs(24 * 60 * 60));
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
                    scheduled_backup_due =
                        Instant::now() + worker_interval(Duration::from_secs(60 * 60));
                } else {
                    scheduled_backup_failures = scheduled_backup_failures.saturating_add(1);
                    scheduled_backup_due = Instant::now()
                        + bounded_backoff(15 * 60, scheduled_backup_failures, 2 * 60 * 60);
                }
                refresh(&e, &shared, selected.as_deref(), review, page)?;
            } else {
                scheduled_backup_failures = 0;
                scheduled_backup_due =
                    Instant::now() + worker_interval(Duration::from_secs(60 * 60));
            }
        } else if !e.settings.scheduled_backup_enabled {
            scheduled_backup_due = Instant::now() + worker_interval(Duration::from_secs(60));
        }

        if e.paused.load(Ordering::SeqCst) || e.demo || !e.connected() {
            continue;
        }
        let now = Utc::now();
        if gmail_gate.ready(Instant::now())
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
            let retry_after = operation_result
                .as_ref()
                .err()
                .and_then(crate::gmail::retry_after_hint);
            let result = protect_audit_boundary(&e, operation_result);
            let transition = if result.is_ok() {
                gmail_gate.success(Instant::now())
            } else {
                gmail_gate.failure(Instant::now(), retry_after).1
            };
            record_circuit_transition(
                &journal,
                transition,
                RuntimeSignal::GmailCircuitOpened,
                RuntimeSignal::GmailCircuitClosed,
            );
            report(&shared, &pulse, OperationKind::SyncMailbox, &result);
            record_current_operation(&journal, &shared);
            refresh(&e, &shared, selected.as_deref(), review, page)?;
        }
        if local_ai_gate.ready(Instant::now())
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
            let transition = if result.is_ok() {
                local_ai_gate.success(Instant::now())
            } else {
                local_ai_gate.failure(Instant::now(), None).1
            };
            record_circuit_transition(
                &journal,
                transition,
                RuntimeSignal::LocalAiCircuitOpened,
                RuntimeSignal::LocalAiCircuitClosed,
            );
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
                    auto_due = Instant::now() + worker_interval(Duration::from_secs(30));
                }
                Err(_) => {
                    automatic_failures = automatic_failures.saturating_add(1);
                    auto_due = Instant::now()
                        + worker_interval(bounded_backoff(30, automatic_failures, 10 * 60));
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
                    "api_rate_limit_burst": crate::api::API_RATE_LIMIT_BURST,
                    "api_rate_limit_per_second": crate::api::API_RATE_LIMIT_PER_SECOND,
                    "privacy_minimal_runtime_journal": true,
                    "snapshot_cursor_item_feed": true,
                    "enterprise_policy": true,
                    "enterprise_policy_digest_pin": true,
                    "enterprise_policy_ed25519_signature": true,
                    "enterprise_emergency_stop": true
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
            let backup_isolation =
                crate::recovery::backup_isolation_status(&e.directory, &e.settings)?;
            let paused = e.paused.load(Ordering::SeqCst);
            let stopping = e.stop.load(Ordering::SeqCst);
            let emergency_stop = crate::emergency::status_fail_closed();
            let readiness =
                crate::readiness::assess_context(crate::readiness::RuntimeReadinessContext {
                    settings: &e.settings,
                    database_integrity_ok: integrity_ok,
                    storage_write_safe: storage.runtime_write_safe,
                    connected: e.connected(),
                    send_scope: e.send_scope(),
                    paused,
                    stopping,
                    emergency_stop_active: emergency_stop.active,
                });
            let counts = e.db.counts(&e.account)?;
            let policy_status = e.enterprise_policy_status();
            let external_audit_anchor_configured =
                std::env::var_os(crate::audit_anchor::AUDIT_ANCHOR_ENV).is_some();
            let os_protected_audit_anchor_required = crate::audit_anchor::os_anchor_required()?;
            let independent_audit_anchor_configured =
                external_audit_anchor_configured || os_protected_audit_anchor_required;
            let operational =
                crate::readiness::operational_indicators(crate::readiness::OperationalContext {
                    settings: &e.settings,
                    counts: &counts,
                    last_poll: e.last_poll()?,
                    database_integrity_ok: integrity_ok,
                    storage_write_safe: storage.runtime_write_safe,
                    scheduled_backup_overdue: scheduled_backup.overdue,
                    backup_distinct_failure_domain: backup_isolation.distinct_failure_domain,
                    connected: e.connected(),
                    now: Utc::now(),
                });
            Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "settings_format_version": e.settings.settings_format_version,
                "healthy": readiness.workspace_ready,
                "readiness": readiness,
                "operational": operational,
                "storage": storage,
                "scheduled_backup": scheduled_backup,
                "backup_isolation": backup_isolation,
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
                "emergency_stop": emergency_stop,
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
        "/v1/settings" => {
            ensure!(
                query.is_empty(),
                "Settings endpoint takes no query parameters"
            );
            Ok(crate::web::settings_view(&e.settings))
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
            "/",
            "/v1/live",
            "/v1/openapi.json",
            "/v1/capabilities",
            "/v1/health",
            "/v1/status",
            "/v1/settings",
            "/v1/items",
            "/v1/item-feed",
            "/v1/items/{id}",
            "/v1/items/{id}/automatic-policy",
            "/v1/events",
            "/v1/audit/anchor",
            "/v1/audit/contains",
            "/v1/metrics",
            "/v1/metrics/openmetrics",
            "/v1/commands/edit-draft",
            "/v1/commands/regenerate",
            "/v1/commands/dismiss",
            "/v1/commands/send",
            "/v1/commands/update-settings",
            "/v1/commands/automatic-arm",
        ] {
            assert!(paths.contains_key(expected), "OpenAPI missing {expected}");
        }
        assert_eq!(paths.len(), 22);
        assert_eq!(spec["openapi"], "3.1.0");
    }

    // why: the web settings view is the page's only settings source; it must
    // stay minimal and non-secret — a stray credential, path or mailbox field
    // here would leak into every browser session.
    #[test]
    fn settings_route_exposes_only_non_secret_presentation_fields() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            dir.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let value = api_query(&engine, "/v1/settings").unwrap();
        assert_eq!(value["mode"], "human_review");
        assert_eq!(value["tone"], "hardline");
        assert_eq!(value["reply_language"], "auto");
        assert_eq!(value["sending_enabled"], false);
        assert_eq!(value["automatic_confirmed"], false);
        assert_eq!(
            value["automatic_arm_cooldown_seconds"],
            crate::config::AUTOMATIC_ARM_COOLDOWN_SECONDS
        );
        assert_eq!(value.as_object().unwrap().len(), 6);
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
        assert_eq!(health["emergency_stop"]["active"], false);
        assert_eq!(health["emergency_stop"]["configured"], false);
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
        let mut items = engine.db.list(&engine.account, true, 0, 25).unwrap();
        assert_eq!(items.len(), 3);
        let job = items.pop().unwrap();
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
        assert!(
            engine
                .db
                .meta::<String>(api_auth::LEGACY_TOKEN_META)
                .unwrap()
                .is_none()
        );
        let stored_verifier: String = engine.db.meta(api_auth::TOKEN_HASH_META).unwrap().unwrap();
        assert_eq!(stored_verifier.len(), 64);

        let snapshot = shared.lock().unwrap();
        assert!(!snapshot.api_listening);
        let displayed = snapshot
            .api_token
            .as_ref()
            .map(|token| token.as_str().to_owned())
            .unwrap();
        drop(snapshot);

        assert_ne!(displayed, old);
        assert!(displayed.len() >= 40);
        let verifier = api_auth::ApiTokenVerifier::from_hex(&stored_verifier).unwrap();
        assert!(verifier.verify_token(&displayed));
        assert!(!verifier.verify_token(&old));

        let events = engine.db.events(0, 100).unwrap();
        let event = events
            .iter()
            .find(|event| event.kind == "security.api_token_rotated")
            .unwrap();
        assert_eq!(event.domain, AuditDomain::Security);
        assert_eq!(event.severity, AuditSeverity::Security);
        assert!(!event.detail.contains(&old));
        assert!(!event.detail.contains(&displayed));
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
    fn rejected_queue_command_never_masks_an_inflight_send_or_backup() {
        for active in [OperationKind::SendReply, OperationKind::Backup] {
            let running = OperationStatus {
                kind: active,
                state: OperationState::Running,
                started_at: Some(Utc::now()),
                ..OperationStatus::default()
            };
            let mut snapshot = Snapshot {
                operation: running.clone(),
                ..Snapshot::default()
            };
            report_unqueued_command(&mut snapshot, OperationKind::Refresh, false);
            assert_eq!(snapshot.operation, running);
            assert!(snapshot.error.contains("full"));
            report_unqueued_command(&mut snapshot, OperationKind::Refresh, true);
            assert_eq!(snapshot.operation, running);
            assert!(snapshot.error.contains("disconnected"));
        }
    }

    #[test]
    fn rejected_idle_command_reports_the_actual_transport_failure() {
        let mut snapshot = Snapshot::default();
        report_unqueued_command(&mut snapshot, OperationKind::Refresh, false);
        assert_eq!(snapshot.operation.state, OperationState::Failed);
        assert_eq!(
            snapshot.operation.code.as_deref(),
            Some("worker_queue_busy")
        );
        assert!(snapshot.operation.retryable);

        report_unqueued_command(&mut snapshot, OperationKind::Refresh, true);
        assert_eq!(snapshot.operation.state, OperationState::Failed);
        assert_eq!(
            snapshot.operation.code.as_deref(),
            Some("worker_disconnected")
        );
        assert!(!snapshot.operation.retryable);
    }

    #[test]
    fn delivery_failure_semantics_never_recommend_blind_retry() {
        let uncertain = anyhow::Error::new(crate::engine::DispatchFailure::reconcile(
            "Synthetic uncertain delivery",
        ));
        let (code, retryable) = classify_operation_failure(OperationKind::SendReply, &uncertain);
        assert_eq!(code, "reconcile_required_delivery_uncertain");
        assert!(!retryable);

        let rejected = anyhow::Error::new(crate::engine::DispatchFailure::review(
            "Synthetic provider rejection",
        ));
        let (code, retryable) = classify_operation_failure(OperationKind::SendReply, &rejected);
        assert!(code.starts_with("review_required_"));
        assert!(!retryable);

        let retry = anyhow::Error::new(crate::engine::DispatchFailure::retryable(
            "Synthetic preflight outage",
        ));
        let (code, retryable) = classify_operation_failure(OperationKind::SendReply, &retry);
        assert_eq!(code, "retryable_dispatch");
        assert!(retryable);
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

#[cfg(test)]
mod orchestration_tests {
    use super::*;
    use crate::engine::Engine;
    use crate::gmail::{FetchFailure, FetchFailureKind};
    use crate::test_support::MockServer;
    use crate::web::{AutomaticArmAction, WriteRequest};
    use std::sync::atomic::AtomicBool;

    fn demo_engine(dir: &std::path::Path) -> Engine {
        Engine::open(
            dir.to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    fn ctx<'a>(
        shared: &'a Arc<Mutex<Snapshot>>,
        pulse: &'a WorkerPulse,
        journal: &'a Option<RuntimeJournal>,
    ) -> WriteContext<'a> {
        WriteContext {
            shared,
            pulse,
            journal,
            selected: None,
            review: true,
            page: 0,
        }
    }

    /// The lifecycle helpers must publish one consistent typed operation
    /// status so every surface (desktop, terminal, web) reports identically.
    #[test]
    fn operation_lifecycle_helpers_publish_typed_status() {
        let dir = tempfile::tempdir().unwrap();
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::new();
        assert_eq!(
            WorkerPulse::default().snapshot(Utc::now()).schema_version,
            1
        );
        pulse.progress();

        begin_operation(&shared, &pulse, OperationKind::Refresh, "Working locally…");
        busy(&shared, &pulse, "Halfway there…");
        {
            let snapshot = shared.lock().unwrap();
            assert_eq!(snapshot.busy, "Halfway there…");
            assert_eq!(snapshot.operation.state, OperationState::Running);
            assert_eq!(snapshot.operation.message, "Halfway there…");
        }
        assert_eq!(current_operation(&shared).kind, OperationKind::Refresh);

        let journal = RuntimeJournal::open(dir.path()).ok();
        record_current_operation(&journal, &shared);
        record_current_operation(&None, &shared);

        report(&shared, &pulse, OperationKind::Refresh, &Ok(()));
        {
            let snapshot = shared.lock().unwrap();
            assert_eq!(snapshot.operation.state, OperationState::Succeeded);
            assert!(snapshot.busy.is_empty());
        }

        report(
            &shared,
            &pulse,
            OperationKind::Refresh,
            &Err(anyhow::anyhow!("synthetic failure")),
        );
        {
            let snapshot = shared.lock().unwrap();
            assert_eq!(snapshot.operation.state, OperationState::Failed);
            assert!(snapshot.error.contains("synthetic failure"));
            assert!(snapshot.notice.is_empty());
        }

        report_silent_success(
            &shared,
            &pulse,
            OperationKind::ReconcileDelivery,
            "quiet success",
        );
        {
            let snapshot = shared.lock().unwrap();
            assert_eq!(snapshot.operation.state, OperationState::Succeeded);
            assert_eq!(snapshot.operation.message, "quiet success");
        }
    }

    /// A poisoned snapshot lock must degrade to the default liveness record
    /// instead of panicking across the worker boundary.
    #[test]
    fn poisoned_pulse_reports_the_unresponsive_default() {
        let pulse = WorkerPulse::new();
        let inner = pulse.inner.clone();
        let handle = std::thread::spawn(move || {
            let _guard = inner.lock().unwrap();
            panic!("poison the pulse state");
        });
        let _ = handle.join();
        let liveness = pulse.snapshot(Utc::now());
        assert!(!liveness.worker_responsive);
        assert_eq!(liveness.progress_age_seconds, 0);
    }

    #[test]
    fn classify_operation_failure_maps_gmail_fetch_failures() {
        let infrastructure = anyhow::Error::new(FetchFailure {
            kind: FetchFailureKind::Infrastructure,
            message: "transport".into(),
        });
        assert_eq!(
            classify_operation_failure(OperationKind::Refresh, &infrastructure),
            ("retryable_gmail_fetch".into(), true)
        );
        let malformed = anyhow::Error::new(FetchFailure {
            kind: FetchFailureKind::MalformedMessage,
            message: "bad message".into(),
        });
        assert_eq!(
            classify_operation_failure(OperationKind::Refresh, &malformed),
            ("review_required_malformed_message".into(), false)
        );
    }

    #[test]
    fn engine_write_errors_keep_the_retry_semantics() {
        let retryable = anyhow::Error::new(crate::engine::DispatchFailure::retryable("later"));
        let error = engine_write_error(OperationKind::SendReply, &retryable);
        assert_eq!(error.status, 503);
        assert!(error.retryable);
        let rejected = anyhow::Error::new(crate::engine::DispatchFailure::review("blocked"));
        let error = engine_write_error(OperationKind::SendReply, &rejected);
        assert_eq!(error.status, 409);
        assert!(!error.retryable);
    }

    #[test]
    fn protected_audit_failure_pauses_the_worker_fail_closed() {
        let paused = AtomicBool::new(false);
        let result: Result<()> = Ok(());
        let checked =
            protect_audit_boundary_with(&paused, result, Err(anyhow::anyhow!("anchor down")));
        assert!(checked.is_err());
        assert!(
            checked.unwrap_err().to_string().contains("worker paused"),
            "error must name the fail-closed pause"
        );
        assert!(paused.load(Ordering::SeqCst));

        // Both failures are reported together so neither is masked.
        let checked: Result<()> = protect_audit_boundary_with(
            &AtomicBool::new(false),
            Err(anyhow::anyhow!("operation broke")),
            Err(anyhow::anyhow!("anchor down")),
        );
        let message = checked.unwrap_err().to_string();
        assert!(message.contains("operation broke"), "{message}");
        assert!(message.contains("anchor down"), "{message}");

        // A healthy checkpoint passes the operation result through.
        let checked = protect_audit_boundary_with(&AtomicBool::new(false), Ok(7), Ok(()));
        assert_eq!(checked.unwrap(), 7);
    }

    #[test]
    fn circuit_transitions_are_journaled_only_on_change() {
        let dir = tempfile::tempdir().unwrap();
        let journal = RuntimeJournal::open(dir.path()).ok();
        record_circuit_transition(
            &journal,
            CircuitTransition::Opened,
            RuntimeSignal::GmailCircuitOpened,
            RuntimeSignal::GmailCircuitClosed,
        );
        record_circuit_transition(
            &journal,
            CircuitTransition::Closed,
            RuntimeSignal::GmailCircuitOpened,
            RuntimeSignal::GmailCircuitClosed,
        );
        record_circuit_transition(
            &journal,
            CircuitTransition::None,
            RuntimeSignal::GmailCircuitOpened,
            RuntimeSignal::GmailCircuitClosed,
        );
        record_circuit_transition(
            &None,
            CircuitTransition::Opened,
            RuntimeSignal::LocalAiCircuitOpened,
            RuntimeSignal::LocalAiCircuitClosed,
        );
    }

    #[test]
    fn api_write_surface_runs_the_shared_write_machinery() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = demo_engine(dir.path());
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::new();
        let journal = RuntimeJournal::open(dir.path()).ok();
        let context = ctx(&shared, &pulse, &journal);
        let mut gate: Option<AutomaticArmGate> = None;
        let items = e.db.list(&e.account, true, 0, 25).unwrap();
        let id = items[0].id.clone();
        let revision = items[0].revision;

        // Unknown ids come back typed without recording an operation.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::EditDraft {
                id: "00".repeat(32),
                revision,
                body: "Please explain the specific criteria used.".into(),
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 404);
        assert_eq!(outcome.body["code"], web::CODE_ITEM_NOT_FOUND);

        // A stale revision is refused by the shared edit gate.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::EditDraft {
                id: id.clone(),
                revision: revision + 5,
                body: "Please explain the specific criteria used.".into(),
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 409);

        // A valid edit runs the begin/report/refresh machinery end to end.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::EditDraft {
                id: id.clone(),
                revision,
                body: "Please explain the specific criteria used.".into(),
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 200);

        // Demo regeneration is refused and reported as a typed failure.
        let job = e.owned(&id).unwrap();
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Regenerate {
                id: id.clone(),
                revision: job.revision,
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 409);

        // Dismissal succeeds and records the operation.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Dismiss {
                id: id.clone(),
                revision: job.revision,
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 200);

        // Send rejects unknown ids before touching anything.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Send {
                id: "11".repeat(32),
                revision: 0,
                confirm_reply: "x".into(),
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 404);

        // The automatic-arm flow opens, cancels and confirms through the gate.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Open,
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 200);
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Cancel,
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 200);
        // Confirming without an open gate is typed, not executed.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Confirm,
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 409);
    }

    /// The web confirm path must only arm Automatic after the cooldown and a
    /// configuration that passes every send gate.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn automatic_arm_confirm_only_arms_a_qualified_configuration() {
        let dir = tempfile::tempdir().unwrap();
        // A real (non-demo) workspace: demo mode can never enable sending.
        let mut e = Engine::open(
            dir.path().to_path_buf(),
            false,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let _cleanup = CredentialCleanup(crate::vault::vault_id(dir.path()).unwrap());
        // Arm the engine as a qualified Automatic workspace with send scope.
        crate::test_support::arm_automatic(&mut e.settings);
        let server = MockServer::new(|_, _| None);
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            crate::oauth::Credentials {
                client_id: "id".into(),
                client_secret: "secret".into(),
                refresh_token: "refresh".into(),
                can_send: true,
            },
            &server.url,
            &server.url,
        ));
        e.db.set_meta("settings", &e.settings).unwrap();

        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::new();
        let journal = RuntimeJournal::open(dir.path()).ok();
        let context = ctx(&shared, &pulse, &journal);
        // A gate whose cooldown elapsed long ago may be confirmed now.
        let mut gate = Some(AutomaticArmGate::open(
            Utc::now() - chrono::Duration::seconds(3600),
        ));
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Confirm,
            },
            &mut gate,
            &context,
        );
        assert_eq!(outcome.status, 200, "body: {}", outcome.body);
        assert!(gate.is_none(), "the confirmed gate must be consumed");
        assert_eq!(e.settings.mode, crate::config::Mode::Automatic);
    }

    /// Every command the dispatch loop recognizes must route to its engine
    /// operation (or stable refusal) without ever stalling or crashing the
    /// worker. The model commands run against a scriptable local runtime and
    /// the installer against an injected runner.
    #[test]
    fn dispatch_loop_executes_every_command_arm() {
        let dir = tempfile::tempdir().unwrap();
        let mut worker = Worker::spawn(dir.path().into(), true);
        let start = Instant::now();
        while !worker.view().initialized {
            assert!(!worker.view().fatal, "{}", worker.view().error);
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "worker did not initialize"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let runtime = crate::test_support::MockServer::new(|route, _| match route {
            "/api/version" => Some(serde_json::json!({"version": "0.35.1"})),
            "/api/pull" => Some(serde_json::json!({"status": "success"})),
            _ => None,
        });

        let mut settings = worker.view().settings;
        settings.ollama_url = runtime.url.clone();
        settings.signature = "Test Applicant".into();
        worker.command(Command::Settings(Box::new(settings)));

        let items = worker.view().items.clone();
        let (id, revision) = (items[0].id.clone(), items[0].revision);

        let commands = vec![
            Command::Refresh,
            Command::CheckNow,
            Command::List {
                review: true,
                page: 0,
            },
            Command::Select(id.clone()),
            Command::Edit {
                id: id.clone(),
                revision,
                body: "Please explain the specific criteria used.".into(),
            },
            Command::Regenerate {
                id: id.clone(),
                revision,
            },
            Command::Dismiss {
                id: id.clone(),
                revision,
            },
            Command::Send {
                id: id.clone(),
                revision,
                body_hash: "deadbeef".into(),
            },
            Command::Reconcile(id.clone()),
            Command::Purge,
            Command::IntegrityCheck,
            Command::CompactDatabase,
            Command::Backup {
                out: dir.path().join("backup-out"),
            },
            Command::ExportRecoveryKey {
                out: dir.path().join("recovery-key.json"),
                passphrase: Zeroizing::new("correct horse battery staple".into()),
            },
            Command::VerifyRecoveryKey {
                backup: dir.path().join("missing-backup"),
                recovery_key: dir.path().join("missing-key"),
                passphrase: Zeroizing::new("correct horse battery staple".into()),
            },
            Command::Diagnostics {
                out: dir.path().join("diagnostics.json"),
            },
            Command::InspectModel,
            Command::InspectVerifierModel,
            Command::QualifyModel,
            Command::QualifyVerifierModel,
            Command::ProfileModel,
            Command::CompareModels,
            Command::PullModel,
            Command::PullVerifierModel,
            Command::StartOllama,
            Command::RevealApiToken,
            Command::HideApiToken,
            Command::RotateApiToken,
            Command::Disconnect,
            Command::Connect {
                path: dir.path().join("missing-oauth.json"),
                send: false,
            },
        ];
        for command in commands {
            // Completion is detected by the operation id advancing: a plain
            // state check would race ahead of the queue while a command is
            // still pending and overflow the bounded channel.
            let before = worker.view().operation.operation_id.clone();
            worker.command(command);
            let start = Instant::now();
            loop {
                let snapshot = worker.view();
                assert!(!snapshot.fatal, "{}", snapshot.error);
                if snapshot.operation.operation_id != before
                    && snapshot.operation.state != OperationState::Running
                    && snapshot.busy.is_empty()
                {
                    break;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(30),
                    "command did not finish"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        // API relay commands answer on their reply channels.
        let snapshot = worker.view();
        assert!(
            !snapshot.fatal,
            "worker died before the API relay: {}",
            snapshot.error
        );
        let (reply_tx, reply_rx) = bounded(1);
        worker.command(Command::Api {
            path: "/v1/health".into(),
            reply: reply_tx,
        });
        assert!(reply_rx.recv_timeout(Duration::from_secs(10)).is_ok());
        let (reply_tx, reply_rx) = bounded(1);
        worker.command(Command::OpenMetrics { reply: reply_tx });
        assert!(reply_rx.recv_timeout(Duration::from_secs(10)).is_ok());
        let (reply_tx, reply_rx) = bounded(1);
        worker.command(Command::ApiWrite {
            request: WriteRequest::Dismiss {
                id: id.clone(),
                revision,
            },
            reply: reply_tx,
        });
        assert!(reply_rx.recv_timeout(Duration::from_secs(10)).is_ok());

        // The installer command routes through the injected runner so the
        // dispatch arm runs without spawning the real installer.
        fn no_install() -> Result<()> {
            anyhow::bail!("installer disabled in tests")
        }
        crate::test_support::with_installer(no_install, || {
            let before = worker.view().operation.operation_id.clone();
            worker.command(Command::InstallOllama);
            let start = Instant::now();
            loop {
                let snapshot = worker.view();
                assert!(!snapshot.fatal, "{}", snapshot.error);
                if snapshot.operation.operation_id != before
                    && snapshot.operation.state != OperationState::Running
                {
                    assert!(
                        snapshot.operation.state == OperationState::Failed,
                        "unexpected install outcome: {:?}",
                        snapshot.operation
                    );
                    break;
                }
                assert!(start.elapsed() < Duration::from_secs(10));
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        assert!(worker.shutdown(Duration::from_secs(5)));
    }

    /// A queue that is full or disconnected must surface the transport state
    /// instead of silently dropping commands.
    #[test]
    fn command_dispatch_reports_queue_pressure() {
        let (tx, rx) = bounded(1);
        let worker = Worker {
            tx,
            snapshot: Arc::new(Mutex::new(Snapshot::default())),
            paused: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            pulse: WorkerPulse::new(),
            join: None,
        };
        // A full queue reports pressure without disturbing running operations.
        let _ = worker.tx.send(Command::Refresh);
        worker.command(Command::CheckNow);
        assert!(worker.view().error.contains("full"));
        // A disconnected queue reports that distinctly.
        drop(rx);
        worker.command(Command::Refresh);
        assert!(worker.view().error.contains("disconnected"));
        assert_eq!(worker.view().operation.state, OperationState::Failed);
    }

    /// A worker whose workspace cannot open must publish the typed fatal
    /// state and journal the startup failure instead of hanging silently.
    #[test]
    fn failed_workspace_open_publishes_the_fatal_state() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vault-id"), b"not-a-uuid").unwrap();
        let mut worker = Worker::spawn(dir.path().into(), false);
        let start = Instant::now();
        loop {
            let snapshot = worker.view();
            if snapshot.fatal {
                assert!(!snapshot.error.is_empty());
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "worker did not report the fatal startup failure"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(worker.shutdown(Duration::from_secs(2)));
    }

    /// Recovery commands must round-trip on a real keyring-backed workspace:
    /// backup, isolated drill, key export and key verification all succeed
    /// without stalling the worker.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn recovery_commands_round_trip_on_a_real_workspace() {
        // Share the cross-test credential-store lock: parallel in-process
        // tests use the same OS credential store, and this workspace round
        // trip must not observe another test's transient vault identifiers.
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let dir = tempfile::tempdir().unwrap();
        let mut worker = Worker::spawn(dir.path().into(), false);
        let start = Instant::now();
        while !worker.view().initialized {
            assert!(!worker.view().fatal, "{}", worker.view().error);
            assert!(start.elapsed() < Duration::from_secs(10), "no init");
            std::thread::sleep(Duration::from_millis(10));
        }
        let vault_id = crate::vault::vault_id(dir.path()).unwrap();
        let _cleanup = CredentialCleanup(vault_id);

        let bundle = dir.path().join("backup-out");
        let key_file = dir.path().join("recovery-key.json");
        let commands = vec![
            Command::Backup {
                out: bundle.clone(),
            },
            Command::RecoveryDrill {
                backup: bundle.clone(),
            },
            Command::ExportRecoveryKey {
                out: key_file.clone(),
                passphrase: Zeroizing::new("correct horse battery staple".into()),
            },
            Command::VerifyRecoveryKey {
                backup: bundle.clone(),
                recovery_key: key_file.clone(),
                passphrase: Zeroizing::new("correct horse battery staple".into()),
            },
        ];
        for command in commands {
            let before = worker.view().operation.operation_id.clone();
            worker.command(command);
            let start = Instant::now();
            loop {
                let snapshot = worker.view();
                assert!(!snapshot.fatal, "{}", snapshot.error);
                if snapshot.operation.operation_id != before
                    && snapshot.operation.state != OperationState::Running
                    && snapshot.busy.is_empty()
                {
                    assert_eq!(
                        snapshot.operation.state,
                        OperationState::Succeeded,
                        "recovery command failed: {}",
                        snapshot.error
                    );
                    break;
                }
                assert!(start.elapsed() < Duration::from_secs(60), "stalled");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert!(worker.shutdown(Duration::from_secs(5)));
    }

    /// Removes the OS credential minted for a test workspace even when an
    /// assertion panics, so repeated runs never collide with stale keys.
    #[cfg(any(windows, target_os = "macos"))]
    struct CredentialCleanup(String);
    #[cfg(any(windows, target_os = "macos"))]
    impl Drop for CredentialCleanup {
        fn drop(&mut self) {
            let _ = keyring::Entry::new("rejection-rejector.v1", &self.0)
                .and_then(|entry| entry.delete_credential());
        }
    }

    /// Open a live (non-demo) workspace for orchestration tests.
    ///
    /// Why: non-demo opens derive the vault key from the OS credential store on
    /// Windows and macOS and from the documented `RR_VAULT_PASSPHRASE` input on
    /// headless hosts; arming the headless vault seam here keeps both the test
    /// thread's own open and the worker thread's later open deriving the same
    /// key on every platform.
    fn live_engine(dir: &std::path::Path) -> Engine {
        let seam_calls_before = crate::test_support::headless_vault_seam_calls();
        crate::test_support::headless_vault_seam();
        // The arming must be observable: a mutant deleting the call above is
        // otherwise silent on Windows/macOS where the seam body is a no-op.
        assert!(
            crate::test_support::headless_vault_seam_calls() > seam_calls_before,
            "headless vault seam must be armed before live opens"
        );
        Engine::open(
            dir.to_path_buf(),
            false,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    /// Poll `pred` until it holds or a generous deadline expires.
    fn wait_for(mut pred: impl FnMut() -> bool) -> bool {
        for _ in 0..400 {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    /// Every read-only integration API route answers its contracted payload
    /// and rejects malformed queries or identifiers.
    #[test]
    fn api_query_routes_cover_the_read_surface() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let e = demo_engine(dir.path());

        assert!(
            api_query_with_operation(&e, "/v1/metrics", None)
                .unwrap()
                .is_object()
        );
        let status = api_query_with_operation(&e, "/v1/status", None).unwrap();
        assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));

        // The cursor feed pages deterministically and re-encodes its cursor.
        let feed = api_query_with_operation(&e, "/v1/item-feed?limit=1", None).unwrap();
        assert_eq!(feed["schema_version"], 1);
        if let Some(cursor) = feed["next_cursor"].as_str() {
            let next = api_query_with_operation(
                &e,
                &format!("/v1/item-feed?limit=1&cursor={cursor}"),
                None,
            )
            .unwrap();
            assert!(next["items"].as_array().is_some());
        }
        assert!(api_query_with_operation(&e, "/v1/item-feed?limit=0", None).is_err());

        // The page variant enforces its range.
        let page = api_query_with_operation(&e, "/v1/items?page=1", None).unwrap();
        assert_eq!(page["page"], 1);
        assert!(api_query_with_operation(&e, "/v1/items?page=999999999", None).is_err());
        assert!(api_query_with_operation(&e, "/v1/items?page=1&x=2", None).is_err());

        // Events accept exactly the `after` cursor.
        let events = api_query_with_operation(&e, "/v1/events?after=0", None).unwrap();
        assert!(events["events"].as_array().is_some());
        assert!(api_query_with_operation(&e, "/v1/events?after=x", None).is_err());

        // Item and policy lookups validate their identifiers.
        let items = api_query_with_operation(&e, "/v1/items?page=0", None).unwrap();
        let id = items["items"][0]["id"].as_str().unwrap().to_owned();
        let item = api_query_with_operation(&e, &format!("/v1/items/{id}"), None).unwrap();
        assert_eq!(item["id"], id);
        let decision =
            api_query_with_operation(&e, &format!("/v1/items/{id}/automatic-policy"), None)
                .unwrap();
        assert!(decision.get("eligible").is_some());
        assert!(
            api_query_with_operation(&e, "/v1/items/not!valid", None).is_err(),
            "identifiers must be validated"
        );
        assert!(
            api_query_with_operation(&e, &format!("/v1/items/{id}?x=1"), None).is_err(),
            "item lookups take no query parameters"
        );

        // Unknown routes fail loudly.
        assert!(api_query_with_operation(&e, "/v1/nope", None).is_err());
    }

    /// Each web write arm executes its engine operation and maps failures onto
    /// the stable error envelope.
    #[test]
    fn handle_api_write_arms_execute_their_engine_operations() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live_engine(dir.path());
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::new();
        let journal = None;
        let mut arm_gate = None;
        let now = Utc::now();

        // Seed one Ready message.
        let mut job = crate::test_support::eligible_job(&e.settings, &e.account, 1, now);
        e.db.insert_stubs([job.stub.clone()], now).unwrap();
        e.db.save(&mut job, "test.seed", "seeded").unwrap();
        let id = job.id.clone();
        let revision = job.revision;
        let body = job.draft.as_ref().unwrap().body.clone();

        // Unknown messages answer 404 through the stable envelope.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::EditDraft {
                id: "f".repeat(64),
                revision,
                body: body.clone(),
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 404);
        assert!(
            outcome.body["code"] == crate::web::CODE_ITEM_NOT_FOUND,
            "body: {:?}",
            outcome.body
        );

        // An invalid edit is rejected before any state change.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::EditDraft {
                id: id.clone(),
                revision: revision + 7,
                body: body.clone(),
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert!(outcome.status >= 400);
        assert_eq!(e.db.get(&id).unwrap().state, JobState::Ready);

        // Regeneration returns the message to the analysis queue.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Regenerate {
                id: id.clone(),
                revision,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 200, "body: {:?}", outcome.body);
        assert_eq!(e.db.get(&id).unwrap().state, JobState::Queued);

        // Dismissal releases a message without sending.
        let mut job2 = crate::test_support::eligible_job(&e.settings, &e.account, 2, now);
        e.db.insert_stubs([job2.stub.clone()], now).unwrap();
        e.db.save(&mut job2, "test.seed", "seeded").unwrap();
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Dismiss {
                id: job2.id.clone(),
                revision: job2.revision,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 200);
        assert_eq!(e.db.get(&job2.id).unwrap().state, JobState::Dismissed);

        // Settings writes merge the resulting view into the response.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::UpdateSettings {
                mode: None,
                tone: None,
                reply_language: None,
                sending_enabled: None,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 200);
        assert!(
            outcome.body.get("mode").is_some(),
            "body: {:?}",
            outcome.body
        );

        // The send arm rechecks the confirmation and dispatches exactly the
        // persisted draft against the provider.
        e.settings.sending_enabled = true;
        e.db.set_meta("settings", &e.settings).unwrap();
        let mut job3 = crate::test_support::eligible_job(&e.settings, &e.account, 3, now);
        e.db.insert_stubs([job3.stub.clone()], now).unwrap();
        e.db.save(&mut job3, "test.seed", "seeded").unwrap();
        let email = job3.email.clone().unwrap();
        let gmail = crate::test_support::gmail_server(
            &e.account,
            vec![email],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000003".into()),
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            crate::oauth::Credentials {
                client_id: "id".into(),
                client_secret: "secret".into(),
                refresh_token: "refresh".into(),
                can_send: true,
            },
            &gmail.url,
            &gmail.url,
        ));
        // A mismatched confirmation is rejected before dispatch.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Send {
                id: job3.id.clone(),
                revision: job3.revision,
                confirm_reply: "not the draft".into(),
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert!(outcome.status >= 400);
        // The exact confirmation dispatches.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Send {
                id: job3.id.clone(),
                revision: job3.revision,
                confirm_reply: job3.draft.as_ref().unwrap().body.clone(),
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 200, "body: {:?}", outcome.body);
        assert_eq!(e.db.get(&job3.id).unwrap().state, JobState::Sent);

        // The arm gate: immediate confirmation is rejected, an aged gate arms.
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Open,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert!(outcome.body["arm"].is_object(), "body: {:?}", outcome.body);
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Confirm,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert!(outcome.status >= 400, "cooldown must hold");
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Cancel,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert!(outcome.body["arm"].is_null());
        arm_gate = Some(AutomaticArmGate::open(
            Utc::now() - chrono::Duration::seconds(60),
        ));
        e.settings.sending_enabled = true;
        e.settings.model_digest = Some("a".repeat(64));
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Confirm,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        // Automatic mode needs a send-scope workspace; either it arms or the
        // guard rejects with the stable envelope.
        if outcome.status < 400 {
            assert_eq!(e.settings.mode, Mode::Automatic);
        } else {
            assert!(outcome.body["code"].is_string(), "body: {:?}", outcome.body);
        }
    }

    /// Seed a connected workspace whose integration API listens on `api_port`.
    fn seed_worker_workspace(dir: &std::path::Path, api_port: u16, mock: &MockServer) {
        let mut e = live_engine(dir);
        e.settings.api_enabled = true;
        e.settings.api_port = api_port;
        crate::test_support::with_login(
            crate::oauth::Credentials {
                client_id: "id".into(),
                client_secret: "secret".into(),
                refresh_token: "refresh".into(),
                can_send: true,
            },
            &mock.url,
            &mock.url,
            || {
                e.connect(&dir.join("oauth.json"), true).unwrap();
            },
        );
    }

    /// Ask the worker one read query and return its reply.
    fn api(w: &Worker, path: &str) -> serde_json::Value {
        let (tx, rx) = bounded(1);
        w.command(Command::Api {
            path: path.into(),
            reply: tx,
        });
        rx.recv_timeout(Duration::from_secs(10)).unwrap()
    }

    /// The worker loop runs every scheduled operation on its timer, applies
    /// enterprise policy changes fail-closed, and keeps the integration API
    /// state honest.
    #[test]
    fn worker_loop_timers_drive_scheduled_operations() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api_port = listener.local_addr().unwrap().port();
        // Keep the reservation bound through workspace setup and release it
        // only at the last moment before Worker::spawn (below): dropping it
        // here would open a multi-second window where a parallel test could
        // re-bind the port and break the API bind.
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        seed_worker_workspace(dir.path(), api_port, &mock);
        let restrictive = crate::test_support::loaded_policy(
            "digest-a",
            crate::policy::EnterprisePolicy {
                version: 1,
                force_human_review: true,
                prohibit_integration_api: true,
                ..Default::default()
            },
        );
        let reload_calls = std::sync::atomic::AtomicUsize::new(0);
        let loader: crate::test_support::PolicyLoader = std::sync::Arc::new(move || {
            if reload_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                None
            } else {
                Some(restrictive.clone())
            }
        });
        crate::test_support::arm_worker_seams(
            Some(loader),
            None,
            None,
            None,
            Some(Duration::ZERO),
            Some((mock.url.clone(), mock.url.clone())),
            || {
                // Release the port reservation microseconds before the API
                // binds it (see the reservation comment above).
                drop(listener);
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                // The scheduled policy reload applies the restrictive policy
                // and disables the prohibited integration API surface.
                assert!(
                    wait_for(|| api(&w, "/v1/status")["enterprise_policy"]["active"]
                        == serde_json::json!(true)),
                    "the policy timer never applied the enterprise policy"
                );
                assert!(
                    wait_for(|| !w.view().api_listening),
                    "a prohibited API surface must be marked closed"
                );
                // The recurring timered operations run and publish their
                // outcomes (the mail poll parks on its cursor after the first
                // pass and is exercised through CheckNow below).
                let mut kinds = std::collections::BTreeSet::new();
                for _ in 0..300 {
                    kinds.insert(format!("{:?}", w.view().operation.kind));
                    if kinds.len() >= 3 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                for expected in ["PurgeRetention", "AutomaticDispatch"] {
                    assert!(
                        kinds.iter().any(|k| k.contains(expected)),
                        "scheduled {expected} never ran; saw {kinds:?}"
                    );
                }
                // A manual provider check succeeds against the scripted API.
                // A manual provider check refreshes the poll cursor.
                let before = api(&w, "/v1/status")["last_poll"].clone();
                w.command(Command::CheckNow);
                assert!(
                    wait_for(|| api(&w, "/v1/status")["last_poll"] != before
                        && api(&w, "/v1/status")["last_poll"].is_string()),
                    "manual provider checks must move the poll cursor"
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
    }

    /// A rollback attempt on the enterprise policy revision floor fails
    /// closed: the worker pauses delivery and surfaces the failure.
    #[test]
    fn worker_policy_rollback_pauses_fail_closed() {
        use crate::policy::{PolicyRevisionFloor, PolicyRevisionRecord};
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        {
            let mut e = live_engine(dir.path());
            // The workspace already accepted revision 2 of this policy.
            let mut floor = PolicyRevisionFloor::default();
            floor.policies.insert(
                "corp.policy".into(),
                PolicyRevisionRecord {
                    revision: 2,
                    digest: "digest-newer".into(),
                },
            );
            e.db.set_meta("enterprise_policy_revision_floor", &floor)
                .unwrap();
        }
        let rollback = crate::test_support::loaded_policy(
            "digest-older",
            crate::policy::EnterprisePolicy {
                version: 2,
                policy_id: Some("corp.policy".into()),
                revision: Some(1),
                ..Default::default()
            },
        );
        let reload_calls = std::sync::atomic::AtomicUsize::new(0);
        let loader: crate::test_support::PolicyLoader = std::sync::Arc::new(move || {
            if reload_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                None
            } else {
                Some(rollback.clone())
            }
        });
        crate::test_support::arm_worker_seams(
            Some(loader),
            None,
            None,
            None,
            Some(Duration::ZERO),
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                let paused = wait_for(|| w.paused.load(Ordering::SeqCst));
                assert!(
                    paused,
                    "a rejected policy rollback must pause delivery fail-closed; error: {} fatal: {}",
                    w.view().error,
                    w.view().fatal
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
    }

    /// When the integration API port is unavailable the worker records the
    /// startup failure instead of pretending the surface is live.
    #[test]
    fn worker_reports_integration_api_startup_failures() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let busy_port = listener.local_addr().unwrap().port();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        // A free port starts the listener and marks the surface live.
        let free_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let free_port = free_listener.local_addr().unwrap().port();
        drop(free_listener);
        seed_worker_workspace(dir.path(), free_port, &mock);
        crate::test_support::arm_worker_seams(
            None,
            None,
            None,
            None,
            Some(Duration::ZERO),
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                assert!(
                    wait_for(|| w.view().api_listening),
                    "a free API port must come up, error: {}",
                    w.view().error
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
        // An occupied port is reported instead of silently ignored.
        seed_worker_workspace(dir.path(), busy_port, &mock);
        crate::test_support::arm_worker_seams(
            None,
            None,
            None,
            None,
            Some(Duration::ZERO),
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                assert!(
                    wait_for(|| w.view().error.contains("Integration API did not start")),
                    "an unavailable API port must be reported, error: {}",
                    w.view().error
                );
                assert!(!w.view().api_listening);
                drop(listener);
                w.shutdown(Duration::from_secs(10));
            },
        );
    }
}
