use crate::mail_transport::AppPasswordCredentials;
use crate::{
    api_auth,
    config::{AutomaticArmGate, Mode, ReplyLanguage, Settings, Tone},
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

/// Point-in-time worker and engine state rendered by the UI and API surfaces.
///
/// Inputs: none (plain struct). Output: the operation lifecycle, settings,
/// account and connection state, counts, storage and model health, the paged
/// item list, audit events, and the one-time API-token exposure state.
#[derive(Clone, Default)]
pub struct Snapshot {
    /// Whether the worker has published its first snapshot.
    pub initialized: bool,
    /// Whether a fatal worker error has been recorded.
    pub fatal: bool,
    /// Human-readable progress description; empty when idle.
    pub busy: String,
    /// Operator-facing transient notice.
    pub notice: String,
    /// Operator-facing error text.
    pub error: String,
    /// Status of the current operation.
    pub operation: OperationStatus,
    /// Current enterprise policy status.
    pub enterprise_policy: crate::policy::PolicyStatus,
    /// Current workspace settings.
    pub settings: Settings,
    /// Revision of the current settings.
    pub settings_revision: u64,
    /// Workspace account key.
    pub account: String,
    /// Whether the Google account is connected.
    pub connected: bool,
    /// Whether the send scope is granted.
    pub send_scope: bool,
    /// Whether the worker runs in demo mode.
    pub demo: bool,
    /// Current item counts.
    pub counts: Counts,
    /// Storage health snapshot, when measured.
    pub storage: Option<crate::storage::StorageHealth>,
    /// Scheduled-backup status, when available.
    pub scheduled_backup: Option<crate::recovery::ScheduledBackupStatus>,
    /// Backup isolation status, when available.
    pub backup_isolation: Option<crate::recovery::BackupIsolationStatus>,
    /// Status of the primary local model.
    pub model: ModelStatus,
    /// Status of the verifier local model.
    pub verifier_model: ModelStatus,
    /// Timestamp of the last provider poll.
    pub last_poll: Option<DateTime<Utc>>,
    /// Timestamp of the next scheduled poll.
    pub next_poll: Option<DateTime<Utc>>,
    /// Items in the current review page.
    pub items: Vec<Job>,
    /// Currently selected item.
    pub selected: Option<Job>,
    /// Recent audit events.
    pub events: Vec<AuditEvent>,
    /// Current review page number.
    pub page: u32,
    /// Whether the worker is restricted to review-only operation.
    pub review_only: bool,
    /// Revealed API token, when requested.
    pub api_token: Option<Zeroizing<String>>,
    /// Revealed read-scope integration token, when requested.
    pub api_read_token: Option<Zeroizing<String>>,
    /// Instant the revealed token stops being shown.
    pub api_token_expires: Option<Instant>,
    /// Whether the local API listener is running.
    pub api_listening: bool,
}

/// Shared liveness probe for the background worker thread.
///
/// Inputs: none (plain struct). Output: cheap progress heartbeats that
/// readers turn into [`WorkerLiveness`] snapshots.
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
        Self::default()
    }

    /// Mark the start of one operation.
    ///
    /// Inputs: `kind` — operation kind being started. Output: none — the pulse
    /// records the start time and the current operation.
    fn begin(&self, kind: OperationKind) {
        if let Ok(mut state) = self.inner.lock() {
            let now = Utc::now();
            state.last_progress_at = now;
            state.current_operation = kind;
            state.operation_started_at = Some(now);
        }
    }

    /// Record forward progress on the current operation.
    ///
    /// Inputs: none (`&self`). Output: none — `last_progress_at` is refreshed.
    fn progress(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.last_progress_at = Utc::now();
        }
    }

    /// Mark the current operation finished.
    ///
    /// Inputs: none (`&self`). Output: none — the pulse returns to `Idle` with no
    /// operation start time.
    fn finish(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.last_progress_at = Utc::now();
            state.current_operation = OperationKind::Idle;
            state.operation_started_at = None;
        }
    }

    /// Record an idle heartbeat.
    ///
    /// Inputs: none (`&self`). Output: none — `last_progress_at` is refreshed only
    /// while no operation is running.
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
    /// Construct the default pulse in its idle state.
    ///
    /// Inputs: none. Output: `Self` — the canonical constructor for
    /// [`WorkerPulse::new`], tracking progress from the current time.
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(WorkerPulseState {
                last_progress_at: Utc::now(),
                current_operation: OperationKind::Idle,
                operation_started_at: None,
            })),
        }
    }
}
/// One command sent to the background worker over the bounded channel.
///
/// Inputs: none (plain enum). Output: the action the worker loop executes
/// against the engine, mirroring the interactive and web surfaces.
pub enum Command {
    /// Recompute and publish the worker snapshot.
    Refresh,
    /// Poll the provider immediately.
    CheckNow,
    /// Import a Google Desktop OAuth client file and connect the account.
    Connect { path: PathBuf, send: bool },
    /// Connect with an IMAP/SMTP app password instead of OAuth.
    ConnectAppPassword(AppPasswordCredentials),
    /// Disconnect the Google account.
    Disconnect,
    /// Apply updated settings.
    Settings(Box<Settings>),
    /// Install the local Ollama runtime.
    InstallOllama,
    /// Start the local Ollama runtime.
    StartOllama,
    /// Pull the primary local model.
    PullModel,
    /// Inspect the primary local model.
    InspectModel,
    /// Qualify the primary local model.
    QualifyModel,
    /// Pull the verifier model.
    PullVerifierModel,
    /// Inspect the verifier model.
    InspectVerifierModel,
    /// Qualify the verifier model.
    QualifyVerifierModel,
    /// Evaluate the active model.
    EvaluateModel,
    /// Profile the active model.
    ProfileModel,
    /// Compare model profiles.
    CompareModels,
    /// Recheck stored evidence integrity.
    IntegrityCheck,
    /// Compact the SQLite database.
    CompactDatabase,
    /// Write an encrypted same-vault backup to the requested path.
    Backup { out: PathBuf },
    /// Run the recovery drill against a backup without touching live state.
    RecoveryDrill { backup: PathBuf },
    /// Export a passphrase-wrapped recovery key for a backup.
    ExportRecoveryKey {
        out: PathBuf,
        passphrase: Zeroizing<String>,
    },
    /// Verify a backup against a passphrase-wrapped recovery key.
    VerifyRecoveryKey {
        backup: PathBuf,
        recovery_key: PathBuf,
        passphrase: Zeroizing<String>,
    },
    /// Write the workspace diagnostics report to the requested path.
    Diagnostics { out: PathBuf },
    /// List one page of items (review queue or full feed).
    List { review: bool, page: u32 },
    /// Make the addressed item the active selection.
    Select(String),
    /// Save an edited reply body for the pinned item revision.
    Edit {
        id: String,
        revision: u64,
        body: String,
    },
    /// Regenerate the draft for the pinned item revision.
    Regenerate { id: String, revision: u64 },
    /// Dismiss the pinned item revision.
    Dismiss { id: String, revision: u64 },
    /// Send the confirmed reply whose body hash matches the pinned revision.
    Send {
        id: String,
        revision: u64,
        body_hash: String,
    },
    /// Reconcile one provider message id against the delivery records.
    Reconcile(String),
    /// Purge items past the retention window.
    Purge,
    /// Reveal the local API token.
    RevealApiToken,
    /// Hide the local API token.
    HideApiToken,
    /// Rotate the local API token.
    RotateApiToken,
    /// Answer a read-only API query over the bounded reply channel.
    Api { path: String, reply: Sender<Value> },
    /// Answer the OpenMetrics exposition query over the bounded reply channel.
    OpenMetrics { reply: Sender<String> },
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
    /// Map one command onto its operation kind.
    ///
    /// Inputs: `self` — command being executed. Output: `OperationKind` — the kind
    /// recorded in the operation journal for this command.
    fn kind(&self) -> OperationKind {
        match self {
            Self::Refresh => OperationKind::Refresh,
            Self::CheckNow => OperationKind::SyncMailbox,
            Self::Connect { .. } | Self::ConnectAppPassword(_) => OperationKind::ConnectGmail,
            Self::Disconnect => OperationKind::DisconnectGmail,
            Self::Settings(_) => OperationKind::UpdateSettings,
            Self::List { .. } => OperationKind::ListItems,
            Self::Select(_) => OperationKind::SelectItem,
            Self::Edit { .. } => OperationKind::EditDraft,
            Self::Regenerate { .. } => OperationKind::RegenerateDraft,
            Self::Dismiss { .. } => OperationKind::DismissItem,
            Self::Send { .. } => OperationKind::SendReply,
            Self::Reconcile(_) => OperationKind::ReconcileDelivery,
            other => other.kind_model_ops(),
        }
    }
    /// Map one local-model or store-maintenance command onto its operation kind.
    ///
    /// Inputs: `self` — command being executed. Output: `OperationKind` — the
    /// kind recorded in the operation journal for this command.
    fn kind_model_ops(&self) -> OperationKind {
        match self {
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
            other => other.kind_workspace_ops(),
        }
    }
    /// Map one workspace, recovery or API command onto its operation kind.
    ///
    /// Inputs: `self` — command being executed. Output: `OperationKind` — the
    /// kind recorded in the operation journal for this command.
    #[allow(clippy::unreachable)]
    fn kind_workspace_ops(&self) -> OperationKind {
        match self {
            Self::Backup { .. } => OperationKind::Backup,
            Self::RecoveryDrill { .. } => OperationKind::RecoveryDrill,
            Self::ExportRecoveryKey { .. } => OperationKind::RecoveryKeyExport,
            Self::VerifyRecoveryKey { .. } => OperationKind::RecoveryKeyVerify,
            Self::Diagnostics { .. } => OperationKind::Diagnostics,
            Self::Purge => OperationKind::PurgeRetention,
            Self::RevealApiToken => OperationKind::RevealApiToken,
            Self::HideApiToken => OperationKind::HideApiToken,
            Self::RotateApiToken => OperationKind::RotateApiToken,
            Self::Api { .. } | Self::OpenMetrics { .. } => OperationKind::ApiRequest,
            Self::ApiWrite { request, .. } => request.operation_kind(),
            _ => unreachable!("every Command variant is mapped by kind"),
        }
    }
}

/// Rejected commands must never mask a running operation. In particular a
/// queue overflow may not make an in-flight Gmail send appear safe to interrupt.
///
/// Inputs: `snapshot` — shared snapshot to update; `kind` — the rejected
/// command's operation kind; `disconnected` — whether the worker channel is
/// gone. Output: none — the snapshot records a failed operation with the
/// matching stable code.
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

/// Handle to the spawned background worker thread and its shared state.
///
/// Inputs: none (plain struct). Output: the command channel, shared
/// snapshot, pause/stop flags, liveness pulse and thread join handle.
pub struct Worker {
    /// Command queue handle for the worker thread.
    pub tx: Sender<Command>,
    /// Shared latest worker snapshot.
    pub snapshot: Arc<Mutex<Snapshot>>,
    /// Shared pause flag.
    pub paused: Arc<AtomicBool>,
    /// Shared stop flag.
    pub stop: Arc<AtomicBool>,
    /// Shared pulse handle for liveness reporting.
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
        let pulse = WorkerPulse::default();
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
        self.snapshot
            .lock()
            .ok()
            .as_deref()
            .cloned()
            .unwrap_or_default()
    }

    /// Wait until the worker snapshot satisfies `ready`, aborting early on
    /// `abort`.
    ///
    /// Inputs: `ready` -- success predicate over the latest snapshot; `abort`
    /// -- fail-fast predicate checked first each cycle; `timeout` -- upper
    /// bound sized for heavily loaded hosts (a hung-worker guard only; the
    /// superseded ad-hoc 10-second loops flaked under sibling build
    /// saturation because the bound modeled latency instead of guarding it).
    /// Output: `bool` -- `true` when `ready` held, `false` when `abort` held
    /// or the deadline elapsed first.
    pub fn wait_for(
        &self,
        ready: impl Fn(&Snapshot) -> bool,
        abort: impl Fn(&Snapshot) -> bool,
        timeout: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let snapshot = self.view();
            if ready(&snapshot) {
                return true;
            }
            if abort(&snapshot) || Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
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
    /// Shut the worker down briefly when the handle drops.
    ///
    /// Inputs: none (`&mut self`). Output: none — a best-effort two-second shutdown
    /// is attempted.
    fn drop(&mut self) {
        let _ = self.shutdown(Duration::from_secs(2));
    }
}

/// Mark the shared snapshot fatally failed.
///
/// Inputs: `shared` — shared snapshot; `message` — operator-facing failure
/// description. Output: none — the snapshot records the error, sets `fatal`,
/// and clears busy state.
fn set_worker_fatal(shared: &Arc<Mutex<Snapshot>>, message: String) {
    if let Ok(mut view) = shared.lock() {
        view.error.clone_from(&message);
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

/// Rebuild the shared snapshot from current store state.
///
/// Inputs: `e` — engine; `shared` — shared snapshot to refresh; `selected` —
/// currently selected item id, if any; `review` — whether the review list is
/// active; `page` — page to render. Output: `Result<()>` — `Ok` once the
/// snapshot reflects the counts, listing, and selection.
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
    s.account.clone_from(&e.account);
    s.connected = e.connected();
    s.send_scope = e.send_scope();
    s.demo = e.demo;
    s.enterprise_policy = e.enterprise_policy_status();
    s.settings.clone_from(&e.settings);
    s.counts = counts;
    s.storage = crate::storage::inspect(&e.directory).ok();
    s.scheduled_backup =
        crate::recovery::scheduled_backup_status(&e.db, &e.settings, Utc::now()).ok();
    s.backup_isolation = crate::recovery::backup_isolation_status(&e.directory, &e.settings).ok();
    s.model.clone_from(&e.model);
    s.verifier_model.clone_from(&e.verifier_model);
    s.last_poll = last;
    s.next_poll = last.map(|t| t + chrono::Duration::seconds(e.settings.interval_seconds()));
    s.items = items;
    s.events = events;
    s.selected = selected;
    s.page = page;
    s.review_only = review;
    Ok(())
}
/// Start one operation in the pulse and the shared snapshot.
///
/// Inputs: `shared` — shared snapshot; `pulse` — worker pulse; `kind` —
/// operation kind; `text` — operator-facing operation description. Output:
/// none.
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

/// Persist the current operation status to the runtime journal.
///
/// Inputs: `journal` — runtime journal, when enabled; `shared` — shared
/// snapshot. Output: none — the record is best-effort and never fails the
/// operation.
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
/// Inputs: none. Output: `anyhow::Result<()>` — `Ok` when the installer
/// completes; failures surface to the operation report.
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

/// Report forward progress with an updated busy message.
///
/// Inputs: `shared` — shared snapshot; `pulse` — worker pulse; `text` —
/// operator-facing progress text. Output: none.
fn busy(shared: &Arc<Mutex<Snapshot>>, pulse: &WorkerPulse, text: &str) {
    pulse.progress();
    if let Ok(mut s) = shared.lock() {
        s.busy = text.into();
        if s.operation.state == OperationState::Running {
            s.operation.message = text.into();
        }
    }
}

/// Classify one operation failure into its stable code and retryability.
///
/// Inputs: `kind` — operation kind that failed; `error` — operation error.
/// Output: `(String, bool)` — the stable operation code and whether the
/// operator may retry.
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

/// Finish one operation and publish its outcome.
///
/// Inputs: `shared` — shared snapshot; `pulse` — worker pulse; `kind` —
/// operation kind; `result` — operation outcome. Output: none — the snapshot
/// records the operation state and, on failure, its classified code.
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
                s.error.clone_from(&message);
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
/// Finish one operation as a quiet success with a fixed message.
///
/// Inputs: `shared` — shared snapshot; `pulse` — worker pulse; `kind` —
/// operation kind; `message` — operator-facing status message. Output: none.
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

/// Rotate the API bearer token and publish the replacement once.
///
/// Inputs: `e` — engine whose store holds the verifier material; `shared` —
/// shared snapshot carrying the exposed token; `api_disabled` — flag that
/// disables the API while rotation runs. Output: `Result<()>` — `Ok` once the
/// rotated plaintext is exposed for the operator exactly once.
fn rotate_api_token(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    api_disabled: &Arc<AtomicBool>,
) -> Result<()> {
    let write = api_auth::rotate(&mut e.db, api_auth::TokenScope::Write)?;
    let read = api_auth::rotate(&mut e.db, api_auth::TokenScope::Read)?;
    let replacement = write
        .plaintext_once
        .context("Rotated API credential did not return one-time plaintext")?;
    let read_replacement = read
        .plaintext_once
        .context("Rotated API credential did not return one-time plaintext")?;
    api_disabled.store(true, Ordering::SeqCst);
    if let Ok(mut snapshot) = shared.lock() {
        snapshot.api_listening = false;
        snapshot.api_token = Some(replacement);
        snapshot.api_read_token = Some(read_replacement);
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
            write_edit_draft(e, id, revision, body, kind, context, &not_found)
        }
        WriteRequest::Regenerate { id, revision } => {
            write_regenerate(e, id, revision, kind, context, &not_found)
        }
        WriteRequest::Dismiss { id, revision } => {
            write_dismiss(e, id, revision, kind, context, &not_found)
        }
        WriteRequest::Send {
            id,
            revision,
            confirm_reply,
        } => write_send(e, id, revision, confirm_reply, kind, context, &not_found),
        WriteRequest::UpdateSettings {
            mode,
            tone,
            reply_language,
            sending_enabled,
        } => write_update_settings(
            e,
            mode,
            tone,
            reply_language,
            sending_enabled,
            kind,
            context,
        ),
        WriteRequest::AutomaticArm { action } => {
            write_automatic_arm(e, action, arm_gate, now, kind, context)
        }
        WriteRequest::CheckNow => {
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Checking the mailbox for missing messages…",
            );
            let result = e.synchronize();
            let inserted = result.as_ref().copied().unwrap_or(0);
            let mut outcome = report_write(e, context, kind, result.map(|_| ()));
            outcome.merge_payload(json!({ "new_identities": inserted }));
            outcome
        }
        WriteRequest::Qualify { verifier } => write_qualify(e, verifier, kind, context),
        WriteRequest::ConnectAppPassword { creds } => {
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Connecting the mailbox with the app password…",
            );
            let result = e.connect_app_password(creds.clone());
            report_write(e, context, kind, result)
        }
        WriteRequest::Disconnect => {
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Disconnecting the mailbox…",
            );
            let result = e.disconnect();
            report_write(e, context, kind, result)
        }
        WriteRequest::IntegrityCheck => {
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Checking encrypted database integrity…",
            );
            let result = e.db.integrity_check();
            report_write(e, context, kind, result)
        }
        WriteRequest::Compact => {
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Checkpointing, compacting and verifying encrypted SQLite state…",
            );
            let result = e.compact_database().map(|_| ());
            report_write(e, context, kind, result)
        }
        WriteRequest::Backup { out } => {
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Creating and verifying encrypted same-vault backup…",
            );
            let out_path: &std::path::Path = std::path::Path::new(out);
            let backup = crate::recovery::create_backup(&e.db, e.directory.as_path(), out_path);
            let result = match backup {
                Ok(_path) => Ok(()),
                Err(error) => Err(error),
            };
            report_write(e, context, kind, result)
        }
        WriteRequest::Purge => {
            begin_operation(
                context.shared,
                context.pulse,
                kind,
                "Purging records past the retention window…",
            );
            let result = e.db.purge(e.settings.retention_days).map(|_| ());
            report_write(e, context, kind, result)
        }
    }
}

/// Execute one validated draft edit write.
///
/// Inputs: `e` — engine owning the workspace; `id` — message id; `revision` —
/// revision the editor was loaded for; `body` — new reply text; `kind` —
/// operation kind; `context` — worker bookkeeping and list view; `not_found` —
/// typed 404 rejection factory. Output: [`WriteOutcome`] for the HTTP
/// response.
#[allow(clippy::ptr_arg)]
fn write_edit_draft(
    e: &mut Engine,
    id: &str,
    revision: &u64,
    body: &String,
    kind: OperationKind,
    context: &WriteContext<'_>,
    not_found: &dyn Fn() -> web::WriteError,
) -> WriteOutcome {
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

/// Execute one validated draft regeneration write.
///
/// Inputs: `e` — engine owning the workspace; `id` — message id; `revision` —
/// revision the editor was loaded for; `kind` — operation kind; `context` —
/// worker bookkeeping and list view; `not_found` — typed 404 rejection
/// factory. Output: [`WriteOutcome`] for the HTTP response.
fn write_regenerate(
    e: &mut Engine,
    id: &str,
    revision: &u64,
    kind: OperationKind,
    context: &WriteContext<'_>,
    not_found: &dyn Fn() -> web::WriteError,
) -> WriteOutcome {
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

/// Execute one validated dismissal write.
///
/// Inputs: `e` — engine owning the workspace; `id` — message id; `revision` —
/// revision the editor was loaded for; `kind` — operation kind; `context` —
/// worker bookkeeping and list view; `not_found` — typed 404 rejection
/// factory. Output: [`WriteOutcome`] for the HTTP response.
fn write_dismiss(
    e: &mut Engine,
    id: &str,
    revision: &u64,
    kind: OperationKind,
    context: &WriteContext<'_>,
    not_found: &dyn Fn() -> web::WriteError,
) -> WriteOutcome {
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

/// Execute one validated confirmed send write.
///
/// Inputs: `e` — engine owning the workspace; `id` — message id; `revision` —
/// revision the approval was given for; `confirm_reply` — exact reply text the
/// operator confirmed; `kind` — operation kind; `context` — worker
/// bookkeeping and list view; `not_found` — typed 404 rejection factory.
/// Output: [`WriteOutcome`] for the HTTP response.
#[allow(clippy::ptr_arg)]
fn write_send(
    e: &mut Engine,
    id: &String,
    revision: &u64,
    confirm_reply: &String,
    kind: OperationKind,
    context: &WriteContext<'_>,
    not_found: &dyn Fn() -> web::WriteError,
) -> WriteOutcome {
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

/// Execute one validated settings update write.
///
/// Inputs: `e` — engine owning the workspace; `mode`/`tone`/
/// `reply_language`/`sending_enabled` — merged settings candidates; `kind` —
/// operation kind; `context` — worker bookkeeping and list view. Output:
/// [`WriteOutcome`] for the HTTP response.
fn write_update_settings(
    e: &mut Engine,
    mode: &Option<Mode>,
    tone: &Option<Tone>,
    reply_language: &Option<ReplyLanguage>,
    sending_enabled: &Option<bool>,
    kind: OperationKind,
    context: &WriteContext<'_>,
) -> WriteOutcome {
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

/// Execute one Automatic-arm cooldown gate step.
///
/// Inputs: `e` — engine owning the workspace; `action` — arm step to perform;
/// `arm_gate` — server-side Automatic-arm cooldown state mutated in place;
/// `now` — request time; `kind` — operation kind; `context` — worker
/// bookkeeping and list view. Output: [`WriteOutcome`] for the HTTP response.
fn write_automatic_arm(
    e: &mut Engine,
    action: &web::AutomaticArmAction,
    arm_gate: &mut Option<AutomaticArmGate>,
    now: DateTime<Utc>,
    kind: OperationKind,
    context: &WriteContext<'_>,
) -> WriteOutcome {
    match action {
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
    }
}

/// Execute one validated model qualification write.
///
/// Inputs: `e` — engine owning the workspace; `verifier` — whether to qualify
/// the independent verifier too; `kind` — operation kind; `context` — worker
/// bookkeeping and list view. Output: [`WriteOutcome`] for the HTTP response.
fn write_qualify(
    e: &mut Engine,
    verifier: &bool,
    kind: OperationKind,
    context: &WriteContext<'_>,
) -> WriteOutcome {
    begin_operation(
        context.shared,
        context.pulse,
        kind,
        "Running a local model smoke test and checking GPU residency…",
    );
    let result = e.qualify().and_then(|()| {
        if *verifier {
            e.qualify_verifier()
        } else {
            Ok(())
        }
    });
    report_write(e, context, kind, result)
}

/// Map a result onto its operation state.
///
/// Inputs: `result` — operation outcome. Output: `OperationState` — `Succeeded`
/// for `Ok`, `Failed` otherwise.
fn operation_state_for_result<T, E>(result: &std::result::Result<T, E>) -> OperationState {
    if result.is_ok() {
        OperationState::Succeeded
    } else {
        OperationState::Failed
    }
}

/// Guard one operation's result with the engine's audit-protection policy.
///
/// Inputs: `engine` — engine supplying the pause flag and checkpoint
/// protection; `result` — operation outcome to guard. Output: `Result<T>` — the
/// outcome unchanged when protection allows it; otherwise the protection
/// failure fails closed.
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

/// Compute an exponential retry backoff with a hard cap.
///
/// Inputs: `base_seconds` — first-failure delay; `failures` — consecutive
/// failure count; `cap_seconds` — maximum delay. Output: `Duration` — the
/// capped exponential delay.
fn bounded_backoff(base_seconds: u64, failures: u32, cap_seconds: u64) -> Duration {
    let shift = failures.saturating_sub(1).min(6);
    Duration::from_secs(base_seconds.saturating_mul(1u64 << shift).min(cap_seconds))
}

/// Record one circuit-breaker transition in the runtime journal.
///
/// Inputs: `journal` — runtime journal, when enabled; `transition` — transition
/// to record; `opened` — signal logged when the circuit opens; `closed` —
/// signal logged when it closes. Output: none — the record is best-effort.
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

/// Run the background worker command loop.
///
/// Inputs: `e` — engine; `rx` — command channel; `shared` — shared snapshot;
/// `sender` — command channel handle for self-queued work; `journal` — runtime
/// journal, when enabled; `pulse` — worker pulse. Output: `Result<()>` — `Ok`
/// when the loop exits cleanly; error on a fatal worker failure.
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
    start_api_listener(&mut e, sender, &api_disabled, &pulse, &journal, &shared)?;
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
            Ok(Command::OpenMetrics { reply }) => handle_open_metrics(&e, &reply),
            Ok(command) => {
                let (selected_out, review_out, page_out, scheduled_backup_due_out) =
                    handle_worker_command(
                        command,
                        &mut e,
                        &shared,
                        &pulse,
                        &journal,
                        &api_disabled,
                        &mut gmail_gate,
                        selected,
                        review,
                        page,
                        scheduled_backup_due,
                    )?;
                selected = selected_out;
                review = review_out;
                page = page_out;
                scheduled_backup_due = scheduled_backup_due_out;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
        }
        expire_api_token(&shared);
        run_maintenance_operations(
            &mut e,
            &shared,
            &pulse,
            &journal,
            &api_disabled,
            &mut policy_failures,
            &mut policy_due,
            &mut retention_failures,
            &mut retention_due,
            &mut scheduled_backup_failures,
            &mut scheduled_backup_due,
            &selected,
            review,
            page,
        )?;
        if worker_scheduling_paused(&e) {
            continue;
        }
        run_ai_operations(
            &mut e,
            &shared,
            &pulse,
            &journal,
            &selected,
            review,
            page,
            &mut gmail_gate,
            &mut local_ai_gate,
            &mut automatic_failures,
            &mut auto_due,
        )?;
    }
    record_process_stopped(&journal);
    Ok(())
}

/// Start the integration API listener when settings enable it.
///
/// Inputs: `e` — engine; `sender` — command channel handle for API requests;
/// `api_disabled` — flag that disables the API under enterprise policy;
/// `pulse` — worker pulse; `journal` — runtime journal, when enabled;
/// `shared` — shared snapshot. Output: `Result<()>` — `Ok` once the listener
/// state is published; error when API credential material cannot be created.
fn start_api_listener(
    e: &mut Engine,
    sender: Sender<Command>,
    api_disabled: &Arc<AtomicBool>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    shared: &Arc<Mutex<Snapshot>>,
) -> Result<()> {
    if e.settings.api_enabled && !e.demo {
        let mut tokens = api_auth::load_or_create(&mut e.db)?;
        let write_once = tokens.plaintext_write_once.take();
        let read_once = tokens.plaintext_read_once.take();
        if let Ok(mut snapshot) = shared.lock() {
            if let Some(token) = write_once {
                snapshot.api_token = Some(token);
                snapshot.api_token_expires =
                    Some(Instant::now() + worker_interval(Duration::from_secs(60)));
            }
            if let Some(token) = read_once {
                snapshot.api_read_token = Some(token);
                snapshot.api_token_expires =
                    Some(Instant::now() + worker_interval(Duration::from_secs(60)));
            }
        }
        match crate::api::start_with_tokens(
            e.settings.api_port,
            tokens,
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
    Ok(())
}

/// Answer one OpenMetrics scrape from the worker loop.
///
/// Inputs: `e` — engine; `reply` — reply channel for the rendered exposition.
/// Output: none — the reply is sent only when collection succeeds.
#[allow(clippy::needless_borrow)]
fn handle_open_metrics(e: &Engine, reply: &Sender<String>) {
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

/// The reported outcome and list view after one worker command dispatch.
///
/// Inputs: none (plain struct). Output: `result` — the operation outcome
/// reported to the snapshot; `settings_changed` — whether settings must bump
/// their revision; `selected`/`review`/`page` — the possibly updated list view.
struct CommandOutcome {
    result: Result<()>,
    settings_changed: bool,
    selected: Option<String>,
    review: bool,
    page: u32,
}

/// Execute one queued worker command and publish its outcome.
///
/// Inputs: `command` — command to execute; `e` — engine; `shared` — shared
/// snapshot; `pulse` — worker pulse; `journal` — runtime journal, when
/// enabled; `api_disabled` — API disable flag; `gmail_gate` — Gmail retry
/// gate; `selected`/`review`/`page` — current list view; `scheduled_backup_due`
/// — next scheduled-backup due time. Output: `Result<(Option<String>, bool,
/// u32, Instant)>` — the possibly updated list view and scheduled-backup due
/// time.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_borrow)]
fn handle_worker_command(
    command: Command,
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    api_disabled: &Arc<AtomicBool>,
    gmail_gate: &mut RetryGate,
    selected: Option<String>,
    review: bool,
    page: u32,
    mut scheduled_backup_due: Instant,
) -> Result<(Option<String>, bool, u32, Instant)> {
    let operation = command.kind();
    begin_operation(&shared, &pulse, operation, "Working locally…");
    record_current_operation(&journal, &shared);
    let CommandOutcome {
        result: operation_result,
        settings_changed,
        selected,
        review,
        page,
    } = execute_command(
        command,
        e,
        shared,
        pulse,
        journal,
        api_disabled,
        gmail_gate,
        selected,
        review,
        page,
    )?;
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
    Ok((selected, review, page, scheduled_backup_due))
}

/// Execute the view, account and qualification worker commands.
///
/// Inputs: `command` — command to execute; `e` — engine; `shared` — shared
/// snapshot; `pulse` — worker pulse; `journal` — runtime journal, when
/// enabled; `api_disabled` — API disable flag; `gmail_gate` — Gmail retry
/// gate; `selected`/`review`/`page` — current list view. Output:
/// `Result<CommandOutcome>` — the operation outcome and possibly updated list
/// view.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_borrow)]
fn execute_command(
    command: Command,
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    api_disabled: &Arc<AtomicBool>,
    gmail_gate: &mut RetryGate,
    mut selected: Option<String>,
    mut review: bool,
    mut page: u32,
) -> Result<CommandOutcome> {
    let mut settings_changed = false;
    let result = match command {
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
        Command::ConnectAppPassword(creds) => {
            busy(
                &shared,
                &pulse,
                "Connecting over IMAP/SMTP with your app password…",
            );
            let r = e.connect_app_password(creds);
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
        Command::List { review: r, page: p } => {
            review = r;
            page = p;
            Ok(())
        }
        Command::Select(id) => {
            selected = Some(id);
            Ok(())
        }
        other => execute_item_ops(other, e, shared, pulse, api_disabled)?,
    };
    Ok(CommandOutcome {
        result,
        settings_changed,
        selected,
        review,
        page,
    })
}

/// Execute the item-lifecycle and API-token worker commands.
///
/// Inputs: `command` — command to execute; `e` — engine; `shared` — shared
/// snapshot; `pulse` — worker pulse; `api_disabled` — API disable flag.
/// Output: `Result<Result<()>>` — the outer `Result` carries the fatal
/// dispatch escapes that bypass the operation report exactly like the
/// original `?` sites; the inner `Result<()>` is the operation outcome
/// reported to the snapshot.
#[allow(clippy::needless_borrow)]
fn execute_item_ops(
    command: Command,
    mut e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    api_disabled: &Arc<AtomicBool>,
) -> Result<Result<()>> {
    Ok(match command {
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
                s.api_read_token = None;
                s.api_token_expires = None;
            }
            Ok(())
        }
        Command::RotateApiToken => rotate_api_token(&mut e, &shared, &api_disabled),
        other => execute_model_ops(other, e, shared, pulse)?,
    })
}

/// Execute the local-model and workspace-maintenance worker commands.
///
/// Inputs: `command` — command to execute; `e` — engine; `shared` — shared
/// snapshot; `pulse` — worker pulse. Output: `Result<Result<()>>` — the outer
/// `Result` carries the fatal dispatch escapes that bypass the operation
/// report exactly like the original `?` sites; the inner `Result<()>` is the
/// operation outcome reported to the snapshot.
#[allow(clippy::needless_borrow)]
fn execute_model_ops(
    command: Command,
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
) -> Result<Result<()>> {
    Ok(match command {
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
            Ollama::new(&e.settings).and_then(|o| o.pull(&e.stop, |p| busy(&shared, &pulse, &p)))
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
        Command::Diagnostics { out } => {
            busy(&shared, &pulse, "Writing privacy-safe diagnostics locally…");
            crate::diagnostics::write_report(&e, &out)
        }
        other => execute_vault_ops(other, e, shared, pulse)?,
    })
}

/// Execute the retention, backup and recovery worker commands.
///
/// Inputs: `command` — command to execute; `e` — engine; `shared` — shared
/// snapshot; `pulse` — worker pulse. Output: `Result<Result<()>>` — the outer
/// `Result` carries the fatal dispatch escapes that bypass the operation
/// report exactly like the original `?` sites; the inner `Result<()>` is the
/// operation outcome reported to the snapshot.
#[allow(clippy::needless_borrow, clippy::unreachable)]
fn execute_vault_ops(
    command: Command,
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
) -> Result<Result<()>> {
    Ok(match command {
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
            match crate::recovery::create_backup(&e.db, &e.directory, &out) {
                Ok(_path) => Ok(()),
                Err(error) => Err(error),
            }
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
            let result =
                crate::recovery::export_recovery_key(&e.directory, passphrase.as_bytes(), &out)
                    .map(|_| ());
            if result.is_ok() {
                let logged = e.db.log(
                    "recovery.key_exported",
                    None,
                    "Passphrase-wrapped recovery key exported",
                );
                logged?;
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
                let logged = e.db.log(
                    "recovery.key_verified",
                    None,
                    "Recovery key authenticated against an encrypted backup",
                );
                logged?;
            }
            result
        }
        Command::Api { .. } | Command::OpenMetrics { .. } | Command::ApiWrite { .. } => Err(
            anyhow::anyhow!("Internal API command reached the wrong dispatcher"),
        ),
        _ => unreachable!("every Command variant is dispatched in execute_command"),
    })
}

/// Expire the one-time API token in the shared snapshot when due.
///
/// Inputs: `shared` — shared snapshot. Output: none — the exposed token is
/// cleared once its one-time window closes.
fn expire_api_token(shared: &Arc<Mutex<Snapshot>>) {
    if let Ok(mut snapshot) = shared.lock()
        && snapshot
            .api_token_expires
            .is_some_and(|until| Instant::now() >= until)
    {
        snapshot.api_token = None;
        snapshot.api_token_expires = None;
    }
}

/// Whether scheduled model work must wait this loop iteration.
///
/// Inputs: `e` — engine. Output: `bool` — `true` while the worker is paused,
/// demonstrating, or disconnected.
fn worker_scheduling_paused(e: &Engine) -> bool {
    e.paused.load(Ordering::SeqCst) || e.demo || !e.connected()
}

/// Record the worker process-stopped event in the runtime journal.
///
/// Inputs: `journal` — runtime journal, when enabled. Output: none — the
/// record is best-effort.
fn record_process_stopped(journal: &Option<RuntimeJournal>) {
    if let Some(journal) = &journal {
        let _ = journal.record_event(RuntimeEvent::ProcessStopped);
    }
}

/// Run one due enterprise-policy reload with its failure backoff.
///
/// Inputs: `e` — engine; `shared` — shared snapshot; `pulse` — worker pulse;
/// `journal` — runtime journal, when enabled; `api_disabled` — API disable
/// flag; `selected`/`review`/`page` — current list view; `policy_failures` —
/// consecutive policy-reload failures; `policy_due` — next policy-reload due
/// time. Output: `Result<(u32, Instant)>` — the updated failure count and due
/// time.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_borrow)]
fn run_policy_reload(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    api_disabled: &Arc<AtomicBool>,
    selected: &Option<String>,
    review: bool,
    page: u32,
    mut policy_failures: u32,
    mut policy_due: Instant,
) -> Result<(u32, Instant)> {
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
                        snapshot.settings_revision = snapshot.settings_revision.saturating_add(1);
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
                policy_due =
                    Instant::now() + worker_interval(bounded_backoff(15, policy_failures, 5 * 60));
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
    Ok((policy_failures, policy_due))
}

/// Run one due retention purge with its failure backoff.
///
/// Inputs: `e` — engine; `shared` — shared snapshot; `pulse` — worker pulse;
/// `journal` — runtime journal, when enabled; `selected`/`review`/`page` —
/// current list view; `retention_failures` — consecutive retention failures;
/// `retention_due` — next retention due time. Output: `Result<(u32, Instant)>`
/// — the updated failure count and due time.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_borrow)]
fn run_retention(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    selected: &Option<String>,
    review: bool,
    page: u32,
    mut retention_failures: u32,
    mut retention_due: Instant,
) -> Result<(u32, Instant)> {
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
            retention_due = Instant::now() + bounded_backoff(15 * 60, retention_failures, 60 * 60);
        }
        refresh(&e, &shared, selected.as_deref(), review, page)?;
    }
    Ok((retention_failures, retention_due))
}

/// Run one due scheduled verified backup with its failure backoff.
///
/// Inputs: `e` — engine; `shared` — shared snapshot; `pulse` — worker pulse;
/// `journal` — runtime journal, when enabled; `selected`/`review`/`page` —
/// current list view; `scheduled_backup_failures` — consecutive backup
/// failures; `scheduled_backup_due` — next backup due time. Output:
/// `Result<(u32, Instant)>` — the updated failure count and due time.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_borrow)]
fn run_scheduled_backup(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    selected: &Option<String>,
    review: bool,
    page: u32,
    mut scheduled_backup_failures: u32,
    mut scheduled_backup_due: Instant,
) -> Result<(u32, Instant)> {
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
            scheduled_backup_due = Instant::now() + worker_interval(Duration::from_secs(60 * 60));
        }
    } else if !e.settings.scheduled_backup_enabled {
        scheduled_backup_due = Instant::now() + worker_interval(Duration::from_secs(60));
    }
    Ok((scheduled_backup_failures, scheduled_backup_due))
}

/// Run one due scheduled Gmail poll under the retry gate.
///
/// Inputs: `e` — engine; `shared` — shared snapshot; `pulse` — worker pulse;
/// `journal` — runtime journal, when enabled; `selected`/`review`/`page` —
/// current list view; `gmail_gate` — Gmail retry gate. Output: `Result<()>` —
/// `Ok` after the poll ran or its gate held it back.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_borrow)]
fn run_gmail_poll(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    selected: &Option<String>,
    review: bool,
    page: u32,
    gmail_gate: &mut RetryGate,
) -> Result<()> {
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
    Ok(())
}

/// Run one due local-AI analysis tick under the retry gate.
///
/// Inputs: `e` — engine; `shared` — shared snapshot; `pulse` — worker pulse;
/// `journal` — runtime journal, when enabled; `selected`/`review`/`page` —
/// current list view; `local_ai_gate` — local-AI retry gate. Output:
/// `Result<()>` — `Ok` after the tick ran or its gate held it back.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_borrow)]
fn run_local_ai(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    selected: &Option<String>,
    review: bool,
    page: u32,
    local_ai_gate: &mut RetryGate,
) -> Result<()> {
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
    Ok(())
}

/// Run one due automatic-dispatch tick with its failure backoff.
///
/// Inputs: `e` — engine; `shared` — shared snapshot; `pulse` — worker pulse;
/// `journal` — runtime journal, when enabled; `selected`/`review`/`page` —
/// current list view; `automatic_failures` — consecutive dispatch failures;
/// `auto_due` — next dispatch due time. Output: `Result<(u32, Instant)>` — the
/// updated failure count and due time.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_borrow)]
fn run_automatic_dispatch(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    selected: &Option<String>,
    review: bool,
    page: u32,
    mut automatic_failures: u32,
    mut auto_due: Instant,
) -> Result<(u32, Instant)> {
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
    Ok((automatic_failures, auto_due))
}

/// Run each due scheduled maintenance operation exactly once.
///
/// Inputs: `e` — engine; `shared` — shared snapshot; `pulse` — worker pulse;
/// `journal` — runtime journal, when enabled; `api_disabled` — API disable
/// flag; `policy_failures`/`policy_due` — policy-reload schedule;
/// `retention_failures`/`retention_due` — retention schedule;
/// `scheduled_backup_failures`/`scheduled_backup_due` — backup schedule;
/// `selected`/`review`/`page` — current list view. Output: `Result<()>` —
/// `Ok` once every due maintenance operation ran; error on a fatal worker
/// failure.
#[allow(clippy::too_many_arguments)]
fn run_maintenance_operations(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    api_disabled: &Arc<AtomicBool>,
    policy_failures: &mut u32,
    policy_due: &mut Instant,
    retention_failures: &mut u32,
    retention_due: &mut Instant,
    scheduled_backup_failures: &mut u32,
    scheduled_backup_due: &mut Instant,
    selected: &Option<String>,
    review: bool,
    page: u32,
) -> Result<()> {
    let (policy_failures_next, policy_due_next) = run_policy_reload(
        e,
        shared,
        pulse,
        journal,
        api_disabled,
        selected,
        review,
        page,
        *policy_failures,
        *policy_due,
    )?;
    *policy_failures = policy_failures_next;
    *policy_due = policy_due_next;
    let (retention_failures_next, retention_due_next) = run_retention(
        e,
        shared,
        pulse,
        journal,
        selected,
        review,
        page,
        *retention_failures,
        *retention_due,
    )?;
    *retention_failures = retention_failures_next;
    *retention_due = retention_due_next;
    let (scheduled_backup_failures_next, scheduled_backup_due_next) = run_scheduled_backup(
        e,
        shared,
        pulse,
        journal,
        selected,
        review,
        page,
        *scheduled_backup_failures,
        *scheduled_backup_due,
    )?;
    *scheduled_backup_failures = scheduled_backup_failures_next;
    *scheduled_backup_due = scheduled_backup_due_next;
    Ok(())
}

/// Run each due scheduled model operation exactly once.
///
/// Inputs: `e` — engine; `shared` — shared snapshot; `pulse` — worker pulse;
/// `journal` — runtime journal, when enabled; `selected`/`review`/`page` —
/// current list view; `gmail_gate` — Gmail retry gate; `local_ai_gate` —
/// local-AI retry gate; `automatic_failures`/`auto_due` — automatic-dispatch
/// schedule. Output: `Result<()>` — `Ok` once every due model operation ran;
/// error on a fatal worker failure.
#[allow(clippy::too_many_arguments)]
fn run_ai_operations(
    e: &mut Engine,
    shared: &Arc<Mutex<Snapshot>>,
    pulse: &WorkerPulse,
    journal: &Option<RuntimeJournal>,
    selected: &Option<String>,
    review: bool,
    page: u32,
    gmail_gate: &mut RetryGate,
    local_ai_gate: &mut RetryGate,
    automatic_failures: &mut u32,
    auto_due: &mut Instant,
) -> Result<()> {
    run_gmail_poll(
        e, shared, pulse, journal, selected, review, page, gmail_gate,
    )?;
    run_local_ai(
        e,
        shared,
        pulse,
        journal,
        selected,
        review,
        page,
        local_ai_gate,
    )?;
    let (automatic_failures_next, auto_due_next) = run_automatic_dispatch(
        e,
        shared,
        pulse,
        journal,
        selected,
        review,
        page,
        *automatic_failures,
        *auto_due,
    )?;
    *automatic_failures = automatic_failures_next;
    *auto_due = auto_due_next;
    Ok(())
}
/// Parse a URL query string, refusing duplicate parameters.
///
/// Inputs: `url` — URL whose query to parse. Output: `Result<BTreeMap<String,
/// String>>` — the unique query pairs; error on a repeated key.
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

/// Encode one item cursor as an opaque URL-safe token.
///
/// Inputs: `cursor` — cursor to encode. Output: `Result<String>` — the
/// base64url (no padding) encoding of the serialized cursor.
fn encode_item_cursor(cursor: &ItemCursor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor)?))
}

/// Decode and validate one opaque item cursor token.
///
/// Inputs: `value` — token supplied by the client. Output: `Result<ItemCursor>`
/// — the decoded cursor; error for empty, oversized, or non-token input.
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

/// Validate one API item identifier.
///
/// Inputs: `id` — candidate identifier. Output: `Result<()>` — `Ok` only for
/// exactly 64 ASCII hex characters.
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

/// Answer one read-only API query, optionally reporting a running operation.
///
/// Inputs: `e` — engine; `path` — request path with its query string;
/// `operation` — current operation status to include, if any. Output:
/// `Result<Value>` — the JSON response body for the routed read path.
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
        "/v1/capabilities" => api_capabilities(&query),
        "/v1/health" => api_health(e, &query, operation),
        "/v1/audit/anchor" => api_audit_anchor(e, &query),
        "/v1/audit/contains" => api_audit_contains(e, &query),
        "/v1/metrics" => api_metrics(e, &query),
        "/v1/settings" => api_settings(e, &query),
        "/v1/status" => api_status(e, &query, operation),
        "/v1/item-feed" => api_item_feed(e, &query),
        "/v1/items" => api_items(e, &query),
        "/v1/events" => api_events(e, &query),
        path => api_item_routes(e, path, &query),
    }
}

/// Answer the read-only capabilities route.
///
/// Inputs: `query` — validated request query parameters. Output: `Result<Value>` — the JSON capabilities document.
fn api_capabilities(query: &std::collections::BTreeMap<String, String>) -> Result<Value> {
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

/// Answer the workspace health route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters; `operation` — current operation status to include, if any. Output: `Result<Value>` — the JSON health document.
fn api_health(
    e: &Engine,
    query: &std::collections::BTreeMap<String, String>,
    operation: Option<&OperationStatus>,
) -> Result<Value> {
    ensure!(
        query.is_empty(),
        "Health endpoint takes no query parameters"
    );
    let integrity_ok = e.db.integrity_check().is_ok();
    let storage = crate::storage::inspect(&e.directory)?;
    let scheduled_backup =
        crate::recovery::scheduled_backup_status(&e.db, &e.settings, Utc::now())?;
    let backup_isolation = crate::recovery::backup_isolation_status(&e.directory, &e.settings)?;
    let paused = e.paused.load(Ordering::SeqCst);
    let stopping = e.stop.load(Ordering::SeqCst);
    let emergency_stop = crate::emergency::status_fail_closed();
    let readiness = crate::readiness::assess_context(crate::readiness::RuntimeReadinessContext {
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

/// Answer the audit-anchor route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters. Output: `Result<Value>` — the JSON audit-anchor document.
fn api_audit_anchor(
    e: &Engine,
    query: &std::collections::BTreeMap<String, String>,
) -> Result<Value> {
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

/// Answer the audit-anchor membership route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters. Output: `Result<Value>` — the JSON anchor-membership answer.
fn api_audit_contains(
    e: &Engine,
    query: &std::collections::BTreeMap<String, String>,
) -> Result<Value> {
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

/// Answer the JSON metrics route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters.
/// Output: `Result<Value>` — the JSON metrics snapshot.
fn api_metrics(e: &Engine, query: &std::collections::BTreeMap<String, String>) -> Result<Value> {
    ensure!(
        query.is_empty(),
        "Metrics endpoint takes no query parameters"
    );
    let collected = crate::metrics::collect(e, Utc::now());
    let collected = collected?;
    Ok(serde_json::to_value(collected)?)
}

/// Answer the settings view route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters.
/// Output: `Result<Value>` — the JSON settings view.
fn api_settings(e: &Engine, query: &std::collections::BTreeMap<String, String>) -> Result<Value> {
    ensure!(
        query.is_empty(),
        "Settings endpoint takes no query parameters"
    );
    Ok(crate::web::settings_view(&e.settings))
}

/// Answer the compact status route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters; `operation` — current operation status to include, if any. Output: `Result<Value>` — the JSON status document.
fn api_status(
    e: &Engine,
    query: &std::collections::BTreeMap<String, String>,
    operation: Option<&OperationStatus>,
) -> Result<Value> {
    ensure!(
        query.is_empty(),
        "Status endpoint takes no query parameters"
    );
    Ok(
        json!({"version":env!("CARGO_PKG_VERSION"),"settings_format_version":e.settings.settings_format_version,"account":e.account,"connected":e.connected(),"paused":e.paused.load(Ordering::SeqCst),"mode":e.settings.mode,"sending_enabled":e.settings.sending_enabled,"counts":e.db.counts(&e.account)?,"last_poll":e.last_poll()?,"operation":operation,"enterprise_policy":e.enterprise_policy_status()}),
    )
}

/// Answer the cursor item-feed route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters. Output: `Result<Value>` — the JSON cursor item feed.
fn api_item_feed(e: &Engine, query: &std::collections::BTreeMap<String, String>) -> Result<Value> {
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

/// Answer the paged items route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters. Output: `Result<Value>` — the JSON paged item listing.
fn api_items(e: &Engine, query: &std::collections::BTreeMap<String, String>) -> Result<Value> {
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

/// Answer the events route.
///
/// Inputs: `e` — engine; `query` — validated request query parameters. Output: `Result<Value>` — the JSON event listing.
fn api_events(e: &Engine, query: &std::collections::BTreeMap<String, String>) -> Result<Value> {
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

/// Route the per-item API paths onto their handlers.
///
/// Inputs: `e` — engine; `path` — request path; `query` — validated request
/// query parameters. Output: `Result<Value>` — the JSON response body for the
/// routed item path; error for an unknown route.
fn api_item_routes(
    e: &Engine,
    path: &str,
    query: &std::collections::BTreeMap<String, String>,
) -> Result<Value> {
    match path {
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
            let decision = automatic_policy(&job, &e.settings, &e.account, Utc::now());
            Ok(serde_json::to_value(decision)?)
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
    fn wait_for_resolves_predicates_and_expires_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::spawn(dir.path().into(), true);
        // The demo worker initializes promptly: the ready predicate resolves.
        assert!(worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60)));
        // An unreachable ready predicate must expire at the bound (bounded
        // wait, not a hang), and the bound is honored from below.
        let start = Instant::now();
        assert!(!worker.wait_for(|_| false, |_| false, Duration::from_millis(200)));
        assert!(start.elapsed() >= Duration::from_millis(200));
        // The abort predicate short-circuits the wait without waiting for
        // ready or the deadline.
        let start = Instant::now();
        assert!(!worker.wait_for(|_| false, |s| s.initialized, Duration::from_secs(60)));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

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
            "/v1/commands/check-now",
            "/v1/commands/qualify",
            "/v1/commands/connect-app-password",
            "/v1/commands/disconnect",
            "/v1/commands/integrity-check",
            "/v1/commands/compact",
            "/v1/commands/backup",
            "/v1/commands/purge",
        ] {
            assert!(paths.contains_key(expected), "OpenAPI missing {expected}");
        }
        assert_eq!(paths.len(), 30);
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
        assert!(!value["sending_enabled"].as_bool().unwrap());
        assert!(!value["automatic_confirmed"].as_bool().unwrap());
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
        assert!(health["healthy"].as_bool().unwrap());
        assert!(health["runtime_log"].is_object());
        assert!(health["database"]["integrity_ok"].as_bool().unwrap());
        assert!(!health["enterprise_policy"]["active"].as_bool().unwrap());
        assert!(!health["emergency_stop"]["active"].as_bool().unwrap());
        assert!(!health["emergency_stop"]["configured"].as_bool().unwrap());
        assert!(
            !health["audit_protection"]["independent_anchor_configured"]
                .as_bool()
                .unwrap()
        );
        assert!(health.get("account").is_none());

        let value = api_query(&engine, "/v1/capabilities").unwrap();
        assert_eq!(value["api_version"], crate::api::API_VERSION);
        assert!(value["read_only"].as_bool().unwrap());
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
        assert!(
            health["worker"]["operation"]["retryable"]
                .as_bool()
                .unwrap()
        );
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
        assert!(!value["eligible"].as_bool().unwrap());
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
        assert!(contains["known"].as_bool().unwrap());
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
        let stored_read: String = engine.db.meta(api_auth::TOKEN_HASH_META).unwrap().unwrap();
        assert_eq!(stored_read.len(), 64);
        let stored_write: String = engine
            .db
            .meta(api_auth::TOKEN_WRITE_HASH_META)
            .unwrap()
            .unwrap();
        assert_eq!(stored_write.len(), 64);

        let snapshot = shared.lock().unwrap();
        assert!(!snapshot.api_listening);
        let displayed = snapshot
            .api_token
            .as_ref()
            .map(|token| token.as_str().to_owned())
            .unwrap();
        let displayed_read = snapshot
            .api_read_token
            .as_ref()
            .map(|token| token.as_str().to_owned())
            .unwrap();
        drop(snapshot);

        assert_ne!(displayed, old);
        assert!(displayed.len() >= 40);
        assert!(displayed_read.len() >= 40);
        let write_verifier =
            api_auth::ApiTokenVerifier::from_hex(api_auth::TokenScope::Write, &stored_write)
                .unwrap();
        assert!(write_verifier.verify_token(&displayed));
        assert!(!write_verifier.verify_token(&old));
        let read_verifier =
            api_auth::ApiTokenVerifier::from_hex(api_auth::TokenScope::Read, &stored_read).unwrap();
        assert!(read_verifier.verify_token(&displayed_read));
        // The scopes never cross: the write plaintext is not the read one.
        assert!(!read_verifier.verify_token(&displayed));

        let events = engine.db.events(0, 100).unwrap();
        let event = events
            .iter()
            .find(|event| event.kind == "security.api_token_rotated")
            .unwrap();
        assert_eq!(event.domain, AuditDomain::Security);
        assert_eq!(event.severity, AuditSeverity::Security);
        assert!(!event.detail.contains(&old));
        assert!(!event.detail.contains(&displayed));
        assert!(!event.detail.contains(&displayed_read));
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
        let pulse = WorkerPulse::default();
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
            // Slow CI runners (2-vCPU Windows hosts under full-suite load)
            // can need well over 10s to start; the budget only catches hangs.
            assert!(
                start.elapsed() < Duration::from_secs(60),
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
                start.elapsed() < Duration::from_secs(60),
                "Worker did not publish selection"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(worker.shutdown(Duration::from_secs(2)));
    }
}

#[cfg(test)]
mod orchestration_tests {
    // Uncovered-by-design lines in these tests carry no product signal and
    // are deliberately left alone: `assert!` message arguments only
    // evaluate when an assertion fails, the `journaled_*`/`wait_for` test
    // helpers' fallback branches only run on fixture anomalies or test
    // failure, the timer-wait poll internals only run when the first check
    // misses, and the `Api`/`OpenMetrics`/`ApiWrite` arm and the
    // channel-disconnect arm of the command dispatcher are defense-in-depth
    // kept for future refactors (those commands are pre-routed above the
    // match, and the loop holds its own channel sender for timer work).
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
        let pulse = WorkerPulse::default();
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
        let pulse = WorkerPulse::default();
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
        let pulse = WorkerPulse::default();
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
    #[test]
    fn automatic_arm_confirm_only_arms_a_qualified_configuration() {
        // Serialize OS credential-store access (see `vault::test_support`).
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let dir = tempfile::tempdir().unwrap();
        // A real (non-demo) workspace: demo mode can never enable sending.
        // Arm the headless vault seam first so the live open derives its key
        // on hosts without an OS credential store.
        crate::test_support::headless_vault_seam();
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
        let pulse = WorkerPulse::default();
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
        assert!(
            worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60),),
            "worker did not initialize: {}",
            worker.view().error
        );

        let runtime = crate::test_support::MockServer::new(|route, _| match route {
            "/api/version" => Some(serde_json::json!({"version": "0.35.1"})),
            "/api/pull" => Some(serde_json::json!({"status": "success"})),
            _ => None,
        });

        let mut settings = worker.view().settings;
        settings.ollama_url.clone_from(&runtime.url);
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
            assert!(
                worker.wait_for(
                    |s| {
                        s.operation.operation_id != before
                            && s.operation.state != OperationState::Running
                    },
                    |s| s.fatal,
                    Duration::from_secs(60),
                ),
                "install operation never settled"
            );
            let snapshot = worker.view();
            assert!(!snapshot.fatal, "{}", snapshot.error);
            assert!(
                snapshot.operation.state == OperationState::Failed,
                "unexpected install outcome: {:?}",
                snapshot.operation
            );
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
            pulse: WorkerPulse::default(),
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
        assert!(
            worker.wait_for(|s| s.fatal, |_| false, Duration::from_secs(60)),
            "worker did not report the fatal startup failure"
        );
        assert!(!worker.view().error.is_empty());
        assert!(worker.shutdown(Duration::from_secs(2)));
    }

    /// Event codes published to the runtime journal so far.
    ///
    /// Why: the runtime journal is the durable record of worker lifecycle
    /// events, so reading it observes crash outcomes deterministically while
    /// sampling live state can race the crash teardown.
    /// Inputs: `dir` — workspace directory. Output: every `event` code recorded
    /// in `logs/runtime.jsonl` and its archives.
    fn journaled_events(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
        let mut events = std::collections::BTreeSet::new();
        let Ok(entries) = std::fs::read_dir(dir.join("logs")) else {
            return events;
        };
        for entry in entries.flatten() {
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            for line in text.lines() {
                let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if let Some(event) = record["event"].as_str() {
                    events.insert(event.to_owned());
                }
            }
        }
        events
    }

    /// Why: the worker boundary is fail-closed. A panic anywhere on the worker
    /// thread must latch delivery closed (paused and stop set), publish the
    /// typed fatal state instead of dying silently, and leave a durable
    /// `worker_panicked` record. A regression here turns a worker crash into a
    /// process that looks alive while delivery silently continues or wedges.
    #[test]
    fn a_panicking_worker_latches_the_fail_closed_state_and_journals_the_crash() {
        let _credential_store = crate::vault::test_support::lock_credential_store();
        crate::test_support::headless_vault_seam();
        let dir = tempfile::tempdir().unwrap();
        // The worker adopts armed seams before doing any fail-closed work, so a
        // policy loader that panics exercises the catch_unwind crash arm on the
        // worker thread itself.
        let panicking: crate::test_support::PolicyLoader = std::sync::Arc::new(|| {
            panic!("synthetic policy-loader crash");
        });
        crate::test_support::arm_worker_seams(
            Some(panicking),
            None,
            None,
            None,
            None,
            None,
            || {
                let mut worker = Worker::spawn(dir.path().into(), false);
                assert!(
                    worker.wait_for(|s| s.fatal, |_| false, Duration::from_secs(60)),
                    "worker did not publish the crash state"
                );
                let snapshot = worker.view();
                assert!(
                    snapshot
                        .error
                        .contains("Background worker crashed unexpectedly"),
                    "unexpected fatal state: {}",
                    snapshot.error
                );
                assert!(
                    worker.paused.load(Ordering::SeqCst),
                    "delivery must be latched paused after a worker panic"
                );
                assert!(
                    worker.stop.load(Ordering::SeqCst),
                    "the stop latch must be set after a worker panic"
                );
                assert!(worker.shutdown(Duration::from_secs(2)));
                let events = journaled_events(dir.path());
                assert!(
                    events.contains("worker_panicked"),
                    "the crash must be recorded in the runtime journal: {events:?}"
                );
                assert!(
                    events.contains("process_started"),
                    "the journal must also keep the normal startup record: {events:?}"
                );
            },
        );
    }

    /// Recovery commands must round-trip on a real (non-demo) workspace:
    /// backup, isolated drill, key export and key verification all succeed
    /// without stalling the worker.
    #[test]
    fn recovery_commands_round_trip_on_a_real_workspace() {
        // Share the cross-test credential-store lock: parallel in-process
        // tests use the same OS credential store, and this workspace round
        // trip must not observe another test's transient vault identifiers.
        let _credential_store = crate::vault::test_support::lock_credential_store();
        // Arm the headless vault seam before the spawn so the worker thread's
        // workspace open derives the same key on hosts without an OS
        // credential store.
        crate::test_support::headless_vault_seam();
        let dir = tempfile::tempdir().unwrap();
        let mut worker = Worker::spawn(dir.path().into(), false);
        assert!(
            worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60)),
            "no init: {}",
            worker.view().error
        );
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
    struct CredentialCleanup(String);
    impl Drop for CredentialCleanup {
        fn drop(&mut self) {
            let _id = &self.0;
            // Only Windows/macOS vault opens mint an OS credential; headless
            // hosts derive the key from the passphrase and have nothing to
            // remove.
            #[cfg(any(windows, target_os = "macos"))]
            let _ = keyring::Entry::new("rejection-rejector.v1", _id)
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

    /// Operation kinds published to the runtime journal so far.
    ///
    /// Why: the runtime journal is the durable record every operation outcome
    /// is published to, so reading it observes scheduled work deterministically
    /// while sampling the live snapshot races the scheduler and silently misses
    /// short operations.
    /// Inputs: `dir` — workspace directory. Output: Debug names of every
    /// operation kind recorded in `logs/runtime.jsonl` and its archives.
    fn journaled_operation_kinds(dir: &std::path::Path) -> std::collections::BTreeSet<String> {
        let mut kinds = std::collections::BTreeSet::new();
        let Ok(entries) = std::fs::read_dir(dir.join("logs")) else {
            return kinds;
        };
        for entry in entries.flatten() {
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            for line in text.lines() {
                let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if record["event"] != "operation" {
                    continue;
                }
                if let Ok(kind) =
                    serde_json::from_value::<OperationKind>(record["operation"].clone())
                {
                    kinds.insert(format!("{kind:?}"));
                }
            }
        }
        kinds
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
        let pulse = WorkerPulse::default();
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
                // outcomes to the runtime journal (the mail poll parks on its
                // cursor after the first pass and is exercised through CheckNow
                // below).
                // Why: observe the journal's durable operation records instead
                // of sampling the live snapshot; snapshot sampling races the
                // scheduler and misses short operations.
                let start = Instant::now();
                loop {
                    let kinds = journaled_operation_kinds(dir.path());
                    if ["PurgeRetention", "AutomaticDispatch"]
                        .iter()
                        .all(|expected| kinds.iter().any(|k| k.contains(expected)))
                    {
                        break;
                    }
                    assert!(
                        start.elapsed() < Duration::from_secs(30),
                        "scheduled timered operations never ran; journaled kinds: {kinds:?}"
                    );
                    std::thread::sleep(Duration::from_millis(50));
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

    /// Why: every web-write error arm must answer through the stable error
    /// envelope with its exact code — unknown messages 404, stale approvals
    /// are `stale_revision` without touching state, switching to Automatic
    /// without arming is `automatic_not_armed`, and confirming the arm dialog
    /// can never enable sending while sending is disabled. Each of these is a
    /// contract the desktop UI and API clients branch on.
    /// Inputs: an unknown id, a stale-revision dismissal, an un-armed
    /// Automatic settings write, and an aged arm confirmation while sending is
    /// disabled. Output: 404/409 envelopes with the stable codes and no state
    /// change.
    #[test]
    fn handle_api_write_error_arms_use_the_stable_envelope() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live_engine(dir.path());
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::default();
        let journal = None;
        let mut arm_gate = None;
        let now = Utc::now();

        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Regenerate {
                id: "f".repeat(64),
                revision: 1,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 404);
        assert_eq!(outcome.body["code"], crate::web::CODE_ITEM_NOT_FOUND);

        let mut job = crate::test_support::eligible_job(&e.settings, &e.account, 1, now);
        e.db.insert_stubs([job.stub.clone()], now).unwrap();
        e.db.save(&mut job, "test.seed", "seeded").unwrap();
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Dismiss {
                id: job.id.clone(),
                revision: job.revision + 1,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 409);
        assert_eq!(outcome.body["code"], crate::web::CODE_STALE_REVISION);
        assert_eq!(e.db.get(&job.id).unwrap().state, JobState::Ready);

        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::UpdateSettings {
                mode: Some(Mode::Automatic),
                tone: None,
                reply_language: None,
                sending_enabled: Some(false),
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 409);
        assert_eq!(outcome.body["code"], crate::web::CODE_AUTOMATIC_NOT_ARMED);

        e.settings.sending_enabled = false;
        e.db.set_meta("settings", &e.settings).unwrap();
        arm_gate = Some(AutomaticArmGate::open(now - chrono::Duration::seconds(60)));
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Confirm,
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        assert_eq!(outcome.status, 409);
        assert_eq!(outcome.body["code"], crate::web::CODE_AUTOMATIC_NOT_ARMED);
        assert_ne!(
            e.settings.mode,
            Mode::Automatic,
            "arming must never bypass the sending-disabled guard"
        );
    }

    /// The observable fields of one runtime-journal record.
    #[derive(Debug)]
    struct JournalRecord {
        event: String,
        operation: Option<String>,
        state: Option<String>,
        code: Option<String>,
    }

    /// Every runtime-journal record.
    ///
    /// Why: the runtime journal is the durable record of every scheduled
    /// attempt; counting attempts there is the only race-free way to observe a
    /// timer's backoff (a live snapshot misses short operations).
    /// Inputs: `dir` — workspace directory. Output: one [`JournalRecord`] per
    /// record in `logs/` and its archives, in file order.
    fn journaled_records(dir: &std::path::Path) -> Vec<JournalRecord> {
        let mut records = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir.join("logs")) else {
            return records;
        };
        for entry in entries.flatten() {
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            for line in text.lines() {
                let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                records.push(JournalRecord {
                    event: record["event"].as_str().unwrap_or_default().to_owned(),
                    operation: record["operation"].as_str().map(str::to_owned),
                    state: record["state"].as_str().map(str::to_owned),
                    code: record["code"].as_str().map(str::to_owned),
                });
            }
        }
        records
    }

    /// Terminal (`succeeded`/`failed`) attempt records for one operation kind.
    ///
    /// Inputs: `dir` — workspace directory; `kind` — serialized operation-kind
    /// name (snake case); `state` — serialized terminal state name. Output:
    /// number of recorded attempts.
    fn journaled_attempts(dir: &std::path::Path, kind: &str, state: &str) -> usize {
        journaled_records(dir)
            .into_iter()
            .filter(|record| {
                record.event == "operation"
                    && record.operation.as_deref() == Some(kind)
                    && record.state.as_deref() == Some(state)
            })
            .count()
    }

    /// Seed a connected (non-demo) workspace and let `seed` adjust settings and
    /// queue state before the worker opens it.
    ///
    /// Inputs: `dir` — workspace directory; `mock` — Gmail provider stand-in
    /// used for the login seam and profile; `seed` — runs against the live
    /// engine after `connect`, with the resulting settings persisted. Output:
    /// none.
    fn seed_worker_workspace_with(
        dir: &std::path::Path,
        mock: &MockServer,
        seed: impl FnOnce(&mut Engine),
    ) {
        let mut e = live_engine(dir);
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
        e.settings.api_enabled = false;
        seed(&mut e);
        e.db.set_meta("settings", &e.settings).unwrap();
    }

    /// Why: the scheduled-backup timer must create and verify exactly one real
    /// encrypted backup while overdue, record the success, and then stay quiet
    /// until the configured interval elapses — a regression that re-fires on
    /// every loop pass would fill the backup disk under a zero test interval
    /// and in production after every settings change.
    /// Inputs: a workspace with scheduled backups enabled and no prior backup.
    /// Output: one verified backup directory plus exactly one journaled Backup
    /// success across the observation window.
    #[test]
    fn scheduled_backup_timer_backs_off_after_one_verified_backup() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        let backups = dir.path().join("scheduled-backups");
        seed_worker_workspace_with(dir.path(), &mock, |e| {
            e.settings.scheduled_backup_enabled = true;
            e.settings.scheduled_backup_directory = backups.to_string_lossy().into_owned();
        });
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
                    wait_for(|| journaled_attempts(dir.path(), "backup", "succeeded") >= 1),
                    "the overdue scheduled-backup timer never ran: {:?}",
                    journaled_records(dir.path())
                );
                // The loop keeps ticking every iteration under the zero
                // interval; the recorded success must hold the next backup
                // back to the configured interval.
                std::thread::sleep(Duration::from_secs(2));
                assert_eq!(
                    journaled_attempts(dir.path(), "backup", "succeeded"),
                    1,
                    "a recorded backup success must push the next run out"
                );
                let entries: Vec<_> = std::fs::read_dir(&backups)
                    .expect("scheduled backup root must exist")
                    .flatten()
                    .collect();
                assert_eq!(entries.len(), 1, "exactly one scheduled backup expected");
                assert!(
                    entries[0].path().join("backup-manifest.json").is_file(),
                    "the scheduled backup must be a verified bundle: {:?}",
                    entries[0].path()
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
    }

    /// Why: a scheduled backup that cannot write its destination must fail
    /// once and back the timer off (bounded backoff), not re-run the whole
    /// backup attempt on every loop pass against a broken destination.
    /// Inputs: a workspace whose scheduled-backup directory sits under a
    /// regular file, so every create attempt fails.
    /// Output: exactly one journaled failed Backup attempt across the
    /// observation window.
    #[test]
    fn scheduled_backup_failure_backs_the_timer_off() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        let blocked = dir.path().join("blocked-target");
        std::fs::write(&blocked, b"not a directory").unwrap();
        seed_worker_workspace_with(dir.path(), &mock, |e| {
            e.settings.scheduled_backup_enabled = true;
            e.settings.scheduled_backup_directory =
                blocked.join("backups").to_string_lossy().into_owned();
        });
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
                    wait_for(|| journaled_attempts(dir.path(), "backup", "failed") >= 1),
                    "the scheduled-backup failure never surfaced: {:?}",
                    journaled_records(dir.path())
                );
                std::thread::sleep(Duration::from_secs(2));
                assert_eq!(
                    journaled_attempts(dir.path(), "backup", "failed"),
                    1,
                    "a failed backup must back the timer off instead of hot-looping"
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
    }

    /// Why: when the retention purge fails mid-operation, the worker must back
    /// the retention timer off (bounded backoff) instead of hammering a broken
    /// store on every loop pass. The contrast with the policy reload — whose
    /// backoff is interval-driven and therefore retries every loop under the
    /// zero test interval — is what proves the retention backoff held.
    /// Inputs: a worker whose protected-audit checkpoint fails for every
    /// operation, so the purge fails at its audit boundary.
    /// Output: exactly one failed PurgeRetention attempt against repeated
    /// failed policy reloads.
    #[test]
    fn retention_purge_failure_backs_the_timer_off() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        seed_worker_workspace_with(dir.path(), &mock, |_| {});
        // The workspace's own open must pass its protected-audit checkpoint;
        // every later operation boundary fails, so exactly the mid-operation
        // failure paths are exercised.
        let checkpoint_calls = std::sync::atomic::AtomicUsize::new(0);
        let refusing: crate::test_support::Gate = std::sync::Arc::new(move || {
            if checkpoint_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                anyhow::bail!("synthetic protected-audit checkpoint outage")
            }
        });
        crate::test_support::arm_worker_seams(
            None,
            None,
            Some(refusing),
            None,
            Some(Duration::ZERO),
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                assert!(
                    wait_for(|| journaled_attempts(dir.path(), "purge_retention", "failed") >= 1),
                    "the failing retention purge never surfaced: {:?}",
                    journaled_records(dir.path())
                );
                std::thread::sleep(Duration::from_secs(2));
                assert_eq!(
                    journaled_attempts(dir.path(), "purge_retention", "failed"),
                    1,
                    "a failed purge must back the retention timer off"
                );
                assert!(
                    journaled_attempts(dir.path(), "enterprise_policy_reload", "failed") >= 2,
                    "the interval-driven policy timer retries every loop; it is the contrast case"
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
    }

    /// Why: a refused automatic dispatch must fail the tick with the
    /// emergency-stop attribution and back the next tick off (bounded backoff)
    /// instead of re-evaluating dispatch on every loop pass against a stop
    /// that is still in force.
    /// Inputs: an Automatic-armed workspace whose dispatch gate refuses every
    /// send. Output: exactly one failed AutomaticDispatch attempt, attributed
    /// to the emergency stop.
    #[test]
    fn refused_automatic_dispatch_backs_the_tick_off() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        seed_worker_workspace_with(dir.path(), &mock, |e| {
            crate::test_support::arm_automatic(&mut e.settings);
        });
        let refusing: crate::test_support::Gate =
            std::sync::Arc::new(|| anyhow::bail!("synthetic enterprise emergency stop"));
        crate::test_support::arm_worker_seams(
            None,
            Some(refusing),
            None,
            None,
            None,
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                assert!(
                    wait_for(
                        || journaled_attempts(dir.path(), "automatic_dispatch", "failed") >= 1
                    ),
                    "the refused automatic tick never surfaced: {:?}",
                    journaled_records(dir.path())
                );
                assert!(
                    w.view().error.contains("emergency stop"),
                    "the refused tick must be attributed to the emergency stop: {}",
                    w.view().error
                );
                std::thread::sleep(Duration::from_secs(3));
                assert_eq!(
                    journaled_attempts(dir.path(), "automatic_dispatch", "failed"),
                    1,
                    "a refused tick must back the next evaluation off"
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
    }

    /// Why: the local-AI timer must drain queued mail through the pinned local
    /// pipeline and leave a durable reviewed draft behind — the observable
    /// contract of the AnalyzeQueuedMail arm.
    /// Inputs: a connected workspace with a pinned model, a queued message and
    /// a scripted local runtime that classifies the message as a verified
    /// rejection. Output: the queued job reaches Ready with a draft recorded.
    #[test]
    fn local_ai_timer_classifies_queued_mail() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let email = crate::test_support::gmail_email(
            "applicant@example.invalid",
            1,
            "Your application — R&D Engineer",
            "Thank you for applying. We have decided not to move forward with your application.",
        );
        let stub = email.stub.clone();
        let job_id = stub.id();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![email],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000001".into()),
        );
        let runtime = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| {
                crate::test_support::verdict(
                    "We have decided not to move forward with your application.",
                )
            },
        );
        let seed_stub = stub.clone();
        // The closure borrows `runtime`: moving the mock in would drop the
        // scripted server before the worker ever queried it.
        seed_worker_workspace_with(dir.path(), &mock, |e| {
            e.settings.signature = "Test Applicant".into();
            e.settings.model_digest = Some("a".repeat(64));
            e.settings.ollama_url.clone_from(&runtime.url);
            let job = Job::new(seed_stub, Utc::now());
            e.db.insert_stubs([job.stub.clone()], Utc::now()).unwrap();
        });
        crate::test_support::arm_worker_seams(
            None,
            None,
            None,
            None,
            None,
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                assert!(
                    wait_for(
                        || journaled_attempts(dir.path(), "analyze_queued_mail", "succeeded") >= 1
                    ),
                    "the local-AI timer never classified the queued message: {} / {:?}",
                    w.view().error,
                    journaled_records(dir.path())
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
        // The durable record: the queued identity now holds an analyzed draft.
        let e = live_engine(dir.path());
        let after =
            e.db.get(&job_id)
                .expect("the queued job must survive processing");
        assert_eq!(
            after.state,
            JobState::Ready,
            "state: {:?}, flags: {:?}",
            after.state,
            after.flags
        );
        assert!(after.draft.is_some(), "classification must leave a draft");
        assert!(
            after.analysis.is_some(),
            "classification must record its analysis"
        );
    }

    /// Why: when the local runtime is unreachable the AnalyzeQueuedMail arm
    /// must fail the attempt and hold the next attempt back through the retry
    /// gate instead of retrying every loop pass — and it must leave the queue
    /// intact for when the runtime returns.
    /// Inputs: a connected workspace with a pinned model and a queued message,
    /// against a runtime that answers nothing. Output: exactly one failed
    /// attempt within the observation window; the job stays queued.
    #[test]
    fn local_ai_failure_holds_the_next_attempt_back() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let email = crate::test_support::gmail_email(
            "applicant@example.invalid",
            2,
            "Your application — R&D Engineer",
            "Thank you for applying. We have decided not to move forward with your application.",
        );
        let job_id = email.stub.id();
        let job_stub = email.stub.clone();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![email],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000002".into()),
        );
        let dead = MockServer::new(|_, _| None);
        // The closure borrows `dead`: moving the mock in would drop the
        // scripted server before the worker ever queried it.
        seed_worker_workspace_with(dir.path(), &mock, |e| {
            e.settings.signature = "Test Applicant".into();
            e.settings.model_digest = Some("a".repeat(64));
            e.settings.ollama_url.clone_from(&dead.url);
            let job = Job::new(job_stub, Utc::now());
            e.db.insert_stubs([job.stub.clone()], Utc::now()).unwrap();
        });
        crate::test_support::arm_worker_seams(
            None,
            None,
            None,
            None,
            None,
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                assert!(
                    wait_for(
                        || journaled_attempts(dir.path(), "analyze_queued_mail", "failed") >= 1
                    ),
                    "the failed local-AI attempt never surfaced: {:?}",
                    journaled_records(dir.path())
                );
                std::thread::sleep(Duration::from_secs(2));
                assert_eq!(
                    journaled_attempts(dir.path(), "analyze_queued_mail", "failed"),
                    1,
                    "the retry gate must hold the next attempt back"
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
        let e = live_engine(dir.path());
        let after =
            e.db.get(&job_id)
                .expect("the queued job must survive the failure");
        assert!(
            matches!(after.state, JobState::Queued),
            "a global runtime failure must leave the queue intact: {:?}",
            after.state
        );
    }

    /// Why: a scheduled Gmail check that fails at the provider must fail the
    /// attempt and hold the next scheduled check back through the retry gate
    /// instead of hammering a failing provider.
    /// Inputs: a connected workspace whose worker-side Gmail endpoints point at
    /// a provider stand-in that answers nothing. Output: exactly one failed
    /// SyncMailbox attempt within the observation window.
    #[test]
    fn gmail_sync_failure_backs_the_next_scheduled_check_off() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        seed_worker_workspace_with(dir.path(), &mock, |_| {});
        let failing = MockServer::new(|_, _| None);
        crate::test_support::arm_worker_seams(
            None,
            None,
            None,
            None,
            None,
            Some((failing.url.clone(), failing.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                assert!(
                    wait_for(|| journaled_attempts(dir.path(), "sync_mailbox", "failed") >= 1),
                    "the failed scheduled Gmail check never surfaced: {:?}",
                    journaled_records(dir.path())
                );
                std::thread::sleep(Duration::from_secs(2));
                assert_eq!(
                    journaled_attempts(dir.path(), "sync_mailbox", "failed"),
                    1,
                    "the retry gate must hold the next scheduled check back"
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
    }

    /// Why: the EvaluateModel command must report a failing model evaluation
    /// through the typed operation status and keep the worker loop alive —
    /// an evaluation failure is a report, never a dead worker.
    /// Inputs: a connected workspace whose local runtime answers nothing, so
    /// the full task evaluation fails. Output: one journaled failed
    /// EvaluateModel attempt carrying its typed failure code, and a
    /// still-responsive loop.
    #[test]
    fn evaluate_model_command_reports_failures_without_wedging_the_loop() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        let dead = MockServer::new(|_, _| None);
        seed_worker_workspace_with(dir.path(), &mock, |e| {
            e.settings.ollama_url.clone_from(&dead.url);
        });
        crate::test_support::arm_worker_seams(
            None,
            None,
            None,
            None,
            None,
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut w = Worker::spawn(dir.path().to_path_buf(), false);
                w.command(Command::EvaluateModel);
                // The journal's durable operation record is the race-free
                // observation point; the live snapshot is republished by every
                // later operation.
                assert!(
                    wait_for(|| {
                        journaled_records(dir.path()).iter().any(|record| {
                            record.operation.as_deref() == Some("evaluate_model")
                                && record.state.as_deref() == Some("failed")
                        })
                    }),
                    "the evaluation command never finished: {:?}",
                    journaled_records(dir.path())
                );
                assert_eq!(
                    journaled_attempts(dir.path(), "evaluate_model", "failed"),
                    1,
                    "a failing evaluation must be reported as a failed attempt: {:?}",
                    journaled_records(dir.path())
                );
                let failure = journaled_records(dir.path()).into_iter().find(|record| {
                    record.operation.as_deref() == Some("evaluate_model")
                        && record.state.as_deref() == Some("failed")
                });
                assert!(
                    failure.is_some_and(|record| record.code.is_some()),
                    "the failed evaluation must carry its typed failure code"
                );
                assert!(
                    !w.view().fatal,
                    "an evaluation failure must not kill the worker: {}",
                    w.view().error
                );
                // The loop still serves commands after the failure.
                let before = w.view().operation.operation_id.clone();
                w.command(Command::Refresh);
                assert!(
                    wait_for(|| {
                        let s = w.view();
                        s.operation.operation_id != before && s.busy.is_empty()
                    }),
                    "the worker loop must stay responsive after an evaluation failure"
                );
                w.shutdown(Duration::from_secs(10));
            },
        );
    }

    /// A shared snapshot whose lock a panicking holder left poisoned.
    ///
    /// Why: the worker helpers must degrade instead of panicking across the
    /// thread boundary when the UI-state lock is poisoned mid-operation.
    fn poisoned_snapshot() -> Arc<Mutex<Snapshot>> {
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        poison_lock(&shared);
        shared
    }

    /// Poison one snapshot lock with a panicking holder.
    fn poison_lock(shared: &Arc<Mutex<Snapshot>>) {
        let for_thread = shared.clone();
        let handle = std::thread::spawn(move || {
            let _guard = for_thread.lock().unwrap();
            panic!("poison the shared snapshot");
        });
        let _ = handle.join();
        assert!(shared.is_poisoned());
    }

    /// Why: a poisoned UI-state lock must degrade to a silent no-op at the
    /// helper boundary (a panic here would take the worker thread down for a
    /// UI-state accident), except for `refresh`, which must fail closed with
    /// its exact documented error instead of publishing a stale snapshot.
    #[test]
    fn lifecycle_helpers_degrade_silently_on_a_poisoned_snapshot_lock() {
        let dir = tempfile::tempdir().unwrap();
        let shared = poisoned_snapshot();
        let pulse = WorkerPulse::default();

        busy(&shared, &pulse, "progress");
        report(&shared, &pulse, OperationKind::Refresh, &Ok(()));
        report(
            &shared,
            &pulse,
            OperationKind::Refresh,
            &Err(anyhow::anyhow!("synthetic failure")),
        );
        report_silent_success(&shared, &pulse, OperationKind::Refresh, "quiet");
        record_current_operation(&None, &shared);
        expire_api_token(&shared);

        // Reads degrade to the documented default instead of propagating.
        assert_eq!(
            format!("{:?}", current_operation(&shared)),
            format!("{:?}", OperationStatus::default())
        );
        let liveness = pulse.snapshot(Utc::now());
        assert_eq!(liveness.current_operation, OperationKind::Idle);

        // `refresh` is the exception: it must refuse to publish.
        let e = demo_engine(dir.path());
        let error = refresh(&e, &shared, None, true, 0).unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");
    }

    /// Why: `busy` reports forward progress, not a new operation outcome —
    /// when no operation is running it must not rewrite the published
    /// operation status (that would erase the recorded outcome of the last
    /// operation).
    #[test]
    fn busy_never_rewrites_a_finished_operation_status() {
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::default();
        begin_operation(&shared, &pulse, OperationKind::Refresh, "Working…");
        report(&shared, &pulse, OperationKind::Refresh, &Ok(()));
        busy(&shared, &pulse, "Background progress…");
        let snapshot = shared.lock().unwrap();
        assert_eq!(snapshot.busy, "Background progress…");
        assert_eq!(snapshot.operation.state, OperationState::Succeeded);
        assert_eq!(snapshot.operation.message, "Operation completed.");
    }

    /// Why: every read-route refusal is a stable operator-facing contract —
    /// the exact reason is what tells a client whether to fix its request or
    /// its expectations, so each guard's wording is pinned.
    #[test]
    fn read_api_error_arms_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let e = demo_engine(dir.path());
        let cases = [
            (
                "/v1/capabilities?x=1",
                "Capabilities endpoint takes no query parameters",
            ),
            (
                "/v1/health?x=1",
                "Health endpoint takes no query parameters",
            ),
            (
                "/v1/metrics?x=1",
                "Metrics endpoint takes no query parameters",
            ),
            (
                "/v1/settings?x=1",
                "Settings endpoint takes no query parameters",
            ),
            (
                "/v1/status?x=1",
                "Status endpoint takes no query parameters",
            ),
            (
                "/v1/audit/anchor?x=1",
                "Audit anchor endpoint takes no query parameters",
            ),
            ("/v1/items?page=1&page=2", "Duplicate query parameter: page"),
            ("/v1/nope", "Unknown API route"),
            ("/v1/items/short", "Invalid item identifier"),
            (
                "/v1/item-feed?bogus=1",
                "Item-feed endpoint accepts only cursor and limit",
            ),
            ("/v1/item-feed?limit=0", "Item-feed limit must be 1..100"),
            (
                "/v1/item-feed?cursor=%21%21",
                "Invalid item-feed cursor encoding",
            ),
            ("/v1/item-feed?cursor=AAAA", "Invalid item-feed cursor"),
            ("/v1/items?page=1000001", "Page is outside supported range"),
        ];
        for (path, expected) in cases {
            let error = api_query(&e, path).unwrap_err().to_string();
            assert_eq!(error, expected, "path {path}");
        }
        // /v1/items rejects parameters other than page.
        let error = api_query(&e, "/v1/items?bogus=1").unwrap_err().to_string();
        assert_eq!(error, "Items endpoint accepts only page");
    }

    /// Why: an invalid request through the API relay must answer the stable
    /// error document rather than drop the reply channel (the desktop would
    /// hang on a missing reply) or leak internal error detail.
    #[test]
    fn api_relay_invalid_requests_answer_the_stable_error_document() {
        let dir = tempfile::tempdir().unwrap();
        let mut worker = Worker::spawn(dir.path().into(), true);
        let start = Instant::now();
        while !worker.view().initialized {
            assert!(!worker.view().fatal, "{}", worker.view().error);
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            api(&worker, "/v1/nope"),
            serde_json::json!({"error": "Invalid request or unavailable resource"})
        );
        assert!(worker.shutdown(Duration::from_secs(5)));
    }

    /// Why: the API relay commands are intercepted by the loop and must never
    /// reach the command dispatchers — if one does, it must be reported as a
    /// typed operation failure with the documented internal error (never run
    /// as a half-formed worker command), without wedging the loop.
    #[test]
    fn wrong_dispatcher_api_commands_report_the_internal_error() {
        let dir = tempfile::tempdir().unwrap();
        let e = &mut demo_engine(dir.path());
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::default();
        let journal = None;
        let api_disabled = Arc::new(AtomicBool::new(false));
        let mut gmail_gate = RetryGate::new(
            Instant::now(),
            Duration::from_secs(30),
            Duration::from_secs(15 * 60),
            3,
            Duration::from_secs(10 * 60),
        );
        let (reply, _rx) = bounded(1);
        let command = Command::Api {
            path: "/v1/health".into(),
            reply,
        };
        let result = execute_vault_ops(command, e, &shared, &pulse)
            .expect("the dispatcher mismatch is an operation failure, not a fatal escape")
            .unwrap_err();
        assert_eq!(
            result.to_string(),
            "Internal API command reached the wrong dispatcher"
        );

        let (reply, _rx) = bounded(1);
        let (selected_out, review_out, page_out, _due) = handle_worker_command(
            Command::OpenMetrics { reply },
            e,
            &shared,
            &pulse,
            &journal,
            &api_disabled,
            &mut gmail_gate,
            None,
            true,
            0,
            Instant::now(),
        )
        .unwrap();
        assert_eq!((selected_out, review_out, page_out), (None, true, 0));
        // The failure is published through the typed operation status.
        let snapshot = shared.lock().unwrap();
        assert_eq!(snapshot.operation.state, OperationState::Failed);
        assert_eq!(
            snapshot.operation.code.as_deref(),
            Some(OperationKind::ApiRequest.failure_code())
        );
        assert_eq!(
            snapshot.operation.message, "Internal API command reached the wrong dispatcher",
            "the dispatch must report the documented internal error"
        );
    }

    /// Why: the app-password arm runs the same connect operation as the
    /// interactive surface — on a demo workspace it must refuse with the exact
    /// demo guard and leave settings untouched (never half-connect a demo
    /// workspace to a real mailbox).
    #[test]
    fn connect_app_password_dispatch_reports_the_demo_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let e = &mut demo_engine(dir.path());
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::default();
        let journal = None;
        let api_disabled = Arc::new(AtomicBool::new(false));
        let mut gmail_gate = RetryGate::new(
            Instant::now(),
            Duration::from_secs(30),
            Duration::from_secs(15 * 60),
            3,
            Duration::from_secs(10 * 60),
        );
        let outcome = execute_command(
            Command::ConnectAppPassword(AppPasswordCredentials::new(
                "applicant@example.invalid",
                "abcd efgh ijkl mnop",
            )),
            e,
            &shared,
            &pulse,
            &journal,
            &api_disabled,
            &mut gmail_gate,
            None,
            true,
            0,
        )
        .unwrap();
        assert!(!outcome.settings_changed);
        let error = outcome.result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "Demo mode never connects to a real mailbox"
        );
    }

    /// Why: the web connect arm must answer through the same stable envelope
    /// as every other write — the exact demo refusal, with its typed operation
    /// code and retryability, so clients can react consistently.
    #[test]
    fn handle_api_write_connect_app_password_answers_the_stable_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = demo_engine(dir.path());
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::default();
        let journal = None;
        let mut arm_gate = None;
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::ConnectAppPassword {
                creds: AppPasswordCredentials::new(
                    "applicant@example.invalid",
                    "abcd efgh ijkl mnop",
                ),
            },
            &mut arm_gate,
            &ctx(&shared, &pulse, &journal),
        );
        let (code, retryable) =
            classify_operation_failure(OperationKind::ConnectGmail, &anyhow::anyhow!("x"));
        assert_eq!(outcome.status, if retryable { 503 } else { 409 });
        assert_eq!(outcome.body["code"], serde_json::json!(code));
        assert_eq!(
            outcome.body["message"],
            serde_json::json!("Demo mode never connects to a real mailbox")
        );
    }

    /// Why: these write arms run the same engine operations as their
    /// interactive commands (mailbox sync, disconnect, integrity, compaction,
    /// backup, retention) through the shared begin/report/audit/refresh
    /// sequence — a regression here would let the web surface diverge from
    /// the desktop on state-changing work.
    #[test]
    fn handle_api_write_executes_the_operational_arms() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live_engine(dir.path());
        e.account = "applicant@example.invalid".into();
        let gmail = crate::test_support::gmail_server(
            &e.account,
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
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
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::default();
        let journal = None;
        let mut arm_gate = None;
        let context = ctx(&shared, &pulse, &journal);

        let outcome = handle_api_write(&mut e, &WriteRequest::CheckNow, &mut arm_gate, &context);
        assert_eq!(outcome.status, 200, "body: {:?}", outcome.body);
        assert_eq!(
            outcome.body["new_identities"],
            serde_json::json!(0),
            "the payload must report the exact number of new identities"
        );

        let backup_out = dir.path().join("api-backup");
        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Backup {
                out: backup_out.to_string_lossy().into_owned(),
            },
            &mut arm_gate,
            &context,
        );
        assert_eq!(outcome.status, 200, "body: {:?}", outcome.body);
        assert!(backup_out.exists(), "the verified backup bundle must exist");

        for (request, label) in [
            (WriteRequest::IntegrityCheck, "integrity"),
            (WriteRequest::Compact, "compact"),
            (WriteRequest::Purge, "purge"),
        ] {
            let outcome = handle_api_write(&mut e, &request, &mut arm_gate, &context);
            assert_eq!(outcome.status, 200, "{label}: {:?}", outcome.body);
        }

        let outcome = handle_api_write(&mut e, &WriteRequest::Disconnect, &mut arm_gate, &context);
        assert_eq!(outcome.status, 200, "body: {:?}", outcome.body);
        assert!(
            !e.settings.sending_enabled || !e.connected(),
            "disconnect must disarm the mailbox"
        );
    }

    /// Why: the Qualify web arm pins provenance digests on success — the
    /// primary pin from its smoke test and, when asked, the verifier pin from
    /// its own qualification — and the `verifier` flag must only add the
    /// verifier qualification after the primary one passed.
    #[test]
    fn handle_api_write_qualify_pins_the_primary_and_verifier_models() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let runtime = crate::test_support::ollama_runtime(
            vec![
                (crate::config::DEFAULT_MODEL.into(), "a".repeat(64)),
                (crate::config::DEFAULT_VERIFIER_MODEL.into(), "b".repeat(64)),
            ],
            "Test Applicant",
            |_| {
                crate::test_support::verdict(
                    "We have decided not to move forward with your application.",
                )
            },
        );
        let mut e = live_engine(dir.path());
        e.settings.signature = "Test Applicant".into();
        e.settings.model = crate::config::DEFAULT_MODEL.into();
        e.settings.model_digest = None;
        e.settings.verifier_model = crate::config::DEFAULT_VERIFIER_MODEL.into();
        e.settings.independent_verifier_enabled = false;
        e.settings.ollama_url.clone_from(&runtime.url);
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let pulse = WorkerPulse::default();
        let journal = None;
        let mut arm_gate = None;
        let context = ctx(&shared, &pulse, &journal);

        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Qualify { verifier: false },
            &mut arm_gate,
            &context,
        );
        assert_eq!(outcome.status, 200, "body: {:?}", outcome.body);
        assert_eq!(e.settings.model_digest, Some("a".repeat(64)));
        assert_eq!(e.settings.verifier_model_digest, None);

        let outcome = handle_api_write(
            &mut e,
            &WriteRequest::Qualify { verifier: true },
            &mut arm_gate,
            &context,
        );
        assert_eq!(outcome.status, 200, "body: {:?}", outcome.body);
        assert_eq!(e.settings.verifier_model_digest, Some("b".repeat(64)));
    }

    /// Why: a poisoned UI-state lock must fail the scheduled stages closed at
    /// their documented refresh boundary ("UI state lock failed") instead of
    /// silently skipping the post-operation snapshot rebuild and leaving the
    /// UI on stale state while retention/policy/backup work keeps running.
    #[test]
    fn poisoned_snapshot_fails_the_scheduled_maintenance_stages_closed() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let e = &mut live_engine(dir.path());
        let shared = poisoned_snapshot();
        let pulse = WorkerPulse::default();
        let journal = None;
        let api_disabled = Arc::new(AtomicBool::new(false));
        let selected = None;
        let now = Instant::now();
        let future = now + Duration::from_secs(3600);

        // Retention purge runs (due), then refuses to publish the rebuild.
        let error =
            run_retention(e, &shared, &pulse, &journal, &selected, true, 0, 0, now).unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");

        // The same boundary holds for the overdue scheduled backup.
        e.settings.scheduled_backup_enabled = true;
        let error = run_scheduled_backup(e, &shared, &pulse, &journal, &selected, true, 0, 0, now)
            .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");

        // And through the maintenance aggregator that drives them.
        let mut policy_due = future;
        let mut retention_due = now;
        let mut backup_due = future;
        let error = run_maintenance_operations(
            e,
            &shared,
            &pulse,
            &journal,
            &api_disabled,
            &mut 0,
            &mut policy_due,
            &mut 0,
            &mut retention_due,
            &mut 0,
            &mut backup_due,
            &selected,
            true,
            0,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");
    }

    /// Why: the AI stages share the same fail-closed refresh boundary — a
    /// scheduled poll, local-AI tick or automatic dispatch that cannot publish
    /// its outcome must stop the schedule, not continue dispatching against a
    /// UI state nobody can observe.
    #[test]
    fn poisoned_snapshot_fails_the_scheduled_ai_stages_closed() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let e = &mut live_engine(dir.path());
        e.settings.model_digest = Some("a".repeat(64));
        let mock = MockServer::new(|_, _| None);
        e.settings.ollama_url.clone_from(&mock.url);
        let shared = poisoned_snapshot();
        let pulse = WorkerPulse::default();
        let journal = None;
        let selected = None;
        let now = Instant::now();
        let mut gmail_gate = RetryGate::new(
            now,
            Duration::from_secs(30),
            Duration::from_secs(60),
            3,
            Duration::from_secs(60),
        );
        let mut local_ai_gate = RetryGate::new(
            now,
            Duration::from_secs(30),
            Duration::from_secs(60),
            3,
            Duration::from_secs(60),
        );

        // The scheduled poll runs its sync, then fails closed at the refresh.
        let error = run_gmail_poll(
            e,
            &shared,
            &pulse,
            &journal,
            &selected,
            true,
            0,
            &mut gmail_gate,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");

        // The local-AI tick needs queued mail to reach its own refresh.
        e.account = "applicant@example.invalid".into();
        let email = crate::test_support::gmail_email(
            "applicant@example.invalid",
            1,
            "Your application",
            "We have decided not to move forward with your application.",
        );
        let job = Job::new(email.stub.clone(), Utc::now());
        e.db.insert_stubs([job.stub.clone()], Utc::now()).unwrap();
        let error = run_local_ai(
            e,
            &shared,
            &pulse,
            &journal,
            &selected,
            true,
            0,
            &mut local_ai_gate,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");

        // The automatic dispatch tick is governed by the enterprise emergency
        // stop; an armed stop errors the tick, which still must fail closed at
        // the same refresh boundary.
        e.settings.mode = crate::config::Mode::Automatic;
        e.settings.sending_enabled = true;
        let error = crate::test_support::with_dispatch_gate(
            std::sync::Arc::new(|| Err(anyhow::anyhow!("emergency stop"))),
            || run_automatic_dispatch(e, &shared, &pulse, &journal, &selected, true, 0, 0, now),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");

        // And through the AI aggregator that drives them.
        let error = run_ai_operations(
            e,
            &shared,
            &pulse,
            &journal,
            &selected,
            true,
            0,
            &mut gmail_gate,
            &mut local_ai_gate,
            &mut 0,
            &mut (now + Duration::from_secs(3600)),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");
    }

    /// Why: a recovery drill against a missing backup bundle is a documented
    /// fatal dispatch escape (it bypasses the operation report exactly like
    /// the original `?` sites) — the worker must latch fail-closed and journal
    /// `worker_startup_failed` instead of pretending the drill was a routine
    /// retryable operation failure.
    #[test]
    fn a_failed_recovery_drill_is_a_fatal_dispatch_escape() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let worker = Worker::spawn(dir.path().into(), false);
        assert!(
            worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60),),
            "worker did not initialize: {}",
            worker.view().error
        );
        worker.command(Command::RecoveryDrill {
            backup: dir.path().join("missing-backup-bundle"),
        });
        assert!(
            wait_for(|| worker.view().fatal),
            "the drill escape must latch the fatal state: {}",
            worker.view().error
        );
        let snapshot = worker.view();
        assert!(
            !snapshot.error.is_empty(),
            "the fatal state must carry the drill failure reason"
        );
        assert!(
            journaled_events(dir.path()).contains("worker_startup_failed"),
            "the dispatch escape must journal worker_startup_failed: {:?}",
            journaled_events(dir.path())
        );
    }

    /// Why: the policy-reload and scheduled-backup stages forward their
    /// fail-closed refresh errors through the maintenance aggregator — each
    /// stage must stop the schedule at its own hand-off instead of continuing
    /// with an unpublishable outcome.
    #[test]
    fn poisoned_snapshot_fails_the_policy_and_backup_aggregator_stages_closed() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let e = &mut live_engine(dir.path());
        let shared = poisoned_snapshot();
        let pulse = WorkerPulse::default();
        let journal = None;
        let api_disabled = Arc::new(AtomicBool::new(false));
        let selected = None;
        let now = Instant::now();
        let future = now + Duration::from_secs(3600);

        // A policy that tightens settings reports the change; publishing that
        // changed outcome must fail closed at the same refresh boundary as
        // every other stage.
        e.settings.sending_enabled = true;
        crate::test_support::with_policy(
            Some(crate::test_support::loaded_policy(
                "d1",
                crate::policy::EnterprisePolicy {
                    version: 1,
                    prohibit_sending: true,
                    ..crate::policy::EnterprisePolicy::default()
                },
            )),
            || {
                let mut policy_due = now;
                let mut retention_due = future;
                let mut backup_due = future;
                let error = run_maintenance_operations(
                    e,
                    &shared,
                    &pulse,
                    &journal,
                    &api_disabled,
                    &mut 0,
                    &mut policy_due,
                    &mut 0,
                    &mut retention_due,
                    &mut 0,
                    &mut backup_due,
                    &selected,
                    true,
                    0,
                )
                .unwrap_err();
                assert_eq!(error.to_string(), "UI state lock failed");
            },
        );

        // And the overdue scheduled-backup stage.
        e.settings.scheduled_backup_enabled = true;
        let mut policy_due = future;
        let mut retention_due = future;
        let mut backup_due = now;
        let error = run_maintenance_operations(
            e,
            &shared,
            &pulse,
            &journal,
            &api_disabled,
            &mut 0,
            &mut policy_due,
            &mut 0,
            &mut retention_due,
            &mut 0,
            &mut backup_due,
            &selected,
            true,
            0,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");
    }

    /// Why: the AI aggregator forwards its stage errors the same way — the
    /// poll stage and the automatic-dispatch stage must each stop the schedule
    /// at their own hand-off when the outcome cannot be published.
    #[test]
    fn poisoned_snapshot_fails_the_poll_and_dispatch_aggregator_stages_closed() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let e = &mut live_engine(dir.path());
        e.settings.model_digest = Some("a".repeat(64));
        e.settings.mode = crate::config::Mode::Automatic;
        e.settings.sending_enabled = true;
        let shared = poisoned_snapshot();
        let pulse = WorkerPulse::default();
        let journal = None;
        let selected = None;
        let now = Instant::now();
        let future = now + Duration::from_secs(3600);

        // The poll stage runs its sync, then fails closed at the refresh.
        let mut gmail_gate = RetryGate::new(
            now,
            Duration::from_secs(30),
            Duration::from_secs(60),
            3,
            Duration::from_secs(60),
        );
        let mut local_ai_gate = RetryGate::new(
            now,
            Duration::from_secs(30),
            Duration::from_secs(60),
            3,
            Duration::from_secs(60),
        );
        let mut auto_due = future;
        let error = run_ai_operations(
            e,
            &shared,
            &pulse,
            &journal,
            &selected,
            true,
            0,
            &mut gmail_gate,
            &mut local_ai_gate,
            &mut 0,
            &mut auto_due,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");

        // With both retry gates held back, the dispatch stage is the one that
        // runs — an enterprise emergency stop errors the tick, which must fail
        // closed at the same boundary.
        let mut gmail_gate = RetryGate::new(
            now,
            Duration::from_secs(30),
            Duration::from_secs(60),
            3,
            Duration::from_secs(60),
        );
        gmail_gate.failure(Instant::now(), None);
        let mut local_ai_gate = RetryGate::new(
            now,
            Duration::from_secs(30),
            Duration::from_secs(60),
            3,
            Duration::from_secs(60),
        );
        local_ai_gate.failure(Instant::now(), None);
        let error = crate::test_support::with_dispatch_gate(
            std::sync::Arc::new(|| Err(anyhow::anyhow!("emergency stop"))),
            || {
                let mut auto_due = now;
                run_ai_operations(
                    e,
                    &shared,
                    &pulse,
                    &journal,
                    &selected,
                    true,
                    0,
                    &mut gmail_gate,
                    &mut local_ai_gate,
                    &mut 0,
                    &mut auto_due,
                )
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "UI state lock failed");
    }

    /// Why: a corrupt incremental-sync record must fail the worker closed with
    /// the exact parse error — both the startup snapshot build and the
    /// scheduled poll read the record, and neither may treat an unreadable
    /// cursor as "never polled" (that would re-poll a mailbox whose synced
    /// state is unknown). The durable `worker_startup_failed` record carries
    /// the failure into the runtime journal.
    #[test]
    fn corrupt_sync_state_fails_the_worker_closed_with_the_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        seed_worker_workspace_with(dir.path(), &mock, |e| {
            // A payload that cannot parse as `SyncState`: the snapshot build
            // and the scheduled poll must escalate the read failure instead of
            // treating it as "never polled".
            e.db.set_meta(
                &format!("sync/{}", e.account),
                &serde_json::json!({"bogus": 1}),
            )
            .unwrap();
        });
        crate::test_support::arm_worker_seams(
            None,
            None,
            None,
            None,
            None,
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let worker = Worker::spawn(dir.path().into(), false);
                assert!(
                    wait_for(|| worker.view().fatal),
                    "the corrupt sync state must latch the fatal state: {}",
                    worker.view().error
                );
                let snapshot = worker.view();
                assert!(
                    snapshot.error.contains("missing field"),
                    "the fatal state must carry the parse failure: {}",
                    snapshot.error
                );
                assert!(
                    journaled_events(dir.path()).contains("worker_startup_failed"),
                    "the escape must journal worker_startup_failed: {:?}",
                    journaled_events(dir.path())
                );
            },
        );
    }

    /// Why: when the scheduled stages cannot publish their outcomes (poisoned
    /// UI-state lock), the worker loop must treat that as a fatal worker
    /// failure and stop — continuing would run unobserved scheduled work
    /// forever. The durable `worker_startup_failed` record is the observable,
    /// because the fatal state itself cannot publish through the poisoned
    /// lock.
    #[test]
    fn the_worker_loop_stops_when_scheduled_stages_cannot_publish() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        // Zero intervals make every maintenance stage due on each loop pass.
        crate::test_support::arm_worker_seams(
            None,
            None,
            None,
            None,
            Some(Duration::ZERO),
            None,
            || {
                let mut worker = Worker::spawn(dir.path().into(), false);
                assert!(
                    worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60),),
                    "worker did not initialize: {}",
                    worker.view().error
                );
                poison_lock(&worker.snapshot);
                assert!(
                    wait_for(|| journaled_events(dir.path()).contains("worker_startup_failed")),
                    "the loop must stop on the unpublishable scheduled outcome: {:?}",
                    journaled_events(dir.path())
                );
                assert!(
                    worker.shutdown(Duration::from_secs(10)),
                    "the worker thread must exit once the schedule is stopped"
                );
            },
        );
    }

    /// Why: the AI schedule shares the loop's fatal publish boundary — an
    /// automatic dispatch tick that cannot publish its outcome must stop the
    /// worker exactly like the maintenance stages, never keep dispatching
    /// against a UI state nobody can observe.
    #[test]
    fn the_worker_loop_stops_when_the_ai_dispatch_cannot_publish() {
        let dir = tempfile::tempdir().unwrap();
        crate::test_support::headless_vault_seam();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mock = crate::test_support::gmail_server(
            "applicant@example.invalid",
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        seed_worker_workspace_with(dir.path(), &mock, |e| {
            // Arm automatic dispatch so its tick runs on the schedule.
            e.settings.mode = crate::config::Mode::Automatic;
            e.settings.sending_enabled = true;
        });
        // The enterprise emergency stop errors every dispatch tick (its retry
        // schedule keeps the tick due while the maintenance timers stay quiet).
        crate::test_support::arm_worker_seams(
            None,
            Some(std::sync::Arc::new(|| {
                Err(anyhow::anyhow!("emergency stop"))
            })),
            None,
            None,
            None,
            Some((mock.url.clone(), mock.url.clone())),
            || {
                let mut worker = Worker::spawn(dir.path().into(), false);
                assert!(
                    worker.wait_for(|s| s.initialized, |s| s.fatal, Duration::from_secs(60),),
                    "worker did not initialize: {}",
                    worker.view().error
                );
                poison_lock(&worker.snapshot);
                let mut stopped = false;
                for _ in 0..240 {
                    if journaled_events(dir.path()).contains("worker_startup_failed") {
                        stopped = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
                assert!(
                    stopped,
                    "the AI schedule must stop the loop on the unpublishable outcome: {:?}",
                    journaled_events(dir.path())
                );
                assert!(worker.shutdown(Duration::from_secs(10)));
            },
        );
    }
}
