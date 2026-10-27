use crate::imap_smtp::{ImapSmtp, ImapSmtpConfig};
use crate::mail_transport::{AppPasswordCredentials, MailTransport};
use crate::sync::Provider;
use crate::{
    audit_anchor,
    config::{
        AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H, Mode, PROMPT_VERSION, Settings, TaskQualification,
        evaluation_suite_hash, settings_context_hash,
    },
    emergency, evaluation,
    gmail::{FetchFailureKind, Gmail, SendFailureKind},
    mail,
    oauth::{self, Credentials},
    ollama::{self, ModelStatus, Ollama},
    policy::{self, LoadedPolicy, PolicyRevisionFloor, PolicyStatus},
    recovery,
    session::SessionLease,
    store::{ProcessingFailureRecord, Store},
    sync,
    types::*,
    vault::{InstanceLock, Vault, write_new_private},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Stable code naming why one item is ineligible for unattended sending.
///
/// Inputs: none (plain enum). Output: the machine-readable block code,
/// serialized in snake_case for the API and operator surfaces.
#[derive(
    Clone, Copy, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticPolicyCode {
    /// The queued item identity does not match the reserved send.
    QueueIdentityMismatch,
    /// The workspace is not armed for automatic dispatch.
    AutomaticModeNotArmed,
    /// The original message is no longer available.
    OriginalEmailMissing,
    /// A mailbox-level sending block applies to the message.
    MailboxSafetyBlock,
    /// No local analysis is stored for the message.
    LocalAnalysisMissing,
    /// No draft exists for the message.
    DraftMissing,
    /// The analysis is not a high-confidence rejection.
    NotHighConfidenceRejection,
    /// Model verification or GPU residency requirements failed.
    ModelVerificationOrResidencyFailed,
    /// The verified draft no longer matches the stored draft.
    DraftVerificationStale,
    /// The stored analysis no longer matches the analyzed message.
    AnalysisIdentityStale,
    /// The model task qualification is out of date.
    TaskQualificationStale,
    /// The per-account send cooldown is still active.
    CooldownActive,
    /// The message is outside the configured automatic age window.
    OutsideAgeWindow,
    /// The message predates the automatic-dispatch enrollment.
    PredatesAutomaticEnrollment,
    /// Deterministic rejection evidence is missing from the analysis.
    MissingDeterministicRejectionEvidence,
    /// The draft language conflicts with the message language.
    ConflictingEmailLanguage,
    /// The draft escalates the thread or contains a link.
    DraftEscalationOrLink,
    /// Sending would create an automatic reply loop.
    AutomaticReplyLoop,
    /// An automatic reply to this thread was already suppressed.
    AutomaticReplySuppressed,
    /// The reply target does not match the authenticated thread.
    ReplyToMismatch,
}

/// One automatic-policy refusal with its stable code and operator text.
///
/// Inputs: none (plain struct). Output: the [`AutomaticPolicyCode`] and the
/// human-readable block message.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AutomaticPolicyBlock {
    /// Stable policy code identifying the block.
    pub code: AutomaticPolicyCode,
    /// Operator-facing explanation of the block.
    pub message: String,
}

/// The eligibility verdict for one item's unattended send.
///
/// Inputs: none (plain struct). Output: the `eligible` flag plus every
/// [`AutomaticPolicyBlock`] explaining a refusal.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AutomaticPolicyDecision {
    /// Whether automatic dispatch is eligible after applying policy.
    pub eligible: bool,
    /// Blocks that prevent automatic dispatch.
    pub blocks: Vec<AutomaticPolicyBlock>,
}

/// Append one automatic-policy block, deduplicated by code.
///
/// Inputs: `blocks` — the block list being built; `code` — policy code
/// identifying the block; `message` — operator-facing policy explanation.
/// Output: none — the block is pushed only when no block with `code` exists
/// yet.
fn push_policy_block(
    blocks: &mut Vec<AutomaticPolicyBlock>,
    code: AutomaticPolicyCode,
    message: impl Into<String>,
) {
    if blocks.iter().any(|block| block.code == code) {
        return;
    }
    blocks.push(AutomaticPolicyBlock {
        code,
        message: message.into(),
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchFailureKind {
    Retryable,
    ReviewRequired,
    ReconcileRequired,
    StateHandled,
}
#[derive(Debug)]
pub(crate) struct DispatchFailure {
    kind: DispatchFailureKind,
    code: &'static str,
    message: String,
}
impl DispatchFailure {
    /// Build a retryable dispatch failure.
    ///
    /// Inputs: `message` — operator-facing failure description. Output: [`Self`]
    /// with the stable `retryable_dispatch` code.
    pub(crate) fn retryable(message: impl Into<String>) -> Self {
        Self::retryable_code("retryable_dispatch", message)
    }
    /// Build a retryable dispatch failure with an explicit code.
    ///
    /// Inputs: `code` — stable failure code; `message` — operator-facing failure
    /// description. Output: [`Self`] with `DispatchFailureKind::Retryable` and the
    /// given code.
    fn retryable_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: DispatchFailureKind::Retryable,
            code,
            message: message.into(),
        }
    }
    /// Build a review-required dispatch failure.
    ///
    /// Inputs: `message` — operator-facing failure description. Output: [`Self`]
    /// with the stable `review_required_dispatch` code.
    pub(crate) fn review(message: impl Into<String>) -> Self {
        Self::review_code("review_required_dispatch", message)
    }
    /// Build a review-required dispatch failure with an explicit code.
    ///
    /// Inputs: `code` — stable failure code; `message` — operator-facing failure
    /// description. Output: [`Self`] with `DispatchFailureKind::ReviewRequired` and
    /// the given code.
    fn review_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: DispatchFailureKind::ReviewRequired,
            code,
            message: message.into(),
        }
    }
    /// Build a reconcile-required failure for an uncertain delivery.
    ///
    /// Inputs: `message` — operator-facing failure description. Output: [`Self`]
    /// with the stable `reconcile_required_delivery_uncertain` code.
    pub(crate) fn reconcile(message: impl Into<String>) -> Self {
        Self {
            kind: DispatchFailureKind::ReconcileRequired,
            code: "reconcile_required_delivery_uncertain",
            message: message.into(),
        }
    }
    /// Build a state-handled dispatch failure.
    ///
    /// Inputs: `message` — operator-facing failure description. Output: [`Self`]
    /// with `DispatchFailureKind::StateHandled` and the stable
    /// `dispatch_state_handled` code.
    fn handled(message: impl Into<String>) -> Self {
        Self {
            kind: DispatchFailureKind::StateHandled,
            code: "dispatch_state_handled",
            message: message.into(),
        }
    }
    /// Build a state-handled dispatch failure with an explicit code.
    ///
    /// Inputs: `code` — stable failure code; `message` — operator-facing failure
    /// description. Output: [`Self`] with `DispatchFailureKind::StateHandled` and
    /// the given code.
    fn handled_code(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind: DispatchFailureKind::StateHandled,
            code,
            message: message.into(),
        }
    }
    /// The stable operation code for this dispatch failure.
    ///
    /// Inputs: none beyond the failure. Output: `&'static str` operation code.
    pub(crate) fn operation_code(&self) -> &'static str {
        self.code
    }
    /// Whether the operator may retry this dispatch failure.
    ///
    /// Inputs: none beyond the failure. Output: `true` only for the retryable
    /// kind.
    pub(crate) fn retryable_for_operator(&self) -> bool {
        self.kind == DispatchFailureKind::Retryable
    }
}
impl std::fmt::Display for DispatchFailure {
    /// Render the failure as its operator-facing message.
    ///
    /// Inputs: `f` — formatter to write into. Output: [`std::fmt::Result`] — writes
    /// `self.message` only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for DispatchFailure {}

/// Turn one dispatch precondition into the typed failure.
///
/// Inputs: `condition` — invariant that must hold; `kind` — failure kind
/// assigned when it does not; `message` — operator-facing failure description.
/// Output: `Ok(())` when the condition holds, else a [`DispatchFailure`]
/// carrying the kind and message.
fn dispatch_require(
    condition: bool,
    kind: DispatchFailureKind,
    message: impl Into<String>,
) -> std::result::Result<(), DispatchFailure> {
    if condition {
        Ok(())
    } else {
        let message = message.into();
        Err(match kind {
            DispatchFailureKind::Retryable => DispatchFailure::retryable(message),
            DispatchFailureKind::ReviewRequired => DispatchFailure::review(message),
            DispatchFailureKind::ReconcileRequired => DispatchFailure::reconcile(message),
            DispatchFailureKind::StateHandled => DispatchFailure::handled(message),
        })
    }
}

/// Refuse an Automatic dispatch when the local model changed since analysis.
///
/// Inputs: `runtime_digest` — digest of the model currently loaded in the
/// local runtime; `analyzed_digest` — digest recorded with the job's analysis.
/// Output: `Ok(())` while the digests match; a review-required
/// [`DispatchFailure`] naming the drift otherwise.
fn require_analysis_model_current(
    runtime_digest: &str,
    analyzed_digest: &str,
) -> std::result::Result<(), DispatchFailure> {
    dispatch_require(
        runtime_digest == analyzed_digest,
        DispatchFailureKind::ReviewRequired,
        "Model changed since analysis",
    )
}

/// Refuse dispatch when durable send state cannot be written safely.
///
/// Inputs: `storage` — measured runtime-write headroom. Output: `Ok(())` while
/// `runtime_write_safe` holds; a retryable [`DispatchFailure`] otherwise, so
/// the dispatch can be retried when headroom recovers.
fn require_runtime_write_safe(
    storage: &crate::storage::StorageHealth,
) -> std::result::Result<(), DispatchFailure> {
    dispatch_require(
        storage.runtime_write_safe,
        DispatchFailureKind::Retryable,
        "Storage headroom is too low for durable send state",
    )
}

/// Presentation-independent inputs for the send gate.
///
/// Each interface (desktop, terminal, web) collects these from its own state
/// and hands them to [`send_gate_eligible`]; no interface reimplements the
/// decision.
pub struct SendGateContext<'a> {
    /// Visible reply text currently shown to the user.
    pub editor_text: &'a str,
    /// Whether the editor is bound to the job's id and revision.
    pub editor_bound: bool,
    /// Whether the editor holds unsaved changes.
    pub dirty: bool,
    /// Mail-level sending blocks that apply to the original message.
    pub hard_blocks: &'a [String],
    /// Whether background work is currently in flight.
    pub busy: bool,
    /// Whether sending has been explicitly enabled in settings.
    pub sending_enabled: bool,
    /// Whether the workspace runs in demonstration mode.
    pub demo: bool,
    /// Whether the background worker is paused.
    pub paused: bool,
}

/// Whether the visible reply is the exact persisted draft for this job.
///
/// Inputs: `job` — candidate job; `text` — visible editor text. Output:
/// `true` only when the job has a persisted draft and `text` equals it byte
/// for byte; any edit disqualifies the candidate (the confirm-exact-reply
/// rule).
pub fn visible_draft_matches(job: &Job, text: &str) -> bool {
    job.draft.as_ref().is_some_and(|d| d.body == text)
}

/// Whether an editor is bound to this job's identity and revision.
///
/// Inputs: `job` — candidate job; `key` — `(id, revision)` the editor was
/// loaded for. Output: `true` only for the exact pair, so stale editors can
/// never act on a newer revision or a different message.
pub fn editor_binding_matches(job: &Job, key: Option<&(String, u64)>) -> bool {
    key.is_some_and(|(id, revision)| id == &job.id && *revision == job.revision)
}

/// Whether a job is a valid send candidate in the current runtime state.
///
/// Inputs: `job` — candidate job; `ctx` — presentation-independent state.
/// Output: `true` only when every gate passes: the job is reviewable, the
/// editor is bound and clean and shows the exact persisted draft, no mail
/// hard blocks apply, nothing is busy, sending is enabled, and the session
/// is neither in demo mode nor paused.
pub fn send_gate_eligible(job: &Job, ctx: &SendGateContext<'_>) -> bool {
    job.state.reviewable()
        && ctx.editor_bound
        && !ctx.dirty
        && visible_draft_matches(job, ctx.editor_text)
        && ctx.hard_blocks.is_empty()
        && !ctx.busy
        && ctx.sending_enabled
        && !ctx.demo
        && !ctx.paused
}

/// Owned engine state: store, settings, account, models and session leases.
///
/// Inputs: none (plain struct). Output: the surface every command executes
/// against — the database, mail transport, loaded enterprise policy and
/// workspace directory.
pub struct Engine {
    /// Open workspace store.
    pub db: Store,
    /// Current workspace settings.
    pub settings: Settings,
    /// Workspace account key.
    pub account: String,
    /// Status of the primary local model.
    pub model: ModelStatus,
    /// Status of the verifier local model.
    pub verifier_model: ModelStatus,
    /// Whether the engine runs in demo mode.
    pub demo: bool,
    /// Shared pause flag honored by dispatch.
    pub paused: Arc<AtomicBool>,
    /// Shared stop flag honored by dispatch.
    pub stop: Arc<AtomicBool>,
    /// Currently loaded enterprise policy, when one is active.
    pub enterprise_policy: Option<LoadedPolicy>,
    mail: Option<Box<dyn MailTransport>>,
    _lock: InstanceLock,
    _session: SessionLease,
    _temporary: Option<tempfile::TempDir>,
    /// Workspace directory backing the store and vault.
    pub directory: PathBuf,
}
/// Disarm delivery settings after an unclean shutdown.
///
/// Inputs: `settings` — settings mutated in place; `unclean` — whether the
/// previous session ended uncleanly. Output: `true` when the disarm changed
/// `settings` and the caller must persist; `false` when the session was clean
/// or nothing changed.
fn disarm_after_unclean_session(settings: &mut Settings, unclean: bool) -> bool {
    if !unclean {
        return false;
    }
    let before = settings.clone();
    settings.disarm_delivery();
    *settings != before
}

/// Observe the loaded enterprise policy against the persisted revision floor.
///
/// Inputs: `db` — state store holding the `enterprise_policy_revision_floor`
/// meta value; `loaded` — the policy currently loaded, if any. Output:
/// `Result<(Option<PolicyRevisionFloor>, bool)>` — the observed floor and
/// whether observing changed it; `(None, false)` without a loaded policy or for
/// policy version 1.
fn staged_policy_revision_floor(
    db: &Store,
    loaded: Option<&LoadedPolicy>,
) -> Result<(Option<PolicyRevisionFloor>, bool)> {
    let Some(loaded) = loaded else {
        return Ok((None, false));
    };
    if loaded.policy.version < 2 {
        return Ok((None, false));
    }
    let mut floor: PolicyRevisionFloor = db
        .meta("enterprise_policy_revision_floor")?
        .unwrap_or_default();
    let changed = floor.observe(loaded)?;
    Ok((Some(floor), changed))
}

/// Resolve the workspace directory and open its exclusive session state.
///
/// Inputs: `directory` — workspace directory (replaced by a temporary
/// directory in demo mode); `demo` — whether demo mode is active. Output:
/// `Result<(Option<TempDir>, PathBuf, InstanceLock, SessionLease>, bool, Store)>`
/// — the temporary holder, resolved directory, exclusive lock, session lease,
/// prior-session cleanliness flag and the opened store.
fn open_workspace(
    directory: PathBuf,
    demo: bool,
) -> Result<(
    Option<tempfile::TempDir>,
    PathBuf,
    InstanceLock,
    SessionLease,
    bool,
    Store,
)> {
    let temporary = if demo {
        Some(tempfile::tempdir()?)
    } else {
        None
    };
    let directory = temporary
        .as_ref()
        .map_or(directory, |p| p.path().to_path_buf());
    let lock = InstanceLock::acquire(&directory)?;
    let session = SessionLease::begin(&directory)?;
    let previous_unclean_session = session.previous_unclean();
    let vault = if demo {
        let identity_written = write_new_private(
            &directory.join("vault-id"),
            uuid::Uuid::new_v4().to_string().as_bytes(),
        );
        identity_written?;
        Vault::random()
    } else {
        Vault::open(&directory)?
    };
    let db = Store::open(&directory.join("state.sqlite3"), vault)?;
    Ok((
        temporary,
        directory,
        lock,
        session,
        previous_unclean_session,
        db,
    ))
}

/// Resolve the recovery and managed-policy context for an engine open.
///
/// Inputs: `directory` — workspace directory; `demo` — whether demo mode is
/// active. Output: `Result<(bool, Option<LoadedPolicy>)>` — whether an offline
/// restore requires rearming and the managed policy, if one is loaded.
fn open_policy_context(directory: &Path, demo: bool) -> Result<(bool, Option<LoadedPolicy>)> {
    let restored_workspace = !demo && recovery::restore_rearm_required(directory)?;
    let enterprise_policy = if demo { None } else { policy::load_optional()? };
    Ok((restored_workspace, enterprise_policy))
}

/// Verify independently persisted rollback evidence at engine open.
///
/// Inputs: `db` — opened store; `directory` — workspace directory;
/// `enterprise_policy` — managed policy, if one was loaded; `demo` — whether
/// demo mode is active. Output: `Result<()>` — `Ok` when the configured
/// anchors satisfy policy; error otherwise.
fn verify_bootstrap_audit_anchor(
    db: &Store,
    directory: &Path,
    enterprise_policy: &Option<LoadedPolicy>,
    demo: bool,
) -> Result<()> {
    if !demo {
        let external_anchor = audit_anchor::verify_configured_anchor(db, directory)?;
        let os_anchor_mode = audit_anchor::os_anchor_required()?;
        audit_anchor::verify_os_anchor_if_required(db, directory)?;
        if enterprise_policy
            .as_ref()
            .is_some_and(|loaded| loaded.policy.require_external_audit_anchor)
        {
            ensure!(
                external_anchor.is_some() || os_anchor_mode,
                "Enterprise policy requires independently protected audit anchoring: configure RR_AUDIT_ANCHOR_FILE or RR_OS_AUDIT_ANCHOR=required"
            );
        }
    }
    Ok(())
}

/// Recover interrupted sends and settle the settings that gate unattended
/// delivery at engine open.
///
/// Inputs: `db` — opened store; `enterprise_policy` — managed policy, if one
/// was loaded; `previous_unclean_session` — whether the previous session ended
/// uncleanly; `restored_workspace` — whether an offline restore was detected;
/// `demo` — whether demo mode is active. Output: `Result<Settings>` — the
/// settled settings; any staged change is persisted as one commit.
fn prepare_open_settings(
    db: &mut Store,
    enterprise_policy: &Option<LoadedPolicy>,
    previous_unclean_session: bool,
    restored_workspace: bool,
    demo: bool,
) -> Result<Settings> {
    db.recover_interrupted_sends()?;
    let mut settings: Settings = db.meta("settings")?.unwrap_or_default();
    let settings_migrated = settings.migrate_format()?;
    let repaired = settings.repair_legacy_automatic_state();
    let crash_disarmed =
        disarm_after_unclean_session(&mut settings, previous_unclean_session && !demo);
    let restore_disarmed = disarm_after_unclean_session(&mut settings, restored_workspace);
    let (revision_floor, revision_floor_changed) =
        staged_policy_revision_floor(db, enterprise_policy.as_ref())?;
    let policy_changed = match &enterprise_policy {
        Some(loaded) => loaded.policy.enforce(&mut settings, true)?,
        None => false,
    };
    settings.validate()?;
    persist_staged_settings(
        db,
        &settings,
        enterprise_policy,
        &revision_floor,
        revision_floor_changed,
        settings_migrated,
        repaired,
        crash_disarmed,
        restore_disarmed,
        policy_changed,
    )?;
    Ok(settings)
}

/// Persist the staged settings change and its audit event as one commit.
///
/// Inputs: `db` — opened store; `settings` — settled settings;
/// `enterprise_policy` — managed policy, if one was loaded; `revision_floor` —
/// staged policy revision floor; `revision_floor_changed` — whether the floor
/// changed; `settings_migrated` — settings format was migrated; `repaired` —
/// legacy Automatic state was repaired; `crash_disarmed` — unclean-session
/// disarm applied; `restore_disarmed` — restore disarm applied;
/// `policy_changed` — enterprise policy constrained settings. Output:
/// `Result<()>` — `Ok` once committed (a no-op when nothing changed).
#[allow(clippy::too_many_arguments)]
fn persist_staged_settings(
    db: &mut Store,
    settings: &Settings,
    enterprise_policy: &Option<LoadedPolicy>,
    revision_floor: &Option<PolicyRevisionFloor>,
    revision_floor_changed: bool,
    settings_migrated: bool,
    repaired: bool,
    crash_disarmed: bool,
    restore_disarmed: bool,
    policy_changed: bool,
) -> Result<()> {
    if settings_migrated
        || repaired
        || crash_disarmed
        || restore_disarmed
        || policy_changed
        || revision_floor_changed
    {
        let upserts = staged_settings_upserts(settings, revision_floor, revision_floor_changed)?;
        let detail = staged_settings_detail(
            enterprise_policy,
            revision_floor_changed,
            settings_migrated,
            restore_disarmed,
            crash_disarmed,
            policy_changed,
        )?;
        let persisted = db.change_meta(
            &upserts,
            &[],
            if revision_floor_changed {
                "policy.accepted"
            } else if settings_migrated {
                "settings.migrated"
            } else {
                "settings.repaired"
            },
            &detail,
        );
        persisted?;
    }
    Ok(())
}

/// Build the metadata upserts for a staged settings change.
///
/// Inputs: `settings` — settled settings; `revision_floor` — staged policy
/// revision floor; `revision_floor_changed` — whether the floor changed.
/// Output: `Result<Vec<(&str, serde_json::Value)>>` — the metadata writes that
/// commit with the change.
fn staged_settings_upserts(
    settings: &Settings,
    revision_floor: &Option<PolicyRevisionFloor>,
    revision_floor_changed: bool,
) -> Result<Vec<(&'static str, serde_json::Value)>> {
    let mut upserts = vec![("settings", serde_json::to_value(settings)?)];
    if revision_floor_changed {
        let staged = revision_floor
            .as_ref()
            .context("Policy revision floor staging was lost")?;
        let staged = serde_json::to_value(staged)?;
        upserts.push(("enterprise_policy_revision_floor", staged));
    }
    Ok(upserts)
}

/// Build the audit detail for a staged settings change.
///
/// Inputs: `enterprise_policy` — managed policy, if one was loaded;
/// `revision_floor_changed` — whether the floor changed; `settings_migrated` —
/// settings format was migrated; `restore_disarmed` — restore disarm applied;
/// `crash_disarmed` — unclean-session disarm applied; `policy_changed` —
/// enterprise policy constrained settings. Output: `Result<String>` — the
/// operator-facing audit detail.
fn staged_settings_detail(
    enterprise_policy: &Option<LoadedPolicy>,
    revision_floor_changed: bool,
    settings_migrated: bool,
    restore_disarmed: bool,
    crash_disarmed: bool,
    policy_changed: bool,
) -> Result<String> {
    let detail = if revision_floor_changed {
        let loaded = enterprise_policy
            .as_ref()
            .context("Policy revision floor changed without active policy")?;
        format!(
            "Enterprise policy accepted fail-closed: policy_id={} revision={} sha256={}; persisted settings and rollback floor committed together",
            loaded.policy.policy_id.as_deref().unwrap_or("<missing>"),
            loaded.policy.revision.unwrap_or_default(),
            loaded.digest
        )
    } else if settings_migrated {
        "Encrypted settings migrated from format v1 to v2; prior task qualification was invalidated and unattended delivery was disabled".into()
    } else if restore_disarmed {
        "Restored workspace was opened with sending and Automatic mode disabled; explicit authorization is required".into()
    } else if crash_disarmed {
        "Previous runtime session ended uncleanly; unattended delivery was disabled fail-closed"
            .into()
    } else if policy_changed {
        "Persisted settings were constrained by enterprise policy and unattended delivery was revalidated fail-closed".into()
    } else {
        "Legacy Automatic mode without current qualification was disabled fail-closed".into()
    };
    Ok(detail)
}

/// Log the security events for restored or uncleanly closed workspaces.
///
/// Inputs: `db` — opened store; `directory` — workspace directory;
/// `restored_workspace` — whether an offline restore was detected;
/// `previous_unclean_session` — whether the previous session ended uncleanly;
/// `demo` — whether demo mode is active. Output: `Result<()>` — `Ok` once the
/// events are written.
fn log_open_security_events(
    db: &mut Store,
    directory: &Path,
    restored_workspace: bool,
    previous_unclean_session: bool,
    demo: bool,
) -> Result<()> {
    if restored_workspace {
        let logged = db.log(
                "security.restore_rearm_required",
                None,
                "Offline backup restore detected; sending and Automatic mode disabled until explicitly reauthorized",
            );
        logged?;
        recovery::clear_restore_rearm_marker(directory)?;
    }
    if previous_unclean_session && !demo {
        let logged = db.log(
                "security.unclean_shutdown_detected",
                None,
                "Previous runtime session marker remained after exclusive workspace lock acquisition; unattended delivery is disabled until explicitly re-enabled",
            );
        logged?;
    }
    Ok(())
}

/// Load the account and provider credentials staged at engine open.
///
/// Inputs: `db` — opened store; `settings` — settled settings. Output:
/// `Result<(String, Option<Credentials>, Option<AppPasswordCredentials>)>` —
/// the account key and the provider credentials, if any.
fn load_open_account_state(
    db: &mut Store,
    settings: &Settings,
) -> Result<(String, Option<Credentials>, Option<AppPasswordCredentials>)> {
    let creds: Option<Credentials> = db.meta("google_credentials")?;
    let app_creds: Option<AppPasswordCredentials> = db.meta("app_password_credentials")?;
    let account = db.meta::<String>("account")?.unwrap_or_default();
    if !account.is_empty() {
        let now = Utc::now();
        db.defer_review_outside_window(&account, settings.cutoff(now), now)?;
    }
    Ok((account, creds, app_creds))
}

impl Engine {
    /// Open (or create) the workspace engine.
    ///
    /// Inputs: `directory` — workspace directory; `demo` — whether demo mode is
    /// active (data lives in a temporary directory and never touches real
    /// accounts); `paused` — fail-closed worker pause flag; `stop` — shutdown
    /// flag. Output: `Result<Self>` — the ready engine; errors when the workspace
    /// cannot be opened.
    pub fn open(
        directory: PathBuf,
        demo: bool,
        paused: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self> {
        let (temporary, directory, lock, session, previous_unclean_session, mut db) =
            open_workspace(directory, demo)?;
        let (restored_workspace, enterprise_policy) = open_policy_context(&directory, demo)?;
        // Verify independently persisted rollback evidence before any runtime
        // recovery event mutates the workspace audit journal. Managed policy may
        // make the external anchor mandatory.
        verify_bootstrap_audit_anchor(&db, &directory, &enterprise_policy, demo)?;
        let settings = prepare_open_settings(
            &mut db,
            &enterprise_policy,
            previous_unclean_session,
            restored_workspace,
            demo,
        )?;
        log_open_security_events(
            &mut db,
            &directory,
            restored_workspace,
            previous_unclean_session,
            demo,
        )?;
        let (account, creds, app_creds) = load_open_account_state(&mut db, &settings)?;
        let mut e = Self {
            db,
            settings,
            account,
            model: ModelStatus::default(),
            verifier_model: ModelStatus::default(),
            demo,
            paused,
            stop,
            enterprise_policy,
            mail: creds.map(Self::provider_client).or_else(|| {
                app_creds.map(|ac| {
                    Box::new(ImapSmtp::new(ac, ImapSmtpConfig::default())) as Box<dyn MailTransport>
                })
            }),
            _lock: lock,
            _session: session,
            _temporary: temporary,
            directory,
        };
        if demo {
            e.seed_demo()?;
        } else {
            audit_anchor::checkpoint_os_anchor_if_required(&e.db, &e.directory)?;
        }
        Ok(e)
    }

    /// Advance independently protected audit evidence after an operation boundary.
    /// This is a no-op unless RR_OS_AUDIT_ANCHOR=required is explicitly configured.
    ///
    /// Inputs: none beyond the engine. Output: `Ok(())` after the checkpoint (a
    /// no-op unless the anchor is required).
    pub fn checkpoint_audit_protection(&self) -> Result<()> {
        if !self.demo {
            audit_anchor::checkpoint_os_anchor_if_required(&self.db, &self.directory)?;
        }
        Ok(())
    }

    /// Whether a mailbox provider is connected.
    ///
    /// Inputs: none beyond the engine. Output: `true` while provider credentials
    /// are attached.
    pub fn connected(&self) -> bool {
        self.mail.is_some()
    }
    /// Whether the connected provider may send.
    ///
    /// Inputs: none beyond the engine. Output: `true` only when a connected
    /// provider holds send scope.
    pub fn send_scope(&self) -> bool {
        self.mail.as_ref().is_some_and(|m| m.can_send())
    }
    /// Test-only: publish a provider client into the engine without OAuth so
    /// dispatch orchestration can run against `Gmail::with_endpoints` mocks.
    ///
    /// Inputs: `gmail` — provider client to publish. Output: none.
    #[cfg(test)]
    pub(crate) fn attach_gmail_for_tests(&mut self, gmail: Gmail) {
        self.mail = Some(Box::new(gmail));
    }
    /// The effective enterprise-policy status.
    ///
    /// Inputs: none beyond the engine. Output: [`PolicyStatus`] for the loaded
    /// policy, or the inactive status when none is loaded.
    pub fn enterprise_policy_status(&self) -> PolicyStatus {
        self.enterprise_policy
            .as_ref()
            .map_or_else(policy::inactive_status, LoadedPolicy::status)
    }

    /// Reload the optional machine-wide policy and apply only restrictive
    /// changes automatically. Removing or relaxing policy never silently enables
    /// capabilities; users must still opt in through normal settings.
    ///
    /// Inputs: none beyond the engine. Output: `Result<bool>` — `true` when the
    /// loaded policy changed.
    pub fn reload_enterprise_policy(&mut self) -> Result<bool> {
        if self.demo {
            return Ok(false);
        }
        let loaded = policy::load_optional()?;
        let external_anchor = audit_anchor::verify_configured_anchor(&self.db, &self.directory)?;
        let os_anchor_mode = audit_anchor::os_anchor_required()?;
        audit_anchor::verify_os_anchor_if_required(&self.db, &self.directory)?;
        if loaded
            .as_ref()
            .is_some_and(|current| current.policy.require_external_audit_anchor)
        {
            ensure!(
                external_anchor.is_some() || os_anchor_mode,
                "Enterprise policy requires independently protected audit anchoring: configure RR_AUDIT_ANCHOR_FILE or RR_OS_AUDIT_ANCHOR=required"
            );
        }
        let old_digest = self
            .enterprise_policy
            .as_ref()
            .map(|current| current.digest.as_str());
        let new_digest = loaded.as_ref().map(|current| current.digest.as_str());
        if old_digest == new_digest {
            return Ok(false);
        }

        let (revision_floor, revision_floor_changed) =
            staged_policy_revision_floor(&self.db, loaded.as_ref())?;
        let mut settings = self.settings.clone();
        let settings_changed = match &loaded {
            Some(current) => current.policy.enforce(&mut settings, true)?,
            None => false,
        };
        settings.validate()?;
        let detail = match &loaded {
            Some(current) => format!(
                "Enterprise policy reloaded; sha256={}{}",
                current.digest,
                if settings_changed {
                    "; persisted settings were restricted"
                } else {
                    ""
                }
            ),
            None => "Enterprise policy removed; existing restrictive settings were not relaxed automatically".into(),
        };
        let mut upserts = Vec::new();
        if settings_changed {
            upserts.push(("settings", serde_json::to_value(&settings)?));
        }
        if revision_floor_changed {
            let staged = revision_floor
                .as_ref()
                .context("Policy revision floor staging was lost")?;
            let staged = serde_json::to_value(staged)?;
            upserts.push(("enterprise_policy_revision_floor", staged));
        }
        if !upserts.is_empty() {
            self.db
                .change_meta(&upserts, &[], "policy.reloaded", &detail)?;
        } else {
            self.db.log("policy.reloaded", None, &detail)?;
        }
        if settings_changed {
            self.settings = settings;
            self.model = ModelStatus::default();
            self.verifier_model = ModelStatus::default();
        }
        self.enterprise_policy = loaded;
        Ok(true)
    }
    /// Build the provider client for persisted credentials.
    ///
    /// Inputs: `credentials` — decrypted OAuth material. Output: a client
    /// bound to the Gmail API. Test seam: threads under test adopt mock
    /// endpoints through `crate::test_support`, so worker-driven provider
    /// flows run deterministically without Google.
    fn provider_client(credentials: Credentials) -> Box<dyn MailTransport> {
        #[cfg(test)]
        if let Some((root, token_url)) = crate::test_support::gmail_endpoints() {
            return Box::new(Gmail::with_endpoints(credentials, &root, &token_url));
        }
        Box::new(Gmail::new(credentials))
    }
    /// Obtain OAuth credentials and a provider client for [`Self::connect`].
    ///
    /// Inputs: `path` — Google Desktop-app OAuth JSON; `send` — whether the
    /// send scope is requested; `stop` — cooperative cancellation flag.
    /// Output: the credentials to persist plus a client bound to them. Test
    /// seam: threads under test arm canned credentials and mock endpoints in
    /// `crate::test_support`, so the whole connection flow runs without a
    /// browser or Google.
    fn login_client(
        path: &Path,
        send: bool,
        stop: &AtomicBool,
    ) -> Result<(Credentials, Box<dyn MailTransport>)> {
        #[cfg(test)]
        if let Some((creds, root, token_url)) = crate::test_support::login_override() {
            return Ok((
                creds.clone(),
                Box::new(Gmail::with_endpoints(creds, &root, &token_url)),
            ));
        }
        let credentials = oauth::login(path, send, stop)?;
        let gmail = Box::new(Gmail::new(credentials.clone()));
        Ok((credentials, gmail))
    }
    /// Connect a mailbox provider for this workspace.
    ///
    /// Inputs: `path` — OAuth credentials file to load; `send` — whether send
    /// scope is requested. Output: `Ok(())` once connected; demo mode, enterprise
    /// policy and the provider can each refuse.
    pub fn connect(&mut self, path: &Path, send: bool) -> Result<()> {
        ensure!(!self.demo, "Demo mode never connects to a real mailbox");
        ensure!(
            !send
                || self
                    .enterprise_policy
                    .as_ref()
                    .is_none_or(|loaded| loaded.policy.allows_send_scope()),
            "Enterprise policy prohibits requesting Gmail send permission"
        );
        let (credentials, mut gmail) = Self::login_client(path, send, &self.stop)?;
        let profile = gmail.profile()?;
        let account = mail::mailbox(&profile.email_address)?;
        // Fail closed during an account switch. Persist the complete connection
        // state and audit event together before publishing it to the in-memory engine.
        let mut settings = self.settings.clone();
        settings.disarm_delivery();
        let connected = self.db.change_meta(
            &[
                ("settings", serde_json::to_value(&settings)?),
                ("google_credentials", serde_json::to_value(&credentials)?),
                ("account", serde_json::to_value(&account)?),
            ],
            &[],
            "account.connected",
            "Google credentials encrypted locally; sending remains disabled",
        );
        connected?;
        self.settings = settings;
        self.account = account;
        self.mail = Some(gmail);
        Ok(())
    }

    /// Connect a mailbox via Gmail app-password (IMAP/SMTP basic auth).
    ///
    /// Inputs: `creds` — the mailbox address + Google app password (zeroized on
    /// drop). Output: `Ok(())` once connected; demo mode, enterprise policy
    /// and the provider can each refuse. The app password is persisted only in
    /// the encrypted store (never logged) and sending stays disabled until
    /// separately armed.
    pub fn connect_app_password(&mut self, creds: AppPasswordCredentials) -> Result<()> {
        ensure!(!self.demo, "Demo mode never connects to a real mailbox");
        let stored = serde_json::to_value(&creds)?;
        let mut imap = ImapSmtp::new(creds, ImapSmtpConfig::default());
        let profile = imap.profile()?;
        let account = mail::mailbox(&profile.email_address)?;
        let mut settings = self.settings.clone();
        settings.disarm_delivery();
        let connected = self.db.change_meta(
            &[
                ("settings", serde_json::to_value(&settings)?),
                ("app_password_credentials", stored),
                ("account", serde_json::to_value(&account)?),
            ],
            &[],
            "account.connected",
            "App-password credentials encrypted locally; sending remains disabled",
        );
        connected?;
        self.settings = settings;
        self.account = account;
        self.mail = Some(Box::new(imap));
        Ok(())
    }

    /// Disconnect the provider and disarm delivery.
    ///
    /// Inputs: none beyond the engine. Output: `Ok(())`; stored credentials and
    /// account identity are removed and delivery is disarmed.
    pub fn disconnect(&mut self) -> Result<()> {
        let mut settings = self.settings.clone();
        settings.disarm_delivery();
        let disconnected = self.db.change_meta(
            &[("settings", serde_json::to_value(&settings)?)],
            &["google_credentials", "app_password_credentials", "account"],
            "account.disconnected",
            "Local credentials removed; revoke Google consent separately if desired",
        );
        disconnected?;
        self.settings = settings;
        self.mail = None;
        self.account.clear();
        Ok(())
    }
    /// Validate and persist new settings under policy constraints.
    ///
    /// Inputs: `settings` — candidate settings. Output: `Ok(())` once accepted and
    /// persisted; demo mode and enterprise policy can refuse the change.
    pub fn update_settings(&mut self, mut settings: Settings) -> Result<()> {
        ensure!(
            !self.demo || !settings.sending_enabled,
            "Demo can never enable sending"
        );
        if let Some(policy) = &self.enterprise_policy {
            policy.policy.enforce(&mut settings, false)?;
        }
        ensure!(
            !settings.api_allow_writes,
            "Current integration API is read-only; write operations are not exposed"
        );
        if settings.mode == Mode::Automatic && self.settings.mode != Mode::Automatic {
            settings.automatic_since = Some(Utc::now());
        }
        if settings.mode == Mode::HumanReview {
            settings.automatic_confirmed = false;
        }
        let model_configuration_changed = settings.model != self.settings.model
            || settings.num_ctx != self.settings.num_ctx
            || settings.ollama_url != self.settings.ollama_url;
        let verifier_configuration_changed = settings.verifier_model
            != self.settings.verifier_model
            || settings.independent_verifier_enabled != self.settings.independent_verifier_enabled
            || settings.num_ctx != self.settings.num_ctx
            || settings.ollama_url != self.settings.ollama_url;
        if model_configuration_changed {
            settings.model_digest = None;
            self.model = ModelStatus::default();
        } else {
            settings
                .model_digest
                .clone_from(&self.settings.model_digest);
        }
        if verifier_configuration_changed {
            settings.verifier_model_digest = None;
            self.verifier_model = ModelStatus::default();
        } else {
            settings
                .verifier_model_digest
                .clone_from(&self.settings.verifier_model_digest);
        }
        let task_context_changed =
            settings_context_hash(&settings) != settings_context_hash(&self.settings);
        if model_configuration_changed || verifier_configuration_changed || task_context_changed {
            settings.task_qualification = None;
            settings.disarm_delivery();
        } else {
            settings
                .task_qualification
                .clone_from(&self.settings.task_qualification);
        }
        settings.validate()?;
        ensure!(
            !settings.sending_enabled || self.send_scope(),
            "Reconnect Gmail with send permission before enabling delivery"
        );
        let tightened_window = settings.lookback_days < self.settings.lookback_days;
        self.db.set_meta("settings", &settings)?;
        self.settings = settings;
        if tightened_window && !self.account.is_empty() {
            let now = Utc::now();
            self.db
                .defer_review_outside_window(&self.account, self.settings.cutoff(now), now)?;
        }
        let logged = self.db.log(
            "settings.changed",
            None,
            "Settings updated; mode, age window and send gates revalidated",
        );
        logged?;
        Ok(())
    }
    /// Run task qualification for the decision model.
    ///
    /// Inputs: none beyond the engine. Output: `Result<()>` — the qualified digest
    /// and status are recorded; errors when qualification fails.
    pub fn qualify(&mut self) -> Result<()> {
        let mut unpinned = self.settings.clone();
        unpinned.disarm_delivery();
        unpinned.model_digest = None;
        unpinned.task_qualification = None;
        let status = Ollama::new(&unpinned)?.qualify()?;
        self.settings.disarm_delivery();
        self.settings.model_digest = Some(status.digest.clone());
        self.settings.task_qualification = None;
        self.db.set_meta("settings", &self.settings)?;
        self.model = status;
        let logged = self.db.log(
            "model.qualified",
            None,
            "Smoke test and Ollama residency check passed; model digest pinned. Automatic mode remains disarmed until the task-specific evaluation passes.",
        );
        logged?;
        Ok(())
    }
    /// Qualify and pin the verifier model.
    ///
    /// Inputs: none beyond the engine. Output: `Result<()>` — the pinned verifier
    /// digest is persisted and any previous task qualification is reset.
    pub fn qualify_verifier(&mut self) -> Result<()> {
        let status = Ollama::new(&self.settings)?.qualify_verifier()?;
        self.settings.disarm_delivery();
        self.settings.verifier_model_digest = Some(status.digest.clone());
        self.settings.task_qualification = None;
        self.db.set_meta("settings", &self.settings)?;
        self.verifier_model = status;
        let logged = self.db.log(
            "model.verifier_qualified",
            None,
            "Independent verifier smoke test and GPU residency passed; verifier digest pinned. Automatic mode remains disarmed until the full task evaluation passes.",
        );
        logged?;
        Ok(())
    }

    /// Inspect the local verifier model and record its status.
    ///
    /// Inputs: none beyond the engine. Output: `Result<()>`; a digest that
    /// contradicts the pin fails closed.
    pub fn inspect_verifier_model_status(&mut self) -> Result<()> {
        let local = Ollama::new(&self.settings)?;
        let mut status = local.inspect_verifier()?;
        if let Some(pin) = &self.settings.verifier_model_digest {
            let expected = pin.trim_start_matches("sha256:");
            let actual = status.digest.trim_start_matches("sha256:");
            if expected != actual {
                status.gpu_resident = false;
                status.message =
                    "Installed verifier digest differs from the qualified pin; qualify again"
                        .into();
            } else {
                let mut verifier_settings = self.settings.clone();
                verifier_settings.disarm_delivery();
                verifier_settings.task_qualification = None;
                verifier_settings
                    .model
                    .clone_from(&verifier_settings.verifier_model);
                verifier_settings.model_digest = Some(pin.clone());
                verifier_settings.independent_verifier_enabled = false;
                match Ollama::new(&verifier_settings)?.residency(&status.digest) {
                    Ok(resident) => status = resident,
                    Err(error) => {
                        status.gpu_resident = false;
                        status.message = format!(
                            "Pinned verifier is installed but not currently confirmed GPU-resident: {error}"
                        );
                    }
                }
            }
        }
        self.verifier_model = status;
        Ok(())
    }

    /// Compact the workspace database.
    ///
    /// Inputs: none beyond the engine. Output: `Result<DatabaseCompactionReport>`
    /// — storage statistics before and after; refused in demo mode.
    pub fn compact_database(&mut self) -> Result<crate::store::DatabaseCompactionReport> {
        ensure!(
            !self.demo,
            "Synthetic demo mode does not compact a real workspace"
        );
        let storage = crate::storage::inspect(&self.directory)?;
        ensure!(
            storage.backup_safe,
            "Database compaction requires the same conservative free-space headroom as backup creation"
        );
        let report = self.db.compact()?;
        self.checkpoint_audit_protection()?;
        Ok(report)
    }

    /// Inspect the local decision model and record its status.
    ///
    /// Inputs: none beyond the engine. Output: `Result<()>`; a digest that
    /// contradicts the pin fails closed.
    pub fn inspect_model_status(&mut self) -> Result<()> {
        let mut unpinned = self.settings.clone();
        unpinned.model_digest = None;
        let local = Ollama::new(&unpinned)?;
        let mut status = local.inspect()?;
        if let Some(pin) = &self.settings.model_digest {
            let expected = pin.trim_start_matches("sha256:");
            let actual = status.digest.trim_start_matches("sha256:");
            if expected != actual {
                status.gpu_resident = false;
                status.message =
                    "Installed model digest differs from the qualified pin; qualify again".into();
            } else {
                match local.residency(&status.digest) {
                    Ok(resident) => status = resident,
                    Err(error) => {
                        status.gpu_resident = false;
                        status.message = format!(
                            "Pinned model is installed but not currently confirmed GPU-resident: {error}"
                        );
                    }
                }
            }
        }
        self.model = status;
        Ok(())
    }

    /// Evaluate the configured model to a timestamped report.
    ///
    /// Inputs: none beyond the engine. Output: `Result<PathBuf>` — the report file
    /// written; refused in demo mode.
    pub fn evaluate_model(&mut self) -> Result<PathBuf> {
        ensure!(
            !self.demo,
            "Synthetic demo mode does not run the configured model"
        );
        let stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let path = self
            .directory
            .join(format!("model-evaluation-{stamp}.json"));
        self.evaluate_model_to(&path)?;
        Ok(path)
    }

    /// Evaluate the configured model to a chosen path.
    ///
    /// Inputs: `path` — destination report file. Output: `Result<()>` once the
    /// report is written; refused in demo mode.
    pub fn evaluate_model_to(&mut self, path: &Path) -> Result<()> {
        ensure!(
            !self.demo,
            "Synthetic demo mode does not run the configured model"
        );
        let report = evaluation::run(&self.settings, path)?;
        let eligible = report
            .pointer("/summary/recommendation_eligible")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let digest = report
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .context("Evaluation report is missing model digest")?
            .to_owned();
        let report_model = report
            .get("model")
            .and_then(serde_json::Value::as_str)
            .context("Evaluation report is missing model name")?;
        ensure!(
            report_model == self.settings.model,
            "Evaluation report model does not match the active configuration"
        );

        if eligible {
            let task_score = report
                .pointer("/summary/task_score")
                .and_then(serde_json::Value::as_f64)
                .context("Evaluation report is missing task score")?;
            let fixture_count = report
                .pointer("/summary/fixture_count")
                .and_then(serde_json::Value::as_u64)
                .context("Evaluation report is missing fixture count")?;
            let ollama_runtime_version = report
                .get("ollama_runtime_version")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .context("Evaluation report is missing Ollama runtime version")?
                .to_owned();
            let qualification = TaskQualification {
                model: self.settings.model.clone(),
                digest: digest.clone(),
                prompt_version: PROMPT_VERSION.into(),
                context_hash: settings_context_hash(&self.settings),
                suite_hash: evaluation_suite_hash(),
                ollama_runtime_version,
                task_score,
                fixture_count: u32::try_from(fixture_count)
                    .context("Evaluation fixture count is outside supported range")?,
                qualified_at: Utc::now(),
            };
            self.settings.model_digest = Some(digest);
            self.settings.task_qualification = Some(qualification);
            self.settings.validate()?;
            self.db.set_meta("settings", &self.settings)?;
            let logged = self.db.log(
                "model.task_qualified",
                None,
                &format!(
                    "Task-specific model evaluation passed and was bound to the current configuration: {}",
                    path.display()
                ),
            );
            logged?;
            Ok(())
        } else {
            self.settings.task_qualification = None;
            self.settings.disarm_delivery();
            self.db.set_meta("settings", &self.settings)?;
            let logged = self.db.log(
                "model.task_rejected",
                None,
                &format!(
                    "Task-specific model evaluation did not meet Automatic-mode gates: {}",
                    path.display()
                ),
            );
            logged?;
            anyhow::bail!(
                "Task-specific evaluation did not meet Automatic-mode gates; report saved at {}",
                path.display()
            )
        }
    }

    /// Profile synthetic model runtime to a timestamped report.
    ///
    /// Inputs: none beyond the engine. Output: `Result<PathBuf>` — the report file
    /// written; refused in demo mode.
    pub fn profile_model_runtime(&mut self) -> Result<PathBuf> {
        ensure!(
            !self.demo,
            "Synthetic demo mode does not run the configured model"
        );
        let stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let path = self
            .directory
            .join(format!("model-runtime-profile-{stamp}.json"));
        self.profile_model_runtime_to(&path)?;
        Ok(path)
    }

    /// Profile synthetic model runtime to a chosen path.
    ///
    /// Inputs: `path` — destination report file. Output: `Result<()>` once the
    /// profile is written; refused in demo mode.
    pub fn profile_model_runtime_to(&mut self, path: &Path) -> Result<()> {
        ensure!(
            !self.demo,
            "Synthetic demo mode does not run the configured model"
        );
        let profile = Ollama::new(&self.settings)?.profile_synthetic_runtime()?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        crate::vault::write_new_private(path, &serde_json::to_vec_pretty(&profile)?)?;
        let logged = self.db.log(
            "model.runtime_profiled",
            None,
            &format!(
                "Synthetic cold/warm/near-context local runtime profile saved as {}",
                path.display()
            ),
        );
        logged?;
        Ok(())
    }

    /// Compare installed decision models to a timestamped report.
    ///
    /// Inputs: none beyond the engine. Output: `Result<PathBuf>` — the report file
    /// written; refused in demo mode.
    pub fn compare_models(&mut self) -> Result<PathBuf> {
        ensure!(
            !self.demo,
            "Synthetic demo mode does not run installed local models"
        );
        let stamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let path = self.directory.join(format!("model-bakeoff-{stamp}.json"));
        evaluation::compare_installed(&self.settings, &path)?;
        let logged = self.db.log(
            "models.compared",
            None,
            &format!(
                "Task-specific installed-model bake-off saved as {}",
                path.display()
            ),
        );
        logged?;
        Ok(path)
    }

    /// Synchronize the mailbox into the workspace store.
    ///
    /// Inputs: none beyond the engine. Output: `Result<usize>` — the number of
    /// newly inserted messages; refused in demo mode.
    pub fn synchronize(&mut self) -> Result<usize> {
        ensure!(
            !self.demo,
            "Demo messages are synthetic and have no provider"
        );
        let gmail = self
            .mail
            .as_mut()
            .context("Connect a Gmail account first")?;
        let r = sync::synchronize(
            gmail,
            &mut self.db,
            &self.settings,
            &self.account,
            Utc::now(),
            &self.stop,
        );
        if let Err(e) = &r {
            eprintln!("[diag] sync error: {e:#}");
        }
        r
    }
    /// The most recent successful mailbox poll time.
    ///
    /// Inputs: none beyond the engine. Output: `Result<Option<DateTime<Utc>>>` —
    /// the saved sync timestamp, if any.
    pub fn last_poll(&self) -> Result<Option<DateTime<Utc>>> {
        Ok(self
            .db
            .meta::<SyncState>(&format!("sync/{}", self.account))?
            .and_then(|s| s.last_poll))
    }
    /// Analyze the next queued message and draft a reply.
    ///
    /// Inputs: none beyond the engine. Output: `Result<bool>` — `true` when one
    /// message was processed; `false` in demo mode, without a provider, without a
    /// pinned model, or when the queue is empty.
    pub fn process_one(&mut self) -> Result<bool> {
        if self.demo || self.mail.is_none() || self.settings.model_digest.is_none() {
            return Ok(false);
        }
        // Global runtime/configuration failures must not consume retries on individual
        // messages. Keep the queue intact so it resumes automatically when Ollama/model
        // availability is restored.
        let local_ai = Ollama::new(&self.settings)?;
        ensure!(
            local_ai.healthy(),
            "Local Ollama is unavailable; queued messages were left unchanged"
        );
        local_ai
            .inspect()
            .context("Pinned local model is unavailable; queued messages were left unchanged")?;
        let Some(mut job) = self.db.next_queued(&self.account, Utc::now())? else {
            return Ok(false);
        };
        if job.email.is_none() {
            match self
                .mail
                .as_mut()
                .context("Connect Gmail")?
                .email(&job.stub)
            {
                Ok(Some(email)) => job.email = Some(email),
                Ok(None) => {
                    job.state = JobState::Other;
                    let saved = self.db.save(
                        &mut job,
                        "email.unavailable",
                        "Provider message no longer exists",
                    );
                    saved?;
                    return Ok(true);
                }
                Err(error) if error.kind == FetchFailureKind::Infrastructure => {
                    return Err(anyhow::anyhow!(error.message));
                }
                Err(error) => {
                    job.state = JobState::Attention;
                    job.flags = vec![error.message];
                    let failure = ProcessingFailureRecord {
                        code: ProcessingFailureCode::MessageMalformed,
                        attempts: 1,
                        retry_exhausted: true,
                        occurred_at: Utc::now(),
                    };
                    let saved = self.db.save_processing_failure(
                        &mut job,
                        &failure,
                        "email.malformed",
                        "Message parsing failed safely; Human review required",
                    );
                    saved?;
                    return Ok(true);
                }
            }
        }
        let result = self.analyze_job(&mut job);
        if let Err(error) = result {
            let now = Utc::now();
            job.attempts = job.attempts.saturating_add(1);
            let retry_exhausted = job.attempts >= 3;
            let code = ollama::processing_failure_code(&error);
            job.flags = vec![format!("Analysis unavailable [{}]: {error}", code.as_str())];
            if retry_exhausted {
                job.state = JobState::Attention;
                job.retry_at = 0;
            } else {
                job.retry_at = now.timestamp() + 60 * (1i64 << job.attempts.min(6));
            }
            let failure = ProcessingFailureRecord {
                code,
                attempts: job.attempts,
                retry_exhausted,
                occurred_at: now,
            };
            let saved = self.db.save_processing_failure(
                &mut job,
                &failure,
                if retry_exhausted {
                    "analysis.retry_exhausted"
                } else {
                    "analysis.retry_scheduled"
                },
                "Per-message analysis failure isolated; no send authorized",
            );
            saved?;
            // This failure is isolated to one item. Global Ollama/provider failures
            // are detected before dequeue and still return Err, opening the worker
            // circuit. A poison message therefore cannot stall unrelated queued mail.
            return Ok(true);
        }
        Ok(true)
    }
    /// Run the analysis stage for one job whose message content is loaded.
    ///
    /// Inputs: `job` — job to analyze, mutated in place; the message content must
    /// already be fetched. Output: `Result<()>` — on success the job carries its
    /// analysis outcome; messages outside the configured age window are deferred
    /// and their content cleared instead.
    fn analyze_job(&mut self, job: &mut Job) -> Result<()> {
        let Some(email) = job.email.as_ref() else {
            anyhow::bail!("Message content must be fetched before analysis");
        };
        if email.received_at < self.settings.cutoff(Utc::now()) || email.received_at > Utc::now() {
            job.state = JobState::Deferred;
            job.email = None;
            let cleared = self.db.save_clearing_processing_failure(
                job,
                "email.outside_window",
                "Identity retained; body not kept outside requested age range",
            );
            cleared?;
            return Ok(());
        }
        if email
            .labels
            .iter()
            .any(|s| matches!(s.as_str(), "SENT" | "DRAFT" | "SPAM" | "TRASH"))
        {
            job.state = JobState::Other;
            job.email = None;
            let cleared = self.db.save_clearing_processing_failure(
                job,
                "email.excluded",
                "Provider folder excluded",
            );
            cleared?;
            return Ok(());
        }
        let (analysis, draft, mut flags) = Ollama::new(&self.settings)?.analyze(email)?;
        flags.extend(mail::hard_blocks(email, &self.account));
        let rejected = analysis.verdict.category == Category::Rejection;
        let uncertain = analysis.verdict.category == Category::Uncertain;
        job.state = if rejected
            && flags.is_empty()
            && analysis.verdict.confidence >= 95
            && analysis
                .verification
                .as_ref()
                .is_some_and(Verification::passed)
        {
            JobState::Ready
        } else if rejected || uncertain {
            JobState::Attention
        } else {
            JobState::Other
        };
        job.draft = draft;
        job.drafted_at = job.draft.as_ref().map(|_| Utc::now());
        job.analysis = Some(analysis);
        job.flags = flags;
        job.retry_at = 0;
        if job.state == JobState::Other {
            job.email = None;
            job.analysis = None;
        }
        let cleared = self.db.save_clearing_processing_failure(
            job,
            "email.analyzed",
            "Local structured classification and reply verification completed",
        );
        cleared?;
        Ok(())
    }
    /// Edit the drafted reply for one message.
    ///
    /// Inputs: `id` — message id; `revision` — expected job revision; `body` —
    /// replacement draft body. Output: `Result<()>`; Human review mode only, and
    /// stale revisions are refused.
    pub fn edit(&mut self, id: &str, revision: u64, body: String) -> Result<()> {
        ensure!(
            self.settings.mode == Mode::HumanReview,
            "Editing is available only in Human review mode"
        );
        mail::validate_draft(&body)?;
        let mut job = self.owned(id)?;
        ensure!(
            job.state.reviewable() && job.revision == revision,
            "Message changed; reload before editing"
        );
        job.draft = Some(Draft {
            body,
            origin: "human".into(),
        });
        job.drafted_at = Some(Utc::now());
        job.state = JobState::Attention;
        if let Some(a) = job.analysis.as_mut() {
            a.verified_draft_hash = None;
            a.verification = None;
        }
        job.flags = vec!["User-edited reply; previous automatic verification invalidated".into()];
        let saved = self.db.save_clearing_processing_failure(
            &mut job,
            "draft.edited",
            "Human edit; explicit review required before send",
        );
        saved?;
        Ok(())
    }
    /// Regenerate the drafted reply for one message.
    ///
    /// Inputs: `id` — message id; `revision` — expected job revision. Output: `Result<()>`;
    /// Human review mode only, and stale revisions are refused.
    pub fn regenerate(&mut self, id: &str, revision: u64) -> Result<()> {
        ensure!(
            self.settings.mode == Mode::HumanReview,
            "Regeneration is available only in Human review mode"
        );
        let mut job = self.owned(id)?;
        ensure!(
            job.state.reviewable() && job.revision == revision,
            "Message changed; reload before regenerating"
        );
        ensure!(!self.demo, "Demo does not run a local model");
        job.attempts = 0;
        job.state = JobState::Queued;
        job.draft = None;
        job.analysis = None;
        job.flags.clear();
        job.retry_at = 0;
        let saved = self.db.save_clearing_processing_failure(
            &mut job,
            "analysis.requested",
            "User requested a fresh local analysis",
        );
        saved?;
        Ok(())
    }
    /// Dismiss one reviewable message without replying.
    ///
    /// Inputs: `id` — message id; `revision` — expected job revision. Output: `Result<()>`;
    /// stale revisions are refused.
    pub fn dismiss(&mut self, id: &str, revision: u64) -> Result<()> {
        let mut job = self.owned(id)?;
        ensure!(
            job.state.reviewable() && job.revision == revision,
            "Message changed; reload before dismissing"
        );
        job.state = JobState::Dismissed;
        let saved = self.db.save_clearing_processing_failure(
            &mut job,
            "email.dismissed",
            "Dismissed by user; no mail sent",
        );
        saved?;
        Ok(())
    }
    /// Load one job after checking it belongs to this account.
    ///
    /// Inputs: `id` — message id. Output: `Result<Job>`; messages from other
    /// accounts are refused.
    pub fn owned(&self, id: &str) -> Result<Job> {
        let j = self.db.get(id)?;
        ensure!(
            j.stub.account == self.account,
            "Message belongs to another account"
        );
        Ok(j)
    }
    /// Send the approved reply for one message.
    ///
    /// Inputs: `id` — message id; `revision` — expected job revision; `expected_hash`
    /// — hash of the exact approved draft; `automatic` — whether this is automatic
    /// dispatch. Output: `Result<()>` — `Ok(())` only on confirmed delivery;
    /// refusals carry the stable dispatch-failure error.
    pub fn send(
        &mut self,
        id: &str,
        revision: u64,
        expected_hash: &str,
        automatic: bool,
    ) -> Result<()> {
        self.send_attempt(id, revision, expected_hash, automatic)
            .map_err(anyhow::Error::new)
    }

    /// Validate every dispatch precondition and send one approved reply.
    ///
    /// Inputs: `id` — job identifier; `revision` — the job revision the approval
    /// was given for; `expected_hash` — draft body hash the operator confirmed;
    /// `automatic` — whether this is an automatic send. Output: `Result<(),
    /// DispatchFailure>` — `Ok(())` once the reply is sent; otherwise the first
    /// violated precondition as the matching typed failure.
    fn send_attempt(
        &mut self,
        id: &str,
        revision: u64,
        expected_hash: &str,
        automatic: bool,
    ) -> std::result::Result<(), DispatchFailure> {
        self.require_dispatch_gates(automatic)?;
        let job = self
            .owned(id)
            .map_err(|error| DispatchFailure::review(error.to_string()))?;
        let original = self.validate_send_job(&job, revision, expected_hash)?;
        if automatic {
            self.validate_automatic_preflight(&job)?;
        }
        let gmail = self.mail.as_deref_mut().ok_or_else(|| {
            DispatchFailure::review_code(
                "review_required_gmail_disconnected",
                "Gmail is not connected",
            )
        })?;
        preflight_gmail_account(gmail, &self.account)?;
        fetch_fresh_original(gmail, &self.account, &job, original)?;
        verify_thread_state(gmail, &job, original)?;
        let raw = self.reserve_dispatch(&job, automatic)?;
        self.guard_reserved_dispatch(id)?;
        self.dispatch_to_provider(id, &raw, &job)
    }

    /// Validate the runtime-level dispatch gates shared by every send path.
    ///
    /// Inputs: `automatic` — whether this is an automatic send. Output:
    /// `Result<(), DispatchFailure>` — `Ok(())` while demo state, the emergency
    /// stop, pause/stop flags and send arming all allow dispatch.
    fn require_dispatch_gates(&self, automatic: bool) -> std::result::Result<(), DispatchFailure> {
        dispatch_require(
            !self.demo,
            DispatchFailureKind::ReviewRequired,
            "Demo messages cannot be sent",
        )?;
        emergency::ensure_dispatch_allowed().map_err(|error| {
            DispatchFailure::retryable_code("retryable_emergency_stop", error.to_string())
        })?;
        dispatch_require(
            !self.paused.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst),
            DispatchFailureKind::Retryable,
            "Paused or stopping; sending is blocked",
        )?;
        dispatch_require(
            self.settings.sending_enabled,
            DispatchFailureKind::ReviewRequired,
            "Sending is disabled",
        )?;
        dispatch_require(
            automatic || self.settings.mode == Mode::HumanReview,
            DispatchFailureKind::ReviewRequired,
            "Manual sending is only available in Human review mode",
        )?;
        Ok(())
    }

    /// Validate the job, its approved draft and its original message for send.
    ///
    /// Inputs: `job` — owned job; `revision` — the revision the approval was
    /// given for; `expected_hash` — draft body hash the operator confirmed.
    /// Output: `Result<&Email, DispatchFailure>` — the validated original
    /// message; otherwise the first violated precondition as the matching typed
    /// failure.
    fn validate_send_job<'a>(
        &self,
        job: &'a Job,
        revision: u64,
        expected_hash: &str,
    ) -> std::result::Result<&'a Email, DispatchFailure> {
        dispatch_require(
            job.revision == revision && job.state.reviewable(),
            DispatchFailureKind::ReviewRequired,
            "Approval is stale or message is not reviewable",
        )?;
        mail::validate_job_identity(job)
            .map_err(|error| DispatchFailure::review(error.to_string()))?;
        let body = &job
            .draft
            .as_ref()
            .ok_or_else(|| DispatchFailure::review("Draft is missing"))?
            .body;
        dispatch_require(
            hash(body) == expected_hash,
            DispatchFailureKind::ReviewRequired,
            "Reply changed after confirmation",
        )?;
        mail::validate_draft(body).map_err(|error| DispatchFailure::review(error.to_string()))?;
        let original = job
            .email
            .as_ref()
            .ok_or_else(|| DispatchFailure::review("Original message missing"))?;
        dispatch_require(
            mail::hard_blocks(original, &self.account).is_empty(),
            DispatchFailureKind::ReviewRequired,
            "Message is blocked by mailbox safety checks",
        )?;
        dispatch_require(
            original.received_at >= self.settings.cutoff(Utc::now()),
            DispatchFailureKind::ReviewRequired,
            "Original message is outside the selected age window",
        )?;
        Ok(original)
    }

    /// Run every Automatic-only pre-send check for one job.
    ///
    /// Inputs: `job` — candidate job. Output: `Result<(), DispatchFailure>` —
    /// `Ok(())` only when the automatic conditions, recipient burst ceiling,
    /// runtime qualification and model currency all pass.
    fn validate_automatic_preflight(&self, job: &Job) -> std::result::Result<(), DispatchFailure> {
        dispatch_require(
            auto_blocks(job, &self.settings, &self.account, Utc::now()).is_empty(),
            DispatchFailureKind::ReviewRequired,
            "Automatic send conditions were not satisfied",
        )?;
        let burst_safety = self
            .db
            .recipient_attempts_24h(job, Utc::now())
            .map_err(recipient_burst_unavailable);
        let recipient_attempts = burst_safety?;
        dispatch_require(
            recipient_attempts < u64::from(AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H),
            DispatchFailureKind::ReviewRequired,
            "Automatic recipient 24-hour reply limit reached; Human Review is required",
        )?;
        let local_ai = Ollama::new(&self.settings)
            .map_err(|error| DispatchFailure::review(error.to_string()))?;
        let runtime_version = local_ai.runtime_version().map_err(|error| {
            DispatchFailure::retryable(format!(
                "Local model runtime pre-send check is temporarily unavailable: {error}"
            ))
        })?;
        let qualification = self
            .settings
            .task_qualification
            .as_ref()
            .ok_or_else(|| DispatchFailure::review("Task qualification is missing"))?;
        dispatch_require(
            runtime_version == qualification.ollama_runtime_version,
            DispatchFailureKind::ReviewRequired,
            "Ollama runtime changed since task qualification; re-evaluate before Automatic sending",
        )?;
        let status = local_ai.inspect().map_err(|error| {
            DispatchFailure::retryable(format!(
                "Local model pre-send check is temporarily unavailable: {error}"
            ))
        })?;
        let analyzed_digest = &job
            .analysis
            .as_ref()
            .ok_or_else(|| DispatchFailure::review("Missing analysis"))?
            .model_digest;
        require_analysis_model_current(&status.digest, analyzed_digest)?;
        Ok(())
    }

    /// Render the approved reply and hold the durable send reservation.
    ///
    /// Inputs: `job` — approved job; `automatic` — whether this is an automatic
    /// send. Output: `Result<String, DispatchFailure>` — the rendered RFC 2822
    /// reply once the reservation is held.
    fn reserve_dispatch(
        &mut self,
        job: &Job,
        automatic: bool,
    ) -> std::result::Result<String, DispatchFailure> {
        let raw = mail::raw_reply(job, &self.settings, &self.account, Utc::now())
            .map_err(|error| DispatchFailure::review(error.to_string()))?;
        dispatch_require(
            !self.paused.load(Ordering::SeqCst) && !self.stop.load(Ordering::SeqCst),
            DispatchFailureKind::Retryable,
            "Paused before dispatch; nothing sent",
        )?;
        let headroom = crate::storage::ensure_runtime_write_headroom(&self.directory)
            .map_err(storage_headroom_unknown);
        let storage = headroom?;
        require_runtime_write_safe(&storage)?;
        self.db
            .reserve_send_with_recipient_limit(
                job,
                self.settings.daily_send_limit,
                automatic.then_some(AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H),
                Utc::now(),
            )
            .map_err(|error| DispatchFailure::retryable(error.to_string()))?;
        Ok(raw)
    }

    /// Recheck the dispatch gates after the reservation and hold the send when
    /// one fails.
    ///
    /// Inputs: `id` — job identifier holding the reservation. Output:
    /// `Result<(), DispatchFailure>` — `Ok(())` when dispatch may proceed;
    /// otherwise the reservation is released and the matching failure returned.
    fn guard_reserved_dispatch(&mut self, id: &str) -> std::result::Result<(), DispatchFailure> {
        if let Err(error) = self.checkpoint_audit_protection() {
            self.db
                .release_unsent_reservation(
                    id,
                    "Protected audit checkpoint failed before the Gmail network request; no email was sent",
                )
                .map_err(|db_error| DispatchFailure::handled(db_error.to_string()))?;
            return Err(DispatchFailure::retryable(format!(
                "Protected audit checkpoint is unavailable; Gmail dispatch was blocked: {error}"
            )));
        }

        if let Err(error) = emergency::ensure_dispatch_allowed() {
            self.db
                .release_unsent_reservation(
                    id,
                    "Enterprise emergency stop blocked dispatch before the Gmail network request; no email was sent",
                )
                .map_err(|db_error| DispatchFailure::handled(db_error.to_string()))?;
            if let Err(anchor_error) = self.checkpoint_audit_protection() {
                return Err(DispatchFailure::handled_code(
                    "nonretryable_audit_checkpoint_failed",
                    format!(
                        "Emergency stop blocked Gmail dispatch, but the protected audit checkpoint failed: {anchor_error}. No email was sent."
                    ),
                ));
            }
            return Err(DispatchFailure::retryable_code(
                "retryable_emergency_stop",
                error.to_string(),
            ));
        }
        if self.paused.load(Ordering::SeqCst) || self.stop.load(Ordering::SeqCst) {
            self.db
                .release_unsent_reservation(
                    id,
                    "Dispatch was cancelled before the Gmail network request; no email was sent",
                )
                .map_err(|error| DispatchFailure::handled(error.to_string()))?;
            return Err(DispatchFailure::handled(
                "Dispatch cancelled before Gmail accepted any request",
            ));
        }
        self.db
            .log(
                "delivery.dispatch_attempt",
                Some(id),
                "Initiating provider network request",
            )
            .map_err(|error| DispatchFailure::handled(error.to_string()))?;
        Ok(())
    }

    /// Execute the provider send and settle the durable outcome.
    ///
    /// Inputs: `id` — job identifier holding the reservation; `raw` — rendered
    /// reply; `job` — job being dispatched. Output: `Result<(), DispatchFailure>`
    /// — `Ok(())` only on confirmed delivery; otherwise the settled failure.
    fn dispatch_to_provider(
        &mut self,
        id: &str,
        raw: &str,
        job: &Job,
    ) -> std::result::Result<(), DispatchFailure> {
        match self
            .mail
            .as_mut()
            .ok_or_else(|| DispatchFailure::handled("Gmail disconnected after reservation"))?
            .send(raw, &job.stub.thread_id)
        {
            Ok(provider_id) => {
                self.db
                    .finish_send(id, Some(provider_id))
                    .map_err(|error| DispatchFailure::handled(error.to_string()))?;
                self.checkpoint_audit_protection().map_err(|error| {
                    DispatchFailure::handled(format!(
                        "Gmail accepted the reply and local state is Sent, but the required protected audit checkpoint failed: {error}. Do not resend."
                    ))
                })?;
                Ok(())
            }
            Err(error) if error.kind == SendFailureKind::NotAccepted => {
                self.db
                    .release_unsent_reservation(
                        id,
                        "Gmail definitively rejected the send request; no email was accepted",
                    )
                    .map_err(|db_error| DispatchFailure::handled(db_error.to_string()))?;
                self.checkpoint_audit_protection().map_err(|anchor_error| {
                    DispatchFailure::handled_code(
                        "nonretryable_audit_checkpoint_failed",
                        format!(
                            "Gmail rejected the reply before acceptance, but the required protected audit checkpoint failed: {anchor_error}"
                        ),
                    )
                })?;
                Err(DispatchFailure::review_code(
                    "review_required_gmail_send_rejected",
                    error.message,
                ))
            }
            Err(error) => {
                self.db
                    .finish_send(id, None)
                    .map_err(|db_error| DispatchFailure::handled(db_error.to_string()))?;
                if let Err(anchor_error) = self.checkpoint_audit_protection() {
                    return Err(DispatchFailure::handled(format!(
                        "{} Delivery remains Uncertain and the required protected audit checkpoint also failed: {anchor_error}. Do not resend; reconcile Gmail Sent.",
                        error.message
                    )));
                }
                Err(DispatchFailure::reconcile(format!(
                    "{} Do not resend. Use Reconcile to check Gmail Sent.",
                    error.message
                )))
            }
        }
    }

    /// Run one automatic-dispatch pass when policy allows it.
    ///
    /// Inputs: none beyond the engine. Output: `Result<bool>` — `true` when one
    /// message was dispatched; `false` when the mode, send arming or pause flag
    /// blocks dispatch.
    pub fn automatic_tick(&mut self) -> Result<bool> {
        if self.settings.mode != Mode::Automatic
            || !self.settings.sending_enabled
            || self.paused.load(Ordering::SeqCst)
        {
            return Ok(false);
        }
        emergency::ensure_dispatch_allowed()
            .context("Automatic dispatch is blocked by the enterprise emergency stop")?;
        if self.db.counts(&self.account)?.attempts_24h >= u64::from(self.settings.daily_send_limit)
        {
            return Ok(false);
        }
        for id in self.db.ready_ids(&self.account)? {
            let job = self.owned(&id)?;
            if self.db.thread_blocked(&job.stub.thread_key())?
                || !auto_blocks(&job, &self.settings, &self.account, Utc::now()).is_empty()
            {
                continue;
            }
            let fingerprint = hash(&job.draft.as_ref().context("Missing draft")?.body);
            if let Err(error) = self.send_attempt(&id, job.revision, &fingerprint, true) {
                if error.kind == DispatchFailureKind::ReviewRequired {
                    let mut current = self.owned(&id)?;
                    if current.state.reviewable() {
                        current.state = JobState::Attention;
                        current
                            .flags
                            .push(format!("Automatic dispatch held: {}", error.message));
                        let saved = self.db.save(
                            &mut current,
                            "automatic.held",
                            "Deterministic preflight failed; requires human review",
                        );
                        saved?;
                    }
                }
                return Err(anyhow::Error::new(error));
            }
            return Ok(true);
        }
        Ok(false)
    }
    /// Reconcile one uncertain delivery with the provider.
    ///
    /// Inputs: `id` — message id. Output: `Result<()>`; only uncertain deliveries
    /// can be reconciled.
    pub fn reconcile(&mut self, id: &str) -> Result<()> {
        let j = self.owned(id)?;
        ensure!(
            j.state == JobState::Uncertain,
            "Only uncertain deliveries can be reconciled"
        );
        let found = self
            .mail
            .as_mut()
            .context("Connect Gmail")?
            .find_sent(&mail::outgoing_id(&j))?;
        if let Some(provider) = found {
            self.db.finish_send(id, Some(provider))?;
        } else {
            let logged = self.db.log(
                "delivery.unresolved",
                Some(id),
                "No Sent match found. Reservation retained; absence does not prove non-delivery",
            );
            logged?;
        }
        Ok(())
    }
    /// Seed the demo engine with sample settings and jobs.
    ///
    /// Inputs: none (`&mut self` — the demo engine state to populate). Output:
    /// `Result<()>` — the engine holds a demo account, signature, and sample
    /// recruiting messages.
    fn seed_demo(&mut self) -> Result<()> {
        self.account = "demo@example.invalid".into();
        self.settings.signature = "Alex Morgan".into();
        for (company, subject, text) in [
            (
                "Northstar Materials",
                "Your application — Thin Film Engineer",
                "Thank you for applying for the Thin Film Engineer position. After reviewing your experience, we have decided not to move forward with your application.",
            ),
            (
                "Helix Instruments",
                "Update on your application",
                "We appreciate your interest in our R&D team. Your application has not been selected for the next stage.",
            ),
            (
                "Aperture Systems",
                "Research Engineer application",
                "Thank you for your time. We have decided to pursue other candidates for this position.",
            ),
        ] {
            let email = ollama::sample_email(subject, text);
            let id = email.stub.id();
            self.db.insert_stub(email.stub.clone(), Utc::now())?;
            let mut job = self.db.get(&id)?;
            job.email = Some(email);
            job.state = JobState::Ready;
            job.flags =
                vec!["Synthetic demonstration. No actual account or live inference.".into()];
            job.draft = Some(Draft {
                body: format!(
                    "Dear {company} Recruitment Team,\n\nI challenge this decision and request a substantive explanation of the assessment. Please identify the specific advertised requirements I did not meet and explain how my relevant experience was evaluated. A restatement of the outcome would not address these questions.\n\nRegards,\nAlex Morgan"
                ),
                origin: "demo".into(),
            });
            job.drafted_at = Some(Utc::now());
            let saved = self.db.save(
                &mut job,
                "demo.loaded",
                "Synthetic fixture, not model-generated or real email",
            );
            saved?;
        }
        Ok(())
    }
}

/// Validate the connected provider account before dispatch.
///
/// Inputs: `gmail` — connected transport; `account` — workspace account key.
/// Output: `Result<(), DispatchFailure>` — `Ok` when the transport may send and
/// its profile matches the workspace account.
fn preflight_gmail_account(
    gmail: &mut dyn MailTransport,
    account: &str,
) -> std::result::Result<(), DispatchFailure> {
    dispatch_require(
        gmail.can_send(),
        DispatchFailureKind::ReviewRequired,
        "Google send permission is missing",
    )?;
    let profile = gmail.profile().map_err(|error| {
        DispatchFailure::retryable(format!(
            "Gmail account preflight is temporarily unavailable: {error}"
        ))
    })?;
    let profile_account = mail::mailbox(&profile.email_address)
        .map_err(|error| DispatchFailure::review(error.to_string()))?;
    dispatch_require(
        profile_account == account,
        DispatchFailureKind::ReviewRequired,
        "Connected account changed",
    )?;
    Ok(())
}
/// Refetch the original message and prove it is unchanged.
///
/// Inputs: `gmail` — connected transport; `account` — workspace account key;
/// `job` — job being dispatched; `original` — the originally analyzed message.
/// Output: `Result<Email, DispatchFailure>` — the fresh message copy; failure
/// when the message vanished, changed, or became blocked.
fn fetch_fresh_original(
    gmail: &mut dyn MailTransport,
    account: &str,
    job: &Job,
    original: &Email,
) -> std::result::Result<Email, DispatchFailure> {
    let fresh = match gmail.email(&job.stub) {
        Ok(Some(email)) => email,
        Ok(None) => return Err(DispatchFailure::review("Original message no longer exists")),
        Err(error) if error.kind == FetchFailureKind::Infrastructure => {
            return Err(DispatchFailure::retryable(error.message));
        }
        Err(error) => return Err(DispatchFailure::review(error.message)),
    };
    dispatch_require(
        fresh.fingerprint() == original.fingerprint()
            && mail::hard_blocks(&fresh, account).is_empty(),
        DispatchFailureKind::ReviewRequired,
        "Original message changed; review it again",
    )?;
    Ok(fresh)
}
/// Prove the conversation holds no activity newer than the original.
///
/// Inputs: `gmail` — connected transport; `job` — job being dispatched;
/// `original` — the originally analyzed message. Output:
/// `Result<(), DispatchFailure>` — `Ok` while the thread contains the original
/// and every other message predates it.
fn verify_thread_state(
    gmail: &mut dyn MailTransport,
    job: &Job,
    original: &Email,
) -> std::result::Result<(), DispatchFailure> {
    let thread = gmail.thread(&job.stub.thread_id).map_err(|error| {
        DispatchFailure::retryable(format!(
            "Gmail conversation preflight is temporarily unavailable: {error}"
        ))
    })?;
    dispatch_require(
        thread
            .messages
            .iter()
            .any(|message| message.id == job.stub.provider_id),
        DispatchFailureKind::ReviewRequired,
        "Original message is no longer in the conversation",
    )?;
    for message in thread.messages {
        if message.id != job.stub.provider_id {
            let at = message.internal_date.parse::<i64>().map_err(|_| {
                DispatchFailure::review("Conversation contains an invalid provider timestamp")
            })?;
            dispatch_require(
                at < original.received_at.timestamp_millis(),
                DispatchFailureKind::ReviewRequired,
                "Newer conversation activity exists; review it before replying",
            )?;
        }
    }
    Ok(())
}

/// Decide whether one job may dispatch automatically.
///
/// Inputs: `job` — candidate job; `settings` — current settings; `account` —
/// account key; `now` — decision time. Output: [`AutomaticPolicyDecision`]
/// listing every blocking reason with its stable code.
pub fn automatic_policy(
    job: &Job,
    settings: &Settings,
    account: &str,
    now: DateTime<Utc>,
) -> AutomaticPolicyDecision {
    let mut blocks = Vec::new();

    automatic_mode_blocks(&mut blocks, job, settings);

    let Some(email) = job.email.as_ref() else {
        push_policy_block(
            &mut blocks,
            AutomaticPolicyCode::OriginalEmailMissing,
            "Original email missing",
        );
        return AutomaticPolicyDecision {
            eligible: false,
            blocks,
        };
    };
    automatic_mailbox_blocks(&mut blocks, email, account);

    let Some(analysis) = job.analysis.as_ref() else {
        push_policy_block(
            &mut blocks,
            AutomaticPolicyCode::LocalAnalysisMissing,
            "Local analysis missing",
        );
        return AutomaticPolicyDecision {
            eligible: false,
            blocks,
        };
    };
    let Some(draft) = job.draft.as_ref() else {
        push_policy_block(
            &mut blocks,
            AutomaticPolicyCode::DraftMissing,
            "Draft missing",
        );
        return AutomaticPolicyDecision {
            eligible: false,
            blocks,
        };
    };

    automatic_verdict_blocks(&mut blocks, job, analysis);
    automatic_provenance_blocks(&mut blocks, settings, analysis, draft, email);
    automatic_freshness_blocks(&mut blocks, settings, job, email, now);
    automatic_language_blocks(&mut blocks, email, draft, settings);

    AutomaticPolicyDecision {
        eligible: blocks.is_empty(),
        blocks,
    }
}

/// Collect the identity and mode-arming blocks for automatic policy.
///
/// Inputs: `blocks` — block list being built; `job` — candidate job;
/// `settings` — current settings. Output: none — blocks are appended in place.
fn automatic_mode_blocks(blocks: &mut Vec<AutomaticPolicyBlock>, job: &Job, settings: &Settings) {
    if mail::validate_job_identity(job).is_err() {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::QueueIdentityMismatch,
            "Queue/message identity mismatch",
        );
    }
    if settings.mode != Mode::Automatic
        || !settings.sending_enabled
        || !settings.automatic_confirmed
    {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::AutomaticModeNotArmed,
            "Automatic mode not explicitly armed",
        );
    }
}

/// Collect the mailbox-safety blocks for automatic policy.
///
/// Inputs: `blocks` — block list being built; `email` — original message;
/// `account` — account key. Output: none — blocks are appended in place.
fn automatic_mailbox_blocks(blocks: &mut Vec<AutomaticPolicyBlock>, email: &Email, account: &str) {
    for message in mail::hard_blocks(email, account) {
        push_policy_block(blocks, AutomaticPolicyCode::MailboxSafetyBlock, message);
    }
}

/// Collect the verdict and model-verification blocks for automatic policy.
///
/// Inputs: `blocks` — block list being built; `job` — candidate job;
/// `analysis` — local analysis record. Output: none — blocks are appended in
/// place.
fn automatic_verdict_blocks(
    blocks: &mut Vec<AutomaticPolicyBlock>,
    job: &Job,
    analysis: &Analysis,
) {
    if job.state != JobState::Ready
        || analysis.verdict.category != Category::Rejection
        || analysis.verdict.confidence < 95
    {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::NotHighConfidenceRejection,
            "Not a high-score reviewed rejection",
        );
    }
    if !analysis.input_complete
        || !analysis.gpu_resident
        || !analysis
            .verification
            .as_ref()
            .is_some_and(Verification::passed)
    {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::ModelVerificationOrResidencyFailed,
            "Model verification or residency failed",
        );
    }
}

/// Collect the draft and analysis-provenance blocks for automatic policy.
///
/// Inputs: `blocks` — block list being built; `settings` — current settings;
/// `analysis` — local analysis record; `draft` — approved draft; `email` —
/// original message. Output: none — blocks are appended in place.
fn automatic_provenance_blocks(
    blocks: &mut Vec<AutomaticPolicyBlock>,
    settings: &Settings,
    analysis: &Analysis,
    draft: &Draft,
    email: &Email,
) {
    if draft.origin != "ollama-v1"
        || analysis.verified_draft_hash.as_deref() != Some(hash(&draft.body).as_str())
    {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::DraftVerificationStale,
            "Draft changed since verification",
        );
    }
    if settings.model_digest.as_ref() != Some(&analysis.model_digest)
        || settings.model != analysis.model
        || analysis.prompt_version != PROMPT_VERSION
        || analysis.context_hash != ollama::context_hash(settings)
        || analysis.email_fingerprint != email.fingerprint()
    {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::AnalysisIdentityStale,
            "Analysis identity is stale",
        );
    }
    if settings.independent_verifier_enabled
        && (analysis.verification_model != settings.verifier_model
            || settings.verifier_model_digest.as_ref() != Some(&analysis.verification_model_digest))
    {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::AnalysisIdentityStale,
            "Independent-verifier provenance is stale",
        );
    }
}

/// Collect the qualification, cooldown and age-window blocks for automatic
/// policy.
///
/// Inputs: `blocks` — block list being built; `settings` — current settings;
/// `job` — candidate job; `email` — original message; `now` — decision time.
/// Output: none — blocks are appended in place.
fn automatic_freshness_blocks(
    blocks: &mut Vec<AutomaticPolicyBlock>,
    settings: &Settings,
    job: &Job,
    email: &Email,
    now: DateTime<Utc>,
) {
    if !settings.task_qualification_current() {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::TaskQualificationStale,
            "Task-specific model qualification is missing or stale",
        );
    }
    if job.drafted_at.is_none_or(|time| {
        now.signed_duration_since(time).num_minutes() < i64::from(settings.cooldown_minutes)
    }) {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::CooldownActive,
            "Cooldown active",
        );
    }
    if email.received_at < settings.cutoff(now) || email.received_at > now {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::OutsideAgeWindow,
            "Outside selected age window",
        );
    }
    if !settings.include_backlog
        && settings
            .automatic_since
            .is_none_or(|time| email.received_at < time)
    {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::PredatesAutomaticEnrollment,
            "Predates automatic-mode enrollment",
        );
    }
}

/// Collect the rejection-evidence, language and reply-loop blocks for
/// automatic policy.
///
/// Inputs: `blocks` — block list being built; `email` — original message;
/// `draft` — approved draft; `settings` — current settings. Output: none —
/// blocks are appended in place.
fn automatic_language_blocks(
    blocks: &mut Vec<AutomaticPolicyBlock>,
    email: &Email,
    draft: &Draft,
    settings: &Settings,
) {
    if !mail::clear_rejection_language(&email.subject, &email.text) {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::MissingDeterministicRejectionEvidence,
            "No independent clear rejection phrase in the current message",
        );
    }
    if mail::auto_language_conflict(&email.subject, &email.text) {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::ConflictingEmailLanguage,
            "Conflicting or suspicious email language",
        );
    }
    if mail::automatic_draft_conflict(&draft.body, &settings.signature) {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::DraftEscalationOrLink,
            "Draft requires Human review because of escalation or link content",
        );
    }
    if email.header("auto-submitted").is_some_and(|value| {
        !value.eq_ignore_ascii_case("no") && !value.eq_ignore_ascii_case("auto-generated")
    }) {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::AutomaticReplyLoop,
            "Automatic reply-loop marker requires Human review",
        );
    }
    for name in [
        "list-id",
        "list-unsubscribe",
        "precedence",
        "x-auto-response-suppress",
    ] {
        if email.headers.contains_key(name) {
            push_policy_block(
                blocks,
                AutomaticPolicyCode::AutomaticReplySuppressed,
                format!("Automatic replies suppressed by {name}"),
            );
        }
    }
    if let Some(reply) = &email.reply_to
        && mail::mailbox(reply).ok() != mail::mailbox(&email.from).ok()
    {
        push_policy_block(
            blocks,
            AutomaticPolicyCode::ReplyToMismatch,
            "Reply-To differs from sender; human review required",
        );
    }
}

/// Compatibility helper for existing UI/tests. Integrations should prefer
/// `automatic_policy` and its stable reason codes.
///
/// Inputs: `job` — candidate job; `settings` — current settings; `account` —
/// account key; `now` — decision time. Output: `Vec<String>` of blocking
/// messages.
pub fn auto_blocks(
    job: &Job,
    settings: &Settings,
    account: &str,
    now: DateTime<Utc>,
) -> Vec<String> {
    automatic_policy(job, settings, account, now)
        .blocks
        .into_iter()
        .map(|block| block.message)
        .collect()
}

/// Map a failed recipient-burst safety probe onto its dispatch failure.
///
/// Inputs: `error` — the storage error that prevented counting this
/// recipient's recent attempts. Output: [`DispatchFailure`] requiring review:
/// burst safety cannot be assumed when it could not be measured, so the send
/// is held for a human instead of being blindly retried.
fn recipient_burst_unavailable(error: impl std::fmt::Display) -> DispatchFailure {
    DispatchFailure::review(format!(
        "Automatic recipient burst safety could not be established: {error}"
    ))
}

/// Map a failed storage-headroom probe onto its dispatch failure.
///
/// Inputs: `error` — the storage error that prevented measuring write
/// headroom. Output: [`DispatchFailure`] that is operator-retryable: a
/// measurement outage is transient and must not consume the approval, while
/// the durable-send-state guarantee still blocks the attempt.
fn storage_headroom_unknown(error: impl std::fmt::Display) -> DispatchFailure {
    DispatchFailure::retryable(format!(
        "Durable send state cannot be recorded safely because storage headroom is low: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unclean_session_disarms_unattended_delivery_without_erasing_model_evidence() {
        let mut settings = Settings {
            mode: Mode::Automatic,
            sending_enabled: true,
            automatic_confirmed: true,
            automatic_since: Some(Utc::now()),
            model_digest: Some("a".repeat(64)),
            ..Settings::default()
        };
        let qualification = settings.task_qualification.clone();
        assert!(disarm_after_unclean_session(&mut settings, true));
        assert_eq!(settings.mode, Mode::HumanReview);
        assert!(!settings.sending_enabled);
        assert!(!settings.automatic_confirmed);
        assert!(settings.automatic_since.is_none());
        assert_eq!(settings.task_qualification, qualification);
        assert!(!disarm_after_unclean_session(&mut settings, false));
    }

    #[test]
    fn demo_is_disarmed_and_editable() {
        let d = tempfile::tempdir().unwrap();
        let mut e = Engine::open(
            d.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        assert!(!e.settings.sending_enabled);
        let mut items = e.db.list(&e.account, true, 0, 25).unwrap();
        assert_eq!(items.len(), 3);
        let j = items.pop().unwrap();
        e.edit(
            &j.id,
            j.revision,
            "Please explain the specific assessment criteria used.".into(),
        )
        .unwrap();
        let updated = e.owned(&j.id).unwrap();
        assert_eq!(updated.draft.unwrap().origin, "human");
        assert!(e.send(&j.id, j.revision, "bad", false).is_err());
    }
    #[test]
    fn default_auto_policy_blocks() {
        let s = Settings::default();
        let email = ollama::sample_email("Test", "not selected");
        let mut j = Job::new(email.stub.clone(), Utc::now());
        j.email = Some(email);
        assert!(!auto_blocks(&j, &s, "demo@example.invalid", Utc::now()).is_empty());
    }
}

#[cfg(test)]
mod dispatch_failure_taxonomy_tests {
    use super::*;

    /// A satisfied precondition passes for every kind; a failed one always
    /// produces a typed failure.
    #[test]
    fn dispatch_require_passes_only_when_the_condition_holds() {
        for kind in [
            DispatchFailureKind::Retryable,
            DispatchFailureKind::ReviewRequired,
            DispatchFailureKind::ReconcileRequired,
            DispatchFailureKind::StateHandled,
        ] {
            assert!(dispatch_require(true, kind, "ok").is_ok());
            assert!(dispatch_require(false, kind, "x").is_err());
        }
    }

    /// Why: the model-drift gate is the defence behind the deterministic
    /// rejection gate — a reply drafted under one model must never dispatch
    /// from another without human review. Both arms are pinned here with the
    /// exact operator-facing attribution the review UI branches on.
    /// Inputs: matching and mismatching runtime/analysis digests. Output: pass
    /// while they match; a review-required, non-retryable failure naming the
    /// drift otherwise.
    #[test]
    fn analysis_model_drift_is_refused_for_human_review() {
        assert!(
            require_analysis_model_current("a".repeat(64).as_str(), "a".repeat(64).as_str())
                .is_ok()
        );
        let error =
            require_analysis_model_current("a".repeat(64).as_str(), "b".repeat(64).as_str())
                .unwrap_err();
        assert_eq!(error.kind, DispatchFailureKind::ReviewRequired);
        assert!(!error.retryable_for_operator());
        assert_eq!(error.message, "Model changed since analysis");
    }

    /// Why: dispatch may only reserve send state when the durable write is
    /// guaranteed to succeed; a headroom refusal must be retryable so the
    /// dispatch resumes when space recovers, never silently dropped.
    /// Inputs: storage measurements with and without runtime-write headroom.
    /// Output: pass while safe; a retryable failure naming the headroom
    /// otherwise.
    #[test]
    fn runtime_write_headroom_refusal_is_retryable() {
        let health = |runtime_write_safe: bool| crate::storage::StorageHealth {
            schema_version: 1,
            database_bytes: 0,
            wal_bytes: 0,
            shm_bytes: 0,
            workspace_database_bytes: 0,
            available_bytes: 0,
            total_bytes: 0,
            runtime_required_bytes: 0,
            backup_required_bytes: 0,
            runtime_write_safe,
            backup_safe: true,
        };
        assert!(require_runtime_write_safe(&health(true)).is_ok());
        let error = require_runtime_write_safe(&health(false)).unwrap_err();
        assert_eq!(error.kind, DispatchFailureKind::Retryable);
        assert!(error.retryable_for_operator());
        assert_eq!(
            error.message,
            "Storage headroom is too low for durable send state"
        );
    }

    /// Failure kinds route to recovery paths and carry stable operation codes.
    /// Swapping Retryable and ReconcileRequired would let an operator retry an
    /// uncertain delivery (a double-send risk), so retryability and codes are
    /// pinned here as the at-most-once routing contract.
    #[test]
    fn failure_kind_routing_pins_the_at_most_once_invariants() {
        let retryable = dispatch_require(false, DispatchFailureKind::Retryable, "t").unwrap_err();
        assert!(retryable.retryable_for_operator());
        assert_eq!(retryable.operation_code(), "retryable_dispatch");

        let review = dispatch_require(false, DispatchFailureKind::ReviewRequired, "r").unwrap_err();
        assert!(!review.retryable_for_operator());
        assert_eq!(review.operation_code(), "review_required_dispatch");

        let reconcile =
            dispatch_require(false, DispatchFailureKind::ReconcileRequired, "u").unwrap_err();
        assert!(
            !reconcile.retryable_for_operator(),
            "uncertain delivery must not be operator-retried"
        );
        assert_eq!(
            reconcile.operation_code(),
            "reconcile_required_delivery_uncertain"
        );

        let handled = dispatch_require(false, DispatchFailureKind::StateHandled, "h").unwrap_err();
        assert!(!handled.retryable_for_operator());
        assert_eq!(handled.operation_code(), "dispatch_state_handled");
    }

    /// Custom codes keep the operations journal contract, and the displayed
    /// message is the operator-facing text.
    #[test]
    fn custom_codes_and_display_are_preserved() {
        let failure = DispatchFailure::handled_code("custom_code", "operator text");
        assert_eq!(failure.operation_code(), "custom_code");
        assert!(!failure.retryable_for_operator());
        assert_eq!(failure.to_string(), "operator text");
    }

    /// One workspace, one live engine: the instance lock must exclude a second
    /// holder of the same directory and release cleanly on drop.
    #[test]
    fn instance_lock_is_exclusive_per_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let held = crate::vault::InstanceLock::acquire(dir.path()).expect("first lock");
        assert!(
            crate::vault::InstanceLock::acquire(dir.path()).is_err(),
            "second lock on the same workspace must fail"
        );
        drop(held);
        let reacquired = crate::vault::InstanceLock::acquire(dir.path());
        assert!(reacquired.is_ok(), "lock must release on drop");
    }
}

#[cfg(test)]
mod send_gate_tests {
    use super::*;

    fn job_with_draft() -> Job {
        let mut job = Job::new(
            Stub {
                account: "acct".to_string(),
                provider_id: "msg".to_string(),
                thread_id: "thread".to_string(),
                source: Source::Gmail,
            },
            chrono::Utc::now(),
        );
        job.state = JobState::Ready;
        job.revision = 3;
        job.draft = Some(Draft {
            body: "exact".to_string(),
            origin: "test".to_string(),
        });
        job
    }

    fn ctx<'a>(text: &'a str) -> SendGateContext<'a> {
        SendGateContext {
            editor_text: text,
            editor_bound: true,
            dirty: false,
            hard_blocks: &[],
            busy: false,
            sending_enabled: true,
            demo: false,
            paused: false,
        }
    }

    /// Every individual gate must independently disqualify a send; the
    /// conjunction is what protects users from wrong or duplicate sends.
    #[test]
    fn every_send_gate_independently_disqualifies() {
        let job = job_with_draft();
        assert!(send_gate_eligible(&job, &ctx("exact")));

        let mut dirty = ctx("exact");
        dirty.dirty = true;
        assert!(!send_gate_eligible(&job, &dirty), "unsaved editor");

        let unbound = ctx("exact");
        let mut unbound = unbound;
        unbound.editor_bound = false;
        assert!(!send_gate_eligible(&job, &unbound), "stale editor");

        assert!(!send_gate_eligible(&job, &ctx("exact ")), "edited text");

        let blocked = ["blocked".to_string()];
        let mut blocks = ctx("exact");
        blocks.hard_blocks = &blocked;
        assert!(!send_gate_eligible(&job, &blocks), "mail hard block");

        let mut busy = ctx("exact");
        busy.busy = true;
        assert!(!send_gate_eligible(&job, &busy), "busy worker");

        let mut off = ctx("exact");
        off.sending_enabled = false;
        assert!(!send_gate_eligible(&job, &off), "sending disabled");

        let mut demo = ctx("exact");
        demo.demo = true;
        assert!(!send_gate_eligible(&job, &demo), "demo mode");

        let mut paused = ctx("exact");
        paused.paused = true;
        assert!(!send_gate_eligible(&job, &paused), "paused worker");
    }

    /// A job that is not reviewable (already sent, dismissed, uncertain) is
    /// never a send candidate regardless of editor state.
    #[test]
    fn non_reviewable_jobs_are_never_send_candidates() {
        let mut job = job_with_draft();
        job.state = JobState::Sent;
        assert!(!send_gate_eligible(&job, &ctx("exact")));
    }
}

#[cfg(test)]
mod dispatch_tests {
    // Uncovered-by-design lines in these tests carry no product signal and
    // are deliberately left alone: mock `_ => None` fallbacks only run when
    // a test sends a route the protocol does not use, mock verdict closures
    // only run when a test drives model calls it is deliberately avoiding,
    // and `assert!` message arguments only evaluate when the assertion
    // fails. Covering them would mean padding the suite with noise.
    use super::*;
    use crate::config::DEFAULT_VERIFIER_MODEL;
    use crate::test_support::{MockServer, draft_body, gmail_email, verified_analysis};
    use serde_json::{Value, json};
    use std::sync::Mutex;

    /// App-password connect must refuse in demo mode, fail-closed before any
    /// network or credential handling.
    #[test]
    fn connect_app_password_refuses_in_demo_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = demo(dir.path());
        let creds = crate::mail_transport::AppPasswordCredentials::new(
            "user@example.com",
            "abcdefghijklmnop",
        );
        let err = e.connect_app_password(creds).unwrap_err();
        assert!(
            err.to_string().contains("Demo mode"),
            "demo must refuse app-password connect: {err}"
        );
    }

    fn demo(dir: &std::path::Path) -> Engine {
        Engine::open(
            dir.to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    /// Open a live (non-demo) workspace for these tests.
    ///
    /// Why: non-demo opens derive the vault key from the OS credential store on
    /// Windows and macOS and from the documented `RR_VAULT_PASSPHRASE` input on
    /// headless hosts, so the headless vault seam must be armed first or Linux
    /// runs fail closed.
    /// Inputs: `dir` — workspace directory. Output: the opened [`Engine`].
    fn live(dir: &std::path::Path) -> Engine {
        crate::test_support::headless_vault_seam();
        Engine::open(
            dir.to_path_buf(),
            false,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    fn verdict_content() -> Value {
        json!({"category":"rejection","confidence":99,
            "evidence":"We have decided not to move forward with your application.",
            "explanation":"Explicit negative hiring decision","company":"","position":"","language":"en"})
    }

    fn verification_content() -> Value {
        json!({"genuine_rejection":true,"claims_supported":true,"professional":true,
            "injection_free":true,"purpose_aligned":true,"reason":"Synthetic verification result"})
    }

    /// Scriptable local runtime whose loaded-model state follows the wire
    /// protocol, so `/api/ps` answers residency like the real daemon.
    fn runtime(cpu_only_from_call: usize) -> MockServer {
        let loaded: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let state = loaded.clone();
        let ps_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        MockServer::new(move |route, body| {
            let body = body.unwrap_or_else(|| json!({}));
            let model = body["model"].as_str().unwrap_or("").to_owned();
            match route {
                "/api/version" => Some(json!({"version": "0.35.1"})),
                "/api/tags" => Some(json!({"models": [
                    {"name": crate::config::DEFAULT_MODEL, "digest": "a".repeat(64), "size": 7_200_000_000u64},
                    {"name": DEFAULT_VERIFIER_MODEL, "digest": "b".repeat(64), "size": 7_200_000_000u64}
                ]})),
                "/api/show" => Some(json!({"details":{"format":"gguf"},
                    "model_info":{"general.architecture":"gemma4"},
                    "capabilities":["completion","thinking"]})),
                "/api/ps" => {
                    let n = ps_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let current = state.lock().unwrap().clone();
                    Some(match current {
                        Some(name) => json!({"models": [{
                            "name": name,
                            "digest": if name == DEFAULT_VERIFIER_MODEL { "b".repeat(64) } else { "a".repeat(64) },
                            "size": 7_200_000_000u64,
                            "size_vram": if n >= cpu_only_from_call { 1_000_000_000u64 } else { 7_200_000_000u64 },
                            "context_length": 32768u32
                        }]}),
                        None => json!({"models": []}),
                    })
                }
                "/api/generate" => {
                    if body["keep_alive"] == json!(0) {
                        *state.lock().unwrap() = None;
                    } else {
                        *state.lock().unwrap() = Some(model);
                    }
                    Some(json!({"done":true,"prompt_eval_count":4,"eval_count":1}))
                }
                "/api/chat" => {
                    *state.lock().unwrap() = Some(model);
                    let payload: Value = serde_json::from_str(
                        body["messages"][1]["content"].as_str().unwrap_or("{}"),
                    )
                    .unwrap_or_else(|_| json!({}));
                    let content = if payload.get("proposed_reply").is_some() {
                        verification_content()
                    } else if payload.get("tone").is_some() {
                        json!({"body": draft_body("Test Applicant")})
                    } else {
                        verdict_content()
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

    /// The automatic-policy block codes are the operator-facing contract; each
    /// gate must name the specific reason dispatch is held.
    #[test]
    fn automatic_policy_reports_stable_block_codes() {
        let mut settings = Settings::default();
        crate::test_support::arm_automatic(&mut settings);
        let now = Utc::now();
        let account = "applicant@example.invalid";
        let email = gmail_email(
            account,
            1,
            "Your application",
            "We have decided not to move forward with your application.",
        );
        let body = draft_body(&settings.signature);

        // Missing analysis, then missing draft, are distinct early blocks.
        let mut job = Job::new(email.stub.clone(), now);
        job.email = Some(email.clone());
        let decision = automatic_policy(&job, &settings, account, now);
        assert!(
            decision
                .blocks
                .iter()
                .any(|b| b.code == AutomaticPolicyCode::LocalAnalysisMissing)
        );
        job.analysis = Some(verified_analysis(&settings, &email, &body));
        let decision = automatic_policy(&job, &settings, account, now);
        assert!(
            decision
                .blocks
                .iter()
                .any(|b| b.code == AutomaticPolicyCode::DraftMissing)
        );

        // Original content loss is its own early block.
        let bare = Job::new(email.stub.clone(), now);
        let decision = automatic_policy(&bare, &settings, account, now);
        assert!(
            decision
                .blocks
                .iter()
                .any(|b| b.code == AutomaticPolicyCode::OriginalEmailMissing)
        );

        // A reviewable-but-not-Ready rejection is held as low-confidence.
        job.draft = Some(Draft {
            body: body.clone(),
            origin: "ollama-v1".into(),
        });
        job.drafted_at = Some(now - chrono::Duration::hours(1));
        job.state = JobState::Attention;
        let decision = automatic_policy(&job, &settings, account, now);
        assert!(
            decision
                .blocks
                .iter()
                .any(|b| b.code == AutomaticPolicyCode::NotHighConfidenceRejection)
        );
        job.state = JobState::Ready;

        // Escalating drafts are held even when everything else is current.
        let hostile = "I will sue you unless you explain your assessment criteria for this advertised position in full detail and provide every note from every interview stage and the complete scoring sheet you used.\n\nRegards,\nTest Applicant";
        job.draft = Some(Draft {
            body: hostile.into(),
            origin: "ollama-v1".into(),
        });
        job.analysis = Some(verified_analysis(&settings, &email, hostile));
        let decision = automatic_policy(&job, &settings, account, now);
        assert!(
            decision
                .blocks
                .iter()
                .any(|b| b.code == AutomaticPolicyCode::DraftEscalationOrLink)
        );
        job.draft = Some(Draft {
            body: body.clone(),
            origin: "ollama-v1".into(),
        });
        job.analysis = Some(verified_analysis(&settings, &email, &body));

        // Stale independent-verifier provenance blocks under the stale
        // analysis-identity code.
        let mut verifier_settings = settings.clone();
        verifier_settings.independent_verifier_enabled = true;
        verifier_settings.verifier_model = DEFAULT_VERIFIER_MODEL.into();
        verifier_settings.verifier_model_digest = Some("b".repeat(64));
        let decision = automatic_policy(&job, &verifier_settings, account, now);
        assert!(
            decision
                .blocks
                .iter()
                .any(|b| b.code == AutomaticPolicyCode::AnalysisIdentityStale)
        );
    }

    /// Settings changes must revalidate every send gate and disarm unattended
    /// delivery whenever the model or task context moves.
    #[test]
    fn update_settings_revalidates_and_disarms_on_context_changes() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.signature = "Test Applicant".into();

        let mut rejected = e.settings.clone();
        rejected.api_allow_writes = true;
        assert!(e.update_settings(rejected).is_err());

        // Enabling delivery without send scope is refused.
        let mut send = e.settings.clone();
        send.sending_enabled = true;
        let error = e.update_settings(send).unwrap_err().to_string();
        assert!(
            error.contains("Reconnect Gmail"),
            "unexpected error: {error}"
        );

        // Entering Automatic records the enrollment time once every gate
        // passes; leaving Automatic clears the consent again.
        let server = crate::test_support::MockServer::new(|_, _| None);
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
        e.settings.model_digest = Some("a".repeat(64));
        e.settings.task_qualification = Some(TaskQualification {
            model: e.settings.model.clone(),
            digest: "a".repeat(64),
            prompt_version: PROMPT_VERSION.into(),
            context_hash: crate::config::settings_context_hash(&e.settings),
            suite_hash: crate::config::evaluation_suite_hash(),
            ollama_runtime_version: "0.35.1".into(),
            task_score: 96.0,
            fixture_count: 40,
            qualified_at: Utc::now(),
        });
        let mut automatic = e.settings.clone();
        automatic.mode = Mode::Automatic;
        automatic.automatic_confirmed = true;
        automatic.sending_enabled = true;
        e.update_settings(automatic).unwrap();
        assert_eq!(e.settings.mode, Mode::Automatic);
        assert!(e.settings.automatic_since.is_some());
        let mut manual = e.settings.clone();
        manual.mode = Mode::HumanReview;
        e.update_settings(manual).unwrap();
        assert!(!e.settings.automatic_confirmed);

        // A model change drops the digest pin and any task qualification.
        e.settings.model_digest = Some("a".repeat(64));
        let mut changed = e.settings.clone();
        changed.model = "other:model".into();
        e.update_settings(changed).unwrap();
        assert!(e.settings.model_digest.is_none());
        assert!(e.settings.task_qualification.is_none());

        // An unrelated edit keeps the pin.
        e.settings.model_digest = Some("a".repeat(64));
        let mut unrelated = e.settings.clone();
        unrelated.retention_days = 120;
        e.update_settings(unrelated).unwrap();
        assert_eq!(
            e.settings.model_digest.as_deref(),
            Some("a".repeat(64).as_str())
        );

        // A tightened age window defers review items outside it.
        e.account = "applicant@example.invalid".into();
        let mut job = seed_ready_job(&mut e, 9, Utc::now());
        job.email.as_mut().unwrap().received_at = Utc::now() - chrono::Duration::days(20);
        e.db.save(&mut job, "test.age", "aged").unwrap();
        let mut tightened = e.settings.clone();
        tightened.lookback_days = 1;
        tightened.candidate_context = "changed".into();
        e.update_settings(tightened).unwrap();
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Deferred);
    }

    /// Seed a Ready job with a complete, verified analysis payload.
    fn seed_ready_job(e: &mut Engine, n: u64, now: DateTime<Utc>) -> Job {
        let account = e.account.clone();
        let email = gmail_email(
            &account,
            n,
            "Your application — R&D Engineer",
            "Thank you for applying. We have decided not to move forward with your application.",
        );
        let body = draft_body(&e.settings.signature);
        let mut job = Job::new(email.stub.clone(), now);
        job.analysis = Some(verified_analysis(&e.settings, &email, &body));
        job.email = Some(email);
        job.draft = Some(Draft {
            body,
            origin: "ollama-v1".into(),
        });
        job.drafted_at = Some(now - chrono::Duration::hours(1));
        job.state = JobState::Ready;
        e.db.insert_stubs([job.stub.clone()], now).unwrap();
        e.db.save(&mut job, "test.seed", "seeded").unwrap();
        job
    }

    /// Model qualification and status flows must pin digests and surface
    /// stale pins instead of silently continuing with changed weights.
    #[test]
    fn model_status_and_qualification_track_the_local_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = demo(dir.path());
        let server = runtime(usize::MAX);
        e.settings.ollama_url.clone_from(&server.url);
        e.settings.signature = "Test Applicant".into();

        // Qualify pins the digest and keeps unattended delivery disabled.
        e.qualify().unwrap();
        assert_eq!(
            e.settings.model_digest.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert!(e.settings.task_qualification.is_none());

        // The pinned model reports full residency; a changed install is stale.
        e.inspect_model_status().unwrap();
        assert!(e.model.gpu_resident);
        e.settings.model_digest = Some("c".repeat(64));
        e.inspect_model_status().unwrap();
        assert!(!e.model.gpu_resident);
        assert!(e.model.message.contains("qualify again"));

        // Verifier status follows the same pin semantics.
        e.settings.model = DEFAULT_VERIFIER_MODEL.into();
        e.settings.model_digest = None;
        e.inspect_verifier_model_status().unwrap();
        assert_eq!(e.verifier_model.digest, "b".repeat(64));
        e.settings.verifier_model = DEFAULT_VERIFIER_MODEL.into();
        e.settings.verifier_model_digest = Some("c".repeat(64));
        e.inspect_verifier_model_status().unwrap();
        assert!(!e.verifier_model.gpu_resident);
        assert!(e.verifier_model.message.contains("qualify again"));
    }

    /// Automatic dispatch drives the full send gate for a qualified queue and
    /// holds (never silently skips) the message when a gate fails.
    #[test]
    fn automatic_tick_dispatches_and_holds_on_preflight_failures() {
        use crate::test_support::eligible_job;
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        crate::test_support::arm_automatic(&mut e.settings);
        let server = runtime(usize::MAX);
        e.settings.ollama_url.clone_from(&server.url);
        e.account = "applicant@example.invalid".into();

        let now = Utc::now();
        let job = eligible_job(&e.settings, &e.account, 1, now);
        e.db.insert_stubs([job.stub.clone()], now).unwrap();
        let mut job = job;
        e.db.save(&mut job, "test.seed", "seeded").unwrap();

        // Without a provider client the dispatch is held for review.
        let error = e.automatic_tick().unwrap_err().to_string();
        assert!(error.contains("Gmail"), "unexpected error: {error}");
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Attention);
        assert!(
            after
                .flags
                .iter()
                .any(|f| f.contains("Automatic dispatch held"))
        );
    }

    /// Why: the automatic branch re-validates the analysis provenance on the
    /// job as re-read at dispatch time — an analysis recorded under a
    /// different model digest must fail closed with the reason named and leave
    /// the job untouched for the operator. This is the dispatch-time gate of
    /// the layered provenance defence; the `Model changed since analysis`
    /// check behind it is defence in depth for the same invariant.
    #[test]
    fn automatic_pre_send_refuses_an_analysis_recorded_under_another_model() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        crate::test_support::arm_automatic(&mut e.settings);
        e.account = "applicant@example.invalid".into();
        let (mut job, body_hash) = seed_send_job(&mut e, 27);
        // The analysis recorded a digest the pinned model never had.
        job.analysis.as_mut().unwrap().model_digest = "c".repeat(64);
        e.db.save(&mut job, "test.seed", "provenance drift")
            .unwrap();
        let job_id = job.id.clone();
        let revision = job.revision;

        let failure = e
            .send_attempt(&job_id, revision, &body_hash, true)
            .expect_err("a drifted analysis provenance must not dispatch");
        assert!(
            failure
                .to_string()
                .contains("Automatic send conditions were not satisfied"),
            "unexpected failure: {failure}"
        );
        assert!(!failure.retryable_for_operator());
        let after = e.db.get(&job_id).unwrap();
        assert_eq!(
            after.state,
            JobState::Ready,
            "the job must be left untouched"
        );
        assert!(after.flags.is_empty(), "no flags on an untouched job");
    }

    /// Manual dispatch enforces the human-review pipeline end to end and maps
    /// every provider outcome onto the durable delivery state machine.
    #[test]
    fn manual_send_walks_the_durable_state_machine() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let now = Utc::now();
        let job = seed_ready_job(&mut e, 1, now);

        // A demo-less engine without a provider refuses cleanly.
        let error = e
            .send(
                &job.id,
                job.revision,
                &hash(&job.draft.as_ref().unwrap().body),
                false,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("Gmail"), "unexpected error: {error}");

        // Wrong approval hashes and stale revisions never reach the provider.
        let error = e
            .send(&job.id, job.revision, "bad-hash", false)
            .unwrap_err();
        assert!(error.to_string().contains("Reply changed"));
        let error = e.send(&job.id, job.revision + 3, "bad", false).unwrap_err();
        assert!(error.to_string().contains("stale"));
    }

    // =====================================================================
    // Workspace-open state machine and enterprise policy lifecycle.
    // =====================================================================

    /// Arm settings exactly like [`crate::test_support::arm_automatic`] but
    /// leave the task qualification stale, so `open` must repair it.
    fn arm_legacy_automatic(settings: &mut Settings) {
        settings.mode = Mode::Automatic;
        settings.sending_enabled = true;
        settings.automatic_confirmed = true;
        settings.automatic_since = Some(Utc::now());
    }

    /// Reopen a workspace whose previous session marker survived a crash and
    /// assert the fail-closed disarm is persisted and audited.
    #[test]
    fn open_disarms_unattended_delivery_after_unclean_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let mut e = live(dir.path());
            crate::test_support::arm_automatic(&mut e.settings);
            e.db.set_meta("settings", &e.settings).unwrap();
            crate::vault::vault_id(dir.path()).unwrap()
        };
        std::fs::write(dir.path().join(".runtime-session.json"), b"not-json").unwrap();
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let e = live(dir.path());
        assert!(!e.settings.sending_enabled);
        assert!(!e.settings.automatic_confirmed);
        let events = e.db.events(0, 500).unwrap();
        assert!(
            events
                .iter()
                .any(|ev| ev.kind == "security.unclean_shutdown_detected"),
            "unclean shutdown must be audited"
        );
        assert!(
            events
                .iter()
                .any(|ev| ev.detail.contains("ended uncleanly")),
            "the persisted disarm must name the unclean session"
        );
    }

    /// A workspace restored from an offline backup must reopen with delivery
    /// disarmed, audit the restore, and drop the one-shot re-arm marker.
    #[test]
    fn open_restored_workspace_requires_explicit_reauthorization() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let mut e = live(dir.path());
            crate::test_support::arm_automatic(&mut e.settings);
            e.db.set_meta("settings", &e.settings).unwrap();
            crate::vault::vault_id(dir.path()).unwrap()
        };
        std::fs::write(
            dir.path().join(".restore-rearm-required"),
            b"restore-rearm:v1\n",
        )
        .unwrap();
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let e = live(dir.path());
        assert!(!e.settings.sending_enabled);
        assert!(!e.settings.automatic_confirmed);
        let events = e.db.events(0, 500).unwrap();
        assert!(
            events
                .iter()
                .any(|ev| ev.kind == "security.restore_rearm_required"),
            "offline restore must be audited"
        );
        assert!(
            !dir.path().join(".restore-rearm-required").exists(),
            "the one-shot marker must be consumed"
        );
    }

    /// Settings persisted in the legacy v1 format migrate on open: the
    /// obsolete qualification is dropped and delivery disarms fail-closed.
    #[test]
    fn open_migrates_legacy_settings_format() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let mut e = live(dir.path());
            crate::test_support::arm_automatic(&mut e.settings);
            e.settings.settings_format_version = 1;
            e.settings.independent_verifier_enabled = true;
            e.db.set_meta("settings", &e.settings).unwrap();
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let e = live(dir.path());
        assert!(e.settings.task_qualification.is_none());
        assert!(!e.settings.independent_verifier_enabled);
        assert!(!e.settings.sending_enabled);
        let events = e.db.events(0, 500).unwrap();
        assert!(
            events.iter().any(|ev| ev.kind == "settings.migrated"
                && ev.detail.contains("migrated from format v1")),
            "the format migration must be audited"
        );
    }

    /// Legacy Automatic mode without a current qualification is disabled and
    /// audited; aged review items outside the age window are deferred at open.
    #[test]
    fn open_repairs_legacy_automatic_state_and_defers_aged_review() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let (vault, aged_id) = {
            let mut e = live(dir.path());
            arm_legacy_automatic(&mut e.settings);
            e.db.set_meta("settings", &e.settings).unwrap();
            e.db.set_meta("account", &"applicant@example.invalid".to_string())
                .unwrap();
            e.account = "applicant@example.invalid".into();
            let now = Utc::now();
            let mut job = seed_ready_job(&mut e, 7, now);
            job.email.as_mut().unwrap().received_at = now - chrono::Duration::days(20);
            e.db.save(&mut job, "test.age", "aged").unwrap();
            (crate::vault::vault_id(dir.path()).unwrap(), job.id.clone())
        };
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let e = live(dir.path());
        assert!(!e.settings.sending_enabled);
        assert_eq!(e.settings.mode, Mode::HumanReview);
        let events = e.db.events(0, 500).unwrap();
        assert!(
            events.iter().any(|ev| ev
                .detail
                .contains("Legacy Automatic mode without current qualification")),
            "the legacy-state repair must be audited"
        );
        let aged = e.db.get(&aged_id).unwrap();
        assert_eq!(aged.state, JobState::Deferred);
    }

    /// Open under a v2 enterprise policy: restrictive enforcement and the
    /// revision floor are committed together in one audited transaction.
    #[test]
    fn open_accepts_enterprise_policy_with_revision_floor() {
        use crate::policy::EnterprisePolicy;
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let e = live(dir.path());
            drop(e);
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let policy = crate::test_support::loaded_policy(
            "digest-a",
            EnterprisePolicy {
                version: 2,
                policy_id: Some("corp.policy".into()),
                revision: Some(3),
                force_human_review: true,
                ..Default::default()
            },
        );
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let e = crate::test_support::with_policy(Some(policy), || {
            let e = live(dir.path());
            // Restrictive policy is applied and delivery stays disarmed.
            assert_eq!(e.settings.mode, Mode::HumanReview);
            assert!(!e.settings.sending_enabled);
            let floor: serde_json::Value =
                e.db.meta("enterprise_policy_revision_floor")
                    .unwrap()
                    .unwrap();
            assert_eq!(floor["policies"]["corp.policy"]["revision"], 3);
            let events = e.db.events(0, 500).unwrap();
            assert!(
                events.iter().any(|ev| ev.kind == "policy.accepted"
                    && ev.detail.contains("policy_id=corp.policy")
                    && ev.detail.contains("revision=3")),
                "policy acceptance must record the pinned identity"
            );
            e
        });
        assert!(e.enterprise_policy.is_some());
    }

    /// Why: `update_settings` must route every candidate through the active
    /// enterprise policy before anything is persisted — the policy clamps
    /// out-of-range values and a refused change must leave the durable
    /// settings untouched. Skipping enforcement would let a local edit
    /// silently override enterprise constraints.
    #[test]
    fn update_settings_enforces_enterprise_policy_before_persisting() {
        use crate::policy::EnterprisePolicy;
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let e = live(dir.path());
            drop(e);
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let policy = crate::test_support::loaded_policy(
            "digest-clamp",
            EnterprisePolicy {
                version: 1,
                max_daily_send_limit: Some(2),
                ..Default::default()
            },
        );
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let mut e = crate::test_support::with_policy(Some(policy), || live(dir.path()));
        assert!(e.enterprise_policy.is_some(), "policy must be active");

        let mut candidate = e.settings.clone();
        candidate.daily_send_limit = 50;
        e.update_settings(candidate).unwrap();
        assert_eq!(
            e.settings.daily_send_limit, 2,
            "the policy clamp must apply before persistence"
        );
    }

    /// Why: a settings change naming a model outside the enterprise
    /// allow-list must be refused by the policy gate and must not reach the
    /// persisted settings; a silently accepted model swap would change the
    /// whole classification pipeline under enterprise control.
    #[test]
    fn update_settings_refuses_models_the_policy_does_not_approve() {
        use crate::policy::EnterprisePolicy;
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let e = live(dir.path());
            drop(e);
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let policy = crate::test_support::loaded_policy(
            "digest-allow-list",
            EnterprisePolicy {
                version: 1,
                allowed_models: vec!["approved-model".into()],
                ..Default::default()
            },
        );
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let mut e = crate::test_support::with_policy(Some(policy), || live(dir.path()));
        assert_eq!(
            e.settings.model, "approved-model",
            "startup must repair to the approved model"
        );

        let mut refused = e.settings.clone();
        refused.model = "unapproved-model".into();
        let error = e.update_settings(refused).unwrap_err().to_string();
        assert!(
            error.contains("Selected model is not approved by enterprise policy"),
            "unexpected error: {error}"
        );
        assert_eq!(
            e.settings.model, "approved-model",
            "the refused change must not reach the persisted settings"
        );
    }

    /// Reload semantics: restrictive changes apply and are audited, identical
    /// digests are no-ops, removal never relaxes anything, and revision
    /// rollback or same-revision tampering is rejected.
    #[test]
    fn reload_enterprise_policy_tightens_but_never_relaxes() {
        use crate::policy::EnterprisePolicy;
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );

        // Demo mode never consults the machine-wide policy.
        let mut d = demo(dir.path());
        assert!(!d.reload_enterprise_policy().unwrap());

        // No policy anywhere: reload is a reported no-op.
        assert!(!crate::test_support::with_policy(None, || {
            e.reload_enterprise_policy().unwrap()
        }));

        // A restrictive policy disarms live delivery and records the reload.
        e.settings.sending_enabled = true;
        e.settings.mode = Mode::Automatic;
        let restrictive = crate::test_support::loaded_policy(
            "digest-a",
            EnterprisePolicy {
                version: 1,
                prohibit_sending: true,
                ..Default::default()
            },
        );
        assert!(crate::test_support::with_policy(
            Some(restrictive.clone()),
            || { e.reload_enterprise_policy().unwrap() }
        ));
        assert!(!e.settings.sending_enabled);
        assert_eq!(e.settings.mode, Mode::HumanReview);
        assert!(!e.model.installed, "model status must be revalidated");
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "policy.reloaded"
            && ev.detail.contains("persisted settings were restricted")));

        // The same digest is a no-op.
        assert!(!crate::test_support::with_policy(Some(restrictive), || {
            e.reload_enterprise_policy().unwrap()
        }));

        // Removing the policy reports the change but never relaxes settings.
        assert!(crate::test_support::with_policy(None, || {
            e.reload_enterprise_policy().unwrap()
        }));
        assert!(!e.settings.sending_enabled);
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| {
            ev.detail
                .contains("existing restrictive settings were not relaxed automatically")
        }));

        // v2 lifecycle: revision floor staged on accept, rollback rejected,
        // and same-revision content swaps are rejected.
        let v2 = |revision: u64, digest: &str| {
            crate::test_support::loaded_policy(
                digest,
                EnterprisePolicy {
                    version: 2,
                    policy_id: Some("corp.policy".into()),
                    revision: Some(revision),
                    ..Default::default()
                },
            )
        };
        assert!(crate::test_support::with_policy(
            Some(v2(2, "digest-b")),
            || { e.reload_enterprise_policy().unwrap() }
        ));
        let error = crate::test_support::with_policy(Some(v2(1, "digest-c")), || {
            e.reload_enterprise_policy().unwrap_err().to_string()
        });
        assert!(error.contains("rollback rejected"), "unexpected: {error}");
        let error = crate::test_support::with_policy(Some(v2(2, "digest-d")), || {
            e.reload_enterprise_policy().unwrap_err().to_string()
        });
        assert!(
            error.contains("without increasing revision"),
            "unexpected: {error}"
        );
        assert!(crate::test_support::with_policy(
            Some(v2(3, "digest-e")),
            || { e.reload_enterprise_policy().unwrap() }
        ));

        // A policy demanding protected audit anchoring without an anchor fails
        // closed at reload.
        let anchored = crate::test_support::loaded_policy(
            "digest-f",
            EnterprisePolicy {
                version: 1,
                require_external_audit_anchor: true,
                ..Default::default()
            },
        );
        let error = crate::test_support::with_policy(Some(anchored), || {
            e.reload_enterprise_policy().unwrap_err().to_string()
        });
        assert!(
            error.contains("independently protected audit anchoring"),
            "unexpected: {error}"
        );
    }

    // =====================================================================
    // Queue processing and the durable dispatch state machine.
    // =====================================================================

    fn test_creds() -> crate::oauth::Credentials {
        crate::oauth::Credentials {
            client_id: "id".into(),
            client_secret: "secret".into(),
            refresh_token: "refresh".into(),
            can_send: true,
        }
    }

    /// Seed one queued message (identity only) and return its synthetic email
    /// content for the provider mock.
    fn queue_message(e: &mut Engine, n: u64) -> (Job, crate::test_support::MockServer) {
        let now = Utc::now();
        let email = gmail_email(
            &e.account,
            n,
            "Your application — R&D Engineer",
            "Thank you for applying. We have decided not to move forward with your application.",
        );
        let job = Job::new(email.stub.clone(), now);
        e.db.insert_stubs([job.stub.clone()], now).unwrap();
        let gmail = crate::test_support::gmail_server(
            &e.account,
            vec![email],
            crate::test_support::SendOutcome::Deliver(format!("sent{n:021}")),
        );
        (job, gmail)
    }

    /// Without a provider, a pinned model or (in demo mode) real mail,
    /// `process_one` refuses to touch the queue.
    #[test]
    fn process_one_short_circuits_unavailable_runtimes() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut d = demo(dir.path());
        assert!(!d.process_one().unwrap());

        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.account = "applicant@example.invalid".into();
        // No provider client yet.
        assert!(!e.process_one().unwrap());
        // Provider attached but no pinned digest: still a no-op.
        let gmail = crate::test_support::gmail_server(
            &e.account,
            vec![],
            crate::test_support::SendOutcome::Deliver("sent00000000000000000001".into()),
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &gmail.url,
            &gmail.url,
        ));
        assert!(!e.process_one().unwrap());

        // A dead runtime is a global failure: the queue stays intact.
        e.settings.model_digest = Some("a".repeat(64));
        e.settings.ollama_url = "http://127.0.0.1:9".into();
        let error = e.process_one().unwrap_err().to_string();
        assert!(
            error.contains("Local Ollama is unavailable"),
            "unexpected: {error}"
        );

        // A runtime without the pinned model fails before dequeue as well.
        let bare = crate::test_support::ollama_runtime(vec![], "Test Applicant", |_| {
            crate::test_support::verdict_category("other")
        });
        e.settings.ollama_url.clone_from(&bare.url);
        let error = e.process_one().unwrap_err().to_string();
        assert!(
            error.contains("Pinned local model is unavailable"),
            "unexpected: {error}"
        );

        // A healthy runtime with an empty queue reports nothing to do.
        let runtime = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| crate::test_support::verdict_category("other"),
        );
        e.settings.ollama_url.clone_from(&runtime.url);
        assert!(!e.process_one().unwrap());
    }

    /// The runtime profile report lands wherever the operator asked, even
    /// under directories that do not exist yet.
    ///
    /// Why: `rr profile-model --out <fresh>/nested/profile.json` is invoked
    /// by scripted tooling into new directories — failing on the first run
    /// because a parent is absent would break every cold invocation.
    #[test]
    fn profile_model_runtime_to_creates_the_report_path() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        let runtime = crate::test_support::ollama_runtime(
            vec![(e.settings.model.clone(), "a".repeat(64))],
            "Test Applicant",
            |_| crate::test_support::verdict_category("other"),
        );
        e.settings.ollama_url.clone_from(&runtime.url);
        let out = dir.path().join("fresh").join("nested").join("profile.json");
        e.profile_model_runtime_to(&out)
            .expect("profile is written");
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(report.get("schema_version"), Some(&serde_json::json!(1)));
        for pass in [
            "cold_pipeline",
            "warm_repeat_pipeline",
            "near_context_pipeline",
        ] {
            assert!(report.get(pass).is_some(), "{pass} must be measured");
        }
    }

    /// The real login path (outside the test seam) fails closed when the
    /// OAuth client file is missing.
    ///
    /// Why: credentials must only ever come from the consent flow; a bad
    /// client file has to propagate before any browser or listener is
    /// touched, never fabricate a connection.
    #[test]
    fn login_client_without_a_client_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-oauth-client.json");
        let stop = AtomicBool::new(false);
        assert!(Engine::login_client(&missing, false, &stop).is_err());
    }

    /// One queued message per run: provider fetch outcomes route each message
    /// to its durable state (analyzed, gone, malformed) without stalling the
    /// rest of the queue.
    #[test]
    fn process_one_routes_provider_fetch_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        e.settings.model_digest = Some("a".repeat(64));
        let runtime = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| {
                crate::test_support::verdict(
                    "We have decided not to move forward with your application.",
                )
            },
        );
        e.settings.ollama_url.clone_from(&runtime.url);

        // Provider has no record of the message: it becomes Other with the
        // reason preserved.
        let (job, _gmail) = {
            let now = Utc::now();
            let email = gmail_email(
                &e.account,
                1,
                "Your application — R&D Engineer",
                "Thank you for applying. We have decided not to move forward with your application.",
            );
            let job = Job::new(email.stub.clone(), now);
            e.db.insert_stubs([job.stub.clone()], now).unwrap();
            let empty = crate::test_support::gmail_server(
                &e.account,
                vec![],
                crate::test_support::SendOutcome::Deliver("sent00000000000000000001".into()),
            );
            e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
                test_creds(),
                &empty.url,
                &empty.url,
            ));
            (job, empty)
        };
        assert!(e.process_one().unwrap());
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Other);
        let events = e.db.events(0, 500).unwrap();
        assert!(
            events
                .iter()
                .any(|ev| ev.kind == "email.unavailable" && ev.detail.contains("no longer exists")),
            "the vanished-message outcome must be audited"
        );

        // A provider message that cannot be parsed safely is held for humans.
        let mut broken = gmail_email(
            &e.account,
            2,
            "Your application",
            "We have decided not to move forward with your application.",
        );
        broken.message_id = "not-a-message-id".into();
        let mut resource = crate::test_support::gmail_resource(&broken);
        resource["raw"] = serde_json::json!("!!!not-base64!!!");
        let broken_gmail = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            if route == "/" {
                return answer(200, crate::test_support::token_ok("test-scope"));
            }
            if route.starts_with("/messages/") {
                return answer(200, resource.clone());
            }
            None
        });
        let now = Utc::now();
        let job2 = Job::new(broken.stub.clone(), now);
        e.db.insert_stubs([job2.stub.clone()], now).unwrap();
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &broken_gmail.url,
            &broken_gmail.url,
        ));
        assert!(e.process_one().unwrap());
        let after = e.db.get(&job2.id).unwrap();
        assert_eq!(after.state, JobState::Attention);
        let failure = e.db.processing_failure(&job2.id).unwrap().unwrap();
        assert_eq!(failure.attempts, 1);
        assert!(failure.retry_exhausted);

        // A provider outage is global: it must surface as an error rather than
        // consume one message's retry budget.
        let outage = MockServer::new_raw(move |route, _| match route {
            "/" => Some((200, crate::test_support::token_ok("test-scope").to_string())),
            _ => Some((500, r#"{"error":{"status":"UNAVAILABLE"}}"#.into())),
        });
        let job3 = {
            let email = gmail_email(
                &e.account,
                3,
                "Your application",
                "We have decided not to move forward with your application.",
            );
            let job = Job::new(email.stub.clone(), now);
            e.db.insert_stubs([job.stub.clone()], now).unwrap();
            job
        };
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &outage.url,
            &outage.url,
        ));
        let error = e.process_one().unwrap_err().to_string();
        assert!(
            error.contains("fetch returned HTTP 500"),
            "unexpected: {error}"
        );
        assert_eq!(e.db.get(&job3.id).unwrap().state, JobState::Queued);
    }

    /// Analysis outcomes land in the review states they deserve, and analysis
    /// failures retry with an isolated per-message budget before escalating.
    #[test]
    fn process_one_classifies_and_isolates_analysis_failures() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        e.settings.model_digest = Some("a".repeat(64));
        e.settings.lookback_days = 7;

        // A high-confidence verified rejection is Ready for review.
        let runtime = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| {
                crate::test_support::verdict(
                    "We have decided not to move forward with your application.",
                )
            },
        );
        e.settings.ollama_url.clone_from(&runtime.url);
        let (job, gmail) = queue_message(&mut e, 1);
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &gmail.url,
            &gmail.url,
        ));
        assert!(e.process_one().unwrap());
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Ready);
        assert!(after.draft.is_some());
        assert!(
            after
                .analysis
                .as_ref()
                .unwrap()
                .verified_draft_hash
                .is_some()
        );

        // An uncertain message is held for attention, a non-rejection is
        // discarded with its content released, an aged message is deferred and
        // provider-side folders are excluded.
        let uncertain = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| crate::test_support::verdict_category("uncertain"),
        );
        e.settings.ollama_url.clone_from(&uncertain.url);
        let (job2, gmail2) = queue_message(&mut e, 2);
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &gmail2.url,
            &gmail2.url,
        ));
        assert!(e.process_one().unwrap());
        assert_eq!(e.db.get(&job2.id).unwrap().state, JobState::Attention);

        let other = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| crate::test_support::verdict_category("other"),
        );
        e.settings.ollama_url.clone_from(&other.url);
        let (job3, gmail3) = queue_message(&mut e, 3);
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &gmail3.url,
            &gmail3.url,
        ));
        assert!(e.process_one().unwrap());
        let after = e.db.get(&job3.id).unwrap();
        assert_eq!(after.state, JobState::Other);
        assert!(after.email.is_none() && after.analysis.is_none());

        // Outside the age window: identity kept, content released.
        let mut aged = gmail_email(
            &e.account,
            4,
            "Your application",
            "We have decided not to move forward with your application.",
        );
        aged.received_at = Utc::now() - chrono::Duration::days(20);
        let aged_gmail = crate::test_support::gmail_server(
            &e.account,
            vec![aged.clone()],
            crate::test_support::SendOutcome::Deliver("sent00000000000000000004".into()),
        );
        let job4 = Job::new(aged.stub.clone(), Utc::now());
        e.db.insert_stubs([job4.stub.clone()], Utc::now()).unwrap();
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &aged_gmail.url,
            &aged_gmail.url,
        ));
        assert!(e.process_one().unwrap());
        let after = e.db.get(&job4.id).unwrap();
        assert_eq!(after.state, JobState::Deferred);
        assert!(after.email.is_none());

        // Excluded provider folders never reach analysis.
        let mut excluded = gmail_email(
            &e.account,
            5,
            "Your application",
            "We have decided not to move forward with your application.",
        );
        excluded.labels = vec!["SENT".into()];
        let excluded_gmail = crate::test_support::gmail_server(
            &e.account,
            vec![excluded.clone()],
            crate::test_support::SendOutcome::Deliver("sent00000000000000000005".into()),
        );
        let job5 = Job::new(excluded.stub.clone(), Utc::now());
        e.db.insert_stubs([job5.stub.clone()], Utc::now()).unwrap();
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &excluded_gmail.url,
            &excluded_gmail.url,
        ));
        assert!(e.process_one().unwrap());
        let after = e.db.get(&job5.id).unwrap();
        assert_eq!(after.state, JobState::Other);
        let events = e.db.events(0, 500).unwrap();
        assert!(
            events
                .iter()
                .any(|ev| ev.kind == "email.excluded"
                    && ev.detail.contains("Provider folder excluded")),
            "folder exclusions must be audited"
        );
    }

    /// Per-message analysis failures are isolated with a retry budget and
    /// escalate to human attention only after it is exhausted.
    #[test]
    fn process_one_retries_analysis_before_escalating() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        e.settings.model_digest = Some("a".repeat(64));
        let broken = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| serde_json::json!("not-a-verdict"),
        );
        e.settings.ollama_url.clone_from(&broken.url);
        let (job, gmail) = queue_message(&mut e, 1);
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &gmail.url,
            &gmail.url,
        ));
        assert!(e.process_one().unwrap());
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.attempts, 1);
        assert!(after.retry_at > Utc::now().timestamp());
        assert!(
            after
                .flags
                .iter()
                .any(|f| f.contains("Analysis unavailable"))
        );
        let failure = e.db.processing_failure(&job.id).unwrap().unwrap();
        assert!(!failure.retry_exhausted);

        // With the budget already spent the message escalates to a human.
        let mut current = e.db.get(&job.id).unwrap();
        current.attempts = 2;
        current.retry_at = 0;
        e.db.save(&mut current, "test.budget", "spent").unwrap();
        assert!(e.process_one().unwrap());
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Attention);
        assert_eq!(after.retry_at, 0);
        let failure = e.db.processing_failure(&job.id).unwrap().unwrap();
        assert_eq!(failure.attempts, 3);
        assert!(failure.retry_exhausted);
    }

    /// Seed a Ready send candidate and return it with its approval hash.
    fn seed_send_job(e: &mut Engine, n: u64) -> (Job, String) {
        let job = seed_ready_job(e, n, Utc::now());
        let body_hash = hash(&job.draft.as_ref().unwrap().body);
        (job, body_hash)
    }

    /// Every manual-dispatch preflight gate fails closed with its own reason
    /// and none of them ever reaches the provider or marks the job sent.
    #[test]
    fn every_manual_dispatch_preflight_gate_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let base = e.settings.clone();
        let gmail = crate::test_support::gmail_server(
            &e.account,
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &gmail.url,
            &gmail.url,
        ));
        let mut keep: Vec<MockServer> = Vec::new();
        let mut n = 100u64;

        macro_rules! gate {
            ($message:expr, $perturb:expr) => {{
                e.settings.clone_from(&base);
                e.paused.store(false, Ordering::SeqCst);
                e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
                    test_creds(),
                    &gmail.url,
                    &gmail.url,
                ));
                n += 1;
                let (mut job, body_hash) = seed_send_job(&mut e, n);
                ($perturb)(&mut e, &mut job, &mut keep);
                let error = e
                    .send(&job.id, job.revision, &body_hash, false)
                    .unwrap_err()
                    .to_string();
                assert!(
                    error.contains($message),
                    "expected {:?} in {:?}",
                    $message,
                    error
                );
                let after = e.db.get(&job.id).unwrap();
                assert_ne!(
                    after.state,
                    JobState::Sent,
                    "gate {:?} must never dispatch",
                    $message
                );
            }};
        }

        gate!(
            "Paused or stopping",
            |e: &mut Engine, _: &mut Job, _: &mut Vec<MockServer>| {
                e.paused.store(true, Ordering::SeqCst);
            }
        );
        gate!(
            "Sending is disabled",
            |e: &mut Engine, _: &mut Job, _: &mut Vec<MockServer>| {
                e.settings.sending_enabled = false;
            }
        );
        gate!(
            "Manual sending is only available in Human review mode",
            |e: &mut Engine, _: &mut Job, _: &mut Vec<MockServer>| {
                e.settings.mode = Mode::Automatic;
            }
        );
        gate!(
            "Approval is stale or message is not reviewable",
            |_e: &mut Engine, job: &mut Job, _: &mut Vec<MockServer>| {
                job.state = JobState::Dismissed;
                _e.db.save(job, "test.dismiss", "held").unwrap();
            }
        );
        gate!("Reply changed after confirmation", |_e: &mut Engine,
                                                   job: &mut Job,
                                                   _: &mut Vec<
            MockServer,
        >| {
            // The stored draft is swapped after the approval hash was taken.
            let mut edited = job.draft.clone().unwrap();
            edited.body = crate::test_support::draft_body("Someone Else");
            job.draft = Some(edited);
            _e.db.save(job, "test.edit", "swapped").unwrap();
        });
        gate!(
            "Original email is missing",
            |_e: &mut Engine, job: &mut Job, _: &mut Vec<MockServer>| {
                job.email = None;
                _e.db.save(job, "test.drop", "dropped").unwrap();
            }
        );
        gate!(
            "Draft is missing",
            |_e: &mut Engine, job: &mut Job, _: &mut Vec<MockServer>| {
                job.draft = None;
                _e.db.save(job, "test.nodraft", "dropped").unwrap();
            }
        );
        gate!(
            "Message is blocked by mailbox safety checks",
            |_e: &mut Engine, job: &mut Job, _: &mut Vec<MockServer>| {
                job.email.as_mut().unwrap().message_id = "invalid-message-id".into();
                _e.db.save(job, "test.block", "blocked").unwrap();
            }
        );
        gate!(
            "Original message is outside the selected age window",
            |_e: &mut Engine, job: &mut Job, _: &mut Vec<MockServer>| {
                job.email.as_mut().unwrap().received_at = Utc::now() - chrono::Duration::days(20);
                _e.db.save(job, "test.age", "aged").unwrap();
            }
        );
        gate!(
            "Gmail is not connected",
            |e: &mut Engine, _: &mut Job, _: &mut Vec<MockServer>| {
                e.mail = None;
            }
        );
        gate!("Google send permission is missing", |e: &mut Engine,
                                                    _: &mut Job,
                                                    _: &mut Vec<
            MockServer,
        >| {
            let creds = crate::oauth::Credentials {
                client_id: "id".into(),
                client_secret: "secret".into(),
                refresh_token: "refresh".into(),
                can_send: false,
            };
            e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
                creds, &gmail.url, &gmail.url,
            ));
        });
        gate!(
            "Connected account changed",
            |e: &mut Engine, _: &mut Job, keep: &mut Vec<MockServer>| {
                let foreign = crate::test_support::gmail_server(
                    "other@example.invalid",
                    vec![],
                    crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
                );
                e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
                    test_creds(),
                    &foreign.url,
                    &foreign.url,
                ));
                keep.push(foreign);
            }
        );
        gate!("Original message no longer exists", |_e: &mut Engine,
                                                    _job: &mut Job,
                                                    _: &mut Vec<
            MockServer,
        >| {});
        // Automatic dispatch has its own gates after the shared preflight.
        {
            e.settings.clone_from(&base);
            n += 1;
            let (mut job, body_hash) = seed_send_job(&mut e, n);
            job.state = JobState::Attention;
            e.db.save(&mut job, "test.hold", "held").unwrap();
            let error = e
                .send(&job.id, job.revision, &body_hash, true)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("Automatic send conditions were not satisfied"),
                "unexpected: {error}"
            );
        }

        // Stale approvals fail before any gate above is consulted.
        let (job, body_hash) = seed_send_job(&mut e, n + 1);
        let error = e
            .send(&job.id, job.revision + 5, &body_hash, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("stale"), "unexpected: {error}");
    }

    /// Dispatch-time provider reality checks (changed content, dead thread,
    /// newer conversation activity, invalid timestamps) block the send.
    #[test]
    fn provider_reality_checks_block_stale_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let (job, body_hash) = seed_send_job(&mut e, 1);
        let email = job.email.clone().unwrap();
        let mut keep: Vec<MockServer> = Vec::new();

        // The original message changed after review.
        let mut altered = email.clone();
        altered.text = "We regret to inform you that this text was edited.".into();
        let altered_resource = crate::test_support::gmail_resource(&altered);
        let thread = crate::test_support::gmail_thread(&email);
        let changed = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, crate::test_support::token_ok("test-scope")),
                "/profile" => answer(
                    200,
                    crate::test_support::gmail_profile("applicant@example.invalid"),
                ),
                p if p.starts_with("/messages/") => answer(200, altered_resource.clone()),
                p if p.starts_with("/threads/") => answer(200, thread.clone()),
                _ => None,
            }
        });
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &changed.url,
            &changed.url,
        ));
        keep.push(changed);
        let error = e
            .send(&job.id, job.revision, &body_hash, false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Original message changed"),
            "unexpected: {error}"
        );

        // The conversation itself is gone.
        let resource = crate::test_support::gmail_resource(&email);
        let gone = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, crate::test_support::token_ok("test-scope")),
                "/profile" => answer(
                    200,
                    crate::test_support::gmail_profile("applicant@example.invalid"),
                ),
                p if p.starts_with("/messages/") => answer(200, resource.clone()),
                _ => None,
            }
        });
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &gone.url,
            &gone.url,
        ));
        keep.push(gone);
        let error = e
            .send(&job.id, job.revision, &body_hash, false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("conversation preflight is temporarily unavailable"),
            "unexpected: {error}"
        );

        // The thread no longer contains the reviewed message.
        let resource = crate::test_support::gmail_resource(&email);
        let stranger_thread = serde_json::json!({"messages": [{
            "id": "msg999999999999999999999",
            "internalDate": email.received_at.timestamp_millis().to_string(),
            "labelIds": ["INBOX"],
        }]});
        let stranger = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, crate::test_support::token_ok("test-scope")),
                "/profile" => answer(
                    200,
                    crate::test_support::gmail_profile("applicant@example.invalid"),
                ),
                p if p.starts_with("/messages/") => answer(200, resource.clone()),
                p if p.starts_with("/threads/") => answer(200, stranger_thread.clone()),
                _ => None,
            }
        });
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &stranger.url,
            &stranger.url,
        ));
        keep.push(stranger);
        let error = e
            .send(&job.id, job.revision, &body_hash, false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no longer in the conversation"),
            "unexpected: {error}"
        );

        // Newer thread activity requires re-review before replying.
        let resource = crate::test_support::gmail_resource(&email);
        let busy_thread = serde_json::json!({"messages": [
            {"id": email.stub.provider_id,
             "internalDate": email.received_at.timestamp_millis().to_string(),
             "labelIds": ["INBOX"]},
            {"id": "msg888888888888888888888",
             "internalDate": (email.received_at.timestamp_millis() + 60_000).to_string(),
             "labelIds": ["INBOX"]},
        ]});
        let busy = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, crate::test_support::token_ok("test-scope")),
                "/profile" => answer(
                    200,
                    crate::test_support::gmail_profile("applicant@example.invalid"),
                ),
                p if p.starts_with("/messages/") => answer(200, resource.clone()),
                p if p.starts_with("/threads/") => answer(200, busy_thread.clone()),
                _ => None,
            }
        });
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &busy.url,
            &busy.url,
        ));
        keep.push(busy);
        let error = e
            .send(&job.id, job.revision, &body_hash, false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Newer conversation activity exists"),
            "unexpected: {error}"
        );

        // Unparseable provider timestamps fail closed.
        let resource = crate::test_support::gmail_resource(&email);
        let bogus_thread = serde_json::json!({"messages": [
            {"id": email.stub.provider_id,
             "internalDate": email.received_at.timestamp_millis().to_string(),
             "labelIds": ["INBOX"]},
            {"id": "msg777777777777777777777",
             "internalDate": "not-a-timestamp",
             "labelIds": ["INBOX"]},
        ]});
        let bogus = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, crate::test_support::token_ok("test-scope")),
                "/profile" => answer(
                    200,
                    crate::test_support::gmail_profile("applicant@example.invalid"),
                ),
                p if p.starts_with("/messages/") => answer(200, resource.clone()),
                p if p.starts_with("/threads/") => answer(200, bogus_thread.clone()),
                _ => None,
            }
        });
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &bogus.url,
            &bogus.url,
        ));
        keep.push(bogus);
        let error = e
            .send(&job.id, job.revision, &body_hash, false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("invalid provider timestamp"),
            "unexpected: {error}"
        );
        // No provider outcome ever dispatched anything.
        assert_ne!(e.db.get(&job.id).unwrap().state, JobState::Sent);
    }

    /// Provider send outcomes map onto the durable delivery states: rejection
    /// returns the message to review, ambiguity marks Uncertain, acceptance
    /// marks Sent exactly once.
    #[test]
    fn provider_send_outcomes_map_onto_delivery_states() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();

        // Definitive rejection: nothing was accepted, review resumes.
        let (job, body_hash) = seed_send_job(&mut e, 1);
        let email = job.email.clone().unwrap();
        let rejecting = crate::test_support::gmail_server(
            &e.account,
            vec![email.clone()],
            crate::test_support::SendOutcome::Reject,
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &rejecting.url,
            &rejecting.url,
        ));
        let error = e
            .send(&job.id, job.revision, &body_hash, false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Gmail rejected the send request"),
            "unexpected: {error}"
        );
        let after = e.db.get(&job.id).unwrap();
        assert!(after.state.reviewable(), "state: {:?}", after.state);
        assert!(after.provider_sent_id.is_none());

        // Ambiguous transport outcome: the delivery is Uncertain and must be
        // reconciled, never retried blindly.
        let (job2, body_hash2) = seed_send_job(&mut e, 2);
        let email2 = job2.email.clone().unwrap();
        let flaky = crate::test_support::gmail_server(
            &e.account,
            vec![email2.clone()],
            crate::test_support::SendOutcome::Uncertain,
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &flaky.url,
            &flaky.url,
        ));
        let error = e
            .send(&job2.id, job2.revision, &body_hash2, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Do not resend"), "unexpected: {error}");
        let after = e.db.get(&job2.id).unwrap();
        assert_eq!(after.state, JobState::Uncertain);

        // Acceptance marks Sent with the provider identity.
        let (job3, body_hash3) = seed_send_job(&mut e, 3);
        let email3 = job3.email.clone().unwrap();
        let accepting = crate::test_support::gmail_server(
            &e.account,
            vec![email3.clone()],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000003".into()),
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &accepting.url,
            &accepting.url,
        ));
        e.send(&job3.id, job3.revision, &body_hash3, false).unwrap();
        let after = e.db.get(&job3.id).unwrap();
        assert_eq!(after.state, JobState::Sent);
        assert_eq!(
            after.provider_sent_id.as_deref(),
            Some("sent000000000000000000003")
        );
        assert!(e.db.has_dispatch_attempt_event(&job3.id).unwrap());
    }

    /// Reservation lifecycle under gate failures: the emergency stop and the
    /// protected audit checkpoint each release the reservation or record the
    /// exact delivery truth, never leaving a phantom send.
    #[test]
    fn reservation_lifecycle_survives_gate_failures() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();

        let run = |e: &mut Engine,
                   n: u64,
                   dispatch_script: Vec<bool>,
                   audit_script: Vec<bool>,
                   paused_mid_send: bool|
         -> (String, Job) {
            let (job, body_hash) = seed_send_job(e, n);
            let email = job.email.clone().unwrap();
            let accepting = crate::test_support::gmail_server(
                &e.account,
                vec![email],
                crate::test_support::SendOutcome::Deliver(format!("sent{n:021}")),
            );
            e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
                test_creds(),
                &accepting.url,
                &accepting.url,
            ));
            let dispatch_calls = std::sync::atomic::AtomicUsize::new(0);
            let audit_calls = std::sync::atomic::AtomicUsize::new(0);
            let paused = e.paused.clone();
            let dispatch: crate::test_support::Gate = std::sync::Arc::new(move || {
                let step = dispatch_calls.fetch_add(1, Ordering::SeqCst);
                if dispatch_script.get(step).copied().unwrap_or(true) {
                    Ok(())
                } else {
                    anyhow::bail!("synthetic enterprise emergency stop")
                }
            });
            let audit: crate::test_support::Gate = std::sync::Arc::new(move || {
                let step = audit_calls.fetch_add(1, Ordering::SeqCst);
                if paused_mid_send && step == 0 {
                    paused.store(true, Ordering::SeqCst);
                }
                if audit_script.get(step).copied().unwrap_or(true) {
                    Ok(())
                } else {
                    anyhow::bail!("synthetic protected audit outage")
                }
            });
            let outcome = crate::test_support::with_dispatch_gate(dispatch, || {
                crate::test_support::with_audit_gate(audit, || {
                    e.send(&job.id, job.revision, &body_hash, false)
                })
            });
            e.paused.store(false, Ordering::SeqCst);
            (outcome.unwrap_err().to_string(), job)
        };

        // Emergency stop before any provider contact.
        let (error, job) = run(&mut e, 11, vec![false], vec![], false);
        assert!(error.contains("emergency stop"), "unexpected: {error}");
        assert_ne!(e.db.get(&job.id).unwrap().state, JobState::Sent);

        // Emergency stop after the reservation: the reservation is released.
        let (error, job) = run(&mut e, 12, vec![true, false], vec![], false);
        assert!(error.contains("emergency stop"), "unexpected: {error}");
        let after = e.db.get(&job.id).unwrap();
        assert!(after.state.reviewable(), "state: {:?}", after.state);

        // Emergency stop after the reservation while the protected checkpoint
        // is also down: the failure is explicitly non-retryable.
        let (error, job) = run(&mut e, 13, vec![true, false], vec![true, false], false);
        assert!(
            error.contains("protected audit checkpoint failed"),
            "unexpected: {error}"
        );
        assert_ne!(e.db.get(&job.id).unwrap().state, JobState::Sent);

        // Checkpoint outage before the network request releases the
        // reservation without sending.
        let (error, job) = run(&mut e, 14, vec![true], vec![false], false);
        assert!(
            error.contains("Protected audit checkpoint is unavailable"),
            "unexpected: {error}"
        );
        let after = e.db.get(&job.id).unwrap();
        assert!(after.state.reviewable(), "state: {:?}", after.state);

        // Pausing after the reservation cancels before Gmail accepts anything.
        let (error, job) = run(&mut e, 15, vec![true], vec![true], true);
        assert!(
            error.contains("Dispatch cancelled before Gmail accepted"),
            "unexpected: {error}"
        );
        let after = e.db.get(&job.id).unwrap();
        assert!(after.state.reviewable(), "state: {:?}", after.state);

        // Checkpoint outage after Gmail accepted: the state is Sent and the
        // operator is told not to resend.
        let (error, job) = run(&mut e, 16, vec![true], vec![true, false], false);
        assert!(error.contains("Do not resend"), "unexpected: {error}");
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Sent);
    }

    /// Automatic dispatch drives the full pipeline for a qualified queue and
    /// holds the recipient burst limit as a review gate, never a silent skip.
    #[test]
    fn automatic_dispatch_sends_until_the_recipient_burst_limit() {
        use crate::test_support::eligible_job_to;
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        crate::test_support::arm_automatic(&mut e.settings);
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let runtime = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| {
                crate::test_support::verdict(
                    "We have decided not to move forward with your application.",
                )
            },
        );
        e.settings.ollama_url.clone_from(&runtime.url);
        let now = Utc::now();

        // Every job shares one recipient mailbox so the per-recipient burst
        // limit eventually engages.
        let limit = crate::test_support::recipient_limit();
        let mut jobs = Vec::new();
        for k in 0..=limit {
            let mut job =
                eligible_job_to(&e.settings, &e.account, 600 + k, "hr0@example.invalid", now);
            e.db.insert_stubs([job.stub.clone()], now).unwrap();
            e.db.save(&mut job, "test.seed", "seeded").unwrap();
            jobs.push(job);
        }
        let emails: Vec<_> = jobs.iter().map(|j| j.email.clone().unwrap()).collect();
        let gmail = crate::test_support::gmail_server(
            &e.account,
            emails,
            crate::test_support::SendOutcome::Deliver("sent000000000000000000600".into()),
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &gmail.url,
            &gmail.url,
        ));

        for k in 0..limit {
            assert!(e.automatic_tick().unwrap(), "burst slot {k} must dispatch");
        }
        let error = e.automatic_tick().unwrap_err().to_string();
        assert!(
            error.contains("Automatic recipient 24-hour reply limit reached"),
            "unexpected: {error}"
        );
        let states: Vec<_> = jobs.iter().map(|j| e.db.get(&j.id).unwrap()).collect();
        let sent = states.iter().filter(|j| j.state == JobState::Sent).count();
        assert_eq!(sent, limit as usize, "exactly the burst slots may dispatch");
        let held: Vec<_> = states
            .iter()
            .filter(|j| j.state != JobState::Sent)
            .collect();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].state, JobState::Attention);
        assert!(
            held[0]
                .flags
                .iter()
                .any(|f| f.contains("Automatic dispatch held")),
            "flags: {:?}",
            held[0].flags
        );
    }

    /// Why: every engine mutation that records an audit event must surface a
    /// failed audit write to its caller instead of reporting success — a silent
    /// `Ok` would let a storage fault erase the audit trail while the UI claims
    /// the change landed.
    /// Inputs: a demo engine whose `events` table has been dropped so every
    /// audit write fails. Output: `Err` from each mutation with an audit tail,
    /// and no partial state change from the review mutations.
    #[test]
    fn audit_write_failures_surface_through_engine_mutations() {
        let d = tempfile::tempdir().unwrap();
        let mut e = Engine::open(
            d.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        e.db.drop_table_for_tests("events");

        // update_settings: the audit tail fails after staging the settings.
        assert!(e.update_settings(e.settings.clone()).is_err());
        // disconnect: account teardown must not claim success.
        assert!(e.disconnect().is_err());

        // Human-review mutations must fail without partially applying.
        let mut items = e.db.list(&e.account, true, 0, 25).unwrap();
        let j = items.pop().unwrap();
        let before = e.db.get(&j.id).unwrap();
        assert!(
            e.edit(
                &j.id,
                j.revision,
                "Please explain the specific assessment criteria used.".into(),
            )
            .is_err()
        );
        assert!(e.dismiss(&j.id, j.revision).is_err());
        let after = e.db.get(&j.id).unwrap();
        assert_eq!(
            after.state, before.state,
            "state must not change on failure"
        );
        assert_eq!(
            after.draft.as_ref().map(|draft| draft.body.clone()),
            before.draft.as_ref().map(|draft| draft.body.clone()),
            "draft must not change on failure"
        );
    }

    /// Why: with no digest pin the engine must report the local installation
    /// verbatim — no pin comparison and no residency gate — so a regression
    /// that applies pin semantics to unpinned workspaces (or drops recording
    /// the local status) is caught.
    /// Inputs: a demo engine pointed at a mock runtime reporting one installed
    /// model, with `model_digest` unset. Output: `Ok(())`; `e.model.digest`
    /// equals the installed digest and no pin-mismatch message is recorded.
    #[test]
    fn inspect_model_status_without_pin_reports_local_installation() {
        let d = tempfile::tempdir().unwrap();
        let mut e = Engine::open(
            d.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let installed = "a".repeat(64);
        let runtime = crate::test_support::ollama_runtime(
            vec![(e.settings.model.clone(), installed.clone())],
            "Test Applicant",
            |_| crate::test_support::verdict_category("other"),
        );
        e.settings.ollama_url.clone_from(&runtime.url);
        e.settings.model_digest = None;
        e.inspect_model_status().unwrap();
        assert_eq!(e.model.digest, installed);
        assert!(
            !e.model.message.contains("differs from the qualified pin"),
            "no pin means no pin comparison"
        );
    }

    /// Why: when the pinned verifier is installed but its GPU residency cannot
    /// be confirmed, the engine must fail closed — `gpu_resident` false with an
    /// explicit operator message — instead of trusting the pin alone.
    /// Inputs: a mock runtime whose verifier tag digest equals the pin but
    /// whose process-list endpoint is unavailable. Output: `Ok(())` with
    /// `verifier_model.gpu_resident == false` and the unconfirmed-residency
    /// message.
    #[test]
    fn inspect_verifier_model_status_surfaces_unconfirmed_residency() {
        let d = tempfile::tempdir().unwrap();
        let mut e = Engine::open(
            d.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let digest = "b".repeat(64);
        e.settings.verifier_model = "verifier-model".into();
        e.settings.verifier_model_digest = Some(digest.clone());
        let server = crate::test_support::MockServer::new(move |route, _| match route {
            "/api/version" => Some(crate::test_support::version_ok()),
            "/api/tags" => Some(crate::test_support::tags_for("verifier-model", &digest)),
            "/api/show" => Some(crate::test_support::show_ok()),
            _ => None,
        });
        e.settings.ollama_url.clone_from(&server.url);
        e.inspect_verifier_model_status().unwrap();
        assert!(!e.verifier_model.gpu_resident);
        assert!(
            e.verifier_model
                .message
                .contains("not currently confirmed GPU-resident"),
            "the operator must be told residency is unconfirmed"
        );
    }

    /// Why: verifier provenance must be re-checked on the digest, not only the
    /// model name — a matching verifier name with a drifted digest is stale
    /// provenance and must block unattended sending.
    /// Inputs: an eligible job whose analysis names the configured verifier but
    /// pins a different digest, then the matching digest. Output: the
    /// stale-provenance block present for the drift, absent for the match.
    #[test]
    fn automatic_policy_blocks_stale_verifier_provenance_digest() {
        let mut settings = Settings::default();
        crate::test_support::arm_automatic(&mut settings);
        settings.independent_verifier_enabled = true;
        settings.verifier_model = "verifier-model".into();
        settings.verifier_model_digest = Some("c".repeat(64));
        let now = Utc::now();
        let mut job = crate::test_support::eligible_job(&settings, "me@example.com", 1, now);
        let analysis = job.analysis.as_mut().unwrap();
        analysis.verification_model = "verifier-model".into();
        analysis.verification_model_digest = "d".repeat(64);

        let blocks = auto_blocks(&job, &settings, "me@example.com", now);
        assert!(
            blocks
                .iter()
                .any(|b| b.contains("Independent-verifier provenance is stale")),
            "digest drift must block: {blocks:?}"
        );

        job.analysis.as_mut().unwrap().verification_model_digest = "c".repeat(64);
        let blocks = auto_blocks(&job, &settings, "me@example.com", now);
        assert!(
            !blocks
                .iter()
                .any(|b| b.contains("Independent-verifier provenance is stale")),
            "matching provenance must not block: {blocks:?}"
        );
    }

    /// Why: `automatic_tick` must SKIP a ready job that fails automatic policy
    /// — no dispatch attempt and no "held" downgrade — leaving it untouched for
    /// human review. If the skip guard regresses, the blocked job is pushed
    /// into the send path and is either wrongly held or consumes a send
    /// attempt.
    /// Inputs: a demo engine whose ready jobs all fail automatic policy (seeded
    /// demo fixtures have no analysis; the seeded test job has low confidence).
    /// Output: `Ok(false)` and the job still Ready with no held-flag.
    #[test]
    fn automatic_tick_skips_policy_blocked_jobs_untouched() {
        let d = tempfile::tempdir().unwrap();
        let mut e = Engine::open(
            d.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        crate::test_support::arm_automatic(&mut e.settings);
        let now = Utc::now();
        let mut job = crate::test_support::eligible_job(&e.settings, &e.account, 77, now);
        job.analysis.as_mut().unwrap().verdict.confidence = 40;
        e.db.insert_stubs([job.stub.clone()], now).unwrap();
        e.db.save(&mut job, "test.seed", "blocked fixture").unwrap();

        assert!(!e.automatic_tick().unwrap());
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Ready);
        assert!(
            after
                .flags
                .iter()
                .all(|flag| !flag.contains("Automatic dispatch held")),
            "a skipped job must never be downgraded to held"
        );
    }

    /// Automatic ticks respect their guards, skip blocked conversations and
    /// hold (never silently drop) messages whose preflight fails late.
    #[test]
    fn automatic_tick_guards_skips_and_holds() {
        use crate::test_support::eligible_job;
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        crate::test_support::arm_automatic(&mut e.settings);
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let runtime = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| {
                crate::test_support::verdict(
                    "We have decided not to move forward with your application.",
                )
            },
        );
        e.settings.ollama_url.clone_from(&runtime.url);

        // Not armed for unattended work: nothing happens.
        e.settings.sending_enabled = false;
        assert!(!e.automatic_tick().unwrap());
        e.settings.sending_enabled = true;

        // The rolling daily budget is spent: nothing happens.
        let spent = e.settings.daily_send_limit;
        e.settings.daily_send_limit = 0;
        assert!(!e.automatic_tick().unwrap());
        e.settings.daily_send_limit = spent;

        // A job failing automatic policy is skipped, not dispatched.
        let now = Utc::now();
        let mut blocked = eligible_job(&e.settings, &e.account, 1, now);
        blocked.state = JobState::Attention;
        e.db.insert_stubs([blocked.stub.clone()], now).unwrap();
        e.db.save(&mut blocked, "test.seed", "blocked").unwrap();
        assert!(!e.automatic_tick().unwrap());
        assert_eq!(e.db.get(&blocked.id).unwrap().state, JobState::Attention);

        // A late preflight failure holds the message for human review.
        let job = eligible_job(&e.settings, &e.account, 2, now);
        let email = job.email.clone().unwrap();
        e.db.insert_stubs([job.stub.clone()], now).unwrap();
        let mut job = job;
        e.db.save(&mut job, "test.seed", "seeded").unwrap();
        // The provider now reports a different connected account.
        let foreign = crate::test_support::gmail_server(
            "other@example.invalid",
            vec![email],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000002".into()),
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &foreign.url,
            &foreign.url,
        ));
        let error = e.automatic_tick().unwrap_err().to_string();
        assert!(
            error.contains("Automatic dispatch held")
                || error.contains("Connected account changed"),
            "unexpected: {error}"
        );
        let held = e.db.get(&job.id).unwrap();
        assert_eq!(held.state, JobState::Attention);
        assert!(
            held.flags
                .iter()
                .any(|f| f.contains("Automatic dispatch held")),
            "flags: {:?}",
            held.flags
        );
    }

    /// Reconciliation resolves Uncertain deliveries against Gmail Sent and
    /// never pretends absence is proof of non-delivery.
    #[test]
    fn reconcile_resolves_uncertain_deliveries_against_sent() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();

        let (job, _) = seed_send_job(&mut e, 1);

        // Only Uncertain deliveries may be reconciled.
        let error = e.reconcile(&job.id).unwrap_err().to_string();
        assert!(error.contains("Only uncertain"), "unexpected: {error}");

        // Put the job into Uncertain exactly like an ambiguous send outcome.
        let current = e.db.get(&job.id).unwrap();
        let reserved = e.db.reserve_send(&current, 50, Utc::now()).unwrap();
        e.db.finish_send(&reserved.id, None).unwrap();
        assert_eq!(e.db.get(&job.id).unwrap().state, JobState::Uncertain);

        // Without a provider reconciliation cannot even start.
        let error = e.reconcile(&job.id).unwrap_err().to_string();
        assert!(error.contains("Connect Gmail"), "unexpected: {error}");

        // Sent contains no matching message: the reservation is retained.
        let empty = crate::test_support::gmail_server(
            &e.account,
            vec![],
            crate::test_support::SendOutcome::Deliver("sent000000000000000000000".into()),
        );
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &empty.url,
            &empty.url,
        ));
        e.reconcile(&job.id).unwrap();
        assert_eq!(e.db.get(&job.id).unwrap().state, JobState::Uncertain);
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "delivery.unresolved"));

        // Sent contains the message: the delivery resolves to Sent once.
        let found = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, crate::test_support::token_ok("test-scope")),
                "/profile" => answer(
                    200,
                    crate::test_support::gmail_profile("applicant@example.invalid"),
                ),
                "/messages" => answer(
                    200,
                    serde_json::json!({"messages": [{
                        "id": "sent000000000000000000009",
                        "threadId": current.stub.thread_id,
                    }]}),
                ),
                _ => None,
            }
        });
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &found.url,
            &found.url,
        ));
        e.reconcile(&job.id).unwrap();
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Sent);
        assert_eq!(
            after.provider_sent_id.as_deref(),
            Some("sent000000000000000000009")
        );
    }

    // =====================================================================
    // Model qualification, evaluation and operator diagnostics.
    // =====================================================================

    /// A scripted runtime whose classifications mirror the evaluation
    /// fixtures: `perfect` answers every case with its expected category,
    /// while degraded mode answers only the qualification smoke test and
    /// holds everything else as uncertain.
    fn evaluation_runtime(perfect: bool) -> MockServer {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../tests/fixtures/classification.json")).unwrap();
        crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            move |payload| {
                let subject = payload["subject"].as_str().unwrap_or("").to_owned();
                let text = payload["untrusted_email"].as_str().unwrap_or("").to_owned();
                let key =
                    |s: &str, t: &str| format!("{s}\n{}", t.chars().take(64).collect::<String>());
                let matched = cases.iter().find(|case| {
                    let case_text =
                        crate::mail::current_text(case["text"].as_str().unwrap_or("\0"));
                    key(&subject, &text)
                        .starts_with(&key(case["subject"].as_str().unwrap_or(""), &case_text))
                });
                let smoke = text.starts_with("Thank you for applying for the engineer position.");
                let expected = if smoke {
                    "rejection"
                } else {
                    matched
                        .and_then(|case| case["expected"].as_str())
                        .unwrap_or("other")
                };
                if (perfect && matched.is_some()) || smoke {
                    if expected == "rejection" {
                        let source = format!("{subject}\n{text}");
                        let quote: String = source.chars().take(40).collect();
                        crate::test_support::verdict(&quote)
                    } else {
                        crate::test_support::verdict_category(expected)
                    }
                } else {
                    crate::test_support::verdict_category("uncertain")
                }
            },
        )
    }

    /// Task evaluation either qualifies the pinned model with a bound
    /// qualification or fails closed and disarms delivery.
    #[test]
    fn evaluate_model_to_qualifies_or_rejects_the_task() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.signature = "Test Applicant".into();
        e.settings.reply_language = crate::config::ReplyLanguage::English;

        // A model mirroring the whole fixture suite passes and is bound.
        let perfect = evaluation_runtime(true);
        e.settings.ollama_url.clone_from(&perfect.url);
        let out = dir.path().join("reports").join("eval.json");
        e.evaluate_model_to(&out).unwrap();
        assert!(e.settings.task_qualification.is_some());
        assert_eq!(
            e.settings.model_digest.as_deref(),
            Some("a".repeat(64).as_str())
        );
        let report: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(report["summary"]["fixture_count"], 74);
        assert!(
            report["summary"]["recommendation_eligible"]
                .as_bool()
                .unwrap()
        );
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "model.task_qualified"));

        // The dated wrapper writes its report next to the workspace.
        e.evaluate_model().unwrap();

        // A degraded model fails the gates: qualification is dropped and
        // unattended delivery disarms fail-closed.
        let degraded = evaluation_runtime(false);
        e.settings.ollama_url.clone_from(&degraded.url);
        let out2 = dir.path().join("eval2.json");
        let error = e.evaluate_model_to(&out2).unwrap_err().to_string();
        assert!(
            error.contains("did not meet Automatic-mode gates"),
            "unexpected: {error}"
        );
        assert!(e.settings.task_qualification.is_none());
        assert!(!e.settings.sending_enabled);
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "model.task_rejected"));
    }

    /// Qualification pins digests, status inspection surfaces stale pins and
    /// residency losses, and verifier flows follow the same contract.
    #[test]
    fn qualification_and_status_flows_pin_and_revalidate() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.signature = "Test Applicant".into();
        e.settings.reply_language = crate::config::ReplyLanguage::English;
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
        e.settings.ollama_url.clone_from(&runtime.url);

        // Qualify pins the digest and keeps unattended delivery disabled.
        e.settings.sending_enabled = true;
        e.qualify().unwrap();
        assert_eq!(
            e.settings.model_digest.as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert!(!e.settings.sending_enabled);
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "model.qualified"));

        // Status reflects residency while the pin matches.
        e.inspect_model_status().unwrap();
        assert!(e.model.gpu_resident);
        // A stale pin surfaces as a requalification demand.
        e.settings.model_digest = Some("c".repeat(64));
        e.inspect_model_status().unwrap();
        assert!(!e.model.gpu_resident);
        assert!(e.model.message.contains("qualify again"));
        // A pin that matches but has no residency says so precisely.
        e.settings.model_digest = Some("a".repeat(64));
        let empty_ps = MockServer::new_raw(move |route, _| match route {
            "/" => Some((200, crate::test_support::token_ok("test-scope").to_string())),
            "/api/version" => Some((200, crate::test_support::version_ok().to_string())),
            "/api/tags" => Some((
                200,
                crate::test_support::tags_for(crate::config::DEFAULT_MODEL, &"a".repeat(64))
                    .to_string(),
            )),
            "/api/show" => Some((200, crate::test_support::show_ok().to_string())),
            "/api/ps" => Some((200, serde_json::json!({"models": []}).to_string())),
            _ => None,
        });
        e.settings.ollama_url.clone_from(&empty_ps.url);
        e.inspect_model_status().unwrap();
        assert!(!e.model.gpu_resident);
        assert!(
            e.model
                .message
                .contains("not currently confirmed GPU-resident")
        );

        // Verifier qualification and status follow the same pin semantics.
        e.settings.ollama_url.clone_from(&runtime.url);
        e.settings.verifier_model = crate::config::DEFAULT_VERIFIER_MODEL.into();
        e.settings.verifier_model_digest = None;
        e.qualify_verifier().unwrap();
        assert_eq!(
            e.settings.verifier_model_digest.as_deref(),
            Some("b".repeat(64).as_str())
        );
        e.inspect_verifier_model_status().unwrap();
        assert!(e.verifier_model.gpu_resident);
        e.settings.verifier_model_digest = Some("c".repeat(64));
        e.inspect_verifier_model_status().unwrap();
        assert!(!e.verifier_model.gpu_resident);
        assert!(e.verifier_model.message.contains("qualify again"));
    }

    /// Runtime profiling and the installed-model bake-off persist private
    /// reports and audit their creation.
    #[test]
    fn runtime_profile_and_bakeoff_persist_private_reports() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.signature = "Test Applicant".into();
        e.settings.reply_language = crate::config::ReplyLanguage::English;
        let runtime = crate::test_support::ollama_runtime(
            vec![(crate::config::DEFAULT_MODEL.into(), "a".repeat(64))],
            "Test Applicant",
            |_| {
                crate::test_support::verdict(
                    "We have decided not to move forward with your application.",
                )
            },
        );
        e.settings.ollama_url.clone_from(&runtime.url);

        let report = e.profile_model_runtime().unwrap();
        assert!(report.exists());
        let profile: Value =
            serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
        assert!(profile["cold_pipeline"]["request_count"].as_u64().unwrap() > 0);

        let bakeoff = e.compare_models().unwrap();
        assert!(bakeoff.exists());
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "model.runtime_profiled"));
        assert!(events.iter().any(|ev| ev.kind == "models.compared"));
    }

    /// Synchronize against the provider records its poll cursor.
    #[test]
    fn synchronize_records_the_poll_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.account = "applicant@example.invalid".into();
        assert!(e.last_poll().unwrap().is_none());
        let sync_server = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, crate::test_support::token_ok("test-scope")),
                "/profile" => answer(
                    200,
                    crate::test_support::gmail_profile("applicant@example.invalid"),
                ),
                "/messages" => answer(200, serde_json::json!({"messages": []})),
                "/history" => answer(200, serde_json::json!({"history": [], "historyId": "42"})),
                _ => None,
            }
        });
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &sync_server.url,
            &sync_server.url,
        ));
        let inserted = e.synchronize().unwrap();
        assert_eq!(inserted, 0);
        assert!(e.last_poll().unwrap().is_some());
    }

    /// Editing, regenerating and dismissing drive the review lifecycle and
    /// invalidate model verification whenever a human takes over.
    #[test]
    fn review_lifecycle_edits_regenerates_and_dismisses() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let (job, _) = seed_send_job(&mut e, 1);

        // A human edit invalidates model verification and holds the draft.
        e.edit(
            &job.id,
            job.revision,
            crate::test_support::draft_body("Test Applicant"),
        )
        .unwrap();
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Attention);
        assert!(after.analysis.as_ref().unwrap().verification.is_none());
        assert!(
            after
                .analysis
                .as_ref()
                .unwrap()
                .verified_draft_hash
                .is_none()
        );
        assert!(
            after.flags.iter().any(|f| f.contains("User-edited reply")),
            "flags: {:?}",
            after.flags
        );

        // Regeneration returns the message to the local analysis queue.
        e.regenerate(&job.id, after.revision).unwrap();
        let after = e.db.get(&job.id).unwrap();
        assert_eq!(after.state, JobState::Queued);
        assert!(after.draft.is_none() && after.analysis.is_none());

        // Dismissal releases the message with no mail sent.
        let (job2, _) = seed_send_job(&mut e, 2);
        e.dismiss(&job2.id, job2.revision).unwrap();
        assert_eq!(e.db.get(&job2.id).unwrap().state, JobState::Dismissed);
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "email.dismissed"));
    }

    /// Connecting persists encrypted credentials with delivery disarmed;
    /// disconnecting removes them; demo and policy refusals stay hard.
    #[test]
    fn connect_and_disconnect_persist_credentials_disarmed() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        let provider = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, crate::test_support::token_ok("test-scope")),
                "/profile" => answer(
                    200,
                    crate::test_support::gmail_profile("applicant@example.invalid"),
                ),
                _ => None,
            }
        });

        // Demo mode never touches a real mailbox.
        let mut d = demo(dir.path());
        let error =
            crate::test_support::with_login(test_creds(), &provider.url, &provider.url, || {
                d.connect(&dir.path().join("oauth.json"), true).unwrap_err()
            })
            .to_string();
        assert!(error.contains("Demo mode"), "unexpected: {error}");

        // An enterprise policy can forbid even requesting send scope.
        let restrictive = crate::test_support::loaded_policy(
            "digest-a",
            crate::policy::EnterprisePolicy {
                version: 1,
                prohibit_sending: true,
                ..Default::default()
            },
        );
        let error = crate::test_support::with_policy(Some(restrictive), || {
            e.reload_enterprise_policy().unwrap();
            crate::test_support::with_login(test_creds(), &provider.url, &provider.url, || {
                e.connect(&dir.path().join("oauth.json"), true).unwrap_err()
            })
            .to_string()
        });
        assert!(
            error.contains("prohibits requesting Gmail send permission"),
            "unexpected: {error}"
        );

        // Removing the policy does not re-enable anything by itself; a normal
        // login then persists everything with delivery disarmed.
        crate::test_support::with_policy(None, || {
            e.reload_enterprise_policy().unwrap();
        });
        crate::test_support::with_login(test_creds(), &provider.url, &provider.url, || {
            e.connect(&dir.path().join("oauth.json"), true).unwrap();
        });
        assert_eq!(e.account, "applicant@example.invalid");
        assert!(e.connected() && e.send_scope());
        assert!(!e.settings.sending_enabled);
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "account.connected"));

        // Disconnecting removes local credentials and audits it.
        e.disconnect().unwrap();
        assert!(!e.connected());
        assert!(e.account.is_empty());
        assert!(!e.settings.sending_enabled);
        let events = e.db.events(0, 500).unwrap();
        assert!(events.iter().any(|ev| ev.kind == "account.disconnected"));
    }
}

#[cfg(test)]
mod fail_closed_open_tests {
    use super::*;
    use crate::policy::EnterprisePolicy;

    /// Open a live (non-demo) workspace for these tests.
    ///
    /// Why: non-demo opens derive the vault key from the OS credential store on
    /// Windows and macOS and from the documented `RR_VAULT_PASSPHRASE` input on
    /// headless hosts, so the headless vault seam must be armed first or Linux
    /// runs fail closed.
    /// Inputs: `dir` — workspace directory. Output: the opened [`Engine`].
    fn live(dir: &std::path::Path) -> Engine {
        crate::test_support::headless_vault_seam();
        Engine::open(
            dir.to_path_buf(),
            false,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    /// Why: a managed policy that requires independently protected audit
    /// anchoring must fail closed — opening without a configured external
    /// anchor or OS anchor mode would run with unverifiable rollback evidence,
    /// so the workspace must refuse to open and name the missing protection.
    /// Inputs: workspace plus a policy demanding `require_external_audit_anchor`
    /// with no anchor environment configured. Output: open error naming the
    /// anchoring requirement.
    #[test]
    fn open_refuses_policy_that_requires_an_unconfigured_external_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let e = live(dir.path());
            drop(e);
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let policy = crate::test_support::loaded_policy(
            "digest-anchor",
            EnterprisePolicy {
                version: 2,
                policy_id: Some("corp.anchor".into()),
                revision: Some(1),
                require_external_audit_anchor: true,
                ..Default::default()
            },
        );
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let error = crate::test_support::with_policy(Some(policy), || {
            Engine::open(
                dir.path().into(),
                false,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            )
            .err()
            .expect("policy-required anchoring must fail closed")
        });
        assert!(
            error
                .to_string()
                .contains("independently protected audit anchoring"),
            "unexpected error: {error}"
        );
    }

    /// Why: settings persisted between sessions may only be relaxed by an
    /// explicit user action; reopening under the same already-accepted policy
    /// must re-constrain settings that were relaxed out of band and audit the
    /// policy-constrained detail, otherwise a manual settings edit could
    /// silently outlive the managed policy between restarts.
    /// Inputs: workspace opened under a restrictive policy, then reopened after
    /// its stored settings were replaced with armed Automatic mode. Output:
    /// policy restrictions re-applied and the constraint audited.
    #[test]
    fn open_reconstrains_out_of_band_settings_under_accepted_policy() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let e = live(dir.path());
            drop(e);
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let policy = crate::test_support::loaded_policy(
            "digest-reconstrain",
            EnterprisePolicy {
                version: 2,
                policy_id: Some("corp.reconstrain".into()),
                revision: Some(7),
                force_human_review: true,
                ..Default::default()
            },
        );
        {
            let e = crate::test_support::with_policy(Some(policy.clone()), || live(dir.path()));
            assert_eq!(e.settings.mode, Mode::HumanReview);
        }
        {
            let mut e = live(dir.path());
            crate::test_support::arm_automatic(&mut e.settings);
            e.db.set_meta("settings", &e.settings).unwrap();
        }
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let e = crate::test_support::with_policy(Some(policy), || live(dir.path()));
        assert_eq!(
            e.settings.mode,
            Mode::HumanReview,
            "policy must re-constrain an out-of-band mode change"
        );
        assert!(!e.settings.sending_enabled);
        let events = e.db.events(0, 500).unwrap();
        assert!(
            events.iter().any(|ev| ev
                .detail
                .contains("Persisted settings were constrained by enterprise policy")),
            "the re-constraint must be audited as a policy action"
        );
    }

    /// Why: analysis must never run on unfetched content — classifying a job
    /// whose body is still missing could bless a draft for the wrong message,
    /// so the guard must error before any analysis output is recorded.
    /// Inputs: a queued job with `email: None`. Output: error naming the
    /// missing content, job untouched.
    #[test]
    fn analyze_job_refuses_jobs_without_fetched_content() {
        let d = tempfile::tempdir().unwrap();
        let mut e = Engine::open(
            d.path().into(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let mut job = Job::new(
            ollama::sample_email("Test", "not selected").stub.clone(),
            Utc::now(),
        );
        let error = e
            .analyze_job(&mut job)
            .expect_err("analysis of unfetched content must be refused");
        assert!(
            error
                .to_string()
                .contains("Message content must be fetched before analysis"),
            "unexpected error: {error}"
        );
        assert!(job.analysis.is_none());
    }
}

#[cfg(test)]
mod dispatch_error_path_tests {
    use super::*;
    use crate::test_support::{self as ts, MockServer};
    use serde_json::Value;

    /// Open a live (non-demo) workspace for these tests.
    ///
    /// Why: non-demo opens derive the vault key from the OS credential store on
    /// Windows and macOS and from the documented `RR_VAULT_PASSPHRASE` input on
    /// headless hosts, so the headless vault seam must be armed first or Linux
    /// runs fail closed.
    /// Inputs: `dir` — workspace directory. Output: the opened [`Engine`].
    fn live(dir: &std::path::Path) -> Engine {
        crate::test_support::headless_vault_seam();
        Engine::open(
            dir.to_path_buf(),
            false,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    fn test_creds() -> crate::oauth::Credentials {
        crate::oauth::Credentials {
            client_id: "id".into(),
            client_secret: "secret".into(),
            refresh_token: "refresh".into(),
            can_send: true,
        }
    }

    fn seed_send_job(e: &mut Engine, n: u64) -> (Job, String) {
        let now = Utc::now();
        let email = ts::gmail_email(
            &e.account,
            n,
            "Your application — R&D Engineer",
            "Thank you for applying. We have decided not to move forward with your application.",
        );
        let body = ts::draft_body(&e.settings.signature);
        let mut job = Job::new(email.stub.clone(), now);
        job.analysis = Some(ts::verified_analysis(&e.settings, &email, &body));
        job.email = Some(email);
        job.draft = Some(Draft {
            body,
            origin: "ollama-v1".into(),
        });
        job.drafted_at = Some(now - chrono::Duration::hours(1));
        job.state = JobState::Ready;
        e.db.insert_stubs([job.stub.clone()], now).unwrap();
        e.db.save(&mut job, "test.seed", "seeded").unwrap();
        let body_hash = hash(&job.draft.as_ref().unwrap().body);
        (job, body_hash)
    }

    fn attach(e: &mut Engine, server: &MockServer) {
        e.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            test_creds(),
            &server.url,
            &server.url,
        ));
    }

    fn runtime_version_exposing(version: &str) -> MockServer {
        let version = version.to_owned();
        MockServer::new_raw(move |route, _| {
            (route == "/api/version")
                .then(|| (200, serde_json::json!({"version": version}).to_string()))
        })
    }

    /// Why: provider fetch failures must be classified before anything is sent
    /// — a transient outage is operator-retryable while a malformed provider
    /// response is not — and no message state may change, so an outage can
    /// never consume an approval or mark mail as handled.
    /// Inputs: message fetches answering 503 then 400 INVALID_ARGUMENT.
    /// Output: retryable failure for the outage, non-retryable failure for the
    /// malformed response, job still Ready in both cases.
    #[test]
    fn provider_fetch_failures_split_retryable_from_review() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let (job, body_hash) = seed_send_job(&mut e, 21);
        let email = job.email.clone().unwrap();

        let outage = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, ts::token_ok("test-scope")),
                "/profile" => answer(200, ts::gmail_profile("applicant@example.invalid")),
                p if p.starts_with("/messages/") => {
                    answer(503, serde_json::json!({"error": {"status": "UNAVAILABLE"}}))
                }
                _ => None,
            }
        });
        attach(&mut e, &outage);
        let failure = e
            .send_attempt(&job.id, job.revision, &body_hash, false)
            .expect_err("an unreachable provider must not dispatch");
        assert!(
            failure.retryable_for_operator(),
            "transient fetch outages must be operator-retryable: {failure}"
        );
        assert_eq!(e.db.get(&job.id).unwrap().state, JobState::Ready);

        let malformed = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, ts::token_ok("test-scope")),
                "/profile" => answer(200, ts::gmail_profile("applicant@example.invalid")),
                p if p.starts_with("/messages/") => {
                    let mut broken = ts::gmail_resource(&email);
                    broken["raw"] = serde_json::json!("%%%not-base64%%%");
                    answer(200, broken)
                }
                _ => None,
            }
        });
        attach(&mut e, &malformed);
        let failure = e
            .send_attempt(&job.id, job.revision, &body_hash, false)
            .expect_err("a malformed provider response must not dispatch");
        assert!(
            !failure.retryable_for_operator(),
            "malformed provider responses must require review: {failure}"
        );
        assert_eq!(e.db.get(&job.id).unwrap().state, JobState::Ready);
    }

    /// Why: the pause check immediately before durable reservation is the last
    /// gate before send state is recorded — a pause that arrives mid-flight
    /// (while provider fetches are in progress) must still block dispatch and
    /// leave the job untouched, or a paused worker could still put mail on the
    /// wire.
    /// Inputs: a message fetch that flips the pause flag as it answers.
    /// Output: retryable "Paused before dispatch" failure, no send request on
    /// the wire, job still Ready.
    #[test]
    fn a_pause_arriving_mid_flight_still_blocks_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let (job, body_hash) = seed_send_job(&mut e, 22);
        let email = job.email.clone().unwrap();
        let resource = ts::gmail_resource(&email);
        let thread = ts::gmail_thread(&email);
        let paused = e.paused.clone();

        let server = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, ts::token_ok("test-scope")),
                "/profile" => answer(200, ts::gmail_profile("applicant@example.invalid")),
                p if p.starts_with("/messages/") => {
                    paused.store(true, Ordering::SeqCst);
                    answer(200, resource.clone())
                }
                p if p.starts_with("/threads/") => answer(200, thread.clone()),
                _ => None,
            }
        });
        attach(&mut e, &server);
        let failure = e
            .send_attempt(&job.id, job.revision, &body_hash, false)
            .expect_err("a mid-flight pause must block dispatch");
        assert!(
            failure.to_string().contains("Paused before dispatch"),
            "unexpected: {failure}"
        );
        assert!(failure.retryable_for_operator());
        assert!(
            !server.routes().iter().any(|r| r == "/messages/send"),
            "nothing may reach the provider send endpoint"
        );
        assert_eq!(e.db.get(&job.id).unwrap().state, JobState::Ready);
        e.paused.store(false, Ordering::SeqCst);
    }

    /// Why: an unreachable account-profile preflight is a transient condition
    /// and must be classified operator-retryable with its own stable wording,
    /// so operators retry instead of escalating a routine outage.
    /// Inputs: a profile endpoint answering 503. Output: retryable failure
    /// naming the account preflight; nothing dispatched.
    #[test]
    fn profile_preflight_outages_are_operator_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();
        let (job, body_hash) = seed_send_job(&mut e, 23);
        let server = MockServer::new_raw(move |route, _| {
            let answer = |status: u16, value: Value| Some((status, value.to_string()));
            match route {
                "/" => answer(200, ts::token_ok("test-scope")),
                "/profile" => answer(503, serde_json::json!({"error": {"status": "UNAVAILABLE"}})),
                _ => None,
            }
        });
        attach(&mut e, &server);
        let failure = e
            .send_attempt(&job.id, job.revision, &body_hash, false)
            .expect_err("a failed preflight must not dispatch");
        assert!(
            failure
                .to_string()
                .contains("Gmail account preflight is temporarily unavailable"),
            "unexpected: {failure}"
        );
        assert!(failure.retryable_for_operator());
    }

    /// Why: once the provider has given a definitive answer, a failing protected
    /// audit checkpoint must flip the failure to explicitly non-retryable with
    /// the operator instruction not to resend — retrying a rejected send or an
    /// uncertain delivery after losing audit evidence risks a duplicate reply.
    /// Inputs: a rejecting send and an uncertain send, each with the protected
    /// checkpoint failing after the provider answer. Output: non-retryable
    /// `nonretryable_audit_checkpoint_failed` for the rejection and the
    /// "Do not resend" uncertainty wording for the uncertain delivery.
    #[test]
    fn checkpoint_outage_after_provider_answers_is_never_retryable() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        e.settings.sending_enabled = true;
        e.settings.signature = "Test Applicant".into();
        e.account = "applicant@example.invalid".into();

        let failing_checkpoint = || -> ts::Gate {
            let calls = std::sync::atomic::AtomicUsize::new(0);
            std::sync::Arc::new(move || {
                let step = calls.fetch_add(1, Ordering::SeqCst);
                if step >= 1 {
                    anyhow::bail!("synthetic protected audit outage")
                }
                Ok(())
            })
        };

        let (job, body_hash) = seed_send_job(&mut e, 24);
        let email = job.email.clone().unwrap();
        let rejecting = ts::gmail_server(&e.account, vec![email], ts::SendOutcome::Reject);
        attach(&mut e, &rejecting);
        let failure = ts::with_audit_gate(failing_checkpoint(), || {
            e.send_attempt(&job.id, job.revision, &body_hash, false)
        })
        .expect_err("a rejected send with a failed checkpoint must not report success");
        assert_eq!(
            failure.operation_code(),
            "nonretryable_audit_checkpoint_failed"
        );
        assert!(
            !failure.retryable_for_operator(),
            "a lost audit checkpoint must never be operator-retried: {failure}"
        );
        assert!(
            failure
                .to_string()
                .contains("Gmail rejected the reply before acceptance"),
            "unexpected: {failure}"
        );

        let (job, body_hash) = seed_send_job(&mut e, 25);
        let email = job.email.clone().unwrap();
        let uncertain = ts::gmail_server(&e.account, vec![email], ts::SendOutcome::Uncertain);
        attach(&mut e, &uncertain);
        let failure = ts::with_audit_gate(failing_checkpoint(), || {
            e.send_attempt(&job.id, job.revision, &body_hash, false)
        })
        .expect_err("an uncertain delivery with a failed checkpoint must not report success");
        assert!(
            failure.to_string().contains(
                "Delivery remains Uncertain and the required protected audit checkpoint also failed"
            ),
            "unexpected: {failure}"
        );
        assert!(
            failure.to_string().contains("Do not resend"),
            "the operator must be told not to resend: {failure}"
        );
    }

    /// Why: the automatic branch re-validates the local runtime immediately
    /// before dispatch — an unreachable runtime is retryable while a runtime
    /// version that changed since task qualification requires re-review —
    /// because sending from a runtime the user never qualified would break the
    /// whole qualification guarantee.
    /// Inputs: runtimes exposing a failing version endpoint, a foreign
    /// version, and a failing model catalogue. Output: retryable failures for
    /// the outages and a review-required failure naming the runtime change.
    #[test]
    fn automatic_pre_send_runtime_gates_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let mut e = live(dir.path());
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(
            crate::vault::vault_id(dir.path()).unwrap(),
        );
        ts::arm_automatic(&mut e.settings);
        e.account = "applicant@example.invalid".into();
        let (job, body_hash) = seed_send_job(&mut e, 26);
        let job_id = job.id.clone();
        let revision = job.revision;

        // The version endpoint is unreachable: a transient, retryable failure.
        let broken_version = MockServer::new_raw(|_, _| None);
        e.settings.ollama_url.clone_from(&broken_version.url);
        let failure = e
            .send_attempt(&job_id, revision, &body_hash, true)
            .expect_err("an unreachable runtime must not dispatch");
        assert!(
            failure
                .to_string()
                .contains("Local model runtime pre-send check"),
            "unexpected: {failure}"
        );
        assert!(failure.retryable_for_operator());

        // The runtime version drifted from task qualification: re-evaluate.
        let foreign = runtime_version_exposing("9.9.9");
        e.settings.ollama_url.clone_from(&foreign.url);
        let failure = e
            .send_attempt(&job_id, revision, &body_hash, true)
            .expect_err("a changed runtime must not dispatch");
        assert!(
            failure
                .to_string()
                .contains("Ollama runtime changed since task qualification"),
            "unexpected: {failure}"
        );
        assert!(!failure.retryable_for_operator());

        // The model catalogue is unreachable: a transient, retryable failure.
        let broken_tags = MockServer::new_raw(move |route, _| {
            (route == "/api/version").then(|| (200, ts::version_ok().to_string()))
        });
        e.settings.ollama_url.clone_from(&broken_tags.url);
        let failure = e
            .send_attempt(&job_id, revision, &body_hash, true)
            .expect_err("an unreachable model catalogue must not dispatch");
        assert!(
            failure.to_string().contains("Local model pre-send check"),
            "unexpected: {failure}"
        );
        assert!(failure.retryable_for_operator());
    }

    /// Why: when recent recipient attempts cannot be counted the send must be
    /// held for review — silently assuming zero attempts would defeat the
    /// per-recipient burst limit exactly when the limit is unverifiable — and
    /// the operator-facing text must name the burst-safety failure.
    /// Inputs: a storage error from the attempt counter. Output: a
    /// non-retryable review failure naming the recipient burst safety.
    #[test]
    fn unmeasurable_recipient_burst_safety_holds_the_send_for_review() {
        let failure = recipient_burst_unavailable("database is locked");
        assert!(!failure.retryable_for_operator());
        assert!(
            failure.to_string().contains(
                "Automatic recipient burst safety could not be established: database is locked"
            ),
            "unexpected: {failure}"
        );
    }

    /// Why: a storage-headroom measurement outage is transient, so the send
    /// must be operator-retryable — but it still blocks the attempt because
    /// durable send state cannot be guaranteed while headroom is unknown.
    /// Inputs: a storage error from the headroom probe. Output: a retryable
    /// failure naming the durable send state requirement.
    #[test]
    fn unknown_storage_headroom_is_retryable_but_still_blocks() {
        let failure = storage_headroom_unknown("volume unavailable");
        assert!(failure.retryable_for_operator());
        assert!(
            failure.to_string().contains(
                "Durable send state cannot be recorded safely because storage headroom is low: volume unavailable"
            ),
            "unexpected: {failure}"
        );
    }
}

#[cfg(test)]
mod open_stage_and_automatic_gap_tests {
    use super::*;
    use crate::policy::{EnterprisePolicy, PolicyRevisionFloor};
    use crate::test_support::{arm_automatic, eligible_job, loaded_policy, verified_analysis};

    /// Open a live (non-demo) workspace, serializing OS credential-store access.
    ///
    /// Why: non-demo opens derive the vault key from the OS credential store,
    /// so tests must hold the credential-store lock and clean up the entry.
    fn live(dir: &std::path::Path) -> Engine {
        crate::test_support::headless_vault_seam();
        Engine::open(
            dir.to_path_buf(),
            false,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    /// Open a synthetic demo workspace for negative-path tests.
    ///
    /// Why: demo workspaces live in throwaway directories and never touch the
    /// OS credential store, so refusal paths can be exercised safely.
    fn demo(dir: &std::path::Path) -> Engine {
        Engine::open(
            dir.to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    fn armed() -> Settings {
        let mut settings = Settings::default();
        arm_automatic(&mut settings);
        settings
    }

    /// Recompute the analysis provenance for the job's current email/draft.
    ///
    /// Why: the provenance gates hash the stored analysis against the message
    /// and settings, so tests mutating one input must rebind the analysis to
    /// isolate the single gate under test.
    fn rebind_analysis(job: &mut Job, settings: &Settings) {
        let email = job.email.clone().unwrap();
        let body = job.draft.as_ref().unwrap().body.clone();
        job.analysis = Some(verified_analysis(settings, &email, &body));
    }

    fn single(
        job: &Job,
        settings: &Settings,
        now: DateTime<Utc>,
        account: &str,
    ) -> Vec<AutomaticPolicyBlock> {
        let decision = automatic_policy(job, settings, account, now);
        assert_eq!(decision.eligible, decision.blocks.is_empty());
        decision.blocks
    }

    /// App-password connect persists encrypted credentials atomically and
    /// stays disarmed; reopening rebuilds the IMAP/SMTP transport from the
    /// stored credentials without any network round trip.
    ///
    /// Why: an account switch must never inherit sending rights, and the
    /// persisted credentials are the only bridge back to the mailbox after a
    /// restart — losing them silently would strand the workspace.
    #[test]
    fn app_password_connect_persists_encrypted_state_and_reopen_rebuilds_the_transport() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let mut e = live(dir.path());
            arm_automatic(&mut e.settings);
            e.db.set_meta("settings", &e.settings).unwrap();
            let creds = crate::mail_transport::AppPasswordCredentials::new(
                "user@example.com",
                "abcdefghijklmnop",
            );
            e.connect_app_password(creds).expect("connect succeeds");
            assert!(
                !e.settings.sending_enabled && e.settings.mode == Mode::HumanReview,
                "an account switch disarms delivery fail-closed"
            );
            assert_eq!(e.account, "user@example.com");
            assert!(e.connected(), "the IMAP/SMTP transport is attached");
            let stored: Option<serde_json::Value> = e.db.meta("app_password_credentials").unwrap();
            assert!(stored.is_some(), "credentials are persisted encrypted");
            let events = e.db.events(0, 500).unwrap();
            assert!(events.iter().any(|ev| ev.kind == "account.connected"));
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let e = live(dir.path());
        assert!(
            e.connected(),
            "reopen rebuilds the transport from the stored app-password credentials"
        );
        assert_eq!(e.account, "user@example.com");
        assert!(!e.settings.sending_enabled, "reopen never re-arms delivery");
    }

    /// App-password connect refuses malformed mailbox identities before any
    /// state is written.
    ///
    /// Why: the mailbox identity keys the account and the recipient buckets —
    /// persisting an unparseable identity would corrupt every downstream gate.
    #[test]
    fn app_password_connect_refuses_invalid_mailbox_identities_without_touching_state() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let mut e = live(dir.path());
            arm_automatic(&mut e.settings);
            e.db.set_meta("settings", &e.settings).unwrap();
            let error = e
                .connect_app_password(crate::mail_transport::AppPasswordCredentials::new(
                    "user\u{7}@example.com",
                    "abcdefghijklmnop",
                ))
                .expect_err("control characters are refused");
            assert_eq!(error.to_string(), "Invalid mailbox characters");
            let error = e
                .connect_app_password(crate::mail_transport::AppPasswordCredentials::new(
                    "a@example.com, b@example.com",
                    "abcdefghijklmnop",
                ))
                .expect_err("multiple mailboxes are refused");
            assert_eq!(error.to_string(), "Exactly one mailbox is required");
            assert!(
                e.db.meta::<serde_json::Value>("app_password_credentials")
                    .unwrap()
                    .is_none()
            );
            assert!(e.db.meta::<String>("account").unwrap().is_none());
            assert!(
                e.settings.sending_enabled && e.settings.mode == Mode::Automatic,
                "a refused connect leaves the prior settings untouched"
            );
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
    }

    /// Compaction is refused in demo mode and reports real page statistics on a
    /// live workspace.
    ///
    /// Why: demo data lives in a throwaway directory — compacting it would
    /// claim maintenance on a workspace that does not exist; the live path
    /// must report measured page counts, not a canned success.
    #[test]
    fn compact_database_refuses_demo_and_reports_real_compaction() {
        let d = tempfile::tempdir().unwrap();
        let mut demo_engine = demo(d.path());
        let error = demo_engine
            .compact_database()
            .expect_err("demo never compacts");
        assert_eq!(
            error.to_string(),
            "Synthetic demo mode does not compact a real workspace"
        );

        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let (report, vault) = {
            let mut e = live(dir.path());
            let report = e.compact_database().expect("live compaction succeeds");
            (report, crate::vault::vault_id(dir.path()).unwrap())
        };
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        assert!(
            report.after_page_count > 0,
            "pages are measured after compaction"
        );
        assert!(report.page_size_bytes > 0);
        assert!(
            report.after_freelist_count <= report.before_freelist_count,
            "compaction never grows the freelist"
        );
    }

    /// Staged-settings persistence fails closed: a lost revision-floor stage, a
    /// floor without an active policy, and a broken audit journal each abort
    /// without writing partial settings state.
    ///
    /// Why: settings and the policy rollback floor are committed together — a
    /// partial write would let relaxed settings outlive the policy that
    /// constrained them.
    #[test]
    fn staged_settings_persistence_fails_closed_without_half_committing() {
        let d = tempfile::tempdir().unwrap();
        let mut e = demo(d.path());
        let settings = Settings::default();
        let floor = PolicyRevisionFloor::default();

        // Staging claimed a floor change but the staged floor is gone.
        let error = persist_staged_settings(
            &mut e.db, &settings, &None, &None, true, false, false, false, false, false,
        )
        .expect_err("a lost staging buffer must abort");
        assert_eq!(error.to_string(), "Policy revision floor staging was lost");

        // A staged floor without an active policy cannot describe its audit
        // detail; nothing may be committed.
        let error = persist_staged_settings(
            &mut e.db,
            &settings,
            &None,
            &Some(floor),
            true,
            false,
            false,
            false,
            false,
            false,
        )
        .expect_err("a floor without an active policy must abort");
        assert_eq!(
            error.to_string(),
            "Policy revision floor changed without active policy"
        );
        assert!(
            e.db.meta::<PolicyRevisionFloor>("enterprise_policy_revision_floor")
                .unwrap()
                .is_none(),
            "no floor metadata is written on failure"
        );

        // A broken audit journal aborts the staged migration commit.
        e.db.drop_table_for_tests("events");
        let before = e.db.meta::<Settings>("settings").unwrap();
        let error = persist_staged_settings(
            &mut e.db, &settings, &None, &None, false, true, false, false, false, false,
        )
        .expect_err("a broken audit journal must abort the commit");
        assert_eq!(error.to_string(), "no such table: events");
        assert_eq!(
            e.db.meta::<Settings>("settings").unwrap(),
            before,
            "the staged migration left no partial settings write"
        );
    }

    /// Opening a workspace whose audit journal cannot authenticate fails
    /// closed with the storage error instead of starting unverified.
    ///
    /// Why: engine open verifies the chained audit evidence before any runtime
    /// recovery event is appended; a workspace that cannot present its journal
    /// must never open.
    #[test]
    fn engine_open_fails_closed_when_the_audit_journal_is_broken() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let mut e = live(dir.path());
            let legacy = Settings {
                mode: Mode::Automatic,
                ..Settings::default()
            };
            e.db.set_meta("settings", &legacy).unwrap();
            e.db.drop_table_for_tests("events");
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
        let error = Engine::open(
            dir.path().into(),
            false,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .err()
        .expect("an unverifiable audit journal must refuse to open");
        assert_eq!(error.to_string(), "no such table: events");
    }

    /// Connecting without the login seam propagates the OAuth client-file
    /// failure before any credential state is touched.
    ///
    /// Why: `connect` must not half-persist a connection — a failed login
    /// leaves the previous account and settings exactly as they were.
    #[test]
    fn connect_without_the_login_seam_fails_closed_before_any_state_change() {
        let dir = tempfile::tempdir().unwrap();
        let _credential_store = crate::vault::test_support::lock_credential_store();
        let vault = {
            let mut e = live(dir.path());
            let client = dir.path().join("client.json");
            std::fs::write(&client, b"{}").unwrap();
            let error = e
                .connect(&client, false)
                .expect_err("a non-OAuth client file is refused");
            assert_eq!(
                error.to_string(),
                "Choose a Google Desktop app OAuth JSON file containing an installed object"
            );
            assert!(!e.connected());
            assert!(e.db.meta::<String>("account").unwrap().is_none());
            assert!(
                e.db.meta::<serde_json::Value>("google_credentials")
                    .unwrap()
                    .is_none()
            );
            crate::vault::vault_id(dir.path()).unwrap()
        };
        let _cleanup = crate::vault::test_support::OsCredentialCleanup::from_vault_id(vault);
    }

    /// Automatic policy blocks dispatch when model verification or residency
    /// evidence is missing, naming the gate exactly.
    ///
    /// Why: the verifier result and GPU residency are the only independent
    /// checks on the classifier — dispatch must not proceed without them.
    #[test]
    fn automatic_policy_blocks_unverified_model_provenance() {
        let settings = armed();
        let account = "applicant@example.invalid";

        let mut job = eligible_job(&settings, account, 1, Utc::now());
        job.analysis.as_mut().unwrap().verification = None;
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::ModelVerificationOrResidencyFailed,
                message: "Model verification or residency failed".into(),
            }]
        );

        let mut job = eligible_job(&settings, account, 2, Utc::now());
        job.analysis.as_mut().unwrap().gpu_resident = false;
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::ModelVerificationOrResidencyFailed,
                message: "Model verification or residency failed".into(),
            }]
        );

        let mut job = eligible_job(&settings, account, 3, Utc::now());
        job.analysis.as_mut().unwrap().input_complete = false;
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::ModelVerificationOrResidencyFailed,
                message: "Model verification or residency failed".into(),
            }]
        );
    }

    /// Automatic policy blocks dispatch when the verified draft no longer
    /// matches the stored draft.
    ///
    /// Why: verification binds to one exact draft body — an origin change or a
    /// body edit after verification voids the evidence.
    #[test]
    fn automatic_policy_blocks_stale_draft_provenance() {
        let settings = armed();
        let account = "applicant@example.invalid";

        let mut job = eligible_job(&settings, account, 1, Utc::now());
        job.draft.as_mut().unwrap().origin = "human".into();
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::DraftVerificationStale,
                message: "Draft changed since verification".into(),
            }]
        );

        let mut job = eligible_job(&settings, account, 2, Utc::now());
        job.draft.as_mut().unwrap().body = "tampered body".into();
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::DraftVerificationStale,
                message: "Draft changed since verification".into(),
            }]
        );
    }

    /// Automatic policy enforces the send cooldown boundary and the
    /// enrollment cutoff.
    ///
    /// Why: the cooldown stops burst replies to one recipient and the
    /// enrollment cutoff stops retroactive replies to old mail — both are
    /// operator safety limits with exact boundaries.
    #[test]
    fn automatic_policy_enforces_the_cooldown_boundary_and_enrollment_cutoff() {
        let account = "applicant@example.invalid";

        // Exactly at the cooldown boundary the send is already allowed.
        let settings = armed();
        let mut job = eligible_job(&settings, account, 1, Utc::now());
        let now = Utc::now();
        job.drafted_at =
            Some(now - chrono::Duration::minutes(i64::from(settings.cooldown_minutes)));
        assert!(single(&job, &settings, now, account).is_empty());

        // One minute inside the cooldown the send is held.
        let mut job = eligible_job(&settings, account, 2, Utc::now());
        let now = Utc::now();
        job.drafted_at =
            Some(now - chrono::Duration::minutes(i64::from(settings.cooldown_minutes) - 1));
        assert_eq!(
            single(&job, &settings, now, account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::CooldownActive,
                message: "Cooldown active".into(),
            }]
        );

        // No draft timestamp is treated as "just drafted" and held.
        let mut job = eligible_job(&settings, account, 3, Utc::now());
        job.drafted_at = None;
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::CooldownActive,
                message: "Cooldown active".into(),
            }]
        );

        // Without backlog inclusion, mail from before enrollment is held even
        // when it is inside the lookback window.
        let mut settings = armed();
        settings.include_backlog = false;
        settings.automatic_since = Some(Utc::now() + chrono::Duration::hours(1));
        let job = eligible_job(&settings, account, 4, Utc::now());
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::PredatesAutomaticEnrollment,
                message: "Predates automatic-mode enrollment".into(),
            }]
        );
    }

    /// Automatic policy requires independent deterministic rejection evidence
    /// in the current message and blocks conflicting offer/interview language.
    ///
    /// Why: the classifier can be wrong; only an explicit rejection phrase in
    /// the message itself may authorize an unattended rejection, and offer
    /// language contradicts sending one.
    #[test]
    fn automatic_policy_enforces_deterministic_rejection_language() {
        let settings = armed();
        let account = "applicant@example.invalid";

        let mut job = eligible_job(&settings, account, 1, Utc::now());
        job.email.as_mut().unwrap().text =
            "Thank you for applying to the R&D Engineer role.".into();
        rebind_analysis(&mut job, &settings);
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::MissingDeterministicRejectionEvidence,
                message: "No independent clear rejection phrase in the current message".into(),
            }]
        );

        let mut job = eligible_job(&settings, account, 2, Utc::now());
        job.email.as_mut().unwrap().text = "We have decided not to move forward with your \
                                           application. We would like to offer you the position."
            .into();
        rebind_analysis(&mut job, &settings);
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::ConflictingEmailLanguage,
                message: "Conflicting or suspicious email language".into(),
            }]
        );
    }

    /// Automatic policy holds automatic-reply loops and bulk traffic, and
    /// refuses mismatched Reply-To targets.
    ///
    /// Why: replying to a list or an auto-submitted message creates mail
    /// loops, and a Reply-To that differs from the sender would send the
    /// rejection to a third party.
    #[test]
    fn automatic_policy_holds_reply_loops_bulk_traffic_and_reply_to_mismatches() {
        let settings = armed();
        let account = "applicant@example.invalid";

        for value in ["auto-replied", "Auto-Reply"] {
            let mut job = eligible_job(&settings, account, 1, Utc::now());
            job.email
                .as_mut()
                .unwrap()
                .headers
                .insert("auto-submitted".into(), vec![value.into()]);
            rebind_analysis(&mut job, &settings);
            assert_eq!(
                single(&job, &settings, Utc::now(), account),
                vec![
                    AutomaticPolicyBlock {
                        code: AutomaticPolicyCode::MailboxSafetyBlock,
                        message: "Automatic reply loop prevented".into(),
                    },
                    AutomaticPolicyBlock {
                        code: AutomaticPolicyCode::AutomaticReplyLoop,
                        message: "Automatic reply-loop marker requires Human review".into(),
                    },
                ],
                "auto-submitted={value} must hold the reply"
            );
        }
        for value in ["no", "auto-generated"] {
            let mut job = eligible_job(&settings, account, 2, Utc::now());
            job.email
                .as_mut()
                .unwrap()
                .headers
                .insert("auto-submitted".into(), vec![value.into()]);
            rebind_analysis(&mut job, &settings);
            assert!(
                single(&job, &settings, Utc::now(), account).is_empty(),
                "auto-submitted={value} is not a reply loop"
            );
        }

        for name in [
            "list-id",
            "list-unsubscribe",
            "precedence",
            "x-auto-response-suppress",
        ] {
            let mut job = eligible_job(&settings, account, 3, Utc::now());
            job.email
                .as_mut()
                .unwrap()
                .headers
                .insert(name.into(), vec!["bulk@example.invalid".into()]);
            rebind_analysis(&mut job, &settings);
            assert_eq!(
                single(&job, &settings, Utc::now(), account),
                vec![AutomaticPolicyBlock {
                    code: AutomaticPolicyCode::AutomaticReplySuppressed,
                    message: format!("Automatic replies suppressed by {name}"),
                }],
                "{name} must suppress automatic replies"
            );
        }

        let mut job = eligible_job(&settings, account, 4, Utc::now());
        job.email.as_mut().unwrap().reply_to = Some("other@example.invalid".into());
        rebind_analysis(&mut job, &settings);
        assert_eq!(
            single(&job, &settings, Utc::now(), account),
            vec![AutomaticPolicyBlock {
                code: AutomaticPolicyCode::ReplyToMismatch,
                message: "Reply-To differs from sender; human review required".into(),
            }]
        );

        let mut job = eligible_job(&settings, account, 5, Utc::now());
        job.email.as_mut().unwrap().reply_to = Some("hr5@example.invalid".into());
        rebind_analysis(&mut job, &settings);
        assert!(
            single(&job, &settings, Utc::now(), account).is_empty(),
            "a Reply-To equal to the sender is not a mismatch"
        );
    }

    /// The audit detail for an accepted enterprise policy pins the exact
    /// policy identity and says what was committed together.
    ///
    /// Why: the detail is the operator's rollback evidence — it must name the
    /// accepted policy id, revision and digest, not just "policy accepted".
    #[test]
    fn policy_acceptance_detail_pins_the_accepted_policy_identity() {
        let policy = loaded_policy(
            "digest-anchor-hint",
            EnterprisePolicy {
                version: 2,
                policy_id: Some("corp.anchor".into()),
                revision: Some(1),
                require_external_audit_anchor: true,
                ..Default::default()
            },
        );
        let message =
            staged_settings_detail(&Some(policy), true, false, false, false, false).unwrap();
        assert!(
            message.contains("policy_id=corp.anchor revision=1 sha256=digest-anchor-hint"),
            "the audit detail must pin the accepted policy identity: {message}"
        );
        assert!(
            message.contains("persisted settings and rollback floor committed together"),
            "the audit detail must say what was committed together: {message}"
        );
    }
}
