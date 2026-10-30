use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Hash a value with SHA-256 for identities and fingerprints.
///
/// Inputs: `value` — any byte buffer. Output: `String` of lowercase hex.
pub fn hash(value: impl AsRef<[u8]>) -> String {
    crate::hex_lower(Sha256::digest(value.as_ref()))
}

/// Where one message originated.
///
/// Inputs: none (plain enum). Output: `Gmail` (live mailbox) or `Demo`
/// (synthetic demonstration data).
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Item synced from the connected Google mailbox.
    Gmail,
    /// Synthetic demo item.
    Demo,
}
/// Lightweight message identity that survives without the full email.
///
/// Inputs: none (plain struct). Output: the account, provider message id,
/// thread id and [`Source`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stub {
    /// Account key the stub belongs to.
    pub account: String,
    /// Provider message id.
    pub provider_id: String,
    /// Provider thread id.
    pub thread_id: String,
    /// Where the item came from.
    pub source: Source,
}
impl Stub {
    /// The stable message identity.
    ///
    /// Inputs: none beyond the stub. Output: `String` — hash of account, source
    /// and provider id.
    pub fn id(&self) -> String {
        hash(format!(
            "{}\0{:?}\0{}",
            self.account.to_lowercase(),
            self.source,
            self.provider_id
        ))
    }
    /// The stable thread identity.
    ///
    /// Inputs: none beyond the stub. Output: `String` — hash of account, source
    /// and thread id.
    pub fn thread_key(&self) -> String {
        hash(format!(
            "{}\0{:?}\0{}",
            self.account.to_lowercase(),
            self.source,
            self.thread_id
        ))
    }
}
/// One received message preserved for review.
///
/// Inputs: none (plain struct). Output: the [`Stub`], sender, subject, body,
/// routing headers and receipt metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Email {
    /// Provider identity stub for the message.
    pub stub: Stub,
    /// Sender address.
    pub from: String,
    /// Reply-to address, when the sender sets one.
    pub reply_to: Option<String>,
    /// Message subject line.
    pub subject: String,
    /// Normalized message body text.
    pub text: String,
    /// Provider timestamp of receipt.
    pub received_at: DateTime<Utc>,
    /// RFC `Message-ID` header value.
    pub message_id: String,
    /// `References` header values in provider order.
    pub references: Vec<String>,
    /// Full header map as received.
    pub headers: BTreeMap<String, Vec<String>>,
    /// Provider labels on the message.
    pub labels: Vec<String>,
    /// Whether the stored body is the complete body.
    pub body_complete: bool,
    /// Whether every tracked safety header was retained within bounds. A
    /// tracked header over the value cap is recorded as dropped without its
    /// attacker-sized value, so header-absence never reads as a genuine
    /// absence of a safety signal (security review finding 5).
    pub security_headers_complete: bool,
}
impl Email {
    /// Read the first value of one message header.
    ///
    /// Inputs: `name` — header name. Output: `Option<&str>` — the first matching
    /// value, if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }
    /// The normalized reply mailbox for this message.
    ///
    /// Inputs: none beyond the message. Output: `anyhow::Result<String>` — the
    /// reply-to mailbox, falling back to the sender.
    pub fn recipient(&self) -> anyhow::Result<String> {
        crate::mail::mailbox(self.reply_to.as_deref().unwrap_or(&self.from))
    }
    /// The content fingerprint used to detect message changes.
    ///
    /// Inputs: none beyond the message. Output: `String` fingerprint hash (labels
    /// are excluded; they are checked separately at send time).
    pub fn fingerprint(&self) -> String {
        // Gmail labels can legitimately change. They are checked separately at send time.
        hash(format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.stub.id(),
            self.from,
            self.reply_to.as_deref().unwrap_or(""),
            self.subject,
            self.text,
            self.received_at.timestamp_millis(),
            self.message_id
        ))
    }
}
/// Model classification of one message.
///
/// Inputs: none (plain enum). Output: `Rejection`, `Opportunity`, `Other` or
/// `Uncertain`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// The message is a rejection.
    Rejection,
    /// The message advances the application (interview or offer).
    Opportunity,
    /// The message is neither a rejection nor an opportunity.
    Other,
    /// The message cannot be classified confidently.
    Uncertain,
}
/// Model verdict for one message.
///
/// Inputs: none (plain struct). Output: the [`Category`], self-reported
/// confidence, evidence, explanation and the derived company, position and
/// language.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    /// Message category the model assigned.
    pub category: Category,
    /// A model's self-reported score, not a calibrated probability.
    pub confidence: u8,
    /// Quoted evidence supporting the classification.
    pub evidence: String,
    /// Model explanation of the classification.
    pub explanation: String,
    /// Company named in the message.
    pub company: String,
    /// Position named in the message.
    pub position: String,
    /// Detected message language.
    pub language: String,
}
/// Independent verifier's checks on one generated draft.
///
/// Inputs: none (plain struct). Output: the pass/fail checks — genuine
/// rejection, supported claims, professionalism, injection freedom and
/// purpose alignment — plus the verifier's reason.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    /// Whether the draft verifies as a genuine rejection reply.
    pub genuine_rejection: bool,
    /// Whether the draft claims are supported by the message.
    pub claims_supported: bool,
    /// Whether the draft meets the professional-tone standard.
    pub professional: bool,
    /// Whether the draft is free of injected instructions.
    pub injection_free: bool,
    /// Whether the reply directly addresses the rejection and asks for individualized,
    /// specific assessment feedback rather than merely acknowledging the outcome.
    #[serde(default)]
    pub purpose_aligned: bool,
    /// Verifier reason when verification fails.
    pub reason: String,
}
impl Verification {
    /// Whether every verification check passed.
    ///
    /// Inputs: none beyond the verification. Output: `true` only when all five
    /// checks pass.
    pub fn passed(&self) -> bool {
        self.genuine_rejection
            && self.claims_supported
            && self.professional
            && self.injection_free
            && self.purpose_aligned
    }

    /// Names of the verification checks that did not pass.
    ///
    /// Inputs: none beyond the verification. Output: `Vec<&'static str>` — the
    /// failing check names in declaration order (empty when all pass). Surfaces
    /// exactly which gate rejected a draft so failures are diagnosable rather
    /// than a single opaque "verification failed".
    pub fn failing_checks(&self) -> Vec<&'static str> {
        [
            ("genuine_rejection", self.genuine_rejection),
            ("claims_supported", self.claims_supported),
            ("professional", self.professional),
            ("injection_free", self.injection_free),
            ("purpose_aligned", self.purpose_aligned),
        ]
        .into_iter()
        .filter(|(_, ok)| !*ok)
        .map(|(name, _)| name)
        .collect()
    }
}

#[cfg(test)]
mod verification_tests {
    use super::Verification;

    fn v(g: bool, c: bool, p: bool, i: bool, pa: bool) -> Verification {
        Verification {
            genuine_rejection: g,
            claims_supported: c,
            professional: p,
            injection_free: i,
            purpose_aligned: pa,
            reason: String::default(),
        }
    }

    /// why: the smoke test must name exactly which gate rejected a draft, so a
    /// model failure is diagnosable rather than one opaque "verification failed".
    #[test]
    fn failing_checks_names_each_failed_gate_in_order() {
        assert!(v(true, true, true, true, true).failing_checks().is_empty());
        assert_eq!(
            v(false, true, true, true, false).failing_checks(),
            vec!["genuine_rejection", "purpose_aligned"]
        );
        assert_eq!(
            v(true, false, true, true, true).failing_checks(),
            vec!["claims_supported"]
        );
    }
}
/// Full model analysis recorded for one message.
///
/// Inputs: none (plain struct). Output: the [`Verdict`], optional
/// [`Verification`], the model and prompt identities and the email
/// fingerprint binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Analysis {
    /// Classification verdict for the message.
    pub verdict: Verdict,
    /// Draft verification outcome, when verified.
    pub verification: Option<Verification>,
    /// Model name used for the analysis.
    pub model: String,
    /// Digest of the model used for the analysis.
    pub model_digest: String,
    /// Verifier model name.
    #[serde(default)]
    pub verification_model: String,
    /// Digest of the verifier model.
    #[serde(default)]
    pub verification_model_digest: String,
    /// Prompt version used for the analysis.
    pub prompt_version: String,
    /// Fingerprint of the analyzed message.
    pub email_fingerprint: String,
    /// Hash of the draft that verification approved.
    pub verified_draft_hash: Option<String>,
    /// Hash of the analysis context.
    pub context_hash: String,
    /// Whether the model saw the complete input.
    pub input_complete: bool,
    /// Whether the model was GPU-resident during analysis.
    pub gpu_resident: bool,
}
/// One generated reply draft.
///
/// Inputs: none (plain struct). Output: the draft body and the origin tag
/// naming the producing path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Draft {
    /// Draft reply body text.
    pub body: String,
    /// Where the draft came from (model, operator, or demo).
    pub origin: String,
}

/// Stage that produced one processing failure.
///
/// Inputs: none (plain enum). Output: the failing stage code, serialized in
/// snake_case for storage and reporting.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingFailureCode {
    /// The stored message payload is malformed.
    MessageMalformed,
    /// Model preflight failed.
    ModelPreflight,
    /// Classification failed.
    Classification,
    /// Draft generation failed.
    DraftGeneration,
    /// The verification runtime failed.
    VerificationRuntime,
    /// Analysis failed for an unknown reason.
    AnalysisUnknown,
}
impl ProcessingFailureCode {
    /// The stable stored failure code.
    ///
    /// Inputs: none beyond the code. Output: `&'static str`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MessageMalformed => "message_malformed",
            Self::ModelPreflight => "model_preflight",
            Self::Classification => "classification",
            Self::DraftGeneration => "draft_generation",
            Self::VerificationRuntime => "verification_runtime",
            Self::AnalysisUnknown => "analysis_unknown",
        }
    }

    /// Parse a stored processing-failure code.
    ///
    /// Inputs: `value` — stored code string. Output: `Option<Self>`; `None` for
    /// unknown codes.
    pub fn from_db(value: &str) -> Option<Self> {
        Some(match value {
            "message_malformed" => Self::MessageMalformed,
            "model_preflight" => Self::ModelPreflight,
            "classification" => Self::Classification,
            "draft_generation" => Self::DraftGeneration,
            "verification_runtime" => Self::VerificationRuntime,
            "analysis_unknown" => Self::AnalysisUnknown,
            _ => return None,
        })
    }
}

/// Lifecycle state of one reviewable item.
///
/// Inputs: none (plain enum). Output: the state driving queue placement and
/// send eligibility.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// New item waiting for analysis.
    Queued,
    /// Analyzed and ready for review or sending.
    Ready,
    /// Needs operator attention before it can proceed.
    Attention,
    /// Classified as a non-rejection, non-opportunity message.
    Other,
    /// Parked for later reconsideration.
    Deferred,
    /// Closed without a reply.
    Dismissed,
    /// A reply send is reserved or in flight.
    Sending,
    /// The reply was accepted by the provider.
    Sent,
    /// Provider outcome is unknown; delivery needs reconciliation.
    Uncertain,
}
impl JobState {
    /// The stable stored job state name.
    ///
    /// Inputs: none beyond the state. Output: `&'static str`.
    pub fn db(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Ready => "ready",
            Self::Attention => "attention",
            Self::Other => "other",
            Self::Deferred => "deferred",
            Self::Dismissed => "dismissed",
            Self::Sending => "sending",
            Self::Sent => "sent",
            Self::Uncertain => "uncertain",
        }
    }
    /// The operator-facing job state label.
    ///
    /// Inputs: none beyond the state. Output: `&'static str` label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Awaiting analysis",
            Self::Ready => "Ready",
            Self::Attention => "Needs attention",
            Self::Other => "Not a rejection",
            Self::Deferred => "Outside current scope",
            Self::Dismissed => "Dismissed",
            Self::Sending => "Sending",
            Self::Sent => "Sent",
            Self::Uncertain => "Delivery uncertain",
        }
    }
    /// Whether the state is actionable in review.
    ///
    /// Inputs: none beyond the state. Output: `true` for the ready and attention
    /// states.
    pub fn reviewable(self) -> bool {
        matches!(self, Self::Ready | Self::Attention)
    }

    /// Parse a stored job state name.
    ///
    /// Inputs: `value` — stored state string. Output: `Option<Self>`; `None` for
    /// unknown states.
    pub fn from_db(value: &str) -> Option<Self> {
        Some(match value {
            "queued" => Self::Queued,
            "ready" => Self::Ready,
            "attention" => Self::Attention,
            "other" => Self::Other,
            "deferred" => Self::Deferred,
            "dismissed" => Self::Dismissed,
            "sending" => Self::Sending,
            "sent" => Self::Sent,
            "uncertain" => Self::Uncertain,
            _ => return None,
        })
    }

    /// Persisted lifecycle invariant. Same-state saves are allowed for metadata,
    /// retry counters, retention pruning and other non-transition updates.
    ///
    /// Inputs: `next` — requested next state. Output: `true` for allowed
    /// transitions (same-state saves included).
    pub fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Queued => matches!(
                next,
                Self::Ready | Self::Attention | Self::Other | Self::Deferred
            ),
            Self::Ready | Self::Attention => matches!(
                next,
                Self::Queued | Self::Attention | Self::Dismissed | Self::Deferred | Self::Sending
            ),
            Self::Deferred => next == Self::Queued,
            Self::Sending => matches!(next, Self::Attention | Self::Sent | Self::Uncertain),
            Self::Uncertain => next == Self::Sent,
            Self::Other | Self::Dismissed | Self::Sent => false,
        }
    }
}
/// One reviewable item: identity, analysis, draft and delivery posture.
///
/// Inputs: none (plain struct). Output: the [`Stub`], [`JobState`], the
/// stored [`Email`], [`Analysis`] and [`Draft`], flags, revision and retry
/// counters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    /// Stable item id.
    pub id: String,
    /// Provider identity stub for the item.
    pub stub: Stub,
    /// Current item state.
    pub state: JobState,
    /// Stored original message.
    pub email: Option<Email>,
    /// Stored analysis, when analyzed.
    pub analysis: Option<Analysis>,
    /// Stored draft, when drafted.
    pub draft: Option<Draft>,
    /// Timestamp of draft creation.
    pub drafted_at: Option<DateTime<Utc>>,
    /// Operator and system flags on the item.
    pub flags: Vec<String>,
    /// Optimistic-lock revision of the item.
    pub revision: u64,
    /// Send attempts made for the item.
    pub attempts: u32,
    /// Earliest timestamp of the next send attempt.
    pub retry_at: i64,
    /// Timestamp of item creation.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the last item update.
    pub updated_at: DateTime<Utc>,
    /// Provider id of the sent reply, when sent.
    pub provider_sent_id: Option<String>,
}
impl Job {
    /// Create a queued job from one provider stub.
    ///
    /// Inputs: `stub` — provider identity; `now` — creation timestamp. Output: [`Job`]
    /// in the queued state at revision zero.
    pub fn new(stub: Stub, now: DateTime<Utc>) -> Self {
        Self {
            id: stub.id(),
            stub,
            state: JobState::Queued,
            email: None,
            analysis: None,
            draft: None,
            drafted_at: None,
            flags: vec![],
            revision: 0,
            attempts: 0,
            retry_at: 0,
            created_at: now,
            updated_at: now,
            provider_sent_id: None,
        }
    }
}
/// Per-account mailbox synchronization position.
///
/// Inputs: none (plain struct). Output: the account, Gmail history id and
/// the last poll and full-sync instants with the lookback window.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncState {
    /// Account key the sync state belongs to.
    pub account: String,
    /// Provider history id the mailbox is synced to.
    pub history_id: Option<String>,
    /// Timestamp of the last provider poll.
    pub last_poll: Option<DateTime<Utc>>,
    /// Timestamp of the last full resync.
    pub last_full: Option<DateTime<Utc>>,
    /// Lookback window applied to sync, in days.
    pub lookback_days: u8,
}
/// Keyset cursor into the stored item list.
///
/// Inputs: none (plain struct). Output: the snapshot rowid and the last
/// delivered rowid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemCursor {
    /// Rowid the snapshot enumeration is anchored at.
    pub snapshot_rowid: i64,
    /// Last rowid returned to the client.
    pub last_rowid: i64,
}

/// One page of items with its continuation cursor.
///
/// Inputs: none (plain struct). Output: the page's [`Job`]s and the
/// [`ItemCursor`] for the next page.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemCursorPage {
    /// Items in this cursor page.
    pub items: Vec<Job>,
    /// Cursor for the next page, when more remain.
    pub next_cursor: Option<ItemCursor>,
}

/// Queue counters shown on every operator surface.
///
/// Inputs: none (plain struct). Output: stored, queued, review, sent and
/// uncertain totals plus the 24-hour attempt count.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counts {
    /// Number of stored items.
    pub stored: u64,
    /// Number of queued items.
    pub queued: u64,
    /// Number of items awaiting review.
    pub review: u64,
    /// Number of sent items.
    pub sent: u64,
    /// Number of deliveries awaiting reconciliation.
    pub uncertain: u64,
    /// Send attempts in the last 24 hours.
    pub attempts_24h: u64,
}
/// Kind of one background operation.
///
/// Inputs: none (plain enum). Output: the operation label driving status
/// reporting.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// No operation is running.
    #[default]
    Idle,
    /// Recompute and publish the worker snapshot.
    Refresh,
    /// Synchronize the mailbox with the provider.
    SyncMailbox,
    /// Connect the Google account.
    ConnectGmail,
    /// Disconnect the Google account.
    DisconnectGmail,
    /// Apply settings changes.
    UpdateSettings,
    /// Install the local Ollama runtime.
    InstallOllama,
    /// Start the local Ollama runtime.
    StartOllama,
    /// Pull the primary local model.
    PullModel,
    /// Inspect the primary local model.
    InspectModel,
    /// Run the task-qualification suite for the primary model.
    QualifyModel,
    /// Run the evaluation suite for the model.
    EvaluateModel,
    /// Profile model performance and residency.
    ProfileModel,
    /// Compare two model profiles.
    CompareModels,
    /// Recheck stored evidence integrity.
    IntegrityCheck,
    /// Compact the SQLite database.
    CompactDatabase,
    /// Create a backup.
    Backup,
    /// Verify that a backup restores successfully.
    RecoveryDrill,
    /// Export the recovery key envelope.
    RecoveryKeyExport,
    /// Verify a recovery key envelope.
    RecoveryKeyVerify,
    /// Collect privacy-safe diagnostics evidence.
    Diagnostics,
    /// List stored review items.
    ListItems,
    /// Select the active review item.
    SelectItem,
    /// Edit the draft body.
    EditDraft,
    /// Regenerate the draft from the model.
    RegenerateDraft,
    /// Dismiss the selected item.
    DismissItem,
    /// Send the approved reply.
    SendReply,
    /// Reconcile an uncertain delivery.
    ReconcileDelivery,
    /// Purge items past the retention window.
    PurgeRetention,
    /// Reveal the local API token.
    RevealApiToken,
    /// Hide the local API token.
    HideApiToken,
    /// Rotate the local API token.
    RotateApiToken,
    /// Serve a local API request.
    ApiRequest,
    /// Reload the enterprise policy.
    EnterprisePolicyReload,
    /// Analyze a queued message locally.
    AnalyzeQueuedMail,
    /// Run one automatic-dispatch pass.
    AutomaticDispatch,
}
impl OperationKind {
    /// The stable failure code for this operation kind.
    ///
    /// Inputs: none beyond the kind. Output: `&'static str` code.
    pub fn failure_code(self) -> &'static str {
        match self {
            Self::Idle => "operation_idle",
            Self::Refresh => "refresh_failed",
            Self::SyncMailbox => "mailbox_sync_failed",
            Self::ConnectGmail => "gmail_connect_failed",
            Self::DisconnectGmail => "gmail_disconnect_failed",
            Self::UpdateSettings => "settings_update_failed",
            Self::InstallOllama => "ollama_install_failed",
            Self::StartOllama => "ollama_start_failed",
            Self::PullModel => "model_download_failed",
            Self::InspectModel => "model_inspection_failed",
            Self::QualifyModel => "model_smoke_qualification_failed",
            Self::EvaluateModel => "model_task_evaluation_failed",
            remaining => remaining.data_failure_code(),
        }
    }

    /// Failure codes for the model-data and recovery operations.
    ///
    /// Inputs: none beyond the kind. Output: `&'static str` code.
    fn data_failure_code(self) -> &'static str {
        match self {
            Self::ProfileModel => "model_runtime_profile_failed",
            Self::CompareModels => "model_comparison_failed",
            Self::IntegrityCheck => "database_integrity_failed",
            Self::CompactDatabase => "database_compaction_failed",
            Self::Backup => "backup_failed",
            Self::RecoveryDrill => "recovery_drill_failed",
            Self::RecoveryKeyExport => "recovery_key_export_failed",
            Self::RecoveryKeyVerify => "recovery_key_verification_failed",
            Self::Diagnostics => "diagnostics_export_failed",
            Self::ListItems => "item_listing_failed",
            Self::SelectItem => "item_selection_failed",
            Self::EditDraft => "draft_edit_failed",
            remaining => remaining.dispatch_failure_code(),
        }
    }

    /// Failure codes for the dispatch and policy operations.
    ///
    /// Inputs: none beyond the kind. Output: `&'static str` code.
    fn dispatch_failure_code(self) -> &'static str {
        match self {
            Self::RegenerateDraft => "draft_regeneration_failed",
            Self::DismissItem => "item_dismissal_failed",
            Self::SendReply => "reply_send_failed",
            Self::ReconcileDelivery => "delivery_reconciliation_failed",
            Self::PurgeRetention => "retention_purge_failed",
            Self::RevealApiToken => "api_token_reveal_failed",
            Self::HideApiToken => "api_token_hide_failed",
            Self::RotateApiToken => "api_token_rotation_failed",
            Self::ApiRequest => "integration_api_request_failed",
            Self::EnterprisePolicyReload => "enterprise_policy_reload_failed",
            Self::AnalyzeQueuedMail => "mail_analysis_failed",
            Self::AutomaticDispatch => "automatic_dispatch_failed",
            // Unreachable for the kinds matched above; kept so a new kind
            // added without a code fails closed instead of panicking.
            _ => "operation_failed",
        }
    }

    /// Operations for which process termination can leave an external side
    /// effect ambiguous or an operator artifact incomplete. SQLite-only
    /// transactions are intentionally excluded because they roll back atomically.
    ///
    /// Inputs: none beyond the kind. Output: `true` for operations whose
    /// interruption can leave an external side effect ambiguous.
    pub fn shutdown_sensitive(self) -> bool {
        matches!(
            self,
            Self::SendReply | Self::AutomaticDispatch | Self::Backup | Self::RecoveryDrill
        )
    }

    /// Whether a failed operation of this kind may be retried safely.
    ///
    /// Inputs: none beyond the kind. Output: `true` for the idempotent, retryable
    /// operations.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::Refresh
                | Self::SyncMailbox
                | Self::ConnectGmail
                | Self::StartOllama
                | Self::PullModel
                | Self::InspectModel
                | Self::QualifyModel
                | Self::EvaluateModel
                | Self::ProfileModel
                | Self::CompareModels
                | Self::CompactDatabase
                | Self::Backup
                | Self::RecoveryDrill
                | Self::RecoveryKeyExport
                | Self::RecoveryKeyVerify
                | Self::Diagnostics
                | Self::ReconcileDelivery
                | Self::ApiRequest
                | Self::EnterprisePolicyReload
                | Self::AnalyzeQueuedMail
        )
    }

    /// Monitoring threshold, not a cancellation deadline. A worker that has not
    /// reported progress within this operation-specific budget is considered
    /// stalled by the direct liveness endpoint.
    ///
    /// Inputs: none beyond the kind. Output: `u64` seconds before the operation
    /// counts as stalled.
    pub fn stall_budget_seconds(self) -> u64 {
        match self {
            Self::Idle => 10,
            Self::Refresh
            | Self::ListItems
            | Self::SelectItem
            | Self::EditDraft
            | Self::RegenerateDraft
            | Self::DismissItem
            | Self::RevealApiToken
            | Self::HideApiToken
            | Self::RotateApiToken
            | Self::ApiRequest => 30,
            Self::UpdateSettings | Self::DisconnectGmail => 60,
            Self::StartOllama | Self::InspectModel | Self::EnterprisePolicyReload => 120,
            Self::SendReply | Self::AutomaticDispatch | Self::ReconcileDelivery => 300,
            Self::ConnectGmail
            | Self::SyncMailbox
            | Self::RecoveryKeyExport
            | Self::RecoveryKeyVerify
            | Self::Diagnostics
            | Self::PurgeRetention => 600,
            Self::QualifyModel | Self::AnalyzeQueuedMail | Self::IntegrityCheck => 1_800,
            Self::InstallOllama | Self::CompactDatabase | Self::Backup | Self::RecoveryDrill => {
                3_600
            }
            Self::PullModel | Self::EvaluateModel | Self::ProfileModel => 7_200,
            Self::CompareModels => 21_600,
        }
    }
}

#[cfg(test)]
mod operation_kind_tests {
    use super::{FailureDisposition, OperationKind, OperationState, OperationStatus};

    #[test]
    fn stall_budgets_are_explicit_and_sane() {
        assert_eq!(OperationKind::Idle.stall_budget_seconds(), 10);
        assert!(OperationKind::SendReply.stall_budget_seconds() >= 120);
        assert!(
            OperationKind::EvaluateModel.stall_budget_seconds()
                > OperationKind::AnalyzeQueuedMail.stall_budget_seconds()
        );
        assert_eq!(
            OperationKind::ProfileModel.stall_budget_seconds(),
            OperationKind::EvaluateModel.stall_budget_seconds()
        );
        assert!(
            OperationKind::CompareModels.stall_budget_seconds()
                >= OperationKind::EvaluateModel.stall_budget_seconds()
        );
    }

    #[test]
    fn failure_disposition_is_derived_from_stable_codes() {
        let mut status = OperationStatus {
            state: OperationState::Failed,
            code: Some("reconcile_required_delivery_uncertain".into()),
            retryable: false,
            ..OperationStatus::default()
        };
        assert_eq!(
            status.failure_disposition(),
            FailureDisposition::ReconcileRequired
        );
        status.code = Some("review_required_gmail_send_rejected".into());
        assert_eq!(
            status.failure_disposition(),
            FailureDisposition::ReviewRequired
        );
        status.code = Some("mailbox_sync_failed".into());
        status.retryable = true;
        assert_eq!(status.failure_disposition(), FailureDisposition::Retryable);
        status.retryable = false;
        assert_eq!(
            status.failure_disposition(),
            FailureDisposition::NonRetryable
        );
        status.state = OperationState::Succeeded;
        assert_eq!(status.failure_disposition(), FailureDisposition::None);
    }

    #[test]
    fn shutdown_sensitive_operations_are_explicit_and_narrow() {
        for kind in [
            OperationKind::SendReply,
            OperationKind::AutomaticDispatch,
            OperationKind::Backup,
            OperationKind::RecoveryDrill,
        ] {
            assert!(kind.shutdown_sensitive(), "{kind:?}");
        }
        for kind in [
            OperationKind::Refresh,
            OperationKind::SyncMailbox,
            OperationKind::UpdateSettings,
            OperationKind::RecoveryKeyExport,
            OperationKind::RecoveryKeyVerify,
            OperationKind::Diagnostics,
            OperationKind::PurgeRetention,
        ] {
            assert!(!kind.shutdown_sensitive(), "{kind:?}");
        }
    }
}

/// Lifecycle state of one operation.
///
/// Inputs: none (plain enum). Output: `Idle`, `Running`, `Succeeded` or
/// `Failed`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// No operation in progress.
    #[default]
    Idle,
    /// The operation is in progress.
    Running,
    /// The operation finished successfully.
    Succeeded,
    /// The operation failed.
    Failed,
}

/// How a failed operation should be recovered.
///
/// Inputs: none (plain enum). Output: the disposition from `None` through
/// `Retryable` to `NonRetryable`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureDisposition {
    /// No failure disposition is recorded.
    #[default]
    None,
    /// The operation may be retried automatically.
    Retryable,
    /// The operator must review before retrying.
    ReviewRequired,
    /// Delivery state must be reconciled with the provider.
    ReconcileRequired,
    /// The operation must not be retried.
    NonRetryable,
}

/// Status of the current or last worker operation.
///
/// Inputs: none (plain struct). Output: the correlation id,
/// [`OperationKind`] and [`OperationState`], failure code, retryability and
/// timing.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationStatus {
    /// Locally generated correlation UUID for one worker operation lifecycle.
    pub operation_id: Option<String>,
    /// Kind of the operation being reported.
    pub kind: OperationKind,
    /// Current state of the operation.
    pub state: OperationState,
    /// Stable result code, when the operation finished.
    pub code: Option<String>,
    /// Whether the failed operation may be retried.
    pub retryable: bool,
    /// Operator-facing status message.
    pub message: String,
    /// Timestamp of operation start.
    pub started_at: Option<DateTime<Utc>>,
    /// Timestamp of operation completion.
    pub finished_at: Option<DateTime<Utc>>,
}

impl OperationStatus {
    /// Interpret the stable failure-code contract without changing the serialized
    /// OperationStatus layout used by existing integrations.
    ///
    /// Inputs: none beyond the status. Output: [`FailureDisposition`] derived from
    /// the stable failure-code prefix and the retryable flag.
    pub fn failure_disposition(&self) -> FailureDisposition {
        if self.state != OperationState::Failed {
            return FailureDisposition::None;
        }
        match self.code.as_deref() {
            Some(code) if code.starts_with("reconcile_required_") => {
                FailureDisposition::ReconcileRequired
            }
            Some(code) if code.starts_with("review_required_") => {
                FailureDisposition::ReviewRequired
            }
            _ if self.retryable => FailureDisposition::Retryable,
            _ => FailureDisposition::NonRetryable,
        }
    }
}

/// Worker heartbeat summary for stall detection.
///
/// Inputs: none (plain struct). Output: responsiveness, last-progress age,
/// current-operation age and the stall budget.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerLiveness {
    /// Schema version of the liveness record.
    pub schema_version: u32,
    /// Whether the worker is responsive.
    pub worker_responsive: bool,
    /// Timestamp of the last worker progress.
    pub last_progress_at: DateTime<Utc>,
    /// Age of the last worker progress in seconds.
    pub progress_age_seconds: i64,
    /// Operation currently in flight.
    pub current_operation: OperationKind,
    /// Timestamp of current operation start.
    pub operation_started_at: Option<DateTime<Utc>>,
    /// Age of the current operation in seconds.
    pub operation_age_seconds: Option<i64>,
    /// Seconds after which the operation is considered stalled.
    pub stall_budget_seconds: u64,
}

/// Subsystem one audit event belongs to.
///
/// Inputs: none (plain enum). Output: the domain keying audit filtering.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuditDomain {
    /// Mailbox synchronization and message handling.
    Mail,
    /// Reply delivery and reconciliation.
    Delivery,
    /// Local model and verification activity.
    Model,
    /// Settings changes.
    Settings,
    /// Enterprise policy activity.
    Policy,
    /// Authentication, token and vault activity.
    Security,
    /// Backup and recovery operations.
    Recovery,
    /// External integration API activity.
    Integration,
    /// Retention purge activity.
    Retention,
    /// Database storage maintenance.
    Storage,
    /// Background worker lifecycle.
    Worker,
    /// Activity that does not fit another domain.
    #[default]
    Other,
}
impl AuditDomain {
    /// The stable stored audit domain name.
    ///
    /// Inputs: none beyond the domain. Output: `&'static str`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mail => "mail",
            Self::Delivery => "delivery",
            Self::Model => "model",
            Self::Settings => "settings",
            Self::Policy => "policy",
            Self::Security => "security",
            Self::Recovery => "recovery",
            Self::Integration => "integration",
            Self::Retention => "retention",
            Self::Storage => "storage",
            Self::Worker => "worker",
            Self::Other => "other",
        }
    }
}

/// Severity of one audit event.
///
/// Inputs: none (plain enum). Output: `Info`, `Warning`, `Error` or
/// `Security`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    /// Informational record with no operator action implied.
    #[default]
    Info,
    /// Notable condition the operator should review.
    Warning,
    /// A failed operation.
    Error,
    /// Security-relevant activity or failure.
    Security,
}
impl AuditSeverity {
    /// The stable stored audit severity name.
    ///
    /// Inputs: none beyond the severity. Output: `&'static str`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Security => "security",
        }
    }
}

/// Classify an audit event kind into domain and severity.
///
/// Inputs: `kind` — audit event kind. Output: `(AuditDomain, AuditSeverity)`
/// derived from the kind's prefix.
pub fn audit_attributes(kind: &str) -> (AuditDomain, AuditSeverity) {
    (audit_domain(kind), audit_severity(kind))
}

/// Map an audit event kind to its subsystem domain.
///
/// Inputs: `kind` — audit event kind. Output: [`AuditDomain`] derived from
/// the kind's prefix.
fn audit_domain(kind: &str) -> AuditDomain {
    if kind.starts_with("email.")
        || kind.starts_with("gmail.")
        || kind.starts_with("account.")
        || kind.starts_with("sync.")
    {
        AuditDomain::Mail
    } else if kind.starts_with("delivery.") {
        AuditDomain::Delivery
    } else if kind.starts_with("model.") {
        AuditDomain::Model
    } else if kind.starts_with("settings.") {
        AuditDomain::Settings
    } else if kind.starts_with("policy.") || kind.starts_with("enterprise.") {
        AuditDomain::Policy
    } else if kind.starts_with("security.") || kind.starts_with("audit.") {
        AuditDomain::Security
    } else if kind.starts_with("backup.") || kind.starts_with("restore.") {
        AuditDomain::Recovery
    } else {
        audit_domain_tail(kind)
    }
}

/// Domain classification for the integration, retention and worker prefixes.
///
/// Inputs: `kind` — audit event kind. Output: [`AuditDomain`].
fn audit_domain_tail(kind: &str) -> AuditDomain {
    if kind.starts_with("api.") || kind.starts_with("integration.") {
        AuditDomain::Integration
    } else if kind.starts_with("content.") || kind.starts_with("retention.") {
        AuditDomain::Retention
    } else if kind.starts_with("database.") || kind.starts_with("storage.") {
        AuditDomain::Storage
    } else if kind.starts_with("worker.") {
        AuditDomain::Worker
    } else {
        AuditDomain::Other
    }
}

/// Map an audit event kind to its severity.
///
/// Inputs: `kind` — audit event kind. Output: [`AuditSeverity`] derived from
/// the kind's keywords.
fn audit_severity(kind: &str) -> AuditSeverity {
    if kind.contains("security") || kind.contains("tamper") || kind.contains("integrity_failed") {
        AuditSeverity::Security
    } else if kind.contains("failed") || kind.contains("error") || kind.contains("fatal") {
        AuditSeverity::Error
    } else if kind.contains("uncertain")
        || kind.contains("rejected")
        || kind.contains("repaired")
        || kind.contains("blocked")
        || kind.contains("disabled")
    {
        AuditSeverity::Warning
    } else {
        AuditSeverity::Info
    }
}

/// One appended audit-trail entry.
///
/// Inputs: none (plain struct). Output: the sequence number, timestamp,
/// kind, [`AuditDomain`], [`AuditSeverity`], optional item id and detail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Monotonic audit sequence of the event.
    pub seq: i64,
    /// Timestamp of the event.
    pub at: DateTime<Utc>,
    /// Stable event kind name.
    pub kind: String,
    /// Audit domain the event belongs to.
    #[serde(default)]
    pub domain: AuditDomain,
    /// Severity of the event.
    #[serde(default)]
    pub severity: AuditSeverity,
    /// Item the event refers to, when item-scoped.
    pub item_id: Option<String>,
    /// Operator-facing event detail.
    pub detail: String,
}

#[cfg(test)]
mod audit_event_tests {
    use super::*;

    #[test]
    fn audit_event_classification_is_stable_and_conservative() {
        assert_eq!(
            audit_attributes("delivery.uncertain"),
            (AuditDomain::Delivery, AuditSeverity::Warning)
        );
        assert_eq!(
            audit_attributes("model.task_rejected"),
            (AuditDomain::Model, AuditSeverity::Warning)
        );
        assert_eq!(
            audit_attributes("audit.integrity_failed"),
            (AuditDomain::Security, AuditSeverity::Security)
        );
        assert_eq!(
            audit_attributes("email.queued"),
            (AuditDomain::Mail, AuditSeverity::Info)
        );
        assert_eq!(
            audit_attributes("unknown.event"),
            (AuditDomain::Other, AuditSeverity::Info)
        );
    }

    #[test]
    fn legacy_audit_event_defaults_new_operational_fields() {
        let value = serde_json::json!({
            "seq": 1,
            "at": "2026-09-27T00:00:00Z",
            "kind": "legacy.event",
            "item_id": null,
            "detail": "legacy"
        });
        let event: AuditEvent = serde_json::from_value(value).unwrap();
        assert_eq!(event.domain, AuditDomain::Other);
        assert_eq!(event.severity, AuditSeverity::Info);
    }
}

#[cfg(test)]
mod operation_status_tests {
    use super::*;

    #[test]
    fn operation_failure_codes_are_stable_and_nonempty() {
        let kinds = [
            OperationKind::SyncMailbox,
            OperationKind::ConnectGmail,
            OperationKind::UpdateSettings,
            OperationKind::EvaluateModel,
            OperationKind::IntegrityCheck,
            OperationKind::Backup,
            OperationKind::SendReply,
            OperationKind::AutomaticDispatch,
        ];
        for kind in kinds {
            let code = kind.failure_code();
            assert!(!code.is_empty());
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
        assert!(OperationKind::SyncMailbox.retryable());
        assert!(!OperationKind::UpdateSettings.retryable());
    }
}

#[cfg(test)]
mod job_state_tests {
    use super::JobState;

    #[test]
    fn persisted_state_machine_rejects_terminal_reopen_and_illegal_jumps() {
        assert!(JobState::Queued.can_transition_to(JobState::Ready));
        assert!(JobState::Queued.can_transition_to(JobState::Deferred));
        assert!(!JobState::Queued.can_transition_to(JobState::Sent));

        assert!(JobState::Ready.can_transition_to(JobState::Sending));
        assert!(JobState::Attention.can_transition_to(JobState::Queued));
        assert!(!JobState::Ready.can_transition_to(JobState::Sent));

        assert!(JobState::Deferred.can_transition_to(JobState::Queued));
        assert!(!JobState::Deferred.can_transition_to(JobState::Ready));

        assert!(JobState::Sending.can_transition_to(JobState::Uncertain));
        assert!(JobState::Sending.can_transition_to(JobState::Sent));
        assert!(JobState::Uncertain.can_transition_to(JobState::Sent));
        assert!(!JobState::Uncertain.can_transition_to(JobState::Ready));

        for terminal in [JobState::Other, JobState::Dismissed, JobState::Sent] {
            assert!(terminal.can_transition_to(terminal));
            assert!(!terminal.can_transition_to(JobState::Queued));
            assert!(!terminal.can_transition_to(JobState::Ready));
        }
    }

    #[test]
    fn database_state_round_trip_is_complete() {
        for state in [
            JobState::Queued,
            JobState::Ready,
            JobState::Attention,
            JobState::Other,
            JobState::Deferred,
            JobState::Dismissed,
            JobState::Sending,
            JobState::Sent,
            JobState::Uncertain,
        ] {
            assert_eq!(JobState::from_db(state.db()), Some(state));
        }
        assert_eq!(JobState::from_db("unknown"), None);
    }
}

#[cfg(test)]
mod stable_string_mapping_tests {
    use super::*;

    /// Why: these strings are persisted in the database and consumed by the
    /// integration API; every variant must keep its exact stable code and every
    /// code must decode back, so a renamed arm fails here instead of silently
    /// breaking stored records.
    #[test]
    fn processing_failure_codes_round_trip_with_exact_stable_strings() {
        for (code, expected) in [
            (ProcessingFailureCode::MessageMalformed, "message_malformed"),
            (ProcessingFailureCode::ModelPreflight, "model_preflight"),
            (ProcessingFailureCode::Classification, "classification"),
            (ProcessingFailureCode::DraftGeneration, "draft_generation"),
            (
                ProcessingFailureCode::VerificationRuntime,
                "verification_runtime",
            ),
            (ProcessingFailureCode::AnalysisUnknown, "analysis_unknown"),
        ] {
            assert_eq!(code.as_str(), expected);
            assert_eq!(ProcessingFailureCode::from_db(expected), Some(code));
        }
        assert_eq!(ProcessingFailureCode::from_db("unknown_code"), None);
        assert_eq!(ProcessingFailureCode::from_db(""), None);
    }

    /// Why: operator-facing queue labels are shown verbatim in every interface;
    /// renaming one silently changes the product surface.
    #[test]
    fn job_state_labels_are_pinned() {
        for (state, label) in [
            (JobState::Queued, "Awaiting analysis"),
            (JobState::Ready, "Ready"),
            (JobState::Attention, "Needs attention"),
            (JobState::Other, "Not a rejection"),
            (JobState::Deferred, "Outside current scope"),
            (JobState::Dismissed, "Dismissed"),
            (JobState::Sending, "Sending"),
            (JobState::Sent, "Sent"),
            (JobState::Uncertain, "Delivery uncertain"),
        ] {
            assert_eq!(state.label(), label);
        }
    }

    /// Why: failure codes reach the operations journal and liveness endpoint;
    /// the exact code strings and their lowercase contract are API-visible.
    #[test]
    fn every_operation_kind_has_a_stable_failure_code() {
        for (kind, code) in [
            (OperationKind::Idle, "operation_idle"),
            (OperationKind::Refresh, "refresh_failed"),
            (OperationKind::SyncMailbox, "mailbox_sync_failed"),
            (OperationKind::ConnectGmail, "gmail_connect_failed"),
            (OperationKind::DisconnectGmail, "gmail_disconnect_failed"),
            (OperationKind::UpdateSettings, "settings_update_failed"),
            (OperationKind::InstallOllama, "ollama_install_failed"),
            (OperationKind::StartOllama, "ollama_start_failed"),
            (OperationKind::PullModel, "model_download_failed"),
            (OperationKind::InspectModel, "model_inspection_failed"),
            (
                OperationKind::QualifyModel,
                "model_smoke_qualification_failed",
            ),
            (OperationKind::EvaluateModel, "model_task_evaluation_failed"),
            (OperationKind::ProfileModel, "model_runtime_profile_failed"),
            (OperationKind::CompareModels, "model_comparison_failed"),
            (OperationKind::IntegrityCheck, "database_integrity_failed"),
            (OperationKind::CompactDatabase, "database_compaction_failed"),
            (OperationKind::Backup, "backup_failed"),
            (OperationKind::RecoveryDrill, "recovery_drill_failed"),
            (
                OperationKind::RecoveryKeyExport,
                "recovery_key_export_failed",
            ),
            (
                OperationKind::RecoveryKeyVerify,
                "recovery_key_verification_failed",
            ),
            (OperationKind::Diagnostics, "diagnostics_export_failed"),
            (OperationKind::ListItems, "item_listing_failed"),
            (OperationKind::SelectItem, "item_selection_failed"),
            (OperationKind::EditDraft, "draft_edit_failed"),
            (OperationKind::RegenerateDraft, "draft_regeneration_failed"),
            (OperationKind::DismissItem, "item_dismissal_failed"),
            (OperationKind::SendReply, "reply_send_failed"),
            (
                OperationKind::ReconcileDelivery,
                "delivery_reconciliation_failed",
            ),
            (OperationKind::PurgeRetention, "retention_purge_failed"),
            (OperationKind::RevealApiToken, "api_token_reveal_failed"),
            (OperationKind::HideApiToken, "api_token_hide_failed"),
            (OperationKind::RotateApiToken, "api_token_rotation_failed"),
            (OperationKind::ApiRequest, "integration_api_request_failed"),
            (
                OperationKind::EnterprisePolicyReload,
                "enterprise_policy_reload_failed",
            ),
            (OperationKind::AnalyzeQueuedMail, "mail_analysis_failed"),
            (
                OperationKind::AutomaticDispatch,
                "automatic_dispatch_failed",
            ),
        ] {
            assert_eq!(kind.failure_code(), code);
        }
    }

    /// Why: stall budgets are the liveness thresholds that decide when an
    /// operator is told an operation may be stuck; every variant keeps its
    /// explicit budget so a merge cannot silently retune one operation's
    /// watchdog.
    #[test]
    fn stall_budgets_are_pinned_per_operation() {
        for (kind, seconds) in [
            (OperationKind::Refresh, 30),
            (OperationKind::ListItems, 30),
            (OperationKind::ApiRequest, 30),
            (OperationKind::UpdateSettings, 60),
            (OperationKind::DisconnectGmail, 60),
            (OperationKind::StartOllama, 120),
            (OperationKind::InspectModel, 120),
            (OperationKind::EnterprisePolicyReload, 120),
            (OperationKind::SendReply, 300),
            (OperationKind::AutomaticDispatch, 300),
            (OperationKind::ReconcileDelivery, 300),
            (OperationKind::ConnectGmail, 600),
            (OperationKind::SyncMailbox, 600),
            (OperationKind::RecoveryKeyExport, 600),
            (OperationKind::RecoveryKeyVerify, 600),
            (OperationKind::Diagnostics, 600),
            (OperationKind::PurgeRetention, 600),
            (OperationKind::QualifyModel, 1_800),
            (OperationKind::AnalyzeQueuedMail, 1_800),
            (OperationKind::IntegrityCheck, 1_800),
            (OperationKind::InstallOllama, 3_600),
            (OperationKind::CompactDatabase, 3_600),
            (OperationKind::Backup, 3_600),
            (OperationKind::RecoveryDrill, 3_600),
            (OperationKind::PullModel, 7_200),
            (OperationKind::EvaluateModel, 7_200),
            (OperationKind::ProfileModel, 7_200),
            (OperationKind::CompareModels, 21_600),
        ] {
            assert_eq!(kind.stall_budget_seconds(), seconds);
        }
    }

    /// Why: audit domains and severities are stored with every journal row and
    /// drive retention/escalation filters; the wire strings must not drift.
    #[test]
    fn audit_domain_and_severity_strings_are_pinned() {
        for (domain, name) in [
            (AuditDomain::Mail, "mail"),
            (AuditDomain::Delivery, "delivery"),
            (AuditDomain::Model, "model"),
            (AuditDomain::Settings, "settings"),
            (AuditDomain::Policy, "policy"),
            (AuditDomain::Security, "security"),
            (AuditDomain::Recovery, "recovery"),
            (AuditDomain::Integration, "integration"),
            (AuditDomain::Retention, "retention"),
            (AuditDomain::Storage, "storage"),
            (AuditDomain::Worker, "worker"),
            (AuditDomain::Other, "other"),
        ] {
            assert_eq!(domain.as_str(), name);
        }
        for (severity, name) in [
            (AuditSeverity::Info, "info"),
            (AuditSeverity::Warning, "warning"),
            (AuditSeverity::Error, "error"),
            (AuditSeverity::Security, "security"),
        ] {
            assert_eq!(severity.as_str(), name);
        }
    }

    /// Why: journal routing must classify every operational area; a kind that
    /// falls into `Other`/`Info` by accident hides failures from operators.
    #[test]
    fn audit_attributes_cover_every_domain_and_error_severity() {
        assert_eq!(
            audit_attributes("settings.changed"),
            (AuditDomain::Settings, AuditSeverity::Info)
        );
        assert_eq!(
            audit_attributes("policy.reloaded"),
            (AuditDomain::Policy, AuditSeverity::Info)
        );
        assert_eq!(
            audit_attributes("enterprise.enforced"),
            (AuditDomain::Policy, AuditSeverity::Info)
        );
        assert_eq!(
            audit_attributes("api.token_rotated"),
            (AuditDomain::Integration, AuditSeverity::Info)
        );
        assert_eq!(
            audit_attributes("integration.request"),
            (AuditDomain::Integration, AuditSeverity::Info)
        );
        assert_eq!(
            audit_attributes("worker.stalled"),
            (AuditDomain::Worker, AuditSeverity::Info)
        );
        assert_eq!(
            audit_attributes("backup.failed"),
            (AuditDomain::Recovery, AuditSeverity::Error)
        );
        assert_eq!(
            audit_attributes("db.error"),
            (AuditDomain::Other, AuditSeverity::Error)
        );
        assert_eq!(
            audit_attributes("job.fatal"),
            (AuditDomain::Other, AuditSeverity::Error)
        );
    }
}
