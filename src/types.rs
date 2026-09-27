use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn hash(value: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(value.as_ref()))
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Gmail,
    Demo,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stub {
    pub account: String,
    pub provider_id: String,
    pub thread_id: String,
    pub source: Source,
}
impl Stub {
    pub fn id(&self) -> String {
        hash(format!(
            "{}\0{:?}\0{}",
            self.account.to_lowercase(),
            self.source,
            self.provider_id
        ))
    }
    pub fn thread_key(&self) -> String {
        hash(format!(
            "{}\0{:?}\0{}",
            self.account.to_lowercase(),
            self.source,
            self.thread_id
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Email {
    pub stub: Stub,
    pub from: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub text: String,
    pub received_at: DateTime<Utc>,
    pub message_id: String,
    pub references: Vec<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub labels: Vec<String>,
    pub body_complete: bool,
}
impl Email {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }
    pub fn recipient(&self) -> anyhow::Result<String> {
        crate::mail::mailbox(self.reply_to.as_deref().unwrap_or(&self.from))
    }
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
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Rejection,
    Opportunity,
    Other,
    Uncertain,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    pub category: Category,
    /// A model's self-reported score, not a calibrated probability.
    pub confidence: u8,
    pub evidence: String,
    pub explanation: String,
    pub company: String,
    pub position: String,
    pub language: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub genuine_rejection: bool,
    pub claims_supported: bool,
    pub professional: bool,
    pub injection_free: bool,
    /// Whether the reply directly addresses the rejection and asks for individualized,
    /// specific assessment feedback rather than merely acknowledging the outcome.
    #[serde(default)]
    pub purpose_aligned: bool,
    pub reason: String,
}
impl Verification {
    pub fn passed(&self) -> bool {
        self.genuine_rejection
            && self.claims_supported
            && self.professional
            && self.injection_free
            && self.purpose_aligned
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Analysis {
    pub verdict: Verdict,
    pub verification: Option<Verification>,
    pub model: String,
    pub model_digest: String,
    pub prompt_version: String,
    pub email_fingerprint: String,
    pub verified_draft_hash: Option<String>,
    pub context_hash: String,
    pub input_complete: bool,
    pub gpu_resident: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Draft {
    pub body: String,
    pub origin: String,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Ready,
    Attention,
    Other,
    Deferred,
    Dismissed,
    Sending,
    Sent,
    Uncertain,
}
impl JobState {
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
    pub fn reviewable(self) -> bool {
        matches!(self, Self::Ready | Self::Attention)
    }

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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub stub: Stub,
    pub state: JobState,
    pub email: Option<Email>,
    pub analysis: Option<Analysis>,
    pub draft: Option<Draft>,
    pub drafted_at: Option<DateTime<Utc>>,
    pub flags: Vec<String>,
    pub revision: u64,
    pub attempts: u32,
    pub retry_at: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub provider_sent_id: Option<String>,
}
impl Job {
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncState {
    pub account: String,
    pub history_id: Option<String>,
    pub last_poll: Option<DateTime<Utc>>,
    pub last_full: Option<DateTime<Utc>>,
    pub lookback_days: u8,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counts {
    pub stored: u64,
    pub queued: u64,
    pub review: u64,
    pub sent: u64,
    pub uncertain: u64,
    pub attempts_24h: u64,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    #[default]
    Idle,
    Refresh,
    SyncMailbox,
    ConnectGmail,
    DisconnectGmail,
    UpdateSettings,
    InstallOllama,
    StartOllama,
    PullModel,
    InspectModel,
    QualifyModel,
    EvaluateModel,
    CompareModels,
    IntegrityCheck,
    Backup,
    Diagnostics,
    ListItems,
    SelectItem,
    EditDraft,
    RegenerateDraft,
    DismissItem,
    SendReply,
    ReconcileDelivery,
    PurgeRetention,
    RevealApiToken,
    HideApiToken,
    ApiRequest,
    AnalyzeQueuedMail,
    AutomaticDispatch,
}
impl OperationKind {
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
            Self::CompareModels => "model_comparison_failed",
            Self::IntegrityCheck => "database_integrity_failed",
            Self::Backup => "backup_failed",
            Self::Diagnostics => "diagnostics_export_failed",
            Self::ListItems => "item_listing_failed",
            Self::SelectItem => "item_selection_failed",
            Self::EditDraft => "draft_edit_failed",
            Self::RegenerateDraft => "draft_regeneration_failed",
            Self::DismissItem => "item_dismissal_failed",
            Self::SendReply => "reply_send_failed",
            Self::ReconcileDelivery => "delivery_reconciliation_failed",
            Self::PurgeRetention => "retention_purge_failed",
            Self::RevealApiToken => "api_token_reveal_failed",
            Self::HideApiToken => "api_token_hide_failed",
            Self::ApiRequest => "integration_api_request_failed",
            Self::AnalyzeQueuedMail => "mail_analysis_failed",
            Self::AutomaticDispatch => "automatic_dispatch_failed",
        }
    }

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
                | Self::CompareModels
                | Self::Backup
                | Self::Diagnostics
                | Self::SendReply
                | Self::ReconcileDelivery
                | Self::ApiRequest
                | Self::AnalyzeQueuedMail
                | Self::AutomaticDispatch
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    #[default]
    Idle,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationStatus {
    pub kind: OperationKind,
    pub state: OperationState,
    pub code: Option<String>,
    pub retryable: bool,
    pub message: String,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: i64,
    pub at: DateTime<Utc>,
    pub kind: String,
    pub item_id: Option<String>,
    pub detail: String,
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
            assert!(code.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
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
