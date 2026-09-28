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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ItemCursor {
    pub snapshot_rowid: i64,
    pub last_rowid: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemCursorPage {
    pub items: Vec<Job>,
    pub next_cursor: Option<ItemCursor>,
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
    RecoveryDrill,
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
    RotateApiToken,
    ApiRequest,
    EnterprisePolicyReload,
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
            Self::RecoveryDrill => "recovery_drill_failed",
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
            Self::RotateApiToken => "api_token_rotation_failed",
            Self::ApiRequest => "integration_api_request_failed",
            Self::EnterprisePolicyReload => "enterprise_policy_reload_failed",
            Self::AnalyzeQueuedMail => "mail_analysis_failed",
            Self::AutomaticDispatch => "automatic_dispatch_failed",
        }
    }

    /// Operations for which process termination can leave an external side
    /// effect ambiguous or an operator artifact incomplete. SQLite-only
    /// transactions are intentionally excluded because they roll back atomically.
    pub fn shutdown_sensitive(self) -> bool {
        matches!(
            self,
            Self::SendReply | Self::AutomaticDispatch | Self::Backup | Self::RecoveryDrill
        )
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
                | Self::RecoveryDrill
                | Self::Diagnostics
                | Self::SendReply
                | Self::ReconcileDelivery
                | Self::ApiRequest
                | Self::EnterprisePolicyReload
                | Self::AnalyzeQueuedMail
                | Self::AutomaticDispatch
        )
    }
}

#[cfg(test)]
mod operation_kind_tests {
    use super::OperationKind;

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
            OperationKind::Diagnostics,
            OperationKind::PurgeRetention,
        ] {
            assert!(!kind.shutdown_sensitive(), "{kind:?}");
        }
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
    /// Locally generated correlation UUID for one worker operation lifecycle.
    pub operation_id: Option<String>,
    pub kind: OperationKind,
    pub state: OperationState,
    pub code: Option<String>,
    pub retryable: bool,
    pub message: String,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuditDomain {
    Mail,
    Delivery,
    Model,
    Settings,
    Policy,
    Security,
    Recovery,
    Integration,
    Retention,
    Storage,
    Worker,
    #[default]
    Other,
}
impl AuditDomain {
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

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    #[default]
    Info,
    Warning,
    Error,
    Security,
}
impl AuditSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Security => "security",
        }
    }
}

pub fn audit_attributes(kind: &str) -> (AuditDomain, AuditSeverity) {
    let domain = if kind.starts_with("email.")
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
    } else if kind.starts_with("api.") || kind.starts_with("integration.") {
        AuditDomain::Integration
    } else if kind.starts_with("content.") || kind.starts_with("retention.") {
        AuditDomain::Retention
    } else if kind.starts_with("database.") || kind.starts_with("storage.") {
        AuditDomain::Storage
    } else if kind.starts_with("worker.") {
        AuditDomain::Worker
    } else {
        AuditDomain::Other
    };

    let severity = if kind.contains("security")
        || kind.contains("tamper")
        || kind.contains("integrity_failed")
    {
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
    };
    (domain, severity)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: i64,
    pub at: DateTime<Utc>,
    pub kind: String,
    #[serde(default)]
    pub domain: AuditDomain,
    #[serde(default)]
    pub severity: AuditSeverity,
    pub item_id: Option<String>,
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
