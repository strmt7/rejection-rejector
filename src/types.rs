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
                Self::Queued
                    | Self::Attention
                    | Self::Dismissed
                    | Self::Deferred
                    | Self::Sending
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: i64,
    pub at: DateTime<Utc>,
    pub kind: String,
    pub item_id: Option<String>,
    pub detail: String,
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
