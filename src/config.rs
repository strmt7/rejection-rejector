use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub const POLL_HOURS: [u8; 5] = [1, 2, 4, 8, 24];
pub const LOOKBACK_DAYS: [u8; 5] = [1, 3, 7, 14, 28];
pub const DEFAULT_MODEL: &str = "qwen3.5:9b-q8_0";
/// Old runtimes are rejected because structured-output and newer model support
/// are part of the application's correctness boundary.
pub const MIN_OLLAMA_VERSION: (u32, u32, u32) = (0, 34, 0);
/// Curated challengers for this application's text-classification/drafting task.
/// They are not ranked until evaluated locally on the task-specific suite.
pub const MODEL_CANDIDATES: [(&str, &str); 6] = [
    ("Qwen3.5 9B Q8 · provisional default", "qwen3.5:9b-q8_0"),
    (
        "Granite 4.2 8B Q8 · classification/JSON challenger",
        "granite4.2:8b-q8_0",
    ),
    (
        "Gemma 4 12B Q8 · dense writing/reasoning challenger",
        "gemma4:12b-it-q8_0",
    ),
    (
        "Ministral 3 14B · multilingual/JSON challenger",
        "ministral-3:14b",
    ),
    ("Qwen3.5 9B Q4 · lower-VRAM fallback", "qwen3.5:9b"),
    ("gpt-oss 20B · reasoning / very tight VRAM", "gpt-oss:20b"),
];
pub const GPU_BUDGET_BYTES: u64 = 14 * 1024 * 1024 * 1024;
pub const PROMPT_VERSION: &str = "rr-prompts-v1";

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    HumanReview,
    Automatic,
}
impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::HumanReview => "Human review",
            Self::Automatic => "Automatic",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    Firm,
    #[default]
    Strong,
    Reconsideration,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TaskQualification {
    pub model: String,
    pub digest: String,
    pub prompt_version: String,
    pub context_hash: String,
    pub task_score: f64,
    pub fixture_count: u32,
    pub qualified_at: DateTime<Utc>,
}

impl Tone {
    pub fn label(self) -> &'static str {
        match self {
            Self::Firm => "Firm",
            Self::Strong => "Strong",
            Self::Reconsideration => "Reconsideration",
        }
    }
    pub fn instruction(self) -> &'static str {
        match self {
            Self::Firm => "Firmly request specific feedback against the advertised requirements; do not thank them for rejecting the application.",
            Self::Strong => "Directly challenge the decision and request a substantive, individualized explanation. Be assertive, concise and unmistakably dissatisfied, without insults, threats or unsupported accusations.",
            Self::Reconsideration => "Request an individual reconsideration and an explanation of the criteria. Challenge the outcome professionally without pretending a reply can invalidate a hiring decision.",
        }
    }
}

/// Configuration is encrypted in SQLite, not saved in a plaintext .env file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub poll_hours: u8,
    pub lookback_days: u8,
    pub mode: Mode,
    pub sending_enabled: bool,
    pub automatic_confirmed: bool,
    pub automatic_since: Option<DateTime<Utc>>,
    pub include_backlog: bool,
    pub cooldown_minutes: u16,
    pub daily_send_limit: u16,
    pub tone: Tone,
    pub signature: String,
    pub candidate_context: String,
    pub model: String,
    pub model_digest: Option<String>,
    pub task_qualification: Option<TaskQualification>,
    pub ollama_url: String,
    pub num_ctx: u32,
    pub llm_timeout_seconds: u64,
    pub api_enabled: bool,
    pub api_port: u16,
    pub api_allow_writes: bool,
    pub retention_days: u16,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            poll_hours: 1,
            lookback_days: 7,
            mode: Mode::HumanReview,
            sending_enabled: false,
            automatic_confirmed: false,
            automatic_since: None,
            include_backlog: false,
            cooldown_minutes: 15,
            daily_send_limit: 10,
            tone: Tone::Strong,
            signature: "Your name".into(),
            candidate_context: String::new(),
            model: DEFAULT_MODEL.into(),
            model_digest: None,
            task_qualification: None,
            ollama_url: "http://127.0.0.1:11434".into(),
            num_ctx: 8192,
            llm_timeout_seconds: 600,
            api_enabled: false,
            api_port: 8734,
            api_allow_writes: false,
            retention_days: 90,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            POLL_HOURS.contains(&self.poll_hours),
            "Polling must be 1, 2, 4, 8 or 24 hours"
        );
        ensure!(
            LOOKBACK_DAYS.contains(&self.lookback_days),
            "Lookback must be 1, 3, 7, 14 or 28 days"
        );
        ensure!(
            (1..=1440).contains(&self.cooldown_minutes),
            "Cooldown must be 1..1440 minutes"
        );
        ensure!(
            (1..=100).contains(&self.daily_send_limit),
            "Daily limit must be 1..100 attempts"
        );
        ensure!(
            (30..=3650).contains(&self.retention_days),
            "Retention must be 30..3650 days"
        );
        ensure!(
            [8192, 16384].contains(&self.num_ctx),
            "Supported context sizes are 8192 and 16384; qualify GPU residency after changing this"
        );
        ensure!(
            (30..=1200).contains(&self.llm_timeout_seconds),
            "LLM timeout must be 30..1200 seconds"
        );
        ensure!(
            self.api_port >= 1024 && self.api_port != 11434,
            "Choose an unprivileged API port other than Ollama's port"
        );
        ensure!(
            !self.signature.trim().is_empty() && self.signature.len() <= 500,
            "Signature must be 1..500 bytes"
        );
        ensure!(
            self.candidate_context.len() <= 2500,
            "Candidate context is limited to 2500 UTF-8 bytes"
        );
        for text in [&self.signature, &self.candidate_context] {
            ensure!(
                !text
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t'),
                "Text contains unsupported control characters"
            );
        }
        validate_local_url(&self.ollama_url)?;
        validate_model_name(&self.model)?;
        if let Some(digest) = &self.model_digest {
            let d = digest.strip_prefix("sha256:").unwrap_or(digest);
            ensure!(
                d.len() == 64 && d.bytes().all(|c| c.is_ascii_hexdigit()),
                "Invalid model digest"
            );
        }
        if let Some(qualification) = &self.task_qualification {
            validate_model_name(&qualification.model)?;
            let digest = qualification
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&qualification.digest);
            ensure!(
                digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()),
                "Invalid task-qualification model digest"
            );
            ensure!(
                qualification.prompt_version == PROMPT_VERSION,
                "Task qualification belongs to another prompt version"
            );
            ensure!(
                qualification.context_hash.len() == 64
                    && qualification
                        .context_hash
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit()),
                "Invalid task-qualification context hash"
            );
            ensure!(
                qualification.task_score.is_finite()
                    && (0.0..=100.0).contains(&qualification.task_score),
                "Invalid task-qualification score"
            );
            ensure!(
                qualification.fixture_count > 0,
                "Task qualification must record evaluated fixtures"
            );
        }
        if self.sending_enabled {
            ensure!(
                self.signature.trim() != "Your name",
                "Replace the placeholder signature before enabling sending"
            );
        }
        if self.mode == Mode::Automatic {
            ensure!(
                self.sending_enabled && self.automatic_confirmed,
                "Automatic mode requires explicit sending and automatic-mode consent"
            );
            ensure!(
                self.model_digest.is_some(),
                "Qualify and pin the local model before enabling Automatic mode"
            );
            let qualification = self.task_qualification.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Run the task-specific model evaluation before enabling Automatic mode"
                )
            })?;
            ensure!(
                Some(&qualification.digest) == self.model_digest.as_ref()
                    && qualification.model == self.model
                    && qualification.prompt_version == PROMPT_VERSION
                    && qualification.context_hash == settings_context_hash(self),
                "Task-specific model qualification is stale; evaluate the current configuration again"
            );
            ensure!(
                self.automatic_since.is_some(),
                "Automatic enrollment time is missing"
            );
        }
        Ok(())
    }
    pub fn disarm_delivery(&mut self) {
        self.mode = Mode::HumanReview;
        self.sending_enabled = false;
        self.automatic_confirmed = false;
        self.automatic_since = None;
    }

    pub fn repair_legacy_automatic_state(&mut self) -> bool {
        if self.mode != Mode::Automatic {
            return false;
        }
        let task_current = self
            .task_qualification
            .as_ref()
            .is_some_and(|qualification| {
                self.model_digest.as_ref() == Some(&qualification.digest)
                    && self.model == qualification.model
                    && qualification.prompt_version == PROMPT_VERSION
                    && qualification.context_hash == settings_context_hash(self)
            });
        if self.model_digest.is_none() || !task_current {
            self.disarm_delivery();
            return true;
        }
        false
    }

    pub fn interval_seconds(&self) -> i64 {
        i64::from(self.poll_hours) * 3600
    }
    pub fn cutoff(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now - chrono::Duration::days(i64::from(self.lookback_days))
    }
}

pub fn settings_context_hash(settings: &Settings) -> String {
    let mut digest = Sha256::new();
    for value in [
        settings.candidate_context.as_str(),
        settings.signature.as_str(),
        settings.tone.instruction(),
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    digest.update(settings.num_ctx.to_le_bytes());
    format!("{:x}", digest.finalize())
}

pub fn validate_local_url(value: &str) -> Result<()> {
    let u = url::Url::parse(value)?;
    ensure!(
        u.scheme() == "http",
        "Ollama must use local HTTP; no remote inference is permitted"
    );
    ensure!(
        matches!(u.host_str(), Some("127.0.0.1" | "[::1]" | "::1")),
        "Use a literal loopback IP, not a hostname or remote server"
    );
    ensure!(
        u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && matches!(u.path(), "" | "/"),
        "Ollama URL must be a plain loopback origin"
    );
    Ok(())
}
pub fn validate_model_name(model: &str) -> Result<()> {
    ensure!(
        !model.is_empty() && model.len() <= 150 && !model.starts_with('-'),
        "Invalid model name"
    );
    ensure!(
        model
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-:/".contains(&c)),
        "Invalid model name"
    );
    let low = model.to_lowercase();
    ensure!(
        !low.contains("cloud") && !low.contains("://") && !low.contains(".."),
        "Cloud models and arbitrary model URLs are forbidden"
    );
    Ok(())
}
pub fn data_dir() -> Result<PathBuf> {
    directories::ProjectDirs::from("dev", "strmt7", "RejectionRejector")
        .map(|p| p.data_local_dir().to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("Cannot find local application data; supply --data-dir"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task_qualification(settings: &Settings) -> TaskQualification {
        TaskQualification {
            model: settings.model.clone(),
            digest: settings.model_digest.clone().unwrap(),
            prompt_version: PROMPT_VERSION.into(),
            context_hash: settings_context_hash(settings),
            task_score: 100.0,
            fixture_count: 32,
            qualified_at: Utc::now(),
        }
    }
    #[test]
    fn exact_presets_only() {
        for p in POLL_HOURS {
            let s = Settings {
                poll_hours: p,
                ..Default::default()
            };
            s.validate().unwrap();
        }
        for p in LOOKBACK_DAYS {
            let s = Settings {
                lookback_days: p,
                ..Default::default()
            };
            s.validate().unwrap();
        }
        assert!(Settings {
            poll_hours: 3,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(Settings {
            lookback_days: 2,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
    #[test]
    fn default_is_not_armed() {
        let s = Settings::default();
        s.validate().unwrap();
        assert!(!s.sending_enabled);
        assert_eq!(s.mode, Mode::HumanReview);
    }
    #[test]
    fn auto_requires_both_consents() {
        assert!(Settings {
            mode: Mode::Automatic,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
    #[test]
    fn automatic_requires_model_pin_and_task_qualification() {
        let mut s = Settings {
            mode: Mode::Automatic,
            sending_enabled: true,
            automatic_confirmed: true,
            automatic_since: Some(Utc::now()),
            signature: "Test Applicant".into(),
            ..Default::default()
        };
        assert!(s.validate().is_err());
        s.model_digest = Some("a".repeat(64));
        assert!(s.validate().is_err());
        s.task_qualification = Some(task_qualification(&s));
        s.validate().unwrap();

        s.signature = "Changed Applicant".into();
        assert!(s.validate().is_err());
    }

    #[test]
    fn disarm_delivery_clears_all_unattended_send_state() {
        let mut s = Settings {
            mode: Mode::Automatic,
            sending_enabled: true,
            automatic_confirmed: true,
            automatic_since: Some(Utc::now()),
            signature: "Test Applicant".into(),
            model_digest: Some("a".repeat(64)),
            ..Default::default()
        };
        s.disarm_delivery();
        assert_eq!(s.mode, Mode::HumanReview);
        assert!(!s.sending_enabled);
        assert!(!s.automatic_confirmed);
        assert!(s.automatic_since.is_none());
    }

    #[test]
    fn legacy_automatic_state_without_task_qualification_repairs_fail_closed() {
        for with_model_pin in [false, true] {
            let mut s = Settings {
                mode: Mode::Automatic,
                sending_enabled: true,
                automatic_confirmed: true,
                automatic_since: Some(Utc::now()),
                signature: "Test Applicant".into(),
                model_digest: with_model_pin.then(|| "a".repeat(64)),
                ..Default::default()
            };
            assert!(s.repair_legacy_automatic_state());
            assert_eq!(s.mode, Mode::HumanReview);
            assert!(!s.sending_enabled);
            assert!(!s.automatic_confirmed);
            assert!(s.automatic_since.is_none());
            s.validate().unwrap();
        }
    }

    #[test]
    fn no_remote_inference() {
        for u in [
            "http://localhost:11434",
            "https://example.com",
            "http://127.0.0.1.evil.test",
            "http://127.0.0.1:11434/path",
            "http://me@127.0.0.1:11434",
        ] {
            assert!(validate_local_url(u).is_err(), "{u}");
        }
        validate_local_url("http://127.0.0.1:11434").unwrap();
    }
    #[test]
    fn cloud_tag_denied() {
        assert!(validate_model_name("gemma4:31b-cloud").is_err());
    }
}
