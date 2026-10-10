use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub const POLL_HOURS: [u8; 5] = [1, 2, 4, 8, 24];
pub const LOOKBACK_DAYS: [u8; 5] = [1, 3, 7, 14, 28];
pub const BACKUP_INTERVAL_HOURS: [u16; 4] = [24, 72, 168, 336];
pub const DEFAULT_MODEL: &str = "qwen3.5:9b-q8_0";
pub const DEFAULT_VERIFIER_MODEL: &str = "granite4.2:8b-q8_0";
pub const DECISION_MODEL_CANDIDATES: [(&str, &str); 3] = [
    (
        "Nimble 9B Q8 · typed classification R&D default",
        "nimble:9b-q8_0",
    ),
    (
        "Clef Flash 9B Q8 · recent typed decision challenger",
        "clef-flash:9b-q8_0",
    ),
    ("Tev1 4B · compact experimental baseline", "tev1:4b"),
];
pub const VERIFIER_CANDIDATES: [(&str, &str); 3] = [
    (
        "Granite 4.2 8B Q8 · enterprise default",
        "granite4.2:8b-q8_0",
    ),
    ("Granite 4.2 3B Q8 · lower latency", "granite4.2:3b-q8_0"),
    ("Qwen3.5 4B · compact independent check", "qwen3.5:4b"),
];
/// Old runtimes are rejected because structured-output and newer model support
/// are part of the application's correctness boundary.
pub const MIN_OLLAMA_VERSION: (u32, u32, u32) = (0, 35, 1);
/// Curated challengers for this application's text-classification/drafting task.
/// They are not ranked until evaluated locally on the task-specific suite.
pub const MODEL_CANDIDATES: [(&str, &str); 8] = [
    ("Qwen3.5 9B Q8 · provisional default", "qwen3.5:9b-q8_0"),
    (
        "MiMo V2.6 Distill 9B Q8 · agentic-distill challenger",
        "maternion/mimo-v2.6:9b-instruct-q8_0",
    ),
    (
        "Granite 4.2 8B Q8 · classification/JSON challenger",
        "granite4.2:8b-q8_0",
    ),
    (
        "Gemma 4 12B Q8 · dense writing/reasoning challenger",
        "gemma4:12b-it-q8_0",
    ),
    (
        "Gemma 4 12B Q4 · VRAM-headroom writing challenger",
        "gemma4:12b-it-q4_K_M",
    ),
    (
        "Ministral 3 14B · multilingual/JSON challenger",
        "ministral-3:14b",
    ),
    ("Qwen3.5 9B Q4 · lower-VRAM fallback", "qwen3.5:9b"),
    ("gpt-oss 20B · reasoning / very tight VRAM", "gpt-oss:20b"),
];
/// Hard safety ceiling for unattended replies to one normalized recipient mailbox.
/// This is intentionally not user-raiseable; Human Review remains the override path.
pub const AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H: u16 = 2;
pub const GPU_BUDGET_BYTES: u64 = 14 * 1024 * 1024 * 1024;
pub const PROMPT_VERSION: &str = "rr-prompts-v1";
pub const EVALUATION_CONTRACT_VERSION: &str = "rr-eval-contract-v5";
pub const SETTINGS_FORMAT_VERSION: u32 = 2;

fn default_settings_format_version() -> u32 {
    SETTINGS_FORMAT_VERSION
}

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
/// Reply-tone intensity, graded soft to harsh.
///
/// Legacy wire names (`firm`, `strong`, `reconsideration`) remain accepted as
/// deserialization aliases so existing settings keep loading unchanged.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tone {
    /// Softest level: civil and constructive feedback request.
    #[serde(alias = "firm", alias = "reconsideration")]
    Professional,
    /// Middle level: direct, assertive challenge.
    #[serde(alias = "strong")]
    Assertive,
    /// Harsh level: blunt, uncompromising, still fact-bound.
    #[default]
    Hardline,
    /// Offensive level: hostile and borderline profane within legal limits.
    Insane,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TaskQualification {
    pub model: String,
    pub digest: String,
    pub prompt_version: String,
    pub context_hash: String,
    #[serde(default)]
    pub suite_hash: String,
    #[serde(default)]
    pub ollama_runtime_version: String,
    pub task_score: f64,
    pub fixture_count: u32,
    pub qualified_at: DateTime<Utc>,
}

impl Tone {
    /// Human-readable level name.
    ///
    /// Inputs: none. Output: short label shown in the settings picker.
    pub fn label(self) -> &'static str {
        match self {
            Self::Professional => "Professional (soft)",
            Self::Assertive => "Assertive",
            Self::Hardline => "Hardline (harsh)",
            Self::Insane => "Insane (offensive)",
        }
    }
    /// Trusted drafting instruction implementing this intensity level.
    ///
    /// Inputs: none. Output: prompt text merged into the draft contract; it is
    /// trusted configuration and never read from email content.
    pub fn instruction(self) -> &'static str {
        match self {
            Self::Professional => {
                "Request specific feedback against the advertised requirements politely and professionally; keep the tone civil and constructive, and do not thank them for rejecting the application."
            }
            Self::Assertive => {
                "Directly challenge the decision and request a substantive, individualized explanation. Be assertive, concise and unmistakably dissatisfied, without insults, threats or unsupported accusations."
            }
            Self::Hardline => {
                "Confront the decision bluntly and demand a substantive, individualized justification against the advertised requirements. Make the dissatisfaction unmistakable and the challenge uncompromising, while staying strictly fact-bound: no insults, threats, profanity or invented accusations, and no claim that a reply can overturn a hiring decision."
            }
            Self::Insane => {
                "Rip the decision apart with raw, hostile blunness bordering on swearing: make the disgust and contempt unmistakable and treat the process as an insult. Legal limits are absolute: never use slurs or discriminatory language, never threaten or encourage harm, never defame or allege crimes or misconduct without evidence, never demand money or threaten legal action, never disclose third-party personal data, and never claim a reply can overturn a hiring decision. Rude and contemptuous is allowed; illegal, abusive or discriminatory is not."
            }
        }
    }
}

/// Language policy for drafted replies.
///
/// `Auto` replies in the first substantive language of the rejection (a
/// deterministic detector decides it; see `crate::language`), which
/// accommodates every language; `English` always replies in English.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplyLanguage {
    /// Reply in the email's first substantive language (all languages).
    #[default]
    Auto,
    /// Always reply in English.
    English,
}

impl ReplyLanguage {
    /// Human-readable policy name.
    ///
    /// Inputs: none. Output: label shown in the settings picker.
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Match the email's first language (all languages)",
            Self::English => "Always English",
        }
    }
}

/// Delay the user must wait before an Automatic-mode arming can be confirmed.
pub const AUTOMATIC_ARM_COOLDOWN_SECONDS: i64 = 30;

/// Cooldown gate guarding the Human-review to Automatic transition.
///
/// Opening the gate starts a mandatory waiting period (comparable to enabling
/// a device administrator on mobile platforms): the confirmation cannot be
/// acknowledged until the cooldown elapses, so the risk warning cannot be
/// clicked through in one motion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutomaticArmGate {
    opened_at: DateTime<Utc>,
}

impl AutomaticArmGate {
    /// Open the gate at the given instant.
    ///
    /// Inputs: `now` — current time. Output: gate whose cooldown ends at
    /// `now + AUTOMATIC_ARM_COOLDOWN_SECONDS`.
    pub fn open(now: DateTime<Utc>) -> Self {
        Self { opened_at: now }
    }

    /// Remaining cooldown, clamped at zero.
    ///
    /// Inputs: `now` — current time. Output: non-negative duration until the
    /// confirmation becomes available.
    pub fn remaining(&self, now: DateTime<Utc>) -> chrono::Duration {
        let left =
            chrono::Duration::seconds(AUTOMATIC_ARM_COOLDOWN_SECONDS) - (now - self.opened_at);
        if left < chrono::Duration::zero() {
            chrono::Duration::zero()
        } else {
            left
        }
    }

    /// Whether the confirmation may be acknowledged yet.
    ///
    /// Inputs: `now` — current time. Output: `true` only after the cooldown
    /// has fully elapsed.
    pub fn can_confirm(&self, now: DateTime<Utc>) -> bool {
        self.remaining(now) == chrono::Duration::zero()
    }
}

/// Configuration is encrypted in SQLite, not saved in a plaintext .env file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "default_settings_format_version")]
    pub settings_format_version: u32,
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
    #[serde(default)]
    pub reply_language: ReplyLanguage,
    pub signature: String,
    pub candidate_context: String,
    pub model: String,
    pub model_digest: Option<String>,
    pub task_qualification: Option<TaskQualification>,
    pub independent_verifier_enabled: bool,
    pub verifier_model: String,
    pub verifier_model_digest: Option<String>,
    pub ollama_url: String,
    pub num_ctx: u32,
    pub llm_timeout_seconds: u64,
    pub api_enabled: bool,
    pub api_port: u16,
    pub api_allow_writes: bool,
    pub retention_days: u16,
    pub scheduled_backup_enabled: bool,
    pub scheduled_backup_directory: String,
    pub scheduled_backup_interval_hours: u16,
    pub scheduled_backup_keep: u8,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            settings_format_version: SETTINGS_FORMAT_VERSION,
            poll_hours: 1,
            lookback_days: 7,
            mode: Mode::HumanReview,
            sending_enabled: false,
            automatic_confirmed: false,
            automatic_since: None,
            include_backlog: false,
            cooldown_minutes: 15,
            daily_send_limit: 10,
            tone: Tone::Hardline,
            reply_language: ReplyLanguage::Auto,
            signature: "Your name".into(),
            candidate_context: String::new(),
            model: DEFAULT_MODEL.into(),
            model_digest: None,
            task_qualification: None,
            independent_verifier_enabled: false,
            verifier_model: DEFAULT_VERIFIER_MODEL.into(),
            verifier_model_digest: None,
            ollama_url: "http://127.0.0.1:11434".into(),
            num_ctx: 32768,
            llm_timeout_seconds: 600,
            api_enabled: false,
            api_port: 8734,
            api_allow_writes: false,
            retention_days: 90,
            scheduled_backup_enabled: false,
            scheduled_backup_directory: String::new(),
            scheduled_backup_interval_hours: 24,
            scheduled_backup_keep: 7,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.settings_format_version == SETTINGS_FORMAT_VERSION,
            "Unsupported settings format version {}; expected {}",
            self.settings_format_version,
            SETTINGS_FORMAT_VERSION
        );
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
            BACKUP_INTERVAL_HOURS.contains(&self.scheduled_backup_interval_hours),
            "Backup interval must be 24, 72, 168 or 336 hours"
        );
        ensure!(
            (2..=30).contains(&self.scheduled_backup_keep),
            "Scheduled backup retention must be 2..30 backups"
        );
        ensure!(
            self.scheduled_backup_directory.len() <= 2048
                && !self
                    .scheduled_backup_directory
                    .chars()
                    .any(char::is_control),
            "Scheduled backup directory is invalid"
        );
        if self.scheduled_backup_enabled {
            ensure!(
                !self.scheduled_backup_directory.trim().is_empty(),
                "Choose a scheduled backup directory before enabling scheduled backups"
            );
            ensure!(
                std::path::Path::new(&self.scheduled_backup_directory).is_absolute(),
                "Scheduled backup directory must be an absolute path"
            );
        }
        ensure!(
            [8192, 16384, 32768].contains(&self.num_ctx),
            "Supported context sizes are 8192, 16384 and 32768; qualify GPU residency after changing this"
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
        validate_model_name(&self.verifier_model)?;
        if self.independent_verifier_enabled {
            ensure!(
                self.verifier_model != self.model,
                "Independent verifier must use a different model tag from the primary model"
            );
        }
        if let Some(digest) = &self.model_digest {
            let d = digest.strip_prefix("sha256:").unwrap_or(digest);
            ensure!(
                d.len() == 64 && d.bytes().all(|c| c.is_ascii_hexdigit()),
                "Invalid model digest"
            );
        }
        if let Some(digest) = &self.verifier_model_digest {
            let digest = digest.strip_prefix("sha256:").unwrap_or(digest);
            ensure!(
                digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()),
                "Invalid independent-verifier model digest"
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
                qualification.suite_hash.is_empty()
                    || (qualification.suite_hash.len() == 64
                        && qualification
                            .suite_hash
                            .bytes()
                            .all(|c| c.is_ascii_hexdigit())),
                "Invalid task-qualification suite hash"
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
            ensure!(
                qualification.ollama_runtime_version.is_empty()
                    || qualification.ollama_runtime_version.len() <= 64,
                "Task qualification contains an invalid Ollama runtime version"
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
            if self.independent_verifier_enabled {
                ensure!(
                    self.verifier_model_digest.is_some(),
                    "Qualify and pin the independent verifier before enabling Automatic mode"
                );
            }
            let qualification = self.task_qualification.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Run the task-specific model evaluation before enabling Automatic mode"
                )
            })?;
            ensure!(
                Some(&qualification.digest) == self.model_digest.as_ref()
                    && qualification.model == self.model
                    && qualification.prompt_version == PROMPT_VERSION
                    && qualification.context_hash == settings_context_hash(self)
                    && qualification.suite_hash == evaluation_suite_hash()
                    && !qualification.ollama_runtime_version.is_empty(),
                "Task-specific model qualification is stale; evaluate the current configuration again"
            );
            ensure!(
                self.automatic_since.is_some(),
                "Automatic enrollment time is missing"
            );
        }
        Ok(())
    }
    pub fn migrate_format(&mut self) -> Result<bool> {
        match self.settings_format_version {
            SETTINGS_FORMAT_VERSION => Ok(false),
            1 => {
                self.settings_format_version = SETTINGS_FORMAT_VERSION;
                self.independent_verifier_enabled = false;
                self.verifier_model = DEFAULT_VERIFIER_MODEL.into();
                self.verifier_model_digest = None;
                self.task_qualification = None;
                self.disarm_delivery();
                Ok(true)
            }
            version if version > SETTINGS_FORMAT_VERSION => anyhow::bail!(
                "Settings were written by a newer application format version {version}; current version is {}",
                SETTINGS_FORMAT_VERSION
            ),
            version => anyhow::bail!("Unsupported legacy settings format version {version}"),
        }
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
        if self.model_digest.is_none() || !self.task_qualification_current() {
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

    pub fn task_qualification_current(&self) -> bool {
        self.task_qualification
            .as_ref()
            .is_some_and(|qualification| {
                self.model_digest.as_ref() == Some(&qualification.digest)
                    && self.model == qualification.model
                    && qualification.prompt_version == PROMPT_VERSION
                    && qualification.context_hash == settings_context_hash(self)
                    && qualification.suite_hash == evaluation_suite_hash()
                    && !qualification.ollama_runtime_version.is_empty()
            })
    }
}

pub fn evaluation_suite_hash() -> String {
    let mut digest = Sha256::new();
    digest.update(EVALUATION_CONTRACT_VERSION.as_bytes());
    digest.update([0]);
    digest.update(include_bytes!("../tests/fixtures/classification.json"));
    digest.update([0]);
    digest.update(
        b"weights:fp_avoidance=.35,recall=.20,pipeline=.20,accuracy=.15,completion=.10;eligibility:complete,fp=0,unsafe_drafts=0,critical_complete,critical_fp=0,critical_unsafe_drafts=0,recall>=.90,pipeline>=.90,gpu_resident",
    );
    crate::hex_lower(digest.finalize())
}

pub fn settings_context_hash(settings: &Settings) -> String {
    let mut digest = Sha256::new();
    for value in [
        settings.candidate_context.as_str(),
        settings.signature.as_str(),
        settings.tone.instruction(),
        settings.reply_language.label(),
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    digest.update(settings.num_ctx.to_le_bytes());
    digest.update([u8::from(settings.independent_verifier_enabled)]);
    if settings.independent_verifier_enabled {
        digest.update(settings.verifier_model.as_bytes());
        digest.update([0]);
        digest.update(
            settings
                .verifier_model_digest
                .as_deref()
                .unwrap_or("<unqualified>")
                .as_bytes(),
        );
        digest.update([0]);
    }
    crate::hex_lower(digest.finalize())
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
            suite_hash: evaluation_suite_hash(),
            ollama_runtime_version: "0.35.0".into(),
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
        assert!(
            Settings {
                poll_hours: 3,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Settings {
                lookback_days: 2,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    #[test]
    fn legacy_settings_json_without_version_migrates_to_current() {
        let value = serde_json::json!({
            "poll_hours": 2,
            "lookback_days": 14,
            "signature": "Legacy User"
        });
        let settings: Settings = serde_json::from_value(value).unwrap();
        assert_eq!(settings.settings_format_version, SETTINGS_FORMAT_VERSION);
        assert_eq!(settings.poll_hours, 2);
        assert_eq!(settings.lookback_days, 14);
        assert_eq!(settings.signature, "Legacy User");
        settings.validate().unwrap();
    }

    #[test]
    fn legacy_settings_without_explicit_format_version_upgrade_to_current() {
        let mut value = serde_json::to_value(Settings::default()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("settings_format_version");
        let legacy: Settings = serde_json::from_value(value).unwrap();
        assert_eq!(legacy.settings_format_version, SETTINGS_FORMAT_VERSION);
        legacy.validate().unwrap();
    }

    #[test]
    fn settings_format_version_defaults_and_future_versions_fail_closed() {
        let current = Settings::default();
        assert_eq!(current.settings_format_version, SETTINGS_FORMAT_VERSION);
        current.validate().unwrap();

        let mut future = current;
        future.settings_format_version = SETTINGS_FORMAT_VERSION + 1;
        assert!(future.validate().is_err());
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
        assert!(
            Settings {
                mode: Mode::Automatic,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
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
    fn scheduled_backup_settings_are_explicit_and_bounded() {
        let mut settings = Settings {
            scheduled_backup_enabled: true,
            ..Settings::default()
        };
        assert!(settings.validate().is_err());

        let absolute = std::env::temp_dir().join("rr-scheduled-backups");
        settings.scheduled_backup_directory = absolute.to_string_lossy().into_owned();
        settings.validate().unwrap();

        settings.scheduled_backup_interval_hours = 48;
        assert!(settings.validate().is_err());
        settings.scheduled_backup_interval_hours = 72;
        settings.scheduled_backup_keep = 1;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn cloud_tag_denied() {
        assert!(validate_model_name("gemma4:31b-cloud").is_err());
    }

    #[test]
    fn explicit_v1_settings_migrate_fail_closed_to_v2() {
        let mut settings = Settings {
            settings_format_version: 1,
            mode: Mode::Automatic,
            sending_enabled: true,
            automatic_confirmed: true,
            automatic_since: Some(Utc::now()),
            model_digest: Some("a".repeat(64)),
            ..Settings::default()
        };
        assert!(settings.migrate_format().unwrap());
        assert_eq!(settings.settings_format_version, SETTINGS_FORMAT_VERSION);
        assert_eq!(settings.mode, Mode::HumanReview);
        assert!(!settings.sending_enabled);
        assert!(settings.task_qualification.is_none());
        settings.validate().unwrap();
    }

    #[test]
    fn independent_verifier_is_distinct_pinned_and_task_bound() {
        let mut settings = Settings {
            independent_verifier_enabled: true,
            verifier_model: DEFAULT_MODEL.into(),
            ..Settings::default()
        };
        assert!(settings.validate().is_err());
        settings.verifier_model = DEFAULT_VERIFIER_MODEL.into();
        settings.validate().unwrap();
        let base_hash = settings_context_hash(&settings);
        settings.verifier_model_digest = Some("b".repeat(64));
        assert_ne!(base_hash, settings_context_hash(&settings));
    }
}

#[cfg(test)]
mod tone_and_gate_tests {
    use super::*;

    #[test]
    fn tone_defaults_to_hardest_level() {
        assert_eq!(Tone::default(), Tone::Hardline);
    }

    #[test]
    fn tone_legacy_wire_names_still_load() {
        assert_eq!(
            serde_json::from_str::<Tone>("\"firm\"").unwrap(),
            Tone::Professional
        );
        assert_eq!(
            serde_json::from_str::<Tone>("\"strong\"").unwrap(),
            Tone::Assertive
        );
        assert_eq!(
            serde_json::from_str::<Tone>("\"reconsideration\"").unwrap(),
            Tone::Professional
        );
        assert_eq!(
            serde_json::from_str::<Tone>("\"hardline\"").unwrap(),
            Tone::Hardline
        );
    }

    #[test]
    fn tone_labels_and_instructions_are_unique() {
        let all = [Tone::Professional, Tone::Assertive, Tone::Hardline];
        for (a, b) in [(0usize, 1usize), (0, 2), (1, 2)] {
            assert_ne!(all[a].label(), all[b].label());
            assert_ne!(all[a].instruction(), all[b].instruction());
        }
    }

    #[test]
    fn automatic_arm_gate_enforces_the_cooldown() {
        let t0 = Utc::now();
        let gate = AutomaticArmGate::open(t0);
        assert!(!gate.can_confirm(t0));
        assert_eq!(
            gate.remaining(t0).num_seconds(),
            AUTOMATIC_ARM_COOLDOWN_SECONDS
        );
        let mid = t0 + chrono::Duration::seconds(AUTOMATIC_ARM_COOLDOWN_SECONDS - 1);
        assert!(!gate.can_confirm(mid));
        let after = t0 + chrono::Duration::seconds(AUTOMATIC_ARM_COOLDOWN_SECONDS);
        assert!(gate.can_confirm(after));
        let late = t0 + chrono::Duration::seconds(AUTOMATIC_ARM_COOLDOWN_SECONDS + 120);
        assert_eq!(gate.remaining(late), chrono::Duration::zero());
    }
}

#[cfg(test)]
mod reply_language_tests {
    use super::*;

    #[test]
    fn reply_language_defaults_to_auto() {
        assert_eq!(ReplyLanguage::default(), ReplyLanguage::Auto);
        assert_eq!(Settings::default().reply_language, ReplyLanguage::Auto);
    }

    #[test]
    fn reply_language_wire_names_are_stable() {
        assert_eq!(
            serde_json::from_str::<ReplyLanguage>("\"auto\"").unwrap(),
            ReplyLanguage::Auto
        );
        assert_eq!(
            serde_json::from_str::<ReplyLanguage>("\"english\"").unwrap(),
            ReplyLanguage::English
        );
    }
}
