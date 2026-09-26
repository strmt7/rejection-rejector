use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const POLL_HOURS: [u8; 5] = [1, 2, 4, 8, 24];
pub const LOOKBACK_DAYS: [u8; 5] = [1, 3, 7, 14, 28];
pub const DEFAULT_MODEL: &str = "gemma4:12b-it-qat";
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
                self.automatic_since.is_some(),
                "Automatic enrollment time is missing"
            );
        }
        Ok(())
    }
    pub fn interval_seconds(&self) -> i64 {
        i64::from(self.poll_hours) * 3600
    }
    pub fn cutoff(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now - chrono::Duration::days(i64::from(self.lookback_days))
    }
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
