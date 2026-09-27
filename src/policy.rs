use crate::config::{Settings, validate_model_name};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::{Path, PathBuf}};

const MAX_POLICY_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct EnterprisePolicy {
    pub version: u32,
    pub force_human_review: bool,
    pub prohibit_sending: bool,
    pub prohibit_integration_api: bool,
    pub max_daily_send_limit: Option<u16>,
    pub min_cooldown_minutes: Option<u16>,
    pub min_retention_days: Option<u16>,
    pub allowed_models: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PolicyStatus {
    pub active: bool,
    pub digest: Option<String>,
    pub force_human_review: bool,
    pub prohibit_sending: bool,
    pub prohibit_integration_api: bool,
    pub max_daily_send_limit: Option<u16>,
    pub min_cooldown_minutes: Option<u16>,
    pub min_retention_days: Option<u16>,
    pub allowed_model_count: usize,
    pub allowed_models: Vec<String>,
}

impl EnterprisePolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "Unsupported enterprise policy version");
        if let Some(limit) = self.max_daily_send_limit {
            ensure!((1..=100).contains(&limit), "Enterprise daily send limit must be 1..100");
        }
        if let Some(minutes) = self.min_cooldown_minutes {
            ensure!((1..=1440).contains(&minutes), "Enterprise minimum cooldown must be 1..1440 minutes");
        }
        if let Some(days) = self.min_retention_days {
            ensure!((30..=3650).contains(&days), "Enterprise minimum retention must be 30..3650 days");
        }
        ensure!(self.allowed_models.len() <= 64, "Enterprise model allow-list is too large");
        let mut unique = std::collections::BTreeSet::new();
        for model in &self.allowed_models {
            validate_model_name(model)?;
            ensure!(unique.insert(model), "Enterprise model allow-list contains duplicates");
        }
        Ok(())
    }

    /// Apply non-bypassable policy to mutable user settings.
    ///
    /// At startup an already-persisted disallowed model is replaced by the first
    /// approved tag and its qualification is invalidated. During an explicit user
    /// settings update, attempting to select a non-approved model is rejected.
    pub fn enforce(&self, settings: &mut Settings, startup: bool) -> Result<bool> {
        self.validate()?;
        let before = settings.clone();

        if self.force_human_review || self.prohibit_sending {
            settings.disarm_delivery();
        }
        if self.prohibit_integration_api {
            settings.api_enabled = false;
            settings.api_allow_writes = false;
        }
        if let Some(limit) = self.max_daily_send_limit {
            settings.daily_send_limit = settings.daily_send_limit.min(limit);
        }
        if let Some(minutes) = self.min_cooldown_minutes {
            settings.cooldown_minutes = settings.cooldown_minutes.max(minutes);
        }
        if let Some(days) = self.min_retention_days {
            settings.retention_days = settings.retention_days.max(days);
        }

        if !self.allowed_models.is_empty() && !self.allowed_models.contains(&settings.model) {
            if startup {
                settings.model = self.allowed_models[0].clone();
                settings.model_digest = None;
                settings.task_qualification = None;
                settings.disarm_delivery();
            } else {
                anyhow::bail!("Selected model is not approved by enterprise policy");
            }
        }

        settings.validate()?;
        Ok(*settings != before)
    }

    pub fn allows_send_scope(&self) -> bool {
        !self.prohibit_sending
    }
}

#[derive(Clone, Debug)]
pub struct LoadedPolicy {
    pub policy: EnterprisePolicy,
    pub digest: String,
}

impl LoadedPolicy {
    pub fn status(&self) -> PolicyStatus {
        PolicyStatus {
            active: true,
            digest: Some(self.digest.clone()),
            force_human_review: self.policy.force_human_review,
            prohibit_sending: self.policy.prohibit_sending,
            prohibit_integration_api: self.policy.prohibit_integration_api,
            max_daily_send_limit: self.policy.max_daily_send_limit,
            min_cooldown_minutes: self.policy.min_cooldown_minutes,
            min_retention_days: self.policy.min_retention_days,
            allowed_model_count: self.policy.allowed_models.len(),
            allowed_models: self.policy.allowed_models.clone(),
        }
    }
}

pub fn inactive_status() -> PolicyStatus {
    PolicyStatus {
        active: false,
        digest: None,
        force_human_review: false,
        prohibit_sending: false,
        prohibit_integration_api: false,
        max_daily_send_limit: None,
        min_cooldown_minutes: None,
        min_retention_days: None,
        allowed_model_count: 0,
        allowed_models: vec![],
    }
}

pub fn default_policy_path() -> Result<Option<PathBuf>> {
    if let Some(explicit) = std::env::var_os("RR_ENTERPRISE_POLICY") {
        let path = PathBuf::from(explicit);
        ensure!(
            path.is_absolute(),
            "RR_ENTERPRISE_POLICY must be an absolute path"
        );
        return Ok(Some(path));
    }
    #[cfg(windows)]
    {
        Ok(std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .map(|root| root.join("RejectionRejector").join("policy.json")))
    }
    #[cfg(not(windows))]
    {
        Ok(Some(PathBuf::from("/etc/rejection-rejector/policy.json")))
    }
}

pub fn load_optional() -> Result<Option<LoadedPolicy>> {
    let Some(path) = default_policy_path()? else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    load_file(&path).map(Some)
}

pub fn load_file(path: &Path) -> Result<LoadedPolicy> {
    ensure!(path.is_absolute(), "Enterprise policy path must be absolute");
    ensure!(path.is_file(), "Enterprise policy file is missing");
    ensure!(!fs::symlink_metadata(path)?.file_type().is_symlink(), "Enterprise policy file must not be a symlink");
    let metadata = fs::metadata(path)?;
    ensure!(metadata.len() <= MAX_POLICY_BYTES, "Enterprise policy exceeds 64 KiB");
    let bytes = fs::read(path)?;
    ensure!(bytes.len() as u64 <= MAX_POLICY_BYTES, "Enterprise policy exceeds 64 KiB");
    let policy: EnterprisePolicy =
        serde_json::from_slice(&bytes).context("Enterprise policy is invalid JSON")?;
    policy.validate()?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok(LoadedPolicy { policy, digest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Mode, DEFAULT_MODEL};

    fn policy() -> EnterprisePolicy {
        EnterprisePolicy {
            version: 1,
            force_human_review: true,
            prohibit_sending: true,
            prohibit_integration_api: true,
            max_daily_send_limit: Some(3),
            min_cooldown_minutes: Some(90),
            min_retention_days: Some(365),
            allowed_models: vec!["granite4.2:8b-q8_0".into()],
        }
    }

    #[test]
    fn enterprise_policy_clamps_and_disarms_user_settings() {
        let mut settings = Settings {
            mode: Mode::Automatic,
            sending_enabled: true,
            automatic_confirmed: true,
            api_enabled: true,
            daily_send_limit: 25,
            cooldown_minutes: 5,
            retention_days: 30,
            model: DEFAULT_MODEL.into(),
            ..Settings::default()
        };
        policy().enforce(&mut settings, true).unwrap();
        assert_eq!(settings.mode, Mode::HumanReview);
        assert!(!settings.sending_enabled);
        assert!(!settings.api_enabled);
        assert_eq!(settings.daily_send_limit, 3);
        assert_eq!(settings.cooldown_minutes, 90);
        assert_eq!(settings.retention_days, 365);
        assert_eq!(settings.model, "granite4.2:8b-q8_0");
        assert!(settings.model_digest.is_none());
        assert!(settings.task_qualification.is_none());
    }

    #[test]
    fn interactive_settings_cannot_bypass_model_allow_list() {
        let mut settings = Settings {
            model: "qwen3.5:9b-q8_0".into(),
            ..Settings::default()
        };
        assert!(policy().enforce(&mut settings, false).is_err());
    }

    #[test]
    fn relative_policy_override_is_rejected_fail_closed() {
        let previous = std::env::var_os("RR_ENTERPRISE_POLICY");
        unsafe { std::env::set_var("RR_ENTERPRISE_POLICY", "relative-policy.json") };
        assert!(default_policy_path().is_err());
        match previous {
            Some(value) => unsafe { std::env::set_var("RR_ENTERPRISE_POLICY", value) },
            None => unsafe { std::env::remove_var("RR_ENTERPRISE_POLICY") },
        }
    }

    #[test]
    fn loaded_policy_has_stable_sha256_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        let body = br#"{"version":1,"prohibit_sending":true}"#;
        std::fs::write(&path, body).unwrap();
        let loaded = load_file(&path).unwrap();
        assert_eq!(loaded.digest.len(), 64);
        assert!(loaded.policy.prohibit_sending);
        assert!(loaded.status().active);
    }
}
