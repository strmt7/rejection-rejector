use crate::config::{Settings, validate_model_name};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

const MAX_POLICY_BYTES: u64 = 64 * 1024;
const MAX_POLICY_SIGNATURE_BYTES: u64 = 4 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct EnterprisePolicy {
    pub version: u32,
    pub policy_id: Option<String>,
    pub revision: Option<u64>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub force_human_review: bool,
    pub prohibit_sending: bool,
    pub prohibit_integration_api: bool,
    pub prohibit_recovery_key_export: bool,
    pub max_daily_send_limit: Option<u16>,
    pub min_cooldown_minutes: Option<u16>,
    pub min_retention_days: Option<u16>,
    pub allowed_models: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PolicyStatus {
    pub active: bool,
    pub version: Option<u32>,
    pub policy_id: Option<String>,
    pub revision: Option<u64>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub digest: Option<String>,
    pub digest_pin_enforced: bool,
    pub digest_pin_matches: bool,
    pub signature_enforced: bool,
    pub signature_verified: bool,
    pub signer_key_sha256: Option<String>,
    pub force_human_review: bool,
    pub prohibit_sending: bool,
    pub prohibit_integration_api: bool,
    pub prohibit_recovery_key_export: bool,
    pub max_daily_send_limit: Option<u16>,
    pub min_cooldown_minutes: Option<u16>,
    pub min_retention_days: Option<u16>,
    pub allowed_model_count: usize,
    pub allowed_models: Vec<String>,
}

impl EnterprisePolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1 | 2),
            "Unsupported enterprise policy version"
        );
        match self.version {
            1 => ensure!(
                self.policy_id.is_none()
                    && self.revision.is_none()
                    && self.not_before.is_none()
                    && self.expires_at.is_none(),
                "Policy v1 cannot contain v2 lifecycle fields"
            ),
            2 => {
                let policy_id = self
                    .policy_id
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .context("Policy v2 requires policy_id")?;
                ensure!(
                    policy_id.len() <= 128
                        && policy_id.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)
                        }),
                    "Policy v2 policy_id contains unsupported characters"
                );
                ensure!(
                    self.revision.is_some_and(|revision| revision >= 1),
                    "Policy v2 requires revision >= 1"
                );
                if let (Some(not_before), Some(expires_at)) = (self.not_before, self.expires_at) {
                    ensure!(
                        not_before < expires_at,
                        "Policy v2 not_before must be before expires_at"
                    );
                }
            }
            _ => unreachable!("version was validated above"),
        }
        if let Some(limit) = self.max_daily_send_limit {
            ensure!(
                (1..=100).contains(&limit),
                "Enterprise daily send limit must be 1..100"
            );
        }
        if let Some(minutes) = self.min_cooldown_minutes {
            ensure!(
                (1..=1440).contains(&minutes),
                "Enterprise minimum cooldown must be 1..1440 minutes"
            );
        }
        if let Some(days) = self.min_retention_days {
            ensure!(
                (30..=3650).contains(&days),
                "Enterprise minimum retention must be 30..3650 days"
            );
        }
        ensure!(
            self.allowed_models.len() <= 64,
            "Enterprise model allow-list is too large"
        );
        let mut unique = std::collections::BTreeSet::new();
        for model in &self.allowed_models {
            validate_model_name(model)?;
            ensure!(
                unique.insert(model),
                "Enterprise model allow-list contains duplicates"
            );
        }
        Ok(())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        self.validate()?;
        if self.version >= 2 {
            if let Some(not_before) = self.not_before {
                ensure!(now >= not_before, "Enterprise policy is not active yet");
            }
            if let Some(expires_at) = self.expires_at {
                ensure!(now < expires_at, "Enterprise policy has expired");
            }
        }
        Ok(())
    }

    pub fn revision_identity(&self) -> Option<(&str, u64)> {
        (self.version >= 2)
            .then(|| Some((self.policy_id.as_deref()?, self.revision?)))
            .flatten()
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

    pub fn allows_recovery_key_export(&self) -> bool {
        !self.prohibit_recovery_key_export
    }
}

#[derive(Clone, Debug)]
pub struct LoadedPolicy {
    pub policy: EnterprisePolicy,
    pub digest: String,
    pub expected_digest: Option<String>,
    pub signature_enforced: bool,
    pub signature_verified: bool,
    pub signer_key_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachedPolicySignature {
    version: u32,
    algorithm: String,
    signature: String,
}

#[derive(Clone, Debug)]
struct SignatureRequirement {
    public_key: Vec<u8>,
    signer_key_sha256: String,
    signature_path: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyRevisionFloor {
    pub policies: std::collections::BTreeMap<String, PolicyRevisionRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevisionRecord {
    pub revision: u64,
    pub digest: String,
}

impl PolicyRevisionFloor {
    pub fn observe(&mut self, loaded: &LoadedPolicy) -> Result<bool> {
        let Some((policy_id, revision)) = loaded.policy.revision_identity() else {
            return Ok(false);
        };
        ensure!(
            self.policies.len() < 32 || self.policies.contains_key(policy_id),
            "Enterprise policy revision floor has too many policy identities"
        );
        match self.policies.get(policy_id) {
            Some(existing) if revision < existing.revision => {
                anyhow::bail!(
                    "Enterprise policy rollback rejected for {policy_id}: revision {revision} is below previously accepted revision {}",
                    existing.revision
                );
            }
            Some(existing) if revision == existing.revision && loaded.digest != existing.digest => {
                anyhow::bail!(
                    "Enterprise policy content changed without increasing revision for {policy_id}"
                );
            }
            Some(existing) if revision == existing.revision => Ok(false),
            _ => {
                self.policies.insert(
                    policy_id.to_owned(),
                    PolicyRevisionRecord {
                        revision,
                        digest: loaded.digest.clone(),
                    },
                );
                Ok(true)
            }
        }
    }
}

impl LoadedPolicy {
    pub fn status(&self) -> PolicyStatus {
        PolicyStatus {
            active: true,
            version: Some(self.policy.version),
            policy_id: self.policy.policy_id.clone(),
            revision: self.policy.revision,
            not_before: self.policy.not_before,
            expires_at: self.policy.expires_at,
            digest: Some(self.digest.clone()),
            digest_pin_enforced: self.expected_digest.is_some(),
            digest_pin_matches: self
                .expected_digest
                .as_ref()
                .is_none_or(|expected| expected == &self.digest),
            signature_enforced: self.signature_enforced,
            signature_verified: self.signature_verified,
            signer_key_sha256: self.signer_key_sha256.clone(),
            force_human_review: self.policy.force_human_review,
            prohibit_sending: self.policy.prohibit_sending,
            prohibit_integration_api: self.policy.prohibit_integration_api,
            prohibit_recovery_key_export: self.policy.prohibit_recovery_key_export,
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
        version: None,
        policy_id: None,
        revision: None,
        not_before: None,
        expires_at: None,
        digest: None,
        digest_pin_enforced: false,
        digest_pin_matches: false,
        signature_enforced: false,
        signature_verified: false,
        signer_key_sha256: None,
        force_human_review: false,
        prohibit_sending: false,
        prohibit_integration_api: false,
        prohibit_recovery_key_export: false,
        max_daily_send_limit: None,
        min_cooldown_minutes: None,
        min_retention_days: None,
        allowed_model_count: 0,
        allowed_models: vec![],
    }
}

fn normalize_digest_pin(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    ensure!(
        normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "RR_ENTERPRISE_POLICY_SHA256 must be exactly 64 hexadecimal characters"
    );
    Ok(normalized)
}

fn normalize_digest_pin_os(value: std::ffi::OsString) -> Result<String> {
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("RR_ENTERPRISE_POLICY_SHA256 must be valid Unicode"))?;
    normalize_digest_pin(&value)
}

fn configured_digest_pin() -> Result<Option<String>> {
    std::env::var_os("RR_ENTERPRISE_POLICY_SHA256")
        .map(normalize_digest_pin_os)
        .transpose()
}

fn normalize_public_key(value: &str) -> Result<Vec<u8>> {
    let decoded = STANDARD
        .decode(value.trim().as_bytes())
        .context("RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY must be standard base64")?;
    ensure!(
        decoded.len() == 32,
        "RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY must decode to exactly 32 bytes"
    );
    Ok(decoded)
}

fn signature_path_for_policy(policy_path: &Path) -> PathBuf {
    let mut path = policy_path.as_os_str().to_os_string();
    path.push(".sig");
    PathBuf::from(path)
}

fn validate_signature_path(path: PathBuf) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "RR_ENTERPRISE_POLICY_SIGNATURE must be an absolute path"
    );
    Ok(path)
}

fn validate_signature_distinct(policy_path: &Path, signature_path: &Path) -> Result<()> {
    validate_signature_distinct(policy_path, &signature_path)?;
    Ok(())
}

fn configured_signature_requirement(policy_path: &Path) -> Result<Option<SignatureRequirement>> {
    let key = std::env::var_os("RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY");
    let signature_override = std::env::var_os("RR_ENTERPRISE_POLICY_SIGNATURE");
    let Some(key) = key else {
        ensure!(
            signature_override.is_none(),
            "RR_ENTERPRISE_POLICY_SIGNATURE requires RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY"
        );
        return Ok(None);
    };
    let key = key.into_string().map_err(|_| {
        anyhow::anyhow!("RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY must be valid Unicode")
    })?;
    let public_key = normalize_public_key(&key)?;
    let signer_key_sha256 = format!("{:x}", Sha256::digest(&public_key));
    let signature_path = signature_override
        .map(PathBuf::from)
        .map(validate_signature_path)
        .transpose()?
        .unwrap_or_else(|| signature_path_for_policy(policy_path));
    ensure!(
        signature_path != policy_path,
        "Enterprise policy signature file must be distinct from the policy file"
    );
    Ok(Some(SignatureRequirement {
        public_key,
        signer_key_sha256,
        signature_path,
    }))
}

fn verify_detached_signature(
    requirement: &SignatureRequirement,
    policy_bytes: &[u8],
) -> Result<()> {
    let path = &requirement.signature_path;
    ensure!(
        path.is_absolute(),
        "Enterprise policy signature path must be absolute"
    );
    ensure!(
        path.is_file(),
        "Enterprise policy signature file is missing"
    );
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Enterprise policy signature file must not be a symlink"
    );
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.len() <= MAX_POLICY_SIGNATURE_BYTES,
        "Enterprise policy signature file exceeds 4 KiB"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() as u64 <= MAX_POLICY_SIGNATURE_BYTES,
        "Enterprise policy signature file exceeds 4 KiB"
    );
    let envelope: DetachedPolicySignature = serde_json::from_slice(&bytes)
        .context("Enterprise policy signature file is invalid JSON")?;
    ensure!(
        envelope.version == 1,
        "Unsupported enterprise policy signature version"
    );
    ensure!(
        envelope.algorithm.eq_ignore_ascii_case("ed25519"),
        "Unsupported enterprise policy signature algorithm"
    );
    let signature_bytes = STANDARD
        .decode(envelope.signature.trim().as_bytes())
        .context("Enterprise policy signature must be standard base64")?;
    ensure!(
        signature_bytes.len() == 64,
        "Enterprise policy Ed25519 signature must decode to exactly 64 bytes"
    );
    signature::UnparsedPublicKey::new(&signature::ED25519, &requirement.public_key)
        .verify(policy_bytes, &signature_bytes)
        .map_err(|_| anyhow::anyhow!("Enterprise policy Ed25519 signature verification failed"))?;
    Ok(())
}

fn validate_explicit_policy_path(path: PathBuf) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "RR_ENTERPRISE_POLICY must be an absolute path"
    );
    Ok(path)
}

pub fn default_policy_path() -> Result<Option<PathBuf>> {
    if let Some(explicit) = std::env::var_os("RR_ENTERPRISE_POLICY") {
        return Ok(Some(validate_explicit_policy_path(PathBuf::from(
            explicit,
        ))?));
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
    let expected_digest = configured_digest_pin()?;
    let signature_configured = std::env::var_os("RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY")
        .is_some()
        || std::env::var_os("RR_ENTERPRISE_POLICY_SIGNATURE").is_some();
    let Some(path) = default_policy_path()? else {
        ensure!(
            expected_digest.is_none() && !signature_configured,
            "Enterprise policy integrity controls are configured but no policy path is available"
        );
        return Ok(None);
    };
    if !path.exists() {
        ensure!(
            expected_digest.is_none() && !signature_configured,
            "Enterprise policy integrity controls are configured but the policy file is missing"
        );
        return Ok(None);
    }
    let signature_requirement = configured_signature_requirement(&path)?;
    load_file_with_controls(&path, expected_digest, signature_requirement).map(Some)
}

pub fn load_file(path: &Path) -> Result<LoadedPolicy> {
    load_file_with_controls(path, None, None)
}

fn load_file_with_expected_digest(
    path: &Path,
    expected_digest: Option<String>,
) -> Result<LoadedPolicy> {
    load_file_with_controls(path, expected_digest, None)
}

fn load_file_with_controls(
    path: &Path,
    expected_digest: Option<String>,
    signature_requirement: Option<SignatureRequirement>,
) -> Result<LoadedPolicy> {
    ensure!(
        path.is_absolute(),
        "Enterprise policy path must be absolute"
    );
    ensure!(path.is_file(), "Enterprise policy file is missing");
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Enterprise policy file must not be a symlink"
    );
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.len() <= MAX_POLICY_BYTES,
        "Enterprise policy exceeds 64 KiB"
    );
    let bytes = fs::read(path)?;
    ensure!(
        bytes.len() as u64 <= MAX_POLICY_BYTES,
        "Enterprise policy exceeds 64 KiB"
    );
    let policy: EnterprisePolicy =
        serde_json::from_slice(&bytes).context("Enterprise policy is invalid JSON")?;
    policy.validate_at(Utc::now())?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if let Some(expected) = &expected_digest {
        ensure!(
            &digest == expected,
            "Enterprise policy digest does not match RR_ENTERPRISE_POLICY_SHA256"
        );
    }
    let (signature_enforced, signature_verified, signer_key_sha256) =
        if let Some(requirement) = &signature_requirement {
            verify_detached_signature(requirement, &bytes)?;
            (true, true, Some(requirement.signer_key_sha256.clone()))
        } else {
            (false, false, None)
        };
    Ok(LoadedPolicy {
        policy,
        digest,
        expected_digest,
        signature_enforced,
        signature_verified,
        signer_key_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_MODEL, Mode};

    fn policy() -> EnterprisePolicy {
        EnterprisePolicy {
            version: 1,
            policy_id: None,
            revision: None,
            not_before: None,
            expires_at: None,
            force_human_review: true,
            prohibit_sending: true,
            prohibit_integration_api: true,
            prohibit_recovery_key_export: true,
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
        assert!(!policy().allows_recovery_key_export());
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
        assert!(validate_explicit_policy_path(PathBuf::from("relative-policy.json")).is_err());
        #[cfg(windows)]
        assert!(
            validate_explicit_policy_path(PathBuf::from(
                r"C:\ProgramData\RejectionRejector\policy.json"
            ))
            .is_ok()
        );
        #[cfg(not(windows))]
        assert!(
            validate_explicit_policy_path(PathBuf::from("/etc/rejection-rejector/policy.json"))
                .is_ok()
        );
    }

    #[test]
    fn digest_pin_rejects_policy_drift() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        let body = br#"{"version":1,"prohibit_sending":true}"#;
        std::fs::write(&path, body).unwrap();
        let digest = format!("{:x}", Sha256::digest(body));

        let loaded = load_file_with_expected_digest(&path, Some(digest.clone())).unwrap();
        assert_eq!(loaded.digest, digest);
        assert!(loaded.status().digest_pin_enforced);
        assert!(loaded.status().digest_pin_matches);

        std::fs::write(&path, br#"{"version":1,"prohibit_sending":false}"#).unwrap();
        assert!(load_file_with_expected_digest(&path, Some(digest)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_digest_pin_is_rejected_fail_closed() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = std::ffi::OsString::from_vec(vec![0xff, 0xfe]);
        assert!(normalize_digest_pin_os(invalid).is_err());
    }

    #[test]
    fn digest_pin_validation_is_strict() {
        assert_eq!(
            normalize_digest_pin(&"A".repeat(64)).unwrap(),
            "a".repeat(64)
        );
        for invalid in ["", "abc", &"g".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            assert!(normalize_digest_pin(invalid).is_err());
        }
    }

    #[test]
    fn v2_policy_lifecycle_and_rollback_floor_are_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        let body = br#"{"version":2,"policy_id":"corp-prod","revision":7,"prohibit_sending":true}"#;
        std::fs::write(&path, body).unwrap();
        let loaded = load_file(&path).unwrap();
        assert_eq!(loaded.policy.revision_identity(), Some(("corp-prod", 7)));

        let mut floor = PolicyRevisionFloor::default();
        assert!(floor.observe(&loaded).unwrap());
        assert!(!floor.observe(&loaded).unwrap());

        std::fs::write(
            &path,
            br#"{"version":2,"policy_id":"corp-prod","revision":6,"prohibit_sending":true}"#,
        )
        .unwrap();
        let older = load_file(&path).unwrap();
        assert!(floor.observe(&older).is_err());

        std::fs::write(
            &path,
            br#"{"version":2,"policy_id":"corp-prod","revision":7,"prohibit_sending":false}"#,
        )
        .unwrap();
        let changed_same_revision = load_file(&path).unwrap();
        assert!(floor.observe(&changed_same_revision).is_err());

        std::fs::write(
            &path,
            br#"{"version":2,"policy_id":"corp-prod","revision":8,"prohibit_sending":false}"#,
        )
        .unwrap();
        let newer = load_file(&path).unwrap();
        assert!(floor.observe(&newer).unwrap());
    }

    #[test]
    fn policy_revision_floor_caps_distinct_namespaces() {
        let root = tempfile::tempdir().unwrap();
        let mut floor = PolicyRevisionFloor::default();
        for index in 0..32 {
            let path = root.path().join(format!("policy-{index}.json"));
            std::fs::write(
                &path,
                format!(r#"{{"version":2,"policy_id":"tenant-{index}","revision":1}}"#),
            )
            .unwrap();
            let loaded = load_file(&path).unwrap();
            assert!(floor.observe(&loaded).unwrap());
        }
        let overflow = root.path().join("overflow.json");
        std::fs::write(
            &overflow,
            r#"{"version":2,"policy_id":"tenant-overflow","revision":1}"#,
        )
        .unwrap();
        assert!(floor.observe(&load_file(&overflow).unwrap()).is_err());
    }

    #[test]
    fn v2_policy_validity_window_is_enforced() {
        let now = Utc::now();
        let future = EnterprisePolicy {
            version: 2,
            policy_id: Some("corp".into()),
            revision: Some(1),
            not_before: Some(now + chrono::Duration::minutes(1)),
            expires_at: None,
            ..EnterprisePolicy::default()
        };
        assert!(future.validate_at(now).is_err());

        let expired = EnterprisePolicy {
            version: 2,
            policy_id: Some("corp".into()),
            revision: Some(1),
            not_before: None,
            expires_at: Some(now - chrono::Duration::seconds(1)),
            ..EnterprisePolicy::default()
        };
        assert!(expired.validate_at(now).is_err());

        let active = EnterprisePolicy {
            version: 2,
            policy_id: Some("corp".into()),
            revision: Some(1),
            not_before: Some(now - chrono::Duration::minutes(1)),
            expires_at: Some(now + chrono::Duration::minutes(1)),
            ..EnterprisePolicy::default()
        };
        active.validate_at(now).unwrap();
    }

    #[test]
    fn signed_policy_authenticates_exact_bytes_and_reports_signer() {
        use base64::engine::general_purpose::STANDARD;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        let signature_path = root.path().join("policy.json.sig");
        let body = br#"{"version":2,"policy_id":"corp","revision":1,"prohibit_sending":true}"#;
        std::fs::write(&path, body).unwrap();

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
        let signature = key_pair.sign(body);
        std::fs::write(
            &signature_path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "algorithm": "ed25519",
                "signature": STANDARD.encode(signature.as_ref())
            }))
            .unwrap(),
        )
        .unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let requirement = SignatureRequirement {
            signer_key_sha256: format!("{:x}", Sha256::digest(&public_key)),
            public_key,
            signature_path: signature_path.clone(),
        };

        let loaded = load_file_with_controls(&path, None, Some(requirement.clone())).unwrap();
        let status = loaded.status();
        assert!(status.signature_enforced);
        assert!(status.signature_verified);
        assert_eq!(
            status.signer_key_sha256,
            Some(requirement.signer_key_sha256.clone())
        );

        std::fs::write(
            &path,
            br#"{"version":2,"policy_id":"corp","revision":2,"prohibit_sending":false}"#,
        )
        .unwrap();
        assert!(load_file_with_controls(&path, None, Some(requirement.clone())).is_err());

        std::fs::write(&path, body).unwrap();
        std::fs::write(
            &signature_path,
            r#"{"version":1,"algorithm":"ed25519","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}"#,
        )
        .unwrap();
        assert!(load_file_with_controls(&path, None, Some(requirement)).is_err());
    }

    #[test]
    fn detached_signature_envelope_rejects_wrong_algorithm_version_and_oversize() {
        use base64::engine::general_purpose::STANDARD;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.json");
        let signature_path = root.path().join("policy.json.sig");
        let body = br#"{"version":2,"policy_id":"corp","revision":1}"#;
        std::fs::write(&path, body).unwrap();
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[3u8; 32]).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        let requirement = SignatureRequirement {
            signer_key_sha256: format!("{:x}", Sha256::digest(&public_key)),
            public_key,
            signature_path: signature_path.clone(),
        };

        for envelope in [
            serde_json::json!({"version":2,"algorithm":"ed25519","signature":STANDARD.encode(key_pair.sign(body).as_ref())}),
            serde_json::json!({"version":1,"algorithm":"rsa","signature":STANDARD.encode(key_pair.sign(body).as_ref())}),
        ] {
            std::fs::write(&signature_path, serde_json::to_vec(&envelope).unwrap()).unwrap();
            assert!(load_file_with_controls(&path, None, Some(requirement.clone())).is_err());
        }

        std::fs::write(&signature_path, vec![b'A'; (MAX_POLICY_SIGNATURE_BYTES + 1) as usize])
            .unwrap();
        assert!(load_file_with_controls(&path, None, Some(requirement)).is_err());
    }

    #[test]
    fn enterprise_policy_public_key_and_signature_paths_are_strict() {
        use base64::engine::general_purpose::STANDARD;

        assert!(normalize_public_key("not-base64").is_err());
        assert!(normalize_public_key(&STANDARD.encode([0u8; 31])).is_err());
        assert_eq!(
            normalize_public_key(&STANDARD.encode([9u8; 32]))
                .unwrap()
                .len(),
            32
        );
        assert!(validate_signature_path(PathBuf::from("policy.sig")).is_err());

        let absolute = std::env::temp_dir().join("policy.json");
        assert!(validate_signature_distinct(&absolute, &absolute).is_err());
        assert_eq!(
            signature_path_for_policy(&absolute),
            PathBuf::from(format!("{}.sig", absolute.display()))
        );
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
