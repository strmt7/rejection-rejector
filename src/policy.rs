use crate::config::{Settings, VERIFIER_CANDIDATES, validate_model_name};
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
/// Schema version of the enterprise policy document.
///
/// Inputs: none (constant). Output: `u32` — the version accepted when
/// parsing.
pub const ENTERPRISE_POLICY_SCHEMA_VERSION: u32 = 1;

/// The bundled enterprise-policy JSON schema.
///
/// Inputs: none. Output: `&'static str` schema text.
pub fn schema_text() -> &'static str {
    include_str!("../docs/enterprise-policy.schema.json")
}

/// Fingerprint the bundled policy schema.
///
/// Inputs: none. Output: `String` of lowercase hex — the SHA-256 digest of [`schema_text`].
pub fn schema_sha256() -> String {
    crate::hex_lower(Sha256::digest(schema_text().as_bytes()))
}

/// Enterprise policy document restricting unattended operation.
///
/// Inputs: none (plain struct). Output: lifecycle bounds and the
/// prohibitions, limits and model allowlists enforced on the workspace
/// settings.
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
    pub require_external_audit_anchor: bool,
    pub require_independent_verifier: bool,
    pub max_daily_send_limit: Option<u16>,
    pub min_cooldown_minutes: Option<u16>,
    pub min_retention_days: Option<u16>,
    pub allowed_models: Vec<String>,
    pub allowed_verifier_models: Vec<String>,
}

/// Current policy posture surfaced to operators.
///
/// Inputs: none (plain struct). Output: activation state, lifecycle, digest
/// and signature verification results and the enforced restrictions.
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
    pub require_external_audit_anchor: bool,
    pub require_independent_verifier: bool,
    pub max_daily_send_limit: Option<u16>,
    pub min_cooldown_minutes: Option<u16>,
    pub min_retention_days: Option<u16>,
    pub allowed_model_count: usize,
    pub allowed_models: Vec<String>,
    pub allowed_verifier_model_count: usize,
    pub allowed_verifier_models: Vec<String>,
}

impl EnterprisePolicy {
    /// Validate the policy document's structure.
    ///
    /// Inputs: none beyond the policy. Output: `Ok(())` for supported versions and
    /// well-formed fields.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1..=3),
            "Unsupported enterprise policy version"
        );
        if self.version == 1 {
            ensure!(
                self.policy_id.is_none()
                    && self.revision.is_none()
                    && self.not_before.is_none()
                    && self.expires_at.is_none(),
                "Policy v1 cannot contain v2 lifecycle fields"
            );
        } else {
            // Versions 2 and 3 share the v2 lifecycle contract; the guard
            // above already rejected every other version.
            let policy_id = self
                .policy_id
                .as_deref()
                .filter(|value| !value.is_empty())
                .context("Policy v2 requires policy_id")?;
            ensure!(
                policy_id.len() <= 128
                    && policy_id
                        .bytes()
                        .all(|byte| { byte.is_ascii_alphanumeric() || b"._:-".contains(&byte) }),
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
        if self.version < 3 {
            ensure!(
                !self.require_independent_verifier && self.allowed_verifier_models.is_empty(),
                "Independent-verifier policy controls require policy version 3"
            );
        }
        if self.require_independent_verifier
            && !self.allowed_models.is_empty()
            && !self.allowed_verifier_models.is_empty()
        {
            ensure!(
                self.allowed_models.iter().any(|primary| {
                    self.allowed_verifier_models
                        .iter()
                        .any(|verifier| verifier != primary)
                }),
                "Enterprise policy cannot require an independent verifier when every allowed primary/verifier pairing uses the same model tag"
            );
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
        ensure!(
            self.allowed_verifier_models.len() <= 64,
            "Enterprise verifier-model allow-list is too large"
        );
        let mut verifier_unique = std::collections::BTreeSet::new();
        for model in &self.allowed_verifier_models {
            validate_model_name(model)?;
            ensure!(
                verifier_unique.insert(model),
                "Enterprise verifier-model allow-list contains duplicates"
            );
        }
        Ok(())
    }

    /// Validate the policy and its time window.
    ///
    /// Inputs: `now` — evaluation time. Output: `Ok(())` when the policy is
    /// well-formed and active.
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

    /// The policy identity/revision pair used for change detection.
    ///
    /// Inputs: none beyond the policy. Output: `Option<(&str, u64)>` — `(policy_id, revision)`
    /// for v2+ policies.
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
    ///
    /// This function applies enterprise policy constraints to mutable user settings,
    /// returning true if settings were modified (indicating policy was applied) or
    /// false if no changes were needed (settings already compliant).
    ///
    /// Inputs: `settings` — mutable user settings to constrain; `startup` —
    /// whether this is the startup enforcement pass. Output: `Result<bool>` — `true`
    /// when the settings changed.
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
        if self.require_independent_verifier {
            settings.independent_verifier_enabled = true;
            if settings.verifier_model_digest.is_none() {
                settings.disarm_delivery();
            }
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
                settings.model.clone_from(&self.allowed_models[0]);
                settings.model_digest = None;
                settings.task_qualification = None;
                settings.disarm_delivery();
            } else {
                anyhow::bail!("Selected model is not approved by enterprise policy");
            }
        }
        if !self.allowed_verifier_models.is_empty()
            && !self
                .allowed_verifier_models
                .contains(&settings.verifier_model)
        {
            if startup {
                settings
                    .verifier_model
                    .clone_from(&self.allowed_verifier_models[0]);
                settings.verifier_model_digest = None;
                settings.task_qualification = None;
                settings.disarm_delivery();
            } else {
                anyhow::bail!(
                    "Selected independent verifier model is not approved by enterprise policy"
                );
            }
        }

        if self.require_independent_verifier && settings.verifier_model == settings.model {
            if !startup {
                anyhow::bail!(
                    "Enterprise policy requires the independent verifier to use a different model tag from the primary model"
                );
            }
            let replacement = if self.allowed_verifier_models.is_empty() {
                VERIFIER_CANDIDATES
                    .iter()
                    .map(|(_, tag)| *tag)
                    .find(|tag| *tag != settings.model)
                    .map(str::to_owned)
            } else {
                self.allowed_verifier_models
                    .iter()
                    .find(|tag| tag.as_str() != settings.model)
                    .cloned()
            }
            .context(
                "Enterprise policy requires independent verification but no distinct permitted verifier model is available",
            )?;
            settings.verifier_model = replacement;
            settings.verifier_model_digest = None;
            settings.task_qualification = None;
            settings.disarm_delivery();
        }

        settings.validate()?;
        Ok(*settings != before)
    }

    /// Whether the policy permits send scope.
    ///
    /// Inputs: none beyond the policy. Output: `true` unless sending is
    /// prohibited.
    pub fn allows_send_scope(&self) -> bool {
        !self.prohibit_sending
    }

    /// Whether the policy permits recovery-key export.
    ///
    /// Inputs: none beyond the policy. Output: `true` unless export is prohibited.
    pub fn allows_recovery_key_export(&self) -> bool {
        !self.prohibit_recovery_key_export
    }
}

/// Policy document loaded from disk with its verification state.
///
/// Inputs: none (plain struct). Output: the parsed policy, its digest, the
/// pinned digest if any, and the signature enforcement results.
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

/// Per-policy revision floor preventing rollback to older policies.
///
/// Inputs: none (plain struct). Output: the policy id to
/// [`PolicyRevisionRecord`] floor map.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyRevisionFloor {
    pub policies: std::collections::BTreeMap<String, PolicyRevisionRecord>,
}

/// Highest accepted revision and digest for one policy id.
///
/// Inputs: none (plain struct). Output: the revision number and digest
/// recorded for rollback protection.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevisionRecord {
    pub revision: u64,
    pub digest: String,
}

impl PolicyRevisionFloor {
    /// Record a loaded policy and detect identity changes.
    ///
    /// Inputs: `loaded` — policy just loaded. Output: `Result<bool>` — `true` when
    /// the tracked identity/revision changed; conflicting identities fail closed.
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
    /// The status reported for this loaded policy.
    ///
    /// Inputs: none beyond the loaded policy. Output: [`PolicyStatus`] marked
    /// active with its identity and revision.
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
            require_external_audit_anchor: self.policy.require_external_audit_anchor,
            require_independent_verifier: self.policy.require_independent_verifier,
            max_daily_send_limit: self.policy.max_daily_send_limit,
            min_cooldown_minutes: self.policy.min_cooldown_minutes,
            min_retention_days: self.policy.min_retention_days,
            allowed_model_count: self.policy.allowed_models.len(),
            allowed_models: self.policy.allowed_models.clone(),
            allowed_verifier_model_count: self.policy.allowed_verifier_models.len(),
            allowed_verifier_models: self.policy.allowed_verifier_models.clone(),
        }
    }
}

/// The status reported when no policy is loaded.
///
/// Inputs: none. Output: [`PolicyStatus`] marked inactive.
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
        require_external_audit_anchor: false,
        require_independent_verifier: false,
        max_daily_send_limit: None,
        min_cooldown_minutes: None,
        min_retention_days: None,
        allowed_model_count: 0,
        allowed_models: vec![],
        allowed_verifier_model_count: 0,
        allowed_verifier_models: vec![],
    }
}

/// Normalize and validate a configured policy digest pin.
///
/// Inputs: `value` — raw `RR_ENTERPRISE_POLICY_SHA256` value. Output:
/// `Result<String>` — the trimmed lowercase digest; error unless it is exactly
/// 64 hex characters.
fn normalize_digest_pin(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    ensure!(
        normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "RR_ENTERPRISE_POLICY_SHA256 must be exactly 64 hexadecimal characters"
    );
    Ok(normalized)
}

/// Normalize a digest pin supplied as an OS string.
///
/// Inputs: `value` — raw environment value. Output: `Result<String>` — the
/// normalized digest as [`normalize_digest_pin`] returns; error when the value
/// is not valid Unicode.
fn normalize_digest_pin_os(value: std::ffi::OsString) -> Result<String> {
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("RR_ENTERPRISE_POLICY_SHA256 must be valid Unicode"))?;
    normalize_digest_pin(&value)
}

/// Read the policy digest pin from the environment.
///
/// Inputs: none. Output: `Result<Option<String>>` — the normalized pin, `None`
/// when the variable is unset; error when it is set but invalid.
fn configured_digest_pin() -> Result<Option<String>> {
    digest_pin_from(std::env::var_os("RR_ENTERPRISE_POLICY_SHA256"))
}

/// Digest-pin resolution over an injected environment value.
///
/// Inputs: `value` — the raw environment value, `None` when unset. Output:
/// the normalized pin, or an error for non-Unicode/invalid content. Test
/// seam: the raw value is injected so every parsing failure is deterministic.
fn digest_pin_from(value: Option<std::ffi::OsString>) -> Result<Option<String>> {
    value.map(normalize_digest_pin_os).transpose()
}

/// Normalize and validate a configured Ed25519 public key.
///
/// Inputs: `value` — raw `RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY` value.
/// Output: `Result<Vec<u8>>` — the 32 decoded key bytes; error for non-base64
/// or wrong-length input.
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

/// Derive the default detached signature path for a policy file.
///
/// Inputs: `policy_path` — policy file path. Output: `PathBuf` — the policy
/// path with `.sig` appended.
fn signature_path_for_policy(policy_path: &Path) -> PathBuf {
    let mut path = policy_path.as_os_str().to_os_string();
    path.push(".sig");
    PathBuf::from(path)
}

/// Validate a configured signature file path.
///
/// Inputs: `path` — `RR_ENTERPRISE_POLICY_SIGNATURE` value. Output:
/// `Result<PathBuf>` — the path unchanged; error when it is not absolute.
fn validate_signature_path(path: PathBuf) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "RR_ENTERPRISE_POLICY_SIGNATURE must be an absolute path"
    );
    Ok(path)
}

/// Ensure the signature file is distinct from the policy file.
///
/// Inputs: `policy_path` — policy file path; `signature_path` — signature file
/// path. Output: `Result<()>` — `Ok` when the paths differ (and canonicalize to
/// different files when both exist); error otherwise.
fn validate_signature_distinct(policy_path: &Path, signature_path: &Path) -> Result<()> {
    ensure!(
        policy_path != signature_path,
        "Enterprise policy signature file must be distinct from the policy file"
    );
    if policy_path.exists() && signature_path.exists() {
        let policy_canonical =
            fs::canonicalize(policy_path).context("Cannot canonicalize enterprise policy path")?;
        let signature_canonical = fs::canonicalize(signature_path)
            .context("Cannot canonicalize enterprise policy signature path")?;
        ensure!(
            policy_canonical != signature_canonical,
            "Enterprise policy signature resolves to the policy file"
        );
    }
    Ok(())
}

/// Build the signature requirement from the environment.
///
/// Inputs: `policy_path` — policy file path used for the default signature
/// path. Output: `Result<Option<SignatureRequirement>>` — the requirement when
/// the public key is configured, `None` otherwise; error on invalid
/// configuration.
fn configured_signature_requirement(policy_path: &Path) -> Result<Option<SignatureRequirement>> {
    signature_requirement_from(
        policy_path,
        std::env::var_os("RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY"),
        std::env::var_os("RR_ENTERPRISE_POLICY_SIGNATURE"),
    )
}

/// Signature requirement resolution over injected environment values.
///
/// Inputs: `policy_path` — active policy file; `key` — raw configured Ed25519
/// public key; `signature_override` — raw configured signature-file path.
/// Output: the requirement to enforce, `None` when no key is configured, or an
/// error for any incomplete/invalid configuration. Test seam: the raw values
/// are injected so every misconfiguration is exercised deterministically.
fn signature_requirement_from(
    policy_path: &Path,
    key: Option<std::ffi::OsString>,
    signature_override: Option<std::ffi::OsString>,
) -> Result<Option<SignatureRequirement>> {
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
    let signer_key_sha256 = crate::hex_lower(Sha256::digest(&public_key));
    let signature_path = signature_override
        .map(PathBuf::from)
        .map(validate_signature_path)
        .transpose()?
        .unwrap_or_else(|| signature_path_for_policy(policy_path));
    validate_signature_distinct(policy_path, &signature_path)?;
    Ok(Some(SignatureRequirement {
        public_key,
        signer_key_sha256,
        signature_path,
    }))
}

/// Verify the detached Ed25519 signature over the policy bytes.
///
/// Inputs: `requirement` — public key and signature path; `policy_bytes` —
/// exact policy file content. Output: `Result<()>` — `Ok` when the signature
/// authenticates; error otherwise (fail closed).
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

/// Validate an explicitly configured policy path.
///
/// Inputs: `path` — `RR_ENTERPRISE_POLICY` value. Output: `Result<PathBuf>` —
/// the path unchanged; error when it is not absolute.
fn validate_explicit_policy_path(path: PathBuf) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "RR_ENTERPRISE_POLICY must be an absolute path"
    );
    Ok(path)
}

/// Resolve the machine-wide policy file path.
///
/// Inputs: none; reads the policy environment override and `PROGRAMDATA`.
/// Output: `Result<Option<PathBuf>>` — the configured policy path, if any.
pub fn default_policy_path() -> Result<Option<PathBuf>> {
    policy_path_from(
        std::env::var_os("RR_ENTERPRISE_POLICY"),
        std::env::var_os("PROGRAMDATA"),
    )
}

/// Policy-path resolution over injected environment values.
///
/// Inputs: `explicit` — raw `RR_ENTERPRISE_POLICY` value; `program_data` — raw
/// Windows `PROGRAMDATA` root. Output: the absolute policy path to load, or
/// `None` when no location is available. Test seam: the raw values are injected
/// so explicit-path validation is exercised deterministically.
fn policy_path_from(
    explicit: Option<std::ffi::OsString>,
    program_data: Option<std::ffi::OsString>,
) -> Result<Option<PathBuf>> {
    if let Some(explicit) = explicit {
        return Ok(Some(validate_explicit_policy_path(PathBuf::from(
            explicit,
        ))?));
    }
    #[cfg(windows)]
    {
        Ok(program_data
            .map(PathBuf::from)
            .map(|root| root.join("RejectionRejector").join("policy.json")))
    }
    #[cfg(not(windows))]
    {
        let _ = program_data;
        Ok(Some(PathBuf::from("/etc/rejection-rejector/policy.json")))
    }
}

/// Load the machine-wide policy when one is configured.
///
/// Inputs: none. Output: `Result<Option<LoadedPolicy>>` — the validated
/// policy, or `None` when none is configured.
pub fn load_optional() -> Result<Option<LoadedPolicy>> {
    // Test seam: process threads under test arm a deterministic policy in
    // `crate::test_support`, so reload/startup flows exercise policy behavior
    // without machine-wide files or environment mutation.
    #[cfg(test)]
    if let Some(loader) = crate::test_support::policy_loader() {
        return Ok(loader());
    }
    let expected_digest = configured_digest_pin()?;
    let signature_configured = std::env::var_os("RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY")
        .is_some()
        || std::env::var_os("RR_ENTERPRISE_POLICY_SIGNATURE").is_some();
    load_optional_from(
        default_policy_path()?,
        expected_digest,
        signature_configured,
        configured_signature_requirement,
    )
}

/// Optional policy loading over injected configuration.
///
/// Inputs: `path` — resolved policy location (`None` when unavailable);
/// `expected_digest` — configured digest pin; `signature_configured` — whether
/// any signature control is set; `requirement` — resolves the signature
/// requirement for an existing policy file. Output: the loaded policy, `None`
/// when no policy exists, or an error when integrity controls reference a
/// missing policy. Test seam: the resolution closure is injected so signature
/// resolution failures are exercised deterministically.
fn load_optional_from(
    path: Option<PathBuf>,
    expected_digest: Option<String>,
    signature_configured: bool,
    requirement: impl FnOnce(&Path) -> Result<Option<SignatureRequirement>>,
) -> Result<Option<LoadedPolicy>> {
    let Some(path) = path else {
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
    let signature_requirement = requirement(&path)?;
    load_file_with_controls(&path, expected_digest, signature_requirement).map(Some)
}

/// Load and validate one policy file.
///
/// Inputs: `path` — policy file to read. Output: `Result<LoadedPolicy>`;
/// malformed policies are refused.
pub fn load_file(path: &Path) -> Result<LoadedPolicy> {
    load_file_with_controls(path, None, None)
}

/// Load a policy file under its configured digest and signature controls.
///
/// Inputs: `path` — absolute policy file path; `expected_digest` — pinned
/// SHA-256 digest, when configured; `signature_requirement` — signature
/// requirement, when configured. Output: `Result<LoadedPolicy>` — the
/// authenticated policy; error when any control fails.
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
    let digest = crate::hex_lower(Sha256::digest(&bytes));
    if let Some(expected) = &expected_digest {
        ensure!(
            &digest == expected,
            "Enterprise policy digest does not match RR_ENTERPRISE_POLICY_SHA256"
        );
    }
    let (signature_enforced, signature_verified, signer_key_sha256) =
        if let Some(requirement) = &signature_requirement {
            validate_signature_distinct(path, &requirement.signature_path)?;
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

    #[test]
    fn machine_policy_schema_matches_runtime_field_surface() {
        let schema: serde_json::Value = serde_json::from_str(schema_text()).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert!(!schema["additionalProperties"].as_bool().unwrap());
        assert_eq!(
            schema["properties"]["version"]["enum"],
            serde_json::json!([1, 2, 3])
        );

        let schema_fields: std::collections::BTreeSet<_> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let runtime_fields: std::collections::BTreeSet<_> =
            serde_json::to_value(EnterprisePolicy::default())
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
        assert_eq!(schema_fields, runtime_fields);
        let digest = schema_sha256();
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));

        let example: EnterprisePolicy =
            serde_json::from_str(include_str!("../config/enterprise-policy.example.json")).unwrap();
        example.validate().unwrap();
    }

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
            require_external_audit_anchor: false,
            require_independent_verifier: false,
            max_daily_send_limit: Some(3),
            min_cooldown_minutes: Some(90),
            min_retention_days: Some(365),
            allowed_models: vec!["granite4.2:8b-q8_0".into()],
            allowed_verifier_models: vec![],
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
    fn policy_status_exposes_external_audit_anchor_requirement() {
        let mut managed = policy();
        managed.require_external_audit_anchor = true;
        let loaded = LoadedPolicy {
            policy: managed,
            digest: "a".repeat(64),
            expected_digest: None,
            signature_enforced: false,
            signature_verified: false,
            signer_key_sha256: None,
        };
        assert!(loaded.status().require_external_audit_anchor);
        assert!(!inactive_status().require_external_audit_anchor);
    }

    #[test]
    fn managed_startup_resolves_primary_verifier_collision_fail_closed() {
        let mut managed = EnterprisePolicy {
            version: 3,
            policy_id: Some("collision-policy".into()),
            revision: Some(1),
            require_independent_verifier: true,
            allowed_models: vec!["granite4.2:8b-q8_0".into()],
            ..EnterprisePolicy::default()
        };
        managed.validate().unwrap();

        let mut settings = Settings {
            model: "qwen3.5:9b-q8_0".into(),
            verifier_model: "granite4.2:8b-q8_0".into(),
            verifier_model_digest: Some("a".repeat(64)),
            sending_enabled: true,
            ..Settings::default()
        };
        managed.enforce(&mut settings, true).unwrap();
        assert_eq!(settings.model, "granite4.2:8b-q8_0");
        assert_ne!(settings.verifier_model, settings.model);
        assert!(settings.verifier_model_digest.is_none());
        assert!(settings.task_qualification.is_none());
        assert!(!settings.sending_enabled);

        managed.allowed_verifier_models = vec!["granite4.2:8b-q8_0".into()];
        assert!(managed.validate().is_err());
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
        let digest = crate::hex_lower(Sha256::digest(body));

        let loaded = load_file_with_controls(&path, Some(digest.clone()), None).unwrap();
        assert_eq!(loaded.digest, digest);
        assert!(loaded.status().digest_pin_enforced);
        assert!(loaded.status().digest_pin_matches);

        std::fs::write(&path, br#"{"version":1,"prohibit_sending":false}"#).unwrap();
        assert!(load_file_with_controls(&path, Some(digest), None).is_err());
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
            signer_key_sha256: crate::hex_lower(Sha256::digest(&public_key)),
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
            signer_key_sha256: crate::hex_lower(Sha256::digest(&public_key)),
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

        std::fs::write(
            &signature_path,
            vec![b'A'; (MAX_POLICY_SIGNATURE_BYTES + 1) as usize],
        )
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

        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.json");
        std::fs::write(&policy, b"{}").unwrap();
        let lexical_alias = root.path().join(".").join("policy.json");
        assert!(validate_signature_distinct(&policy, &lexical_alias).is_err());

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

    #[test]
    fn v3_policy_can_require_and_restrict_independent_verification() {
        let mut managed = EnterprisePolicy {
            version: 3,
            policy_id: Some("corp-independent-verifier".into()),
            revision: Some(1),
            require_independent_verifier: true,
            allowed_models: vec!["qwen3.5:9b-q8_0".into()],
            allowed_verifier_models: vec!["granite4.2:8b-q8_0".into()],
            ..EnterprisePolicy::default()
        };
        managed.validate().unwrap();
        let mut settings = Settings {
            verifier_model: "qwen3.5:4b".into(),
            ..Settings::default()
        };
        managed.enforce(&mut settings, true).unwrap();
        assert!(settings.independent_verifier_enabled);
        assert_eq!(settings.verifier_model, "granite4.2:8b-q8_0");
        assert_eq!(settings.mode, Mode::HumanReview);
        managed.version = 2;
        assert!(managed.validate().is_err());
    }
}

#[cfg(test)]
mod configuration_seam_tests {
    use super::*;
    use crate::config::Settings;

    fn v3_policy() -> EnterprisePolicy {
        EnterprisePolicy {
            version: 3,
            policy_id: Some("corp".into()),
            revision: Some(1),
            ..Default::default()
        }
    }

    #[cfg(windows)]
    fn key_os() -> std::ffi::OsString {
        std::ffi::OsString::from(STANDARD.encode([9u8; 32]))
    }

    /// Why: the digest pin must normalize uppercase hex, reject anything that
    /// is not exactly 64 hex characters, and fail closed on non-Unicode
    /// environment values instead of silently disabling the pin.
    #[cfg(windows)]
    #[test]
    fn digest_pin_normalization_fails_closed_on_every_malformed_value() {
        assert_eq!(digest_pin_from(None).unwrap(), None);
        assert_eq!(
            digest_pin_from(Some("A".repeat(64).into())).unwrap(),
            Some("a".repeat(64))
        );
        assert!(digest_pin_from(Some("short".into())).is_err());
        assert!(digest_pin_from(Some("z".repeat(64).into())).is_err());
        assert!(
            configured_digest_pin().is_ok(),
            "unset pin must read cleanly"
        );

        let non_unicode: std::ffi::OsString =
            std::os::windows::ffi::OsStringExt::from_wide(&[0xD800]);
        let error = digest_pin_from(Some(non_unicode.clone())).unwrap_err();
        assert!(
            error.to_string().contains("valid Unicode"),
            "unexpected error: {error}"
        );
        assert!(normalize_digest_pin_os(non_unicode).is_err());
    }

    /// Why: enterprise signature enforcement must fail closed on every partial
    /// configuration — a signature override without a key, a relative
    /// signature path, a signature that aliases the policy file or a malformed
    /// key are all administrator errors that must never silently disable
    /// signature enforcement.
    #[cfg(windows)]
    #[test]
    fn signature_requirement_resolution_fails_closed_on_every_misconfiguration() {
        let policy = std::env::temp_dir().join("rr-policy-under-test.json");
        assert!(
            signature_requirement_from(&policy, None, None)
                .unwrap()
                .is_none()
        );

        let error =
            signature_requirement_from(&policy, None, Some("C:\\x.sig".into())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY"),
            "unexpected error: {error}"
        );

        let error =
            signature_requirement_from(&policy, Some(key_os()), Some("relative.sig".into()))
                .unwrap_err();
        assert!(error.to_string().contains("absolute path"));

        let error = signature_requirement_from(
            &policy,
            Some(key_os()),
            Some(policy.clone().into_os_string()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("distinct"));

        let default_req = signature_requirement_from(&policy, Some(key_os()), None)
            .unwrap()
            .expect("key without override must derive the .sig path");
        assert!(
            default_req
                .signature_path
                .to_string_lossy()
                .ends_with(".sig")
        );
        assert_eq!(default_req.public_key.len(), 32);
        assert_eq!(default_req.signer_key_sha256.len(), 64);

        let explicit_sig = policy.clone().with_extension("sig");
        let req = signature_requirement_from(
            &policy,
            Some(key_os()),
            Some(explicit_sig.clone().into_os_string()),
        )
        .unwrap()
        .expect("a valid absolute distinct signature path is accepted");
        assert_eq!(req.signature_path, explicit_sig);

        let non_unicode: std::ffi::OsString =
            std::os::windows::ffi::OsStringExt::from_wide(&[0xD800]);
        assert!(signature_requirement_from(&policy, Some(non_unicode), None).is_err());
        assert!(signature_requirement_from(&policy, Some("!!not-base64!!".into()), None).is_err());
        let short = std::ffi::OsString::from(STANDARD.encode([9u8; 16]));
        assert!(signature_requirement_from(&policy, Some(short), None).is_err());

        assert!(configured_signature_requirement(&policy).is_ok());
    }

    /// Why: the explicit `RR_ENTERPRISE_POLICY` location wins and must be
    /// absolute; otherwise Windows resolves under `PROGRAMDATA` and machines
    /// without one simply have no policy to load.
    #[cfg(windows)]
    #[test]
    fn policy_path_resolution_prefers_the_explicit_absolute_path() {
        let explicit = std::env::temp_dir().join("explicit-policy.json");
        assert_eq!(
            policy_path_from(
                Some(explicit.clone().into_os_string()),
                Some("C:\\ProgramData".into())
            )
            .unwrap(),
            Some(explicit)
        );
        assert!(policy_path_from(Some("relative.json".into()), None).is_err());
        assert_eq!(
            policy_path_from(None, Some("C:\\ProgramData".into())).unwrap(),
            Some(
                std::path::PathBuf::from("C:\\ProgramData")
                    .join("RejectionRejector")
                    .join("policy.json")
            )
        );
        assert_eq!(policy_path_from(None, None).unwrap(), None);
        assert!(default_policy_path().is_ok());
    }

    /// Why: integrity controls (digest pin, signature) that reference no
    /// policy at all are administrator errors; loading must fail instead of    /// returning "no policy configured" and silently running unpinned.
    #[test]
    fn optional_loading_fails_closed_when_integrity_controls_reference_nothing() {
        assert!(
            load_optional_from(None, None, false, |_| Ok(None))
                .unwrap()
                .is_none()
        );

        let error =
            load_optional_from(None, Some("a".repeat(64)), false, |_| Ok(None)).unwrap_err();
        assert!(
            error.to_string().contains("no policy path is available"),
            "unexpected error: {error}"
        );

        let missing =
            std::env::temp_dir().join(format!("rr-missing-policy-{}.json", uuid::Uuid::new_v4()));
        let error = load_optional_from(Some(missing), None, true, |_| Ok(None)).unwrap_err();
        assert!(
            error.to_string().contains("policy file is missing"),
            "unexpected error: {error}"
        );
    }

    /// Why: an existing policy file loads with its digest and without forced
    /// signature enforcement, while signature-resolution failures propagate
    /// instead of downgrading to unsigned loading.
    #[test]
    fn optional_loading_reads_policy_files_and_propagates_signature_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, serde_json::to_vec(&v3_policy()).unwrap()).unwrap();

        let loaded = load_optional_from(Some(path.clone()), None, false, |_| Ok(None))
            .unwrap()
            .expect("existing policy must load");
        assert_eq!(loaded.policy.policy_id.as_deref(), Some("corp"));
        assert_eq!(loaded.policy.revision, Some(1));
        assert!(!loaded.signature_enforced);

        let error = load_optional_from(Some(path), None, true, |_| {
            Err(anyhow::anyhow!("signature resolution failed"))
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("signature resolution failed"),
            "unexpected error: {error}"
        );
        assert!(load_optional().is_ok());
    }

    /// Why: an explicit settings update must reject unapproved verifier models
    /// outright rather than silently swapping models the operator did not pick.
    #[test]
    fn enforce_rejects_unapproved_verifier_models_during_explicit_updates() {
        let policy = EnterprisePolicy {
            version: 3,
            policy_id: Some("corp".into()),
            revision: Some(1),
            allowed_verifier_models: vec!["approved-verifier:1".into()],
            ..Default::default()
        };
        let mut settings = Settings {
            verifier_model: "other-verifier:1".into(),
            ..Default::default()
        };
        let error = policy.enforce(&mut settings, false).unwrap_err();
        assert!(
            error.to_string().contains("verifier model is not approved"),
            "unexpected error: {error}"
        );
    }

    /// Why: an explicit update may never arm an independent verifier that uses
    /// the same model tag as the primary — that would defeat the independence
    /// guarantee, so it must be rejected, not auto-corrected.
    #[test]
    fn enforce_requires_a_distinct_verifier_tag_in_explicit_updates() {
        let policy = EnterprisePolicy {
            version: 3,
            policy_id: Some("corp".into()),
            revision: Some(1),
            require_independent_verifier: true,
            ..Default::default()
        };
        let mut settings = Settings {
            model: "shared:1".into(),
            verifier_model: "shared:1".into(),
            ..Default::default()
        };
        let error = policy.enforce(&mut settings, false).unwrap_err();
        assert!(
            error.to_string().contains("different model tag"),
            "unexpected error: {error}"
        );
    }

    /// Why: at startup a same-tag verifier is replaced by the first distinct
    /// allowed tag (fail-closed auto-repair), and if the allow-list offers no
    /// distinct tag startup must fail instead of running without an
    /// independent verifier.
    #[test]
    fn enforce_startup_repairs_the_verifier_tag_or_fails_without_an_alternative() {
        let repairable = EnterprisePolicy {
            version: 3,
            policy_id: Some("corp".into()),
            revision: Some(1),
            require_independent_verifier: true,
            allowed_verifier_models: vec!["shared:1".into(), "distinct:1".into()],
            ..Default::default()
        };
        let mut settings = Settings {
            model: "shared:1".into(),
            verifier_model: "shared:1".into(),
            ..Default::default()
        };
        assert!(repairable.enforce(&mut settings, true).unwrap());
        assert_eq!(settings.verifier_model, "distinct:1");

        let stuck = EnterprisePolicy {
            allowed_verifier_models: vec!["shared:1".into()],
            ..repairable
        };
        let mut settings = Settings {
            model: "shared:1".into(),
            verifier_model: "shared:1".into(),
            ..Default::default()
        };
        let error = stuck.enforce(&mut settings, true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no distinct permitted verifier model"),
            "unexpected error: {error}"
        );
    }

    /// Why: the revision floor only tracks policies with an explicit v2+
    /// identity; v1 policies must neither be tracked nor change the floor.
    #[test]
    fn revision_floor_ignores_policies_without_a_revision_identity() {
        let mut floor = PolicyRevisionFloor::default();
        let loaded = LoadedPolicy {
            policy: EnterprisePolicy {
                version: 1,
                ..Default::default()
            },
            digest: "d".repeat(64),
            expected_digest: None,
            signature_enforced: false,
            signature_verified: false,
            signer_key_sha256: None,
        };
        assert!(!floor.observe(&loaded).unwrap());
        assert!(floor.policies.is_empty());
    }

    /// Why: `connect` consults `allows_send_scope` before requesting Gmail send
    /// permission; only the explicit prohibit control may block it.
    #[test]
    fn send_scope_follows_only_the_prohibit_sending_control() {
        assert!(EnterprisePolicy::default().allows_send_scope());
        assert!(
            !EnterprisePolicy {
                prohibit_sending: true,
                ..Default::default()
            }
            .allows_send_scope()
        );
    }

    /// Why: the digest pin arrives as an OS environment string — valid pins
    /// must normalize (trimmed, lowercased, exactly 64 hex) or a rollout pin
    /// silently never applies, and invalid content must error rather than
    /// disable the pin.
    #[test]
    fn digest_pin_normalizes_valid_os_values_and_rejects_the_rest() {
        let pin = "AB".repeat(32);
        assert_eq!(
            digest_pin_from(Some(format!("  {pin}  ").into())).unwrap(),
            Some(pin.to_ascii_lowercase())
        );
        assert!(digest_pin_from(Some("not-hex".into())).is_err());
        assert!(digest_pin_from(None).unwrap().is_none());
    }

    /// Why: a configured Ed25519 signer must resolve to a concrete
    /// requirement — the decoded key, its SHA-256 identity and the signature
    /// file (default `<policy>.sig`, or the validated absolute override) —
    /// or enforcement could verify against the wrong file or key. The
    /// canonicalization branch of the distinctness check runs whenever both
    /// files exist.
    #[test]
    fn signature_requirement_resolves_the_signer_and_signature_file() {
        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.json");
        std::fs::write(&policy, b"{}").unwrap();
        let key_bytes = [7u8; 32];
        let key = STANDARD.encode(key_bytes);

        let req = signature_requirement_from(&policy, Some(key.clone().into()), None)
            .unwrap()
            .expect("a configured key always produces a requirement");
        assert_eq!(req.public_key, key_bytes);
        assert_eq!(
            req.signer_key_sha256,
            crate::hex_lower(Sha256::digest(key_bytes))
        );
        assert_eq!(req.signature_path, signature_path_for_policy(&policy));

        // Both files present: the canonicalized distinctness check passes.
        std::fs::write(&req.signature_path, b"sig").unwrap();
        signature_requirement_from(&policy, Some(key.clone().into()), None)
            .unwrap()
            .expect("both files present and distinct");

        // An absolute override wins; a relative one is refused up front.
        let override_path = root.path().join("explicit.sig");
        std::fs::write(&override_path, b"sig").unwrap();
        let req = signature_requirement_from(
            &policy,
            Some(key.clone().into()),
            Some(override_path.clone().into()),
        )
        .unwrap()
        .expect("absolute override");
        assert_eq!(req.signature_path, override_path);
        assert!(
            signature_requirement_from(&policy, Some(key.into()), Some("relative.sig".into()))
                .is_err(),
            "relative signature paths must be refused before any file access"
        );
    }

    /// Why: an explicit `RR_ENTERPRISE_POLICY` path is a security control
    /// input — it must be validated before use (absolute; a relative path
    /// would resolve against whatever directory the service happens to
    /// start in).
    #[test]
    fn explicit_policy_path_is_validated_before_use() {
        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.json");
        std::fs::write(&policy, b"{}").unwrap();
        assert_eq!(
            policy_path_from(Some(policy.clone().into_os_string()), None).unwrap(),
            Some(policy)
        );
        assert!(policy_path_from(Some("relative.json".into()), None).is_err());
    }
}
