use serde::Serialize;

/// Schema version of the [`ContractInfo`] document.
///
/// Inputs: none (constant). Output: `u32` — the version asserted by
/// consumers.
pub const CONTRACT_INFO_SCHEMA_VERSION: u32 = 1;

/// Machine-readable description of every versioned integration contract.
///
/// Inputs: none (plain struct). Output: schema and API versions with the
/// digests of the OpenAPI, policy and evaluation contracts.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ContractInfo {
    /// Schema version of the contract record.
    pub schema_version: u32,
    /// Application version that produced the contracts.
    pub application_version: String,
    /// Version of the bundled API contract.
    pub api_version: u32,
    /// SHA-256 of the bundled API contract document.
    pub api_contract_sha256: String,
    /// Settings format version handled by this build.
    pub settings_format_version: u32,
    /// Database schema version handled by this build.
    pub database_schema_version: i64,
    /// Enterprise policy schema version handled by this build.
    pub enterprise_policy_schema_version: u32,
    /// SHA-256 of the enterprise policy schema definition.
    pub enterprise_policy_schema_sha256: String,
    /// Evaluation contract version handled by this build.
    pub evaluation_contract_version: String,
    /// SHA-256 of the evaluation suite contract.
    pub evaluation_suite_sha256: String,
    /// Prompt version used by the analysis pipeline.
    pub prompt_version: String,
}

/// Collect the machine-readable contract and version inventory.
///
/// Inputs: none. Output: [`ContractInfo`] with schema, application and API
/// versions plus contract digests and settings format version.
pub fn current() -> ContractInfo {
    ContractInfo {
        schema_version: CONTRACT_INFO_SCHEMA_VERSION,
        application_version: env!("CARGO_PKG_VERSION").into(),
        api_version: crate::api::API_VERSION,
        api_contract_sha256: crate::api::openapi_sha256(),
        settings_format_version: crate::config::SETTINGS_FORMAT_VERSION,
        database_schema_version: crate::store::DATABASE_SCHEMA_VERSION,
        enterprise_policy_schema_version: crate::policy::ENTERPRISE_POLICY_SCHEMA_VERSION,
        enterprise_policy_schema_sha256: crate::policy::schema_sha256(),
        evaluation_contract_version: crate::config::EVALUATION_CONTRACT_VERSION.into(),
        evaluation_suite_sha256: crate::config::evaluation_suite_hash(),
        prompt_version: crate::config::PROMPT_VERSION.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_manifest_is_complete_and_content_bound() {
        let info = current();
        assert_eq!(info.schema_version, CONTRACT_INFO_SCHEMA_VERSION);
        assert_eq!(info.application_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.api_version, crate::api::API_VERSION);
        assert_eq!(
            info.settings_format_version,
            crate::config::SETTINGS_FORMAT_VERSION
        );
        assert_eq!(
            info.database_schema_version,
            crate::store::DATABASE_SCHEMA_VERSION
        );
        assert_eq!(
            info.enterprise_policy_schema_version,
            crate::policy::ENTERPRISE_POLICY_SCHEMA_VERSION
        );
        assert_eq!(
            info.evaluation_contract_version,
            crate::config::EVALUATION_CONTRACT_VERSION
        );
        assert_eq!(info.prompt_version, crate::config::PROMPT_VERSION);
        for digest in [
            &info.api_contract_sha256,
            &info.enterprise_policy_schema_sha256,
            &info.evaluation_suite_sha256,
        ] {
            assert_eq!(digest.len(), 64);
            assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }
}
