use serde::Serialize;

pub const CONTRACT_INFO_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ContractInfo {
    pub schema_version: u32,
    pub application_version: String,
    pub api_version: u32,
    pub api_contract_sha256: String,
    pub settings_format_version: u32,
    pub database_schema_version: i64,
    pub enterprise_policy_schema_version: u32,
    pub enterprise_policy_schema_sha256: String,
    pub evaluation_contract_version: String,
    pub evaluation_suite_sha256: String,
    pub prompt_version: String,
}

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
