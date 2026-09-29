use crate::{oauth, store::Store};
use anyhow::{ensure, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const TOKEN_HASH_META: &str = "api_token_sha256_v1";
pub const LEGACY_TOKEN_META: &str = "api_token";
const DOMAIN: &[u8] = b"rejection-rejector/api-token/v1\0";

#[derive(Clone)]
pub struct ApiTokenVerifier([u8; 32]);

pub struct ApiCredentialMaterial {
    pub verifier: ApiTokenVerifier,
    /// Present only for a newly created or explicitly rotated token. The
    /// plaintext is never persisted after the verifier has been committed.
    pub plaintext_once: Option<Zeroizing<String>>,
    pub migrated_legacy: bool,
}

impl ApiTokenVerifier {
    pub fn from_token(token: &str) -> Result<Self> {
        ensure!(token.len() >= 40, "API token lacks required entropy");
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(token.as_bytes());
        Ok(Self(hasher.finalize().into()))
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        ensure!(
            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Stored API token verifier is invalid"
        );
        let mut digest = [0u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let part = std::str::from_utf8(chunk)?;
            digest[index] =
                u8::from_str_radix(part, 16).context("Stored API token verifier is invalid")?;
        }
        Ok(Self(digest))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub fn verify_token(&self, token: &str) -> bool {
        let Ok(candidate) = Self::from_token(token) else {
            return false;
        };
        self.0.ct_eq(&candidate.0).unwrap_u8() == 1
    }

    pub fn authorize_header(&self, value: Option<&str>) -> bool {
        let Some(token) = value.and_then(|header| header.strip_prefix("Bearer ")) else {
            return false;
        };
        self.verify_token(token)
    }
}

fn persist_verifier(
    store: &mut Store,
    verifier: &ApiTokenVerifier,
    audit_kind: &str,
    audit_detail: &str,
) -> Result<()> {
    store.change_meta(
        &[(TOKEN_HASH_META, json!(verifier.to_hex()))],
        &[LEGACY_TOKEN_META],
        audit_kind,
        audit_detail,
    )
}

/// Load the persisted verifier or migrate/create it without changing an
/// existing integration credential.
///
/// Legacy plaintext tokens are hashed in-place and then deleted atomically, so
/// existing clients continue to authenticate but the token can no longer be
/// recovered from application storage.
pub fn load_or_create(store: &mut Store) -> Result<ApiCredentialMaterial> {
    if let Some(encoded) = store.meta::<String>(TOKEN_HASH_META)? {
        return Ok(ApiCredentialMaterial {
            verifier: ApiTokenVerifier::from_hex(&encoded)?,
            plaintext_once: None,
            migrated_legacy: false,
        });
    }

    if let Some(legacy) = store.meta::<String>(LEGACY_TOKEN_META)? {
        let legacy = Zeroizing::new(legacy);
        let verifier = ApiTokenVerifier::from_token(legacy.as_str())?;
        persist_verifier(
            store,
            &verifier,
            "security.api_token_migrated",
            "Legacy recoverable integration API token replaced by a one-way verifier",
        )?;
        return Ok(ApiCredentialMaterial {
            verifier,
            plaintext_once: None,
            migrated_legacy: true,
        });
    }

    let token = Zeroizing::new(oauth::secret());
    let verifier = ApiTokenVerifier::from_token(token.as_str())?;
    persist_verifier(
        store,
        &verifier,
        "security.api_token_created",
        "Integration API token verifier created; plaintext credential is shown once only",
    )?;
    Ok(ApiCredentialMaterial {
        verifier,
        plaintext_once: Some(token),
        migrated_legacy: false,
    })
}

/// Rotate the integration credential. Only the verifier is persisted. The
/// returned plaintext must be displayed/transferred once and then discarded.
pub fn rotate(store: &mut Store) -> Result<ApiCredentialMaterial> {
    let token = Zeroizing::new(oauth::secret());
    let verifier = ApiTokenVerifier::from_token(token.as_str())?;
    persist_verifier(
        store,
        &verifier,
        "security.api_token_rotated",
        "Integration API token rotated; only the one-way verifier is persisted",
    )?;
    Ok(ApiCredentialMaterial {
        verifier,
        plaintext_once: Some(token),
        migrated_legacy: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Vault;

    #[test]
    fn verifier_is_domain_separated_and_constant_time_comparable() {
        let token = "A".repeat(48);
        let verifier = ApiTokenVerifier::from_token(&token).unwrap();
        assert_eq!(verifier.to_hex().len(), 64);
        assert!(verifier.verify_token(&token));
        assert!(!verifier.verify_token(&"B".repeat(48)));
        assert!(verifier.authorize_header(Some(&format!("Bearer {token}"))));
        assert!(!verifier.authorize_header(Some(&format!("Bearer {token} "))));
        assert!(!verifier.authorize_header(Some(&token)));
        assert!(!verifier.authorize_header(None));
        assert_eq!(
            ApiTokenVerifier::from_hex(&verifier.to_hex())
                .unwrap()
                .to_hex(),
            verifier.to_hex()
        );
    }

    #[test]
    fn legacy_plaintext_is_removed_without_invalidating_credential() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open(&root.path().join("state.sqlite3"), Vault::random()).unwrap();
        let token = "L".repeat(48);
        store.set_meta(LEGACY_TOKEN_META, &token).unwrap();

        let material = load_or_create(&mut store).unwrap();
        assert!(material.migrated_legacy);
        assert!(material.plaintext_once.is_none());
        assert!(material.verifier.verify_token(&token));
        assert!(store.meta::<String>(LEGACY_TOKEN_META).unwrap().is_none());
        assert!(store.meta::<String>(TOKEN_HASH_META).unwrap().is_some());
    }

    #[test]
    fn newly_created_and_rotated_tokens_are_never_persisted_reversibly() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open(&root.path().join("state.sqlite3"), Vault::random()).unwrap();

        let first = load_or_create(&mut store).unwrap();
        let first_plaintext = first.plaintext_once.unwrap();
        assert!(first.verifier.verify_token(first_plaintext.as_str()));
        assert!(store.meta::<String>(LEGACY_TOKEN_META).unwrap().is_none());

        let second = rotate(&mut store).unwrap();
        let second_plaintext = second.plaintext_once.unwrap();
        assert!(second.verifier.verify_token(second_plaintext.as_str()));
        assert!(!second.verifier.verify_token(first_plaintext.as_str()));
        assert!(store.meta::<String>(LEGACY_TOKEN_META).unwrap().is_none());
    }
}
