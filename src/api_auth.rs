use crate::{oauth, store::Store};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Authority a bearer credential carries. Read credentials serve machine
/// integrations and can only query; write credentials serve the embedded web
/// console and may additionally drive the state-changing command routes.
///
/// Inputs: none (plain enum). Output: the scope tag carried by every derived
/// verifier so a credential can never authorize beyond its scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenScope {
    /// Query-only authority for machine integrations.
    Read,
    /// Full authority for the operator's embedded web console.
    Write,
}

/// Metadata key under which the hashed read-scope API-token verifier is
/// committed.
///
/// Inputs: none (constant). Output: `&str` — the store metadata key.
pub const TOKEN_HASH_META: &str = "api_token_sha256_v1";
/// Metadata key under which the hashed write-scope API-token verifier is
/// committed.
///
/// Inputs: none (constant). Output: `&str` — the store metadata key.
pub const TOKEN_WRITE_HASH_META: &str = "api_write_token_sha256_v1";
/// Metadata key of the legacy plaintext token format.
///
/// Inputs: none (constant). Output: `&str` — read only to migrate pre-hash
/// tokens.
pub const LEGACY_TOKEN_META: &str = "api_token";
/// Domain-separation prefix of the read-scope verifier. This domain is kept
/// from the original single-credential scheme so existing integration
/// credentials keep authenticating after the scope split; they lose only the
/// write authority they were never documented to hold.
///
/// Inputs: none (constant). Output: the domain bytes prefixed to the token.
const READ_DOMAIN: &[u8] = b"rejection-rejector/api-token/v1\0";
/// Domain-separation prefix of the write-scope verifier. Distinct from the
/// read domain so no credential can verify across scopes.
///
/// Inputs: none (constant). Output: the domain bytes prefixed to the token.
const WRITE_DOMAIN: &[u8] = b"rejection-rejector/api-write-token/v1\0";

impl TokenScope {
    /// Domain-separation bytes for this scope.
    ///
    /// Inputs: none beyond the scope. Output: `&'static [u8]` — the digest
    /// domain prefix unique to this scope.
    fn domain(self) -> &'static [u8] {
        match self {
            TokenScope::Read => READ_DOMAIN,
            TokenScope::Write => WRITE_DOMAIN,
        }
    }

    /// Persisted metadata key holding this scope's verifier.
    ///
    /// Inputs: none beyond the scope. Output: `&'static str` — the store
    /// metadata key.
    pub fn storage_key(self) -> &'static str {
        match self {
            TokenScope::Read => TOKEN_HASH_META,
            TokenScope::Write => TOKEN_WRITE_HASH_META,
        }
    }

    /// Machine-readable scope name used in CLI output and audit details.
    ///
    /// Inputs: none beyond the scope. Output: `&'static str` — `read` or
    /// `write`.
    pub fn name(self) -> &'static str {
        match self {
            TokenScope::Read => "read",
            TokenScope::Write => "write",
        }
    }
}

/// Fixed-size verifier compared in place of one plaintext API token, tagged
/// with the scope it authorizes.
///
/// Inputs: none (plain struct). Output: the 32-byte domain-separated digest
/// for one token plus its scope.
#[derive(Clone)]
pub struct ApiTokenVerifier {
    digest: [u8; 32],
    scope: TokenScope,
}

/// Token verifier plus the one-time plaintext produced by creation or
/// rotation.
///
/// Inputs: none (plain struct). Output: the [`ApiTokenVerifier`], the
/// one-time plaintext (never persisted) and whether a legacy token migrated.
pub struct ApiCredentialMaterial {
    /// Verifier for API tokens issued from this material.
    pub verifier: ApiTokenVerifier,
    /// Present only for a newly created or explicitly rotated token. The
    /// plaintext is never persisted after the verifier has been committed.
    pub plaintext_once: Option<Zeroizing<String>>,
    /// Whether the stored token hash was migrated from the legacy scheme.
    pub migrated_legacy: bool,
}

/// Both scope verifiers the loopback API admits, with any one-time plaintexts
/// that a caller must display exactly once.
///
/// Inputs: none (plain struct). Output: the read and write verifiers plus the
/// one-time plaintexts minted during load.
pub struct ApiTokens {
    /// Query-only credential for machine integrations.
    pub read: ApiTokenVerifier,
    /// Write-capable credential for the embedded web console.
    pub write: ApiTokenVerifier,
    /// One-time read-token plaintext, present only when this load minted or
    /// migrated one.
    pub plaintext_read_once: Option<Zeroizing<String>>,
    /// One-time write-token plaintext, present only when this load minted the
    /// write credential.
    pub plaintext_write_once: Option<Zeroizing<String>>,
    /// Whether the read credential was migrated from the legacy scheme.
    pub migrated_legacy: bool,
}

impl ApiTokenVerifier {
    /// Derive the verifier for one plaintext API token in one scope.
    ///
    /// Inputs: `scope` — authority the token will carry; `token` — candidate
    /// plaintext token (at least 40 characters). Output: `Result<Self>` — the
    /// scope-separated SHA-256 verifier; errors when the token lacks required
    /// entropy.
    pub fn from_token(scope: TokenScope, token: &str) -> Result<Self> {
        ensure!(token.len() >= 40, "API token lacks required entropy");
        let mut hasher = Sha256::new();
        hasher.update(scope.domain());
        hasher.update(token.as_bytes());
        Ok(Self {
            digest: hasher.finalize().into(),
            scope,
        })
    }

    /// Parse a persisted verifier from its stored hex encoding.
    ///
    /// Inputs: `scope` — authority the verifier represents; `value` — exactly
    /// 64 hex characters. Output: `Result<Self>`; errors on any malformed
    /// encoding.
    pub fn from_hex(scope: TokenScope, value: &str) -> Result<Self> {
        ensure!(
            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Stored API token verifier is invalid"
        );
        let mut digest = [0u8; 32];
        for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let part = std::str::from_utf8(chunk)?;
            digest[index] =
                u8::from_str_radix(part, 16).context("Stored API token verifier is invalid")?;
        }
        Ok(Self { digest, scope })
    }

    /// Serialize the verifier for persistence.
    ///
    /// Inputs: none beyond the verifier. Output: `String` of exactly 64
    /// lowercase hex characters.
    pub fn to_hex(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The scope this verifier authorizes.
    ///
    /// Inputs: none beyond the verifier. Output: [`TokenScope`] — the scope
    /// the verifier was derived for.
    pub fn scope(&self) -> TokenScope {
        self.scope
    }

    /// Check one plaintext token against this verifier in constant time.
    ///
    /// Inputs: `token` — candidate plaintext token. Output: `true` only when
    /// the scope-separated derived verifier matches.
    pub fn verify_token(&self, token: &str) -> bool {
        let Ok(candidate) = Self::from_token(self.scope, token) else {
            return false;
        };
        self.digest.ct_eq(&candidate.digest).unwrap_u8() == 1
    }

    /// Authorize one `Authorization` header value against this verifier.
    ///
    /// Inputs: `value` — raw header value, if present. Output: `true` only for
    /// a well-formed `Bearer` token that verifies.
    pub fn authorize_header(&self, value: Option<&str>) -> bool {
        let Some(token) = value.and_then(|header| header.strip_prefix("Bearer ")) else {
            return false;
        };
        self.verify_token(token)
    }
}

impl ApiTokens {
    /// Whether a header holds either scope's plaintext credential.
    ///
    /// Inputs: `value` — raw `Authorization` header value, if present.
    /// Output: `true` for a well-formed `Bearer` token that verifies under the
    /// read or the write verifier.
    pub fn authorize_read(&self, value: Option<&str>) -> bool {
        self.read.authorize_header(value) || self.write.authorize_header(value)
    }

    /// Whether a header holds the write-scope credential.
    ///
    /// Inputs: `value` — raw `Authorization` header value, if present.
    /// Output: `true` only for a well-formed `Bearer` token that verifies
    /// under the write verifier — the read credential never authorizes a
    /// write.
    pub fn authorize_write(&self, value: Option<&str>) -> bool {
        self.write.authorize_header(value)
    }
}

/// Persist a one-way token verifier for one scope and, when migrating the
/// read scope, drop the legacy plaintext slot.
///
/// Inputs: `store` — application meta store; `scope` — credential scope whose
/// `storage_key()` receives the verifier; `verifier` — reduced token
/// verifier; `audit_kind` / `audit_detail` — audit-log event identity;
/// `retire_legacy` — whether the legacy plaintext key must be atomically
/// removed. Output: `Ok(())` once the verifier is stored; any storage failure
/// propagates unchanged.
///
/// The call result is bound by callers before `?` so LLVM line attribution
/// lands on executed lines (the old multi-line `...)?;` form attributed the
/// never-taken early-return block to its closing line, showing as uncovered).
fn persist_verifier(
    store: &mut Store,
    scope: TokenScope,
    verifier: &ApiTokenVerifier,
    audit_kind: &str,
    audit_detail: &str,
    retire_legacy: bool,
) -> Result<()> {
    let retired: &[&str] = if retire_legacy {
        &[LEGACY_TOKEN_META]
    } else {
        &[]
    };
    store.change_meta(
        &[(scope.storage_key(), json!(verifier.to_hex()))],
        retired,
        audit_kind,
        audit_detail,
    )
}

/// Load or create both credential scopes without changing an existing
/// integration credential.
///
/// The read scope keeps the original verifier domain and storage key, so an
/// existing integration token keeps authenticating with its documented
/// query-only authority. The write scope is minted on first load; only its
/// verifier is persisted and the plaintext is surfaced exactly once. Legacy
/// plaintext tokens are hashed in-place and then deleted atomically.
///
/// Inputs: `store` — persistent metadata store to read or migrate. Output:
/// `Result<ApiTokens>` — both scope verifiers plus one-time plaintexts for
/// credentials minted or migrated during this load.
pub fn load_or_create(store: &mut Store) -> Result<ApiTokens> {
    let (read, plaintext_read_once, migrated_legacy) = load_read_scope(store)?;
    let (write, plaintext_write_once) = load_write_scope(store)?;
    Ok(ApiTokens {
        read,
        write,
        plaintext_read_once,
        plaintext_write_once,
        migrated_legacy,
    })
}

/// Load, migrate, or mint the read-scope credential.
///
/// Inputs: `store` — persistent metadata store. Output:
/// `Result<(ApiTokenVerifier, Option<Zeroizing<String>>, bool)>` — the read
/// verifier, one-time plaintext when this call minted or migrated a
/// credential, and whether a legacy token was migrated.
fn load_read_scope(
    store: &mut Store,
) -> Result<(ApiTokenVerifier, Option<Zeroizing<String>>, bool)> {
    if let Some(encoded) = store.meta::<String>(TOKEN_HASH_META)? {
        return Ok((
            ApiTokenVerifier::from_hex(TokenScope::Read, &encoded)?,
            None,
            false,
        ));
    }

    if let Some(legacy) = store.meta::<String>(LEGACY_TOKEN_META)? {
        let legacy = Zeroizing::new(legacy);
        let verifier = ApiTokenVerifier::from_token(TokenScope::Read, legacy.as_str())?;
        let persisted = persist_verifier(
            store,
            TokenScope::Read,
            &verifier,
            "security.api_token_migrated",
            "Legacy recoverable integration API token replaced by a one-way verifier",
            true,
        );
        persisted?;
        return Ok((verifier, None, true));
    }

    let token = Zeroizing::new(oauth::secret());
    let verifier = ApiTokenVerifier::from_token(TokenScope::Read, token.as_str())?;
    let persisted = persist_verifier(
        store,
        TokenScope::Read,
        &verifier,
        "security.api_token_created",
        "Read-scope integration API token verifier created; plaintext credential is shown once only",
        true,
    );
    persisted?;
    Ok((verifier, Some(token), false))
}

/// Load or mint the write-scope credential.
///
/// Inputs: `store` — persistent metadata store. Output:
/// `Result<(ApiTokenVerifier, Option<Zeroizing<String>>)>` — the write
/// verifier and its one-time plaintext when this call minted it.
fn load_write_scope(store: &mut Store) -> Result<(ApiTokenVerifier, Option<Zeroizing<String>>)> {
    if let Some(encoded) = store.meta::<String>(TOKEN_WRITE_HASH_META)? {
        return Ok((
            ApiTokenVerifier::from_hex(TokenScope::Write, &encoded)?,
            None,
        ));
    }

    let token = Zeroizing::new(oauth::secret());
    let verifier = ApiTokenVerifier::from_token(TokenScope::Write, token.as_str())?;
    let persisted = persist_verifier(
        store,
        TokenScope::Write,
        &verifier,
        "security.api_write_token_created",
        "Write-scope console API token verifier created; plaintext credential is shown once only",
        false,
    );
    persisted?;
    Ok((verifier, Some(token)))
}

/// Rotate one scope's credential. Only the verifier is persisted. The
/// returned plaintext must be displayed/transferred once and then discarded.
///
/// Inputs: `store` — persistent metadata store receiving the new verifier;
/// `scope` — credential scope to rotate. Output:
/// `Result<ApiCredentialMaterial>` whose `plaintext_once` must be displayed
/// once and then discarded.
pub fn rotate(store: &mut Store, scope: TokenScope) -> Result<ApiCredentialMaterial> {
    let token = Zeroizing::new(oauth::secret());
    let verifier = ApiTokenVerifier::from_token(scope, token.as_str())?;
    let audit_detail = match scope {
        TokenScope::Read => {
            "Read-scope integration API token rotated; only the one-way verifier is persisted"
        }
        TokenScope::Write => {
            "Write-scope console API token rotated; only the one-way verifier is persisted"
        }
    };
    let persisted = persist_verifier(
        store,
        scope,
        &verifier,
        "security.api_token_rotated",
        audit_detail,
        true,
    );
    persisted?;
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
        let verifier = ApiTokenVerifier::from_token(TokenScope::Read, &token).unwrap();
        assert_eq!(verifier.to_hex().len(), 64);
        assert!(verifier.verify_token(&token));
        assert!(!verifier.verify_token(&"B".repeat(48)));
        assert!(verifier.authorize_header(Some(&format!("Bearer {token}"))));
        assert!(!verifier.authorize_header(Some(&format!("Bearer {token} "))));
        assert!(!verifier.authorize_header(Some(&token)));
        assert!(!verifier.authorize_header(None));
        assert_eq!(
            ApiTokenVerifier::from_hex(TokenScope::Read, &verifier.to_hex())
                .unwrap()
                .to_hex(),
            verifier.to_hex()
        );
    }

    // why: read and write authority must be cryptographically distinct — a
    // credential held under one scope's verifier must never authorize the
    // other scope, in either direction, or the whole separation collapses.
    #[test]
    fn scopes_are_cryptographically_distinct() {
        let read_plain = "R".repeat(48);
        let write_plain = "W".repeat(48);
        let read = ApiTokenVerifier::from_token(TokenScope::Read, &read_plain).unwrap();
        let write = ApiTokenVerifier::from_token(TokenScope::Write, &write_plain).unwrap();
        assert_ne!(read.to_hex(), write.to_hex());
        assert_eq!(read.scope(), TokenScope::Read);
        assert_eq!(write.scope(), TokenScope::Write);

        let tokens = ApiTokens {
            read,
            write,
            plaintext_read_once: None,
            plaintext_write_once: None,
            migrated_legacy: false,
        };
        let read_header = format!("Bearer {read_plain}");
        let write_header = format!("Bearer {write_plain}");
        // The read credential reads but never writes.
        assert!(tokens.authorize_read(Some(&read_header)));
        assert!(!tokens.authorize_write(Some(&read_header)));
        // The write credential carries the superset: reads and writes.
        assert!(tokens.authorize_read(Some(&write_header)));
        assert!(tokens.authorize_write(Some(&write_header)));
        // The same plaintext under the wrong scope's verifier never verifies.
        assert!(!tokens.write.verify_token(&read_plain));
        assert!(!tokens.read.verify_token(&write_plain));
    }

    #[test]
    fn legacy_plaintext_is_removed_without_invalidating_credential() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open(&root.path().join("state.sqlite3"), Vault::random()).unwrap();
        let token = "L".repeat(48);
        store.set_meta(LEGACY_TOKEN_META, &token).unwrap();

        let tokens = load_or_create(&mut store).unwrap();
        assert!(tokens.migrated_legacy);
        assert!(tokens.plaintext_read_once.is_none());
        assert!(tokens.read.verify_token(&token));
        assert!(store.meta::<String>(LEGACY_TOKEN_META).unwrap().is_none());
        assert!(store.meta::<String>(TOKEN_HASH_META).unwrap().is_some());
        // The same load mints the write scope exactly once.
        assert!(tokens.plaintext_write_once.is_some());
        assert!(
            store
                .meta::<String>(TOKEN_WRITE_HASH_META)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn newly_created_and_rotated_tokens_are_never_persisted_reversibly() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open(&root.path().join("state.sqlite3"), Vault::random()).unwrap();

        let first = load_or_create(&mut store).unwrap();
        let first_plaintext = first.plaintext_write_once.unwrap();
        assert!(first.write.verify_token(first_plaintext.as_str()));
        assert!(store.meta::<String>(LEGACY_TOKEN_META).unwrap().is_none());

        let second = rotate(&mut store, TokenScope::Write).unwrap();
        let second_plaintext = second.plaintext_once.unwrap();
        assert!(second.verifier.verify_token(second_plaintext.as_str()));
        assert!(!second.verifier.verify_token(first_plaintext.as_str()));
        assert!(store.meta::<String>(LEGACY_TOKEN_META).unwrap().is_none());
    }

    // why: rotation paths must be independent — rotating one scope must leave
    // the other scope's credential valid, so rotating the integration token
    // can never silently disable the console (or vice versa).
    #[test]
    fn rotating_one_scope_leaves_the_other_valid() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open(&root.path().join("state.sqlite3"), Vault::random()).unwrap();
        let before = load_or_create(&mut store).unwrap();
        let write_plain = before.plaintext_write_once.clone().unwrap();
        let read_plain = before.plaintext_read_once.clone();

        let rotated_read = rotate(&mut store, TokenScope::Read).unwrap();
        let rotated_plaintext = rotated_read.plaintext_once.unwrap();
        assert!(
            rotated_read
                .verifier
                .verify_token(rotated_plaintext.as_str())
        );
        assert_eq!(rotated_read.verifier.scope(), TokenScope::Read);

        let after = load_or_create(&mut store).unwrap();
        // The write credential survived the read rotation untouched.
        assert!(after.write.verify_token(write_plain.as_str()));
        // The old read credential is gone; the rotated one is in force.
        if let Some(old_read) = read_plain {
            assert!(!after.read.verify_token(old_read.as_str()));
        }
        assert!(after.read.verify_token(rotated_plaintext.as_str()));
    }

    // why: the verifier must fail closed on tokens below the entropy floor
    // instead of hashing them anyway, so a truncated or hand-typed credential
    // can never authenticate even against a matching short stored token.
    #[test]
    fn sub_entropy_tokens_never_verify() {
        let verifier = ApiTokenVerifier::from_token(TokenScope::Read, &"A".repeat(48)).unwrap();
        assert!(ApiTokenVerifier::from_token(TokenScope::Read, "short").is_err());
        assert!(ApiTokenVerifier::from_token(TokenScope::Read, "").is_err());
        assert!(!verifier.verify_token("short"));
        assert!(!verifier.verify_token(""));
        assert!(!verifier.authorize_header(Some("Bearer short")));
    }

    // why: reloading the persisted verifiers must reproduce the same
    // credentials without ever resurrecting plaintext, so a second startup
    // neither rotates the tokens nor exposes them again.
    #[test]
    fn reloading_the_persisted_verifier_is_stable_and_never_yields_plaintext() {
        let root = tempfile::tempdir().unwrap();
        let mut store = Store::open(&root.path().join("state.sqlite3"), Vault::random()).unwrap();
        let first = load_or_create(&mut store).unwrap();
        let read_plaintext = first.plaintext_read_once.clone();
        let write_plaintext = first.plaintext_write_once.clone();
        let second = load_or_create(&mut store).unwrap();
        assert!(second.plaintext_read_once.is_none());
        assert!(second.plaintext_write_once.is_none());
        assert!(!second.migrated_legacy);
        assert_eq!(second.read.to_hex(), first.read.to_hex());
        assert_eq!(second.write.to_hex(), first.write.to_hex());
        if let Some(plaintext) = write_plaintext {
            assert!(second.write.verify_token(plaintext.as_str()));
        }
        if let Some(plaintext) = read_plaintext {
            assert!(second.read.verify_token(plaintext.as_str()));
        }
    }
}
