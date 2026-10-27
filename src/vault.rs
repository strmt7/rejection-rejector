//! Application-layer authenticated encryption. Indexes/counts/timestamps are not encrypted.
use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{fs, io::Write, path::Path, sync::Arc};
use zeroize::Zeroizing;

const RECOVERY_KEY_FORMAT: u32 = 1;
const RECOVERY_MEMORY_KIB: u32 = 64 * 1024;
const RECOVERY_TIME_COST: u32 = 3;
const RECOVERY_LANES: u32 = 1;
const RECOVERY_MIN_PASSPHRASE_BYTES: usize = 20;

/// Wrapped workspace key document written for recovery.
///
/// Inputs: none (plain struct). Output: format and application versions,
/// vault id, KDF parameters, salt and the key wrapped under the recovery key.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyEnvelope {
    /// Envelope format version.
    pub format_version: u32,
    /// Application version that wrote the envelope.
    pub app_version: String,
    /// Timestamp of envelope creation.
    pub created_at: DateTime<Utc>,
    /// Vault identifier the envelope is bound to.
    pub vault_id: String,
    /// Key-derivation function name.
    pub kdf: String,
    /// KDF memory cost in KiB.
    pub memory_kib: u32,
    /// KDF time cost.
    pub time_cost: u32,
    /// KDF parallelism lanes.
    pub lanes: u32,
    /// Base64 KDF salt.
    pub salt_b64: String,
    /// Base64 AEAD nonce.
    pub nonce_b64: String,
    /// Base64 wrapped vault key.
    pub wrapped_key_b64: String,
}

/// Generate fresh 192-bit XChaCha20-Poly1305 nonce bytes.
///
/// Inputs: none. Output: 24 nonce bytes drawn from the OS-seeded process
/// CSPRNG at the moment of encryption; never a fixed or zero-initialized
/// value, so no hard-coded cryptographic value exists in this path.
fn fresh_nonce() -> XNonce {
    let mut nonce = XNonce::default();
    nonce.copy_from_slice(&rand::random::<[u8; 24]>());
    nonce
}

/// Build the recovery-key additional authenticated data.
///
/// Inputs: `vault_id` — workspace vault identifier. Output: `Vec<u8>` — the
/// domain tag bound with the vault id.
fn recovery_aad(vault_id: &str) -> Vec<u8> {
    let mut aad = b"rejection-rejector/recovery-key/v1\0".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

/// Validate one vault identifier.
///
/// Inputs: `value` — candidate identifier. Output: `Result<()>` — `Ok` only for
/// a parseable UUID.
fn validate_vault_id(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value).is_ok(),
        "Invalid vault identifier"
    );
    Ok(())
}

/// Build the recovery-key KDF within its safety bounds.
///
/// Inputs: `memory_kib` — memory cost (19 KiB..=512 KiB); `time_cost` — time
/// cost (1..=10); `lanes` — parallelism lanes. Output:
/// `Result<Argon2<'static>>` — the configured KDF; error for out-of-range
/// parameters.
fn recovery_argon2(memory_kib: u32, time_cost: u32, lanes: u32) -> Result<Argon2<'static>> {
    ensure!(
        (19 * 1024..=512 * 1024).contains(&memory_kib),
        "Recovery KDF memory cost is outside the supported safety range"
    );
    ensure!(
        (1..=10).contains(&time_cost),
        "Recovery KDF time cost is outside the supported safety range"
    );
    ensure!(
        (1..=8).contains(&lanes),
        "Recovery KDF parallelism is outside the supported safety range"
    );
    let params = Params::new(memory_kib, time_cost, lanes, Some(32))
        .map_err(|_| anyhow::anyhow!("Invalid recovery KDF parameters"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

// Windows/macOS only: encodes the OS credential-store protocol and speaks
// `keyring::Error`; the keyring crate is a target-scoped dependency and Linux
// derives vault keys from RR_VAULT_PASSPHRASE instead.
#[cfg(any(windows, target_os = "macos"))]
/// Resolve the vault key from an OS credential-store lookup.
///
/// Inputs: `lookup` — the raw credential-store read result; `is_new` — whether
/// this vault identifier was just created (so a missing credential may be
/// minted exactly once); `mint` — persists a freshly generated key. Output:
/// the 32-byte vault key, or an error that never silently mints a replacement
/// for an existing vault. Test seam: the lookup result is injected so every
/// credential-store failure mode is exercised deterministically.
fn key_from_credential_store(
    lookup: std::result::Result<String, keyring::Error>,
    is_new: bool,
    mint: impl FnOnce(&str) -> Result<()>,
) -> Result<Zeroizing<[u8; 32]>> {
    match lookup {
        Ok(encoded) => {
            let encoded = Zeroizing::new(encoded);
            let bytes = Zeroizing::new(STANDARD.decode(encoded.as_bytes())?);
            ensure!(bytes.len() == 32, "Invalid OS credential-store key");
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(keyring::Error::NoEntry) if is_new => {
            let mut key = Zeroizing::new([0u8; 32]);
            key.as_mut().copy_from_slice(&rand::random::<[u8; 32]>());
            let encoded = Zeroizing::new(STANDARD.encode(key.as_ref()));
            mint(encoded.as_str())?;
            Ok(key)
        }
        Err(keyring::Error::NoEntry) => Err(anyhow::anyhow!(
            "Existing vault identifier has no OS credential. Refusing to generate a replacement key; import verified recovery material or restore the original credential"
        )),
        Err(error) => Err(anyhow::anyhow!(
            "OS credential store unavailable or original key missing: {error}"
        )),
    }
}

#[cfg(any(windows, target_os = "macos"))]
/// Install a recovered vault key into the OS credential store exactly once.
///
/// Inputs: `lookup` — the raw credential-store read result; `key` — the
/// recovered 32-byte vault key; `store` — persists the encoded key. Output:
/// `Ok(())` after one install; an existing credential is never overwritten and
/// credential-store failures surface as errors. Test seam: the lookup result
/// is injected so the error arms are exercised deterministically.
fn install_key_into_credential_store(
    lookup: std::result::Result<String, keyring::Error>,
    key: &[u8],
    store: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    match lookup {
        Ok(_) => anyhow::bail!(
            "An OS credential already exists for this vault; refusing to overwrite it"
        ),
        Err(keyring::Error::NoEntry) => {}
        Err(error) => {
            return Err(anyhow::anyhow!(
                "Cannot inspect the OS credential store: {error}"
            ));
        }
    }
    let encoded = Zeroizing::new(STANDARD.encode(key));
    store(encoded.as_str())
}

/// Read the workspace vault identifier.
///
/// Inputs: `dir` — workspace directory. Output: `Result<String>` — the
/// validated vault id.
pub fn vault_id(dir: &Path) -> Result<String> {
    let id = fs::read_to_string(dir.join("vault-id")).context("Vault identifier is missing")?;
    let id = id.trim().to_owned();
    validate_vault_id(&id)?;
    Ok(id)
}

#[cfg(not(any(windows, target_os = "macos")))]
/// Read the headless vault input for hosts without an OS credential store.
///
/// Why: Linux has no credential store, so [`Vault::open`] derives the workspace
/// key from `RR_VAULT_PASSPHRASE` (docs/SETUP.md) on every run and fails closed
/// when it is absent. In-process tests install the same documented input through
/// the one-shot seam in `test_support` instead of mutating the process
/// environment mid-run, which would race concurrent environment readers in
/// parallel tests. Inputs: none. Output: the passphrase, or the fail-closed
/// error naming the variable when neither the seam nor the environment
/// supplies one.
fn linux_vault_passphrase() -> Result<Zeroizing<String>> {
    #[cfg(test)]
    if let Some(pass) = test_support::HEADLESS_PASSPHRASE.get() {
        return Ok(Zeroizing::new(pass.clone()));
    }
    const VAULT_PASSPHRASE_ENV: &str = "RR_VAULT_PASSPHRASE";
    Ok(Zeroizing::new(
        std::env::var(VAULT_PASSPHRASE_ENV).context(format!(
            "On Linux, set {VAULT_PASSPHRASE_ENV} to a strong passphrase (20+ characters). \
         Windows uses Credential Manager automatically"
        ))?,
    ))
}

/// Authenticated-encryption vault for one workspace.
///
/// Inputs: none (plain struct). Output: the sealing and opening surface for
/// values stored under the workspace key.
#[derive(Clone)]
pub struct Vault {
    key: Arc<Zeroizing<[u8; 32]>>,
}
impl Vault {
    /// Wrap a raw key as a vault.
    ///
    /// Inputs: `key` — 32-byte master key (zeroized on drop). Output: `Self` — the
    /// vault wrapping the key.
    fn from_zeroizing_key(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key: Arc::new(key) }
    }

    /// Generate a vault with a fresh random master key.
    ///
    /// Inputs: none. Output: [`Self`] holding an in-memory 32-byte key.
    pub fn random() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        key.as_mut().copy_from_slice(&rand::random::<[u8; 32]>());
        Self::from_zeroizing_key(key)
    }
    /// Open (or create) the workspace vault.
    ///
    /// Inputs: `dir` — workspace directory. Output: `Result<Self>` — the vault
    /// whose master key is installed or recovered for this workspace.
    pub fn open(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        let id_path = dir.join("vault-id");
        let is_new = !id_path.exists();
        if is_new {
            ensure!(
                !dir.join("state.sqlite3").exists(),
                "Vault identifier is missing while a database exists. Restore the original key; refusing to create a replacement"
            );
            write_new_private(&id_path, uuid::Uuid::new_v4().to_string().as_bytes())?;
        }
        let id = fs::read_to_string(&id_path)?;
        ensure!(
            uuid::Uuid::parse_str(id.trim()).is_ok(),
            "Invalid vault identifier"
        );
        #[cfg(any(windows, target_os = "macos"))]
        {
            // Test builds are hermetic by default: derive the key from the
            // one-shot test passphrase instead of minting OS credential
            // entries. Leaked entries accumulate until the store rejects new
            // ones and flakes unrelated tests; tests asserting live OS-store
            // behavior opt in with `test_support::LiveOsCredentialStore`.
            #[cfg(test)]
            if !test_support::live_os_credential_store_active() {
                let pass = test_support::test_vault_passphrase();
                return Self::from_passphrase(pass.as_str(), id.trim());
            }
            let entry = keyring::Entry::new("rejection-rejector.v1", id.trim())?;
            let key = key_from_credential_store(entry.get_password(), is_new, |encoded| {
                entry
                    .set_password(encoded)
                    .context("Cannot save encryption key to the OS credential store; no plaintext fallback exists")
            })?;
            Ok(Self::from_zeroizing_key(key))
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            // Linux fallback is explicit and requires a user-supplied passphrase on every run.
            let pass = linux_vault_passphrase()?;
            Self::from_passphrase(pass.as_str(), id.trim())
        }
    }

    /// Derive the vault master key from a passphrase (the Linux flow and the
    /// hermetic test flow).
    ///
    /// Inputs: `pass` — 20+ character passphrase; `id` — vault identifier used
    /// as the derivation salt. Output: `Result<Self>` — the deterministically
    /// derived vault, or the fail-closed error for a short passphrase or a
    /// derivation failure.
    #[cfg(any(test, not(any(windows, target_os = "macos"))))]
    fn from_passphrase(pass: &str, id: &str) -> Result<Self> {
        ensure!(
            pass.len() >= 20,
            "Vault passphrase must be at least 20 characters"
        );
        let salt = uuid::Uuid::parse_str(id)?;
        let mut key = Zeroizing::new([0u8; 32]);
        argon2::Argon2::default()
            .hash_password_into(pass.as_bytes(), salt.as_bytes(), key.as_mut())
            .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;
        Ok(Self::from_zeroizing_key(key))
    }
    /// Wrap this vault's master key for offline disaster recovery.
    ///
    /// The passphrase is never serialized. The envelope contains only an
    /// Argon2id salt/parameters and an AEAD-wrapped 256-bit key bound to the
    /// vault UUID as associated data.
    ///
    /// Inputs: `vault_id` — workspace vault identifier to bind; `passphrase` —
    /// passphrase wrapping the key. Output: `Result<RecoveryKeyEnvelope>`; the
    /// passphrase is never serialized.
    pub fn recovery_envelope(
        &self,
        vault_id: &str,
        passphrase: &[u8],
    ) -> Result<RecoveryKeyEnvelope> {
        validate_vault_id(vault_id)?;
        ensure!(
            passphrase.len() >= RECOVERY_MIN_PASSPHRASE_BYTES,
            "Recovery passphrase must be at least {RECOVERY_MIN_PASSPHRASE_BYTES} bytes"
        );

        let salt = rand::random::<[u8; 16]>();
        let nonce = fresh_nonce();

        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        recovery_argon2(RECOVERY_MEMORY_KIB, RECOVERY_TIME_COST, RECOVERY_LANES)?
            .hash_password_into(passphrase, &salt, wrapping_key.as_mut())
            .map_err(|_| anyhow::anyhow!("Recovery key derivation failed"))?;

        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid recovery wrapping key"))?;
        let wrapped = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: self.key.as_ref().as_ref(),
                    aad: &recovery_aad(vault_id),
                },
            )
            .map_err(|_| anyhow::anyhow!("Recovery key wrapping failed"))?;

        Ok(RecoveryKeyEnvelope {
            format_version: RECOVERY_KEY_FORMAT,
            app_version: env!("CARGO_PKG_VERSION").into(),
            created_at: Utc::now(),
            vault_id: vault_id.into(),
            kdf: "argon2id-v1.3".into(),
            memory_kib: RECOVERY_MEMORY_KIB,
            time_cost: RECOVERY_TIME_COST,
            lanes: RECOVERY_LANES,
            salt_b64: STANDARD.encode(salt),
            nonce_b64: STANDARD.encode(nonce),
            wrapped_key_b64: STANDARD.encode(wrapped),
        })
    }

    /// Recover a Vault from a passphrase-wrapped recovery envelope.
    ///
    /// This does not write to the OS credential store. Callers must first
    /// authenticate the recovered key against the backup database.
    ///
    /// Inputs: `envelope` — exported recovery envelope; `passphrase` — passphrase
    /// wrapping the key. Output: `Result<Self>` — the recovered vault; nothing is
    /// written to the OS credential store.
    pub fn from_recovery_envelope(
        envelope: &RecoveryKeyEnvelope,
        passphrase: &[u8],
    ) -> Result<Self> {
        ensure!(
            envelope.format_version == RECOVERY_KEY_FORMAT,
            "Unsupported recovery-key format"
        );
        ensure!(
            envelope.kdf == "argon2id-v1.3",
            "Unsupported recovery-key KDF"
        );
        validate_vault_id(&envelope.vault_id)?;
        ensure!(
            passphrase.len() >= RECOVERY_MIN_PASSPHRASE_BYTES,
            "Recovery passphrase must be at least {RECOVERY_MIN_PASSPHRASE_BYTES} bytes"
        );

        let salt = STANDARD
            .decode(&envelope.salt_b64)
            .context("Invalid recovery salt encoding")?;
        let nonce = STANDARD
            .decode(&envelope.nonce_b64)
            .context("Invalid recovery nonce encoding")?;
        let wrapped = STANDARD
            .decode(&envelope.wrapped_key_b64)
            .context("Invalid wrapped recovery key encoding")?;
        ensure!(salt.len() == 16, "Invalid recovery salt length");
        ensure!(nonce.len() == 24, "Invalid recovery nonce length");
        ensure!(wrapped.len() == 48, "Invalid wrapped recovery key length");

        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        recovery_argon2(envelope.memory_kib, envelope.time_cost, envelope.lanes)?
            .hash_password_into(passphrase, &salt, wrapping_key.as_mut())
            .map_err(|_| anyhow::anyhow!("Recovery key derivation failed"))?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid recovery wrapping key"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::try_from(&nonce[..])
                        .map_err(|_| anyhow::anyhow!("Invalid nonce length"))?,
                    Payload {
                        msg: &wrapped,
                        aad: &recovery_aad(&envelope.vault_id),
                    },
                )
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Recovery envelope authentication failed: wrong passphrase or damaged file"
                    )
                })?,
        );
        ensure!(plain.len() == 32, "Invalid recovered vault-key length");
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&plain);
        Ok(Self::from_zeroizing_key(key))
    }

    #[cfg(any(windows, target_os = "macos"))]
    /// Install the master key into the OS credential store when missing.
    ///
    /// Inputs: `dir` — workspace directory. Output: `Ok(())`; existing credentials
    /// are never replaced.
    pub fn install_os_key_if_missing(&self, dir: &Path) -> Result<()> {
        let id = vault_id(dir)?;
        let entry = keyring::Entry::new("rejection-rejector.v1", &id)?;
        install_key_into_credential_store(
            entry.get_password(),
            self.key.as_ref().as_ref(),
            |encoded| {
                entry
                    .set_password(encoded)
                    .context("Cannot install the recovered vault key in the OS credential store")
            },
        )
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    /// Refuse portable recovery-key import on this platform.
    ///
    /// Inputs: `_dir` — workspace directory (unused). Output: always an error
    /// naming the supported platforms.
    pub fn install_os_key_if_missing(&self, _dir: &Path) -> Result<()> {
        anyhow::bail!(
            "Portable recovery-key import targets Windows Credential Manager or macOS Keychain; Linux recovery uses the original RR_VAULT_PASSPHRASE plus vault-id"
        )
    }

    /// Encrypt one value under a context binding.
    ///
    /// Inputs: `context` — domain-separation context; `value` — value to encrypt.
    /// Output: `Result<Vec<u8>>` — the sealed record.
    pub fn seal<T: Serialize>(&self, context: &str, value: &T) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(serde_json::to_vec(value)?);
        let nonce = fresh_nonce();
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref().as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?;
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: context.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
        let mut out = Vec::with_capacity(25 + encrypted.len());
        out.push(1);
        out.extend_from_slice(&nonce);
        out.extend(encrypted);
        Ok(out)
    }
    /// Decrypt one sealed record under a context binding.
    ///
    /// Inputs: `context` — domain-separation context; `bytes` — sealed record.
    /// Output: `Result<T>` — the decrypted value; records bound to another context
    /// are refused.
    pub fn open_value<T: DeserializeOwned>(&self, context: &str, bytes: &[u8]) -> Result<T> {
        ensure!(
            bytes.len() >= 41 && bytes[0] == 1,
            "Invalid encrypted record"
        );
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref().as_ref())
            .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::try_from(&bytes[1..25])
                        .map_err(|_| anyhow::anyhow!("Invalid nonce length"))?,
                    Payload {
                        msg: &bytes[25..],
                        aad: context.as_bytes(),
                    },
                )
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Cannot decrypt record: wrong key, damaged data or authentication failure"
                    )
                })?,
        );
        Ok(serde_json::from_slice(&plain)?)
    }
}
/// Create (and validate) a private data directory.
///
/// Inputs: `path` — directory to create. Output: `Ok(())`; symlinks are
/// refused.
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Data directory must not be a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
/// Create a new private file exclusively.
///
/// Inputs: `path` — file to create; `data` — bytes to write. Output: `Ok(())`;
/// existing files and unsafe paths are refused.
pub fn write_new_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
/// Exclusive process lock for one workspace directory.
///
/// Inputs: none (plain struct). Output: the held file lock, released on drop.
pub struct InstanceLock {
    _file: fs::File,
}
impl InstanceLock {
    /// Acquire the exclusive workspace instance lock.
    ///
    /// Inputs: `dir` — workspace directory. Output: `Result<Self>` — the held
    /// lock; a live existing lock is refused.
    pub fn acquire(dir: &Path) -> Result<Self> {
        private_dir(dir)?;
        let path = dir.join("instance.lock");
        if path.exists() {
            ensure!(
                !fs::symlink_metadata(&path)?.file_type().is_symlink(),
                "Lock must not be a symlink"
            );
        }
        let mut opts = fs::OpenOptions::new();
        opts.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(path)?;
        fs2::FileExt::try_lock_exclusive(&f).context("Another Rejection Rejector process is already using this data directory. Close the GUI before starting the background worker")?;
        Ok(Self { _file: f })
    }
}
#[cfg(test)]
mod tests {
    #[cfg(any(windows, target_os = "macos"))]
    use super::test_support::lock_credential_store;
    use super::*;
    #[test]
    fn encrypts_authenticates_and_binds_context() {
        let v = Vault::random();
        let a = v.seal("job:1", &"private email").unwrap();
        let b = v.seal("job:1", &"private email").unwrap();
        assert_ne!(a, b);
        assert!(!a.windows(13).any(|w| w == b"private email"));
        assert_eq!(
            v.open_value::<String>("job:1", &a).unwrap(),
            "private email"
        );
        assert!(v.open_value::<String>("job:2", &a).is_err());
        assert!(Vault::random().open_value::<String>("job:1", &a).is_err());
        let mut damaged = a;
        damaged[30] ^= 1;
        assert!(v.open_value::<String>("job:1", &damaged).is_err());
    }
    #[test]
    fn recovery_envelope_roundtrips_and_rejects_tampering() {
        let vault = Vault::random();
        let id = uuid::Uuid::new_v4().to_string();
        let passphrase = b"correct horse battery staple";
        let envelope = vault.recovery_envelope(&id, passphrase).unwrap();
        assert_eq!(envelope.format_version, 1);
        assert_eq!(envelope.vault_id, id);
        assert!(!envelope.wrapped_key_b64.is_empty());

        let recovered = Vault::from_recovery_envelope(&envelope, passphrase).unwrap();
        let sealed = vault.seal("test", &"secret").unwrap();
        assert_eq!(
            recovered.open_value::<String>("test", &sealed).unwrap(),
            "secret"
        );
        assert!(
            Vault::from_recovery_envelope(&envelope, b"this passphrase is definitely wrong")
                .is_err()
        );

        let mut damaged = envelope.clone();
        damaged.vault_id = uuid::Uuid::new_v4().to_string();
        assert!(Vault::from_recovery_envelope(&damaged, passphrase).is_err());

        let mut expensive = envelope;
        expensive.memory_kib = 1024 * 1024;
        assert!(Vault::from_recovery_envelope(&expensive, passphrase).is_err());
    }

    // Windows/macOS only: this test drives the real OS credential store,
    // which is exactly what it asserts; the keyring crate is a target-scoped
    // dependency and Linux has no credential store to test against.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn existing_vault_id_without_credential_never_mints_a_replacement_key() {
        // Serialize OS credential-store access (see `test_support`).
        let _lock = lock_credential_store();
        let _live = test_support::LiveOsCredentialStore::acquire();
        let root = tempfile::tempdir().unwrap();
        private_dir(root.path()).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&root.path().join("vault-id"), id.as_bytes()).unwrap();

        let error = Vault::open(root.path())
            .err()
            .expect("existing vault ID without credential must fail closed");
        assert!(
            error
                .to_string()
                .contains("Refusing to generate a replacement key")
        );
        assert!(!root.path().join("state.sqlite3").exists());
    }

    #[test]
    fn only_one_instance() {
        let d = tempfile::tempdir().unwrap();
        let _a = InstanceLock::acquire(d.path()).unwrap();
        assert!(InstanceLock::acquire(d.path()).is_err());
    }

    /// Why: an encrypted database without its vault identifier must fail closed
    /// before any key material is created; silently minting a new key would make
    /// the existing ciphertext permanently undecryptable and hide the loss.
    /// Inputs: directory holding only `state.sqlite3`. Output: error mentioning
    /// key restoration, no `vault-id` written.
    #[test]
    fn vault_open_refuses_database_without_vault_identifier() {
        let root = tempfile::tempdir().unwrap();
        private_dir(root.path()).unwrap();
        fs::write(root.path().join("state.sqlite3"), b"encrypted bytes").unwrap();
        let error = Vault::open(root.path())
            .err()
            .expect("database without vault identifier must fail closed");
        assert!(
            error.to_string().contains("Restore the original key"),
            "unexpected error: {error}"
        );
        assert!(!root.path().join("vault-id").exists());
    }

    /// Why: the OS-credential path must mint exactly one key on first open and
    /// reuse that same key on every later open; a second mint would orphan all
    /// previously sealed records. Exercises the mint arm, the read arm and the
    /// seal/open round trip across two independently opened vaults.
    /// Inputs: fresh directory. Output: both vault handles decrypt each other's
    /// sealed records; the credential is removed on teardown.
    // Windows/macOS only: this test drives the real OS credential store,
    // which is exactly what it asserts; the keyring crate is a target-scoped
    // dependency and Linux has no credential store to test against.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn vault_open_mints_and_reuses_the_os_credential_key() {
        // Serialize OS credential-store access (see `test_support`).
        let _lock = lock_credential_store();
        let _live = test_support::LiveOsCredentialStore::acquire();
        let root = tempfile::tempdir().unwrap();
        private_dir(root.path()).unwrap();
        let minted = Vault::open(root.path()).unwrap();
        let _cleanup = test_support::OsCredentialCleanup::for_workspace(root.path());
        let reopened = Vault::open(root.path()).unwrap();
        let sealed = minted.seal("job:1", &"payload").unwrap();
        assert_eq!(
            reopened.open_value::<String>("job:1", &sealed).unwrap(),
            "payload"
        );
        let sealed_back = reopened.seal("job:2", &"reply").unwrap();
        assert_eq!(
            minted.open_value::<String>("job:2", &sealed_back).unwrap(),
            "reply"
        );
    }

    /// Why: recovery-key import must install the recovered key exactly once and
    /// refuse to overwrite an existing OS credential, otherwise a stale or
    /// hostile credential could be silently replaced. Also proves a missing
    /// vault identifier is rejected before any credential-store access.
    /// Inputs: directory with a vault identifier and a recovered vault.
    /// Output: first install succeeds, second install errors, an opened vault
    /// reads the installed key, and a directory without identifier errors.
    // Windows/macOS only: this test drives the real OS credential store,
    // which is exactly what it asserts; the keyring crate is a target-scoped
    // dependency and Linux has no credential store to test against.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn install_os_key_if_missing_installs_once_and_refuses_overwrite() {
        // Serialize OS credential-store access (see `test_support`).
        let _lock = lock_credential_store();
        let _live = test_support::LiveOsCredentialStore::acquire();
        let root = tempfile::tempdir().unwrap();
        private_dir(root.path()).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        write_new_private(&root.path().join("vault-id"), id.as_bytes()).unwrap();
        let _cleanup = test_support::OsCredentialCleanup::for_workspace(root.path());
        let recovered = Vault::random();
        recovered.install_os_key_if_missing(root.path()).unwrap();
        let overwrite = recovered
            .install_os_key_if_missing(root.path())
            .expect_err("existing credential must not be overwritten");
        assert!(
            overwrite.to_string().contains("refusing to overwrite"),
            "unexpected error: {overwrite}"
        );
        let opened = Vault::open(root.path()).unwrap();
        let sealed = recovered.seal("job:1", &"state").unwrap();
        assert_eq!(
            opened.open_value::<String>("job:1", &sealed).unwrap(),
            "state"
        );

        let unidentified = root.path().join("no-identity");
        private_dir(&unidentified).unwrap();
        assert!(recovered.install_os_key_if_missing(&unidentified).is_err());
    }

    /// Extract the error text from a fail-closed result whose success type does
    /// not implement `Debug` (e.g. `Vault`, `Argon2`, `InstanceLock`); a
    /// successful call fails the test instead.
    fn err<T>(result: Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected a fail-closed error"),
            Err(error) => error.to_string(),
        }
    }

    /// Why: passphrase derivation is the Linux and hermetic-test key source; it
    /// must be deterministic for one (passphrase, vault id) pair and reject a
    /// short passphrase or unparsable vault id before deriving anything, so a
    /// weak input can never silently produce a key.
    #[test]
    fn passphrase_derivation_is_deterministic_and_fail_closed() {
        assert_eq!(
            err(Vault::from_passphrase(
                "short",
                &uuid::Uuid::new_v4().to_string()
            )),
            "Vault passphrase must be at least 20 characters"
        );
        assert!(
            Vault::from_passphrase(&"p".repeat(20), "not-a-uuid").is_err(),
            "an unparsable vault id cannot serve as a derivation salt"
        );

        let id = uuid::Uuid::new_v4().to_string();
        let first = Vault::from_passphrase(&"p".repeat(20), &id).unwrap();
        let second = Vault::from_passphrase(&"p".repeat(20), &id).unwrap();
        let sealed = first.seal("ctx", &"value").unwrap();
        assert_eq!(
            second.open_value::<String>("ctx", &sealed).unwrap(),
            "value",
            "the same passphrase and vault id must derive the same key"
        );
        let other =
            Vault::from_passphrase(&"p".repeat(20), &uuid::Uuid::new_v4().to_string()).unwrap();
        assert!(
            other.open_value::<String>("ctx", &sealed).is_err(),
            "a different vault id must derive a different key"
        );
    }

    /// Why: the recovery envelope is only useful while it binds the exact vault
    /// id and a strong passphrase; each invalid input must be refused up front
    /// with its own reason so operators can tell a typo from a damaged file.
    #[test]
    fn recovery_envelope_input_validation_names_each_defect() {
        let vault = Vault::random();
        let id = uuid::Uuid::new_v4().to_string();
        let error = vault
            .recovery_envelope("not-a-uuid", b"a strong enough passphrase")
            .unwrap_err();
        assert_eq!(error.to_string(), "Invalid vault identifier");
        let error = vault
            .recovery_envelope(&id, b"1234567890123456789")
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Recovery passphrase must be at least 20 bytes"
        );
    }

    /// Why: a recovery envelope is an offline trust artifact; every malformed
    /// field (format, KDF, ids, encodings, lengths, KDF bounds) must fail
    /// closed with its own reason before any key material is unwrapped, and a
    /// wrong passphrase must surface as an authentication failure, never as a
    /// different error that could mask tampering.
    #[test]
    fn recovery_envelope_decoding_rejects_every_malformed_field() {
        let vault = Vault::random();
        let id = uuid::Uuid::new_v4().to_string();
        let passphrase = b"correct horse battery staple";
        let envelope = vault.recovery_envelope(&id, passphrase).unwrap();

        let mut altered = envelope.clone();
        altered.format_version = 2;
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Unsupported recovery-key format"
        );

        let mut altered = envelope.clone();
        altered.kdf = "argon2i".into();
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Unsupported recovery-key KDF"
        );

        let mut altered = envelope.clone();
        altered.vault_id = "not-a-uuid".into();
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Invalid vault identifier"
        );

        assert_eq!(
            err(Vault::from_recovery_envelope(
                &envelope,
                b"1234567890123456789"
            )),
            "Recovery passphrase must be at least 20 bytes"
        );

        let mut altered = envelope.clone();
        altered.salt_b64 = "!!!".into();
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Invalid recovery salt encoding"
        );

        let mut altered = envelope.clone();
        altered.nonce_b64 = "!!!".into();
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Invalid recovery nonce encoding"
        );

        let mut altered = envelope.clone();
        altered.wrapped_key_b64 = "!!!".into();
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Invalid wrapped recovery key encoding"
        );

        let mut altered = envelope.clone();
        altered.salt_b64 = STANDARD.encode([0u8; 8]);
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Invalid recovery salt length"
        );

        let mut altered = envelope.clone();
        altered.nonce_b64 = STANDARD.encode([0u8; 23]);
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Invalid recovery nonce length"
        );

        let mut altered = envelope.clone();
        altered.wrapped_key_b64 = STANDARD.encode([0u8; 47]);
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Invalid wrapped recovery key length"
        );

        let mut altered = envelope.clone();
        altered.memory_kib = 1024 * 1024;
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Recovery KDF memory cost is outside the supported safety range"
        );

        let mut altered = envelope.clone();
        altered.time_cost = 11;
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Recovery KDF time cost is outside the supported safety range"
        );

        let mut altered = envelope.clone();
        altered.lanes = 9;
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            "Recovery KDF parallelism is outside the supported safety range"
        );

        const AUTH: &str =
            "Recovery envelope authentication failed: wrong passphrase or damaged file";
        assert_eq!(
            err(Vault::from_recovery_envelope(
                &envelope,
                b"this passphrase is definitely wrong"
            )),
            AUTH
        );

        let mut altered = envelope.clone();
        let mut wrapped = STANDARD.decode(&altered.wrapped_key_b64).unwrap();
        wrapped[0] ^= 1;
        altered.wrapped_key_b64 = STANDARD.encode(wrapped);
        assert_eq!(
            err(Vault::from_recovery_envelope(&altered, passphrase)),
            AUTH,
            "tampered ciphertext must surface as an authentication failure"
        );
    }

    /// Why: the recovery KDF parameters are a resource-exhaustion boundary;
    /// the documented bounds are exact (inclusive), so an attacker-controlled
    /// envelope can neither freeze the machine with huge costs nor weaken
    /// derivation with tiny ones.
    #[test]
    fn recovery_kdf_bounds_are_exact_and_inclusive() {
        recovery_argon2(19 * 1024, 1, 1).unwrap();
        recovery_argon2(512 * 1024, 10, 8).unwrap();
        for (memory, reason) in [
            (
                19 * 1024 - 1,
                "Recovery KDF memory cost is outside the supported safety range",
            ),
            (
                512 * 1024 + 1,
                "Recovery KDF memory cost is outside the supported safety range",
            ),
        ] {
            assert_eq!(err(recovery_argon2(memory, 1, 1)), reason);
        }
        for time in [0, 11] {
            assert_eq!(
                err(recovery_argon2(19 * 1024, time, 1)),
                "Recovery KDF time cost is outside the supported safety range"
            );
        }
        for lanes in [0, 9] {
            assert_eq!(
                err(recovery_argon2(19 * 1024, 1, lanes)),
                "Recovery KDF parallelism is outside the supported safety range"
            );
        }
    }

    /// Why: `open_value` is the decryption boundary; structurally broken
    /// records must be refused as invalid, and a sealed value must only ever
    /// open as the type it was sealed with — a silent coercion would corrupt
    /// stored state.
    #[test]
    fn open_value_refuses_malformed_records_and_cross_type_reads() {
        let vault = Vault::random();
        assert_eq!(
            vault
                .open_value::<String>("ctx", b"short")
                .unwrap_err()
                .to_string(),
            "Invalid encrypted record"
        );
        let mut wrong_version = vault.seal("ctx", &"payload").unwrap();
        wrong_version[0] = 2;
        assert_eq!(
            vault
                .open_value::<String>("ctx", &wrong_version)
                .unwrap_err()
                .to_string(),
            "Invalid encrypted record"
        );
        let sealed = vault.seal("ctx", &"42").unwrap();
        assert!(
            vault.open_value::<u64>("ctx", &sealed).is_err(),
            "a sealed string must not open as a number"
        );
    }

    /// Why: the vault identifier is the credential-store account name and the
    /// recovery salt; a missing file must fail with its own reason, an invalid
    /// identifier must never reach the key layer, and incidental whitespace is
    /// trimmed to the canonical id.
    #[test]
    fn vault_id_reads_trims_and_validates_the_workspace_identifier() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            vault_id(dir.path()).unwrap_err().to_string(),
            "Vault identifier is missing"
        );
        write_new_private(&dir.path().join("vault-id"), b"not-a-uuid").unwrap();
        assert_eq!(
            vault_id(dir.path()).unwrap_err().to_string(),
            "Invalid vault identifier"
        );
        let id = uuid::Uuid::new_v4().to_string();
        fs::write(dir.path().join("vault-id"), format!("  {id}\n")).unwrap();
        assert_eq!(vault_id(dir.path()).unwrap(), id);
    }

    /// Why: `write_new_private` is create-only so no code path can silently
    /// clobber key material or a pinned vault identifier; an existing file
    /// must be refused and left byte-identical.
    #[test]
    fn write_new_private_refuses_to_overwrite_and_leaves_data_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-id");
        write_new_private(&path, b"first").unwrap();
        let error = write_new_private(&path, b"second").unwrap_err();
        let io = error.downcast_ref::<std::io::Error>().expect("an io error");
        assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"first");
    }

    /// Why: the instance lock is the single-writer guard for a workspace; it
    /// must be free again after its holder drops, or a crashed run's lock
    /// cleanup would leave the workspace permanently unusable.
    #[test]
    fn instance_lock_is_released_on_drop_and_reacquirable() {
        let dir = tempfile::tempdir().unwrap();
        let first = InstanceLock::acquire(dir.path()).unwrap();
        assert!(InstanceLock::acquire(dir.path()).is_err());
        drop(first);
        let _second = InstanceLock::acquire(dir.path()).unwrap();
    }

    /// Why: a symlinked lock file could redirect the single-writer guard to a
    /// shared location and defeat mutual exclusion across workspaces; it must
    /// be refused before any lock is taken.
    #[cfg(windows)]
    #[test]
    fn instance_lock_refuses_a_symlinked_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.lock");
        fs::write(&target, b"").unwrap();
        if std::os::windows::fs::symlink_file(&target, dir.path().join("instance.lock")).is_err() {
            // The platform forbids symlink creation without elevation; the
            // unix symlink tests cover the same guard there.
            return;
        }
        assert_eq!(
            err(InstanceLock::acquire(dir.path())),
            "Lock must not be a symlink"
        );
    }

    /// Why: a symlinked data directory could redirect every secret in the
    /// workspace to attacker-controlled storage; it must be refused before the
    /// vault touches anything inside.
    #[cfg(windows)]
    #[test]
    fn private_dir_refuses_a_symlinked_directory() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        fs::create_dir_all(&target).unwrap();
        if std::os::windows::fs::symlink_dir(&target, dir.path().join("linked")).is_err() {
            // The platform forbids symlink creation without elevation; the
            // unix symlink tests cover the same guard there.
            return;
        }
        assert_eq!(
            private_dir(&dir.path().join("linked"))
                .unwrap_err()
                .to_string(),
            "Data directory must not be a symlink"
        );
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Test-only helpers shared by every module that exercises the OS
    //! credential store.

    #[cfg(any(windows, target_os = "macos"))]
    use zeroize::Zeroizing;

    // Per-thread nesting depth for the credential-store lock: cleanup guards
    // drop inside tests that already hold the lock, and re-acquiring the same
    // OS file lock from the same thread would deadlock.
    std::thread_local! {
        static CREDENTIAL_LOCK_DEPTH: std::cell::Cell<u32> =
            const { std::cell::Cell::new(0) };
    }

    /// RAII handle for one credential-store lock level on the calling thread.
    /// Only the outermost handle owns the OS file lock.
    pub(crate) struct CredentialStoreLock {
        file: Option<std::fs::File>,
    }

    impl Drop for CredentialStoreLock {
        /// Inputs: `self` — the handle. Output: none; releases the OS file
        /// lock (when this level owns it) and lowers the nesting depth.
        fn drop(&mut self) {
            drop(self.file.take());
            CREDENTIAL_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }

    /// Serializes OS credential-store access across tests: the store is one
    /// shared system resource and concurrent mint/read/delete sequences have
    /// been observed to lose writes between parallel tests. Reentrant per
    /// thread: a cleanup guard may drop inside an already-locked test without    /// deadlocking on the same thread.
    ///
    /// Acquire the credential-store serialization lock for the calling test.
    /// Inputs: none. Output: [`CredentialStoreLock`] held until drop. The
    /// lock is cross-process, so it also serializes nextest's
    /// one-process-per-test execution of credential-store tests.
    pub(crate) fn lock_credential_store() -> CredentialStoreLock {
        if CREDENTIAL_LOCK_DEPTH.with(|depth| depth.get()) > 0 {
            CREDENTIAL_LOCK_DEPTH.with(|depth| depth.set(depth.get() + 1));
            return CredentialStoreLock { file: None };
        }
        let path = std::env::temp_dir().join("rr-test-credential-store.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .expect("open credential-store test lock");
        fs2::FileExt::lock_exclusive(&file).expect("credential-store test lock");
        CREDENTIAL_LOCK_DEPTH.with(|depth| depth.set(1));
        CredentialStoreLock { file: Some(file) }
    }

    /// One-shot in-process stand-in for the headless `RR_VAULT_PASSPHRASE`
    /// input (docs/SETUP.md).
    ///
    /// Why: the value is a constant test passphrase, so installing it once and
    /// never mutating it again lets every parallel vault open — including the
    /// ones worker threads perform on their own threads — read it race-free.
    /// Windows and macOS never consult it: their `Vault::open` resolves the key
    /// from the OS credential store instead.
    pub(crate) static HEADLESS_PASSPHRASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    /// Install the documented headless vault input for this test process.
    ///
    /// Inputs: none. Output: none; idempotent one-shot installation, so any
    /// number of tests and worker threads may call it.
    pub(crate) fn install_headless_passphrase() {
        let _ = HEADLESS_PASSPHRASE.set("rr-test-headless-vault-passphrase".to_owned());
    }

    // Thread-local live-OS-store opt-in: while held on the calling test
    // thread, `Vault::open` drives the real OS credential store. Tests that
    // assert live-store behavior must hold it; every other test derives the
    // key hermetically and never touches the store.
    std::thread_local! {
        static LIVE_OS_CREDENTIAL_STORE: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    /// Guard that opts the calling test thread into the live OS credential
    /// store for its duration.
    pub(crate) struct LiveOsCredentialStore {
        _private: (),
    }

    impl LiveOsCredentialStore {
        /// Inputs: none. Output: `Self` — guard; the thread derives vault keys
        /// from the live OS store until the guard drops.
        pub(crate) fn acquire() -> Self {
            LIVE_OS_CREDENTIAL_STORE.with(|flag| flag.set(true));
            Self { _private: () }
        }
    }

    impl Drop for LiveOsCredentialStore {
        fn drop(&mut self) {
            LIVE_OS_CREDENTIAL_STORE.with(|flag| flag.set(false));
        }
    }

    /// Inputs: none. Output: `true` when the running test thread opted into    /// the live OS credential store.
    #[cfg(any(windows, target_os = "macos"))]
    pub(crate) fn live_os_credential_store_active() -> bool {
        LIVE_OS_CREDENTIAL_STORE.with(|flag| flag.get())
    }

    /// Deterministic passphrase for hermetic test vault derivation.
    ///
    /// Inputs: none. Output: `Zeroizing<String>` — the armed headless seam
    /// value when installed, else a fixed test passphrase of sufficient length.
    #[cfg(any(windows, target_os = "macos"))]
    pub(crate) fn test_vault_passphrase() -> Zeroizing<String> {
        if let Some(pass) = HEADLESS_PASSPHRASE.get() {
            return Zeroizing::new(pass.clone());
        }
        Zeroizing::new("rr-test-hermetic-vault-passphrase".to_owned())
    }

    /// Deletes a workspace's OS credentials on drop so tests never leak
    /// Credential Manager entries. Leaked entries accumulate until `CredWrite`
    /// fails with OS error 8 and flakes unrelated tests, so every test that
    /// mints a workspace credential must hold one of these guards.
    ///
    /// Inputs: `dir` — workspace directory whose `vault-id` names the entries.
    /// Output: guard that deletes the workspace vault key and audit-anchor
    /// entries when dropped. A no-op on platforms without an OS store.
    #[cfg(any(windows, target_os = "macos"))]
    pub(crate) struct OsCredentialCleanup {
        vault_id: Option<String>,
        workspace: Option<std::path::PathBuf>,
    }

    #[cfg(any(windows, target_os = "macos"))]
    impl OsCredentialCleanup {
        /// Inputs: `dir` — workspace directory that will contain `vault-id`.
        /// Output: `Self` — cleanup guard; the vault identity is resolved at
        /// drop time, so the guard may be created before the workspace opens.
        pub(crate) fn for_workspace(dir: &std::path::Path) -> Self {
            Self {
                vault_id: None,
                workspace: Some(dir.to_path_buf()),
            }
        }

        /// Inputs: `id` — vault identifier used as the credential account
        /// name. Output: `Self` — cleanup guard bound to that identity.
        pub(crate) fn from_vault_id(id: impl Into<String>) -> Self {
            Self {
                vault_id: Some(id.into()),
                workspace: None,
            }
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    impl Drop for OsCredentialCleanup {
        fn drop(&mut self) {
            let vault_id = match self.vault_id.take() {
                Some(id) => id,
                None => self
                    .workspace
                    .as_ref()
                    .map(|workspace| {
                        std::fs::read_to_string(workspace.join("vault-id"))
                            .unwrap_or_default()
                            .trim()
                            .to_owned()
                    })
                    .unwrap_or_default(),
            };
            if vault_id.is_empty() {
                return;
            }
            // Serialize with the shared credential-store lock and remove both
            // entries this workspace may have minted. Deleting an absent entry
            // is harmless.
            let _lock = lock_credential_store();
            for service in [
                "rejection-rejector.v1",
                crate::audit_anchor::OS_AUDIT_ANCHOR_SERVICE,
            ] {
                let _ = keyring::Entry::new(service, &vault_id)
                    .and_then(|entry| entry.delete_credential());
            }
        }
    }

    /// Cross-platform shape of [`OsCredentialCleanup`] on hosts without an OS
    /// credential store: construction is cheap and dropping is a no-op, so
    /// test code can hold the guard unconditionally.
    #[cfg(not(any(windows, target_os = "macos")))]
    pub(crate) struct OsCredentialCleanup;

    #[cfg(not(any(windows, target_os = "macos")))]
    impl OsCredentialCleanup {
        /// Inputs: `_dir` — workspace directory (unused without an OS store).
        /// Output: `Self` — no-op guard.
        pub(crate) fn for_workspace(_dir: &std::path::Path) -> Self {
            Self
        }

        /// Inputs: `_id` — vault identifier (unused without an OS store).
        /// Output: `Self` — no-op guard.
        pub(crate) fn from_vault_id(_id: impl Into<String>) -> Self {
            Self
        }
    }
}

// Windows/macOS only: the seam functions under test take injected
// `keyring::Error` values (they never touch a live store themselves), but the
// keyring crate is a target-scoped dependency, so this module cannot compile
// where the crate is absent.
#[cfg(all(test, any(windows, target_os = "macos")))]
mod credential_store_seam_tests {
    use super::*;

    fn store_error() -> keyring::Error {
        keyring::Error::BadEncoding(vec![1, 2, 3])
    }

    /// Why: every credential-store outcome must fail closed except the two
    /// documented ones — reading an existing key and minting exactly once on
    /// first open. A store outage must surface as an error and never mint a
    /// replacement key, which would orphan all previously sealed records.
    #[test]
    fn key_lookup_outcomes_fail_closed_except_read_and_first_open_mint() {
        let payload = Zeroizing::new(STANDARD.encode([7u8; 32]));
        let key = key_from_credential_store(Ok(payload.as_str().to_owned()), true, |_| {
            panic!("an existing credential must never be overwritten")
        })
        .unwrap();
        assert_eq!(key.as_slice(), &[7u8; 32][..]);

        assert!(key_from_credential_store(Ok("not base64 !".into()), true, |_| Ok(())).is_err());
        let short = Zeroizing::new(STANDARD.encode([1u8; 16]));
        assert!(
            key_from_credential_store(Ok(short.as_str().to_owned()), true, |_| Ok(())).is_err(),
            "non-32-byte keys are rejected"
        );

        let mut minted: Option<String> = None;
        let fresh = key_from_credential_store(Err(keyring::Error::NoEntry), true, |encoded| {
            minted = Some(encoded.to_owned());
            Ok(())
        })
        .unwrap();
        let stored = minted.expect("first open must mint exactly one key");
        let decoded = STANDARD.decode(stored.as_str()).unwrap();
        assert_eq!(fresh.as_slice(), decoded.as_slice());

        assert!(
            key_from_credential_store(Err(keyring::Error::NoEntry), false, |_| {
                panic!("an existing vault must never mint a replacement key")
            })
            .is_err()
        );
        assert!(
            key_from_credential_store(Err(store_error()), true, |_| Ok(())).is_err(),
            "credential-store outages must fail closed"
        );
    }

    /// Why: recovery-key import must install exactly once, refuse to overwrite
    /// an existing credential, and surface credential-store inspection failures
    /// instead of silently skipping the install.
    #[test]
    fn recovered_key_install_refuses_overwrite_and_surfaces_store_errors() {
        let mut stored: Option<String> = None;
        install_key_into_credential_store(Err(keyring::Error::NoEntry), &[3u8; 32], |encoded| {
            stored = Some(encoded.to_owned());
            Ok(())
        })
        .unwrap();
        let encoded = stored.expect("missing credential must be installed");
        assert_eq!(STANDARD.decode(encoded).unwrap().len(), 32);

        assert!(
            install_key_into_credential_store(Ok("existing".into()), &[3u8; 32], |_| {
                panic!("existing credential must not be overwritten")
            })
            .is_err()
        );
        let error = install_key_into_credential_store(Err(store_error()), &[3u8; 32], |_| {
            panic!("store errors must not install anything")
        })
        .expect_err("an unavailable credential store must fail");
        assert!(
            error
                .to_string()
                .contains("Cannot inspect the OS credential store"),
            "unexpected error: {error}"
        );
    }
}
