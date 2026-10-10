use crate::{
    types::*,
    vault::{Vault, private_dir, write_new_private},
};
use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, backup::Backup, params,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

/// Convert a domain `u64` into SQLite's signed INTEGER representation.
///
/// Inputs: `value` — unsigned counter/revision/timestamp domain value.
/// Output: [`i64`] suitable for SQL parameters; values outside the signed
/// 64-bit range return [`rusqlite::Error`] instead of silently wrapping.
fn sql_i64(value: u64) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|_| {
        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
            "u64 value exceeds the SQLite INTEGER range",
        )))
    })
}

/// Read a SQLite INTEGER column as `u64`.
///
/// Inputs: `row` — one query result row; `index` — 0-based column index.
/// Output: the column value as [`u64`]; negative stored values are rejected
/// instead of wrapping, so corrupted state cannot become a large unsigned value.
fn row_get_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let raw: i64 = row.get(index)?;
    u64::try_from(raw).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, raw))
}

pub const DATABASE_SCHEMA_VERSION: i64 = 5;

#[derive(Clone, Debug, Serialize)]
pub struct BackupVerificationSummary {
    pub schema_version: i64,
    pub audit_head: Option<String>,
    pub metadata_records: u64,
    pub item_records: u64,
    pub audit_events: u64,
    pub delivery_records: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ApplicationIntegritySummary {
    pub metadata_records: u64,
    pub item_records: u64,
    pub audit_event_records: u64,
    pub delivery_records: u64,
    pub active_delivery_records: u64,
    pub sent_delivery_records: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessingFailureRecord {
    pub code: ProcessingFailureCode,
    pub attempts: u32,
    pub retry_exhausted: bool,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ProcessingFailureSummary {
    pub active_records: u64,
    pub retry_exhausted: u64,
    pub by_code: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DatabaseCompactionReport {
    pub schema_version: u32,
    pub before_page_count: u64,
    pub before_freelist_count: u64,
    pub after_page_count: u64,
    pub after_freelist_count: u64,
    pub page_size_bytes: u64,
}

pub struct Store {
    conn: Connection,
    vault: Vault,
}

enum ProcessingFailureMutation<'a> {
    Keep,
    Set(&'a ProcessingFailureRecord),
    Clear,
}

fn decode(vault: &Vault, id: &str, bytes: &[u8], revision: u64, state: &str) -> Result<Job> {
    let job: Job = vault.open_value(&format!("item/{id}"), bytes)?;
    ensure!(
        job.id == id && job.revision == revision && job.state.db() == state,
        "Authenticated record metadata mismatch"
    );
    Ok(job)
}
const AUDIT_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn audit_hash(previous_hash: &str, event_id: &str, payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"rejection-rejector-audit-v1\0");
    for part in [previous_hash.as_bytes(), event_id.as_bytes(), payload] {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    crate::hex_lower(digest.finalize())
}

fn valid_audit_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn event(
    tx: &Transaction<'_>,
    vault: &Vault,
    kind: &str,
    item: Option<&str>,
    detail: &str,
    at: DateTime<Utc>,
) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let (domain, severity) = audit_attributes(kind);
    let e = AuditEvent {
        seq: 0,
        at,
        kind: kind.into(),
        domain,
        severity,
        item_id: item.map(str::to_owned),
        detail: detail.into(),
    };
    let payload = vault.seal(&format!("event/{id}"), &e)?;
    let previous_hash: Option<String> = tx
        .query_row(
            "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let previous_hash = previous_hash.unwrap_or_else(|| AUDIT_GENESIS.to_owned());
    ensure!(
        valid_audit_hash(&previous_hash),
        "Audit journal predecessor hash is invalid"
    );
    let event_hash = audit_hash(&previous_hash, &id, &payload);
    tx.execute(
        "INSERT INTO events(event_id,payload,prev_hash,event_hash) VALUES(?1,?2,?3,?4)",
        params![id, payload, previous_hash, event_hash],
    )?;
    tx.execute(
        "INSERT INTO meta(name,payload) VALUES('audit_head',?1)
         ON CONFLICT(name) DO UPDATE SET payload=excluded.payload",
        [vault.seal("meta/audit_head", &event_hash)?],
    )?;
    Ok(())
}

fn migrate_processing_failures(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS processing_failures(
            item_id TEXT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
            code TEXT NOT NULL,
            attempts INTEGER NOT NULL,
            retry_exhausted INTEGER NOT NULL CHECK(retry_exhausted IN (0,1)),
            occurred_at INTEGER NOT NULL,
            payload BLOB NOT NULL
         );
         CREATE INDEX IF NOT EXISTS processing_failures_code
             ON processing_failures(code,retry_exhausted);
         PRAGMA user_version=5;",
    )?;
    tx.commit()?;
    Ok(())
}

fn migrate_audit_chain(conn: &Connection, vault: &Vault) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        "ALTER TABLE events ADD COLUMN prev_hash TEXT;
         ALTER TABLE events ADD COLUMN event_hash TEXT;",
    )?;
    let rows: Vec<(i64, String, Vec<u8>)> = {
        let mut query = tx.prepare("SELECT seq,event_id,payload FROM events ORDER BY seq")?;
        let mapped = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        mapped.collect::<std::result::Result<Vec<_>, _>>()?
    };

    let mut previous_hash = AUDIT_GENESIS.to_owned();
    for (seq, event_id, payload) in rows {
        let event_hash = audit_hash(&previous_hash, &event_id, &payload);
        tx.execute(
            "UPDATE events SET prev_hash=?2,event_hash=?3 WHERE seq=?1",
            params![seq, previous_hash, event_hash],
        )?;
        previous_hash = event_hash;
    }
    tx.execute(
        "INSERT INTO meta(name,payload) VALUES('audit_head',?1)
         ON CONFLICT(name) DO UPDATE SET payload=excluded.payload",
        [vault.seal("meta/audit_head", &previous_hash)?],
    )?;
    tx.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS events_hash ON events(event_hash);
         PRAGMA user_version=4;",
    )?;
    tx.commit()?;
    Ok(())
}

fn verify_audit_chain_connection(conn: &Connection, vault: &Vault) -> Result<()> {
    let encrypted_head: Vec<u8> = conn
        .query_row(
            "SELECT payload FROM meta WHERE name='audit_head'",
            [],
            |row| row.get(0),
        )
        .context("Audit journal head is missing")?;
    let expected_head: String = vault.open_value("meta/audit_head", &encrypted_head)?;
    ensure!(
        valid_audit_hash(&expected_head),
        "Audit journal head is invalid"
    );

    let mut query =
        conn.prepare("SELECT event_id,payload,prev_hash,event_hash FROM events ORDER BY seq")?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    let mut previous_hash = AUDIT_GENESIS.to_owned();
    for row in rows {
        let (event_id, payload, stored_previous, stored_hash) = row?;
        ensure!(
            stored_previous == previous_hash,
            "Audit journal chain link mismatch"
        );
        ensure!(
            valid_audit_hash(&stored_hash),
            "Audit journal event hash is invalid"
        );
        let computed = audit_hash(&stored_previous, &event_id, &payload);
        ensure!(computed == stored_hash, "Audit journal event was modified");
        previous_hash = stored_hash;
    }
    ensure!(
        previous_hash == expected_head,
        "Audit journal head does not match stored events"
    );
    Ok(())
}
fn create_pre_migration_backup(
    source_path: &Path,
    source: &Connection,
    from_version: i64,
) -> Result<PathBuf> {
    ensure!(
        from_version > 0 && from_version < DATABASE_SCHEMA_VERSION,
        "Pre-migration backup requested for an invalid schema version"
    );
    let parent = source_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let recovery_dir = parent.join("recovery").join("migrations");
    private_dir(&recovery_dir)?;
    let destination = recovery_dir.join(format!(
        "pre-schema-v{from_version}-to-v{}-{}-{}.sqlite3",
        DATABASE_SCHEMA_VERSION,
        Utc::now().format("%Y%m%d-%H%M%S"),
        uuid::Uuid::new_v4()
    ));
    write_new_private(&destination, b"")?;
    let backup_result = (|| -> Result<()> {
        let mut target = Connection::open(&destination)?;
        {
            let backup = Backup::new(source, &mut target)?;
            backup.run_to_completion(64, Duration::from_millis(10), None)?;
        }
        target.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        check_connection_integrity(&target)?;
        let backed_up_version: i64 =
            target.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        ensure!(
            backed_up_version == from_version,
            "Pre-migration backup schema does not match the source"
        );
        Ok(())
    })();
    if let Err(error) = backup_result {
        let _ = std::fs::remove_file(&destination);
        return Err(error.context("Could not create verified pre-migration recovery image"));
    }
    Ok(destination)
}

fn check_connection_integrity(conn: &Connection) -> Result<()> {
    let quick: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    ensure!(quick == "ok", "SQLite quick_check failed: {quick}");
    let foreign_key_violations: i64 =
        conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    ensure!(
        foreign_key_violations == 0,
        "SQLite foreign-key check found {foreign_key_violations} violation(s)"
    );
    Ok(())
}

fn verify_application_invariants_connection(
    conn: &Connection,
    vault: &Vault,
) -> Result<ApplicationIntegritySummary> {
    let mut metadata_records = 0u64;
    let mut item_records = 0u64;
    let mut audit_event_records = 0u64;
    let mut active_delivery_records = 0u64;
    let mut sent_delivery_records = 0u64;

    {
        let mut metadata = conn.prepare("SELECT name,payload FROM meta ORDER BY name")?;
        let rows = metadata.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (name, payload) = row?;
            let _: serde_json::Value = vault.open_value(&format!("meta/{name}"), &payload)?;
            metadata_records += 1;
        }
    }

    {
        let mut events = conn.prepare("SELECT event_id,payload FROM events ORDER BY seq")?;
        let rows = events.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (event_id, payload) = row?;
            let _: AuditEvent = vault.open_value(&format!("event/{event_id}"), &payload)?;
            audit_event_records += 1;
        }
    }

    let mut items = conn.prepare("SELECT id,payload,revision,state FROM items ORDER BY id")?;
    let rows = items.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row_get_u64(row, 2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    for row in rows {
        let (id, payload, revision, state) = row?;
        let job = decode(vault, &id, &payload, revision, &state)?;
        item_records += 1;

        let delivery: Option<(String, String, i64, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT thread_key,status,attempt_at,provider_id FROM deliveries WHERE item_id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        match job.state {
            JobState::Sending | JobState::Uncertain | JobState::Sent => {
                let (thread_key, status, attempt_at, provider_payload) = delivery
                    .context("Delivery-state job is missing its durable delivery record")?;
                ensure!(
                    thread_key == job.stub.thread_key(),
                    "Delivery thread key does not match authenticated job identity"
                );
                ensure!(attempt_at > 0, "Delivery attempt timestamp is invalid");

                let expected_status = match job.state {
                    JobState::Sending => "reserved",
                    JobState::Uncertain => "uncertain",
                    JobState::Sent => "sent",
                    _ => anyhow::bail!("Internal delivery-state validation mismatch"),
                };
                ensure!(
                    status == expected_status,
                    "Delivery record state does not match authenticated job state"
                );

                match job.state {
                    JobState::Sent => {
                        let provider_payload = provider_payload.context(
                            "Sent delivery is missing its encrypted provider identifier",
                        )?;
                        let provider: String =
                            vault.open_value(&format!("delivery/{id}"), &provider_payload)?;
                        ensure!(
                            job.provider_sent_id.as_deref() == Some(provider.as_str()),
                            "Sent provider identifier does not match authenticated job payload"
                        );
                        sent_delivery_records += 1;
                    }
                    JobState::Sending | JobState::Uncertain => {
                        ensure!(
                            provider_payload.is_none() && job.provider_sent_id.is_none(),
                            "Unresolved delivery unexpectedly contains a provider identifier"
                        );
                        active_delivery_records += 1;
                    }
                    _ => anyhow::bail!("Internal delivery-state validation mismatch"),
                }
            }
            _ => {
                ensure!(
                    delivery.is_none(),
                    "Non-delivery job unexpectedly has a durable delivery record"
                );
                ensure!(
                    job.provider_sent_id.is_none(),
                    "Non-sent job unexpectedly contains a provider identifier"
                );
            }
        }
    }

    let schema_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version >= 5 {
        let mut failures = conn.prepare(
            "SELECT item_id,code,attempts,retry_exhausted,occurred_at,payload
             FROM processing_failures ORDER BY item_id",
        )?;
        let rows = failures.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        for row in rows {
            let (item_id, code, attempts, retry_exhausted, occurred_at, payload) = row?;
            ensure!(
                ProcessingFailureCode::from_db(&code).is_some(),
                "Processing-failure record has an unknown stable code"
            );
            ensure!(attempts > 0, "Processing-failure attempt count is invalid");
            ensure!(occurred_at > 0, "Processing-failure timestamp is invalid");
            let record: ProcessingFailureRecord =
                vault.open_value(&format!("processing_failure/{item_id}"), &payload)?;
            ensure!(
                record.code.as_str() == code
                    && record.attempts == attempts
                    && record.retry_exhausted == retry_exhausted
                    && record.occurred_at.timestamp() == occurred_at,
                "Processing-failure clear metadata does not match authenticated payload"
            );
            let item_exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM items WHERE id=?1)",
                [&item_id],
                |row| row.get(0),
            )?;
            ensure!(
                item_exists,
                "Processing-failure record references a missing item"
            );
        }
    }

    let delivery_records: u64 = conn.query_row("SELECT COUNT(*) FROM deliveries", [], |row| {
        row_get_u64(row, 0)
    })?;
    ensure!(
        delivery_records == active_delivery_records + sent_delivery_records,
        "Delivery table contains records not represented by authenticated item state"
    );

    Ok(ApplicationIntegritySummary {
        metadata_records,
        item_records,
        audit_event_records,
        delivery_records,
        active_delivery_records,
        sent_delivery_records,
    })
}

fn recipient_attempts_since(
    conn: &Connection,
    vault: &Vault,
    recipient: &str,
    cutoff: i64,
) -> Result<u64> {
    let mut query = conn.prepare(
        "SELECT i.id,i.payload,i.revision,i.state
         FROM deliveries d
         JOIN items i ON i.id=d.item_id
         WHERE d.attempt_at>=?1
         ORDER BY d.attempt_at DESC",
    )?;
    let rows = query.query_map([cutoff], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row_get_u64(row, 2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut count = 0u64;
    for row in rows {
        let (id, payload, revision, state) = row?;
        let job = decode(vault, &id, &payload, revision, &state)?;
        let email = job.email.as_ref().context(
            "Recent delivery is missing source email required for recipient burst safety",
        )?;
        if email.recipient()? == recipient {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

impl Store {
    pub fn open(path: &Path, vault: Vault) -> Result<Self> {
        if !path.exists() {
            write_new_private(path, b"")?;
        }
        ensure!(
            !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
            "Database must not be a symlink"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF; PRAGMA wal_autocheckpoint=1000; PRAGMA journal_size_limit=67108864;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        ensure!(
            version <= DATABASE_SCHEMA_VERSION,
            "Database belongs to a newer app version"
        );
        if version > 0 {
            let existing_check: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT payload FROM meta WHERE name='vault_check'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            let bytes = existing_check.context(
                "Existing database is missing its authenticated vault marker; refusing to migrate or adopt a new key",
            )?;
            let check: String = vault.open_value("meta/vault_check", &bytes)?;
            ensure!(check == "rejection-rejector:v1", "Wrong vault");
        }
        let pre_migration_backup = if version > 0 && version < DATABASE_SCHEMA_VERSION {
            Some(create_pre_migration_backup(path, &conn, version)?)
        } else {
            None
        };
        if version == 0 {
            conn.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE meta(name TEXT PRIMARY KEY,payload BLOB NOT NULL);
                CREATE TABLE items(id TEXT PRIMARY KEY,account_key TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL,received_at INTEGER,updated_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,payload BLOB NOT NULL);
                CREATE INDEX items_queue ON items(account_key,state,retry_at,created_at);
                CREATE INDEX items_review_order ON items(account_key,state,received_at,created_at);
                CREATE TABLE processing_failures(
                    item_id TEXT PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
                    code TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    retry_exhausted INTEGER NOT NULL CHECK(retry_exhausted IN (0,1)),
                    occurred_at INTEGER NOT NULL,
                    payload BLOB NOT NULL
                );
                CREATE INDEX processing_failures_code ON processing_failures(code,retry_exhausted);
                CREATE TABLE deliveries(item_id TEXT PRIMARY KEY,thread_key TEXT NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                CREATE INDEX deliveries_time ON deliveries(attempt_at);
                CREATE INDEX deliveries_thread_state ON deliveries(thread_key,status);
                CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL,prev_hash TEXT NOT NULL,event_hash TEXT NOT NULL);
                CREATE UNIQUE INDEX events_hash ON events(event_hash);")?;
            let marker = vault.seal("meta/vault_check", &"rejection-rejector:v1")?;
            let audit_head = vault.seal("meta/audit_head", &AUDIT_GENESIS)?;
            conn.execute(
                "INSERT INTO meta(name,payload) VALUES('vault_check',?1)",
                [marker],
            )?;
            conn.execute(
                "INSERT INTO meta(name,payload) VALUES('audit_head',?1)",
                [audit_head],
            )?;
            conn.execute_batch("PRAGMA user_version=5; COMMIT;")?;
        } else if version == 1 {
            conn.execute_batch("BEGIN IMMEDIATE;
                ALTER TABLE items ADD COLUMN received_at INTEGER;
                CREATE INDEX IF NOT EXISTS items_review_order ON items(account_key,state,received_at,created_at);
                ALTER TABLE deliveries RENAME TO deliveries_v2;
                CREATE TABLE deliveries(item_id TEXT PRIMARY KEY,thread_key TEXT NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                INSERT INTO deliveries(item_id,thread_key,attempt_at,status,provider_id)
                    SELECT item_id,thread_key,attempt_at,status,provider_id FROM deliveries_v2;
                DROP TABLE deliveries_v2;
                CREATE INDEX deliveries_time ON deliveries(attempt_at);
                CREATE INDEX deliveries_thread_state ON deliveries(thread_key,status);
                PRAGMA user_version=3; COMMIT;")?;
        } else if version == 2 {
            conn.execute_batch("BEGIN IMMEDIATE;
                ALTER TABLE deliveries RENAME TO deliveries_v2;
                CREATE TABLE deliveries(item_id TEXT PRIMARY KEY,thread_key TEXT NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                INSERT INTO deliveries(item_id,thread_key,attempt_at,status,provider_id)
                    SELECT item_id,thread_key,attempt_at,status,provider_id FROM deliveries_v2;
                DROP TABLE deliveries_v2;
                CREATE INDEX deliveries_time ON deliveries(attempt_at);
                CREATE INDEX deliveries_thread_state ON deliveries(thread_key,status);
                PRAGMA user_version=3; COMMIT;")?;
        } else if version >= 3 {
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS items_review_order ON items(account_key,state,received_at,created_at);
                 CREATE INDEX IF NOT EXISTS deliveries_thread_state ON deliveries(thread_key,status);",
            )?;
        }
        let current_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if current_version == 3 {
            migrate_audit_chain(&conn, &vault)?;
        }
        let current_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if current_version == 4 {
            migrate_processing_failures(&conn)?;
        }
        let mut db = Self { conn, vault };
        let check = db
            .meta::<String>("vault_check")?
            .context("Database vault marker is missing after initialization")?;
        ensure!(check == "rejection-rejector:v1", "Wrong vault");
        db.verify_audit_chain()?;
        if let Some(backup) = pre_migration_backup {
            let name = backup
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("pre-migration.sqlite3");
            db.log(
                "database.migrated",
                None,
                &format!(
                    "Schema migrated from v{version} to v{DATABASE_SCHEMA_VERSION}; verified pre-migration image retained as {name}"
                ),
            )?;
        }
        Ok(db)
    }
    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    /// Bounded runtime readiness check suitable for health endpoints.
    ///
    /// This authenticates the vault marker and audit-head metadata and confirms
    /// the migrated schema, but deliberately does not scan every row/event.
    pub fn readiness_check(&self) -> Result<()> {
        let probe: i64 = self.conn.query_row("SELECT 1", [], |row| row.get(0))?;
        ensure!(probe == 1, "Database readiness probe failed");
        ensure!(
            self.schema_version()? == DATABASE_SCHEMA_VERSION,
            "Database schema is not at the current migrated version"
        );
        let marker = self
            .meta::<String>("vault_check")?
            .context("Database vault marker is missing")?;
        ensure!(marker == "rejection-rejector:v1", "Wrong vault marker");
        let head = self
            .meta::<String>("audit_head")?
            .context("Audit journal head is missing")?;
        ensure!(valid_audit_hash(&head), "Audit journal head is invalid");
        Ok(())
    }

    /// Deep database integrity check for explicit diagnostics/recovery operations.
    /// This may scan SQLite structures and the complete tamper-evident audit chain.
    pub fn integrity_check(&self) -> Result<()> {
        self.readiness_check()?;
        check_connection_integrity(&self.conn)?;
        self.verify_audit_chain()?;
        verify_application_invariants_connection(&self.conn, &self.vault)?;
        Ok(())
    }

    pub fn application_integrity(&self) -> Result<ApplicationIntegritySummary> {
        verify_application_invariants_connection(&self.conn, &self.vault)
    }

    pub fn verify_audit_chain(&self) -> Result<()> {
        verify_audit_chain_connection(&self.conn, &self.vault)
    }

    pub fn audit_head(&self) -> Result<String> {
        let head = self
            .meta::<String>("audit_head")?
            .context("Audit journal head is missing")?;
        ensure!(valid_audit_hash(&head), "Audit journal head is invalid");
        Ok(head)
    }

    /// Return the current tamper-evident audit point after validating the full chain.
    pub fn audit_point(&self) -> Result<(i64, String)> {
        self.verify_audit_chain()?;
        let row: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((sequence, head)) => {
                ensure!(sequence > 0, "Audit sequence is invalid");
                ensure!(valid_audit_hash(&head), "Audit journal head is invalid");
                ensure!(
                    head == self.audit_head()?,
                    "Audit point does not match authenticated journal head"
                );
                Ok((sequence, head))
            }
            None => {
                let head = self.audit_head()?;
                ensure!(
                    head == AUDIT_GENESIS,
                    "Empty audit journal has a non-genesis head"
                );
                Ok((0, head))
            }
        }
    }

    /// Verify that an externally persisted sequence/hash pair is an exact prefix
    /// of the current audit journal. A newer current head is allowed; rollback,
    /// chain replacement and sequence/hash mismatch fail closed.
    pub fn verify_audit_point(&self, sequence: i64, anchor: &str) -> Result<()> {
        ensure!(sequence >= 0, "Audit anchor sequence is invalid");
        ensure!(valid_audit_hash(anchor), "Invalid audit anchor");
        self.verify_audit_chain()?;
        if sequence == 0 {
            ensure!(
                anchor == AUDIT_GENESIS,
                "Sequence zero must use the audit genesis hash"
            );
            return Ok(());
        }
        let stored: Option<String> = self
            .conn
            .query_row(
                "SELECT event_hash FROM events WHERE seq=?1",
                [sequence],
                |row| row.get(0),
            )
            .optional()?;
        let stored =
            stored.context("Current workspace no longer contains the anchored audit sequence")?;
        ensure!(
            stored == anchor,
            "Current workspace does not extend the anchored audit history"
        );
        Ok(())
    }

    /// Verify only the audit suffix after an already trusted external point.
    ///
    /// This is suitable for frequent protected-anchor checkpoints: it proves
    /// that the current authenticated head extends the trusted sequence/hash
    /// without rescanning the entire historical prefix on every operation.
    pub fn verify_audit_extension(&self, sequence: i64, anchor: &str) -> Result<(i64, String)> {
        ensure!(sequence >= 0, "Audit anchor sequence is invalid");
        ensure!(valid_audit_hash(anchor), "Invalid audit anchor");

        if sequence == 0 {
            ensure!(
                anchor == AUDIT_GENESIS,
                "Sequence zero must use the audit genesis hash"
            );
        } else {
            let stored: Option<String> = self
                .conn
                .query_row(
                    "SELECT event_hash FROM events WHERE seq=?1",
                    [sequence],
                    |row| row.get(0),
                )
                .optional()?;
            ensure!(
                stored.as_deref() == Some(anchor),
                "Current workspace does not contain the trusted audit point"
            );
        }

        let mut previous_hash = anchor.to_owned();
        let mut latest_sequence = sequence;
        let mut query = self.conn.prepare(
            "SELECT seq,event_id,payload,prev_hash,event_hash
             FROM events WHERE seq>?1 ORDER BY seq",
        )?;
        let rows = query.query_map([sequence], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;

        for row in rows {
            let (event_sequence, event_id, payload, stored_previous, stored_hash) = row?;
            ensure!(
                event_sequence > latest_sequence,
                "Audit journal sequence is not strictly increasing"
            );
            ensure!(
                stored_previous == previous_hash,
                "Audit journal extension does not link to the trusted anchor"
            );
            ensure!(
                valid_audit_hash(&stored_hash),
                "Audit journal event hash is invalid"
            );
            let computed = audit_hash(&stored_previous, &event_id, &payload);
            ensure!(computed == stored_hash, "Audit journal event was modified");
            previous_hash = stored_hash;
            latest_sequence = event_sequence;
        }

        ensure!(
            previous_hash == self.audit_head()?,
            "Audit journal extension does not reach the authenticated current head"
        );
        Ok((latest_sequence, previous_hash))
    }

    /// Check whether an externally persisted audit anchor is still represented
    /// by this database's history. This enables rollback detection when another
    /// trusted component stores previously observed heads.
    pub fn contains_audit_anchor(&self, anchor: &str) -> Result<bool> {
        ensure!(valid_audit_hash(anchor), "Invalid audit anchor");
        self.verify_audit_chain()?;
        if anchor == AUDIT_GENESIS {
            return Ok(true);
        }
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE event_hash=?1)",
            [anchor],
            |row| row.get(0),
        )?)
    }

    /// Create a consistent online copy of the encrypted SQLite database.
    ///
    /// This is a same-vault backup: application payloads remain encrypted and
    /// the matching vault identifier / OS-protected key is still required.
    /// Existing files are never overwritten.
    pub fn backup_to(&self, path: &Path) -> Result<()> {
        self.integrity_check()?;
        ensure!(!path.exists(), "Backup destination already exists");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            ensure!(
                !std::fs::symlink_metadata(parent)?.file_type().is_symlink(),
                "Backup parent directory must not be a symlink"
            );
        }
        write_new_private(path, b"")?;
        let mut destination = Connection::open(path)?;
        {
            let backup = Backup::new(&self.conn, &mut destination)?;
            backup.run_to_completion(64, Duration::from_millis(10), None)?;
        }
        destination.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        check_connection_integrity(&destination)?;
        let source_version = self.schema_version()?;
        let backup_version: i64 =
            destination.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        ensure!(
            source_version == backup_version,
            "Backup schema version does not match source"
        );
        Ok(())
    }

    /// Verify a backup without modifying it. The encrypted vault marker must
    /// authenticate under this Store's current master key.
    pub fn verify_backup_file(&self, path: &Path) -> Result<BackupVerificationSummary> {
        ensure!(path.is_file(), "Backup database file is missing");
        ensure!(
            !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
            "Backup database must not be a symlink"
        );
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        check_connection_integrity(&connection)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let current_version = self.schema_version()?;
        ensure!(
            (1..=current_version).contains(&version),
            "Backup schema version is not supported by this application"
        );

        let mut metadata_records = 0u64;
        {
            let mut statement =
                connection.prepare("SELECT name,payload FROM meta ORDER BY name")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (name, payload) = row?;
                let _: serde_json::Value =
                    self.vault.open_value(&format!("meta/{name}"), &payload)?;
                metadata_records += 1;
            }
        }

        let encrypted: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM meta WHERE name='vault_check'",
                [],
                |row| row.get(0),
            )
            .context("Backup vault marker is missing")?;
        let marker: String = self.vault.open_value("meta/vault_check", &encrypted)?;
        ensure!(
            marker == "rejection-rejector:v1",
            "Backup belongs to another vault"
        );

        let mut item_records = 0u64;
        {
            let mut statement =
                connection.prepare("SELECT id,payload,revision,state FROM items ORDER BY id")?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row_get_u64(row, 2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (id, payload, revision, state) = row?;
                decode(&self.vault, &id, &payload, revision, &state)?;
                item_records += 1;
            }
        }

        let mut audit_events = 0u64;
        {
            let mut statement =
                connection.prepare("SELECT event_id,payload FROM events ORDER BY seq")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (event_id, payload) = row?;
                let _: AuditEvent = self
                    .vault
                    .open_value(&format!("event/{event_id}"), &payload)?;
                audit_events += 1;
            }
        }

        let application_integrity =
            verify_application_invariants_connection(&connection, &self.vault)?;
        ensure!(
            application_integrity.metadata_records == metadata_records
                && application_integrity.item_records == item_records
                && application_integrity.audit_event_records == audit_events,
            "Backup deep-integrity record counts are inconsistent"
        );
        let delivery_records = application_integrity.delivery_records;

        let audit_head = if version >= 4 {
            verify_audit_chain_connection(&connection, &self.vault)?;
            let encrypted: Vec<u8> = connection.query_row(
                "SELECT payload FROM meta WHERE name='audit_head'",
                [],
                |row| row.get(0),
            )?;
            let head: String = self.vault.open_value("meta/audit_head", &encrypted)?;
            ensure!(valid_audit_hash(&head), "Backup audit head is invalid");
            Some(head)
        } else {
            None
        };

        Ok(BackupVerificationSummary {
            schema_version: version,
            audit_head,
            metadata_records,
            item_records,
            audit_events,
            delivery_records,
        })
    }

    pub fn meta<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT payload FROM meta WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        bytes
            .map(|b| self.vault.open_value(&format!("meta/{name}"), &b))
            .transpose()
    }
    pub fn set_meta<T: Serialize>(&mut self, name: &str, value: &T) -> Result<()> {
        self.conn.execute("INSERT INTO meta(name,payload) VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload", params![name, self.vault.seal(&format!("meta/{name}"), value)?])?;
        Ok(())
    }
    pub fn delete_meta(&mut self, name: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM meta WHERE name=?1", [name])?;
        Ok(())
    }

    /// Atomically update related encrypted metadata and its audit event.
    pub fn change_meta(
        &mut self,
        upserts: &[(&str, serde_json::Value)],
        deletes: &[&str],
        audit_kind: &str,
        audit_detail: &str,
    ) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (name, value) in upserts {
            ensure!(
                !name.is_empty() && name.len() <= 512,
                "Invalid metadata key"
            );
            let encrypted = self.vault.seal(&format!("meta/{name}"), value)?;
            tx.execute(
                "INSERT INTO meta(name,payload) VALUES(?1,?2)
                 ON CONFLICT(name) DO UPDATE SET payload=excluded.payload",
                params![name, encrypted],
            )?;
        }
        for name in deletes {
            ensure!(
                !name.is_empty() && name.len() <= 512,
                "Invalid metadata key"
            );
            tx.execute("DELETE FROM meta WHERE name=?1", [name])?;
        }
        event(&tx, &self.vault, audit_kind, None, audit_detail, Utc::now())?;
        tx.commit()?;
        Ok(())
    }
    pub fn contains(&self, id: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM items WHERE id=?1)",
            [id],
            |r| r.get(0),
        )?)
    }
    /// Insert a Gmail page worth of message identities in one durable transaction.
    /// Existing identities are ignored without rewriting their encrypted payloads.
    pub fn insert_stubs<I>(&mut self, stubs: I, now: DateTime<Utc>) -> Result<usize>
    where
        I: IntoIterator<Item = Stub>,
    {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut inserted = 0usize;
        for stub in stubs {
            let j = Job::new(stub, now);
            let n = tx.execute("INSERT OR IGNORE INTO items(id,account_key,state,revision,created_at,updated_at,retry_at,payload) VALUES(?1,?2,?3,0,?4,?4,0,?5)", params![j.id, hash(&j.stub.account), j.state.db(), now.timestamp(), self.vault.seal(&format!("item/{}", j.id), &j)?])?;
            if n == 1 {
                event(
                    &tx,
                    &self.vault,
                    "email.queued",
                    Some(&j.id),
                    "New provider identity stored",
                    now,
                )?;
                inserted += 1;
            }
        }
        tx.commit()?;
        Ok(inserted)
    }

    pub fn insert_stub(&mut self, stub: Stub, now: DateTime<Utc>) -> Result<bool> {
        Ok(self.insert_stubs(std::iter::once(stub), now)? == 1)
    }
    pub fn get(&self, id: &str) -> Result<Job> {
        let (b, r, s): (Vec<u8>, u64, String) = self
            .conn
            .query_row(
                "SELECT payload,revision,state FROM items WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, row_get_u64(r, 1)?, r.get(2)?)),
            )
            .optional()?
            .context("Message not found")?;
        decode(&self.vault, id, &b, r, &s)
    }
    pub fn save(&mut self, job: &mut Job, kind: &str, detail: &str) -> Result<()> {
        self.save_internal(job, kind, detail, ProcessingFailureMutation::Keep)
    }

    pub fn save_processing_failure(
        &mut self,
        job: &mut Job,
        failure: &ProcessingFailureRecord,
        kind: &str,
        detail: &str,
    ) -> Result<()> {
        self.save_internal(job, kind, detail, ProcessingFailureMutation::Set(failure))
    }

    pub fn save_clearing_processing_failure(
        &mut self,
        job: &mut Job,
        kind: &str,
        detail: &str,
    ) -> Result<()> {
        self.save_internal(job, kind, detail, ProcessingFailureMutation::Clear)
    }

    fn save_internal(
        &mut self,
        job: &mut Job,
        kind: &str,
        detail: &str,
        failure: ProcessingFailureMutation<'_>,
    ) -> Result<()> {
        let old = job.revision;
        let mut next = job.clone();
        next.revision += 1;
        next.updated_at = Utc::now();
        let received_at = next
            .email
            .as_ref()
            .map(|email| email.received_at.timestamp());
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let persisted_state: String = tx
            .query_row(
                "SELECT state FROM items WHERE id=?1 AND revision=?2",
                params![next.id, sql_i64(old)?],
                |row| row.get(0),
            )
            .optional()?
            .context("Stale revision: reload the message before acting")?;
        let persisted_state = JobState::from_db(&persisted_state)
            .context("Database contains an unknown job state")?;
        ensure!(
            persisted_state.can_transition_to(next.state),
            "Illegal job-state transition: {} -> {}",
            persisted_state.db(),
            next.state.db()
        );
        let changed = tx.execute("UPDATE items SET state=?2,revision=?3,updated_at=?4,retry_at=?5,received_at=COALESCE(?6,received_at),payload=?7 WHERE id=?1 AND revision=?8", params![next.id, next.state.db(), sql_i64(next.revision)?, next.updated_at.timestamp(), next.retry_at, received_at, self.vault.seal(&format!("item/{}", next.id), &next)?, sql_i64(old)?])?;
        ensure!(
            changed == 1,
            "Stale revision: reload the message before acting"
        );

        match failure {
            ProcessingFailureMutation::Keep => {}
            ProcessingFailureMutation::Clear => {
                tx.execute(
                    "DELETE FROM processing_failures WHERE item_id=?1",
                    [&next.id],
                )?;
            }
            ProcessingFailureMutation::Set(record) => {
                ensure!(
                    record.attempts > 0,
                    "Processing-failure attempts must be positive"
                );
                ensure!(
                    record.occurred_at.timestamp() > 0,
                    "Processing-failure timestamp is invalid"
                );
                let payload = self
                    .vault
                    .seal(&format!("processing_failure/{}", next.id), record)?;
                tx.execute(
                    "INSERT INTO processing_failures(item_id,code,attempts,retry_exhausted,occurred_at,payload)
                     VALUES(?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(item_id) DO UPDATE SET
                        code=excluded.code,
                        attempts=excluded.attempts,
                        retry_exhausted=excluded.retry_exhausted,
                        occurred_at=excluded.occurred_at,
                        payload=excluded.payload",
                    params![
                        next.id,
                        record.code.as_str(),
                        record.attempts,
                        record.retry_exhausted,
                        record.occurred_at.timestamp(),
                        payload
                    ],
                )?;
            }
        }

        event(
            &tx,
            &self.vault,
            kind,
            Some(&next.id),
            detail,
            next.updated_at,
        )?;
        tx.commit()?;
        *job = next;
        Ok(())
    }
    pub fn list(
        &self,
        account: &str,
        review_only: bool,
        page: u32,
        limit: u32,
    ) -> Result<Vec<Job>> {
        let limit = limit.clamp(1, 100);
        let mut q = self.conn.prepare("SELECT id,payload,revision,state FROM items WHERE account_key=?1 AND (?2=0 OR state IN ('ready','attention')) ORDER BY COALESCE(received_at,created_at) DESC,id LIMIT ?3 OFFSET ?4")?;
        let rows = q.query_map(
            params![
                hash(account),
                review_only,
                sql_i64(u64::from(limit))?,
                sql_i64(u64::from(page) * u64::from(limit))?
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    row_get_u64(r, 2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )?;
        rows.map(|r| {
            let (id, b, rev, s) = r?;
            decode(&self.vault, &id, &b, rev, &s)
        })
        .collect()
    }
    /// Snapshot-consistent cursor feed for integrations.
    ///
    /// The first page captures the current maximum SQLite rowid for the account.
    /// Traversal is ordered only by immutable rowid and every continuation is
    /// bounded by that high-water mark. New inserts and later job hydration/state
    /// changes therefore cannot shift an in-progress feed.
    pub fn list_cursor(
        &self,
        account: &str,
        review_only: bool,
        cursor: Option<&ItemCursor>,
        limit: u32,
    ) -> Result<ItemCursorPage> {
        let limit = limit.clamp(1, 100);
        if let Some(cursor) = cursor {
            ensure!(
                cursor.snapshot_rowid >= 0
                    && cursor.last_rowid > 0
                    && cursor.last_rowid <= cursor.snapshot_rowid,
                "Invalid item cursor"
            );
        }
        let account_key = hash(account);
        let snapshot_rowid = match cursor {
            Some(cursor) => cursor.snapshot_rowid,
            None => self.conn.query_row(
                "SELECT COALESCE(MAX(rowid),0) FROM items WHERE account_key=?1",
                [&account_key],
                |row| row.get(0),
            )?,
        };
        if snapshot_rowid == 0 {
            return Ok(ItemCursorPage {
                items: Vec::new(),
                next_cursor: None,
            });
        }

        let before_rowid = cursor.map(|value| value.last_rowid);
        let mut statement = self.conn.prepare(
            "SELECT rowid,id,payload,revision,state
             FROM items
             WHERE account_key=?1
               AND rowid<=?2
               AND (?3=0 OR state IN ('ready','attention'))
               AND (?4 IS NULL OR rowid<?4)
             ORDER BY rowid DESC
             LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                account_key,
                snapshot_rowid,
                review_only,
                before_rowid,
                sql_i64(u64::from(limit) + 1)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row_get_u64(row, 3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )?;
        let mut raw = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        let has_more = raw.len() > limit as usize;
        if has_more {
            raw.truncate(limit as usize);
        }

        let next_cursor = if has_more {
            raw.last().map(|(rowid, _, _, _, _)| ItemCursor {
                snapshot_rowid,
                last_rowid: *rowid,
            })
        } else {
            None
        };
        let items = raw
            .into_iter()
            .map(|(rowid, id, payload, revision, state)| {
                ensure!(
                    rowid <= snapshot_rowid,
                    "Cursor feed escaped its snapshot high-water mark"
                );
                decode(&self.vault, &id, &payload, revision, &state)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ItemCursorPage { items, next_cursor })
    }

    pub fn next_queued(&self, account: &str, now: DateTime<Utc>) -> Result<Option<Job>> {
        let id: Option<String> = self.conn.query_row("SELECT id FROM items WHERE account_key=?1 AND state='queued' AND retry_at<=?2 ORDER BY created_at,id LIMIT 1", params![hash(account),now.timestamp()], |r| r.get(0)).optional()?;
        id.map(|id| self.get(&id)).transpose()
    }
    pub fn ready_ids(&self, account: &str) -> Result<Vec<String>> {
        let mut q = self.conn.prepare(
            "SELECT id FROM items WHERE account_key=?1 AND state='ready' ORDER BY COALESCE(received_at,created_at),id",
        )?;
        let rows = q.query_map([hash(account)], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
    pub fn wake_deferred(&mut self, account: &str) -> Result<usize> {
        let ids: Vec<String> = {
            let mut q = self
                .conn
                .prepare("SELECT id FROM items WHERE account_key=?1 AND state='deferred'")?;
            let r = q.query_map([hash(account)], |r| r.get(0))?;
            r.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for id in &ids {
            let mut j = self.get(id)?;
            j.state = JobState::Queued;
            j.retry_at = 0;
            j.attempts = 0;
            self.save(&mut j, "email.requeued", "Lookback expanded")?;
        }
        Ok(ids.len())
    }
    /// Remove actionable content that falls outside a newly tightened age window.
    /// Provider identities remain as deduplication tombstones and can be requeued if the
    /// lookback is expanded later.
    pub fn defer_review_outside_window(
        &mut self,
        account: &str,
        cutoff: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<usize> {
        let ids: Vec<String> = {
            let mut q = self.conn.prepare(
                "SELECT id FROM items WHERE account_key=?1 AND state IN ('ready','attention')",
            )?;
            let rows = q.query_map([hash(account)], |r| r.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut deferred = 0usize;
        for id in ids {
            let mut job = self.get(&id)?;
            let outside = job
                .email
                .as_ref()
                .is_some_and(|email| email.received_at < cutoff || email.received_at > now);
            if outside {
                job.state = JobState::Deferred;
                job.email = None;
                job.analysis = None;
                job.draft = None;
                job.drafted_at = None;
                job.retry_at = 0;
                job.flags = vec!["Outside selected age window; private content removed".into()];
                self.save_clearing_processing_failure(
                    &mut job,
                    "email.outside_window",
                    "Age window tightened; identity retained and private content removed",
                )?;
                deferred += 1;
            }
        }
        Ok(deferred)
    }

    pub fn processing_failure(&self, item_id: &str) -> Result<Option<ProcessingFailureRecord>> {
        let row: Option<(String, u32, bool, i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT code,attempts,retry_exhausted,occurred_at,payload
                 FROM processing_failures WHERE item_id=?1",
                [item_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(code, attempts, retry_exhausted, occurred_at, payload)| {
            let record: ProcessingFailureRecord = self
                .vault
                .open_value(&format!("processing_failure/{item_id}"), &payload)?;
            ensure!(
                record.code.as_str() == code
                    && record.attempts == attempts
                    && record.retry_exhausted == retry_exhausted
                    && record.occurred_at.timestamp() == occurred_at,
                "Processing-failure metadata does not match authenticated payload"
            );
            Ok(record)
        })
        .transpose()
    }

    pub fn processing_failure_summary(&self, account: &str) -> Result<ProcessingFailureSummary> {
        let mut summary = ProcessingFailureSummary::default();
        let mut query = self.conn.prepare(
            "SELECT f.code,COUNT(*),SUM(f.retry_exhausted)
             FROM processing_failures f
             JOIN items i ON i.id=f.item_id
             WHERE i.account_key=?1 AND i.state IN ('queued','attention')
             GROUP BY f.code ORDER BY f.code",
        )?;
        let rows = query.query_map([hash(account)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row_get_u64(row, 1)?,
                row_get_u64(row, 2)?,
            ))
        })?;
        for row in rows {
            let (code, count, exhausted) = row?;
            ensure!(
                ProcessingFailureCode::from_db(&code).is_some(),
                "Processing-failure summary encountered an unknown code"
            );
            summary.active_records = summary.active_records.saturating_add(count);
            summary.retry_exhausted = summary.retry_exhausted.saturating_add(exhausted);
            summary.by_code.insert(code, count);
        }
        Ok(summary)
    }

    pub fn counts(&self, account: &str) -> Result<Counts> {
        let mut c = Counts::default();
        let mut q = self
            .conn
            .prepare("SELECT state,COUNT(*) FROM items WHERE account_key=?1 GROUP BY state")?;
        let r = q.query_map([hash(account)], |r| {
            Ok((r.get::<_, String>(0)?, row_get_u64(r, 1)?))
        })?;
        for row in r {
            let (s, n) = row?;
            c.stored += n;
            match s.as_str() {
                "queued" => c.queued += n,
                "ready" | "attention" => c.review += n,
                "sent" => c.sent += n,
                "sending" | "uncertain" => c.uncertain += n,
                _ => (),
            }
        }
        c.attempts_24h = self.conn.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE attempt_at>=?1",
            [Utc::now().timestamp() - 86400],
            |r| row_get_u64(r, 0),
        )?;
        Ok(c)
    }
    pub fn thread_blocked(&self, key: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM deliveries WHERE thread_key=?1 AND status IN ('reserved','uncertain'))",
            [key],
            |r| r.get(0),
        )?)
    }

    /// Count recent durable send attempts to the same normalized reply mailbox.
    ///
    /// No recipient index is persisted. The global daily cap bounds this scan to
    /// a small set of encrypted rows and recent completed content is retained for
    /// much longer than 24 hours.
    pub fn recipient_attempts_24h(&self, snapshot: &Job, now: DateTime<Utc>) -> Result<u64> {
        let recipient = snapshot
            .email
            .as_ref()
            .context("Original message is required for recipient rate limiting")?
            .recipient()?;
        recipient_attempts_since(
            &self.conn,
            &self.vault,
            &recipient,
            now.timestamp() - 86_400,
        )
    }

    /// Backward-compatible manual/global-cap reservation API.
    pub fn reserve_send(&mut self, snapshot: &Job, limit: u16, now: DateTime<Utc>) -> Result<Job> {
        self.reserve_send_with_recipient_limit(snapshot, limit, None, now)
    }

    /// Reserve a send with an optional additional rolling recipient ceiling.
    ///
    /// Automatic dispatch uses this stronger path; the legacy public API above
    /// remains source-compatible for explicit Human Review/integrations.
    pub fn reserve_send_with_recipient_limit(
        &mut self,
        snapshot: &Job,
        limit: u16,
        recipient_limit: Option<u16>,
        now: DateTime<Utc>,
    ) -> Result<Job> {
        ensure!(snapshot.state.reviewable(), "Message is not reviewable");
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (b, r, s): (Vec<u8>, u64, String) = tx.query_row(
            "SELECT payload,revision,state FROM items WHERE id=?1",
            [&snapshot.id],
            |r| Ok((r.get(0)?, row_get_u64(r, 1)?, r.get(2)?)),
        )?;
        let mut j = decode(&self.vault, &snapshot.id, &b, r, &s)?;
        ensure!(
            j.revision == snapshot.revision && j.state == snapshot.state,
            "Send approval is stale"
        );
        let attempts: u64 = tx.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE attempt_at>=?1",
            [now.timestamp() - 86400],
            |r| row_get_u64(r, 0),
        )?;
        ensure!(
            attempts < u64::from(limit),
            "Rolling 24-hour attempt limit reached"
        );
        if let Some(recipient_limit) = recipient_limit {
            ensure!(
                (1..=100).contains(&recipient_limit),
                "Recipient attempt limit is outside the supported range"
            );
            let recipient = j
                .email
                .as_ref()
                .context("Original message is required for recipient rate limiting")?
                .recipient()?;
            let recipient_attempts =
                recipient_attempts_since(&tx, &self.vault, &recipient, now.timestamp() - 86_400)?;
            ensure!(
                recipient_attempts < u64::from(recipient_limit),
                "Automatic recipient 24-hour attempt limit reached"
            );
        }
        let item_taken: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM deliveries WHERE item_id=?1)",
            [&j.id],
            |r| r.get(0),
        )?;
        ensure!(
            !item_taken,
            "This rejection message already has a delivery record; it will not be sent twice"
        );
        let thread_blocked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM deliveries WHERE thread_key=?1 AND status IN ('reserved','uncertain'))",
            [j.stub.thread_key()],
            |r| r.get(0),
        )?;
        ensure!(
            !thread_blocked,
            "Conversation has an active or uncertain delivery; reconcile it before replying again"
        );
        tx.execute("INSERT INTO deliveries(item_id,thread_key,attempt_at,status) VALUES(?1,?2,?3,'reserved')",params![j.id,j.stub.thread_key(),now.timestamp()])?;
        j.state = JobState::Sending;
        j.revision += 1;
        j.updated_at = now;
        tx.execute(
            "UPDATE items SET state='sending',revision=?2,updated_at=?3,payload=?4 WHERE id=?1",
            params![
                j.id,
                sql_i64(j.revision)?,
                now.timestamp(),
                self.vault.seal(&format!("item/{}", j.id), &j)?
            ],
        )?;
        event(
            &tx,
            &self.vault,
            "delivery.reserved",
            Some(&j.id),
            "Durable reservation before network dispatch",
            now,
        )?;
        tx.commit()?;
        Ok(j)
    }
    pub fn release_unsent_reservation(&mut self, id: &str, detail: &str) -> Result<Job> {
        let mut job = self.get(id)?;
        ensure!(
            job.state == JobState::Sending,
            "No reserved send is available to cancel"
        );
        let original_state = job.state;
        let original_revision = job.revision;
        job.state = JobState::Attention;
        job.revision += 1;
        job.updated_at = Utc::now();
        job.flags.push(detail.into());
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute(
            "DELETE FROM deliveries WHERE item_id=?1 AND status='reserved'",
            [id],
        )?;
        ensure!(
            removed == 1,
            "Reserved delivery was not found; refusing to release conversation lock"
        );
        tx.execute(
            "UPDATE items SET state=?2,revision=?3,updated_at=?4,payload=?5 WHERE id=?1 AND state=?6 AND revision=?7",
            params![
                id,
                job.state.db(),
                sql_i64(job.revision)?,
                job.updated_at.timestamp(),
                self.vault.seal(&format!("item/{id}"), &job)?,
                original_state.db(),
                sql_i64(original_revision)?,
            ],
        )?;
        event(
            &tx,
            &self.vault,
            "delivery.rejected",
            Some(id),
            detail,
            job.updated_at,
        )?;
        tx.commit()?;
        Ok(job)
    }

    pub fn finish_send(&mut self, id: &str, provider_id: Option<String>) -> Result<Job> {
        let mut j = self.get(id)?;
        ensure!(
            matches!(j.state, JobState::Sending | JobState::Uncertain),
            "No unresolved delivery"
        );
        let original_state = j.state;
        let original_revision = j.revision;
        j.state = if provider_id.is_some() {
            JobState::Sent
        } else {
            JobState::Uncertain
        };
        j.provider_sent_id = provider_id;
        j.revision += 1;
        j.updated_at = Utc::now();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let encrypted = j
            .provider_sent_id
            .as_ref()
            .map(|p| self.vault.seal(&format!("delivery/{id}"), p))
            .transpose()?;
        let deliveries_changed = tx.execute(
            "UPDATE deliveries SET status=?2,provider_id=?3 WHERE item_id=?1",
            params![id, j.state.db(), encrypted],
        )?;
        ensure!(
            deliveries_changed == 1,
            "Delivery record was not updated; state or item may have changed"
        );
        let items_changed = tx.execute(
            "UPDATE items SET state=?2,revision=?3,updated_at=?4,payload=?5 WHERE id=?1 AND state=?6 AND revision=?7",
            params![
                id,
                j.state.db(),
                sql_i64(j.revision)?,
                j.updated_at.timestamp(),
                self.vault.seal(&format!("item/{id}"), &j)?,
                original_state.db(),
                sql_i64(original_revision)?,
            ],
        )?;
        ensure!(
            items_changed == 1,
            "Item record was not updated; concurrent modification detected"
        );
        event(
            &tx,
            &self.vault,
            if j.state == JobState::Sent {
                "delivery.sent"
            } else {
                "delivery.uncertain"
            },
            Some(id),
            "Message-level delivery record retained; uncertain thread remains blocked",
            j.updated_at,
        )?;
        tx.commit()?;
        Ok(j)
    }
    pub fn has_dispatch_attempt_event(&self, item_id: &str) -> Result<bool> {
        let mut statement = self
            .conn
            .prepare("SELECT event_id, payload FROM events ORDER BY seq DESC")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let event_id: String = row.get(0)?;
            let payload: Vec<u8> = row.get(1)?;
            let e: AuditEvent = self
                .vault
                .open_value(&format!("event/{event_id}"), &payload)?;
            if e.item_id.as_deref() == Some(item_id) {
                if e.kind == "delivery.dispatch_attempt" {
                    return Ok(true);
                }
                if e.kind == "delivery.reserved" {
                    return Ok(false);
                }
            }
        }
        Ok(false)
    }

    pub fn recover_interrupted_sends(&mut self) -> Result<usize> {
        let ids: Vec<String> = {
            let mut q = self
                .conn
                .prepare("SELECT id FROM items WHERE state='sending'")?;
            let r = q.query_map([], |r| r.get(0))?;
            r.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for id in &ids {
            if self.has_dispatch_attempt_event(id)? {
                self.finish_send(id, None)?;
            } else {
                self.release_unsent_reservation(
                    id,
                    "Recovered never-dispatched reservation after interruption; released to Attention",
                )?;
            }
        }
        Ok(ids.len())
    }
    fn page_stats(&self) -> Result<(u64, u64, u64)> {
        let page_count: u64 = self
            .conn
            .query_row("PRAGMA page_count", [], |row| row_get_u64(row, 0))?;
        let freelist_count: u64 = self
            .conn
            .query_row("PRAGMA freelist_count", [], |row| row_get_u64(row, 0))?;
        let page_size: u64 = self
            .conn
            .query_row("PRAGMA page_size", [], |row| row_get_u64(row, 0))?;
        Ok((page_count, freelist_count, page_size))
    }

    /// Reclaim free SQLite pages under the exclusive workspace writer.
    ///
    /// This is storage maintenance, not secure erasure. Application payloads
    /// remain encrypted, and SSD/controller remapping remains outside SQLite's
    /// guarantees.
    pub fn compact(&mut self) -> Result<DatabaseCompactionReport> {
        self.readiness_check()?;
        let (before_page_count, before_freelist_count, page_size_bytes) = self.page_stats()?;
        self.conn.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
             VACUUM;
             PRAGMA optimize;",
        )?;
        let (after_page_count, after_freelist_count, after_page_size) = self.page_stats()?;
        ensure!(
            page_size_bytes == after_page_size,
            "SQLite page size changed unexpectedly during compaction"
        );
        let report = DatabaseCompactionReport {
            schema_version: 1,
            before_page_count,
            before_freelist_count,
            after_page_count,
            after_freelist_count,
            page_size_bytes,
        };
        self.log(
            "database.compacted",
            None,
            &format!(
                "SQLite compaction completed: pages {}->{}, freelist {}->{}",
                before_page_count, after_page_count, before_freelist_count, after_freelist_count
            ),
        )?;
        self.readiness_check()?;
        Ok(report)
    }

    pub fn log(&mut self, kind: &str, item: Option<&str>, detail: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        event(&tx, &self.vault, kind, item, detail, Utc::now())?;
        tx.commit()?;
        Ok(())
    }
    pub fn latest_event_seq(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(seq),0) FROM events", [], |r| r.get(0))?)
    }
    pub fn events(&self, after: i64, limit: u32) -> Result<Vec<AuditEvent>> {
        let mut q = self.conn.prepare(
            "SELECT seq,event_id,payload FROM events WHERE seq>?1 ORDER BY seq LIMIT ?2",
        )?;
        let rows = q.query_map(params![after, limit.clamp(1, 500)], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        rows.map(|r| {
            let (seq, id, b) = r?;
            let mut e: AuditEvent = self.vault.open_value(&format!("event/{id}"), &b)?;
            e.seq = seq;
            Ok(e)
        })
        .collect()
    }
    /// Prune message content while retaining deduplication and delivery identities.
    pub fn purge(&mut self, days: u16) -> Result<usize> {
        ensure!((30..=3650).contains(&days), "Invalid retention");
        let before = (Utc::now() - chrono::Duration::days(i64::from(days))).timestamp();
        let ids: Vec<String> = {
            let mut q=self.conn.prepare("SELECT id FROM items WHERE state IN ('sent','dismissed','other') AND updated_at<?1")?;
            let r = q.query_map([before], |r| r.get(0))?;
            r.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut n = 0;
        for id in ids {
            let mut j = self.get(&id)?;
            if j.email.is_some() || j.draft.is_some() || j.analysis.is_some() {
                j.email = None;
                j.draft = None;
                j.analysis = None;
                j.drafted_at = None;
                j.attempts = 0;
                j.retry_at = 0;
                j.flags = vec!["Private content pruned; delivery identity retained".into()];
                self.save(&mut j, "content.pruned", "Retention policy")?;
                n += 1;
            }
        }
        self.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)")?;
        Ok(n)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn stub(id: &str, t: &str) -> Stub {
        Stub {
            account: "me@example.com".into(),
            provider_id: id.into(),
            thread_id: t.into(),
            source: Source::Gmail,
        }
    }
    fn ready(db: &mut Store, id: &str, t: &str) -> Job {
        let s = stub(id, t);
        let key = s.id();
        db.insert_stub(s, Utc::now()).unwrap();
        let mut j = db.get(&key).unwrap();
        j.state = JobState::Ready;
        db.save(&mut j, "test", "ready").unwrap();
        j
    }
    #[test]
    fn batch_insert_only_stores_missing_identities() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let now = Utc::now();
        assert_eq!(
            db.insert_stubs(vec![stub("a", "ta"), stub("b", "tb"), stub("a", "ta")], now,)
                .unwrap(),
            2
        );
        assert_eq!(
            db.insert_stubs(vec![stub("a", "ta"), stub("b", "tb")], now)
                .unwrap(),
            0
        );
        assert_eq!(db.counts("me@example.com").unwrap().stored, 2);
        assert_eq!(
            db.events(0, 100)
                .unwrap()
                .into_iter()
                .filter(|e| e.kind == "email.queued")
                .count(),
            2
        );
    }

    #[test]
    fn tightened_window_defers_and_clears_private_content() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let now = Utc::now();
        let identity = stub("old", "thread-old");
        let id = identity.id();
        db.insert_stub(identity, now).unwrap();
        let mut job = db.get(&id).unwrap();
        let mut email = crate::ollama::sample_email("Old rejection", "We will not proceed.");
        email.stub = job.stub.clone();
        email.received_at = now - chrono::Duration::days(10);
        job.email = Some(email);
        job.draft = Some(Draft {
            body: "Please provide specific feedback on the assessment.".into(),
            origin: "test".into(),
        });
        job.drafted_at = Some(now);
        job.state = JobState::Ready;
        db.save(&mut job, "test", "reviewable").unwrap();

        assert_eq!(
            db.defer_review_outside_window("me@example.com", now - chrono::Duration::days(1), now,)
                .unwrap(),
            1
        );
        let deferred = db.get(&id).unwrap();
        assert_eq!(deferred.state, JobState::Deferred);
        assert!(deferred.email.is_none());
        assert!(deferred.draft.is_none());
        assert!(deferred.analysis.is_none());
        assert!(deferred.drafted_at.is_none());
        assert!(db.list("me@example.com", true, 0, 25).unwrap().is_empty());
    }

    #[test]
    fn new_database_creates_schema_and_vault_marker_together() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let vault = Vault::random();
        let db = Store::open(&path, vault).unwrap();
        assert_eq!(
            db.meta::<String>("vault_check").unwrap(),
            Some("rejection-rejector:v1".into())
        );
        drop(db);
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, DATABASE_SCHEMA_VERSION);
        let markers: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM meta WHERE name='vault_check'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(markers, 1);
    }

    #[test]
    fn existing_database_without_vault_marker_is_never_adopted() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta(name TEXT PRIMARY KEY,payload BLOB NOT NULL);
                 CREATE TABLE items(id TEXT PRIMARY KEY,account_key TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,payload BLOB NOT NULL);
                 CREATE TABLE deliveries(thread_key TEXT PRIMARY KEY,item_id TEXT UNIQUE NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                 CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL);
                 PRAGMA user_version=1;",
            )
            .unwrap();
        }
        assert!(Store::open(&path, Vault::random()).is_err());
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let markers: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM meta WHERE name='vault_check'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(markers, 0);
    }

    #[test]
    fn wrong_key_cannot_mutate_a_pending_schema_migration() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let good = Vault::random();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE meta(name TEXT PRIMARY KEY,payload BLOB NOT NULL);
                CREATE TABLE items(id TEXT PRIMARY KEY,account_key TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,payload BLOB NOT NULL);
                CREATE TABLE deliveries(thread_key TEXT PRIMARY KEY,item_id TEXT UNIQUE NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL);
                PRAGMA user_version=1;").unwrap();
            conn.execute(
                "INSERT INTO meta(name,payload) VALUES('vault_check',?1)",
                [good
                    .seal("meta/vault_check", &"rejection-rejector:v1")
                    .unwrap()],
            )
            .unwrap();
        }
        assert!(Store::open(&path, Vault::random()).is_err());
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 1);
        let mut columns = conn.prepare("PRAGMA table_info(items)").unwrap();
        let names = columns
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(!names.iter().any(|name| name == "received_at"));
    }

    #[test]
    fn cursor_feed_is_snapshot_consistent_across_concurrent_inserts() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let base = Utc::now() - chrono::Duration::minutes(10);
        for index in 0..5 {
            db.insert_stub(
                stub(&format!("cursor-{index}"), &format!("thread-{index}")),
                base + chrono::Duration::seconds(index),
            )
            .unwrap();
        }

        let first = db.list_cursor("me@example.com", false, None, 2).unwrap();
        assert_eq!(first.items.len(), 2);
        let cursor = first
            .next_cursor
            .clone()
            .expect("first page should continue");
        let first_ids: std::collections::BTreeSet<_> =
            first.items.iter().map(|job| job.id.clone()).collect();

        db.insert_stub(stub("cursor-new-arrival", "thread-new-arrival"), Utc::now())
            .unwrap();

        // Mutate an existing unseen row's received_at/state between requests.
        // Immutable-rowid ordering must keep traversal stable despite the update.
        let target_id = stub("cursor-1", "thread-1").id();
        let mut target = db.get(&target_id).unwrap();
        let mut hydrated = crate::ollama::sample_email("Hydrated", "Rejected");
        hydrated.stub = target.stub.clone();
        hydrated.received_at = Utc::now() + chrono::Duration::days(30);
        target.email = Some(hydrated);
        target.state = JobState::Ready;
        db.save(&mut target, "test", "hydrate during cursor traversal")
            .unwrap();

        let second = db
            .list_cursor("me@example.com", false, Some(&cursor), 2)
            .unwrap();
        assert_eq!(second.items.len(), 2);
        assert!(second.items.iter().all(|job| !first_ids.contains(&job.id)));
        assert!(
            second
                .items
                .iter()
                .all(|job| job.stub.provider_id != "cursor-new-arrival")
        );

        let third = db
            .list_cursor("me@example.com", false, second.next_cursor.as_ref(), 2)
            .unwrap();
        assert_eq!(third.items.len(), 1);
        assert!(third.next_cursor.is_none());
        assert!(
            third
                .items
                .iter()
                .all(|job| job.stub.provider_id != "cursor-new-arrival")
        );

        let fresh = db.list_cursor("me@example.com", false, None, 10).unwrap();
        assert!(
            fresh
                .items
                .iter()
                .any(|job| job.stub.provider_id == "cursor-new-arrival")
        );
    }

    #[test]
    fn review_queue_orders_by_email_received_time() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let now = Utc::now();
        for (provider, days) in [("older", 3), ("newer", 1)] {
            let identity = stub(provider, provider);
            let id = identity.id();
            db.insert_stub(identity, now).unwrap();
            let mut job = db.get(&id).unwrap();
            let mut email = crate::ollama::sample_email(provider, "Rejected");
            email.stub = job.stub.clone();
            email.received_at = now - chrono::Duration::days(days);
            job.email = Some(email);
            job.state = JobState::Ready;
            db.save(&mut job, "test", "ready").unwrap();
        }
        let jobs = db.list("me@example.com", true, 0, 25).unwrap();
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].stub.provider_id, "newer");
        assert_eq!(jobs[1].stub.provider_id, "older");
    }

    #[test]
    fn schema_v1_migrates_received_time_index() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let vault = Vault::random();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE meta(name TEXT PRIMARY KEY,payload BLOB NOT NULL);
                CREATE TABLE items(id TEXT PRIMARY KEY,account_key TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,payload BLOB NOT NULL);
                CREATE TABLE deliveries(thread_key TEXT PRIMARY KEY,item_id TEXT UNIQUE NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL);
                PRAGMA user_version=1;").unwrap();
            conn.execute(
                "INSERT INTO meta(name,payload) VALUES('vault_check',?1)",
                [vault
                    .seal("meta/vault_check", &"rejection-rejector:v1")
                    .unwrap()],
            )
            .unwrap();
        }
        let mut db = Store::open(&path, vault).unwrap();
        assert!(
            db.insert_stub(stub("after-migration", "thread"), Utc::now())
                .unwrap()
        );
    }

    #[test]
    fn legacy_schema_migration_preserves_verified_pre_migration_image() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("state.sqlite3");
        let vault = Vault::random();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta(name TEXT PRIMARY KEY,payload BLOB NOT NULL);
                 CREATE TABLE items(id TEXT PRIMARY KEY,account_key TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL,received_at INTEGER,updated_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,payload BLOB NOT NULL);
                 CREATE INDEX items_queue ON items(account_key,state,retry_at,created_at);
                 CREATE INDEX items_review_order ON items(account_key,state,received_at,created_at);
                 CREATE TABLE deliveries(thread_key TEXT PRIMARY KEY,item_id TEXT UNIQUE NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                 CREATE INDEX deliveries_time ON deliveries(attempt_at);
                 CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL);
                 PRAGMA user_version=2;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO meta(name,payload) VALUES('vault_check',?1)",
                [vault
                    .seal("meta/vault_check", &"rejection-rejector:v1")
                    .unwrap()],
            )
            .unwrap();
        }

        let db = Store::open(&path, vault).unwrap();
        assert_eq!(db.schema_version().unwrap(), DATABASE_SCHEMA_VERSION);

        let migration_dir = d.path().join("recovery").join("migrations");
        let backups = std::fs::read_dir(&migration_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        let backup =
            Connection::open_with_flags(&backups[0], rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let backed_up_version: i64 = backup
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(backed_up_version, 2);
        assert!(
            db.events(0, 100)
                .unwrap()
                .iter()
                .any(|event| event.kind == "database.migrated")
        );
    }

    #[test]
    fn schema_v2_delivery_records_migrate_to_message_level_keys() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let vault = Vault::random();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta(name TEXT PRIMARY KEY,payload BLOB NOT NULL);
                 CREATE TABLE items(id TEXT PRIMARY KEY,account_key TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL,received_at INTEGER,updated_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,payload BLOB NOT NULL);
                 CREATE INDEX items_queue ON items(account_key,state,retry_at,created_at);
                 CREATE INDEX items_review_order ON items(account_key,state,received_at,created_at);
                 CREATE TABLE deliveries(thread_key TEXT PRIMARY KEY,item_id TEXT UNIQUE NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                 CREATE INDEX deliveries_time ON deliveries(attempt_at);
                 CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL);
                 PRAGMA user_version=2;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO meta(name,payload) VALUES('vault_check',?1)",
                [vault
                    .seal("meta/vault_check", &"rejection-rejector:v1")
                    .unwrap()],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO deliveries(thread_key,item_id,attempt_at,status) VALUES(?1,?2,?3,'sent')",
                ["thread-key", "old-item", "1"],
            )
            .unwrap();
        }
        let db = Store::open(&path, vault).unwrap();
        let version: i64 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, DATABASE_SCHEMA_VERSION);
        let row: (String, String) = db
            .conn
            .query_row(
                "SELECT item_id,status FROM deliveries WHERE item_id='old-item'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row, ("old-item".into(), "sent".into()));
        assert!(!db.thread_blocked("thread-key").unwrap());
    }

    #[test]
    fn schema_v3_backfills_and_verifies_audit_chain() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let vault = Vault::random();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE meta(name TEXT PRIMARY KEY,payload BLOB NOT NULL);
                 CREATE TABLE items(id TEXT PRIMARY KEY,account_key TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL,received_at INTEGER,updated_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,payload BLOB NOT NULL);
                 CREATE INDEX items_queue ON items(account_key,state,retry_at,created_at);
                 CREATE INDEX items_review_order ON items(account_key,state,received_at,created_at);
                 CREATE TABLE deliveries(item_id TEXT PRIMARY KEY,thread_key TEXT NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                 CREATE INDEX deliveries_time ON deliveries(attempt_at);
                 CREATE INDEX deliveries_thread_state ON deliveries(thread_key,status);
                 CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL);
                 PRAGMA user_version=3;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO meta(name,payload) VALUES('vault_check',?1)",
                [vault
                    .seal("meta/vault_check", &"rejection-rejector:v1")
                    .unwrap()],
            )
            .unwrap();
            let event_id = "legacy-event";
            let legacy = AuditEvent {
                seq: 0,
                at: Utc::now(),
                kind: "legacy.test".into(),
                domain: AuditDomain::Other,
                severity: AuditSeverity::Info,
                item_id: None,
                detail: "historical encrypted event".into(),
            };
            conn.execute(
                "INSERT INTO events(event_id,payload) VALUES(?1,?2)",
                params![
                    event_id,
                    vault.seal(&format!("event/{event_id}"), &legacy).unwrap()
                ],
            )
            .unwrap();
        }

        let db = Store::open(&path, vault).unwrap();
        assert_eq!(db.schema_version().unwrap(), DATABASE_SCHEMA_VERSION);
        db.verify_audit_chain().unwrap();
        let events = db.events(0, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "legacy.test");
        assert_eq!(events[1].kind, "database.migrated");
        assert_eq!(events[1].domain, AuditDomain::Storage);
    }

    #[test]
    fn audit_chain_detects_ciphertext_tampering() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        db.log("audit.first", None, "first").unwrap();
        db.log("audit.second", None, "second").unwrap();
        db.verify_audit_chain().unwrap();

        let mut payload: Vec<u8> = db
            .conn
            .query_row(
                "SELECT payload FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let midpoint = payload.len() / 2;
        payload[midpoint] ^= 0x01;
        db.conn
            .execute(
                "UPDATE events SET payload=?1 WHERE seq=(SELECT MAX(seq) FROM events)",
                [payload],
            )
            .unwrap();
        assert!(db.verify_audit_chain().is_err());
        assert!(db.integrity_check().is_err());
    }

    #[test]
    fn audit_chain_detects_tail_truncation() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        db.log("audit.first", None, "first").unwrap();
        db.log("audit.second", None, "second").unwrap();
        db.verify_audit_chain().unwrap();

        db.conn
            .execute(
                "DELETE FROM events WHERE seq=(SELECT MAX(seq) FROM events)",
                [],
            )
            .unwrap();
        assert!(db.verify_audit_chain().is_err());
    }

    #[test]
    fn bounded_readiness_and_deep_integrity_both_pass_on_healthy_store() {
        let d = tempfile::tempdir().unwrap();
        let db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        db.readiness_check().unwrap();
        db.integrity_check().unwrap();
        assert_eq!(db.schema_version().unwrap(), DATABASE_SCHEMA_VERSION);
    }

    #[test]
    fn related_metadata_changes_are_committed_together() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        db.set_meta("old", &"remove-me").unwrap();
        db.change_meta(
            &[
                ("first", serde_json::json!({"value": 1})),
                ("second", serde_json::json!("two")),
            ],
            &["old"],
            "meta.test",
            "Atomic metadata test",
        )
        .unwrap();
        assert_eq!(
            db.meta::<serde_json::Value>("first").unwrap(),
            Some(serde_json::json!({"value": 1}))
        );
        assert_eq!(db.meta::<String>("second").unwrap(), Some("two".into()));
        assert!(db.meta::<String>("old").unwrap().is_none());
        assert!(
            db.events(0, 100)
                .unwrap()
                .iter()
                .any(|event| event.kind == "meta.test")
        );
    }

    #[test]
    fn schema_v4_migrates_processing_failure_metadata() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db");
        let vault = Vault::random();
        {
            let db = Store::open(&path, vault.clone()).unwrap();
            db.conn
                .execute_batch("DROP TABLE processing_failures; PRAGMA user_version=4;")
                .unwrap();
        }
        let db = Store::open(&path, vault).unwrap();
        assert_eq!(db.schema_version().unwrap(), 5);
        let exists: bool = db
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='processing_failures')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists);
    }

    #[test]
    fn processing_failure_metadata_is_authenticated_and_does_not_block_later_mail() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let now = Utc::now();
        let first_stub = stub("poison", "poison-thread");
        let first_id = first_stub.id();
        db.insert_stub(first_stub, now - chrono::Duration::seconds(2))
            .unwrap();
        let second_stub = stub("healthy", "healthy-thread");
        let second_id = second_stub.id();
        db.insert_stub(second_stub, now - chrono::Duration::seconds(1))
            .unwrap();

        let mut first = db.get(&first_id).unwrap();
        first.attempts = 1;
        first.retry_at = now.timestamp() + 3600;
        let failure = ProcessingFailureRecord {
            code: ProcessingFailureCode::Classification,
            attempts: 1,
            retry_exhausted: false,
            occurred_at: now,
        };
        db.save_processing_failure(
            &mut first,
            &failure,
            "analysis.retry_scheduled",
            "Synthetic poison-message isolation",
        )
        .unwrap();

        assert_eq!(db.processing_failure(&first_id).unwrap(), Some(failure));
        let summary = db.processing_failure_summary("me@example.com").unwrap();
        assert_eq!(summary.active_records, 1);
        assert_eq!(summary.retry_exhausted, 0);
        assert_eq!(summary.by_code.get("classification"), Some(&1));
        assert_eq!(
            db.next_queued("me@example.com", now).unwrap().unwrap().id,
            second_id
        );
        db.integrity_check().unwrap();

        db.conn
            .execute(
                "UPDATE processing_failures SET code='draft_generation' WHERE item_id=?1",
                [&first_id],
            )
            .unwrap();
        assert!(db.integrity_check().is_err());
    }

    #[test]
    fn dedup_and_stale_revisions() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let s = stub("one", "t");
        assert!(db.insert_stub(s.clone(), Utc::now()).unwrap());
        assert!(!db.insert_stub(s.clone(), Utc::now()).unwrap());
        let mut a = db.get(&s.id()).unwrap();
        let mut b = a.clone();
        db.save(&mut a, "test", "first").unwrap();
        assert!(db.save(&mut b, "test", "stale").is_err());
    }
    #[test]
    fn save_rejects_illegal_persisted_state_transitions() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let id = stub("state-machine", "thread").id();
        db.insert_stub(stub("state-machine", "thread"), Utc::now())
            .unwrap();

        let mut job = db.get(&id).unwrap();
        job.state = JobState::Sent;
        assert!(db.save(&mut job, "test", "illegal jump").is_err());
        assert_eq!(db.get(&id).unwrap().state, JobState::Queued);

        let mut job = db.get(&id).unwrap();
        job.state = JobState::Ready;
        db.save(&mut job, "test", "legal analysis result").unwrap();
        let mut terminal = db.get(&id).unwrap();
        terminal.state = JobState::Dismissed;
        db.save(&mut terminal, "test", "legal dismissal").unwrap();

        let mut reopen = db.get(&id).unwrap();
        reopen.state = JobState::Ready;
        assert!(db.save(&mut reopen, "test", "illegal reopen").is_err());
        assert_eq!(db.get(&id).unwrap().state, JobState::Dismissed);
    }

    #[test]
    fn crash_never_releases_reservation() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::random();
        let p = d.path().join("db");
        let mut db = Store::open(&p, v.clone()).unwrap();
        let a = ready(&mut db, "a", "same-a");
        db.reserve_send(&a, 10, Utc::now()).unwrap();
        drop(db);
        let mut db = Store::open(&p, v).unwrap();
        assert_eq!(db.recover_interrupted_sends().unwrap(), 1);
        assert_eq!(db.get(&a.id).unwrap().state, JobState::Attention);
        assert!(!db.thread_blocked(&a.stub.thread_key()).unwrap());
    }

    #[test]
    fn never_dispatched_reservation_releases_to_attention_with_audit_and_no_delivery_row() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::random();
        let p = d.path().join("db");
        let mut db = Store::open(&p, v.clone()).unwrap();
        let a = ready(&mut db, "never-dispatched", "nd-thread");
        db.reserve_send(&a, 10, Utc::now()).unwrap();
        assert_eq!(
            db.conn
                .query_row(
                    "SELECT status FROM deliveries WHERE item_id=?1",
                    [&a.id],
                    |r| r.get::<usize, String>(0),
                )
                .unwrap(),
            "reserved"
        );
        drop(db);
        let mut db = Store::open(&p, v).unwrap();
        assert_eq!(db.recover_interrupted_sends().unwrap(), 1);
        let restored = db.get(&a.id).unwrap();
        assert_eq!(restored.state, JobState::Attention);
        assert!(
            restored.flags.iter().any(|f| {
                f.contains("Recovered never-dispatched reservation after interruption")
            })
        );
        let delivery_row_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM deliveries WHERE item_id=?1",
                [&a.id],
                |r| r.get::<usize, i64>(0),
            )
            .unwrap();
        assert_eq!(delivery_row_count, 0);
        let events = db.events(0, 1000).unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.kind == "delivery.rejected" && e.item_id.as_deref() == Some(&a.id))
        );
        assert!(!db.thread_blocked(&a.stub.thread_key()).unwrap());
    }

    #[test]
    fn dispatch_attempt_event_keeps_reservation_uncertain_on_restart() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::random();
        let p = d.path().join("db");
        let mut db = Store::open(&p, v.clone()).unwrap();
        let a = ready(&mut db, "maybe-dispatched", "md-thread");
        db.reserve_send(&a, 10, Utc::now()).unwrap();
        db.log(
            "delivery.dispatch_attempt",
            Some(&a.id),
            "Initiating provider network request",
        )
        .unwrap();
        drop(db);
        let mut db = Store::open(&p, v).unwrap();
        assert_eq!(db.recover_interrupted_sends().unwrap(), 1);
        assert_eq!(db.get(&a.id).unwrap().state, JobState::Uncertain);
        assert!(db.thread_blocked(&a.stub.thread_key()).unwrap());
    }

    #[test]
    fn definite_provider_rejection_releases_reservation_for_review() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let first = ready(&mut db, "first", "same-thread");
        let second = ready(&mut db, "second", "same-thread");
        db.reserve_send(&first, 10, Utc::now()).unwrap();
        let restored = db
            .release_unsent_reservation(&first.id, "Synthetic HTTP 403")
            .unwrap();
        assert_eq!(restored.state, JobState::Attention);
        assert!(!db.thread_blocked(&first.stub.thread_key()).unwrap());
        db.reserve_send(&second, 10, Utc::now()).unwrap();
    }

    #[test]
    fn known_unsent_cancellation_does_not_become_uncertain() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let candidate = ready(&mut db, "cancelled", "cancelled-thread");
        db.reserve_send(&candidate, 10, Utc::now()).unwrap();
        let restored = db
            .release_unsent_reservation(&candidate.id, "Synthetic pause before network dispatch")
            .unwrap();
        assert_eq!(restored.state, JobState::Attention);
        assert_eq!(db.counts("me@example.com").unwrap().uncertain, 0);
        assert!(!db.thread_blocked(&candidate.stub.thread_key()).unwrap());
    }

    #[test]
    fn a_sent_reply_does_not_block_a_later_distinct_rejection_in_the_same_thread() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let first = ready(&mut db, "first-rejection", "same-thread");
        let later = ready(&mut db, "later-rejection", "same-thread");
        db.reserve_send(&first, 10, Utc::now()).unwrap();
        db.finish_send(&first.id, Some("gmail-sent-id".into()))
            .unwrap();
        assert!(!db.thread_blocked(&first.stub.thread_key()).unwrap());
        db.reserve_send(&later, 10, Utc::now()).unwrap();
    }

    #[test]
    fn automatic_recipient_limit_is_transactional() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let now = Utc::now();

        let mut first = ready(&mut db, "recipient-a", "thread-a");
        let mut second = ready(&mut db, "recipient-b", "thread-b");
        let mut third = ready(&mut db, "recipient-c", "thread-c");
        for job in [&mut first, &mut second, &mut third] {
            let mut email =
                crate::ollama::sample_email("Synthetic rejection", "We are not moving forward.");
            email.stub = job.stub.clone();
            email.from = "recruiter@example.com".into();
            email.reply_to = None;
            job.email = Some(email);
            db.save(job, "test", "Normalize recipient for burst-limit test")
                .unwrap();
        }

        assert_eq!(db.recipient_attempts_24h(&first, now).unwrap(), 0);
        db.reserve_send_with_recipient_limit(&first, 10, Some(2), now)
            .unwrap();
        assert_eq!(db.recipient_attempts_24h(&second, now).unwrap(), 1);
        db.finish_send(&first.id, Some("provider-a".into()))
            .unwrap();

        db.reserve_send_with_recipient_limit(&second, 10, Some(2), now)
            .unwrap();
        db.finish_send(&second.id, Some("provider-b".into()))
            .unwrap();
        assert_eq!(db.recipient_attempts_24h(&third, now).unwrap(), 2);
        assert!(
            db.reserve_send_with_recipient_limit(&third, 10, Some(2), now)
                .is_err()
        );

        // Human Review can still make an explicit operator decision.
        db.reserve_send(&third, 10, now).unwrap();
    }

    #[test]
    fn cap_counts_uncertain_attempts() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let a = ready(&mut db, "a", "a");
        let b = ready(&mut db, "b", "b");
        db.reserve_send(&a, 1, Utc::now()).unwrap();
        db.finish_send(&a.id, None).unwrap();
        assert!(db.reserve_send(&b, 1, Utc::now()).is_err());
    }
    #[test]
    fn retention_prunes_private_processing_state_but_keeps_identity() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let identity = stub("retained-id", "retained-thread");
        let id = identity.id();
        let old = Utc::now() - chrono::Duration::days(100);
        db.insert_stub(identity, old).unwrap();
        let mut job = db.get(&id).unwrap();
        job.state = JobState::Ready;
        job.email = Some(crate::ollama::sample_email(
            "Private subject",
            "Private body",
        ));
        job.draft = Some(Draft {
            body: "Private draft with enough content for retention testing.".into(),
            origin: "human".into(),
        });
        job.drafted_at = Some(old);
        job.attempts = 2;
        job.retry_at = old.timestamp();
        db.save(&mut job, "test", "old reviewable content").unwrap();
        job.state = JobState::Dismissed;
        db.save(&mut job, "test", "old completed content").unwrap();
        db.conn
            .execute(
                "UPDATE items SET updated_at=?2 WHERE id=?1",
                params![id, old.timestamp()],
            )
            .unwrap();
        assert_eq!(db.purge(30).unwrap(), 1);
        let pruned = db.get(&id).unwrap();
        assert_eq!(pruned.stub.provider_id, "retained-id");
        assert!(pruned.email.is_none());
        assert!(pruned.draft.is_none());
        assert!(pruned.analysis.is_none());
        assert!(pruned.drafted_at.is_none());
        assert_eq!(pruned.attempts, 0);
        assert_eq!(pruned.retry_at, 0);
    }

    #[test]
    fn incremental_audit_extension_verifies_only_new_suffix_semantics() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        db.log("test.anchor", None, "trusted point").unwrap();
        let (sequence, head) = db.audit_point().unwrap();

        db.log("test.after_anchor", None, "one").unwrap();
        db.log("test.after_anchor", None, "two").unwrap();
        let (latest_sequence, latest_head) = db.verify_audit_extension(sequence, &head).unwrap();
        assert!(latest_sequence > sequence);
        assert_eq!(latest_head, db.audit_head().unwrap());

        db.conn
            .execute(
                "UPDATE events SET prev_hash=?2 WHERE seq=?1",
                params![latest_sequence, AUDIT_GENESIS],
            )
            .unwrap();
        assert!(db.verify_audit_extension(sequence, &head).is_err());
    }

    #[test]
    fn deep_integrity_rejects_semantically_impossible_delivery_state() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let candidate = ready(&mut db, "semantic", "semantic-thread");
        db.reserve_send(&candidate, 10, Utc::now()).unwrap();
        db.integrity_check().unwrap();

        db.conn
            .execute(
                "UPDATE deliveries SET status='sent' WHERE item_id=?1",
                [&candidate.id],
            )
            .unwrap();
        assert!(db.readiness_check().is_ok());
        assert!(db.integrity_check().is_err());
    }

    #[test]
    fn deep_integrity_rejects_delivery_thread_identity_mismatch() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let candidate = ready(&mut db, "semantic-thread", "real-thread");
        db.reserve_send(&candidate, 10, Utc::now()).unwrap();
        db.conn
            .execute(
                "UPDATE deliveries SET thread_key='forged-thread' WHERE item_id=?1",
                [&candidate.id],
            )
            .unwrap();
        assert!(db.integrity_check().is_err());
    }

    #[test]
    fn secret_not_in_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        db.set_meta("oauth", &"REFRESH_TOKEN_SENTINEL").unwrap();
        db.insert_stub(stub("message123", "thread123"), Utc::now())
            .unwrap();
        drop(db);
        for entry in std::fs::read_dir(d.path()).unwrap() {
            let b = std::fs::read(entry.unwrap().path()).unwrap();
            for needle in ["REFRESH_TOKEN_SENTINEL", "me@example.com", "message123"] {
                assert!(!b.windows(needle.len()).any(|w| w == needle.as_bytes()));
            }
        }
    }
    #[test]
    fn deep_backup_verification_detects_ciphertext_corruption_inside_valid_sqlite() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.sqlite3");
        let backup = d.path().join("backup.sqlite3");
        let vault = Vault::random();
        let mut db = Store::open(&source, vault).unwrap();
        let identity = stub("ciphertext-corruption", "thread");
        let id = identity.id();
        db.insert_stub(identity, Utc::now()).unwrap();
        db.backup_to(&backup).unwrap();
        db.verify_backup_file(&backup).unwrap();

        {
            let connection = Connection::open(&backup).unwrap();
            connection
                .execute(
                    "UPDATE items SET payload=zeroblob(length(payload)) WHERE id=?1",
                    [&id],
                )
                .unwrap();
            let quick: String = connection
                .query_row("PRAGMA quick_check", [], |row| row.get(0))
                .unwrap();
            assert_eq!(quick, "ok");
        }

        assert!(db.verify_backup_file(&backup).is_err());
    }

    #[test]
    fn audit_points_detect_rollback_or_hash_substitution() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        let (genesis_seq, genesis) = db.audit_point().unwrap();
        assert_eq!(genesis_seq, 0);
        db.verify_audit_point(genesis_seq, &genesis).unwrap();

        db.log("test.first", None, "first").unwrap();
        let (first_seq, first_head) = db.audit_point().unwrap();
        assert!(first_seq > 0);
        db.verify_audit_point(first_seq, &first_head).unwrap();

        db.log("test.second", None, "second").unwrap();
        let (second_seq, second_head) = db.audit_point().unwrap();
        assert!(second_seq > first_seq);
        assert_ne!(first_head, second_head);
        db.verify_audit_point(first_seq, &first_head).unwrap();
        db.verify_audit_point(second_seq, &second_head).unwrap();

        assert!(db.verify_audit_point(first_seq, &second_head).is_err());
        assert!(db.verify_audit_point(second_seq + 1, &second_head).is_err());
        assert!(db.verify_audit_point(-1, &first_head).is_err());
    }

    #[test]
    fn online_backup_is_consistent_and_requires_the_same_vault() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.sqlite3");
        let backup = d.path().join("backup.sqlite3");
        let vault = Vault::random();
        let mut db = Store::open(&source, vault.clone()).unwrap();
        assert!(
            db.insert_stub(stub("backup-message", "backup-thread"), Utc::now())
                .unwrap()
        );
        db.integrity_check().unwrap();
        db.backup_to(&backup).unwrap();
        assert!(backup.is_file());

        let restored = Store::open(&backup, vault).unwrap();
        restored.integrity_check().unwrap();
        assert_eq!(restored.counts("me@example.com").unwrap().stored, 1);
        drop(restored);

        assert!(Store::open(&backup, Vault::random()).is_err());
        assert!(db.backup_to(&backup).is_err());
    }

    #[test]
    fn compaction_reclaims_free_pages_and_preserves_integrity() {
        let d = tempfile::tempdir().unwrap();
        let mut db = Store::open(&d.path().join("db"), Vault::random()).unwrap();
        db.set_meta("large-temporary-value", &"x".repeat(2_000_000))
            .unwrap();
        db.delete_meta("large-temporary-value").unwrap();
        let (_, free_before, _) = db.page_stats().unwrap();
        assert!(free_before > 0);
        let report = db.compact().unwrap();
        assert!(report.after_page_count <= report.before_page_count);
        assert!(report.after_freelist_count <= report.before_freelist_count);
        db.readiness_check().unwrap();
    }

    #[test]
    fn wrong_key_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("db");
        drop(Store::open(&p, Vault::random()).unwrap());
        assert!(Store::open(&p, Vault::random()).is_err());
    }
}
