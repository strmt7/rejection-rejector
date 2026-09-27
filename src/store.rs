use crate::{
    types::*,
    vault::{write_new_private, Vault},
};
use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{
    backup::Backup, params, Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{path::Path, time::Duration};

pub struct Store {
    conn: Connection,
    vault: Vault,
}
fn decode(vault: &Vault, id: &str, bytes: &[u8], revision: u64, state: &str) -> Result<Job> {
    let job: Job = vault.open_value(&format!("item/{id}"), bytes)?;
    ensure!(
        job.id == id && job.revision == revision && job.state.db() == state,
        "Authenticated record metadata mismatch"
    );
    Ok(job)
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
    let e = AuditEvent {
        seq: 0,
        at,
        kind: kind.into(),
        item_id: item.map(str::to_owned),
        detail: detail.into(),
    };
    tx.execute(
        "INSERT INTO events(event_id,payload) VALUES(?1,?2)",
        params![id, vault.seal(&format!("event/{id}"), &e)?],
    )?;
    Ok(())
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
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        ensure!(version <= 3, "Database belongs to a newer app version");
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
        if version == 0 {
            conn.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE meta(name TEXT PRIMARY KEY,payload BLOB NOT NULL);
                CREATE TABLE items(id TEXT PRIMARY KEY,account_key TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,created_at INTEGER NOT NULL,received_at INTEGER,updated_at INTEGER NOT NULL,retry_at INTEGER NOT NULL,payload BLOB NOT NULL);
                CREATE INDEX items_queue ON items(account_key,state,retry_at,created_at);
                CREATE INDEX items_review_order ON items(account_key,state,received_at,created_at);
                CREATE TABLE deliveries(item_id TEXT PRIMARY KEY,thread_key TEXT NOT NULL,attempt_at INTEGER NOT NULL,status TEXT NOT NULL,provider_id BLOB);
                CREATE INDEX deliveries_time ON deliveries(attempt_at);
                CREATE INDEX deliveries_thread_state ON deliveries(thread_key,status);
                CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL);")?;
            let marker = vault.seal("meta/vault_check", &"rejection-rejector:v1")?;
            conn.execute(
                "INSERT INTO meta(name,payload) VALUES('vault_check',?1)",
                [marker],
            )?;
            conn.execute_batch("PRAGMA user_version=3; COMMIT;")?;
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
        } else {
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS items_review_order ON items(account_key,state,received_at,created_at);
                 CREATE INDEX IF NOT EXISTS deliveries_thread_state ON deliveries(thread_key,status);",
            )?;
        }
        let db = Self { conn, vault };
        let check = db
            .meta::<String>("vault_check")?
            .context("Database vault marker is missing after initialization")?;
        ensure!(check == "rejection-rejector:v1", "Wrong vault");
        Ok(db)
    }
    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    /// Validate SQLite structure and foreign-key integrity and authenticate the
    /// vault marker before reporting the store as healthy.
    pub fn integrity_check(&self) -> Result<()> {
        check_connection_integrity(&self.conn)?;
        let marker = self
            .meta::<String>("vault_check")?
            .context("Database vault marker is missing")?;
        ensure!(marker == "rejection-rejector:v1", "Wrong vault marker");
        Ok(())
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
    pub fn verify_backup_file(&self, path: &Path) -> Result<i64> {
        ensure!(path.is_file(), "Backup database file is missing");
        ensure!(
            !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
            "Backup database must not be a symlink"
        );
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        check_connection_integrity(&connection)?;
        let version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        ensure!(
            version == self.schema_version()?,
            "Backup schema version does not match the current database"
        );
        let encrypted: Vec<u8> = connection
            .query_row(
                "SELECT payload FROM meta WHERE name='vault_check'",
                [],
                |row| row.get(0),
            )
            .context("Backup vault marker is missing")?;
        let marker: String = self.vault.open_value("meta/vault_check", &encrypted)?;
        ensure!(marker == "rejection-rejector:v1", "Backup belongs to another vault");
        Ok(version)
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
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .context("Message not found")?;
        decode(&self.vault, id, &b, r, &s)
    }
    pub fn save(&mut self, job: &mut Job, kind: &str, detail: &str) -> Result<()> {
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
        let changed = tx.execute("UPDATE items SET state=?2,revision=?3,updated_at=?4,retry_at=?5,received_at=COALESCE(?6,received_at),payload=?7 WHERE id=?1 AND revision=?8", params![next.id, next.state.db(), next.revision, next.updated_at.timestamp(), next.retry_at, received_at, self.vault.seal(&format!("item/{}", next.id), &next)?, old])?;
        ensure!(
            changed == 1,
            "Stale revision: reload the message before acting"
        );
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
                limit,
                u64::from(page) * u64::from(limit)
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u64>(2)?,
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
                self.save(
                    &mut job,
                    "email.outside_window",
                    "Age window tightened; identity retained and private content removed",
                )?;
                deferred += 1;
            }
        }
        Ok(deferred)
    }

    pub fn counts(&self, account: &str) -> Result<Counts> {
        let mut c = Counts::default();
        let mut q = self
            .conn
            .prepare("SELECT state,COUNT(*) FROM items WHERE account_key=?1 GROUP BY state")?;
        let r = q.query_map([hash(account)], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
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
            |r| r.get(0),
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
    pub fn reserve_send(&mut self, snapshot: &Job, limit: u16, now: DateTime<Utc>) -> Result<Job> {
        ensure!(snapshot.state.reviewable(), "Message is not reviewable");
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (b, r, s): (Vec<u8>, u64, String) = tx.query_row(
            "SELECT payload,revision,state FROM items WHERE id=?1",
            [&snapshot.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let mut j = decode(&self.vault, &snapshot.id, &b, r, &s)?;
        ensure!(
            j.revision == snapshot.revision && j.state == snapshot.state,
            "Send approval is stale"
        );
        let attempts: u64 = tx.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE attempt_at>=?1",
            [now.timestamp() - 86400],
            |r| r.get(0),
        )?;
        ensure!(
            attempts < u64::from(limit),
            "Rolling 24-hour attempt limit reached"
        );
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
                j.revision,
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
            "UPDATE items SET state=?2,revision=?3,updated_at=?4,payload=?5 WHERE id=?1",
            params![
                id,
                job.state.db(),
                job.revision,
                job.updated_at.timestamp(),
                self.vault.seal(&format!("item/{id}"), &job)?
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
        tx.execute(
            "UPDATE deliveries SET status=?2,provider_id=?3 WHERE item_id=?1",
            params![id, j.state.db(), encrypted],
        )?;
        tx.execute(
            "UPDATE items SET state=?2,revision=?3,updated_at=?4,payload=?5 WHERE id=?1",
            params![
                id,
                j.state.db(),
                j.revision,
                j.updated_at.timestamp(),
                self.vault.seal(&format!("item/{id}"), &j)?
            ],
        )?;
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
    pub fn recover_interrupted_sends(&mut self) -> Result<usize> {
        let ids: Vec<String> = {
            let mut q = self
                .conn
                .prepare("SELECT id FROM items WHERE state='sending'")?;
            let r = q.query_map([], |r| r.get(0))?;
            r.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for id in &ids {
            self.finish_send(id, None)?;
        }
        Ok(ids.len())
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
        assert_eq!(version, 3);
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
        assert!(db
            .insert_stub(stub("after-migration", "thread"), Utc::now())
            .unwrap());
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
        assert_eq!(version, 3);
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
        assert!(db
            .events(0, 100)
            .unwrap()
            .iter()
            .any(|event| event.kind == "meta.test"));
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
    fn crash_never_releases_reservation() {
        let d = tempfile::tempdir().unwrap();
        let v = Vault::random();
        let p = d.path().join("db");
        let mut db = Store::open(&p, v.clone()).unwrap();
        let a = ready(&mut db, "a", "same");
        let b = ready(&mut db, "b", "same");
        db.reserve_send(&a, 10, Utc::now()).unwrap();
        assert!(db.reserve_send(&b, 10, Utc::now()).is_err());
        drop(db);
        let mut db = Store::open(&p, v).unwrap();
        assert_eq!(db.recover_interrupted_sends().unwrap(), 1);
        assert_eq!(db.get(&a.id).unwrap().state, JobState::Uncertain);
        assert!(db.reserve_send(&b, 10, Utc::now()).is_err());
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
        job.state = JobState::Dismissed;
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
    fn online_backup_is_consistent_and_requires_the_same_vault() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.sqlite3");
        let backup = d.path().join("backup.sqlite3");
        let vault = Vault::random();
        let mut db = Store::open(&source, vault.clone()).unwrap();
        assert!(db
            .insert_stub(stub("backup-message", "backup-thread"), Utc::now())
            .unwrap());
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
    fn wrong_key_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("db");
        drop(Store::open(&p, Vault::random()).unwrap());
        assert!(Store::open(&p, Vault::random()).is_err());
    }
}
