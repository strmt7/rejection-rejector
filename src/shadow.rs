use crate::{
    config::{AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H, Mode},
    engine::{AutomaticPolicyCode, Engine, automatic_policy},
    storage,
    vault::write_new_private,
};
use anyhow::{Result, ensure};
use chrono::Utc;
use serde::Serialize;
use std::{collections::BTreeMap, path::Path, sync::atomic::Ordering};

const MAX_REVIEW_ITEMS: usize = 10_000;
const PAGE_SIZE: u32 = 100;

#[derive(Debug, Serialize)]
struct ShadowReport {
    report_version: u32,
    generated_at: chrono::DateTime<Utc>,
    privacy: ShadowPrivacy,
    assumptions: ShadowAssumptions,
    global: ShadowGlobal,
    queue: ShadowQueue,
    block_code_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct ShadowPrivacy {
    contains_account_address: bool,
    contains_message_content: bool,
    contains_recipient_addresses: bool,
    contains_employer_or_position: bool,
    contains_draft_text: bool,
}

#[derive(Debug, Serialize)]
struct ShadowAssumptions {
    automatic_arm_state_simulated: bool,
    existing_backlog_in_selected_window_included: bool,
    provider_preflight_performed: bool,
    external_write_performed: bool,
}

#[derive(Debug, Serialize)]
struct ShadowGlobal {
    enterprise_policy_permits_automatic: bool,
    gmail_connected: bool,
    gmail_send_scope: bool,
    task_qualification_current: bool,
    configuration_ready: bool,
    storage_write_safe: bool,
    worker_paused: bool,
    daily_send_limit: u16,
    attempts_24h: u64,
    daily_capacity_remaining: u64,
    automatic_recipient_attempt_limit_24h: u16,
}

#[derive(Debug, Serialize)]
struct ShadowQueue {
    reviewable_items: u64,
    semantic_policy_eligible: u64,
    eligible_but_thread_blocked: u64,
    eligible_but_recipient_limited: u64,
    locally_dispatchable_before_provider_preflight: u64,
    dispatchable_now_by_local_gates_and_daily_capacity: u64,
}

/// Render one policy code as its storage key string.
///
/// Inputs: `code` — automatic policy code. Output: `Result<String>` — the
/// serialized string form; error when the code does not serialize as a string.
fn code_key(code: AutomaticPolicyCode) -> Result<String> {
    let value = serde_json::to_value(code)?;
    Ok(value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Automatic policy code did not serialize as a string"))?
        .to_owned())
}

/// Simulate what Automatic mode would do now, without sending anything.
///
/// Inputs: `engine` — open engine with current settings and jobs. Output: `Result<Value>`
/// — the shadow-mode simulation report.
pub fn report(engine: &Engine) -> Result<serde_json::Value> {
    let now = Utc::now();
    let policy = engine.enterprise_policy_status();
    let enterprise_policy_permits_automatic =
        !policy.force_human_review && !policy.prohibit_sending;

    let mut simulated = engine.settings.clone();
    simulated.mode = Mode::Automatic;
    simulated.sending_enabled = true;
    simulated.automatic_confirmed = true;
    simulated.include_backlog = true;
    simulated.automatic_since = Some(simulated.cutoff(now));

    let configuration_ready = simulated.validate().is_ok();
    let task_qualification_current = engine.settings.task_qualification_current();
    let storage = storage::inspect(&engine.directory)?;
    let counts = engine.db.counts(&engine.account)?;
    let daily_capacity_remaining =
        u64::from(engine.settings.daily_send_limit).saturating_sub(counts.attempts_24h);

    let mut reviewable_items = 0u64;
    let mut semantic_policy_eligible = 0u64;
    let mut eligible_but_thread_blocked = 0u64;
    let mut eligible_but_recipient_limited = 0u64;
    let mut locally_dispatchable = 0u64;
    let mut block_code_counts = BTreeMap::<String, u64>::new();

    for page in 0..100u32 {
        let jobs = engine.db.list(&engine.account, true, page, PAGE_SIZE)?;
        if jobs.is_empty() {
            break;
        }
        ensure!(
            reviewable_items.saturating_add(jobs.len() as u64) <= MAX_REVIEW_ITEMS as u64,
            "Shadow audit exceeds the bounded review-queue limit"
        );
        for job in jobs {
            reviewable_items += 1;
            let decision = automatic_policy(&job, &simulated, &engine.account, now);
            for block in &decision.blocks {
                *block_code_counts.entry(code_key(block.code)?).or_default() += 1;
            }
            if !decision.eligible {
                continue;
            }
            semantic_policy_eligible += 1;
            if engine.db.thread_blocked(&job.stub.thread_key())? {
                eligible_but_thread_blocked += 1;
            } else if engine.db.recipient_attempts_24h(&job, now)?
                >= u64::from(AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H)
            {
                eligible_but_recipient_limited += 1;
            } else {
                locally_dispatchable += 1;
            }
        }
    }

    let global_ready = enterprise_policy_permits_automatic
        && engine.connected()
        && engine.send_scope()
        && task_qualification_current
        && configuration_ready
        && storage.runtime_write_safe
        && !engine.paused.load(Ordering::SeqCst);

    let dispatchable_now = if global_ready {
        locally_dispatchable.min(daily_capacity_remaining)
    } else {
        0
    };

    Ok(serde_json::to_value(ShadowReport {
        report_version: 1,
        generated_at: now,
        privacy: ShadowPrivacy {
            contains_account_address: false,
            contains_message_content: false,
            contains_recipient_addresses: false,
            contains_employer_or_position: false,
            contains_draft_text: false,
        },
        assumptions: ShadowAssumptions {
            automatic_arm_state_simulated: true,
            existing_backlog_in_selected_window_included: true,
            provider_preflight_performed: false,
            external_write_performed: false,
        },
        global: ShadowGlobal {
            enterprise_policy_permits_automatic,
            gmail_connected: engine.connected(),
            gmail_send_scope: engine.send_scope(),
            task_qualification_current,
            configuration_ready,
            storage_write_safe: storage.runtime_write_safe,
            worker_paused: engine.paused.load(Ordering::SeqCst),
            daily_send_limit: engine.settings.daily_send_limit,
            attempts_24h: counts.attempts_24h,
            daily_capacity_remaining,
            automatic_recipient_attempt_limit_24h: AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H,
        },
        queue: ShadowQueue {
            reviewable_items,
            semantic_policy_eligible,
            eligible_but_thread_blocked,
            eligible_but_recipient_limited,
            locally_dispatchable_before_provider_preflight: locally_dispatchable,
            dispatchable_now_by_local_gates_and_daily_capacity: dispatchable_now,
        },
        block_code_counts,
    })?)
}

/// Write the shadow-mode simulation report to disk.
///
/// Inputs: `engine` — open engine; `path` — destination file. Output: `Ok(())`
/// once the report is written; missing parent directories are created first.
/// Render a shadow-mode report into any write-like sink.
///
/// Inputs: `data` — assembled report; `path` — destination (used for parent
/// directory preparation and error naming); `out` — write-like sink receiving
/// the pretty-printed JSON bytes. Output: `Ok(())` once the full document is
/// written and flushed; destinations without a parent component do no
/// directory work and a symlinked parent is refused. Write and serialization
/// failures propagate unchanged so a partial report can never be mistaken for
/// a complete one.
fn write_report_to(
    data: &serde_json::Value,
    path: &Path,
    out: &mut dyn std::io::Write,
) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
        ensure!(
            !std::fs::symlink_metadata(parent)?.file_type().is_symlink(),
            "Shadow-report parent directory must not be a symlink"
        );
    }
    out.write_all(&serde_json::to_vec_pretty(data)?)?;
    out.flush()?;
    Ok(())
}

/// Write the shadow evaluation report to one path.
///
/// Inputs: `engine` — engine carrying the state to report; `path` — destination
/// file. Output: `Result<()>` — `Ok` once the rendered report is written
/// privately.
pub fn write_report(engine: &Engine, path: &Path) -> Result<()> {
    let data = report(engine)?;
    let mut rendered = Vec::new();
    write_report_to(&data, path, &mut rendered)?;
    write_new_private(path, &rendered)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};

    /// A destination whose parent cannot be created fails loudly instead of
    /// writing a partial shadow report.
    #[test]
    fn write_report_refuses_unusable_destinations() {
        let root = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            root.path().to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let blocker = root.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let target = blocker.join("nested").join("shadow.json");
        assert!(write_report(&engine, &target).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn demo_shadow_audit_is_aggregate_private_and_non_mutating() {
        let root = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            root.path().to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let before = engine.db.latest_event_seq().unwrap();
        let value = report(&engine).unwrap();
        let after = engine.db.latest_event_seq().unwrap();

        assert_eq!(before, after);
        assert_eq!(value["queue"]["reviewable_items"], 3);
        assert!(
            !value["assumptions"]["provider_preflight_performed"]
                .as_bool()
                .unwrap()
        );
        assert!(
            !value["assumptions"]["external_write_performed"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            value["global"]["automatic_recipient_attempt_limit_24h"],
            AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H
        );
        assert!(value["queue"]["eligible_but_recipient_limited"].is_u64());
        let text = value.to_string();
        for forbidden in [
            "demo@example.invalid",
            "Northstar Materials",
            "Thin Film Engineer",
            "Alex Morgan",
            "recruitment",
        ] {
            assert!(
                !text.contains(forbidden),
                "shadow report leaked {forbidden}"
            );
        }
    }

    use crate::types::{Job, JobState};

    fn armed_engine(root: &std::path::Path) -> Engine {
        let mut engine = Engine::open(
            root.to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        crate::test_support::arm_automatic(&mut engine.settings);
        engine
    }

    fn reviewable(engine: &Engine, n: u64, recipient: &str, now: chrono::DateTime<Utc>) -> Job {
        let email = crate::test_support::gmail_email_to(
            &engine.account,
            n,
            recipient,
            "Your application — R&D Engineer",
            "Thank you for applying. We have decided not to move forward with your application.",
        );
        let mut job = Job::new(email.stub.clone(), now);
        job.email = Some(email);
        job.state = JobState::Attention;
        job
    }

    /// Insert the stub identity first (as sync does), then persist the payload.
    fn persist(engine: &mut Engine, mut job: Job, now: chrono::DateTime<Utc>) -> Job {
        engine.db.insert_stubs([job.stub.clone()], now).unwrap();
        engine.db.save(&mut job, "test.seed", "seed").unwrap();
        job
    }

    fn connected_mock(engine: &mut Engine) -> crate::test_support::MockServer {
        let server = crate::test_support::MockServer::new(|_, _| None);
        engine.attach_gmail_for_tests(crate::gmail::Gmail::with_endpoints(
            crate::oauth::Credentials {
                client_id: "id".into(),
                client_secret: "secret".into(),
                refresh_token: "refresh".into(),
                can_send: true,
            },
            &server.url,
            &server.url,
        ));
        server
    }

    /// The queue section must distinguish semantic eligibility from thread
    /// blocks and per-recipient burst limits so operators see why dispatch is
    /// held instead of a single opaque count.
    #[test]
    fn shadow_queue_classifies_thread_blocks_and_recipient_limits() {
        let root = tempfile::tempdir().unwrap();
        let mut engine = armed_engine(root.path());
        let _server = connected_mock(&mut engine);
        let now = Utc::now();

        let ready = crate::test_support::eligible_job(&engine.settings, &engine.account, 1, now);
        persist(&mut engine, ready, now);

        let shared = "thread-shared".to_string();
        let mut blocked =
            crate::test_support::eligible_job(&engine.settings, &engine.account, 2, now);
        blocked.stub.thread_id.clone_from(&shared);
        blocked
            .email
            .as_mut()
            .unwrap()
            .stub
            .thread_id
            .clone_from(&shared);
        persist(&mut engine, blocked, now);
        let mut sibling = reviewable(&engine, 21, "hr21@example.invalid", now);
        sibling.stub.thread_id.clone_from(&shared);
        sibling
            .email
            .as_mut()
            .unwrap()
            .stub
            .thread_id
            .clone_from(&shared);
        let sibling = persist(&mut engine, sibling, now);
        engine
            .db
            .reserve_send_with_recipient_limit(&sibling, 10, None, now)
            .unwrap();

        let limited = crate::test_support::eligible_job(&engine.settings, &engine.account, 3, now);
        persist(&mut engine, limited, now);
        for n in [31, 32] {
            let attempt = reviewable(&engine, n, "hr3@example.invalid", now);
            let attempt = persist(&mut engine, attempt, now);
            engine
                .db
                .reserve_send_with_recipient_limit(&attempt, 10, None, now)
                .unwrap();
        }

        let value = report(&engine).unwrap();
        assert_eq!(value["queue"]["semantic_policy_eligible"], 3);
        assert_eq!(value["queue"]["eligible_but_thread_blocked"], 1);
        assert_eq!(value["queue"]["eligible_but_recipient_limited"], 1);
        assert_eq!(
            value["queue"]["locally_dispatchable_before_provider_preflight"],
            1
        );
        assert_eq!(
            value["queue"]["dispatchable_now_by_local_gates_and_daily_capacity"],
            1
        );
        assert!(value["global"]["gmail_connected"].as_bool().unwrap());
        assert!(value["global"]["gmail_send_scope"].as_bool().unwrap());
        assert!(
            value["global"]["task_qualification_current"]
                .as_bool()
                .unwrap()
        );
        assert!(value["global"]["configuration_ready"].as_bool().unwrap());
        assert!(!value["global"]["worker_paused"].as_bool().unwrap());
        assert_eq!(value["global"]["daily_capacity_remaining"], 7);
    }

    /// A paused worker must clamp the dispatchable count to zero even when
    /// every local gate passes; the queue numbers stay visible for the audit.
    #[test]
    fn shadow_dispatchable_is_zero_while_the_worker_is_paused() {
        let root = tempfile::tempdir().unwrap();
        let mut engine = armed_engine(root.path());
        let _server = connected_mock(&mut engine);
        let now = Utc::now();
        let ready = crate::test_support::eligible_job(&engine.settings, &engine.account, 4, now);
        persist(&mut engine, ready, now);
        engine.paused.store(true, Ordering::SeqCst);

        let value = report(&engine).unwrap();
        assert_eq!(
            value["queue"]["locally_dispatchable_before_provider_preflight"],
            1
        );
        assert_eq!(
            value["queue"]["dispatchable_now_by_local_gates_and_daily_capacity"],
            0
        );
        assert!(value["global"]["worker_paused"].as_bool().unwrap());
    }

    /// Writing the report must create private parent directories and produce
    /// parseable JSON without leaking queue content beyond aggregates.
    #[test]
    fn write_report_creates_parent_directories() {
        let root = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            root.path().to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let output = root.path().join("audit").join("shadow.json");
        write_report(&engine, &output).unwrap();
        assert!(output.is_file());
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
        assert_eq!(value["report_version"], 1);
    }

    /// Why: the shadow-report writer must accept any write-like sink — a bare
    /// filename destination has no directory work to do and must not error,
    /// and a sink failure must surface instead of leaving a silently partial
    /// report behind.
    /// Inputs: a bare filename rendered into a capturing sink and into an
    /// always-failing sink. Output: complete JSON for the good sink and the
    /// sink's own error for the failing one.
    #[test]
    fn shadow_report_renders_through_write_like_sinks() {
        use serde_json::json;
        struct FailingSink;
        impl std::io::Write for FailingSink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("sink unavailable"))
            }
        }

        let data = json!({"report_version": 1});
        let mut out = Vec::new();
        write_report_to(&data, Path::new("shadow-report.json"), &mut out).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["report_version"], 1);

        let error = write_report_to(&data, Path::new("shadow-report.json"), &mut FailingSink)
            .expect_err("sink failures must propagate");
        assert!(
            error.to_string().contains("sink unavailable"),
            "unexpected error: {error}"
        );
    }

    /// Why: the shadow report refuses a symlinked parent directory so a local
    /// observer cannot redirect the simulated-arm report into an attacker
    /// chosen location, and a sink that refuses the write must surface its own
    /// error. The refusal must fire before any bytes are rendered.
    /// Inputs: a symlinked parent directory and a write-refusing sink.
    /// Output: the documented symlink refusal and the sink's own error.
    #[test]
    fn write_report_refuses_a_symlinked_parent_and_propagates_write_failures() {
        struct RefusingSink {
            fail_write: bool,
        }
        impl std::io::Write for RefusingSink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.fail_write {
                    return Err(std::io::Error::other("sink write refused"));
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("sink flush refused"))
            }
        }

        let data = serde_json::json!({"report_version": 1});
        let error = write_report_to(
            &data,
            Path::new("shadow-report.json"),
            &mut RefusingSink { fail_write: true },
        )
        .expect_err("write failures must propagate");
        assert!(
            error.to_string().contains("sink write refused"),
            "unexpected error: {error}"
        );
        let error = write_report_to(
            &data,
            Path::new("shadow-report.json"),
            &mut RefusingSink { fail_write: false },
        )
        .expect_err("flush failures must propagate");
        assert!(
            error.to_string().contains("sink flush refused"),
            "unexpected error: {error}"
        );

        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.path().join("link");
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_dir(&real, &link);
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&real, &link);
        if made.is_err() {
            // Symlink creation is unavailable for this host user; the refusal
            // path cannot be exercised here.
            return;
        }
        let error = write_report_to(&data, &link.join("shadow.json"), &mut Vec::new())
            .expect_err("a symlinked parent must be refused");
        assert!(
            error.to_string().contains("must not be a symlink"),
            "unexpected error: {error}"
        );
    }

    /// Why: the shadow report must never replace an existing destination —
    /// the prior simulated-arm evidence is operator data a failed render must
    /// not destroy.
    /// Inputs: a writable destination used twice. Output: first write stored,
    /// second write refused with the original bytes intact.
    #[test]
    fn write_report_keeps_existing_destinations() {
        let root = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            root.path().to_path_buf(),
            true,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();
        let output = root.path().join("shadow.json");
        write_report(&engine, &output).unwrap();
        let first = std::fs::read(&output).unwrap();
        assert!(write_report(&engine, &output).is_err());
        assert_eq!(
            std::fs::read(&output).unwrap(),
            first,
            "the existing shadow report must survive a refused overwrite"
        );
    }
}
