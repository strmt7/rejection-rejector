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
pub fn write_report(engine: &Engine, path: &Path) -> Result<()> {
    let data = report(engine)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
        ensure!(
            !std::fs::symlink_metadata(parent)?.file_type().is_symlink(),
            "Shadow-report parent directory must not be a symlink"
        );
    }
    write_new_private(path, &serde_json::to_vec_pretty(&data)?)?;
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
        assert_eq!(value["assumptions"]["provider_preflight_performed"], false);
        assert_eq!(value["assumptions"]["external_write_performed"], false);
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
        blocked.stub.thread_id = shared.clone();
        blocked.email.as_mut().unwrap().stub.thread_id = shared.clone();
        persist(&mut engine, blocked, now);
        let mut sibling = reviewable(&engine, 21, "hr21@example.invalid", now);
        sibling.stub.thread_id = shared.clone();
        sibling.email.as_mut().unwrap().stub.thread_id = shared.clone();
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
        assert_eq!(value["global"]["gmail_connected"], true);
        assert_eq!(value["global"]["gmail_send_scope"], true);
        assert_eq!(value["global"]["task_qualification_current"], true);
        assert_eq!(value["global"]["configuration_ready"], true);
        assert_eq!(value["global"]["worker_paused"], false);
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
        assert_eq!(value["global"]["worker_paused"], true);
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
}
