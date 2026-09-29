use crate::{
    config::Mode,
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
}

#[derive(Debug, Serialize)]
struct ShadowQueue {
    reviewable_items: u64,
    semantic_policy_eligible: u64,
    eligible_but_thread_blocked: u64,
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
        },
        queue: ShadowQueue {
            reviewable_items,
            semantic_policy_eligible,
            eligible_but_thread_blocked,
            locally_dispatchable_before_provider_preflight: locally_dispatchable,
            dispatchable_now_by_local_gates_and_daily_capacity: dispatchable_now,
        },
        block_code_counts,
    })?)
}

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
        let text = value.to_string();
        for forbidden in [
            "demo@example.invalid",
            "Northstar Materials",
            "Thin Film Engineer",
            "Alex Morgan",
            "recruitment",
        ] {
            assert!(!text.contains(forbidden), "shadow report leaked {forbidden}");
        }
    }
}
