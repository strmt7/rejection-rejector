use crate::{
    engine::Engine,
    readiness::{OperationalIndicators, operational_indicators},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub service_name: &'static str,
    pub application_version: &'static str,
    pub database_schema_version: i64,
    pub database_bytes: Option<u64>,
    pub audit_sequence: i64,
    pub audit_head_present: bool,
    pub stored_items: u64,
    pub queued_items: u64,
    pub review_items: u64,
    pub sent_items: u64,
    pub uncertain_deliveries: u64,
    pub send_attempts_24h: u64,
    pub gmail_connected: bool,
    pub gmail_send_scope: bool,
    pub model_digest_pinned: bool,
    pub task_qualification_current: bool,
    pub enterprise_policy_active: bool,
    pub enterprise_policy_revision: Option<u64>,
    pub operational: OperationalIndicators,
}

pub fn collect(engine: &Engine, now: DateTime<Utc>) -> Result<MetricsSnapshot> {
    let counts = engine.db.counts(&engine.account)?;
    let integrity_ok = engine.db.readiness_check().is_ok();
    let operational = operational_indicators(
        &engine.settings,
        &counts,
        engine.last_poll()?,
        integrity_ok,
        engine.connected(),
        now,
    );
    let policy = engine.enterprise_policy_status();
    let database_bytes = std::fs::metadata(engine.directory.join("state.sqlite3"))
        .ok()
        .map(|metadata| metadata.len());
    Ok(MetricsSnapshot {
        schema_version: 1,
        generated_at: now,
        service_name: "rejection-rejector",
        application_version: env!("CARGO_PKG_VERSION"),
        database_schema_version: engine.db.schema_version()?,
        database_bytes,
        audit_sequence: engine.db.latest_event_seq()?,
        audit_head_present: engine.db.audit_head().is_ok(),
        stored_items: counts.stored,
        queued_items: counts.queued,
        review_items: counts.review,
        sent_items: counts.sent,
        uncertain_deliveries: counts.uncertain,
        send_attempts_24h: counts.attempts_24h,
        gmail_connected: engine.connected(),
        gmail_send_scope: engine.send_scope(),
        model_digest_pinned: engine.settings.model_digest.is_some(),
        task_qualification_current: engine.settings.task_qualification_current(),
        enterprise_policy_active: policy.active,
        enterprise_policy_revision: policy.revision,
        operational,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};

    #[test]
    fn metrics_are_privacy_safe_and_stable() {
        let root = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            root.path().to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let metrics = collect(&engine, Utc::now()).unwrap();
        let encoded = serde_json::to_string(&metrics).unwrap();

        assert_eq!(metrics.schema_version, 1);
        assert_eq!(metrics.service_name, "rejection-rejector");
        assert!(metrics.database_schema_version >= 1);
        assert!(metrics.stored_items >= 3);
        for forbidden in [
            "demo@example.invalid",
            "Northstar Materials",
            "Alex Morgan",
            "refresh_token",
            "candidate_context",
            "api_token",
        ] {
            assert!(!encoded.contains(forbidden), "metrics leaked {forbidden}");
        }
    }
}
