use crate::{
    engine::Engine,
    readiness::{OperationalContext, OperationalIndicators, operational_indicators},
    recovery::{BackupIsolationStatus, ScheduledBackupStatus},
    storage::StorageHealth,
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
    pub storage: StorageHealth,
    pub scheduled_backup: ScheduledBackupStatus,
    pub backup_isolation: BackupIsolationStatus,
    pub audit_sequence: i64,
    pub audit_head_present: bool,
    pub runtime_performance: crate::runtime_log::RuntimePerformanceSummary,
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
    pub policy_requires_independent_audit_anchor: bool,
    pub external_audit_anchor_configured: bool,
    pub os_protected_audit_anchor_required: bool,
    pub independent_audit_anchor_configured: bool,
    pub operational: OperationalIndicators,
}

pub fn collect(engine: &Engine, now: DateTime<Utc>) -> Result<MetricsSnapshot> {
    let counts = engine.db.counts(&engine.account)?;
    let runtime_performance = crate::runtime_log::performance_summary(&engine.directory)?;
    let integrity_ok = engine.db.readiness_check().is_ok();
    let storage = crate::storage::inspect(&engine.directory)?;
    let scheduled_backup =
        crate::recovery::scheduled_backup_status(&engine.db, &engine.settings, now)?;
    let backup_isolation =
        crate::recovery::backup_isolation_status(&engine.directory, &engine.settings)?;
    let operational = operational_indicators(OperationalContext {
        settings: &engine.settings,
        counts: &counts,
        last_poll: engine.last_poll()?,
        database_integrity_ok: integrity_ok,
        storage_write_safe: storage.runtime_write_safe,
        scheduled_backup_overdue: scheduled_backup.overdue,
        backup_distinct_failure_domain: backup_isolation.distinct_failure_domain,
        connected: engine.connected(),
        now,
    });
    let policy = engine.enterprise_policy_status();
    let external_audit_anchor_configured =
        std::env::var_os(crate::audit_anchor::AUDIT_ANCHOR_ENV).is_some();
    let os_protected_audit_anchor_required = crate::audit_anchor::os_anchor_required()?;
    let independent_audit_anchor_configured =
        external_audit_anchor_configured || os_protected_audit_anchor_required;
    let database_bytes = std::fs::metadata(engine.directory.join("state.sqlite3"))
        .ok()
        .map(|metadata| metadata.len());
    Ok(MetricsSnapshot {
        schema_version: 3,
        generated_at: now,
        service_name: "rejection-rejector",
        application_version: env!("CARGO_PKG_VERSION"),
        database_schema_version: engine.db.schema_version()?,
        database_bytes,
        storage,
        scheduled_backup,
        backup_isolation,
        audit_sequence: engine.db.latest_event_seq()?,
        audit_head_present: engine.db.audit_head().is_ok(),
        runtime_performance,
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
        policy_requires_independent_audit_anchor: policy.require_external_audit_anchor,
        external_audit_anchor_configured,
        os_protected_audit_anchor_required,
        independent_audit_anchor_configured,
        operational,
    })
}

fn metric_bool(value: bool) -> u8 {
    u8::from(value)
}

fn push_gauge(
    out: &mut String,
    name: &str,
    help: &str,
    unit: Option<&str>,
    value: impl std::fmt::Display,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" gauge\n");
    if let Some(unit) = unit {
        out.push_str("# UNIT ");
        out.push_str(name);
        out.push(' ');
        out.push_str(unit);
        out.push('\n');
    }
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Render a privacy-safe OpenMetrics 1.0 snapshot.
///
/// Metric names and semantics are deliberately stable and label-free so mailbox,
/// employer, account and candidate data can never become high-cardinality labels.
pub fn render_openmetrics(snapshot: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(4096);
    push_gauge(
        &mut out,
        "rejection_rejector_up",
        "Whether the local Rejection Rejector process produced this metrics snapshot.",
        None,
        1,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_snapshot_unixtime_seconds",
        "UTC Unix timestamp when this metrics snapshot was generated.",
        Some("seconds"),
        snapshot.generated_at.timestamp(),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_database_schema_version",
        "Current encrypted workspace database schema version.",
        None,
        snapshot.database_schema_version,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_database_bytes",
        "Current SQLite database file size when available.",
        Some("bytes"),
        snapshot.database_bytes.unwrap_or(0),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_workspace_database_bytes",
        "Combined SQLite database, WAL and shared-memory file size.",
        Some("bytes"),
        snapshot.storage.workspace_database_bytes,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_storage_available_bytes",
        "Available bytes on the workspace filesystem.",
        Some("bytes"),
        snapshot.storage.available_bytes,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_storage_total_bytes",
        "Total bytes on the workspace filesystem.",
        Some("bytes"),
        snapshot.storage.total_bytes,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_storage_runtime_required_bytes",
        "Conservative minimum free-space guardrail for durable runtime writes.",
        Some("bytes"),
        snapshot.storage.runtime_required_bytes,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_storage_backup_required_bytes",
        "Conservative minimum free-space guardrail for verified backup creation.",
        Some("bytes"),
        snapshot.storage.backup_required_bytes,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_storage_runtime_write_safe",
        "Whether the workspace currently satisfies the runtime free-space guardrail.",
        None,
        metric_bool(snapshot.storage.runtime_write_safe),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_storage_backup_safe",
        "Whether the workspace currently satisfies the backup free-space guardrail.",
        None,
        metric_bool(snapshot.storage.backup_safe),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_scheduled_backup_enabled",
        "Whether verified scheduled backups are enabled.",
        None,
        metric_bool(snapshot.scheduled_backup.enabled),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_scheduled_backup_overdue",
        "Whether the configured scheduled backup is overdue.",
        None,
        metric_bool(snapshot.scheduled_backup.overdue),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_backup_distinct_failure_domain",
        "Whether the scheduled backup destination is on a distinct filesystem or volume; -1 means unknown/not configured.",
        None,
        snapshot
            .backup_isolation
            .distinct_failure_domain
            .map(|value| if value { 1_i8 } else { 0_i8 })
            .unwrap_or(-1),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_scheduled_backup_age_seconds",
        "Age in seconds of the last successful scheduled backup, or -1 when unavailable.",
        Some("seconds"),
        snapshot.scheduled_backup.age_seconds.unwrap_or(-1),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_audit_sequence",
        "Latest local semantic audit sequence number.",
        None,
        snapshot.audit_sequence,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_audit_head_present",
        "Whether the authenticated semantic audit chain has a readable head.",
        None,
        metric_bool(snapshot.audit_head_present),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_runtime_operations_retained",
        "Number of typed worker operation records retained in the bounded local runtime journal.",
        None,
        snapshot.runtime_performance.retained_operation_records,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_runtime_operations_failed",
        "Number of failed typed worker operations retained in the bounded local runtime journal.",
        None,
        snapshot.runtime_performance.failed_operations,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_runtime_operations_timed",
        "Number of retained operations with a measured start-to-finish duration.",
        None,
        snapshot.runtime_performance.timed_operations,
    );
    push_gauge(
        &mut out,
        "rejection_rejector_runtime_operation_mean_duration_milliseconds",
        "Mean duration in milliseconds across retained timed operations, or -1 when unavailable.",
        Some("milliseconds"),
        snapshot
            .runtime_performance
            .mean_duration_ms
            .map(|value| value as i128)
            .unwrap_or(-1),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_runtime_operation_max_duration_milliseconds",
        "Maximum duration in milliseconds across retained timed operations, or -1 when unavailable.",
        Some("milliseconds"),
        snapshot
            .runtime_performance
            .max_duration_ms
            .map(|value| value as i128)
            .unwrap_or(-1),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_runtime_log_parse_errors",
        "Malformed or oversized runtime-journal lines encountered while building aggregate performance evidence.",
        None,
        snapshot.runtime_performance.parse_errors,
    );
    for (name, help, value) in [
        (
            "rejection_rejector_items_stored",
            "Number of persisted message identities in the local workspace.",
            snapshot.stored_items,
        ),
        (
            "rejection_rejector_items_queued",
            "Number of messages waiting for local analysis.",
            snapshot.queued_items,
        ),
        (
            "rejection_rejector_items_review",
            "Number of messages currently requiring or allowing human review.",
            snapshot.review_items,
        ),
        (
            "rejection_rejector_items_sent",
            "Number of rejection replies recorded as sent.",
            snapshot.sent_items,
        ),
        (
            "rejection_rejector_deliveries_uncertain",
            "Number of delivery attempts whose provider outcome remains uncertain.",
            snapshot.uncertain_deliveries,
        ),
        (
            "rejection_rejector_send_attempts_24h",
            "Rolling count of send attempts reserved during the last 24 hours.",
            snapshot.send_attempts_24h,
        ),
    ] {
        push_gauge(&mut out, name, help, None, value);
    }
    for (name, help, value) in [
        (
            "rejection_rejector_gmail_connected",
            "Whether a Gmail account is connected locally.",
            snapshot.gmail_connected,
        ),
        (
            "rejection_rejector_gmail_send_scope",
            "Whether Gmail send permission is available.",
            snapshot.gmail_send_scope,
        ),
        (
            "rejection_rejector_model_digest_pinned",
            "Whether the configured local model digest is pinned.",
            snapshot.model_digest_pinned,
        ),
        (
            "rejection_rejector_task_qualification_current",
            "Whether task-specific model qualification matches the current configuration.",
            snapshot.task_qualification_current,
        ),
        (
            "rejection_rejector_enterprise_policy_active",
            "Whether administrator enterprise policy is active.",
            snapshot.enterprise_policy_active,
        ),
        (
            "rejection_rejector_independent_audit_anchor_configured",
            "Whether an independent audit anchor is configured when required.",
            snapshot.independent_audit_anchor_configured,
        ),
        (
            "rejection_rejector_sync_fresh",
            "Whether mailbox synchronization is within the local freshness guardrail.",
            snapshot.operational.sync_fresh,
        ),
        (
            "rejection_rejector_operational_degraded",
            "Whether one or more privacy-safe operational degradation reasons are active.",
            snapshot.operational.degraded,
        ),
    ] {
        push_gauge(&mut out, name, help, None, metric_bool(value));
    }
    push_gauge(
        &mut out,
        "rejection_rejector_sync_age_seconds",
        "Age in seconds of the most recent successful mailbox synchronization, or -1 when unavailable.",
        Some("seconds"),
        snapshot.operational.sync_age_seconds.unwrap_or(-1),
    );
    push_gauge(
        &mut out,
        "rejection_rejector_task_qualification_age_seconds",
        "Age in seconds of current task-specific model qualification, or -1 when unavailable.",
        Some("seconds"),
        snapshot
            .operational
            .task_qualification_age_seconds
            .unwrap_or(-1),
    );
    out.push_str("# EOF\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};

    #[test]
    fn openmetrics_exposition_is_stable_private_and_spec_terminated() {
        let root = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            root.path().to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let snapshot = collect(&engine, Utc::now()).unwrap();
        let text = render_openmetrics(&snapshot);
        assert!(text.ends_with("# EOF\n"));
        assert!(!text.contains('\r'));
        assert!(text.contains("# TYPE rejection_rejector_up gauge\n"));
        assert!(text.contains("# UNIT rejection_rejector_storage_available_bytes bytes\n"));
        assert!(text.contains("rejection_rejector_storage_runtime_write_safe "));
        assert!(text.contains("rejection_rejector_operational_degraded "));
        for forbidden in [
            "demo@example.invalid",
            "Northstar Materials",
            "Alex Morgan",
            "refresh_token",
            "candidate_context",
            "api_token",
        ] {
            assert!(!text.contains(forbidden), "OpenMetrics leaked {forbidden}");
        }
    }

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

        assert_eq!(metrics.schema_version, 3);
        assert_eq!(metrics.service_name, "rejection-rejector");
        assert!(metrics.database_schema_version >= 1);
        assert_eq!(metrics.storage.schema_version, 1);
        assert_eq!(metrics.scheduled_backup.schema_version, 1);
        assert!(!metrics.scheduled_backup.enabled);
        assert_eq!(metrics.backup_isolation.schema_version, 1);
        assert!(!metrics.backup_isolation.configured);
        assert!(metrics.storage.total_bytes >= metrics.storage.available_bytes);
        assert!(metrics.stored_items >= 3);
        assert!(!metrics.policy_requires_independent_audit_anchor);
        assert!(!metrics.external_audit_anchor_configured);
        assert!(!metrics.os_protected_audit_anchor_required);
        assert!(!metrics.independent_audit_anchor_configured);
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
