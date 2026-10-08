use crate::{engine::Engine, ollama::Ollama, vault::write_new_private};
use anyhow::Result;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

pub fn report(engine: &Engine) -> Result<Value> {
    let integrity = engine.db.integrity_check();
    let database_bytes = std::fs::metadata(engine.directory.join("state.sqlite3"))
        .ok()
        .map(|metadata| metadata.len());
    let counts = engine.db.counts(&engine.account)?;
    let processing_failures = engine.db.processing_failure_summary(&engine.account)?;
    let storage = crate::storage::inspect(&engine.directory)?;
    let scheduled_backup =
        crate::recovery::scheduled_backup_status(&engine.db, &engine.settings, chrono::Utc::now())?;
    let backup_isolation =
        crate::recovery::backup_isolation_status(&engine.directory, &engine.settings)?;
    let paused = engine.paused.load(std::sync::atomic::Ordering::SeqCst);
    let stopping = engine.stop.load(std::sync::atomic::Ordering::SeqCst);
    let emergency_stop = crate::emergency::status_fail_closed();
    let readiness = crate::readiness::assess_context(crate::readiness::RuntimeReadinessContext {
        settings: &engine.settings,
        database_integrity_ok: integrity.is_ok(),
        storage_write_safe: storage.runtime_write_safe,
        connected: engine.connected(),
        send_scope: engine.send_scope(),
        paused,
        stopping,
        emergency_stop_active: emergency_stop.active,
    });
    let operational =
        crate::readiness::operational_indicators(crate::readiness::OperationalContext {
            settings: &engine.settings,
            counts: &counts,
            last_poll: engine.last_poll()?,
            database_integrity_ok: integrity.is_ok(),
            storage_write_safe: storage.runtime_write_safe,
            scheduled_backup_overdue: scheduled_backup.overdue,
            backup_distinct_failure_domain: backup_isolation.distinct_failure_domain,
            connected: engine.connected(),
            now: chrono::Utc::now(),
        });

    let local_ai = Ollama::new(&engine.settings)?;
    let runtime_version = local_ai.runtime_version().ok();
    let model_status = if runtime_version.is_some() {
        local_ai.inspect().ok()
    } else {
        None
    };

    let mut event_kinds = BTreeMap::<String, u64>::new();
    let mut event_domains = BTreeMap::<String, u64>::new();
    let mut event_severities = BTreeMap::<String, u64>::new();
    let latest = engine.db.latest_event_seq()?;
    for event in engine.db.events((latest - 200).max(0), 200)? {
        *event_kinds.entry(event.kind).or_default() += 1;
        *event_domains
            .entry(event.domain.as_str().to_owned())
            .or_default() += 1;
        *event_severities
            .entry(event.severity.as_str().to_owned())
            .or_default() += 1;
    }

    let qualification = engine.settings.task_qualification.as_ref().map(|q| {
        json!({
            "model": q.model,
            "digest": q.digest,
            "prompt_version": q.prompt_version,
            "context_hash": q.context_hash,
            "suite_hash": q.suite_hash,
            "ollama_runtime_version": q.ollama_runtime_version,
            "task_score": q.task_score,
            "fixture_count": q.fixture_count,
            "qualified_at": q.qualified_at
        })
    });

    let policy_status = engine.enterprise_policy_status();
    let external_audit_anchor_configured =
        std::env::var_os(crate::audit_anchor::AUDIT_ANCHOR_ENV).is_some();
    let os_protected_audit_anchor_required = crate::audit_anchor::os_anchor_required()?;
    let independent_audit_anchor_configured =
        external_audit_anchor_configured || os_protected_audit_anchor_required;

    Ok(json!({
        "report_version": 5,
        "generated_at": chrono::Utc::now(),
        "privacy": {
            "contains_account_address": false,
            "contains_message_content": false,
            "contains_recipient_addresses": false,
            "contains_oauth_credentials": false,
            "contains_api_token": false,
            "contains_signature": false,
            "contains_candidate_facts": false,
            "automatic_upload": false
        },
        "readiness": readiness,
        "operational": operational,
        "runtime_log": crate::runtime_log::status(&engine.directory).ok(),
        "runtime_performance": crate::runtime_log::performance_summary(&engine.directory).ok(),
        "storage": storage,
        "scheduled_backup": scheduled_backup,
        "backup_isolation": backup_isolation,
        "application": {
            "version": env!("CARGO_PKG_VERSION"),
            "build": crate::build_info::current(),
            "settings_format_version": engine.settings.settings_format_version,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "demo": engine.demo
        },
        "database": {
            "integrity_ok": integrity.is_ok(),
            "integrity_message": integrity
                .as_ref()
                .map(|_| "ok".to_string())
                .unwrap_or_else(|error| error.to_string()),
            "schema_version": engine.db.schema_version()?,
            "audit_head": engine.db.audit_head()?,
            "bytes": database_bytes,
            "counts": counts
        },
        "processing_failures": processing_failures,
        "gmail": {
            "connected": engine.connected(),
            "send_scope": engine.send_scope()
        },
        "scheduler": {
            "poll_hours": engine.settings.poll_hours,
            "lookback_days": engine.settings.lookback_days,
            "last_poll": engine.last_poll()?,
            "paused": paused
        },
        "enterprise_policy": policy_status,
        // emergency_stop reflects the live state of the RR_EMERGENCY_STOP_FILE sentinel (fail-closed)
        "emergency_stop": emergency_stop,
        "audit_protection": {
            "policy_requires_independent_anchor": policy_status.require_external_audit_anchor,
            "external_file_anchor_configured": external_audit_anchor_configured,
            "os_protected_anchor_required": os_protected_audit_anchor_required,
            "independent_anchor_configured": independent_audit_anchor_configured
        },
        "delivery_policy": {
            "mode": engine.settings.mode,
            "sending_enabled": engine.settings.sending_enabled,
            "automatic_confirmed": engine.settings.automatic_confirmed,
            "include_backlog": engine.settings.include_backlog,
            "cooldown_minutes": engine.settings.cooldown_minutes,
            "daily_send_limit": engine.settings.daily_send_limit,
            "automatic_recipient_attempt_limit_24h": crate::config::AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H,
            "retention_days": engine.settings.retention_days
        },
        "local_ai": {
            "ollama_origin": "literal-loopback-only",
            "runtime_version": runtime_version,
            "model": engine.settings.model,
            "model_digest_pinned": engine.settings.model_digest,
            "num_ctx": engine.settings.num_ctx,
            "task_qualification": qualification,
            "installed_model": model_status.map(|status| json!({
                "digest": status.digest,
                "size": status.size,
                "size_vram": status.size_vram,
                "context": status.context,
                "gpu_resident": status.gpu_resident,
                "message": status.message
            }))
        },
        "integration_api": {
            "configured_enabled": engine.settings.api_enabled,
            "port": engine.settings.api_port,
            "read_only": true
        },
        "recent_audit": {
            "window": 200,
            "event_kinds": event_kinds,
            "domains": event_domains,
            "severities": event_severities
        },
        "note": "Redacted local diagnostic report. Review it before sharing. Rejection Rejector never uploads this report automatically."
    }))
}

pub fn write_report(engine: &Engine, path: &Path) -> Result<()> {
    let data = report(engine)?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    write_new_private(path, &serde_json::to_vec_pretty(&data)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use std::sync::{Arc, atomic::AtomicBool};

    /// Test that the diagnostics report omits all sensitive private information.
    ///
    /// This test verifies that the JSON diagnostics output does not leak:
    /// - Email addresses (demo@example.invalid)
    /// - Employer names (Northstar Materials)
    /// - Person names (Alex Morgan)
    /// - Signature (SENSITIVE_SIGNATURE_CANARY)
    /// - Candidate context (SENSITIVE_PROFILE_CANARY)
    /// - API token (SENSITIVE_API_TOKEN_CANARY)
    /// - Refresh token (SENSITIVE_REFRESH_TOKEN_CANARY)
    ///
    /// It also verifies that the privacy section correctly reports:
    /// - contains_api_token: false
    /// - contains_oauth_credentials: false
    /// - contains_candidate_facts: false
    /// - automatic_upload: false
    ///
    /// And that the emergency_stop section reflects the sentinel state
    /// (both active and configured should be false in this test).
    #[test]
    fn diagnostic_report_omits_private_mail_and_profile_fields() {
        let root = tempfile::tempdir().unwrap();
        let mut engine = Engine::open(
            root.path().to_path_buf(),
            true,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        engine.settings.signature = "SENSITIVE_SIGNATURE_CANARY".into();
        engine.settings.candidate_context = "SENSITIVE_PROFILE_CANARY".into();
        engine
            .db
            .set_meta("api_token", &"SENSITIVE_API_TOKEN_CANARY")
            .unwrap();
        engine
            .db
            .set_meta("refresh_token_test", &"SENSITIVE_REFRESH_TOKEN_CANARY")
            .unwrap();

        let report = report(&engine).unwrap();
        let text = report.to_string();
        for forbidden in [
            "demo@example.invalid",
            "Northstar Materials",
            "Alex Morgan",
            "SENSITIVE_SIGNATURE_CANARY",
            "SENSITIVE_PROFILE_CANARY",
            "SENSITIVE_API_TOKEN_CANARY",
            "SENSITIVE_REFRESH_TOKEN_CANARY",
        ] {
            assert!(!text.contains(forbidden), "diagnostics leaked {forbidden}");
        }
        assert_eq!(report["privacy"]["contains_api_token"], false);
        assert_eq!(report["privacy"]["contains_oauth_credentials"], false);
        assert_eq!(report["privacy"]["contains_candidate_facts"], false);
        assert_eq!(report["privacy"]["automatic_upload"], false);
        assert_eq!(report["report_version"], 5);
        assert_eq!(report["processing_failures"]["active_records"], 0);
        assert_eq!(report["processing_failures"]["retry_exhausted"], 0);
        assert!(report["processing_failures"]["by_code"].is_object());
        assert_eq!(report["storage"]["schema_version"], 1);
        assert_eq!(report["scheduled_backup"]["schema_version"], 1);
        assert_eq!(report["backup_isolation"]["schema_version"], 1);
        assert_eq!(report["enterprise_policy"]["active"], false);
        assert_eq!(
            report["audit_protection"]["policy_requires_independent_anchor"],
            false
        );
        assert_eq!(
            report["audit_protection"]["independent_anchor_configured"],
            false
        );
        assert_eq!(report["emergency_stop"]["active"], false);
        assert_eq!(report["emergency_stop"]["configured"], false);
        assert_eq!(report["database"]["integrity_ok"], true);
        assert!(report["runtime_log"].is_object() || report["runtime_log"].is_null());
        if report["runtime_log"].is_object() {
            assert!(report["runtime_log"]["total_bytes"].is_u64());
        }
        assert!(
            report["runtime_performance"].is_object() || report["runtime_performance"].is_null()
        );
        if report["runtime_performance"].is_object() {
            assert!(report["runtime_performance"]["retained_operation_records"].is_u64());
        }
        assert!(report["operational"]["queue_depth"].is_number());
        assert!(report["operational"]["degradation_reasons"].is_array());
        assert!(report["recent_audit"]["domains"].is_object());
        assert!(report["recent_audit"]["severities"].is_object());
    }
}
