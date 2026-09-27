use crate::{engine::Engine, ollama::Ollama, vault::write_new_private};
use anyhow::Result;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};

pub fn report(engine: &Engine) -> Result<Value> {
    let integrity = engine.db.integrity_check();
    let database_bytes = std::fs::metadata(engine.directory.join("state.sqlite3"))
        .ok()
        .map(|metadata| metadata.len());
    let counts = engine.db.counts(&engine.account)?;
    let paused = engine
        .paused
        .load(std::sync::atomic::Ordering::SeqCst);
    let stopping = engine
        .stop
        .load(std::sync::atomic::Ordering::SeqCst);
    let readiness = crate::readiness::assess(
        &engine.settings,
        integrity.is_ok(),
        engine.connected(),
        engine.send_scope(),
        paused,
        stopping,
    );

    let local_ai = Ollama::new(&engine.settings)?;
    let runtime_version = local_ai.runtime_version().ok();
    let model_status = if runtime_version.is_some() {
        local_ai.inspect().ok()
    } else {
        None
    };

    let mut event_kinds = BTreeMap::<String, u64>::new();
    let latest = engine.db.latest_event_seq()?;
    for event in engine.db.events((latest - 200).max(0), 200)? {
        *event_kinds.entry(event.kind).or_default() += 1;
    }

    let qualification = engine.settings.task_qualification.as_ref().map(|q| {
        json!({
            "model": q.model,
            "digest": q.digest,
            "prompt_version": q.prompt_version,
            "context_hash": q.context_hash,
            "suite_hash": q.suite_hash,
            "task_score": q.task_score,
            "fixture_count": q.fixture_count,
            "qualified_at": q.qualified_at
        })
    });

    Ok(json!({
        "report_version": 1,
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
        "application": {
            "version": env!("CARGO_PKG_VERSION"),
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
        "delivery_policy": {
            "mode": engine.settings.mode,
            "sending_enabled": engine.settings.sending_enabled,
            "automatic_confirmed": engine.settings.automatic_confirmed,
            "include_backlog": engine.settings.include_backlog,
            "cooldown_minutes": engine.settings.cooldown_minutes,
            "daily_send_limit": engine.settings.daily_send_limit,
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
        "recent_audit_event_kinds": event_kinds,
        "note": "Redacted local diagnostic report. Review it before sharing. Rejection Rejector never uploads this report automatically."
    }))
}

pub fn write_report(engine: &Engine, path: &Path) -> Result<()> {
    let data = report(engine)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    write_new_private(path, &serde_json::to_vec_pretty(&data)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use std::sync::{atomic::AtomicBool, Arc};

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
        assert_eq!(report["database"]["integrity_ok"], true);
    }
}
