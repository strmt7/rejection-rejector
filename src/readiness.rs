use crate::{
    config::{Mode, Settings},
    types::Counts,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct OperationalIndicators {
    pub sync_age_seconds: Option<i64>,
    pub sync_fresh: bool,
    pub queue_depth: u64,
    pub review_depth: u64,
    pub uncertain_deliveries: u64,
    pub task_qualification_age_seconds: Option<i64>,
    pub degraded: bool,
    pub degradation_reasons: Vec<&'static str>,
}

pub fn operational_indicators(
    settings: &Settings,
    counts: &Counts,
    last_poll: Option<DateTime<Utc>>,
    database_integrity_ok: bool,
    connected: bool,
    now: DateTime<Utc>,
) -> OperationalIndicators {
    let sync_age_seconds =
        last_poll.map(|poll| now.signed_duration_since(poll).num_seconds().max(0));
    let freshness_window = settings.interval_seconds().saturating_mul(2);
    let sync_fresh = connected && sync_age_seconds.is_some_and(|age| age <= freshness_window);

    let task_qualification_age_seconds =
        settings.task_qualification.as_ref().map(|qualification| {
            now.signed_duration_since(qualification.qualified_at)
                .num_seconds()
                .max(0)
        });

    let mut degradation_reasons = Vec::new();
    if !database_integrity_ok {
        degradation_reasons.push("database_integrity_failed");
    }
    if !connected {
        degradation_reasons.push("gmail_disconnected");
    } else if !sync_fresh {
        degradation_reasons.push("mailbox_sync_stale");
    }
    if counts.uncertain > 0 {
        degradation_reasons.push("uncertain_delivery_present");
    }
    if settings.mode == Mode::Automatic && !settings.task_qualification_current() {
        degradation_reasons.push("task_qualification_missing_or_stale");
    }

    OperationalIndicators {
        sync_age_seconds,
        sync_fresh,
        queue_depth: counts.queued,
        review_depth: counts.review,
        uncertain_deliveries: counts.uncertain,
        task_qualification_age_seconds,
        degraded: !degradation_reasons.is_empty(),
        degradation_reasons,
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RuntimeReadiness {
    pub live: bool,
    pub workspace_ready: bool,
    pub mailbox_sync_ready: bool,
    pub analysis_ready: bool,
    pub automatic_dispatch_ready: bool,
    pub automatic_block_reasons: Vec<&'static str>,
}

pub fn assess(
    settings: &Settings,
    database_integrity_ok: bool,
    connected: bool,
    send_scope: bool,
    paused: bool,
    stopping: bool,
) -> RuntimeReadiness {
    let live = !stopping;
    let workspace_ready = live && database_integrity_ok;
    let mailbox_sync_ready = workspace_ready && connected;
    let analysis_ready = mailbox_sync_ready && settings.model_digest.is_some();

    let mut reasons = Vec::new();
    if stopping {
        reasons.push("stopping");
    }
    if !database_integrity_ok {
        reasons.push("database_integrity_failed");
    }
    if !connected {
        reasons.push("gmail_disconnected");
    }
    if !send_scope {
        reasons.push("gmail_send_scope_missing");
    }
    if settings.mode != Mode::Automatic {
        reasons.push("automatic_mode_disabled");
    }
    if !settings.sending_enabled {
        reasons.push("sending_disabled");
    }
    if !settings.automatic_confirmed {
        reasons.push("automatic_consent_missing");
    }
    if settings.model_digest.is_none() {
        reasons.push("model_not_pinned");
    }
    if !settings.task_qualification_current() {
        reasons.push("task_qualification_missing_or_stale");
    }
    if paused {
        reasons.push("worker_paused");
    }

    RuntimeReadiness {
        live,
        workspace_ready,
        mailbox_sync_ready,
        analysis_ready,
        automatic_dispatch_ready: reasons.is_empty(),
        automatic_block_reasons: reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        PROMPT_VERSION, TaskQualification, evaluation_suite_hash, settings_context_hash,
    };
    use chrono::Utc;

    fn automatic_settings() -> Settings {
        let mut settings = Settings {
            mode: Mode::Automatic,
            sending_enabled: true,
            automatic_confirmed: true,
            automatic_since: Some(Utc::now()),
            signature: "Test Applicant".into(),
            model_digest: Some("a".repeat(64)),
            ..Settings::default()
        };
        settings.task_qualification = Some(TaskQualification {
            model: settings.model.clone(),
            digest: settings.model_digest.clone().unwrap(),
            prompt_version: PROMPT_VERSION.into(),
            context_hash: settings_context_hash(&settings),
            suite_hash: evaluation_suite_hash(),
            ollama_runtime_version: "0.34.0".into(),
            task_score: 100.0,
            fixture_count: 32,
            qualified_at: Utc::now(),
        });
        settings
    }

    #[test]
    fn operational_indicators_report_staleness_without_invented_slos() {
        let now = Utc::now();
        let settings = Settings {
            poll_hours: 1,
            ..Settings::default()
        };
        let counts = Counts {
            queued: 4,
            review: 2,
            uncertain: 1,
            ..Counts::default()
        };
        let indicators = operational_indicators(
            &settings,
            &counts,
            Some(now - chrono::Duration::hours(3)),
            true,
            true,
            now,
        );
        assert!(!indicators.sync_fresh);
        assert!(indicators.degraded);
        assert!(
            indicators
                .degradation_reasons
                .contains(&"mailbox_sync_stale")
        );
        assert!(
            indicators
                .degradation_reasons
                .contains(&"uncertain_delivery_present")
        );
        assert_eq!(indicators.queue_depth, 4);
        assert_eq!(indicators.review_depth, 2);
        assert_eq!(indicators.uncertain_deliveries, 1);

        let fresh = operational_indicators(
            &settings,
            &Counts::default(),
            Some(now - chrono::Duration::minutes(30)),
            true,
            true,
            now,
        );
        assert!(fresh.sync_fresh);
        assert!(!fresh.degraded);
    }

    #[test]
    fn readiness_is_fail_closed_and_reasoned() {
        let default = assess(&Settings::default(), true, false, false, false, false);
        assert!(default.live);
        assert!(default.workspace_ready);
        assert!(!default.mailbox_sync_ready);
        assert!(!default.automatic_dispatch_ready);
        assert!(
            default
                .automatic_block_reasons
                .contains(&"gmail_disconnected")
        );

        let settings = automatic_settings();
        let ready = assess(&settings, true, true, true, false, false);
        assert!(ready.automatic_dispatch_ready);
        assert!(ready.automatic_block_reasons.is_empty());

        let paused = assess(&settings, true, true, true, true, false);
        assert!(!paused.automatic_dispatch_ready);
        assert_eq!(paused.automatic_block_reasons, vec!["worker_paused"]);
    }
}
