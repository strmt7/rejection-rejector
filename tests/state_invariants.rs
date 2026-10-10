//! Deterministic randomized invariants for enterprise state machines.
//! Fixed seeds make failures reproducible while exercising thousands of combinations.

use chrono::Utc;
use rand::{RngExt, SeedableRng, rngs::StdRng};
use rejection_rejector::{
    config::{
        Mode, PROMPT_VERSION, Settings, TaskQualification, evaluation_suite_hash,
        settings_context_hash,
    },
    policy::{EnterprisePolicy, LoadedPolicy, PolicyRevisionFloor},
    readiness,
};

const SEED: u64 = 0x5252_454A_4543_544F;

fn digest(ch: char) -> String {
    std::iter::repeat_n(ch, 64).collect()
}

fn automatic_settings() -> Settings {
    let mut settings = Settings {
        mode: Mode::Automatic,
        sending_enabled: true,
        automatic_confirmed: true,
        automatic_since: Some(Utc::now()),
        signature: "Invariant Test Applicant".into(),
        model_digest: Some(digest('a')),
        ..Settings::default()
    };
    settings.task_qualification = Some(TaskQualification {
        model: settings.model.clone(),
        digest: settings.model_digest.clone().expect("test model digest"),
        prompt_version: PROMPT_VERSION.into(),
        context_hash: settings_context_hash(&settings),
        suite_hash: evaluation_suite_hash(),
        ollama_runtime_version: "0.35.0".into(),
        task_score: 100.0,
        fixture_count: 72,
        qualified_at: Utc::now(),
    });
    settings.validate().expect("synthetic automatic settings");
    settings
}

#[test]
fn enterprise_policy_is_monotone_and_idempotent_across_generated_settings() {
    let mut rng = StdRng::seed_from_u64(SEED);

    for case in 0..10_000u32 {
        let mut settings = Settings {
            signature: "Invariant Test Applicant".into(),
            sending_enabled: rng.random_bool(0.5),
            api_enabled: rng.random_bool(0.5),
            daily_send_limit: rng.random_range(1..=100),
            cooldown_minutes: rng.random_range(1..=1440),
            retention_days: rng.random_range(30..=3650),
            ..Settings::default()
        };
        settings.validate().expect("generated baseline settings");

        let restrict_primary = rng.random_bool(0.35);
        let restrict_verifier = rng.random_bool(0.35);
        let require_independent_verifier = rng.random_bool(0.5);
        let policy = EnterprisePolicy {
            version: 3,
            policy_id: Some("generated-policy".into()),
            revision: Some(1),
            force_human_review: rng.random_bool(0.25),
            prohibit_sending: rng.random_bool(0.25),
            prohibit_integration_api: rng.random_bool(0.25),
            prohibit_recovery_key_export: rng.random_bool(0.25),
            require_external_audit_anchor: rng.random_bool(0.25),
            require_independent_verifier,
            max_daily_send_limit: rng.random_bool(0.75).then(|| rng.random_range(1..=100)),
            min_cooldown_minutes: rng.random_bool(0.75).then(|| rng.random_range(1..=1440)),
            min_retention_days: rng.random_bool(0.75).then(|| rng.random_range(30..=3650)),
            allowed_models: if restrict_primary {
                vec!["granite4.2:8b-q8_0".into()]
            } else {
                vec![]
            },
            allowed_verifier_models: if restrict_verifier {
                vec!["qwen3.5:4b".into()]
            } else {
                vec![]
            },
            ..EnterprisePolicy::default()
        };
        policy.validate().expect("generated enterprise policy");

        let before = settings.clone();
        let first_changed = policy
            .enforce(&mut settings, true)
            .unwrap_or_else(|error| panic!("case {case} first enforcement failed: {error:#}"));

        if let Some(limit) = policy.max_daily_send_limit {
            assert!(
                settings.daily_send_limit <= before.daily_send_limit.min(limit),
                "case {case}: policy increased daily send capability"
            );
        } else {
            assert_eq!(settings.daily_send_limit, before.daily_send_limit);
        }
        if let Some(minimum) = policy.min_cooldown_minutes {
            assert!(
                settings.cooldown_minutes >= before.cooldown_minutes.max(minimum),
                "case {case}: policy reduced cooldown"
            );
        } else {
            assert_eq!(settings.cooldown_minutes, before.cooldown_minutes);
        }
        if let Some(minimum) = policy.min_retention_days {
            assert!(
                settings.retention_days >= before.retention_days.max(minimum),
                "case {case}: policy reduced retention"
            );
        } else {
            assert_eq!(settings.retention_days, before.retention_days);
        }
        if policy.force_human_review || policy.prohibit_sending {
            assert_eq!(settings.mode, Mode::HumanReview);
            assert!(!settings.sending_enabled);
        }
        if policy.prohibit_integration_api {
            assert!(!settings.api_enabled);
        }
        if policy.require_independent_verifier {
            assert!(settings.independent_verifier_enabled);
        }
        if !policy.allowed_models.is_empty() {
            assert!(policy.allowed_models.contains(&settings.model));
        }
        if !policy.allowed_verifier_models.is_empty() {
            assert!(
                policy
                    .allowed_verifier_models
                    .contains(&settings.verifier_model)
            );
        }

        let once = settings.clone();
        let second_changed = policy
            .enforce(&mut settings, true)
            .unwrap_or_else(|error| panic!("case {case} second enforcement failed: {error:#}"));
        assert_eq!(settings, once, "case {case}: policy is not idempotent");
        assert!(
            !second_changed,
            "case {case}: second enforcement reported drift"
        );
        assert_eq!(first_changed, before != once);
    }
}

fn loaded(revision: u64, digest: String) -> LoadedPolicy {
    LoadedPolicy {
        policy: EnterprisePolicy {
            version: 2,
            policy_id: Some("org-production".into()),
            revision: Some(revision),
            ..EnterprisePolicy::default()
        },
        digest,
        expected_digest: None,
        signature_enforced: false,
        signature_verified: false,
        signer_key_sha256: None,
    }
}

#[test]
fn revision_floor_never_rolls_back_or_accepts_same_revision_drift() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x00A1_1D17);
    for case in 0..5_000u32 {
        let base = rng.random_range(2..=1_000_000u64);
        let advance = rng.random_range(1..=10_000u64);
        let mut floor = PolicyRevisionFloor::default();

        assert!(
            floor
                .observe(&loaded(base, digest('a')))
                .expect("initial observe")
        );
        assert!(
            !floor
                .observe(&loaded(base, digest('a')))
                .expect("same revision same digest")
        );
        assert!(
            floor.observe(&loaded(base, digest('b'))).is_err(),
            "case {case}: same revision content drift accepted"
        );
        assert!(
            floor.observe(&loaded(base - 1, digest('a'))).is_err(),
            "case {case}: rollback accepted"
        );
        assert!(
            floor
                .observe(&loaded(base + advance, digest('c')))
                .expect("higher revision must advance"),
            "case {case}: higher revision did not advance floor"
        );
        assert!(
            floor.observe(&loaded(base, digest('a'))).is_err(),
            "case {case}: old revision accepted after advancing"
        );
    }
}

#[test]
fn automatic_readiness_is_exactly_fail_closed_over_generated_runtime_states() {
    let settings = automatic_settings();
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x5AFE_7EAD);

    for case in 0..10_000u32 {
        let database_integrity_ok = rng.random_bool(0.5);
        let storage_write_safe = rng.random_bool(0.5);
        let connected = rng.random_bool(0.5);
        let send_scope = rng.random_bool(0.5);
        let paused = rng.random_bool(0.5);
        let stopping = rng.random_bool(0.5);

        let assessed = readiness::assess(
            &settings,
            database_integrity_ok,
            storage_write_safe,
            connected,
            send_scope,
            paused,
            stopping,
        );
        let expected = !stopping
            && database_integrity_ok
            && storage_write_safe
            && connected
            && send_scope
            && !paused;

        assert_eq!(
            assessed.automatic_dispatch_ready, expected,
            "case {case}: readiness truth table drifted"
        );
        assert_eq!(assessed.live, !stopping);
        assert_eq!(
            assessed.workspace_ready,
            !stopping && database_integrity_ok && storage_write_safe
        );
        assert_eq!(
            assessed.mailbox_sync_ready,
            !stopping && database_integrity_ok && storage_write_safe && connected
        );
        assert!(
            assessed.automatic_dispatch_ready || !assessed.automatic_block_reasons.is_empty(),
            "case {case}: blocked state had no machine-readable reason"
        );
    }
}
