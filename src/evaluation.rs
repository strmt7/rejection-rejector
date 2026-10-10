use crate::{
    config::{EVALUATION_CONTRACT_VERSION, MODEL_CANDIDATES, Settings, evaluation_suite_hash},
    mail,
    ollama::{Ollama, sample_email},
    types::Category,
    vault::write_new_private,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum CaseTag {
    Multilingual,
    AtsAutomation,
    Interview,
    Offer,
    RecruiterCorrection,
    QuotedHistory,
    PromptInjection,
    Ambiguous,
    PendingStatus,
    Assessment,
    TalentPool,
    RoleClosure,
    ApplicationActionRequired,
    Survey,
}

impl CaseTag {
    fn as_str(self) -> &'static str {
        match self {
            Self::Multilingual => "multilingual",
            Self::AtsAutomation => "ats_automation",
            Self::Interview => "interview",
            Self::Offer => "offer",
            Self::RecruiterCorrection => "recruiter_correction",
            Self::QuotedHistory => "quoted_history",
            Self::PromptInjection => "prompt_injection",
            Self::Ambiguous => "ambiguous",
            Self::PendingStatus => "pending_status",
            Self::Assessment => "assessment",
            Self::TalentPool => "talent_pool",
            Self::RoleClosure => "role_closure",
            Self::ApplicationActionRequired => "application_action_required",
            Self::Survey => "survey",
        }
    }

    fn critical_negative(self) -> bool {
        matches!(
            self,
            Self::Interview
                | Self::Offer
                | Self::RecruiterCorrection
                | Self::QuotedHistory
                | Self::PromptInjection
                | Self::Ambiguous
                | Self::Assessment
                | Self::TalentPool
                | Self::RoleClosure
                | Self::ApplicationActionRequired
        )
    }
}

#[derive(Clone, Deserialize)]
struct Case {
    id: String,
    subject: String,
    text: String,
    expected: Category,
    #[serde(default)]
    tags: Vec<CaseTag>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct TagSummary {
    cases: usize,
    completed: usize,
    correct: usize,
    expected_rejections: usize,
    rejection_true_positives: usize,
    rejection_false_positives: usize,
    rejection_false_negatives: usize,
    verified_rejection_pipeline: usize,
    unsafe_non_rejection_drafts: usize,
}

#[derive(Clone, Debug, Serialize)]
struct Summary {
    fixture_count: usize,
    completed: usize,
    correct: usize,
    accuracy: Option<f64>,
    rejection_true_positive: usize,
    rejection_false_positive: usize,
    rejection_false_negative: usize,
    rejection_precision: Option<f64>,
    rejection_recall: Option<f64>,
    non_rejection_false_positive_avoidance: Option<f64>,
    verified_rejection_pipeline: usize,
    expected_rejections: usize,
    verified_rejection_pipeline_rate: Option<f64>,
    unsafe_non_rejection_drafts: usize,
    critical_negative_cases: usize,
    critical_negative_completed: usize,
    critical_negative_rejection_false_positives: usize,
    critical_negative_unsafe_drafts: usize,
    deterministic_rejection_evidence_hits: usize,
    deterministic_rejection_evidence_false_positives: usize,
    deterministic_rejection_evidence_recall: Option<f64>,
    multilingual_rejection_recall: Option<f64>,
    multilingual_verified_rejection_pipeline_rate: Option<f64>,
    mean_seconds: Option<f64>,
    task_score: f64,
    recommendation_eligible: bool,
    tag_metrics: BTreeMap<String, TagSummary>,
}

fn fixtures() -> Result<Vec<Case>> {
    Ok(serde_json::from_str(include_str!(
        "../tests/fixtures/classification.json"
    ))?)
}

/// Evaluate the complete configured local pipeline on synthetic recruiting mail.
///
/// This is deliberately application-specific. False rejection replies are weighted
/// more heavily than missed rejections because an unattended reply to an interview,
/// offer, quoted history, or adversarial message is the costliest model error here.
fn evaluate(settings: &Settings) -> Result<serde_json::Value> {
    let cases = fixtures()?;
    let unpinned = {
        let mut s = settings.clone();
        s.disarm_delivery();
        s.model_digest = None;
        s
    };
    let qualified = Ollama::new(&unpinned)?.qualify()?;
    let mut pinned = unpinned;
    pinned.model_digest = Some(qualified.digest.clone());
    let llm = Ollama::new(&pinned)?;
    let ollama_runtime_version = llm.runtime_version()?;

    let mut rows = Vec::new();
    let mut correct = 0usize;
    let mut rejection_tp = 0usize;
    let mut rejection_fp = 0usize;
    let mut rejection_fn = 0usize;
    let mut expected_rejections = 0usize;
    let mut verified_pipeline = 0usize;
    let mut unsafe_non_rejection_drafts = 0usize;
    let mut critical_negative_cases = 0usize;
    let mut critical_negative_completed = 0usize;
    let mut critical_negative_rejection_false_positives = 0usize;
    let mut critical_negative_unsafe_drafts = 0usize;
    let mut deterministic_rejection_evidence_hits = 0usize;
    let mut deterministic_rejection_evidence_false_positives = 0usize;
    let mut tag_metrics = BTreeMap::<String, TagSummary>::new();
    let mut completed = 0usize;
    let mut total_seconds = 0.0f64;

    for case in &cases {
        expected_rejections += usize::from(case.expected == Category::Rejection);
        let critical_negative = case.expected != Category::Rejection
            && case.tags.iter().copied().any(CaseTag::critical_negative);
        critical_negative_cases += usize::from(critical_negative);
        let deterministic_rejection_evidence =
            mail::clear_rejection_language(&case.subject, &case.text)
                && !mail::auto_language_conflict(&case.subject, &case.text);
        deterministic_rejection_evidence_hits +=
            usize::from(case.expected == Category::Rejection && deterministic_rejection_evidence);
        deterministic_rejection_evidence_false_positives +=
            usize::from(case.expected != Category::Rejection && deterministic_rejection_evidence);
        for tag in &case.tags {
            let metrics = tag_metrics.entry(tag.as_str().into()).or_default();
            metrics.cases += 1;
            metrics.expected_rejections += usize::from(case.expected == Category::Rejection);
        }
        let start = std::time::Instant::now();
        match llm.analyze(&sample_email(&case.subject, &case.text)) {
            Ok((analysis, draft, flags)) => {
                let seconds = start.elapsed().as_secs_f64();
                total_seconds += seconds;
                completed += 1;
                critical_negative_completed += usize::from(critical_negative);
                let actual = analysis.verdict.category;
                let matched = actual == case.expected;
                correct += usize::from(matched);
                rejection_tp += usize::from(
                    actual == Category::Rejection && case.expected == Category::Rejection,
                );
                rejection_fp += usize::from(
                    actual == Category::Rejection && case.expected != Category::Rejection,
                );
                rejection_fn += usize::from(
                    actual != Category::Rejection && case.expected == Category::Rejection,
                );

                let verification_passed =
                    analysis.verification.as_ref().is_some_and(|v| v.passed());
                let draft_safe = draft.as_ref().is_some_and(|d| {
                    mail::validate_draft(&d.body).is_ok()
                        && !mail::automatic_draft_conflict(&d.body, &pinned.signature)
                });
                let rejection_pipeline_passed = case.expected == Category::Rejection
                    && actual == Category::Rejection
                    && verification_passed
                    && draft_safe
                    && flags.is_empty();
                verified_pipeline += usize::from(rejection_pipeline_passed);

                let non_rejection_draft = case.expected != Category::Rejection && draft.is_some();
                unsafe_non_rejection_drafts += usize::from(non_rejection_draft);
                let rejection_false_positive =
                    case.expected != Category::Rejection && actual == Category::Rejection;
                critical_negative_rejection_false_positives +=
                    usize::from(critical_negative && rejection_false_positive);
                critical_negative_unsafe_drafts +=
                    usize::from(critical_negative && non_rejection_draft);
                for tag in &case.tags {
                    let metrics = tag_metrics.get_mut(tag.as_str()).ok_or_else(|| {
                        anyhow::anyhow!("Evaluation tag registry invariant failed")
                    })?;
                    metrics.completed += 1;
                    metrics.correct += usize::from(matched);
                    metrics.rejection_true_positives += usize::from(
                        actual == Category::Rejection && case.expected == Category::Rejection,
                    );
                    metrics.rejection_false_positives += usize::from(rejection_false_positive);
                    metrics.rejection_false_negatives += usize::from(
                        actual != Category::Rejection && case.expected == Category::Rejection,
                    );
                    metrics.verified_rejection_pipeline += usize::from(rejection_pipeline_passed);
                    metrics.unsafe_non_rejection_drafts += usize::from(non_rejection_draft);
                }

                rows.push(serde_json::json!({
                    "id": case.id,
                    "tags": case.tags.iter().map(|tag| tag.as_str()).collect::<Vec<_>>(),
                    "critical_negative": critical_negative,
                    "deterministic_rejection_evidence": deterministic_rejection_evidence,
                    "expected": case.expected,
                    "actual": actual,
                    "match": matched,
                    "seconds": seconds,
                    "evidence": analysis.verdict.evidence,
                    "verification_passed": verification_passed,
                    "draft_generated": draft.is_some(),
                    "rejection_pipeline_passed": rejection_pipeline_passed,
                    "flags": flags
                }));
            }
            Err(error) => rows.push(serde_json::json!({
                "id": case.id,
                "tags": case.tags.iter().map(|tag| tag.as_str()).collect::<Vec<_>>(),
                "critical_negative": critical_negative,
                "expected": case.expected,
                "error": error.to_string(),
                "match": false
            })),
        }
    }

    let non_rejections = cases.len().saturating_sub(expected_rejections);
    let accuracy = ratio(correct, cases.len());
    let precision = ratio(rejection_tp, rejection_tp + rejection_fp);
    let recall = ratio(rejection_tp, rejection_tp + rejection_fn);
    let fp_avoidance = ratio(non_rejections.saturating_sub(rejection_fp), non_rejections);
    let pipeline_rate = ratio(verified_pipeline, expected_rejections);
    let deterministic_rejection_evidence_recall =
        ratio(deterministic_rejection_evidence_hits, expected_rejections);
    let multilingual = tag_metrics.get(CaseTag::Multilingual.as_str());
    let multilingual_rejection_recall = multilingual.and_then(|metrics| {
        ratio(
            metrics.rejection_true_positives,
            metrics.rejection_true_positives + metrics.rejection_false_negatives,
        )
    });
    let multilingual_verified_rejection_pipeline_rate = multilingual.and_then(|metrics| {
        ratio(
            metrics.verified_rejection_pipeline,
            metrics.expected_rejections,
        )
    });
    let completion_rate = ratio(completed, cases.len()).unwrap_or(0.0);

    // Task-specific weighting: false-positive avoidance dominates because replying
    // to an offer/interview is materially worse than holding a genuine rejection.
    let task_score = task_score(
        fp_avoidance,
        recall,
        pipeline_rate,
        accuracy,
        completion_rate,
    );

    let recommendation_eligible = completed == cases.len()
        && rejection_fp == 0
        && unsafe_non_rejection_drafts == 0
        && critical_negative_completed == critical_negative_cases
        && critical_negative_rejection_false_positives == 0
        && critical_negative_unsafe_drafts == 0
        && deterministic_rejection_evidence_false_positives == 0
        && deterministic_rejection_evidence_recall.unwrap_or(0.0) >= 0.90
        && recall.unwrap_or(0.0) >= 0.90
        && pipeline_rate.unwrap_or(0.0) >= 0.90
        && multilingual_rejection_recall.unwrap_or(0.0) >= 0.85
        && multilingual_verified_rejection_pipeline_rate.unwrap_or(0.0) >= 0.85
        && qualified.gpu_resident;

    let summary = Summary {
        fixture_count: cases.len(),
        completed,
        correct,
        accuracy,
        rejection_true_positive: rejection_tp,
        rejection_false_positive: rejection_fp,
        rejection_false_negative: rejection_fn,
        rejection_precision: precision,
        rejection_recall: recall,
        non_rejection_false_positive_avoidance: fp_avoidance,
        verified_rejection_pipeline: verified_pipeline,
        expected_rejections,
        verified_rejection_pipeline_rate: pipeline_rate,
        unsafe_non_rejection_drafts,
        critical_negative_cases,
        critical_negative_completed,
        critical_negative_rejection_false_positives,
        critical_negative_unsafe_drafts,
        deterministic_rejection_evidence_hits,
        deterministic_rejection_evidence_false_positives,
        deterministic_rejection_evidence_recall,
        multilingual_rejection_recall,
        multilingual_verified_rejection_pipeline_rate,
        mean_seconds: (completed != 0).then(|| total_seconds / completed as f64),
        task_score,
        recommendation_eligible,
        tag_metrics,
    };

    Ok(serde_json::json!({
        "timestamp": chrono::Utc::now(),
        "suite": EVALUATION_CONTRACT_VERSION,
        "suite_hash": evaluation_suite_hash(),
        "ollama_runtime_version": ollama_runtime_version,
        "model": pinned.model,
        "digest": qualified.digest,
        "context": pinned.num_ctx,
        "qualification": {
            "gpu_resident": qualified.gpu_resident,
            "size_vram": qualified.size_vram,
            "reported_context": qualified.context
        },
        "summary": summary,
        "results": rows,
        "limitations": "Synthetic task-specific regression suite. Useful for comparing installed candidates under the same local runtime, but not representative mailbox accuracy, physical GPU peak certification, or proof that Automatic mode is risk-free."
    }))
}

pub fn run(settings: &Settings, out: &Path) -> Result<serde_json::Value> {
    let report = evaluate(settings)?;
    write_report(out, &report)?;
    Ok(report)
}

/// Compare only models already installed in Ollama. Nothing is downloaded implicitly.
///
/// A recommendation is emitted only among models that pass the conservative
/// application-specific eligibility gates and the full-GPU-residency qualification.
pub fn compare_installed(settings: &Settings, out: &Path) -> Result<()> {
    let mut candidates = Vec::new();
    for (label, model) in MODEL_CANDIDATES {
        let mut candidate = settings.clone();
        candidate.disarm_delivery();
        candidate.model = model.into();
        candidate.model_digest = None;
        candidate.validate()?;

        let llm = Ollama::new(&candidate)?;
        match llm.inspect() {
            Ok(_) => match evaluate(&candidate) {
                Ok(report) => candidates.push(serde_json::json!({
                    "label": label,
                    "model": model,
                    "report": report
                })),
                Err(error) => candidates.push(serde_json::json!({
                    "label": label,
                    "model": model,
                    "error": error.to_string()
                })),
            },
            Err(error) => candidates.push(serde_json::json!({
                "label": label,
                "model": model,
                "skipped": true,
                "reason": error.to_string()
            })),
        }
    }

    let winner = select_winner(&candidates);

    let report = serde_json::json!({
        "timestamp": chrono::Utc::now(),
        "suite": EVALUATION_CONTRACT_VERSION,
        "suite_hash": evaluation_suite_hash(),
        "weights": {
            "non_rejection_false_positive_avoidance": 0.35,
            "rejection_recall": 0.20,
            "verified_rejection_pipeline_rate": 0.20,
            "overall_accuracy": 0.15,
            "completion_rate": 0.10
        },
        "eligibility": {
            "all_cases_complete": true,
            "rejection_false_positives": 0,
            "unsafe_non_rejection_drafts": 0,
            "critical_negative_rejection_false_positives": 0,
            "critical_negative_unsafe_drafts": 0,
            "all_critical_negative_cases_complete": true,
            "deterministic_rejection_evidence_false_positives": 0,
            "minimum_deterministic_rejection_evidence_recall": 0.90,
            "minimum_rejection_recall": 0.90,
            "minimum_multilingual_rejection_recall": 0.85,
            "minimum_multilingual_verified_rejection_pipeline_rate": 0.85,
            "minimum_verified_rejection_pipeline_rate": 0.90,
            "full_gpu_residency_required": true
        },
        "recommended_model": winner.as_ref().map(|(model, _)| model),
        "recommended_score": winner.as_ref().map(|(_, score)| score),
        "candidates": candidates,
        "note": "Only already-installed candidates are evaluated. The app never downloads several large models merely to benchmark them. Install challengers explicitly, then rerun this bake-off."
    });
    write_report(out, &report)
}

fn write_report(out: &Path, report: &serde_json::Value) -> Result<()> {
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    write_new_private(out, &serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

/// Weighted task score over the five aggregation components.
///
/// False-positive avoidance carries the largest weight (0.35): replying to an
/// offer, interview or adversarial message is materially worse than holding a
/// genuine rejection. Missing components (zero denominators) score as 0.0.
fn task_score(
    fp_avoidance: Option<f64>,
    recall: Option<f64>,
    pipeline_rate: Option<f64>,
    accuracy: Option<f64>,
    completion_rate: f64,
) -> f64 {
    100.0
        * (0.35 * fp_avoidance.unwrap_or(0.0)
            + 0.20 * recall.unwrap_or(0.0)
            + 0.20 * pipeline_rate.unwrap_or(0.0)
            + 0.15 * accuracy.unwrap_or(0.0)
            + 0.10 * completion_rate)
}

/// Pick the recommendation among evaluated candidates.
///
/// Only candidates that passed every eligibility gate may win; among those the
/// highest task score wins, with earlier candidate order breaking exact ties.
/// Skipped/error/malformed candidates are never recommendable.
fn select_winner(candidates: &[serde_json::Value]) -> Option<(String, f64)> {
    let mut winner: Option<(String, f64)> = None;
    for candidate in candidates {
        let eligible = candidate
            .pointer("/report/summary/recommendation_eligible")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let score = candidate
            .pointer("/report/summary/task_score")
            .and_then(serde_json::Value::as_f64);
        let model = candidate.get("model").and_then(serde_json::Value::as_str);
        if eligible
            && let (Some(score), Some(model)) = (score, model)
            && winner.as_ref().is_none_or(|(_, best)| score > *best)
        {
            winner = Some((model.to_owned(), score));
        }
    }
    winner
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratios_are_explicit_when_denominator_is_zero() {
        assert_eq!(ratio(0, 0), None);
        assert_eq!(ratio(3, 4), Some(0.75));
    }

    #[test]
    fn fixture_ids_are_unique_and_cover_all_decisions() {
        let rows = fixtures().unwrap();
        let unique: std::collections::HashSet<_> = rows.iter().map(|c| &c.id).collect();
        assert_eq!(rows.len(), unique.len());
        assert!(rows.len() >= 74);
        for (category, minimum) in [
            (Category::Rejection, 20),
            (Category::Opportunity, 20),
            (Category::Other, 10),
            (Category::Uncertain, 15),
        ] {
            assert!(
                rows.iter().filter(|row| row.expected == category).count() >= minimum,
                "Synthetic corpus needs at least {minimum} cases for {category:?}"
            );
        }
        for (required, minimum) in [
            (CaseTag::Multilingual, 24),
            (CaseTag::AtsAutomation, 8),
            (CaseTag::Interview, 15),
            (CaseTag::Offer, 5),
            (CaseTag::RecruiterCorrection, 3),
            (CaseTag::QuotedHistory, 5),
            (CaseTag::PromptInjection, 3),
            (CaseTag::Ambiguous, 14),
            (CaseTag::Assessment, 4),
            (CaseTag::TalentPool, 3),
            (CaseTag::RoleClosure, 2),
            (CaseTag::ApplicationActionRequired, 2),
            (CaseTag::Survey, 2),
        ] {
            assert!(
                rows.iter()
                    .filter(|row| row.tags.contains(&required))
                    .count()
                    >= minimum,
                "Synthetic corpus needs at least {minimum} cases for {required:?}"
            );
        }
        assert!(
            rows.iter()
                .filter(|row| {
                    row.expected != Category::Rejection
                        && row.tags.iter().copied().any(CaseTag::critical_negative)
                })
                .count()
                >= 15,
            "Critical hard-negative corpus is too small"
        );
    }

    #[test]
    fn deterministic_automatic_policy_is_safe_on_the_full_fixture_corpus() {
        let rows = fixtures().unwrap();
        let mut expected_rejections = 0usize;
        let mut deterministic_hits = 0usize;
        let mut deterministic_false_positives = Vec::new();
        for case in &rows {
            let evidence = mail::clear_rejection_language(&case.subject, &case.text)
                && !mail::auto_language_conflict(&case.subject, &case.text);
            if case.expected == Category::Rejection {
                expected_rejections += 1;
                deterministic_hits += usize::from(evidence);
            } else if evidence {
                deterministic_false_positives.push(case.id.clone());
            }
        }
        assert!(
            deterministic_false_positives.is_empty(),
            "Deterministic Automatic-mode gate must never fire on non-rejection fixtures: {deterministic_false_positives:?}"
        );
        assert!(
            ratio(deterministic_hits, expected_rejections).unwrap_or(0.0) >= 0.90,
            "Deterministic rejection evidence must cover at least 90% of rejection fixtures"
        );
    }

    #[test]
    fn candidate_list_is_unique_and_contains_quality_challengers() {
        let tags: std::collections::HashSet<_> =
            MODEL_CANDIDATES.iter().map(|(_, tag)| *tag).collect();
        assert_eq!(tags.len(), MODEL_CANDIDATES.len());
        assert!(tags.contains("qwen3.5:9b-q8_0"));
        assert!(tags.contains("granite4.2:8b-q8_0"));
        assert!(tags.contains("gemma4:12b-it-q8_0"));
        assert!(tags.contains("ministral-3:14b"));
    }

    #[test]
    fn suite_fingerprint_is_stable_shape_and_content_bound() {
        let hash = evaluation_suite_hash();
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(
            hash,
            crate::config::settings_context_hash(&Settings::default())
        );
    }

    #[test]
    fn task_score_weights_sum_to_one() {
        let total_weight: f64 = [0.35, 0.20, 0.20, 0.15, 0.10].iter().sum();
        assert!((total_weight - 1.0).abs() < 1e-9);
    }

    /// Guards each component's individual weight in isolation: a weight swap
    /// (e.g. recall vs pipeline rate) or scale change would move one of these
    /// exact values, catching silent re-weighting of the safety model.
    #[test]
    fn task_score_component_weights_are_individually_pinned() {
        let unit = Some(1.0);
        let none = None;
        assert!((task_score(unit, none, none, none, 0.0) - 35.0).abs() < 1e-9);
        assert!((task_score(none, unit, none, none, 0.0) - 20.0).abs() < 1e-9);
        assert!((task_score(none, none, unit, none, 0.0) - 20.0).abs() < 1e-9);
        assert!((task_score(none, none, none, unit, 0.0) - 15.0).abs() < 1e-9);
        assert!((task_score(none, none, none, none, 1.0) - 10.0).abs() < 1e-9);
    }

    /// Guards numeric edge cases: all-missing components score exactly zero
    /// (not NaN from 0/0), a perfect run scores exactly 100, and a missing
    /// component equals an explicit 0.0 rather than being dropped from the sum.
    #[test]
    fn task_score_handles_missing_and_extreme_components() {
        assert_eq!(task_score(None, None, None, None, 0.0), 0.0);
        assert!((task_score(Some(1.0), Some(1.0), Some(1.0), Some(1.0), 1.0) - 100.0).abs() < 1e-9);
        assert_eq!(
            task_score(None, Some(1.0), None, None, 0.0),
            task_score(Some(0.0), Some(1.0), Some(0.0), Some(0.0), 0.0)
        );
    }

    fn candidate(model: &str, eligible: bool, score: f64) -> serde_json::Value {
        serde_json::json!({
            "label": model,
            "model": model,
            "report": {"summary": {"recommendation_eligible": eligible, "task_score": score}}
        })
    }

    /// Guards the eligibility gate in candidate filtering: an ineligible model
    /// with a top score must never be recommended over a barely-eligible one —
    /// scoring by score alone would reintroduce the exact risk the gate blocks.
    #[test]
    fn winner_selection_never_recommends_ineligible_candidates() {
        let candidates = vec![
            candidate("danger-fast", false, 99.9),
            candidate("safe-slow", true, 42.0),
        ];
        assert_eq!(select_winner(&candidates), Some(("safe-slow".into(), 42.0)));
    }

    /// Guards tie-breaking determinism: with identical eligible scores the
    /// earlier candidate wins (strict `>`), so output cannot flap between runs.
    #[test]
    fn winner_selection_breaks_ties_by_candidate_order() {
        let candidates = vec![
            candidate("first", true, 50.0),
            candidate("second", true, 50.0),
        ];
        assert_eq!(select_winner(&candidates), Some(("first".into(), 50.0)));
    }

    /// Guards malformed-candidate handling: skipped entries, error entries and
    /// missing score/model fields must be skipped, and an empty or fully
    /// ineligible field must yield no recommendation at all.
    #[test]
    fn winner_selection_ignores_skipped_malformed_and_absent_candidates() {
        let skipped =
            serde_json::json!({"label":"a","model":"a","skipped":true,"reason":"not installed"});
        let errored = serde_json::json!({"label":"b","model":"b","error":"boom"});
        let eligible_no_score = serde_json::json!({"label":"c","model":"c","report":{"summary":{"recommendation_eligible":true}}});
        let eligible_no_model = serde_json::json!({"label":"d","report":{"summary":{"recommendation_eligible":true,"task_score":10.0}}});
        assert_eq!(select_winner(&[]), None);
        assert_eq!(
            select_winner(&[skipped, errored, eligible_no_score, eligible_no_model]),
            None
        );
    }

    /// Guards snake_case tag renaming: every CaseTag must round-trip through
    /// its wire name and unknown names must fail, so fixture drift cannot
    /// silently drop a tag from the metrics registry.
    #[test]
    fn case_tag_wire_names_round_trip_and_unknown_tags_fail() {
        let names = [
            "multilingual",
            "ats_automation",
            "interview",
            "offer",
            "recruiter_correction",
            "quoted_history",
            "prompt_injection",
            "ambiguous",
            "pending_status",
            "assessment",
            "talent_pool",
            "role_closure",
            "application_action_required",
            "survey",
        ];
        for name in names {
            let parsed: CaseTag = serde_json::from_str(&format!("\"{name}\"")).unwrap();
            assert_eq!(parsed.as_str(), name);
        }
        assert!(serde_json::from_str::<CaseTag>("\"offer_letter\"").is_err());
        assert!(serde_json::from_str::<CaseTag>("\"Interview\"").is_err());
    }

    /// Guards the critical-negative risk set exactly: adding or removing a tag
    /// here changes which mistakes are double-weighted, so the membership is
    /// pinned rather than inferred.
    #[test]
    fn critical_negative_tag_set_is_exactly_pinned() {
        for tag in [
            CaseTag::Interview,
            CaseTag::Offer,
            CaseTag::RecruiterCorrection,
            CaseTag::QuotedHistory,
            CaseTag::PromptInjection,
            CaseTag::Ambiguous,
            CaseTag::Assessment,
            CaseTag::TalentPool,
            CaseTag::RoleClosure,
            CaseTag::ApplicationActionRequired,
        ] {
            assert!(tag.critical_negative(), "{:?} must be critical", tag);
        }
        for tag in [
            CaseTag::Multilingual,
            CaseTag::AtsAutomation,
            CaseTag::PendingStatus,
            CaseTag::Survey,
        ] {
            assert!(!tag.critical_negative(), "{:?} must not be critical", tag);
        }
    }

    /// Guards fixture schema strictness: identity and expectation fields are
    /// mandatory while tags default to empty, so a truncated fixture file fails
    /// loudly instead of scoring cases with default expectations.
    #[test]
    fn case_schema_requires_identity_and_expected_category() {
        let full: Case =
            serde_json::from_str(r#"{"id":"c1","subject":"s","text":"t","expected":"rejection"}"#)
                .unwrap();
        assert_eq!(full.id, "c1");
        assert_eq!(full.expected, Category::Rejection);
        assert!(full.tags.is_empty());
        for partial in [
            r#"{"id":"c1","subject":"s","text":"t"}"#,
            r#"{"subject":"s","text":"t","expected":"rejection"}"#,
            r#"{"id":"c1","subject":"s","text":"t","expected":"nope"}"#,
        ] {
            assert!(
                serde_json::from_str::<Case>(partial).is_err(),
                "{partial} must not parse"
            );
        }
    }

    /// Guards fixture content sanity: every embedded case needs non-empty
    /// identity and content, otherwise scoring silently divides by fixtures
    /// that can never be classified.
    #[test]
    fn every_fixture_has_substantive_identity_and_content() {
        for case in fixtures().unwrap() {
            assert!(!case.id.trim().is_empty(), "empty id");
            assert!(
                !case.subject.trim().is_empty(),
                "{}: empty subject",
                case.id
            );
            assert!(case.text.trim().len() >= 10, "{}: tiny body", case.id);
        }
    }
}
