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
    rejection_false_positives: usize,
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
    let mut tag_metrics = BTreeMap::<String, TagSummary>::new();
    let mut completed = 0usize;
    let mut total_seconds = 0.0f64;

    for case in &cases {
        expected_rejections += usize::from(case.expected == Category::Rejection);
        let critical_negative = case.expected != Category::Rejection
            && case.tags.iter().copied().any(CaseTag::critical_negative);
        critical_negative_cases += usize::from(critical_negative);
        for tag in &case.tags {
            tag_metrics.entry(tag.as_str().into()).or_default().cases += 1;
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
                    let metrics = tag_metrics
                        .get_mut(tag.as_str())
                        .expect("tag was initialized before evaluation");
                    metrics.completed += 1;
                    metrics.correct += usize::from(matched);
                    metrics.rejection_false_positives +=
                        usize::from(rejection_false_positive);
                    metrics.unsafe_non_rejection_drafts +=
                        usize::from(non_rejection_draft);
                }

                rows.push(serde_json::json!({
                    "id": case.id,
                    "tags": case.tags.iter().map(|tag| tag.as_str()).collect::<Vec<_>>(),
                    "critical_negative": critical_negative,
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
    let completion_rate = ratio(completed, cases.len()).unwrap_or(0.0);

    // Task-specific weighting: false-positive avoidance dominates because replying
    // to an offer/interview is materially worse than holding a genuine rejection.
    let task_score = 100.0
        * (0.35 * fp_avoidance.unwrap_or(0.0)
            + 0.20 * recall.unwrap_or(0.0)
            + 0.20 * pipeline_rate.unwrap_or(0.0)
            + 0.15 * accuracy.unwrap_or(0.0)
            + 0.10 * completion_rate);

    let recommendation_eligible = completed == cases.len()
        && rejection_fp == 0
        && unsafe_non_rejection_drafts == 0
        && critical_negative_completed == critical_negative_cases
        && critical_negative_rejection_false_positives == 0
        && critical_negative_unsafe_drafts == 0
        && recall.unwrap_or(0.0) >= 0.90
        && pipeline_rate.unwrap_or(0.0) >= 0.90
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

    let mut winner: Option<(String, f64)> = None;
    for candidate in &candidates {
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
            "minimum_rejection_recall": 0.90,
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
        assert!(rows.len() >= 48);
        for category in [
            Category::Rejection,
            Category::Opportunity,
            Category::Other,
            Category::Uncertain,
        ] {
            assert!(
                rows.iter().filter(|row| row.expected == category).count() >= 5,
                "Synthetic corpus needs at least five cases for {category:?}"
            );
        }
        for required in [
            CaseTag::Interview,
            CaseTag::Offer,
            CaseTag::RecruiterCorrection,
            CaseTag::QuotedHistory,
            CaseTag::PromptInjection,
            CaseTag::Ambiguous,
            CaseTag::Multilingual,
            CaseTag::AtsAutomation,
        ] {
            assert!(
                rows.iter().filter(|row| row.tags.contains(&required)).count() >= 2,
                "Synthetic corpus needs repeated coverage for {required:?}"
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
}
