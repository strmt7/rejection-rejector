use crate::{
    config::Settings,
    ollama::{sample_email, Ollama},
    types::Category,
    vault::write_new_private,
};
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
#[derive(Deserialize)]
struct Case {
    id: String,
    subject: String,
    text: String,
    expected: Category,
}
/// A tiny synthetic regression corpus, not representative accuracy or a model leaderboard.
pub fn run(settings: &Settings, out: &Path) -> Result<()> {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../tests/fixtures/classification.json"))?;
    let llm = Ollama::new(settings)?;
    let qualified = llm.qualify()?;
    let mut rows = Vec::new();
    let mut correct = 0usize;
    let mut rejection_tp = 0usize;
    let mut rejection_fp = 0usize;
    let mut rejection_fn = 0usize;
    let mut completed = 0usize;
    let mut total_seconds = 0.0f64;
    for c in &cases {
        let start = std::time::Instant::now();
        match llm.classify(&sample_email(&c.subject, &c.text)) {
            Ok((verdict, complete)) => {
                let seconds = start.elapsed().as_secs_f64();
                total_seconds += seconds;
                completed += 1;
                let matched = verdict.category == c.expected;
                correct += usize::from(matched);
                rejection_tp += usize::from(
                    verdict.category == Category::Rejection && c.expected == Category::Rejection,
                );
                rejection_fp += usize::from(
                    verdict.category == Category::Rejection && c.expected != Category::Rejection,
                );
                rejection_fn += usize::from(
                    verdict.category != Category::Rejection && c.expected == Category::Rejection,
                );
                rows.push(serde_json::json!({
                    "id": c.id,
                    "expected": c.expected,
                    "actual": verdict.category,
                    "match": matched,
                    "input_complete": complete,
                    "seconds": seconds,
                    "evidence": verdict.evidence
                }));
            }
            Err(error) => rows.push(serde_json::json!({
                "id": c.id,
                "expected": c.expected,
                "error": error.to_string(),
                "match": false
            })),
        }
    }
    let precision = ratio(rejection_tp, rejection_tp + rejection_fp);
    let recall = ratio(rejection_tp, rejection_tp + rejection_fn);
    let report = serde_json::json!({
        "timestamp": chrono::Utc::now(),
        "model": settings.model,
        "digest": qualified.digest,
        "context": settings.num_ctx,
        "qualification": {
            "gpu_resident": qualified.gpu_resident,
            "size_vram": qualified.size_vram
        },
        "fixture_count": cases.len(),
        "completed": completed,
        "correct": correct,
        "accuracy": ratio(correct, cases.len()),
        "rejection": {
            "true_positive": rejection_tp,
            "false_positive": rejection_fp,
            "false_negative": rejection_fn,
            "precision": precision,
            "recall": recall
        },
        "mean_seconds": if completed == 0 { None } else { Some(total_seconds / completed as f64) },
        "results": rows,
        "limitations": "Small synthetic regression set only. Not representative mailbox accuracy, cross-model ranking, GPU peak certification or proof that automatic sending is safe."
    });
    if let Some(p) = out.parent() {
        if !p.as_os_str().is_empty() {
            std::fs::create_dir_all(p)?;
        }
    }
    write_new_private(out, &serde_json::to_vec_pretty(&report)?)?;
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
    fn fixture_ids_are_unique() {
        let rows: Vec<Case> =
            serde_json::from_str(include_str!("../tests/fixtures/classification.json")).unwrap();
        let unique: std::collections::HashSet<_> = rows.iter().map(|c| &c.id).collect();
        assert_eq!(rows.len(), unique.len());
        assert!(rows.len() >= 10);
    }
}
