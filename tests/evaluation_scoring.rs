//! Mock-HTTP evaluation-suite tests: fixture scoring, aggregation math and
//! candidate filtering against a deterministic fake Ollama.
//!
//! These tests re-derive every summary number from the raw result rows, so a
//! wrong order of operations, off-by-one or swapped weight in the aggregation
//! code fails here. They measure no real model accuracy and no GPU behaviour.
use rejection_rejector::{
    config::{DEFAULT_MODEL, MODEL_CANDIDATES, ReplyLanguage, Settings},
    evaluation, mail,
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tiny_http::{Header, Response, Server};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Deterministic fake Ollama: classification mirrors the deterministic
/// rejection-language gate, drafts are a fixed verified-safe English reply,
/// verification always passes, and one fully GPU-resident model is loaded.
struct Fake {
    url: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    installed: Vec<String>,
}
impl Fake {
    fn new(installed: &[&str]) -> Self {
        Self::with_failures(installed, "", "")
    }
    /// Deterministic fake Ollama that answers the first request to `route`
    /// whose body contains `body_marker` (any request to `route` when the
    /// marker is empty) with HTTP 500, so targeted mid-run model failures can
    /// be exercised without a real runtime.
    fn with_failures(installed: &[&str], route: &str, body_marker: &str) -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        rejection_rejector::peer_identity::register_local_listener(
            url.rsplit(':')
                .next()
                .map(|p| p.parse::<u16>().expect("port"))
                .expect("url carries a port"),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let models: Vec<String> = installed.iter().map(|m| (*m).to_string()).collect();
        let listed = models.clone();
        let last_model = Arc::new(Mutex::new(String::default()));
        let tracked = last_model.clone();
        let failure_route = route.to_owned();
        let failure_marker = body_marker.to_owned();
        let failure_left = Arc::new(Mutex::new(1usize));
        let failure_state = failure_left.clone();
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                let Some(mut req) = server.recv_timeout(Duration::from_millis(50)).unwrap() else {
                    continue;
                };
                let mut body = String::default();
                req.as_reader().read_to_string(&mut body).unwrap();
                if let Ok(value) = serde_json::from_str::<Value>(&body)
                    && let Some(model) = value.get("model").and_then(Value::as_str)
                {
                    *tracked.lock().unwrap() = model.to_owned();
                }
                let inject_failure = !failure_route.is_empty()
                    && failure_route == req.url()
                    && (failure_marker.is_empty() || body.contains(&failure_marker))
                    && {
                        let mut left = failure_state.lock().unwrap();
                        let inject = *left > 0;
                        *left = left.saturating_sub(1);
                        inject
                    };
                if inject_failure {
                    let response = Response::from_string("{\"error\":\"injected failure\"}")
                        .with_status_code(500);
                    let _ = req.respond(response);
                    continue;
                }
                let answer = match req.url() {
                    "/api/version" => json!({"version":"0.35.1"}),
                    "/api/tags" => json!({"models": listed.iter().map(|name| json!({
                        "name": name, "digest": DIGEST, "size": 7_200_000_000u64
                    })).collect::<Vec<_>>()}),
                    "/api/show" => json!({
                        "details":{"format":"gguf"},
                        "model_info":{"general.architecture":"qwen3"},
                        "capabilities":["completion","thinking"]
                    }),
                    "/api/ps" => json!({"models":[{
                        "name": tracked.lock().unwrap().clone(),
                        "digest": DIGEST,
                        "size": 9_000_000_000u64,
                        "size_vram": 9_000_000_000u64,
                        "context_length": 32768
                    }]}),
                    "/api/generate" => json!({
                        "done":true,"done_reason":"stop","prompt_eval_count":4,"eval_count":1
                    }),
                    "/api/chat" => {
                        let request: Value = serde_json::from_str(&body).unwrap();
                        let content = chat_content(&request);
                        json!({"message":{"role":"assistant","content":content.to_string()},
                            "done":true,"done_reason":"stop","prompt_eval_count":100,"eval_count":100})
                    }
                    path => panic!("Unexpected local protocol route {path}"),
                };
                let response = Response::from_string(answer.to_string())
                    .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
                let _ = req.respond(response);
            }
        });
        Self {
            url,
            stop,
            handle: Some(handle),
            installed: models,
        }
    }
    fn settings(&self) -> Settings {
        Settings {
            ollama_url: self.url.clone(),
            signature: "Test Applicant".into(),
            reply_language: ReplyLanguage::English,
            ..Default::default()
        }
    }
    fn installed(&self) -> &[String] {
        &self.installed
    }
}
impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.take().unwrap().join().unwrap();
    }
}

/// A contiguous short quote from the untrusted text: guaranteed to be an exact
/// substring of the verification source, never fabricated.
fn quote(text: &str) -> String {
    let start = text.find(|c: char| !c.is_whitespace()).unwrap_or(0);
    let mut end = start;
    for (offset, c) in text[start..].char_indices() {
        if offset + c.len_utf8() > 40 {
            break;
        }
        end = start + offset + c.len_utf8();
    }
    text[start..end].trim_end().to_owned()
}

fn chat_content(request: &Value) -> Value {
    let required = request
        .pointer("/format/required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let needs = |key: &str| required.iter().any(|v| v.as_str() == Some(key));
    let user = request
        .pointer("/messages/1/content")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let payload: Value = serde_json::from_str(user).unwrap_or_else(|_| json!({}));
    if needs("category") {
        let subject = payload["subject"].as_str().unwrap_or_default();
        let text = payload["untrusted_email"].as_str().unwrap_or_default();
        let evidence = quote(text);
        let rejection = !evidence.is_empty()
            && mail::clear_rejection_language(subject, text)
            && !mail::auto_language_conflict(subject, text);
        return json!({
            "category": if rejection {"rejection"} else {"uncertain"},
            "confidence": 95,
            "evidence": evidence,
            "explanation": "Deterministic fake classification",
            "company": "",
            "position": "",
            "language": "en"
        });
    }
    if needs("body") {
        return json!({"body":
            "Dear Recruitment Team,\n\nI am writing to request an individualized explanation of \
             the criteria behind this decision and of how my experience was assessed against the \
             advertised requirements. A specific account of the evaluation would help me understand \
             which qualifications were considered missing and how the final outcome was reached for \
             this role. I would appreciate a concrete review of my application materials and of the \
             assessment notes, so that the decision is transparent to me as a candidate.\n\nRegards,\nTest Applicant"
        });
    }
    if needs("genuine_rejection") {
        return json!({
            "genuine_rejection": true,
            "claims_supported": true,
            "professional": true,
            "injection_free": true,
            "purpose_aligned": true,
            "reason": "Deterministic fake verification"
        });
    }
    panic!("Unexpected chat schema {required:?}");
}

fn approx(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

/// Per-row facts read once from a result row, in report order. `row_facts`
/// evaluates the row-level consistency assertion at read time.
struct RowFacts<'a> {
    expected: &'a str,
    actual: &'a str,
    critical: bool,
    deterministic: bool,
    matched: bool,
    pipeline: bool,
}

/// Independent recomputation counters for every aggregate the summary
/// publishes.
#[derive(Default)]
struct Tally {
    completed: usize,
    correct: usize,
    expected_rejections: usize,
    tp: usize,
    fp: usize,
    mut_fn: usize,
    verified_pipeline: usize,
    unsafe_drafts: usize,
    critical_cases: usize,
    critical_completed: usize,
    critical_fp: usize,
    critical_unsafe: usize,
    det_hits: usize,
    det_false: usize,
}

/// Reads the per-row facts and asserts the row's own match flag against the
/// expectation/actual pair.
fn row_facts(row: &Value) -> RowFacts<'_> {
    let expected = row["expected"].as_str().unwrap();
    let critical = row["critical_negative"].as_bool().unwrap();
    let deterministic = row["deterministic_rejection_evidence"].as_bool().unwrap();
    let actual = row["actual"].as_str().unwrap();
    let matched = row["match"].as_bool().unwrap();
    assert_eq!(matched, expected == actual, "row match flag inconsistent");
    let pipeline = row["rejection_pipeline_passed"].as_bool().unwrap();
    RowFacts {
        expected,
        actual,
        critical,
        deterministic,
        matched,
        pipeline,
    }
}

/// Recomputes the expectation-side aggregates from one row's facts.
fn tally_expectations(facts: &RowFacts<'_>, tally: &mut Tally) {
    let (expected, critical, deterministic) = (facts.expected, facts.critical, facts.deterministic);
    tally.expected_rejections += usize::from(expected == "rejection");
    tally.critical_cases += usize::from(critical && expected != "rejection");
    tally.det_hits += usize::from(expected == "rejection" && deterministic);
    tally.det_false += usize::from(expected != "rejection" && deterministic);
    tally.completed += 1;
    tally.critical_completed += usize::from(critical && expected != "rejection");
}

/// Recomputes the outcome-side aggregates from one row, including the unsafe
/// draft flags that depend on the generated draft.
fn tally_outcomes(row: &Value, facts: &RowFacts<'_>, tally: &mut Tally) {
    let (expected, critical, actual) = (facts.expected, facts.critical, facts.actual);
    tally.correct += usize::from(facts.matched);
    tally.tp += usize::from(actual == "rejection" && expected == "rejection");
    tally.fp += usize::from(actual == "rejection" && expected != "rejection");
    tally.mut_fn += usize::from(actual != "rejection" && expected == "rejection");
    tally.verified_pipeline += usize::from(facts.pipeline);
    let non_rejection_draft = expected != "rejection" && row["draft_generated"].as_bool().unwrap();
    tally.unsafe_drafts += usize::from(non_rejection_draft);
    tally.critical_fp += usize::from(critical && expected != "rejection" && actual == "rejection");
    tally.critical_unsafe += usize::from(critical && non_rejection_draft);
}

/// Recomputes every summary aggregate from the raw result rows. Each row must
/// complete and stay internally consistent with its recorded gates.
fn recompute_from_rows(results: &[Value]) -> Tally {
    let mut tally = Tally::default();
    for row in results {
        assert!(
            row.get("error").is_none(),
            "the deterministic fake must complete every fixture, got {}",
            row["id"]
        );
        let facts = row_facts(row);
        tally_expectations(&facts, &mut tally);
        if facts.pipeline {
            // The pipeline verdict may only be true when every gate that the
            // row records independently held.
            assert!(row["verification_passed"].as_bool().unwrap());
            assert!(row["draft_generated"].as_bool().unwrap());
            assert!(row["flags"].as_array().unwrap().is_empty());
        }
        tally_outcomes(row, &facts, &mut tally);
    }
    tally
}

/// The count-side conjuncts of the documented eligibility gate.
fn gate_counts_hold(summary: &Value, fixture_count: usize) -> bool {
    summary["completed"] == fixture_count
        && summary["rejection_false_positive"] == 0
        && summary["unsafe_non_rejection_drafts"] == 0
        && summary["critical_negative_completed"] == summary["critical_negative_cases"]
        && summary["critical_negative_rejection_false_positives"] == 0
        && summary["critical_negative_unsafe_drafts"] == 0
        && summary["deterministic_rejection_evidence_false_positives"] == 0
}

/// The rate-side conjuncts of the documented eligibility gate.
fn gate_rates_hold(summary: &Value) -> bool {
    summary["deterministic_rejection_evidence_recall"]
        .as_f64()
        .unwrap_or(0.0)
        >= 0.90
        && summary["rejection_recall"].as_f64().unwrap_or(0.0) >= 0.90
        && summary["verified_rejection_pipeline_rate"]
            .as_f64()
            .unwrap_or(0.0)
            >= 0.90
        && multilingual_rate(summary, "rejection_recall") >= 0.85
        && multilingual_rate(summary, "verified") >= 0.85
}

/// Guards fixture scoring and every aggregation step: the summary must equal
/// metrics recomputed independently from the raw rows (confusion matrix,
/// ratios, weighted task score and the eligibility gate), so any off-by-one,
/// swapped counter or wrong denominator in the aggregation loop fails here.
#[test]
fn summary_aggregation_matches_independent_recomputation_from_rows() {
    let fake = Fake::new(&[DEFAULT_MODEL]);
    let settings = fake.settings();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("nested").join("report.json");
    let report = evaluation::run(&settings, &out).unwrap();

    let results = report["results"].as_array().unwrap();
    let summary = &report["summary"];

    // Independent recomputation from the raw rows.
    let Tally {
        completed,
        correct,
        expected_rejections,
        tp,
        fp,
        mut_fn,
        verified_pipeline,
        unsafe_drafts,
        critical_cases,
        critical_completed,
        critical_fp,
        critical_unsafe,
        det_hits,
        det_false,
    } = recompute_from_rows(results);

    let fixture_count = results.len();
    assert!(fixture_count >= 74);
    assert_eq!(summary["fixture_count"], fixture_count);
    assert_eq!(summary["completed"], completed);
    assert_eq!(summary["correct"], correct);
    assert_eq!(summary["expected_rejections"], expected_rejections);
    assert_eq!(summary["rejection_true_positive"], tp);
    assert_eq!(summary["rejection_false_positive"], fp);
    assert_eq!(summary["rejection_false_negative"], mut_fn);
    assert_eq!(summary["verified_rejection_pipeline"], verified_pipeline);
    assert_eq!(summary["unsafe_non_rejection_drafts"], unsafe_drafts);
    assert_eq!(summary["critical_negative_cases"], critical_cases);
    assert_eq!(summary["critical_negative_completed"], critical_completed);
    assert_eq!(
        summary["critical_negative_rejection_false_positives"],
        critical_fp
    );
    assert_eq!(summary["critical_negative_unsafe_drafts"], critical_unsafe);
    assert_eq!(summary["deterministic_rejection_evidence_hits"], det_hits);
    assert_eq!(
        summary["deterministic_rejection_evidence_false_positives"],
        det_false
    );

    let non_rejections = fixture_count - expected_rejections;
    let expected_ratios = [
        ("accuracy", ratio(correct, fixture_count)),
        ("rejection_precision", ratio(tp, tp + fp)),
        ("rejection_recall", ratio(tp, tp + mut_fn)),
        (
            "non_rejection_false_positive_avoidance",
            ratio(non_rejections - fp, non_rejections),
        ),
        (
            "verified_rejection_pipeline_rate",
            ratio(verified_pipeline, expected_rejections),
        ),
        (
            "deterministic_rejection_evidence_recall",
            ratio(det_hits, expected_rejections),
        ),
    ];
    for (name, expected_value) in expected_ratios {
        match expected_value {
            Some(value) => assert!(
                approx(summary[name].as_f64().unwrap(), value),
                "{name} drifted"
            ),
            None => assert!(summary[name].is_null(), "{name} must be null on 0/0"),
        }
    }
    assert_eq!(
        summary["mean_seconds"].is_null(),
        completed == 0,
        "mean_seconds presence must follow completion"
    );

    // The weighted score must be reproducible from the summary components.
    let score = 100.0
        * (0.35
            * summary["non_rejection_false_positive_avoidance"]
                .as_f64()
                .unwrap_or(0.0)
            + 0.20 * summary["rejection_recall"].as_f64().unwrap_or(0.0)
            + 0.20
                * summary["verified_rejection_pipeline_rate"]
                    .as_f64()
                    .unwrap_or(0.0)
            + 0.15 * summary["accuracy"].as_f64().unwrap_or(0.0)
            + 0.10 * ratio(completed, fixture_count).unwrap_or(0.0));
    assert!(approx(summary["task_score"].as_f64().unwrap(), score));
    assert!((0.0..=100.0).contains(&summary["task_score"].as_f64().unwrap()));

    // The eligibility gate must equal its documented conjunction over the
    // summary numbers and the GPU-residency qualification.
    let gate = gate_counts_hold(summary, fixture_count)
        && gate_rates_hold(summary)
        && report["qualification"]["gpu_resident"].as_bool().unwrap();
    assert_eq!(
        summary["recommendation_eligible"].as_bool().unwrap(),
        gate,
        "eligibility gate does not match its documented conjunction"
    );

    // The report must round-trip through the on-disk artifact (created
    // together with missing parent directories). Floats compare with a tiny
    // tolerance: serde_json's default f64 parser is off by at most one ULP.
    assert!(out.is_file());
    let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(approx_json(&on_disk["summary"], &report["summary"]));
    assert_eq!(on_disk["suite"], report["suite"]);
}

/// Structural comparison with ULP-tolerant numeric equality.
fn approx_json(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            let (x, y) = (x.as_f64().unwrap(), y.as_f64().unwrap());
            (x - y).abs() <= 1e-9 * 1.0_f64.max(x.abs()).max(y.abs())
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| approx_json(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| approx_json(v, w)))
        }
        _ => a == b,
    }
}

fn multilingual_rate(summary: &Value, which: &str) -> f64 {
    let name = match which {
        "rejection_recall" => "multilingual_rejection_recall",
        "verified" => "multilingual_verified_rejection_pipeline_rate",
        _ => unreachable!(),
    };
    summary[name].as_f64().unwrap_or(0.0)
}

/// Guards candidate filtering end to end: uninstalled candidates are skipped
/// (never evaluated, never recommended), evaluated candidates carry complete
/// reports, and the emitted recommendation equals the eligible maximum that a
/// from-scratch recomputation picks from the same candidate records.
#[test]
fn compare_installed_skips_absent_models_and_recommends_only_the_eligible_maximum() {
    let installed = ["qwen3.5:9b-q8_0", "granite4.2:8b-q8_0"];
    let fake = Fake::new(&installed);
    let settings = fake.settings();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("compare.json");
    evaluation::compare_installed(&settings, &out).unwrap();

    let report: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let candidates = report["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), MODEL_CANDIDATES.len());

    let mut evaluated = Vec::new();
    for candidate in candidates {
        let model = candidate["model"].as_str().unwrap();
        if candidate.get("skipped").and_then(Value::as_bool) == Some(true) {
            assert!(
                !fake.installed().iter().any(|m| m == model),
                "installed model {model} must not be skipped"
            );
            assert!(!candidate["reason"].as_str().unwrap().is_empty());
            assert!(candidate.get("report").is_none());
        } else {
            assert!(
                fake.installed().contains(&model.to_owned()),
                "uninstalled model {model} must not be evaluated"
            );
            let summary = &candidate["report"]["summary"];
            let score = summary["task_score"].as_f64().unwrap();
            assert!((0.0..=100.0).contains(&score));
            assert_eq!(
                summary["fixture_count"],
                candidate["report"]["results"].as_array().unwrap().len()
            );
            evaluated.push(model.to_owned());
        }
    }
    assert_eq!(
        evaluated,
        fake.installed(),
        "exactly the installed candidates must be evaluated, in candidate order"
    );

    // Recompute the winner with the documented semantics: highest task score
    // among recommendation-eligible candidates only.
    let mut winner: Option<(String, f64)> = None;
    for candidate in candidates {
        let eligible = candidate
            .pointer("/report/summary/recommendation_eligible")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let score = candidate
            .pointer("/report/summary/task_score")
            .and_then(Value::as_f64);
        let model = candidate.get("model").and_then(Value::as_str);
        if eligible
            && let (Some(score), Some(model)) = (score, model)
            && winner.as_ref().is_none_or(|(_, best)| score > *best)
        {
            winner = Some((model.to_owned(), score));
        }
    }
    match winner {
        Some((model, score)) => {
            assert_eq!(report["recommended_model"].as_str(), Some(model.as_str()));
            assert!(approx(report["recommended_score"].as_f64().unwrap(), score));
        }
        None => {
            assert!(report["recommended_model"].is_null());
            assert!(report["recommended_score"].is_null());
        }
    }

    // The published weights must still describe the score actually computed.
    let weights = &report["weights"];
    assert!(approx(
        weights["non_rejection_false_positive_avoidance"]
            .as_f64()
            .unwrap(),
        0.35
    ));
    assert!(approx(weights["rejection_recall"].as_f64().unwrap(), 0.20));
    assert!(approx(
        weights["verified_rejection_pipeline_rate"]
            .as_f64()
            .unwrap(),
        0.20
    ));
    assert!(approx(weights["overall_accuracy"].as_f64().unwrap(), 0.15));
    assert!(approx(weights["completion_rate"].as_f64().unwrap(), 0.10));
}

/// Guards score/recommendation decoupling: the report's headline weights and
/// eligibility thresholds are contractual constants referenced by operators;
/// silently changing one would invalidate every stored qualification.
#[test]
fn comparison_report_pins_the_contractual_thresholds() {
    let fake = Fake::new(&[DEFAULT_MODEL]);
    let dir = tempfile::tempdir().unwrap();
    let out: &Path = &dir.path().join("compare.json");
    evaluation::compare_installed(&fake.settings(), out).unwrap();
    let report: Value = serde_json::from_str(&std::fs::read_to_string(out).unwrap()).unwrap();
    let eligibility = &report["eligibility"];
    assert_eq!(eligibility["rejection_false_positives"], 0);
    assert_eq!(eligibility["unsafe_non_rejection_drafts"], 0);
    assert_eq!(eligibility["minimum_rejection_recall"], 0.90);
    assert_eq!(
        eligibility["minimum_verified_rejection_pipeline_rate"],
        0.90
    );
    assert_eq!(eligibility["minimum_multilingual_rejection_recall"], 0.85);
    assert_eq!(
        eligibility["minimum_deterministic_rejection_evidence_recall"],
        0.90
    );
    assert!(
        eligibility["full_gpu_residency_required"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(report["suite"], "rr-eval-contract-v5");
}

/// Guards per-case failure isolation: when the model errors mid-run, exactly
/// that case is recorded as an error row (never silently dropped or counted
/// as correct), it is excluded from `completed` while staying in
/// `fixture_count`, and the run can never pass the eligibility gate — a
/// partially failed corpus must not inflate accuracy or become recommendable.
#[test]
fn model_errors_become_error_rows_and_fail_the_eligibility_gate() {
    let fake = Fake::with_failures(&[DEFAULT_MODEL], "/api/chat", "Application outcome");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("report.json");
    let report = evaluation::run(&fake.settings(), &out).unwrap();
    let results = report["results"].as_array().unwrap();
    let errors: Vec<&Value> = results
        .iter()
        .filter(|row| row.get("error").is_some())
        .collect();
    assert_eq!(errors.len(), 1, "exactly one case must surface the failure");
    assert_eq!(errors[0]["id"], "en_rejection_regret");
    assert!(!errors[0]["match"].as_bool().unwrap());
    assert!(errors[0].get("expected").is_some());
    assert!(errors[0].get("actual").is_none());
    let summary = &report["summary"];
    assert_eq!(
        summary["completed"].as_u64().unwrap() as usize,
        results.len() - 1
    );
    assert_eq!(
        summary["fixture_count"].as_u64().unwrap() as usize,
        results.len()
    );
    assert!(!summary["recommendation_eligible"].as_bool().unwrap());
    assert!(summary["accuracy"].as_f64().unwrap().is_finite());
}

/// Guards candidate isolation in the bake-off: one candidate whose evaluation
/// errors must be reported with its own error entry (skipped for
/// recommendation) while the comparison report keeps its contract; a broken
/// candidate may never abort the comparison or be recommended.
#[test]
fn comparison_isolates_candidate_evaluation_failures() {
    let fake = Fake::with_failures(&[DEFAULT_MODEL], "/api/ps", "");
    let dir = tempfile::tempdir().unwrap();
    let out: &Path = &dir.path().join("compare.json");
    evaluation::compare_installed(&fake.settings(), out).unwrap();
    let report: Value = serde_json::from_str(&std::fs::read_to_string(out).unwrap()).unwrap();
    let candidates = report["candidates"].as_array().unwrap();
    let evaluated: Vec<&Value> = candidates
        .iter()
        .filter(|c| c.get("report").is_some() || c.get("error").is_some())
        .collect();
    assert_eq!(evaluated.len(), 1, "only the installed model is evaluated");
    assert!(evaluated[0].get("error").is_some());
    assert!(evaluated[0].get("report").is_none());
    assert_eq!(evaluated[0]["model"], DEFAULT_MODEL);
    for skipped in candidates.iter().filter(|c| c["model"] != DEFAULT_MODEL) {
        assert!(
            skipped["skipped"].as_bool().unwrap(),
            "{}",
            skipped["model"]
        );
        assert!(skipped.get("error").is_none());
    }
    assert!(report.get("eligibility").is_some());
}

/// Guards the research-evidence contract on the report envelope: the report
/// must identify the build (source commit and lock digest), the declared
/// sampling policy (temperature/seed), and every unavailable metric must stay
/// null with an explicit reason instead of reading as a measured zero.
#[test]
fn report_carries_research_identity_and_null_metric_reasons() {
    let fake = Fake::new(&[DEFAULT_MODEL]);
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("report.json");
    let report = evaluation::run(&fake.settings(), &out).unwrap();

    // Build identity: source commit and lock digest bind the run to source.
    let build = &report["build"];
    assert!(build["source_commit"].as_str().unwrap().len() >= 7);
    let lock = build["cargo_lock_sha256"].as_str().unwrap();
    assert_eq!(lock.len(), 64);
    assert!(lock.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!build["identity_sha256"].as_str().unwrap().is_empty());

    // Declared sampling policy (matches the Ollama request contract).
    assert!((report["sampling"]["temperature"].as_f64().unwrap() - 0.15).abs() < 1e-9);
    assert_eq!(report["sampling"]["seed"].as_i64().unwrap(), 42);

    // Every null metric must carry a reason; no non-null metric may carry one.
    let summary = &report["summary"];
    let reasons = summary["unavailable_metric_reasons"].as_object().unwrap();
    for name in [
        "accuracy",
        "rejection_precision",
        "rejection_recall",
        "non_rejection_false_positive_avoidance",
        "verified_rejection_pipeline_rate",
        "deterministic_rejection_evidence_recall",
        "multilingual_rejection_recall",
        "multilingual_verified_rejection_pipeline_rate",
        "mean_seconds",
    ] {
        let is_null = summary[name].is_null();
        assert_eq!(
            is_null,
            reasons.contains_key(name),
            "{name}: null metrics need a reason and resolved metrics must not have one"
        );
        if let Some(reason) = reasons.get(name) {
            assert!(!reason.as_str().unwrap().is_empty());
        }
    }
}
