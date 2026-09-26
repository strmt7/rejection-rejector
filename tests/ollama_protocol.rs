//! Mock HTTP protocol tests, not real-model accuracy or physical-GPU measurements.
use rejection_rejector::{
    config::{Settings, DEFAULT_MODEL},
    ollama::{sample_email, Ollama},
    types::Category,
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tiny_http::{Header, Response, Server};

#[derive(Clone, Copy, PartialEq)]
enum Scenario {
    Good,
    InventedEvidence,
    Truncated,
    CpuOnly,
    Remote,
    VerifierFail,
}
struct Fixture {
    url: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    chats: Arc<Mutex<Vec<Value>>>,
    warms: Arc<Mutex<Vec<Value>>>,
}
impl Fixture {
    fn new(scenario: Scenario) -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let chats = Arc::new(Mutex::new(Vec::new()));
        let warms = Arc::new(Mutex::new(Vec::new()));
        let flag = stop.clone();
        let calls = chats.clone();
        let warm_calls = warms.clone();
        let handle = thread::spawn(move || {
            let mut stage = 0;
            while !flag.load(Ordering::SeqCst) {
                let Some(mut req) = server.recv_timeout(Duration::from_millis(50)).unwrap() else {
                    continue;
                };
                let answer = match req.url() {
                    "/api/tags" => {
                        json!({"models":[{"name":DEFAULT_MODEL,"digest":"a".repeat(64),"size":7_200_000_000u64}]})
                    }
                    "/api/show" => {
                        let mut data = json!({"details":{"format":"gguf"},"model_info":{"general.architecture":"gemma4"}});
                        if scenario == Scenario::Remote {
                            data["remote_host"] = json!("https://remote.invalid");
                        }
                        data
                    }
                    "/api/ps" => {
                        json!({"models":[{"name":DEFAULT_MODEL,"digest":"a".repeat(64),"size":9_000_000_000u64,"size_vram":if scenario==Scenario::CpuOnly {2_000_000_000u64}else{9_000_000_000u64},"context_length":8192}]})
                    }
                    "/api/generate" => {
                        let mut body = String::new();
                        req.as_reader().read_to_string(&mut body).unwrap();
                        warm_calls
                            .lock()
                            .unwrap()
                            .push(serde_json::from_str(&body).unwrap());
                        json!({"model":DEFAULT_MODEL,"response":"ready","done":true,"done_reason":"length","prompt_eval_count":4,"eval_count":1})
                    }
                    "/api/chat" => {
                        let mut body = String::new();
                        req.as_reader().read_to_string(&mut body).unwrap();
                        calls
                            .lock()
                            .unwrap()
                            .push(serde_json::from_str(&body).unwrap());
                        let content = match stage {
                            0 => {
                                json!({"category":"rejection","confidence":99,"evidence":if scenario==Scenario::InventedEvidence {"Invented quote not present"}else{"We have decided not to move forward with your application."},"explanation":"Explicit negative hiring decision","company":"","position":"","language":"en"})
                            }
                            1 => {
                                json!({"body":"Dear Recruitment Team,\n\nPlease explain the specific criteria behind the decision and how the application was assessed. I request individualized feedback rather than a restatement of the outcome.\n\nRegards,\nTest Applicant"})
                            }
                            _ => {
                                json!({"genuine_rejection":true,"claims_supported":true,"professional":scenario != Scenario::VerifierFail,"injection_free":true,"reason":"Synthetic verification result"})
                            }
                        };
                        stage += 1;
                        json!({"model":DEFAULT_MODEL,"message":{"role":"assistant","content":content.to_string()},"done":true,"done_reason":if scenario==Scenario::Truncated {"length"}else{"stop"},"prompt_eval_count":100,"eval_count":100})
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
            chats,
            warms,
        }
    }
    fn settings(&self) -> Settings {
        Settings {
            ollama_url: self.url.clone(),
            model_digest: Some("a".repeat(64)),
            signature: "Test Applicant".into(),
            ..Default::default()
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.take().unwrap().join().unwrap();
    }
}
fn email() -> rejection_rejector::types::Email {
    sample_email(
        "Application outcome",
        "We have decided not to move forward with your application.",
    )
}
#[test]
fn three_stage_protocol_binds_draft_and_model_and_uses_reasoning() {
    let f = Fixture::new(Scenario::Good);
    let (analysis, draft, flags) = Ollama::new(&f.settings())
        .unwrap()
        .analyze(&email())
        .unwrap();
    assert_eq!(analysis.verdict.category, Category::Rejection);
    assert!(analysis.input_complete && analysis.gpu_resident);
    assert!(analysis.verification.unwrap().passed());
    assert!(analysis.verified_draft_hash.is_some());
    assert!(draft.unwrap().body.contains("Test Applicant"));
    assert!(flags.is_empty());
    let calls = f.chats.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(f.warms.lock().unwrap().len(), 1);
    for call in calls.iter() {
        assert_eq!(call["think"], true);
        assert_eq!(call["stream"], false);
        assert_eq!(call["model"], DEFAULT_MODEL);
        assert_eq!(call["options"]["num_ctx"], 8192);
        assert!(call["format"].is_object());
        assert!(call.get("tools").is_none());
    }
    assert!(calls[2]["messages"][1]["content"]
        .as_str()
        .unwrap()
        .contains("trusted_signature"));
}
#[test]
fn qualification_exercises_classification_drafting_verification_and_residency() {
    let f = Fixture::new(Scenario::Good);
    let mut settings = f.settings();
    settings.model_digest = None;
    let status = Ollama::new(&settings).unwrap().qualify().unwrap();
    assert!(status.gpu_resident);
    assert_eq!(f.chats.lock().unwrap().len(), 3);
    assert_eq!(f.warms.lock().unwrap().len(), 1);
}

#[test]
fn qualification_rejects_a_failed_reply_verifier() {
    let f = Fixture::new(Scenario::VerifierFail);
    let mut settings = f.settings();
    settings.model_digest = None;
    assert!(Ollama::new(&settings).unwrap().qualify().is_err());
    assert_eq!(f.chats.lock().unwrap().len(), 3);
    assert_eq!(f.warms.lock().unwrap().len(), 1);
}

#[test]
fn fabricated_evidence_prevents_drafting() {
    let f = Fixture::new(Scenario::InventedEvidence);
    assert!(Ollama::new(&f.settings())
        .unwrap()
        .analyze(&email())
        .is_err());
    assert_eq!(f.chats.lock().unwrap().len(), 1);
    assert_eq!(f.warms.lock().unwrap().len(), 1);
}
#[test]
fn truncated_generation_prevents_drafting() {
    let f = Fixture::new(Scenario::Truncated);
    assert!(Ollama::new(&f.settings())
        .unwrap()
        .analyze(&email())
        .is_err());
    assert_eq!(f.chats.lock().unwrap().len(), 1);
    assert_eq!(f.warms.lock().unwrap().len(), 1);
}
#[test]
fn cloud_marker_blocks_before_any_email_inference() {
    let f = Fixture::new(Scenario::Remote);
    assert!(Ollama::new(&f.settings())
        .unwrap()
        .analyze(&email())
        .is_err());
    assert!(f.chats.lock().unwrap().is_empty());
    assert!(f.warms.lock().unwrap().is_empty());
}
#[test]
fn changed_digest_blocks_before_any_email_inference() {
    let f = Fixture::new(Scenario::Good);
    let mut s = f.settings();
    s.model_digest = Some("b".repeat(64));
    assert!(Ollama::new(&s).unwrap().analyze(&email()).is_err());
    assert!(f.chats.lock().unwrap().is_empty());
    assert!(f.warms.lock().unwrap().is_empty());
}
#[test]
fn cpu_offload_is_blocked_before_private_email_inference() {
    let f = Fixture::new(Scenario::CpuOnly);
    assert!(Ollama::new(&f.settings())
        .unwrap()
        .analyze(&email())
        .is_err());
    assert_eq!(f.warms.lock().unwrap().len(), 1);
    assert!(f.chats.lock().unwrap().is_empty());
}
