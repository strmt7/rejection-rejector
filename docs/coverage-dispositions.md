# Coverage dispositions

Every uncovered line of product code carries a written reason. This file
is the durable record (the coverage doctrine in `AGENTS.md` requires it;
thresholds in CI are regression floors, not the goal). Measurement: Rust
via `cargo llvm-cov` on Ubuntu (the `Rust coverage` workflow artifact),
Python via `coverage run` over all three suite roots (`tests/release`,
`training/tests`, `tools/contract`) as wired in the coverage workflow.

Update process: re-measure after any coverage-relevant change, move
resolved entries out, and add new entries with their reason. An entry is
only valid for a structural reason (platform, live service, optional
dependency, defensive arm) — "not worth testing" is not a reason.

## Python (residual, measured 2026-10-31: 74% total)

| Region | Lines | Reason |
| --- | --- | --- |
| `training/train_lora.py` | ~278 | GPU training loop: requires `torch` and an accelerator host. The two telemetry helpers' exception contracts are pinned (`test_train_lora_helpers.py`); the loop executes on the GPU training host under `training/duty_cycle.py`'s watchdog. |
| `training/evaluate_adapter.py` | ~83 | Adapter evaluation against a live local model; runs in the training workflow after fine-tuning. |
| `training/probe_llm_limits.py` | ~90 | The live-Ollama probe loop (`call_ollama`, `probe_one_row`, `run_condition`, `main`) needs a running model; the entire analysis layer (sampling, parsing, accuracy, fail-closed accounting, latency, progress) is pinned in `test_probe_llm_limits.py`. |
| `training/build_corpus_v2.py` | ~223 | CLI main and per-language template arms: the emitter's invariants (determinism, quotas, schema, dedup, 12 languages) are pinned end to end by `test_generator_pipelines.py`; residual lines are individual language×style template branches reached in production-scale runs. |
| `training/mine_enron.py` | ~148 | Error/edge branches: the parquet corpus path (optional `pyarrow` + the real dataset), archive error tails, rare charset fallbacks. The full pipeline (walk, parse, gate, emit, sweep, verification) is pinned by `test_mining_and_campaign.py` and `test_mine_enron_pipeline.py` over fixture corpora. |
| `training/build_sft_dataset.py` | ~47 | CLI main over real corpora; the transform and split are pinned. |
| `training/scale_campaign.py` | ~24 | Residual generation branches (rare format combinations) and CLI print tail; driver determinism pinned byte for byte. |
| `training/selective_eval.py`, `training/calibrate_zero_fp.py`, `training/progress.py`, `training/duty_cycle.py` | ~65 | CLI mains and rare overflow/report tails; core logic pinned. |
| `tools/crawl4ai_tool.py` | ~73 | pip-install provisioning branch and `check_lock` (resolver dry-run): exercised end to end by the "installed runtime contracts" selftest and lock-validation lanes against the pinned wheels. |
| `tools/local_ci.py` | ~88 | The gate runner itself: exercised by every gate run (it is the verification instrument). |
| `tools/validate_receipt.py`, `tools/contract/validate_contract.py` residual | ~130 | Failure-reporting error arms (bad paths, malformed receipts) that only fire on broken inputs; the acceptance/refusal matrices are pinned. |
| `tools/child_containment.py` | partial | Windows job-object arms run on Windows CI/lane hosts only; the Ubuntu coverage measurement cannot execute them (measurement-platform limit). |
| `tools/gpu_util_watchdog.py`, `tools/crawl4ai_research.py` tails | ~100 | Live GPU/process and network probe paths; their pure layers are pinned. |

## Rust (measured on Ubuntu: 96.8% lines / 96.0% functions)

| Region class | Examples | Reason |
| --- | --- | --- |
| Platform-gated arms | `peer_identity.rs` netstat/CIM (Windows) vs `/proc` (Linux), `startup.rs` `free_loopback_port` | Each arm executes only on its own platform; both CI OSes run the suites, but the coverage artifact is measured on Ubuntu only. Windows arms are exercised by the Windows lanes (incl. `process_image`'s live self-image pin). |
| Defensive-unreachable guards | `html_quote.rs` html2text `Err` arm (byte-slice reader cannot fail), `imap_smtp.rs` `find_sent` AString guard (unreachable after `safe_search_token`), `retry.rs` test-double arms (labeled "not coverage targets" in-code) | Retained as the fail-closed contract the Result APIs require. |
| CLI dispatch requiring live state | `bin/rr.rs` clusters (status/qualify/recover paths) | Need a provisioned engine, model, or recovery material; exercised by `tests/cli_smoke.rs`, `tests/cli_workspace.rs` and the qualification flows. |
| Live-service error arms | `imap_smtp.rs`, `engine.rs`, `worker.rs`, `ollama.rs` scattered tails (1–4% each) | Transport errors from live IMAP/SMTP/Ollama interactions; the protocol fakes cover the state machines, these are per-error-class reaction lines. |

## Non-coverage test-code arms

lcov includes `#[cfg(test)]` code in the same artifact; platform-conditional
test-harness arms (e.g. `bin/rr.rs` `ok_output`'s `#[cfg(unix)]` branch)
appear as missed lines on the other platform. Not product code; listed
here only to keep the artifact interpretable.
