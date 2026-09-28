# Verification and acceptance

## Reproducible source selection

The final CI pipeline has read-only repository permissions. It checks out and verifies the exact triggering commit, uses the tracked Cargo.lock, pins Rust 1.98.1 and pins all workflow actions to commit SHAs. It does not edit source, run a finalization script, commit formatting changes or push to main. It fails if tracked source changes during validation.

This fixes source/dependency/toolchain selection. It is not a claim of bit-for-bit binary reproducibility: hosted runner images, OS packages and some external build inputs are not immutable snapshots.

## Automated checks

```text
cargo fmt --all -- --check
cargo test --locked --lib --no-default-features
cargo build --locked --bins
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo run --locked --no-default-features --bin rr -- demo
```

Both Windows and Ubuntu run these checks. Windows additionally builds optimized GUI/CLI executables and packages them with documentation, COMMIT.txt, toolchain evidence, Cargo.lock and per-file SHA-256 sums. A separate SHA256.txt covers the complete Windows ZIP. Checksums detect file changes; these are unsigned builds, not publisher-identity attestations.

## Scheduled enterprise deep verification

A separate scheduled/manual workflow deliberately complements rather than replaces the fast cross-platform CI. It uses pinned `cargo-nextest 0.9.146` to execute the full all-feature test suite with fail-fast disabled, compiles all targets under the release profile (where integer overflow checks remain enabled), builds rustdoc with warnings denied, runs doctests, and exercises the real recovery CLI against an isolated synthetic encrypted workspace:

```text
rr status
rr integrity
rr backup --out <temporary-backup>
rr verify-backup <temporary-backup>
rr recovery-drill <temporary-backup>
```

The drill uses the production restore path in a temporary workspace, deeply authenticates the restored encrypted records/audit chain, and leaves the live test workspace unchanged. The workflow uploads nextest/rustdoc/recovery evidence plus the exact OpenAPI SHA-256 contract fingerprint. It does not authorize Gmail, run a live Ollama model, or make an external write.

Test counts evolve as controls are added. Treat the exact current GitHub Actions run, its COMMIT.txt and uploaded logs as the evidence for a particular source revision; historical test counts are intentionally not used as release evidence.

The tests cover default disarming and exact presets; encryption/tampering/wrong keys and instance locks; stale revisions, durable reservations and caps; concurrent reservation races; mailbox/header injection and MIME threading; duplicate OAuth codes/state; failed history pages, cursor expiry, replay and changed lookback; exact model evidence, stale digest/context and offload rejection; the independent current-message rejection gate for Automatic mode, including quoted-history negatives; response-size limits, redirect/retry policy and redacted errors; editor message/revision binding and demo-only screenshot controls.

## Coverage and mutation quality gates

The safety-critical mutation workflow targets configuration, mail-policy, readiness, enterprise-policy and recovery code. Its current cargo-mutants 27.x configuration keeps concurrency on the CLI (`--jobs 2`) rather than the config file, so tool-schema drift fails visibly instead of being silently ignored. A workflow run now succeeds only when cargo-mutants reports that all viable tested mutants were caught; surviving mutants **or mutation timeouts fail the job**. Because the release workflow requires recent successful mutation evidence, an inconclusive or survivor-bearing run can no longer satisfy the release gate.

Coverage runs on relevant `main` changes as well as its schedule/manual trigger. The measured baseline from commit `555b708d42132d837e8cb291b47a9686f2a7f3b4` was **61.48% line coverage** and **65.13% function coverage** (59.92% regions) on the pinned Ubuntu/Rust/cargo-llvm-cov workflow. The gate therefore ratchets at **61% lines** and **65% functions**: deliberately just below the measured values, so future changes cannot silently degrade below the observed baseline. Raise the floor only from new measured evidence; do not lower it to make a failing change pass.

## Actual native interface checks

The Linux job launches the native executable under Xvfb/Openbox with software OpenGL. It captures Overview, Review, Activity, Local AI and Settings at 1440x940, plus Review at 1180x760. Review capture additionally asserts that the rendered action row lies below the message cards and inside the visible viewport. The regression test rejects off-screen or misplaced action rectangles.

Actual image inspection found and led to fixes for a horizontal-layout inheritance bug that hid the review controls, and colliding Activity-row widget IDs. Images from source 720143c show corrected visible controls and distinct Activity rows. A captured PNG alone is not proof of correct interactions. The Settings screen scrolls; its initial screenshot does not cover every lower control.

Screenshot/view/size switches require --demo, so automated capture cannot open a real mailbox. Demo content and responses are synthetic, not claims about real model behavior.

## Model evaluation and task-specific model selection

With the desktop application closed, run the configured model through the complete synthetic recruiting pipeline:

```powershell
.\rr.exe evaluate --out .\model-evaluation.json
```

To compare curated candidate models that you have **explicitly installed** in Ollama:

```powershell
.\rr.exe compare-models --out .\model-bakeoff.json
```

The comparison never downloads multiple large models implicitly. It skips absent candidates.

Each evaluated model first runs the same local qualification used by the app, then processes **48 synthetic fixtures** through the complete classification/draft/verification pipeline. The corpus has explicit risk tags for ATS automation, interviews, offers, recruiter corrections, quoted history, prompt injection, ambiguity, pending-status wording and multilingual cases. The report tracks classification accuracy, rejection false positives/false negatives, verified rejection-draft success, unsafe drafts on non-rejections, latency, residency and per-tag metrics. The application-specific score weights non-rejection false-positive avoidance most heavily, and recommendation eligibility separately requires all critical hard negatives to complete with zero rejection false positives and zero generated drafts. The report includes exact digest/context, accuracy, rejection true/false positives and false negatives, precision, recall and mean per-case latency. No model score is prefilled. The corpus is still a regression aid, not representative production accuracy or a best-model ranking.

## Remaining owner-environment acceptance

Use a controlled Gmail test account for OAuth, one intentionally authorized reply and Sent reconciliation. Test pause/interruptions, age boundaries, changed conversations and edited drafts. Inspect Windows keyboard access and display scaling at 100%, 125%, 150% and 200%. Check real GPU/backend support, near-limit prompts, peak device memory and classification/draft quality on independently labelled private data before Automatic.

CI does not authorize the owner's Gmail, send real email, run the actual model weights, measure a physical 16 GiB GPU or certify comprehensive Windows visual/accessibility behavior. The same-model reply audit is not an independent verifier. These limits must not be reported as passed tests.
