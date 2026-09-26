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

At source 720143c842d27711a833480da680fadfbb5585e2, the Linux all-feature suite passed 80 tests: 39 library, 2 desktop CLI, 15 automatic-policy, 6 HTTP-boundary, 4 mail-integrity, 6 mocked Ollama-protocol, 2 concurrent-reservation and 6 synchronization-recovery tests. The separate core-only pass repeats a subset; do not double-count it. Inspect the latest run and artifact COMMIT.txt rather than treating this historical result as proof of a later build.

The tests cover default disarming and exact presets; encryption/tampering/wrong keys and instance locks; stale revisions, durable reservations and caps; concurrent reservation races; mailbox/header injection and MIME threading; duplicate OAuth codes/state; failed history pages, cursor expiry, replay and changed lookback; exact model evidence, stale digest/context and offload rejection; response-size limits, redirect/retry policy and redacted errors; editor message/revision binding and demo-only screenshot controls.

## Actual native interface checks

The Linux job launches the native executable under Xvfb/Openbox with software OpenGL. It captures Overview, Review, Activity, Local AI and Settings at 1440x940, plus Review at 1180x760. Review capture additionally asserts that the rendered action row lies below the message cards and inside the visible viewport. The regression test rejects off-screen or misplaced action rectangles.

Actual image inspection found and led to fixes for a horizontal-layout inheritance bug that hid the review controls, and colliding Activity-row widget IDs. Images from source 720143c show corrected visible controls and distinct Activity rows. A captured PNG alone is not proof of correct interactions. The Settings screen scrolls; its initial screenshot does not cover every lower control.

Screenshot/view/size switches require --demo, so automated capture cannot open a real mailbox. Demo content and responses are synthetic, not claims about real model behavior.

## Model evaluation

With the desktop application closed, run:

```powershell
.\rr.exe evaluate --out .\model-evaluation.json
```

This records actual results from the configured local model on 12 synthetic fixtures without sending email. No model score is prefilled. The small corpus is a regression aid, not representative production accuracy or a best-model ranking.

## Remaining owner-environment acceptance

Use a controlled Gmail test account for OAuth, one intentionally authorized reply and Sent reconciliation. Test pause/interruptions, age boundaries, changed conversations and edited drafts. Inspect Windows keyboard access and display scaling at 100%, 125%, 150% and 200%. Check real GPU/backend support, near-limit prompts, peak device memory and classification/draft quality on independently labelled private data before Automatic.

CI does not authorize the owner's Gmail, send real email, run the actual model weights, measure a physical 16 GiB GPU or certify comprehensive Windows visual/accessibility behavior. The same-model reply audit is not an independent verifier. These limits must not be reported as passed tests.
