# Implementation review rounds — 26 September 2026

All work remains on main. The temporary feature branch was removed; no replacement development branch was created.

## Verified baseline

Source f7a8ac1e2a47a1df6201a36dcf63e3338b209b8a, workflow 36257814818: Windows and Linux builds, 36 library tests plus 15 automatic-policy tests, warnings-as-errors, the headless demo, a native Linux capture and the Windows optimized package passed. No live account or physical GPU was used.

## Identity and protocol round

Review exposed risks not covered by compilation: asynchronous selection/revision changes could detach displayed edits from a message; duplicate Subject/Auto-Submitted headers were unchecked; reply composition did not independently bind the embedded email to the queue/conversation; JSON type errors could echo private values; HTTP retry policy was implicit.

The fixes bind the editor to message ID/revision and exact persisted text, validate queue/email/thread identity before composition and delivery, reject duplicate sensitive headers and OAuth authorization codes, explicitly disable HTTP retries and redact JSON errors. The verifier receives the trusted signature. Loopback mocks test all three Ollama stages, fabricated evidence, incomplete generation, cloud metadata, changed digests and CPU offload. These are protocol tests, not model-intelligence measurements.

Workflow 36258403289 passed 71 tests on Linux, then correctly failed warnings-as-errors because a production helper followed a test module. The ordering was fixed without suppressing the lint.

## Synchronization and concurrency round

Source 7145e4f1c0493c2fd6004b82b3cd7fb799727ea0, workflow 36258615253: both platform jobs passed. The expanded suite includes history-cursor expiry, partial-history failure/replay, repeated pagination tokens, cancellation, wrong-account responses, and lookback expansion. Barrier-driven races between independent SQLite connections verify one reservation per conversation and enforcement of the global attempt cap. The Linux all-feature suite total was 79.

## Visual inspection and corrective round

Although six native captures completed, inspection of source 7145e4f exposed two real rendering defects: the right review ScrollArea inherited the outer horizontal layout, pushing actions off-screen; repeated Activity Details controls shared a widget ID. The capture-success result was not treated as visual acceptance.

The review details now have an explicit vertical layout, bounded scrolling and smaller balanced cards. Activity uses message-specific widget IDs. Small text was increased to 12 points and cards use consistent available width. Account switches clear old editor state; stale editor/message bindings prevent mutation; unsaved close requires confirmation.

Source 720143c842d27711a833480da680fadfbb5585e2, workflow 36258976422: the Linux suite passed 80 tests, warnings-as-errors and six native captures. The corrected images were inspected: review controls are visible at 1440x940 and 1180x760 and Activity no longer shows widget-ID collisions. Capture now also checks actual rendered action-row geometry, backed by a regression test.

## Build pipeline cleanup

The final workflow removes the temporary source-finalization and auto-commit job. It has read-only repository access, checks the exact triggering commit, uses the tracked lockfile, pins Rust 1.99.0 and action commit SHAs, and rejects changes to tracked files during validation. Windows artifacts contain commit/toolchain evidence and SHA-256 manifests. Hosted runner/OS inputs are not immutable, so bit-identical rebuilds are not claimed.

## Evidence boundary

Always use the latest completed workflow and its artifact COMMIT.txt to identify the exact tested version. Historic passing tests do not certify later edits. Real Gmail authorization/delivery, actual model accuracy, physical 16 GiB GPU peaks and complete Windows DPI/accessibility testing remain owner-environment acceptance checks. No such results were fabricated.

## Completion hardening rounds

The incremental Gmail queue was changed from one SQLite transaction per discovered message to one encrypted transaction per Gmail page. `INSERT OR IGNORE` keeps existing payloads untouched and only genuinely missing identities receive a queue record and audit event. Regression coverage verifies replay-safe deduplication.

Age-window enforcement was tightened: reducing 28/14/7/3/1-day scope immediately defers older actionable records and clears their stored message body, draft and analysis while retaining only the provider-identity tombstone needed for deduplication and later scope expansion.

Local AI qualification now exercises all three reasoning stages—classification, drafting and verification—before accepting a digest pin, then requires the configured full-GPU-residency gate. Automatic-mode deterministic guards were expanded for clear interview/offer and prompt-injection language across English, German, French, Italian, Spanish and Portuguese; the LLM remains the primary classifier.

The headless CLI gained `rr doctor`, which reports only non-sensitive Gmail permission/configuration flags, schedule/mode, Ollama reachability, model pin/install state and current residency. CI also smoke-tests this command in an isolated encrypted workspace.

## Professional hardening round — 27 September 2026

Automatic mode now requires an independent deterministic clear-rejection phrase in the current de-quoted message in addition to the local model classification, same-model verification, conflict guards and fresh Gmail preflight. This is deliberately stricter than Human Review: a correlated model/verifier false positive can no longer authorize unattended sending on its own. Regression coverage includes ambiguous model-only negatives and quoted historical rejections.

The 16 GiB profile now uses `qwen3.5:9b-q8_0` as a **provisional** default rather than a hard-coded claim of universal superiority. Current challengers include the recent Granite 4.2 8B Q8 model, Gemma 4 12B Q8 and Ministral 3 14B. A new full-pipeline bake-off evaluates already-installed candidates on the repository's multilingual rejection/opportunity/ambiguous/injection fixtures and recommends only candidates with zero rejection false positives, zero unsafe non-rejection drafts, at least 90% rejection recall, at least 90% verified rejection-pipeline completion and full GPU residency. Ollama 0.35.1 is the minimum accepted runtime; the local inference client includes one bounded unload-and-retry recovery for transport timeout/connect failures only.

## Final acceptance rule

The deliverable is only considered build-verified when the newest `main` workflow completes successfully on both Windows and Linux after all of the rounds above. The Windows ZIP must contain an exact `COMMIT.txt`, toolchain evidence and SHA-256 manifests. Live Gmail consent/delivery, model accuracy on the owner's private corpus and physical 16 GiB GPU behavior remain explicit owner-environment acceptance checks.
