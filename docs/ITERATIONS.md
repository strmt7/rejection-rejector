# Implementation review rounds — 26 September 2026

All work is committed on `main`; no replacement development branch is required.

## Verified baseline

Build source `f7a8ac1e2a47a1df6201a36dcf63e3338b209b8a`, workflow run `36257814818`: Windows and Linux passed builds, 36 library tests plus 15 automatic-policy tests, and Clippy with warnings denied. Linux produced an actual 1440×940 native screenshot. Windows produced optimized GUI/CLI binaries. No live account or physical GPU was used.

## Identity and protocol round

The review identified gaps beyond compilation: a displayed edit could become detached from an asynchronous selection/revision change; duplicate Subject/Auto-Submitted headers were not checked; composed replies did not independently bind the embedded email to the queue/conversation; generic JSON type errors could echo private input; HTTP retry policy was implicit.

Fixes add editor-ID/revision guards, exact persisted-body checks, queue/email/thread identity validation, duplicate-header rejection, duplicate OAuth-code rejection, explicit no-retry transport and redacted JSON errors. The signature is included as trusted data in the local verifier. Loopback mock tests exercise the three-stage Ollama protocol, fabricated evidence, interrupted completion, cloud metadata, changed digests and CPU offload. These are protocol tests, not measured model intelligence.

Run `36258403289` passed 71 tests on Linux, including these additions and demo-only CLI guards. The warnings-as-errors gate then caught production items placed after a unit-test module. The source ordering is corrected rather than suppressing the lint.

## Review interface round

The review pane is isolated in `src/gui/review.rs`. Both message cards have balanced minimum heights; the details and body areas scroll so controls remain reachable at smaller window sizes. Text/button contrast is improved, account switches clear old editor state, modal navigation is guarded, and closing with an unsaved reply requires confirmation. Demo-only view/size arguments allow actual captures of all five tabs plus the minimum-size review screen.

## Synchronization and concurrency round

Additional synthetic provider tests cover expired-history reconciliation, partial-history failure and replay, repeated pagination tokens, cancellation, wrong-account responses, and widening the selected age window. SQLite races test simultaneous conversation reservations and the rolling attempt cap across independent connections.

## Evidence boundary

Consult the latest workflow result and its COMMIT.txt for the exact tested version; adding code or tests does not prove they passed. The final pipeline is intended to validate source without rewriting the branch. Real Gmail authorization/delivery, real-model accuracy, physical 16 GiB GPU peaks and full Windows DPI/accessibility testing remain owner-environment acceptance checks. No such results are fabricated here.
