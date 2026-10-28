# RR code and test claims — critical verification and remediation (2026-10-28)

Scope: every rejection-rejector (RR) claim about CODE AND TESTS in
`strmt7-enterprise-engineering-implementation-manual-2026-10-27.pdf` — the R11
action page (Part II, p35), "RR repaired CI fixtures and historical diagnosis"
(Part IV, p93-96), the RR-relevant parts of "Native, Rust and scanner evidence"
(p83-93) and "Native and scanner adversarial revalidation" (p115-118), plus RR
findings elsewhere (N03-N05, N09-N12, CI-RR-1/CI-RR-2, section 6).

Method: the PDF was read in full (4,216 extracted lines) before verification.
Every claim was checked against the CURRENT repository
(`C:/Users/strat/projects/rr/canonical`), not the document's snapshots. The
repository had advanced past the audited SHA 589b89fceac5 (verified commits:
568d979, then a5f346a "chore: bring every tool, action and dependency to
verified-latest; eframe 0.37"); claims true at the audit SHA but changed since
are marked **stale**, not false. Verified defects inside the assigned file
ownership were fixed; fixes outside it are recorded as implementation
directives.

Verification HEAD at report time: `a5f346a3a7a90f57c315760f9c4c7b80039448a5`
plus this work's uncommitted changes. No commits were made.

---

## 1. RR-01 — repaired fixtures, test isolation (R11 p35; p93-96; p115-118)

| # | Claim (source) | Verdict | Evidence |
|---|---|---|---|
| 1.1 | Historical CI-RR-1: at 4d09e133 the ordinary Rust CI lacked the Linux vault passphrase; 831 no-default + 879 all-feature lib tests passed, rr binary tests 18 passed / 9 failed, all with the missing `RR_VAULT_PASSPHRASE` diagnostic; library tests pass via a `#[cfg(test)]` one-shot OnceLock seam (vault.rs:190-212, 1160-1175) | **verified (historical)** | `src/vault.rs` `linux_vault_passphrase()` (env read + `#[cfg(test)]` `test_support::HEADLESS_PASSPHRASE` OnceLock seam, current lines ~195-210 / ~1168-1175) matches the described mechanism exactly. The hosted run links are retained as the document's historical evidence. |
| 1.2 | Historical CI-RR-2: the recovery fixture at rr.rs:2067-2093 wrote its passphrase with plain `std::fs::write` and never applied private permissions, so the production 0600 gate masked the exact-IMPORT assertion | **verified (historical)** | `git show 4d09e13:src/bin/rr.rs` shows `std::fs::write(&passphrase, ...)` with no mode handling — an exact match for the document's quote. |
| 1.3 | "The two original Linux setup defects are source-remediated": test wrapper supplies synthetic vault input to ten live-workspace tests; recovery fixture applies mode 0600 before export and retains the exact IMPORT assertion (at 589b89f) | **verified** | Commit `cdcf64c` ("close the residual DeepSource findings and the Linux recovery test") introduced both fixes; its message documents "4+27+9 green in WSL". Code at the audit SHA matches the cited line ranges (wrapper 1803-1823, fixture 2101-2141). |
| 1.4 | "ten live binary tests now use a synthetic-input wrapper" | **verified** | Exactly 10 `with_headless_vault_input(|| {` call sites existed in `src/bin/rr.rs`. |
| 1.5 | Recovery fixture applies 0600 before export and asserts the exact IMPORT token ("Recovery-key import requires --confirm IMPORT") | **verified** | rr.rs fixture: `perms.set_mode(0o600)` block before `cmd_export_recovery_key`; `assert_eq!(error.to_string(), "Recovery-key import requires --confirm IMPORT")`. |
| 1.6 | "Preserve the dedicated 0644 rejection test and production fail-closed checks" | **verified, preserved** | `recovery_passphrase_file_must_be_private` asserts 0644 → error, 0600 → accepted. Unchanged by this work. |
| 1.7 | Hosted nextest job 122465545513/run 40582566896 at 589b89f: 1,015 run / 1,015 passed / zero skipped, including `recovery_key_import_demands_its_exact_confirmation_token` | **hosted evidence (not independently reproducible here); consistent** | The named test passes locally at current HEAD (Windows run below). Local suite totals have since grown past 1,015 (see receipts), consistent with later test-adding commits. |
| 1.8 | **RR-01 core: `temp_env::with_var` serializes only its own setters; a setter mutex does not coordinate every environment reader; the worker engine thread spawned during a wrapped test reads the environment concurrently (P2 test-isolation design concern)** | **verified TRUE (concretely reproduced by source inspection)** | `Worker::spawn` (`src/worker.rs:444/465`) runs `Engine::open` on a spawned OS thread; `Vault::open` → `linux_vault_passphrase()` reads `std::env::var("RR_VAULT_PASSPHRASE")`; `Engine::open` → `open_policy_context` reads `RR_ENTERPRISE_POLICY*` (`src/policy.rs:670-786`); `emergency.rs:38/84`, `audit_anchor.rs:246/459`, `diagnostics.rs:87`, `worker.rs:2751` all read the environment. temp-env 0.3.6's registry source shows `static SERIAL_TEST: ReentrantMutex<()>` held only around its own closures. Rust 1.99 / edition 2024 marks `env::set_var` unsafe and this crate `forbid(unsafe_code)`, which is why temp-env was used at all. Any getenv in a sibling test thread or engine thread races the per-test set/restore. |
| 1.9 | "No race was reproduced" (the document's own qualifier) | **verified as worded** | No crash was observed locally either; the defect is contract-level soundness plus semantic flicker (input set/restored per test), exactly as the document frames it. |
| 1.10 | "The runtime_log.rs delta only changes a test's empty String construction to `String::default()`, not production logging semantics" | **verified exactly** | `git diff 4d09e13 589b89f -- src/runtime_log.rs` is a single line (`message: String::new()` → `String::default()`) inside `rotation_and_status_tests`. |
| 1.11 | Cargo change resolves multiple windows-sys edges to 0.61.2; dirs-sys 0.5.0 accepts >= 0.59.0 so the movement is not invalid | **verified** | `Cargo.lock`: numerous `windows-sys 0.61.2` edges; `dirs-sys 0.5.0` present. |
| 1.12 | "Rust is pinned to 1.99.0" | **stale** | `rust-toolchain.toml` now pins `1.99.1` (commit a5f346a). True at the audited SHA. |
| 1.13 | "temp-env 0.3.6 resolved as a dev dependency" | **verified then fixed** | Was `temp-env = "0.3"` in `[dev-dependencies]`; removed by this work (see Fixes). |
| 1.14 | RR-01 pass condition "Missing production input still fails closed" | **verified + regression added** | `linux_vault_passphrase()` errors with the documented message when neither seam nor env supplies input; the Linux import child asserts the refusal names `RR_VAULT_PASSPHRASE`. A dedicated entry-point regression now exists (`missing_headless_vault_input_fails_closed`). |
| 1.15 | tests/cli_workspace.rs:45-76 "already uses Command.env to provision each child process" (the recommended pattern) | **verified** | `headless_vault_seam(&mut Command)` sets `RR_VAULT_PASSPHRASE` per spawned child (`#[cfg(not(windows))]`), with the Windows counterpart documented. |
| 1.16 | RR-01 page: "Retain recovery-file mode 0600 and exact IMPORT checks" | **verified, retained** | Both preserved unchanged through the migration (exact sentence assertions carried over verbatim). |

**RR-01 residual (design refinement) — fixed.** The wrapper and its per-test
process-global env mutation are gone; see Fixes F1.

## 2. RR-02 / N03 / N04 — calibration and input validation (R11 p35; p93 N03/N04; p116)

All sub-claims reproduced against the CURRENT `training/calibrate_zero_fp.py`
(python import + executed probes, 2026-10-28):

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 2.1 | N03: `select_best` sweeps only 0.000..1.000 step 0.001; negatives 0.5001 / positive 0.5002 → selects 0.501 with TP 0 / recall 0, while 0.50015 yields TP 1 / FP 0 | **verified, still open** | Ran `calibrate(rows, 0)` on the exact case: `{"threshold": 0.501, "true_positives": 0, ... "recall": 0.0}`; independent `counts_at` at 0.50015 → `(fp=0, tp=1)`. Code line 79: `for threshold in [i / 1000 for i in range(0, 1001)]`. |
| 2.2 | N04: `load_scores` performs no row-shape / label / numeric-type / finiteness / bounds validation | **verified, still open** | Code lines 38-50: bare `json.loads` per line. |
| 2.3 | N04: a NaN negative is never counted by `>=`, so zero false positives can be reported from invalid observations (one NaN negative + one 0.9 positive → threshold 0, recall 1) | **verified, still open** | Ran: report `{"threshold": 0.0, "true_positives": 1, "false_positives": 0, "recall": 1.0}` from a NaN row. |
| 2.4 | N04 (refresh): negative score 2.0 + positive 0.9 → fallback reports threshold 1.01 / FP 0, but applying that threshold yields one FP | **verified, still open** | Ran: report `threshold 1.01, false_positives 0`; `counts_at([2.0], [0.9], 1.01)` → `(fp=1, tp=0)`. Self-contradiction reproduced exactly. |
| 2.5 | N04: booleans and unknown labels are accepted; the documented "ambiguous" label counts as negative (preserve that policy) | **verified, still open** | Ran: `{"label":"banana","rejection_probability":true}` accepted and counted as negative. The ambiguous-label policy is explicit in `load_scores`'s docstring and must be preserved when validation is added. |
| 2.6 | N04: a negative FP budget returns a report instead of rejecting input | **verified, still open** | Ran: `calibrate(rows, -1)` returns a report with `target_false_positives: -1`. |
| 2.7 | N04: the CLI already rejects nonintegral budgets (argparse `type=int`); the callable boundary needs validation | **verified** | `--target-fp` uses `type=int`; `calibrate()` itself validates nothing. |
| 2.8 | N09: "the calibration function has no matching tests in the tracked test tree" | **verified, still open** | `grep -rln "calibrate\|select_best\|wilson" tests/` → zero matches. `tests/release/` contains duty-cycle/progress tests (as the document says) but nothing for calibration. |
| 2.9 | RR-02 wording: "Replace the 0.001 grid with observed decision boundaries, deterministic ties and explicit abstention" | **requirement built on verified defects; open** | — |

Fix lies in `training/calibrate_zero_fp.py` + `tests/release/` — outside this
worker's ownership → **directives D1/D2** below.

## 3. N05 / RR-04 — duplicate security jobs and advisory rationale

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 3.1 | supply-chain.yml has an `advisories` job installing unversioned `cargo install cargo-audit --locked` and running an audit, while `rust-policy` installs pinned cargo-audit@0.22.2 (+ cargo-deny 0.20.2, cargo-cyclonedx 0.5.9, cargo-machete 0.9.2 via taiki-e/install-action) and repeats the same audit with the same four ignores | **verified, still open** | Current `.github/workflows/supply-chain.yml` lines 20-58: identical shape at HEAD. |
| 3.2 | "The older job also installs the rust-toolchain action with its default stable input rather than the explicit version used in the other lane" | **verified, still open** | `advisories` job: `dtolnay/rust-toolchain@6bed076…` with no `with:`; `rust-policy` pins `toolchain: 1.99.1`. |
| 3.3 | The RUSTSEC-2023-0086 ignore is a bare ID in deny.toml while Cargo.toml says the old dependency path was removed; verify before deleting | **verified, still open; new evidence** | deny.toml `ignore = ["RUSTSEC-2023-0086", { id = …, reason = …}×3]` — bare vs reasoned. Cargo.toml:57-58 documents that the nom 7 switch drops imap 2's nom 5 → lexical-core 0.7.6 (RUSTSEC-2023-0086) path. **New:** `cargo audit --deny warnings` WITHOUT the 0086 ignore passes at the current lock (exit 0) — the exception appears unnecessary today. |
| 3.4 | "Correct the stale yoke-derive rationale": `yoke-derive = "0.8.4"` is a compatible range, while the cargo-machete rationale says "Keep 0.8.2 pinned" | **verified, still open** | Cargo.toml:75 `yoke-derive = "0.8.4"`; lines 89-90 rationale says "Keep 0.8.2 pinned until the upstream graph moves" — internally drifted. |

Targets (.github/workflows/supply-chain.yml, deny.toml, Cargo.toml) are outside
this worker's ownership → **directive D3**.

## 4. N09 / RR-03 — Python/model tooling coverage scope

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 4.1 | release-tooling.yml syntax-checks only tools/resource_guard.py and training/train_lora.py, then runs operator tests | **verified, still open** | Current workflow: `python -m py_compile tools/resource_guard.py training/train_lora.py` then `python -m unittest discover -s tests/release -v`. |
| 4.2 | Rust coverage measures Rust and scripts/; training/ and tools/ are outside the measured Python source set | **verified, still open** | coverage.yml: `cargo llvm-cov … --fail-under-lines 95 --fail-under-functions 90` plus `python3 -m coverage run --source=scripts -m unittest discover -s tests/release`. |
| 4.3 | RR-03 "Extend relevant coverage scope beyond operator scripts" | **open requirement** | Same evidence as 4.2; nothing has changed the scope. |

→ **directive D4** (workflow files outside ownership).

## 5. N10 / RR-05 — module scale and orchestration boundaries

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 5.1 | engine.rs 6,786 lines, first `mod tests` at 2,634; worker.rs 6,476 / 2,998; store.rs 4,705 / 2,554 | **verified** | `wc -l` + `grep -n "mod tests"` at HEAD: 6786/2634, 6476/2998, 4705/2554 — exact. |
| 5.2 | gui.rs 5,385 lines with tests starting 2,657 | **stale** (verified at audited SHA) | `git show 589b89f:src/gui.rs` = 5,385 lines, `mod tests` at 2,657 (claim exact for its snapshot). At HEAD: 5,379 / 2,663 (eframe 0.37 upgrade, commit a5f346a). |
| 5.3 | RR-05 "Preserve delivery-state CAS …" | **verified preserved** | `src/store.rs` conditional transitions compare expected state AND revision and inspect the affected row count: line 1681 `UPDATE items SET state=?2,… WHERE id=?1 AND revision=?8`, lines 2252/2315 `… WHERE id=?1 AND state=?6 AND revision=?7`; `let changed = tx.execute(...)` results are checked. |
| 5.4 | RR-05 extraction of transport/scheduling/persistence/presentation | **open structural task (partial progress)** | The four modules still span scheduling, transport, state and API responsibilities (5.1); commit `e3c6822` (RS-R1000 decomposition of 14 over-complex functions) is incremental progress. The manual itself forbids line-count-driven rewrites, so this is recorded as an open task, not a defect with a minimal fix. |

## 6. N11 / N12 / RR-06 — evidence retention, concurrency, release

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 6.1 | RR's ref-scoped concurrency groups use `cancel-in-progress: false` without a queue setting, so the "every main commit" comment is an intention, not a guarantee | **verified for ci.yml + supply-chain.yml; partially stale for the deep lanes** | ci.yml (`group: rust-ci-${{ github.ref }}`) and supply-chain.yml (`supply-chain-${{ github.ref }}`) keep the comment + `cancel-in-progress: false` with no `queue: max` — the document's GitHub-semantics point stands there. BUT `mutation.yml` and `enterprise-deep-verification.yml` now use **per-SHA** groups (`group: mutation-testing-${{ github.sha }}`, `enterprise-deep-verification-${{ github.sha }}`, both commented "evidence runs must never be superseded by later pushes") — the independent-run-identity remedy RR-06 asks for is already implemented for those two lanes. |
| 6.2 | "RR describes a 100% goal with 95%/90% regression floors" | **verified** | AGENTS.md coverage doctrine: "100% line coverage of the measured areas … standing goal, not a CI gate: --fail-under thresholds exist only as regression floors"; coverage.yml enforces `--fail-under-lines 95 --fail-under-functions 90`. |
| 6.3 | "Only RR has a root .editorconfig" / "A root CODEOWNERS file was not found in these four snapshots" | **verified for RR** | `.editorconfig` present; no `CODEOWNERS` / `.github/CODEOWNERS`. |
| 6.4 | N12: RR has an attested Windows package workflow and a separate two-build reproducibility workflow | **verified** | `.github/workflows/release.yml` and `.github/workflows/reproducibility.yml` exist with those roles. |

## 7. Counts, operator suite, misc

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 7.1 | 188 tracked files / 15 workflow files at 589b89f | **verified** | `git ls-tree -r 589b89f --name-only` = 188 lines, 15 under .github/workflows/. |
| 7.2 | RR Python operator suite: 173 tests, 1 Windows-only PowerShell parser skip, exit 0 (historical, at 4d09e133) | **verified; count unchanged at HEAD** | `python -m unittest discover -s tests/release -v` at HEAD: "Ran 173 tests … OK" (on Windows the parser test runs; the documented skip is its non-Windows behavior). |
| 7.3 | RR calibration reproducer: two defects reproduced (grid misses feasible optimum; nonfinite input accepted) | **verified** | Re-executed both reproductions at HEAD (section 2). |
| 7.4 | "80 generated close-score cases all missed the independently computed feasible optimum" | **verified mechanism** | The single-case exact reproduction (2.1) confirms the defect class; the 80-case figure is the auditor's retained probe artifact. |
| 7.5 | Hosted CI observations (11/12 runs, Mutation pending, DeepSource all successful) | **not verifiable here (hosted state; outside code/test scope)** | No authenticated Actions access from this environment. |

---

## Fixes applied (verified still open → fixed at source)

**F1 — RR-01: remove the in-process per-test env mutation; per-child
`Command.env` fixtures carry the synthetic input (coordinator directive D1).**
Files: `src/bin/rr.rs`, `tests/cli_workspace.rs`, `Cargo.toml`, `Cargo.lock`.

1. `with_headless_vault_input` and its `temp_env::with_var` per-test
   set/restore are **deleted**. Net result: `grep -rn 'temp_env|set_var' src
   tests` is **empty**; `temp-env` is dropped from `[dev-dependencies]`
   (the section is gone) and from `Cargo.lock` (regenerated via
   `cargo check --all-targets --all-features`).
2. The ten live-workspace call sites were migrated off in-process workspace
   opens:
   - **Eight** became per-child `Command.env` journeys in
     `tests/cli_workspace.rs` (the existing `headless_vault_seam`
     pattern), folding their pinned assertions into the child suite:
     - `status_reports_demo_and_live_workspaces` → covered by
       `readiness_and_status_commands_emit_machine_readable_reports`
       (live + demo JSON asserts).
     - `status_metrics_and_doctor_reports_print_and_gate` → covered by
       `readiness_and_status…` + `doctor_require_gates_on_the_exact_readiness_level`,
       which now also asserts the pinned sentence
       "Requested readiness level Mailbox is not satisfied".
     - `database_backup_and_drill_commands_round_trip` → covered by
       `backup_verify_drill_and_restore_round_trip`, extended with the
       journal assertion ("backup.drill_passed" audited — read back through
       `rr diagnostics` `recent_audit.event_kinds`, replacing the deleted
       in-process `db.events` read) and the pinned restore sentence
       "Restore requires --confirm RESTORE".
     - `diagnostics_shadow_and_audit_anchor_reports_write` → covered by
       `maintenance_commands_write_their_operator_artifacts` (artifact +
       verify asserts).
     - `recovery_key_import_demands_its_exact_confirmation_token` → covered
       by `recovery_key_envelope_round_trips_with_its_passphrase`, now
       asserting the pinned sentence "Recovery-key import requires --confirm
       IMPORT" (was a contains-"IMPORT" check). The 0600 fixture
       (`write_private`) and the 0644-rejection assertions are preserved
       exactly (`recovery_passphrase_file_must_be_private` unchanged).
     - `configure_applies_requested_fields_and_refuses_invalid_values` →
       NEW child test of the same name: asserts the `configure` settings
       JSON (lookback 3, poll 2, signature, api_enabled, api_port 9001),
       the pinned refusal "Lookback must be 1, 3, 7, 14 or 28 days", and
       that `status` still reports the previous value afterwards.
     - `rotate_api_token_rotates_the_local_api_credential` →
       `maintenance_commands…` extended: second rotation succeeds, prints a
       second one-time token, tokens differ.
     - `model_commands_fail_closed_without_the_runtime` → the previously
       Windows-only child `model_commands_fail_closed_without_the_local_runtime`
       is now cross-platform: it pins an unsatisfiable model tag
       (`rr configure --model rr-audit:absent-runtime`) so a live Ollama can
       never turn failures into passes (Windows additionally keeps the
       closed-port `point_ollama_at` pin), asserts no evidence file is
       fabricated for evaluate/evaluate-decision/profile-model, adds
       `qualify` fail-closed and `sync` fail-closed parity.
   - **Two** shed their live-workspace dependency and stay in-process with
     their oracles intact (no vault input required at all):
     - `misgrouped_subcommands_route_through_the_dispatch_fallbacks` now
       sends vault-free guests (ContractInfo/BuildInfo/Demo) through every
       dispatch group's fallback arm; the workspace-command side of the
       old pairing runs at the real entry point in the child suite.
     - `validate_policy_reports_status_and_refuses_missing_files` uses a
       plain tempdir (its workspace use was only a tempdir), keeping the
       exact OS-error assertions ("No such file or directory (os error 2)" /
       the Windows variant).
3. **New regression test** `missing_headless_vault_input_fails_closed`
   (`tests/cli_workspace.rs`, non-Windows/macOS): spawns `rr status` with
   `RR_VAULT_PASSPHRASE` deliberately removed and asserts the entry point
   fails closed and names the documented input — the RR-01 pass condition
   "Missing production input still fails closed" now has a direct
   failing-before/passing-after style guard (before this contract existed,
   the only Linux input path was the racy in-process mutation).
4. The production guards were not weakened: the 0600 recovery-passphrase
   gate, the 0644 rejection, the exact IMPORT/RESTORE refusal sentences and
   the vault fail-closed checks all remain, several now pinned verbatim at
   the entry point.
5. All new/changed items carry repo-style rustdoc (one-line summary, Why,
   Inputs/Output).
6. Mechanical follow-up of the mandated lock regeneration: `engineering.toml`
   `input_files[cargo-lock].sha256` updated to the new Cargo.lock digest
   (`f0251d1e…`), as the repo's own `tests/release/test_engineering_policy.py`
   enforces (a stale input digest rejects closure). The historical
   `docs/model-scale-report.md` digest entry ("at header time") was left
   untouched — it is timestamped evidence, not a live receipt.

Net diff versus the audited behaviour: no test writes to the process
environment any more (the only writes live in `Command::env` of spawned
children — the documented safe seam); OS credential-store writes remain the
pre-existing mint+drop-cleanup pattern with `VaultGuard` (verified zero net
entries across a full rr-binary run: `cmdkey` count 36 before and after).

**Verification receipts (this work):**

| Run | Result |
|---|---|
| `grep -rn 'temp_env\|set_var' src tests` | empty (0 matches) |
| `cargo fmt --all -- --check` | green |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | green |
| `cargo test --locked --all-features` (Windows, final) | 22 targets, **1,051 passed / 0 failed / 0 ignored** (pre-migration baseline was 1,058 = +7 net of −8 migrated +1 new configure test; the rr bin target drops 26→18 in-process tests on Windows accordingly) |
| `cargo test --locked --all-features` (WSL Linux, `wsl -e bash -lc`, `CARGO_TARGET_DIR=/tmp/rr-linux-check`, `CARGO_BUILD_JOBS=2`, `setsid` headless) | 22 targets, **1,019 passed / 0 failed / 0 ignored**, including `missing_headless_vault_input_fails_closed`, the cross-platform `model_commands_fail_closed_without_the_local_runtime`, and the migrated journeys |
| `cargo test --locked --all-features --test cli_workspace` (WSL Linux, focused) | **12 passed / 0 failed** |
| `python tools/local_ci.py` (CARGO_BUILD_JOBS=4, final run) | **ALL GATES GREEN** (exit 0): fmt GREEN, clippy GREEN, cargo audit GREEN, rustdoc GREEN, cargo test (full) GREEN, python release suites GREEN (ruff check/format remain the pre-existing advisory xfail lanes) |
| `python -m unittest discover -s tests/release -v` | 173 tests, OK |
| OS credential store delta across a full rr-binary run | 36 → 36 (no new live OS credential state) |

Environment note (recorded honestly): running the WSL suite through an
interactive `wsl.exe` console makes `tui_demo_mode_fails_fast_without_a_terminal`
hang — `wsl.exe` attaches a controlling console, so crossterm finds `/dev/tty`
and the demo TUI waits for keys. The test's premise ("without a terminal")
holds on headless hosts (GitHub runners) and under `setsid` detachment, where
it passes. This is a pre-existing environment sensitivity of an unchanged
test, not a product defect and not introduced by this work.

---

## Directives for other areas (fixes outside this worker's ownership)

- **D1 (training/, tests/release/) — RR-02/N03/N04 calibration repair.**
  Status note: at report time an untracked `training/tests/test_calibration_zero_fp.py`
  appeared (concurrent worker), so this directive is being picked up elsewhere;
  the verification above remains the acceptance spec for it.
  In `training/calibrate_zero_fp.py`: (a) replace the 0.001 grid in
  `select_best` with the decision set induced by observed finite scores
  (candidate thresholds = each distinct observed score, with the documented
  `>=` semantics and a deterministic tie-breaker; keep an explicit
  abstain-all outcome instead of the implicit 1.01 fallback); (b) validate
  JSONL at ingestion in `load_scores`/`calibrate` with line-numbered errors:
  require exactly the documented fields, label ∈ {rejection, not_rejection,
  ambiguous} (preserving "ambiguous counts as negative for FP purposes"),
  reject booleans as probabilities, reject NaN/±inf and values outside
  [0, 1], and reject negative/nonintegral `target_fp` in the callable; (c)
  make the fallback report self-consistent — a reported threshold must
  reproduce the reported confusion counts (today score-2.0 input reports
  threshold 1.01 / FP 0 while applying it yields FP 1); (d) emit an explicit
  insufficient-data status instead of a report from invalid rows, and never
  drop invalid rows silently while keeping the denominator. Regression tests
  (in `tests/release/`, excluded from this worker): the 0.5001/0.5002
  close-score case must reach the feasible TP 1 / FP 0; NaN/bool/unknown-
  label/out-of-range/negative-budget inputs must fail before any report; the
  reported-threshold replay must reproduce the reported counts; keep the
  ambiguous-label policy test. A small independent exhaustive oracle (not a
  copy of the optimized implementation) should check small random sets.
- **D2 (tests/release/) — calibration coverage gap** (N09): add the tests
  above; there are currently zero calibration tests in the tracked tree.
- **D3 (.github/workflows/supply-chain.yml, deny.toml, Cargo.toml) — RR-04/N05.**
  Keep one pinned authoritative cargo-audit lane (the unversioned
  `cargo install cargo-audit --locked` job duplicates the pinned
  cargo-audit@0.22.2 lane with different version semantics; its
  dtolnay/rust-toolchain call also runs the default stable instead of
  1.99.1). Convert the bare `RUSTSEC-2023-0086` ignore into a reasoned entry
  or remove it: `cargo audit --deny warnings` passes at the current lock
  WITHOUT it (verified 2026-10-28), and Cargo.toml:57-58 documents that the
  vulnerable lexical-core path was removed. Fix the yoke-derive rationale:
  `yoke-derive = "0.8.4"` is a caret range; the comment's "Keep 0.8.2
  pinned" contradicts it.
- **D4 (.github/workflows/coverage.yml, release-tooling.yml) — RR-03/N09.**
  Extend the measured Python source set beyond `scripts/` to the
  quality-critical training/tools code (calibration, dataset splitting,
  evaluation, release verification), and make the release-tooling syntax
  check cover the whole training/tools surface, not just
  tools/resource_guard.py + training/train_lora.py.
- **D5 (training/README.md) — N09 documentation contradiction.** The
  portability section says "AMD GPUs work through ROCm on Linux or WSL2 on
  Windows" (lines 13-14) while the supported-compute section says PyTorch
  ROCm wheels cannot initialize GPU training in WSL2 (lines 27-32). Reconcile
  against the dated vendor/runtime matrix already recorded there.
- **D6 (ownership ledger note).** Per coordinator directive D1 this worker
  also edited `src/bin/rr.rs` and `Cargo.toml` (both outside the original
  ownership list) to implement the RR-01 migration; the original list would
  have routed those as directives. `engineering.toml`'s `cargo-lock` digest
  was likewise updated mechanically to match the mandated lock regeneration.
- **D7 (tools/contract/) — receipt package manifest.**
  `tests/release/test_engineering_policy.py::test_reference_package_matches_manifest`
  intermittently reports "reference package drifted" for the untracked
  in-flight `tools/contract/` package (build_examples.py, build_schemas.py,
  record_checks.py, test_validate_contract.py, validate_contract.py vs
  PACKAGE-MANIFEST.json). That package and its test are untracked work of the
  concurrent common-standard worker (never edited here); regenerate
  PACKAGE-MANIFEST.json after the package files settle. Observed resolving
  itself as that worker landed changes (11/11 green on re-check).

## Document errors found (with proof)

1. **Stale: "Rust is pinned to 1.99.0"** (RR-01, "Existing commands" note).
   `rust-toolchain.toml` contains `channel = "1.99.1"` at HEAD (changed by
   commit a5f346a after the audit). True at 589b89f.
2. **Stale: N10 "gui.rs has 5,385 lines with tests starting 2,657".** Exact
   for the audited SHA (`git show 589b89f:src/gui.rs` = 5,385 lines,
   `mod tests` at 2,657); at HEAD gui.rs is 5,379 lines with `mod tests` at
   2,663 (eframe 0.37 upgrade). The other three module measurements
   (engine/worker/store) remain exact at HEAD.
3. **Partially stale: N11 "Its ref-scoped concurrency groups use
   cancel-in-progress: false without a queue setting."** Still true for
   ci.yml and supply-chain.yml; but `mutation.yml` and
   `enterprise-deep-verification.yml` now use per-SHA concurrency groups
   with comments stating evidence runs must never be superseded — the
   document's blanket wording predates that remedy.
4. No factual errors were found in the RR code snapshots, quoted source
   lines, reproduction outputs (N03/N04 values reproduce exactly), the
   historical CI-RR-1/CI-RR-2 diagnoses (both match `git show 4d09e13`
   exactly), the runtime_log.rs delta claim (exact), or the 188/15 file
   counts (exact).

## Open items NOT defects (recorded for the closure ledger)

- RR-05 orchestration extraction remains a structural program (5.4).
- RR-02's grid/validation repair awaits D1/D2 (verified open).
- RR-04 advisory consolidation awaits D3 (verified open).
- RR-03 coverage-scope extension awaits D4 (verified open).
- Hosted claims (1,015-test nextest run, Actions/DeepSource statuses) were
  not re-fetchable from this environment; local evidence supersedes their
  test-count content at current HEAD.
