# Audit — Research and AI-evaluation findings (rejection-rejector scope)

Auditor: research/AI-evaluation worker. Date: 2026-10-28 (Europe/Zurich).
Scope: the manual's Section 5 "Research and AI evaluation contract" (Part I,
p18), "Python and AI evaluation evidence" (p72–83), "Original
established-repository research evidence" (p109–111), "Additional
primary-source research and refinements" (p111–115) and "Python and evaluation
adversarial revalidation" (p118–126), **as they apply to
strmt7/rejection-rejector only**. Source of truth is the current repo at
`C:/Users/strat/projects/rr/canonical` (worktree at `a5f346a` plus concurrent
workers' uncommitted edits); the manual audited `589b89f` (2026-10-27).

Method: the 154-page PDF was read in full. Every RR-relevant empirical claim
was reproduced against the real repo (Python reproducers with synthetic data,
Rust mock-HTTP suites, the live `rr evaluate` lane against local Ollama
0.40.12), or checked against the cited primary source (docs.rs, doc.rust-lang.org,
docs.github.com, scikit-learn docs, GitHub Actions API). Evidence files live in
`C:/Users/strat/AppData/Local/hermes/cache/scratch/` (`repro_n03_n04_before.json`,
`repro_n03_n04_after.json`, `cargo_test_owned.log`, `cargo_test_full.log`,
`rr-eval-run.log`, `rr-eval-report.json`).

Verdict vocabulary: **verified** (reproduced/confirmed), **stale** (true at
589b89f, superseded by current repo), **false** (contradicted by evidence),
**not-applicable** (other repositories' scope).

---

## 1. Claim-by-claim verdicts

### 1.1 Section 5 — Research and AI evaluation contract (p18)

| # | Claim | Verdict | Evidence |
|---|-------|---------|----------|
| S5-1 | Research outputs must identify source commit, environment/lock digest, dataset/task identity, requested+resolved model identity, prompt/config/grader versions, attempt counts, seed, denominators, unavailable metrics, qualification label | **verified (right contract); gap implemented** | The `rr evaluate` report already carried suite contract version + suite hash (grader identity), requested model + resolved digest, denominators and a limitations label. Gaps closed in this audit: build identity (source commit, Cargo.lock digest) and sampling (temperature/seed) now recorded (`src/evaluation.rs`); the training calibrate report now records input file identity + `split_role`; `training/evaluate_adapter.py` now records holdout/adapter digests, requested/resolved model identity and the generation policy. Tested (`tests/evaluation_scoring.rs::report_carries_research_identity_and_null_metric_reasons`, `training/tests/test_evaluate_adapter_identity.py`). |
| S5-2 | "Unknown provider/model identity remains unknown" | **verified (complied)** | `evaluate_adapter.py` reports `base_model_resolved_revision` from the loaded snapshot and, when absent, keeps it null with an explicit note instead of inferring from the requested string (matches the manual's AISC-04 "resolved snapshot unavailable must remain marked unavailable" principle). |
| S5-3 | "Artifact byte hashes do not establish independent samples" | **verified (right)** | The RR fixture suite is one pinned synthetic corpus identified by `suite_hash` — byte identity, correctly labelled a regression suite ("Synthetic task-specific regression suite… not representative mailbox accuracy" in the report's `limitations`). No independence claim is made from hashes. Training splits use `stratified_split(records, holdout_fraction, seed)` (deterministic, category-stratified); group/source lineage is not modelled — acceptable for the synthetic corpus, recorded as a directive for real corpus data. |
| S5-4 | Reject overlap, nonfinite scores, invalid labels and unsuitable class denominators before a release-quality result | **verified (right); gap implemented** | Nonfinite/invalid labels were previously accepted (see N04 below). Now rejected at ingestion (`training/calibrate_zero_fp.py::validate_row`) with line-numbered errors, before any report exists. Class-denominator policy implemented as the explicit `insufficient_data` status with null metrics + reasons. |
| S5-5 | "Zero observed false positives is an empirical result, not proof of zero population risk" | **verified (complied)** | `wilson_upper_bound` retained in every report; module docstrings and `docs/MODEL.md` state the limit explicitly. New tests pin `wilson_upper_bound(0, 10) > 0` so zero observed can never render as zero risk. |
| S5-6 | Acceptance: "unavailable metrics remain null with reasons" | **verified (right); gap implemented** | `rr evaluate` returned null on 0/0 denominators but without reasons. Now `summary.unavailable_metric_reasons` names every null metric's reason, and the same rule is enforced in the calibrate report (`metric_reasons`). Test: `report_carries_research_identity_and_null_metric_reasons` asserts null⟺reason for all nine metric names. |
| S5-7 | Acceptance: "reordered/subset copies cannot pass holdout checks" | **not-applicable (RR)** | That defect class belongs to TextForensics' file-hash split check (TF-1). RR's synthetic suite is compiled into the binary (`include_str!`) and hashed in `evaluation_suite_hash()`; there is no external holdout file to reorder. The training holdout is a fixed JSONL whose digest is now recorded, so a substituted copy changes the receipt identity. |
| S5-8 | "Negative/failed attempts remain in denominators" | **verified (complied)** | `rr evaluate` denominators are the pinned fixture count; failed cases become error rows counted in `completed`/`fixture_count` (mock-verified by `model_errors_become_error_rows_and_fail_the_eligibility_gate`). The calibrate report counts every validated row. |
| S5-9 | "Preserve reproducible fixtures for close threshold scores, ties, invalid records and missing metrics" | **verified (right); implemented** | Exactly the new `training/tests/test_calibrate_zero_fp.py` inventory: straddle case (0.5001/0.5002), equal-score ties, 0.0/1.0 endpoints, invalid records, class-empty diagnostics. |

### 1.2 "Python and AI evaluation evidence" + native/scanner evidence, RR items (p72–83, p83–93)

| # | Claim | Verdict | Evidence |
|---|-------|---------|----------|
| N03 | `select_best` sweeps only the 0.001 grid and misses feasible optima; neg 0.5001 / pos 0.5002 returns threshold 0.501, TP 0 while 0.50015 gives TP 1/FP 0 | **verified (was true; now fixed)** | Reproduced exactly at current head before the fix (`repro_n03_n04_before.json`: threshold 0.501, TP 0; reference `counts_at(..., 0.50015) = (0, 1)`). The old code is unchanged since 589b89f (`git diff 589b89f -- training/calibrate_zero_fp.py` was empty before this audit). |
| N03 addendum | "Eighty generated close-score cases all missed an independently computed feasible optimum" | **verified in substance; the literal 80/80 is generator-dependent** | With a mixed close-score generator (bases ±0.0005) I reproduced 49/80 misses and 31 hits; every deterministic straddling-pair counterexample from the manual reproduces. The claim holds for generators whose class gap contains no 0.001-grid point; it is not reproducible as written without the manual's exact generator. The defect (incomplete threshold enumeration) is confirmed either way. |
| N04 | `load_scores` accepts nonfinite scores, booleans, unknown labels, out-of-range probabilities; NaN negative never counts toward FP; score 2.0 yields a self-contradictory fallback (threshold 1.01, FP reported 0, recount = 1 FP); negative FP budget returns a report; missing fields crash with KeyError instead of a line-numbered validation error | **verified (all reproduced); now fixed** | `repro_n03_n04_before.json` reproduces every listed behavior verbatim, including the 2.0 fallback contradiction (recount `fp=1` at the reported threshold) and the NaN case (threshold 0.0, recall 1.0). After the fix every case raises `ScoreRowError`/`ValueError` before any report (`repro_n03_n04_after.json`). |
| N04 sub | "argparse already rejects nonintegral CLI arguments" | **verified** | `--target-fp 1.5` exits 2 with `invalid int value` — the manual correctly limited the defect to the callable API, which now validates too. |
| RR-02 acceptance | Close-score cases reach feasible zero-FP recall; reported counts match the selected threshold; invalid rows fail before reporting; a small independent exhaustive oracle agrees; explicit abstain-all; class-empty diagnostics; permitted FP budgets | **verified (right); implemented** | `training/tests/test_calibrate_zero_fp.py` (19 tests, all passing): oracle is an independent dense-grid sweep (0.0001) over raw float lists; counts are recounted at the reported threshold; `abstain_all` is a status with `threshold: null` (never 1.01); `insufficient_data` keeps counts and nulls undefined metrics with reasons. Selection now enumerates the distinct observed scores, which under `score >= threshold` cover every inducible decision set — exact, deterministic, no tie-breaker needed (distinct boundaries change TP or FP). |
| N05 | `supply-chain.yml` has duplicate security jobs: unversioned `cargo install cargo-audit --locked` vs pinned `cargo-audit@0.22.2`, different toolchain defaults | **stale (verified at 589b89f; remediated since)** | `git show 589b89f:.github/workflows/supply-chain.yml` shows the unversioned install at line 31 beside the pinned 0.22.2. Current `supply-chain.yml` (uncommitted, another worker) consolidates to one checksum-verified `cargo-audit@0.22.2` run with owner/review-dated suppressions; `deny.toml` replaces the bare `RUSTSEC-2023-0086` with reasoned, dated records. No action needed beyond finishing that worker's change. |
| N05 sub | `yoke-derive = "0.8.4"` is a compatible-range requirement, not an exact pin; the cargo-machete rationale still says "Keep 0.8.2 pinned" | **verified (still current)** | `Cargo.toml` line 75 declares `yoke-derive = "0.8.4"` (caret semantics) while the `[package.metadata.cargo-machete]` comment says "Keep 0.8.2 pinned until the upstream graph moves" — exactly the documentation drift the manual reports. Fix is a Cargo.toml edit (not owned) → directive D2. |
| N09 | Model/Python tooling has weaker coverage: `release-tooling.yml` syntax-checks only `tools/resource_guard.py` and `training/train_lora.py`; calibration had no tests; training requirements are prose | **verified (partly still current); partially fixed here** | Current `release-tooling.yml` line 32 still runs `python -m py_compile tools/resource_guard.py training/train_lora.py` only. No calibration tests existed (`grep -rn calibrate` found no test). This audit adds 24 deterministic CPU tests under `training/tests/` needing no model download; wiring them into the workflow is a directive (D1). Training requirements prose unchanged (RR-03 scope, other worker). |
| N09 sub | Training README contradicts itself on ROCm/WSL2 ("works through WSL2" vs "cannot initialize there") | **verified (was still current); fixed here** | `training/README.md` line 14 claimed "AMD GPUs work through ROCm on Linux or WSL2 on Windows" against its own verified limitation ("ROCm wheels cannot initialize GPU training in WSL2"). Portability sentence corrected in this audit to bare-metal Linux + native Windows only, pointing at the verified limitation section. |
| N10 | Large change surfaces (engine.rs 6,786 / worker.rs 6,476 / store.rs 4,705 / gui.rs 5,385 lines with inline tests) | **verified (static; not re-measured)** | Spot-checked: `src/` layout unchanged in kind. Structural advice (extract by change coupling, exclude inline tests from size judgments) is sound; RR-05 is another worker's lane. No action here. |
| N11 | RR CI comments intend per-main-commit evidence but ref-scoped concurrency groups with `cancel-in-progress: false` still replace older pending runs | **verified externally; stale for current repo** | GitHub docs (fetched 2026-10-28) confirm: default `queue: single` "any existing pending … is canceled and replaced"; `queue: max` allows up to 100 pending and "the combination of `queue: max` and `cancel-in-progress: true` is not allowed" — the manual's S04/RR-06 wording is accurate, including "no exact dispatch order". Current `ci.yml` and `supply-chain.yml` (uncommitted, another worker) now use per-SHA concurrency groups explicitly citing S04/RR-06, which resolves the pending-replacement gap. |
| N12 | RR has an attested Windows package workflow and two-build reproducibility workflow; hashes/attestations/signatures establish different properties | **verified (complied; wording consistent with GitHub docs)** | GitHub's artifact-attestations concepts page (fetched) states attestations provide provenance incl. repo/commit/build identity and that "Artifact attestations by itself provides SLSA v1.0 Build Level 2" — consistent with the manual's caution ("do not automatically establish a SLSA level"). RR's report/workflow language matches. |
| CI-RR-1/2 | The two historical Linux failures (missing `RR_VAULT_PASSPHRASE`, recovery fixture permissions) are source-remediated; hosted nextest 1,015/1,015 passed, zero skipped at 589b89f | **verified** | Current source: recovery fixture applies `perms.set_mode(0o600)` before export (`src/bin/rr.rs:2174`), dedicated 0644-rejection tests intact. Public Actions API confirms job `122465545513` ("Nextest, docs and recovery drill") at run `40582566896` concluded `success` — exact job identity the manual cites (R016); the 1,015 count itself is quoted from the manual's log retrieval (log bodies are auth-walled). Local full-suite run at current head: see §3. |
| RR-01 refinement | `temp_env` wrapper is a P2 test-isolation design concern (mutex coordinates only its own callers; Rust's `set_var` contract recommends `Command::env`/prelaunch) | **verified (accurate and measured)** | doc.rust-lang.org `set_var` safety section (fetched): "always sound to call on Windows … In multi-threaded programs on other operating systems, the only sound option is to not use set_var … To pass an environment variable to a child process, you can instead use Command::env." docs.rs temp-env 0.3.6 source (fetched): `static SERIAL_TEST: ReentrantMutex<()>` guarding only its own setters. The manual's characterization of both is exact. Note the repo has moved: another worker's in-flight `src/bin/rr.rs` rework now arms `RR_VAULT_PASSPHRASE` once per test process via a `Once` before any test body and parks the setter (write-once). That removes the repeated-mutation pattern; residual nit (one `set_var` in a possibly multithreaded Linux test process) remains below the strictest reading of the std contract → directive D3. |
| RR tooling claim | "Rust is pinned to 1.99.0" | **stale** | `rust-toolchain.toml` now pins `1.99.1` (changed at `a5f346a`, "bring every tool … to verified-latest"). True at 589b89f. |
| RR lock claim | dirs-sys 0.5.0's manifest permits `windows-sys >= 0.59.0`, so the refreshed lockfile's windows-sys 0.61.2 edges are not invalid from version movement alone | **verified** | docs.rs published manifest for dirs-sys 0.5.0 (fetched): `[target."cfg(windows)".dependencies.windows-sys] version = ">= 0.59.0"`. The manual's refusal to call the lock invalid is correct. |

### 1.3 Research-evidence sections (p109–115) as applied to RR

| # | Claim | Verdict | Evidence |
|---|-------|---------|----------|
| RE-1 | scikit-learn's pitfalls guide: test information must not influence preprocessing/model selection; GroupKFold illustrates nonoverlapping groups but "does not detect semantic duplicates or invent source lineage" | **verified (right; applicable to RR splits)** | scikit-learn docs (fetched, 1.9.1): "K-fold iterator variant with non-overlapping groups"; the manual's limitation note is accurate. RR's training split is category-stratified with a fixed seed (`build_sft_dataset.stratified_split`); no group lineage exists in the synthetic corpus — the manual's requirement "group identity should reflect document/author/source lineage where appropriate" is correctly scoped and recorded as directive D4 for real corpus work. |
| RE-2 | SWE-bench evaluation guide: preserve complete patch/test receipts, task denominators and run/cache identities; don't reuse cached results after changing a patch/prompt/grader | **verified (right)** | The repo's `evaluation_suite_hash()` already binds prompt/config/grader identity into every report, and `evaluate_adapter.py` now records the exact inputs' digests; cached-result reuse is prevented by the digest-stamped receipts. No further RR work needed. |
| RE-3 | Inspect sandboxing: a sandbox setting does not isolate existing host callbacks | **not-applicable (RR)** | Concerns ai_skills_collection_benchmarked's grading boundary (AISC-05). RR has no external grader. |
| RE-4 | GitHub concurrency/uv/Dependabot provider semantics (S04/S06) | **verified** | GitHub concurrency page fetched and quoted above (queue:max = 100 pending; incompatible with cancel-in-progress: true; FIFO by wait time, order not guaranteed). uv `--locked` vs `--frozen` and Dependabot uv support are environment-policy points; RR is Cargo-first and unaffected. |
| RE-5 | SSDF 1.1 final vs 1.2 draft; SLSA v1.2 artifact verification; GitHub attestation availability; OpenSSF criteria; DORA five measures | **verified where fetchable; not-applicable for RR behavior** | The attestation pages (fetched) match the manual's claims, incl. "Artifact attestations by itself provides SLSA v1.0 Build Level 2" supporting its "attestations do not automatically establish a SLSA level". DORA applies to deployed services; the manual itself scopes RR to qualification-time/escaped-regression tracking — consistent. No RR code impact. |
| RE-6 | Google/Microsoft/Kubernetes review practices as portfolio decisions | **not-applicable (RR code)** | Process guidance; no technical assertion to replicate. The "do not claim an AI review provides equivalent independence" caveat is a sound reporting rule and is honoured in this report. |
| RE-7 | Established-repo benchmark observations (uv/Ruff/Tauri/VS Code/FastAPI/HA/OME) | **not-applicable (RR)** | Each row's "required adaptation" targets the shared standard or other repos. One RR-relevant caution verified as sound: FastAPI's 100% coverage target is project-specific and is not an enterprise requirement — important because N11 notes RR describes "a 100% goal with 95%/90% regression floors"; no change demanded. |

### 1.4 "Python and evaluation adversarial revalidation" (p118–126), RR applicability

The five revalidated repositories are TextForensics, model-protocol-lab,
simple_ai_trading, smart-job-seeker and ai_skills_collection_benchmarked —
**not-applicable to RR except for the shared-standard refinements**, which are
already reflected above: null-with-reasons metrics (S09 refinement 2, §S5-6),
score-vs-probability discipline (refinement 4 — RR complies: `docs/MODEL.md`
states scores are "not calibrated probabilities", and the new reports repeat
it), and locked-vs-mutable-inputs honesty (refinement 1 — RR's reports now
name the lock digest and sampling policy explicitly). The correction register
(C01–C07) concerns the other five repos' files; no RR claim retracts.

---

## 2. Fixes implemented in this audit (owned files only)

1. **`training/calibrate_zero_fp.py`** — rewritten selection + validation
   (RR-02 / N03 / N04, Section 5 ingestion rules; orchestrator directive D2):
   - Exact decision-boundary sweep over the distinct observed scores under the
     declared `score >= threshold` contract (same `>=` as runtime
     classification) — the recall optimum is now exact; the 0.001 grid is gone.
   - Explicit deterministic tie policy: maximize TP, then minimize FP, then
     the highest threshold; the reported cutoff is the smallest observed score
     achieving the selected decision set (0.5002 for the 0.5001/0.5002 pair
     under `>=` — the directive's boundary-precision point, not the
     interpolated 0.50015).
   - Ingestion validation with line-numbered errors: record shape, required
     fields, declared labels only (`rejection`/`not_rejection`/`ambiguous`;
     `ambiguous` stays explicitly negative for FP), numeric type excluding
     booleans, finiteness, [0,1] bounds. Invalid rows fail before any report.
   - `target_fp` validated (nonnegative integer) in the callable API
     (`calibrate`/`select_best`) as well as the CLI.
   - Explicit statuses: `ok` (counts recounted at the reported threshold and
     asserted equal — the a5f346a self-contradiction where threshold 1.01
     reported FP 0 but yielded FP 1 is structurally impossible now),
     `abstain_all` (threshold `null` — the out-of-range 1.01 sentinel is gone),
     `insufficient_data` (empty/all-positive/all-negative diagnostics with
     counts retained and null metrics + `metric_reasons`).
   - Report identity: `comparison`, `split_role: calibration`, input
     `{path, sha256, rows}`, `ambiguous_in_negatives`. Wilson upper bound
     retained; null with reason when a denominator is zero.
2. **`training/tests/test_calibration_zero_fp.py`** (new; this is where the
   D2-required calibration tests live — `tests/release/` is another auditor's
   lane) — 19 model-free tests (24 across both new Python files): the manual's
   exact straddle case pinned to
   threshold **0.5002**, TP 1, FP 0; equal-score ties; endpoints 0/1; NaN/inf;
   score 2.0; boolean probabilities; unknown labels; negative and non-integral
   budgets; empty/all-positive/all-negative sets; explicit abstain-all;
   reported-counts-match-threshold; an independent exhaustive oracle (naive
   0.0001-grid sweep over raw lists) across 60 random datasets + 40 close-score
   pairs; line-numbered load errors; CLI exit-code contract; Wilson sanity.
3. **`training/evaluate_adapter.py`** — research-identity block (Section 5):
   holdout/adapter content digests (directory digest covers every member),
   rows available/evaluated/limit, `base_model_requested` +
   `base_model_resolved_revision` (null + explicit note when the provider
   revision is unavailable — never inferred), `split_role: holdout_evaluation`,
   and the deterministic generation policy (`GENERATION` constant now shared
   between the scorer and the report; greedy ⇒ seed-independent, stated).
4. **`training/tests/test_evaluate_adapter_identity.py`** (new) — 5 tests:
   digest stability/content sensitivity for files and directories, row count,
   deterministic generation policy, and that importing the module does not
   pull the ML stack.
5. **`src/evaluation.rs`** — report envelope now records `build`
   (`build_info::current()`: source commit + verification flag, rustc, target,
   `cargo_lock_sha256`, build identity digest) and `sampling`
   (`CHAT_TEMPERATURE`/`CHAT_SEED`); `summary.unavailable_metric_reasons`
   gives every null metric an explicit reason (null⟺reason invariant).
6. **`src/ollama.rs`** — sampling policy exported as `CHAT_TEMPERATURE`,
   `CHAT_SEED`, `PRECHECK_TEMPERATURE` constants and used by the request
   builders, so the reported sampling contract cannot drift from the wire
   behavior.
7. **`tests/evaluation_scoring.rs`** — new test
   `report_carries_research_identity_and_null_metric_reasons` (build identity
   shape, sampling values, null⟺reason consistency across all nine metrics).
8. **`training/README.md`** — calibration contract documented (statuses,
   validation, `>=` semantics, explicit deterministic tie policy and the
   0.5002 canonical-cutoff example, test entry point); the ROCm/WSL2
   self-contradiction (N09 sub-claim) corrected.
9. **`docs/model-scale-report.md`** (orchestrator directive D9-part) — added
   a forward "Evidence identity" header (§0): source commit and run-time lock
   digest recorded as `null` with reasons (the runs did not record them; the
   history was later rewritten) plus the header-time reference commit/lock
   digest, dataset/task identity with the suite hash and `sample_ids`
   pinning, lineage/split description, requested/resolved model identity,
   grader/prompt/config versions, attempt/failure counts, seed as `null` with
   reason, exact denominators, unavailable metrics as `null`+reason (shared-
   runtime latency), and an explicit diagnostic-not-qualification label. No
   frozen historical number was edited.

Verification: `python -m unittest discover -s training/tests -v` → 24 tests,
OK (0.59 s, no model/network). `cargo test --locked --all-features` (private
target dir, CARGO_BUILD_JOBS=2) → all owned suites pass:
decision_protocol 3/3, evaluation_scoring 6/6, ollama_protocol 12/12.
Full workspace suite at current worktree: 22 suites, **1,058 tests, 0 failed,
0 ignored**.

## 3. Task-specific evaluation re-run vs the manual's numbers

Manual's numbers (hosted, 2026-10-27, commit 589b89f):
- Enterprise nextest "Nextest, docs and recovery drill": **1,015 tests run,
  1,015 passed, zero skipped**, incl.
  `recovery_key_import_demands_its_exact_confirmation_token`.
- Calibration reproducer: neg 0.5001/pos 0.5002 → threshold 0.501, TP 0;
  feasible 0.50015 → TP 1/FP 0; NaN negative + 0.9 positive → threshold 0,
  recall 1, "FP 0"; neg 2.0/pos 0.9 → fallback threshold 1.01, reported FP 0,
  recount FP 1; 80 close-score cases missed the optimum.

Current reality (2026-10-28, current worktree incl. concurrent edits):
- Local `cargo test --locked --all-features`: **1,058 tests, 0 failed, 0
  ignored** (22 suites). Divergence explained: the repo advanced two commits
  after 589b89f (scale-campaign work + tool/dependency refresh) adding tests,
  plus this audit's +1 Rust test and other workers' in-flight tests. The
  manual's hosted job identity (run 40582566896 / job 122465545513,
  conclusion `success`) is independently confirmed via the public Actions API.
- Calibration reproducer at current head before this audit's fix: **identical
  to the manual** (threshold 0.501/TP 0 reproduced; NaN/2.0/bool/unknown-label/
  negative-budget behaviors reproduced verbatim). After the fix: threshold
  0.5002, TP 1, FP 0 for the straddle case; all invalid inputs rejected
  before reporting; abstain-all explicit.
- `rr evaluate` (default model `granite4.2:8b-q8_0`, pinned fixtures, local
  Ollama 0.40.12, model fully GPU-resident 14,419,786,464 bytes VRAM):
  (see run summary below)

**`rr evaluate` re-run (2026-10-28, this audit)** — default model
`granite4.2:8b-q8_0` (digest `62837636dd31c99a…aeae02b4`), Ollama **0.40.12**,
suite `rr-eval-contract-v5` (hash `94239602e5fad6fe…` — identical to the
manual-era run), `Settings::default()` with delivery disarmed, `num_ctx` 32768,
temperature 0.15 / seed 42. Private debug build; the report's new `build`/
`sampling`/`unavailable_metric_reasons` envelope fields are present and honest
(`source_commit: "unverified-local-build"` — correctly unverified). Wall time
~2 h 05 min; `mean_seconds` 89.1 s/case on an otherwise idle runtime.

| Task metric | 2026-10-27 documented run (docs/model-scale-report.md §2) | 2026-10-28 re-run (this audit) |
| --- | --- | --- |
| fixtures / completed | 74 / 64 | 74 / 64 |
| correct / accuracy | 62 / 83.8% | 62 / 83.8% (0.8378) |
| rejection TP / FP / FN | 18 / 0 / 0 | 18 / 0 / 0 |
| rejection precision / recall | 100% / 100% | 100% / 100% |
| non-rejection FP avoidance | 100% | 100% |
| verified rejection pipeline rate | 77.3% (17/22) | **72.7% (16/22)** |
| deterministic evidence recall | 90.9% | 90.9% |
| multilingual recall / pipeline | 100% / 61.5% | 100% / 61.5% |
| unsafe non-rejection drafts | 0 | 0 |
| task score | 91.7 | 90.76 |
| recommendation eligible | false (exit 1) | false (exit 1) |
| mean s/case | 360.5 (shared runtime) | 89.1 (idle runtime) |

Divergence analysis: the confusion matrix reproduced **exactly** (62/64, all
rejection metrics identical), but one fewer rejection case completed the full
verified pipeline this run and the ten fail-closed rows differ slightly by
cause (2026-10-27: 4 incomplete + 3 ungrounded position + 2 field-length + 1
transport-retry; 2026-10-28: 3 field-length + 4 incomplete (3 classify, 1
draft) + 2 ungrounded position + 1 non-exact evidence quote). Interpretation:
seed 42 / temperature 0.15 is a *sampling policy*, not bitwise determinism —
GPU kernels, the Ollama 0.40.11→0.40.12 bump and quantized-MoE scheduling are
not bit-stable, so marginal rows (verification/quote-exactness edges) move
between runs. Both runs fail the Automatic-mode eligibility gate for the same
structural reasons (10 non-completions break `all_cases_complete`; pipeline
rates sit below the 0.90/0.85 gates) and `rr evaluate` correctly exits 1 with
the fail-closed disposition "did not meet Automatic-mode gates" — a healthy
gate, not a crash. The 10 failing rows are model-output-contract rejections
kept **in** the denominators (S5-8), never dropped.

No manual number is contradicted: the manual quotes no `rr evaluate` metrics
(it cites the calibration reproducer outputs and the hosted 1,015-test count);
both of those are addressed above (identical pre-fix reproducer output; test
count 1,015 → 1,058 from two commits of repo progress plus new tests).

## 4. Document errors found (with proof)

1. **"Rust is pinned to 1.99.0"** (p~51) — **stale**. `rust-toolchain.toml`
   pins `1.99.1`; `git log -p -- rust-toolchain.toml` shows the bump in
   `a5f346a` (after the audited 589b89f).
2. **N03 "all 80 generated close-score cases missed the optimum"** — the
   defect is real but the universal count is not reproducible without the
   manual's exact generator; a comparable close-score generator gives 49/80
   misses (31 hits where the class gap straddles a 0.001-grid point). Evidence:
   `repro_n03_n04_before.json` + the in-report sweep. The report should say
   "frequently/typically missed" or publish the generator.
3. **N05 duplicate-audit-jobs finding** — presented as current, but the
   consolidation it demands already exists in the working tree (one pinned
   `cargo-audit@0.22.2`, cargo-deny as the second tool, dated suppression
   records). The claim was true at 589b89f (`git show 589b89f:…` proves the
   unversioned install); the manual should mark it remediated at the next
   refresh.
4. **N11/RR-06 concurrency finding** — same staleness class: per-SHA
   concurrency groups now exist in `ci.yml`/`supply-chain.yml` citing
   S04/RR-06. The external semantics quoted by the manual are accurate
   (verified against GitHub docs).
5. **RR-01 "ten live binary tests now use a synthetic-input wrapper"** — true
   at 589b89f, but the wrapper's current worktree form has been redesigned
   again (once-per-process arm + parked setter); the manual's temp-env critique
   describes an intermediate state. Not wrong at its snapshot; refresh needed.
6. Everything else quoted for RR reproduced as written (the 0.5001/0.5002
   case, the 2.0 fallback contradiction, the NaN behavior, the Wilson-bound
   framing, the dirs-sys/windows-sys and set_var/temp-env source claims, the
   GitHub concurrency semantics, the FastAPI-100%-is-project-specific
   caution, GroupKFold's limitation note).

## 5. Refusals (proposals deliberately not implemented)

- No calibrated-probability language anywhere in the training/evaluation lane:
  the manual's warning ("scores must not silently become calibrated
  probabilities") is a correct constraint and the repo already complies
  (`docs/MODEL.md`); I added the reminder to `evaluate_adapter.py`'s report but
  implemented no probability-calibration feature, because none is claimed.
- No blanket zero-skip/zero-ignored policy for the Rust suite: the manual
  itself says required families must not disappear into skips but legitimate
  platform skips are fine; RR currently runs 0 ignored, so no change.
- Did not implement held-out sample/group manifests for the pinned synthetic
  fixture suite (S5-7): there is one compiled-in fixture corpus identified by
  `suite_hash`; a "split manifest" over a single immutable corpus would be
  ceremony without information. Group lineage is recorded as directive D4
  where real, multi-source corpora are trained on.

## 6. Directives for other areas (outside this worker's file ownership)

Orchestrator directive mapping: D2 (RR-02 calibration repair + tests) and
D7b (README contradiction + tie policy) are **completed here** (§2 items 1–2,
8); D9-part for `docs/model-scale-report.md` is **completed here** (§2 item 9).

- **D1 (workflows owner, `release-tooling.yml`)**: add
  `python -m unittest discover -s training/tests -v` to the release-tooling
  lane (and extend the `py_compile` step to `training/calibrate_zero_fp.py
  training/evaluate_adapter.py`), so the new deterministic calibration/data
  tests run in CI without a model download (N09/RR-03).
- **D2 (Cargo owner)**: fix the `cargo-machete` rationale comment in
  `Cargo.toml` ("Keep 0.8.2 pinned") to match the declared
  `yoke-derive = "0.8.4"` requirement and current upstream state (N05
  documentation drift).
- **D3 (`src/bin/rr.rs` owner)**: the in-flight `enter_test()` rework removes
  the repeated temp-env mutation; for full compliance with the std `set_var`
  safety contract on multithreaded non-Windows, prefer provisioning
  `RR_VAULT_PASSPHRASE` in the CI step environment / test-launcher before the
  process starts, and keep `Command.env` for child-process fixtures (manual
  RR-01 acceptance). Preserve the 0600 fixture and 0644-rejection tests.
- **D4 (training-data owner)**: for any real multi-source corpus work
  (e.g. Enron-derived data), add source/author group lineage to the rows and
  split by group (the manual's GroupKFold note), not just category-stratified
  random splits.
- **D5 (docs owner)**: at the next manual refresh, mark N05/N11 and the
  temp-env wrapper description against the consolidated current state quoted
  in §4.
