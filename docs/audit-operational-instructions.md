# Audit: PART III operational instructions vs. rejection-rejector (verified)

Audit date: 2026-10-28. Auditor: operational-instructions verifier (ownership:
`tools/`, `scripts/`, `.github/workflows/`, `tests/release/`, `windows/`).
Source of truth: working tree at `C:/Users/strat/projects/rr/canonical`
(HEAD `e1c0485`, two commits past the manual's audit SHA `589b89fceac5`).
Manual audited: `strmt7-enterprise-engineering-implementation-manual-2026-10-27.pdf`
(Revision 2), read in full (4,216 extracted lines); Part III sections
"Python, evaluation and desktop-controller execution", "Native and scanner
execution", "Platform acceptance cases and exact command entry points", and
"Proposed policy and execution receipt validator: complete guide", plus the
R11 action page and the RR evidence appendices.

**Concurrency caveat (verified, not hypothetical):** sibling workers were
actively editing this checkout during the audit (`src/evaluation.rs` mid-edit
broke compilation twice, `training/calibrate_zero_fp.py` was rewritten
mid-audit, `tools/local_ci.py` gained ruff lanes). Every command below records
which tree state it ran against. A transient rustc OOM crash under that
parallel load is recorded as environment interference, not a repo defect.

Verdict vocabulary: **verified** (claim true at current tree), **stale** (true
at the manual's snapshot, superseded since), **false** (contradicted by
evidence), **not-applicable** (section does not cover RR), **in-flight**
(being remediated by a concurrent worker in uncommitted changes).

---

## 1. Command entry points (run against the repo)

| # | Command (as documented) | Verdict | Evidence |
|---|---|---|---|
| 1 | `cargo test --locked --all-features` (R11 EXISTING) | **working, one load-flaky test** | Full run against `a5f346a`+tree: exit 101, `916 passed; 1 failed` — `worker::orchestration_tests::a_panicking_worker_latches_the_fail_closed_state_and_journals_the_crash` panicked at `src/worker.rs:4176` ("worker did not publish the crash state"). Re-run isolated (`-- --exact`): `1 passed ... finished in 0.31s`. Flaky under parallel load (sibling builds saturate this host), not a deterministic regression; the test lives in `src/` (not my ownership) — flagged to the src owner. Entry point itself compiles, runs and reports correctly. |
| 2 | `python -m unittest discover -s tests/release -v` (R11 EXISTING) | **working** | `Ran 173 tests in 7.159s / OK` at tree start (matches the manual's historical "173 tests" count exactly); `Ran 223 tests / OK` after this audit's additions (21) and a sibling's (29). |
| 3 | `cargo deny check advisories licenses bans sources` (R11 EXISTING) | **working** | `advisories ok, bans ok, licenses ok, sources ok`, exit 0 (post-fix re-run: `advisories ok`). Also surfaced `warning[advisory-not-detected]` for the bare `RUSTSEC-2023-0086` ignore → drove the RR-04/D3a disposition below. |
| 4 | `cargo fmt --all -- --check` (Part III EXISTING) | **working** | Exit 0 (`FMT_OK`). |
| 5 | `cargo clippy --locked --all-targets --all-features -- -D warnings` (Part III EXISTING) | **working** | `Finished dev profile ... in 6.91s`, exit 0. |
| 6 | `cargo nextest run --locked --all-features --no-fail-fast` (Part III EXISTING) | **working** | First three attempts died in the *compile* stage from rustc resource crashes under sibling build load (`STATUS_STACK_BUFFER_OVERRUN`; an allocation-failure backtrace inside rustc; `can't find crate` cascades after a crashed rustc left partial rlibs) — environmental, not source. Retried with `CARGO_BUILD_JOBS=2`: **exit 0, `Summary [418.400s] 1058 tests run: 1058 passed (18 slow), 0 skipped`**. Command shape also verified at `.github/workflows/enterprise-deep-verification.yml:75` with pinned `cargo-nextest@0.9.146` (local binary 0.9.148 — minor drift, recorded). |
| 7 | `cargo audit --deny warnings --ignore …` (local_ci gate) | **working** | Exit 0 against the full 1,380-advisory DB (650 locked crates) with the four documented ignores (SECURITY.md/deny.toml triage), and also with the 2023-0086 ignore omitted (staleness proof for D3a). |
| 8 | `python tools/local_ci.py` (repo CI gate) | **working** | See §6 gate receipts. |

Validator-guide entry points (against the reference package the manual calls
"proposed", now vendored at `tools/contract/` by a sibling worker):

| Command | Documented expectation | Observed | Verdict |
|---|---|---|---|
| `python -B -m unittest -v test_validate_contract` | 48 tests pass | `Ran 48 tests in 1.228s / OK` | **verified** |
| `validate_contract.py … receipt-consistent-synthetic.json` | consistency PASS but final **BLOCKED**, exit **2** | exit 2 | **verified** |
| `… receipt-false-pass-synthetic.json` | **FAIL**, exit **1** | exit 1 | **verified** |
| `… receipt-blocked-synthetic.json` | **BLOCKED**, exit **2** | exit 2 | **verified** |

Entry-point totals (RR scope): 8 repo entry points + 4 validator-guide
invocations = 12 tried; 12 working as documented (nextest required
`CARGO_BUILD_JOBS=2` only because sibling builds were saturating this host),
0 broken.

## 2. Claim-by-claim verdicts (Part III → RR)

### "Native and scanner execution" (RR section)

| Claim | Verdict | Evidence |
|---|---|---|
| "Rust is pinned to 1.99.0" | **stale** | `rust-toolchain.toml` now pins `1.99.1` (bump commit `a5f346a`); workflows pass `toolchain: 1.99.1`. |
| "nextest is separately installed at its reviewed workflow version" | **verified** | `enterprise-deep-verification.yml` installs `cargo-nextest@0.9.146` via `taiki-e/install-action` with `checksum: true`. |
| "ten live binary tests now use a synthetic-input wrapper" (RR-01) | **verified** | `temp_env::with_var` wrapper at `src/bin/rr.rs:1813`; `temp-env = "0.3"` in Cargo.toml, resolved `0.3.6` in Cargo.lock (matches the manual). |
| RR-01 refinement: wrapper "changes process-global environment on Linux… a setter mutex does not coordinate every environment reader" | **verified (design concern stands)** | Wrapper unchanged; Rust `set_var` safety contract cited by the manual is correctly applied. No race reproduced here. |
| N03: 0.001 grid misses feasible optimum ("selects 0.501, TP 0, recall 0"; "0.50015 yields TP 1/FP 0") | **verified — reproduced** | Against committed `training/calibrate_zero_fp.py` (`git show HEAD:`): `calibrate([rejection 0.5001, ham 0.5002], 0)` → `threshold 0.501, tp 0, fp 0, recall 0.0`. Being rewritten concurrently ("the optimum over feasible thresholds is exact" in the uncommitted training diff) → remediation in-flight (training/ is another worker's). |
| N04: score 2.0 → "threshold 1.01 and FP zero, although applying that threshold yields one false positive" | **verified — reproduced** | `calibrate([ham 2.0, rejection 0.9], 0)` → `threshold 1.01, reported_fp 0, fp_if_applied 1`. |
| N04: NaN negative accepted, "threshold zero and recall one" | **verified — reproduced** | `calibrate([ham NaN, rejection 0.9], 0)` → `threshold 0.0, reported_fp 0, recall 1.0`. |
| N04: "treats any label other than rejection as negative"; booleans accepted; negative budget not rejected (at audit SHA) | **verified (source read)** | Committed `calibrate`/`load_scores` show `is_positive = label == "rejection"`, no type/finiteness checks; the uncommitted rewrite adds exactly these validations (in-flight). |
| RR-03: "release-tooling syntax check covers only selected files" | **verified** | `release-tooling.yml:32`: `python -m py_compile tools/resource_guard.py training/train_lora.py` only. |
| RR-03: "Rust coverage measures Rust and scripts/, leaving training/ and tools/ outside that explicit Python coverage scope" | **verified** | `coverage.yml:79`: `python3 -m coverage run --source=scripts -m unittest discover -s tests/release`. |
| RR-03: "calibration … has no matching tests in the tracked test tree" | **stale / in-flight** | True at HEAD commit; sibling worker added untracked `training/tests/`. |
| N05: duplicate cargo-audit executions with different reproducibility (unversioned `cargo install cargo-audit --locked` + pinned `cargo-audit@0.22.2`, same four ignores) | **verified → FIXED** | Both existed in `supply-chain.yml` at HEAD. Consolidated (§3). |
| N05: "The older job also installs the rust-toolchain action with its default stable input" | **verified → FIXED** | Advisories job had no `toolchain:` input; now pinned to `1.99.1`. |
| N05: bare `RUSTSEC-2023-0086` ignore, "verify whether this exception is still required before deleting it" | **verified → FIXED (structured record)** | Proven stale: `cargo deny check advisories` reported `advisory-not-detected … no crate matched advisory criteria`; `cargo audit` passes without the ignore; `lexical-core`/`imap` 2 absent from `Cargo.lock` (SECURITY.md's own removal criterion — the io-imap migration — is met). Final disposition per coordinator directive D3a: converted to a `{ id = …, reason = … }` entry carrying SECURITY.md's rationale, the staleness evidence and the 2027-04-28 review/removal date (kept as a dated record rather than deleted; the `advisory-not-detected` warning keeps it visible for the review). |
| N05: stale yoke-derive rationale ("keep 0.8.2 pinned" while `yoke-derive = "0.8.4"`) | **verified — NOT fixed (out of ownership)** | `Cargo.toml:75` declares `"0.8.4"` (compatible range); the `cargo-machete` rationale at `Cargo.toml:88-90` still says "Keep 0.8.2 pinned". Cargo.toml is outside this auditor's file ownership — flagged to the manifest owner. |
| RR-06: "ref-scoped concurrency groups use cancel-in-progress: false without a queue setting… The comment is an intention, not a guarantee of complete per-commit evidence" | **verified → FIXED** | See §4. |
| RR-05 sizes: engine.rs 6,786 (tests @2,634); worker.rs 6,476 (@2,998); store.rs 4,705 (@2,554); gui.rs 5,385 (@2,657) | **verified except gui.rs (stale by 6 lines)** | `wc -l`: 6786/6476/4705/5379; `mod tests` at 2634/2998/2554/2663. gui.rs shifted after the eframe 0.37 bump. |
| R11 "Preserve: … attestation and reproducibility workflows" | **verified** | `release.yml` runs `verify_package.py` twice + provenance/SBOM attestation verification (pinned by `tests/release/test_release_routing.py`); `reproducibility.yml` does the two-build `if ($hashA -ne $hashB)` comparison. |
| "188 tracked files … 15 workflows" (inventory) | **workflows verified (15); file count stale** | `.github/workflows/` has exactly 15 tracked YAMLs; `git ls-files` now 195. |
| "1,015 tests, zero skipped" (hosted nextest at `589b89f`) | **not re-verifiable locally** | Hosted-run claim; local equivalent is entry #1/#6 above. Historical CI-RR-1/CI-RR-2 fixture failures are correctly retired by the manual (source-remediated). |

### "Python, evaluation and desktop-controller execution" (~p38-50)
**not-applicable to RR** (covers TF/MPL/SAT/SJS/AISC only). The only RR-relevant
strand is the shared receipt contract ("retain a receipt containing the code
commit… command, runtime/tool versions, lock digest, platform/backend, input
identities, exit status, executed/skipped test counts and coverage scope") —
implemented as a validation utility in §5.

### "Platform acceptance cases and exact command entry points" (~p61-67)
**not-applicable to RR** (covers OMERO/QFALES/IMARIS-UI/AIR-DEFENSE). RR's
acceptance cases live on the R11 page and in the Native section; all listed
RR commands are verified in §1.

### "Proposed policy and execution receipt validator: complete guide" (~p67-72)
All four runnable claims verified against the vendored package (§1 table):
48-test suite, exit-2 consistent/synthetic, exit-1 false-pass, exit-2 blocked.
Design review in §5.

## 3. RR-04 advisory policy — findings and fixes

Inventory of advisory/audit executions before the fix:
1. `supply-chain.yml` `advisories` job — `cargo install cargo-audit --locked`
   (**floating tool version**), audit with 4 ignores, toolchain = dtolnay
   default-stable.
2. `supply-chain.yml` `rust-policy` job — pinned `cargo-audit@0.22.2`
   (checksummed), same audit, same 4 ignores, toolchain 1.99.1.
3. `cargo deny check advisories` in `rust-policy` — second tool over the same
   RustSec DB (legitimate separate tool/database pair with structured records).
4. `tools/local_ci.py` local mirror (operator gate, not a workflow run).
5. `osv-scanner.toml` — a *documented* ignore record (reasons + `ignoreUntil`
   2027-04-01) but **no workflow runs osv-scanner**; the "Advisories
   (RUSTSEC/OSV)" job name overstates its data sources (recorded, not fixed:
   job renaming is a required-check identity decision for the owner).

Suppression-record audit (S07: reason, owner, review/removal criterion):
- `deny.toml`: bare `"RUSTSEC-2023-0086"` (**no reason at all**) + three
  structured entries with reasons but **no owner/review date** → fixed.
- Enforcement of *new* advisories: already fail-closed and re-verified:
  `cargo audit --deny warnings` (any new warning fails the job) and
  `cargo deny check advisories` with `yanked = "deny"` both exit nonzero on
  unsuppressed findings; the deny run also self-reports dead ignores
  (`advisory-not-detected`), which is how the stale entry was caught.

Fixes applied (all inside this auditor's ownership except deny.toml, which the
coordinator's RR-04/D3a directives explicitly assigned):
- `supply-chain.yml`: the `advisories` job is now the **single authoritative
  pinned audit** (`cargo-audit@0.22.2`, `checksum: true`, `fallback: none`,
  toolchain `1.99.1`, `timeout-minutes: 15` — D3c); the duplicate "RustSec
  audit" step was removed from `rust-policy` (which keeps `cargo deny check
  advisories licenses bans sources`, machete, SBOM as the second tool's policy
  check). Both job names still report, so no required-status identity changes.
- `RUSTSEC-2023-0086` converted from a bare entry to a structured
  `{ id = …, reason = … }` record (D3a) after the staleness proof; the reason
  carries SECURITY.md's lexical-core/imap-2 rationale, the 2026-10-28 review
  finding (removal criterion met) and the 2027-04-28 removal decision point.
  The `--ignore` flags in `supply-chain.yml` and `tools/local_ci.py` were
  restored so all three ignore sets match the documented triage record.
- `deny.toml`: each ignore now carries owner `strmt7` and a review date in its
  reason, plus a comment block recording the S07 suppression-record policy.

## 4. RR-06 evidence retention — findings and fixes

Mechanism verified: GitHub concurrency keeps 1 running + 1 pending slot **per
group**; with a ref-scoped group and `cancel-in-progress: false` a newer push
replaces an older *pending* run (documented GitHub semantics, cited by the
manual). `scripts/release_guard.py` requires EXACT workflows to have a green
run **at the exact release commit** (`head_sha == commit`), so per-commit run
retention is load-bearing evidence.

Before (all verified in file):
- `ci.yml` `rust-ci-${{ github.ref }}`, cancel false — yet its comment claims
  "each commit as an auditable evidence point" → burst pushes drop older
  pending runs. Same pattern in `semver.yml` ("exact-commit SemVer evidence")
  and `supply-chain.yml` ("every main commit").
- `reproducibility.yml` `windows-reproducibility-main`, **cancel true** →
  every newer push actively cancelled older *running* two-build evidence runs.
- `codeql.yml`, `repository-integrity.yml`, `scorecard.yml`,
  `workflow-lint.yml`: ref-scoped groups with cancel true → same loss mode.
- Already correct (no change): `coverage.yml`, `enterprise-deep-verification.yml`,
  `fuzz.yml`, `mutation.yml` (per-SHA groups, cancel false); `release-tooling.yml`
  (no concurrency block — nothing ever replaces a run); `release.yml` (single
  fixed group `attested-windows-package` — deliberate serialization of manual
  release runs, kept); `dependency-review.yml` (PR-only; superseding PR runs is
  explicitly allowed by S04).

Fix applied (behavior change, exact; satisfies coordinator directives D6):
- **Independent run identities** (the manual's S04 option): push/schedule/
  workflow_dispatch runs now group by `github.sha`, so every pushed commit has
  its own 1-running+1-pending budget and no cross-commit replacement or
  cancellation is possible.
  - `ci.yml`, `codeql.yml`, `repository-integrity.yml` (which also run on
    `pull_request`): `group: …-${{ github.event_name == 'pull_request' &&
    github.ref || github.sha }}` — PR runs keep ref-group superseding
    semantics; non-PR runs are per-SHA.
  - `semver.yml`, `supply-chain.yml`, `scorecard.yml`, `workflow-lint.yml`,
    `reproducibility.yml`: `group: …-${{ github.sha }}`.
  - `reproducibility.yml` additionally changed `cancel-in-progress: true` →
    `false` (same-SHA reruns now queue instead of cancelling evidence).
- All 16 workflow YAMLs re-validated to parse after editing.
- Result: a three-commit burst now retains a completed evidence run for every
  commit in every release_guard EXACT/DEEP workflow; no bounded-queue
  reconciliation job is needed because no replacement occurs.

## 5. Execution receipt validator — decision: **ADAPT** (adopt the core design, repo-scope it)

**Critical review of the proposal (and of its vendored implementation at
`tools/contract/`):**

Sound? Yes, for what it claims. It validates *internal consistency* of an S15
receipt (identity, gate/command/exit agreement, count arithmetic, timestamp
ordering, evidence byte hashes, exception hygiene, fail>blocked>pass
precedence) and explicitly disclaims authentication ("A local PASS does not
authenticate the producer"). The vendored reference behaves exactly as
documented (48 tests; example exit codes 2/1/2 — all re-run and verified).

Secure? The trust model is honest but weak in one direction: a fabricated but
internally consistent receipt **passes** — the design says so, and no local
check can fix that (authenticity must come from hosted evidence such as
`scripts/release_guard.py`). Credential leakage: the reference never executes
receipt content and hashes files read-only; my adaptation additionally pins
(and tests) that findings never echo receipt values, so an accidentally
embedded secret cannot leak through validator output. Path containment,
duplicate-key rejection, nonfinite rejection, and a 2 MiB input cap are sound
defenses and are retained.

Genuinely useful for this repo? Yes. The repo validates hosted runs
(`scripts/release_guard.py`), package bytes (`scripts/verify_package.py`) and
repo integrity (`scripts/repository_integrity.py`), but nothing validated a
local gate/CI **execution receipt** — the S15 closure record the manual's R11
completion contract requires. The reference's portfolio machinery (13-repo
PREFIXES table, S01–S15×6-task closure, policy/receipt SHA pairing,
multi-receipt limits) is over-general and brittle for a single repository, and
the closed JSON-Schema-subset engine repeats the maintenance trap the manual
itself flags for AISC-06.

**Decision: adapt.** Implemented `tools/validate_receipt.py` (stdlib only,
read-only, reuses `tools/json_input.decode_json` for strict decoding) with the
repo's actual gate vocabulary (`fmt`, `clippy`, `cargo-audit`, `cargo-deny`,
`cargo-test`, `release-suites` — mirroring `tools/local_ci.py` and the
workflows), per-gate command/exit/status agreement, test-family arithmetic +
zero-test detection, artifact SHA-256 binding under a contained evidence root,
timestamp ordering/skew, exception hygiene (expired exceptions fail; valid
exceptions **never** upgrade a FAIL/BLOCKED), and independent result
computation cross-checked against the producer label. CLI contract: exit
0/1/2 = PASS/FAIL/BLOCKED, JSON verdict on stdout. Tests:
`tests/release/test_validate_receipt.py` — 21 cases (positive controls,
false-pass, exit/status contradiction, missing/unknown/duplicate gates, count
and zero-test failures, future/naive/disordered timestamps, path escape,
digest mismatch, duplicate paths, expired exception, exception-cannot-rescue,
duplicate JSON keys, oversize input, no-value-echo, CLI exit codes).

## 6. Fixes applied (files)

1. `.github/workflows/supply-chain.yml` — RR-04/D3c: one pinned authoritative
   `cargo-audit@0.22.2` (checksummed) on toolchain 1.99.1 with
   `timeout-minutes: 15`; duplicate audit step removed from `rust-policy`;
   S07 suppression record (owner + review dates) in comments. RR-06: per-SHA
   concurrency group.
2. `deny.toml` — bare `RUSTSEC-2023-0086` entry converted to structured
   `{ id, reason }` form (D3a) with SECURITY.md rationale, staleness evidence
   and the 2027-04-28 review/removal date; owner + review date added to all
   ignore reasons.
3. `tools/local_ci.py` — ignore list aligned with the documented triage record
   (four entries, comment carries owner/review/removal criterion).
4. `.github/workflows/ci.yml` — event-aware per-SHA concurrency group (D6);
   new stable aggregate `verify` job (D5): `needs: [test]`, `if: always()`,
   fails on failure/cancelled/skip/missing; workflow starts it on every
   required event (no path filters).
5. `.github/workflows/semver.yml` — per-SHA group.
6. `.github/workflows/reproducibility.yml` — per-SHA group, `cancel-in-progress`
   true→false (evidence destruction fix).
7. `.github/workflows/codeql.yml` — event-aware per-SHA group.
8. `.github/workflows/repository-integrity.yml` — event-aware per-SHA group.
9. `.github/workflows/scorecard.yml` — per-SHA group.
10. `.github/workflows/workflow-lint.yml` — per-SHA group.
11. `.github/workflows/coverage.yml` — stale step label "Rust 1.99.0" → "1.99.1"
    (D7a); Python coverage scope extended from `scripts` to
    `scripts,tools,training` with tests omitted and the measured scope
    documented (D4).
12. `.github/workflows/release-tooling.yml` — syntax gate extended from two
    hardcoded files to the full operator surface (`python -m compileall -q
    tools scripts training`, exit 1 on any syntax error) (D4).
13. `tools/validate_receipt.py` — new: adapted execution-receipt validator.
14. `tests/release/test_validate_receipt.py` — new: 21 tests.

Not fixed (outside ownership, flagged): `Cargo.toml` stale yoke-derive
machete rationale ("keep 0.8.2 pinned" vs `yoke-derive = "0.8.4"`); the
load-flaky `worker::orchestration_tests::a_panicking_worker…` test in `src/`;
`osv-scanner.toml` triage is documented but no workflow invokes osv-scanner
(job-name/repo-policy decision for the owner).

## 7. Gate receipts (final)

- `python tools/local_ci.py`: **ALL GATES GREEN, exit 0** (final run
  2026-10-28): fmt GREEN; clippy (exact CI flags) GREEN; `cargo audit` GREEN
  with the four documented ignores; rustdoc `-D warnings` GREEN; `cargo test
  --locked` GREEN (full suite — the earlier `worker`/`tui` deadline flakes did
  not recur once sibling builds stopped saturating the host; the four
  `tui::tests::draw_*` flakes were also re-run green in isolation: `11 passed,
  0.73s`); python release suites GREEN (`Ran 230 tests … OK`, including the 21
  new validator tests). The sibling-owned ruff lanes remain advisory (xfail)
  by their design and do not flip the gate.
- `python -m unittest discover -s tests/release -p test_*.py`: `Ran 230 tests
  … OK` (standalone re-run after all edits).
- Workflow YAML: all 16 files parse after edits (PyYAML safe_load); the pinned
  strings asserted by `tests/release/test_release_routing.py` and
  `test_release_guard.py` remain intact (`27 tests OK` in that focused run).
- `cargo nextest run --locked --all-features --no-fail-fast` (final):
  `Summary [418.400s] 1058 tests run: 1058 passed (18 slow), 0 skipped`.
