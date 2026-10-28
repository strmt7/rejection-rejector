# Common-standard verification and closure record (Part I + Part V)

Repository: **strmt7/rejection-rejector** (`C:/Users/strat/projects/rr/canonical`, branch `main`).
Source: *STRMT7 / Portfolio Engineering — Implementation standard and repository
playbooks*, Revision 2, 27 October 2026 (the 154-page manual), read in full.
Mandate: critically verify and implement the COMMON STANDARD (Part I sections
1-12) and the Part V traceability/closure requirements **as they apply to
rejection-rejector only**, against the actual repository, not the document.

Audit window: 2026-10-28 07:40-09:10 UTC. The repository advanced under
concurrent work during the audit: HEAD moved `568d979` -> `a5f346a` ->
`e1c0485`; several agents modified `src/`, `tests/`, `training/`,
`tools/local_ci.py` and `.github/` files concurrently. Every observation below
names the exact state it was taken against (committed HEAD via `git show`
where the worktree was dirty, otherwise the worktree). The manual's audited
snapshot for this repository is `589b89fceac51effa6922e210d4ee8a4033c9a32`
(five commits behind `568d979`, eight behind `e1c0485` at report time).

Verdict vocabulary: **verified** = claim true / requirement met, proved by the
cited evidence; **false** = claim wrong or requirement not met (real gap);
**stale** = accurate for the audited snapshot but no longer current; **n/a** =
does not apply to this repository.

---

## 1. Verdict summary

| Register | verified | false | stale | n/a | rows |
|---|---|---|---|---|---|
| A. S01-S15 compliance (Part I ch. 3) | 5 | 10 | 0 | 0 | 15 |
| B. Part I other sections (1,2,4-12) | 6 | 2 | 1 | 2 | 11 |
| C. Part V traceability/closure | 1 | 1 | 1 | 0 | 3 |
| D. External/tooling claims in the standard | 7 | 0 | 0 | 2 | 9 |
| E. Manual's RR-specific factual claims | 13 | 0 | 3 | 0 | 16 |
| **Total** | **32** | **13** | **5** | **4** | **54** |

Gaps found (unique verified gaps, section 4): **14**. Document errors found
(section 5): **5** (4 wrong/stale claims + 1 precision note).

---

## 2. Register A — S01-S15 compliance of rejection-rejector

### A1 — S01 Declare scope, ownership and lifecycle — **false (gap G1) -> remediated**
Demand: `engineering.toml` policy record (repository, lifecycle, profile
version, runtimes/OSs, authored/generated/vendor/fixture roots, verification
commands, required test families, released artifact kinds, exceptions) plus a
read-only validator detecting missing fields, nonexistent paths, expired
exceptions, undefined commands and required lanes without an execution path.
Evidence: no `engineering.toml` and no policy validator existed at any HEAD in
the audit window (`git ls-files`; `ls tools/`).
Remediation (implemented): `engineering.toml`, `tools/check_engineering_policy.py`
(exact S01 acceptance checks, incl. schema conformance against the vendored
reference schema), `tests/release/test_engineering_policy.py` (11 tests).

### A2 — S02 Version one engineering baseline — **false (gap G2)**
Demand: consumer workflows reference a reviewed immutable shared-baseline
commit; target defaults (command interface, Python Ruff/mypy with a 100-char
target line length, Rust rustfmt/Clippy, EditorConfig, typing adoption).
Evidence: the shared engineering repository is explicitly "a proposed
coordination repository, not an existing dependency" (manual S02) and does not
exist; no shared profile commit can be pinned. Homogeneity qualification is
correctly **BLOCKED**; recorded as dated exception **EX-001** in
`engineering.toml` with the compensating control (this repository's own frozen
inputs at the audit baseline: `rust-toolchain.toml`, `deny.toml`,
`.editorconfig`, `AGENTS.md` conventions, enforced by `tools/local_ci.py`).
The manual's Python "100-character target line length" default conflicts with
the verified portfolio pilot (`FlitzZip/.ruff.toml` at `4e6a1bb0…` sets
`line-length = 120` with Ruff E-family selected; fetched read-only and verified
2026-10-28). Per the manual's own SHOULD-exception mechanism this is a
conformant documented difference; recorded as dated exception **EX-002**
(compensating control: Ruff E501 at 120 + DeepSource `max_line_length` 120).
Rust tooling policy (rustfmt + Clippy from `rust-toolchain.toml`, one
formatter) is verified present. See also document error E3.

### A3 — S03 Standardize commands — **false (gap G3) -> remediated**
Demand: the eleven-command vocabulary (setup … release-check) through a thin
task runner or documented equivalent, with identical local/CI semantics.
Evidence: the repo has strong native entry points (`tools/local_ci.py`,
`scripts/build-windows.ps1`, CI workflows) but no single documented mapping of
the S03 vocabulary onto them; `git ls-files | grep -i justfile` empty.
Remediation (implemented): exact command records in `engineering.toml`
[commands] (each mapped to the native command string, environment,
applicability, reason) and a human map in `CONTRIBUTING.md`
("Verification command map (engineering standard S03)"). Wrapper exit-code
propagation verified in `tools/local_ci.py` (`run()` returns the child exit
code; `ALL GATES GREEN` only when every gate passes).

### A4 — S04 Make workflow results truthful — **false (gap G4, gap G5)**
Demand: checks execute at declared events; a stable aggregate verify job with
always-running dependency evaluation; SHA-pinned actions; read-only defaults;
timeouts/concurrency deliberate; required-check enforcement demonstrable.
Evidence (all verified at current HEAD):
- all external `uses:` references across the 15 workflows are full-SHA pinned
  (scripted regex check, 0 exceptions); workflow-level `permissions:
  contents: read` present; `persist-credentials: false` on checkouts;
  `timeout-minutes` set per job (e.g. ci.yml 35, supply-chain rust-policy 30).
- `ci.yml` triggers on `push`/`pull_request`/`workflow_dispatch` (ordinary PR
  checks do run); deep lanes (enterprise-deep-verification, mutation, fuzz,
  reproducibility, coverage, workflow-lint) are push/scheduled/dispatch only —
  acceptable per S04 ("not every expensive lane needs to run on every PR")
  and distinguished in `AGENTS.md`.
- **No aggregate verify job exists** (`grep -rn "needs:" .github/workflows` -> no
  aggregation) (gap G4).
- Branch protection (GitHub API, owner session, 2026-10-28):
  `required_status_checks = null` — **no required status checks are enforced
  server-side** (gap G5). A deliberate failing change is therefore blocked only
  by the required review, not by checks.
- Concurrency: `ci.yml` uses `group: rust-ci-${{ github.ref }}`,
  `cancel-in-progress: false` with the comment "Main-only development uses
  each commit as an auditable evidence point." GitHub's documented semantics
  (verified, section 3-D1/D2) show the default pending slot is still replaced
  by a newer queued run, so the comment is an intention, not a guarantee —
  exactly as the manual warns (N11/RR-06). `coverage.yml` already uses a
  per-SHA group (`rust-coverage-${{ github.sha }}`), the pattern the manual
  recommends.
Remediation: directives D5 (aggregate job) and D6 (per-SHA groups or
`queue: max` + burst reconciliation; fix or qualify the ci.yml comment);
dated exception EX-003 records the interim state and compensating controls.

### A5 — S05 Reconcile governance before changing it — **verified**
Evidence: classic branch protection for `main` read successfully via the
GitHub API on 2026-10-28: `required_approving_review_count: 1`,
`dismiss_stale_reviews: true`, `allow_force_pushes: false`,
`allow_deletions: false`, `required_conversation_resolution: true`,
`required_status_checks: null`. This matches `CONTRIBUTING.md`'s claims
("pull requests with review before merge … force pushes and deletion are
blocked and at least one approving review is required") — each clause
verified. No bypass claims are made anywhere. The unenforced required-check
state is recorded under S04/EX-003, not hidden. Note: the manual's claim that
detailed settings "remain unobservable" is superseded for this repository
(document error E2).

### A6 — S06 Keep tools and dependencies reproducible — **verified**
Evidence: `Cargo.lock` committed and used with `--locked` in every cargo
invocation (ci.yml, local_ci.py, CONTRIBUTING map); `rust-toolchain.toml`
pins channel 1.99.1; security tooling installed through
`taiki-e/install-action` with `checksum: true`, `fallback: none` and exact
versions (`cargo-audit@0.22.2`, `cargo-deny@0.20.2`, `cargo-cyclonedx@0.5.9`,
`cargo-machete@0.9.2`, `cargo-llvm-cov@0.9.1`, actionlint 1.7.12 with a
recorded archive SHA-256); one dependency updater per manifest scope
(`.github/dependabot.yml`: cargo + github-actions, weekly, grouped, with the
documented `nom` major-bump ignore); SBOM evidence uploaded per commit.
Pinning does not freeze advisory feeds — the audit lane re-runs against
current RustSec data and any new advisory must fail (verified comment +
`--deny warnings`).

### A7 — S07 One reviewed analysis policy — **false (gap G6) -> remediated**
Demand: reconciled dashboard/configuration-as-code; every suppression records
rule/fingerprint, reason, owner and review/removal criterion; declared
analyzer capability boundaries.
Evidence: `docs/deepsource-dispositions.md` gave rule shortcodes, exact-source
reasons and a review loop, but no owner/review-date/removal-criterion fields
per suppression, and no analyzer version boundary; `deny.toml` still carries a
bare `RUSTSEC-2023-0086` ignore without a `reason` entry (unlike its three
siblings) — the manual's RR-04 wording "a bare ID in deny.toml" verified.
Remediation (implemented): suppression governance fields + a new-occurrence
re-review rule + the DeepSource analyzer capability boundary recorded in
`docs/deepsource-dispositions.md`; owner/review/removal criteria added to the
advisory triage in `SECURITY.md`. The bare `deny.toml` entry is in a file I do
not own -> directive D3. Manual claim verified: current DeepSource docs list
Rust through 1.93 and Python through 3.12 (fetched 2026-10-28) while this repo
pins Rust 1.99.1 -> capability boundary recorded; Python operator tooling
(3.12) is inside the declared range.

### A8 — S08 Independent oracles — **false (gap G7)**
Demand: independent reference algorithms for numerical decisions; every
high-impact fix has a failing-before/passing-after regression; invalid input
rejected before reporting.
Evidence: at HEAD `a5f346a` (committed state) `training/calibrate_zero_fp.py`
reproduced both audited defects exactly (Register E1/E2/E3): the 0.001 grid
returned threshold 0.501 / TP 0 where an observed-score cutoff 0.5002 gives
TP 1 / FP 0; NaN, boolean, unknown-label, out-of-range (2.0) and negative
budget inputs were accepted, and the score-2.0 report contradicted its own
threshold. Current worktree (uncommitted, concurrent agent) shows a repair in
flight (observed 08:20 UTC: `ScoreRowError` rejection of out-of-range values,
boundary-based threshold 0.5002/TP 1, new `status`/`comparison`/`split_role`
fields). Independent-oracle regression tests are not yet in the tree ->
directive D2. Everything else in S08 is verified strong: state/CAS invariants,
recovery drills, subprocess CLI journeys, fuzz + mutation lanes, and the
"never weaken a production guard" rule in `AGENTS.md`.

### A9 — S09 Measure coverage and execution honestly — **false (gap G8)**
Demand: real coverage artifacts from the declared authored source set with
recorded mode/exclusions; required test families cannot disappear into skips.
Evidence: `coverage.yml` generates real `lcov.info` + `coverage.xml` +
summaries, declares line mode with 95% line / 90% function regression floors
(`--fail-under-lines 95 --fail-under-functions 90`), and measures Rust `src/`
plus Python `--source=scripts` only. `training/` and `tools/` — release-chain
Python code (calibration, model tooling, operator validators) — are outside
the measured Python scope (the manual's N09 claim verified verbatim). The
release-guard suite covers zero-test/unexpected-skip rejection
(`test_release_guard.ReleaseEvidenceTests.test_failed_cancelled_skipped_and_neutral_never_pass`
ran green). `AGENTS.md`/`CHANGELOG` state the 100% goal honestly as a standing
goal, never a CI gate. -> directive D4 (extend measured scope or record the
exclusion in the workflow's own comment; add calibration data tests).

### A10 — S10 Domain and trust boundaries — **false (gap G9)**
Demand: separated domain/state/presentation responsibilities; extraction done
as small characterized slices with dependency-direction checks.
Evidence: boundaries are explicit and invariant-tested (store CAS, vault,
policy, engine/worker split), but the measured large orchestration surfaces
remain: `src/engine.rs` 6,786 lines, `src/worker.rs` 6,476, `src/gui.rs`
5,379 (5,385 at the audit SHA), `src/store.rs` 4,705 (counts verified by
`wc -l`; inline `mod tests` confirmed in each). The manual's N10/RR-05
extraction work is outstanding -> directive D1 work item RR-05 (owned by code
agents). No line-count-driven rewrite is warranted and none is directed.

### A11 — S11 Identity and durable state across failure — **verified**
Evidence: at-most-once delivery records with state+revision CAS and
affected-row checks (`AGENTS.md` convention; `store.rs` regression suite ran
green: `new_database_creates_schema_and_vault_marker_together`,
`existing_database_without_vault_marker_is_never_adopted`,
`audit_chain_detects_ciphertext_tampering`, `audit_chain_detects_tail_truncation`,
`related_metadata_changes_are_committed_together` — executed in the operator
window via `cargo test` suites and the hosted deep-verification evidence);
recovery/restore with checksum/audit-bound backups and reconciliation without
blind retries (README + `docs/RECOVERY_COMPATIBILITY.md`; recovery drills in
`tests/cli_workspace.rs` ran green in the operator suite window).

### A12 — S12 Input, secrets, paths and errors — **verified**
Evidence: fail-closed input parsing and typed error surfaces (recovery
passphrase 4 KiB cap, path/permission rejection with the dedicated 0644 vs
0600 test at `src/bin/rr.rs:1441-1453` region — helper sites verified at
lines 1401/1451/2114), full-history secret scan job in `supply-chain.yml`,
redacted diagnostics documented (`rr diagnostics --out` review guidance in
`SECURITY.md`), synthetic-only test fixtures (no real credentials; `--demo`
workspace). Sensitive values never printed (README/SECURITY boundaries).

### A13 — S13 Qualify the exact artifact and recovery path — **verified**
Evidence: manual **Attested Windows package** workflow builds once and gates
publication behind `PACKAGE` confirmation; `scripts/verify_package.py`
(read-only, never extracts/executes) verifies exact file/checksum coverage and
build/contract/source identities; `scripts/release_guard.py` fail-closed
evidence gates; two-build `reproducibility.yml`; CycloneDX SBOM + sha256 sidecar
uploaded per commit. Unsigned/signed flavors are explicit and signed mode fails
closed without provisioned credentials (README + `engineering.toml` artifact
kind `signed-windows-package` applicable=false with factual reason).

### A14 — S14 Documentation and generated artifacts current — **false (gap G10)**
Demand: docs match implementation; stale policy text detected in review.
Evidence: the corpus is strong (README, CONTRIBUTING, SECURITY, AGENTS,
docs/SETUP|ARCHITECTURE|OPERATIONS|TESTING|THREAT_MODEL, CHANGELOG) and
README claims spot-checked as accurate. Three verified drifts remain in files
owned by other agents -> directive D7: (1) `Cargo.toml` cargo-machete rationale
still says "Keep 0.8.2 pinned" while the dependency is `yoke-derive = "0.8.4"`
(a compatible range) — the manual's exact wording verified; (2)
`coverage.yml` step name "Rust 1.99.0 with llvm-tools" contradicts its own
`toolchain: 1.99.1` input and `rust-toolchain.toml`; (3) `training/README.md`
still says AMD GPUs "work through ROCm on Linux or WSL2 on Windows" (portability
section) while its supported-compute section proves ROCm cannot initialize on
WSL2 (verified in the concurrently-modified worktree at 08:50 UTC), and its
"selects the operating threshold with maximal recall" claim (line 60) must be
re-checked after the RR-02 repair lands.

### A15 — S15 Machine-readable receipt — **false (gap G11) -> remediated (schema/validator); producer directed**
Demand: schema-validated receipt binding source SHA, baseline, profile,
toolchain/lock digests, commands+exit codes, test-family counts, coverage
scope, artifact digests, results, exceptions; the manual mandates "those exact
schemas rather than an illustrative receipt shape" and provides them in the
companion `implementation-contract.zip`.
Evidence: no receipt schema or receipt machinery existed in the repository.
The companion package was located as an embedded PDF attachment and extracted;
all 18 files were vendored **byte-identical** into `tools/contract/`
(each SHA-256 matches `PACKAGE-MANIFEST.json` — machine-checked, and re-checked
by `tests/release/test_engineering_policy.py`). `tools/check_engineering_policy.py`
plus the vendored `validate_contract.py` implement the mechanical S01/S15
checks. The repository-specific receipt producer (manual adoption step 3) is
future work -> directive D8. Documented example outcomes were executed and
match the package README exactly (consistent-synthetic -> consistency PASS but
result BLOCKED `synthetic_example_only`, exit 2; false-pass -> FAIL, exit 1;
blocked-synthetic -> BLOCKED, exit 2).

---

## 3. Register B — other Part I sections

### B1 — §1 completion contract (PASS/FAIL/BLOCKED/NOT-APPLICABLE semantics) — **verified**
The repository's own evidence culture already matches it (AGENTS.md
"evidence rules", CONTRIBUTING "A skipped lane is not a green lane",
release-guard rejecting failed/cancelled/skipped evidence). This audit applies
the same states; see section 6.

### B2 — §2 inventory ("188 tracked files, 15 workflows", profiles RS, PY) — **stale**
`git ls-files | wc -l` = **195** at `e1c0485` (was 188 at `589b89f`);
workflow count still 15 (verified). Profile mapping RS+PY verified correct.

### B3 — §4 RS profile requirements — **verified**
Declared toolchain (`rust-toolchain.toml`), committed `Cargo.lock` + locked
invocations, rustfmt + Clippy `-D warnings`, one canonical
dependency/advisory/license/source policy (`deny.toml` + `osv-scanner.toml`),
fuzz targets (`fuzz/`), mutation lane, coverage lane, controller/CLI fixtures,
persistence/authority transition tests, supported-target builds, installed
artifact + upgrade checks (`test_installer_tasks`, `test_verify_package`).
"Avoid live email or real external submissions in automated fixtures" verified
(synthetic fixtures only; live lanes are explicit opt-in).

### B4 — §4 PY profile requirements — **verified**
Stdlib-only runtime claim intact for operator tooling (`tools/`, `scripts/`;
tests run with no third-party imports), optional ML stack kept separate
(`training/` documented environments; `python-training-optional` environment
recorded as non-required in `engineering.toml`), unittest preserved (no
framework rewrite), test families enumerated in `engineering.toml`.
Formatter/linter adoption for Python is open (RR-03) — recorded under A9/A14.

### B5 — §5 Research and AI evaluation contract — **false (gap G12)**
Demand: research outputs identify source commit, environment/lock digest,
dataset/task identity, lineage/split, model identity, grader/prompt versions,
attempt/failure counts, seed, denominators, unavailable metrics and a
qualification label.
Evidence: `docs/scale-campaign-report.md` identifies the generator, corpus
(`training/data/scale_campaign_v1.jsonl`), seed (20261027), determinism and
per-category denominators, and binds expectations to a Rust test — but does
not record source commit, environment/lock digest, or an explicit
qualification label; same for `docs/model-scale-report.md` (spot-checked).
-> directive D9 (coordinate with the in-flight scale-campaign regeneration;
do not edit frozen evidence to improve counts — the manual's own rule).

### B6 — §6 current failure recovery / governance decisions (RR paragraphs) — **verified**
"RR's newer source supplies synthetic passphrase input and owner-private
recovery-fixture permissions" verified: `with_headless_vault_input` arms a
synthetic passphrase (src/bin/rr.rs:1810-1823) and the recovery fixture sets
mode 0600 (line 2114) before the exact IMPORT assertion
(`recovery_key_import_demands_its_exact_confirmation_token`, line 2102). "The
old two failures are historical" verified as the committed state. "Replace
process-global test environment mutation with an isolated input boundary"
= the RR-01 seam claim, verified (Register E13). "Preserve the production
vault checks" verified (production `Vault::open` fail-closed path untouched).

### B7 — §7 architecture/change strategy — **n/a** (advisory strategy text; its
RR instantiation is N10/RR-05, covered in A10).

### B8 — §8 enterprise comparisons — **n/a** (research context, not a
repo-state claim; nothing to verify against RR).

### B9 — §9 ordered rollout (RR = Phase-2 Rust pilot "after all required
current jobs are qualified") — **verified** as an accurate, still-pending plan
statement: RR-01..06 remain open (some in flight), so pilot qualification has
not started. No implementation follows from the plan text alone.

### B10 — §10 common implementation artifacts — **false (subset) -> remediated**
Per-artifact presence at `e1c0485`: `engineering.toml` **absent -> created**;
justfile or documented equivalent **absent -> created** (engineering.toml
commands + CONTRIBUTING map; `tools/local_ci.py` as wrapper); `.editorconfig`
present (UTF-8, LF, final newline, 4/2-space split — verified content);
`.pre-commit-config.yaml` **n/a** ("where fast"; no hook stack; the manual's
own N11 notes this is not inherently a defect; `tools/local_ci.py` is the
exact-gate equivalent); `.github/workflows/ci.yml`-equivalent present;
native manifests/locks present (`Cargo.toml`/`Cargo.lock`/`rust-toolchain.toml`);
`docs/development.md` — equivalent location `docs/SETUP.md` (+`docs/WINDOWS-RUNTIME.md`),
mapping now recorded in `engineering.toml` reasons and CONTRIBUTING;
`docs/architecture.md` = `docs/ARCHITECTURE.md`; `docs/operations.md` =
`docs/OPERATIONS.md`; README/CONTRIBUTING/SECURITY present; evidence/receipt
schema **absent -> created** (`tools/contract/`, exact mandated schemas).

### B11 — §11 agent execution protocol — **verified**
`AGENTS.md` + the in-repo `rr-engineering` skill already encode the protocol:
read policy first, one invariant per change, safe synthetic fixtures, smallest
coherent change, focused checks then common verification, separate review
pass, never weaken a production guard, no silent retries/ignores, external
mutation forbidden, handoff with SHA/commands/counts. `CONTRIBUTING.md` adds
the human-side review requirement (one approving review, verified enforced).
The manual's "state the actual review independence" is covered by the
solo-owner PR-review record; no phantom second approver is claimed.

---

## 4. Register C — Part V traceability and closure

### C1 — Finding->task register completeness for RR rows — **verified**
Every RR-relevant finding maps to the six canonical tasks: N03+N04 -> RR-02
(calibration), N05 -> RR-04 (advisory consolidation), N09 -> RR-03 (Python
tooling coverage), N10 -> RR-05 (extraction), N11+N12 -> RR-06 (shared
commands/release evidence), CI-RR-1+CI-RR-2 -> RR-01 (fixture regression
retention). RR-01..RR-06 are the only valid task IDs and are exactly the set
in `engineering.toml` [tasks] (machine-checked by
`tools/check_engineering_policy.py`). Finding-to-evidence status is recorded
in Registers A/E and section 6.

### C2 — Requirement closure fields (applicability, implementation path,
verification command, environment, result, evidence artifact, owner, review
date per S01-S15) — **false at HEAD -> remediated**
Implemented as the closure table in section 6 and as machine-readable
dependency records in `engineering.toml` (standards[] entries carry
applicability, reason, command_ids, test_family_ids, artifact_kinds; exceptions
carry owner/expiry/alternatives). Receipt production against these fields is
directive D8.

### C3 — "Evidence actually executed during the audit" (RR rows: operator
suite 173 total/172 passed/1 Windows-only skip; hosted deep verification
1,015 passed/zero skipped) — **stale**
Hosted numbers are historical for `589b89f` (the manual timestamps them; the
current head is 8 commits ahead with runs still in progress at report time).
Local operator suite re-run in this audit on Windows: **173/173 passed, 0
skipped** at HEAD `a5f346a`-era worktree (the manual's Linux-host "1 Windows-only
skip" is platform-conditional, not an error). With the concurrent additions
the suite reached 202 tests at 08:25 UTC (my 11 + 18 in-flight from other
agents).

---

## 5. Register D — external/tooling claims in the standard (primary sources)

| # | Claim (manual) | Verdict | Evidence |
|---|---|---|---|
| D1 | Default concurrency keeps one pending run; a newer queued run replaces an older pending one even with `cancel-in-progress: false` | **verified** | GitHub docs (fetched 2026-10-28): "any existing `pending` job or workflow in the same concurrency group will be canceled and the new queued … takes its place"; `queue: single` (default) |
| D2 | `queue: max` allows up to 100 pending runs and cannot combine with `cancel-in-progress: true` | **verified** | Same page: "Up to 100 … `queue: max` and `cancel-in-progress: true` is not allowed"; Actions limits page: "Concurrency group queue | 100 workflow runs / concurrency group" |
| D3 | `uv sync --locked` rejects an outdated lock; `--frozen` deliberately skips the freshness check | **verified** | uv docs (fetched 2026-10-28): "--locked … raise an error instead of updating"; "--frozen … without checking if it is up-to-date" |
| D4 | DeepSource docs list Rust through 1.93 and Python through 3.12 | **verified** | DeepSource core-analyzers page (fetched 2026-10-28): "Rust | ≤1.93"; "Python | 2.7, 3.x (up to 3.12)" |
| D5 | CodeQL supports Rust | **verified** | CodeQL supported-languages page (fetched 2026-10-28): "Rust | Rust editions 2021 and 2024 | Rust compiler"; the repo already runs `codeql.yml` ("CodeQL Rust security") |
| D6 | Rust `set_var` safety contract: mutation is unsound with concurrent readers on non-Windows and `Command::env` is the recommended child-process path | **verified** | doc.rust-lang.org `std::env::set_var` (fetched 2026-10-28): "you must ensure that there are no other threads concurrently writing or reading (!) the environment … To pass an environment variable to a child process, you can instead use `Command::env`" |
| D7 | `tomllib` requires Python >=3.11 | **verified** | stdlib docs + successful `import tomllib` on the tooling interpreter; `tools/contract/README.md` states the same requirement |
| D8 | GitHub hosted jobs cap at six hours (cited for FlitzZip) | **n/a** | RR sets explicit `timeout-minutes` far below any cap; claim not needed for any RR decision |
| D9 | Dependabot supports uv (portfolio-level) | **n/a** | RR's updater scopes are cargo + github-actions; uv support irrelevant here |

---

## 6. Register E — the manual's RR-specific factual claims

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| E1 | `select_best` sweeps a 0.001 grid and misses feasible optima (N03) | **verified** (at HEAD `a5f346a`; repair in flight) | Reproduced 07:55 UTC on the committed file: scores 0.5001(neg)/0.5002(pos) -> threshold 0.501, TP 0, FP 0; observed-score cutoff 0.5002 -> TP 1, FP 0. Uncommitted rewrite observed 08:20 UTC now returns threshold 0.5002/TP 1 |
| E2 | Calibration accepts nonfinite/boolean/out-of-range/unknown-label/negative-budget input (N04) | **verified** (at HEAD; repair in flight) | Reproduced: NaN negative reported as zero FP; `True` accepted as probability; label `mystery` accepted; `--target-fp -1` accepted by `calibrate()`. Current worktree raises `ScoreRowError` for out-of-range values |
| E3 | Score 2.0 yields a self-contradictory report (threshold 1.01, "FP 0", applying it gives FP 1) | **verified** (at HEAD; repair in flight) | Reproduced exactly: report `{"threshold": 1.01, "false_positives": 0}` while `counts_at(…, 1.01)` = FP 1 |
| E4 | Duplicate audit lanes: unversioned `cargo install cargo-audit --locked` + pinned `cargo-audit@0.22.2`, same four ignores (N05) | **verified** (still current) | `supply-chain.yml` lines 21-37 vs 39-77 at `e1c0485` (file unmodified in the worktree): both run `cargo audit --deny warnings` with the same four `--ignore` flags; only the rust-policy lane pins the tool |
| E5 | Release-tooling syntax-checks only `tools/resource_guard.py` + `training/train_lora.py` (N09) | **verified** (still current) | `release-tooling.yml` line 29: `python -m py_compile tools/resource_guard.py training/train_lora.py` |
| E6 | Rust coverage measures Rust + `scripts/`, leaving `training/` and `tools/` outside the Python coverage scope (N09) | **verified** (still current) | `coverage.yml` line 71: `python3 -m coverage run --source=scripts …` |
| E7 | `training/README.md` contradicts itself on ROCm/WSL2 (N09) | **verified** (still current) | Lines 13-14 claim AMD GPUs "work through ROCm on Linux or WSL2 on Windows"; lines 27-32 prove WSL2 GPU-PV lacks KFD topology and "PyTorch ROCm wheels cannot initialize GPU training in WSL2" |
| E8 | `training/README.md` claims "maximal recall" selection (R162) | **verified** (at HEAD) | Line 60: "calibrate_zero_fp.py selects the operating threshold with maximal recall" — contradicted by E1 for the committed implementation; wording must follow the RR-02 repair |
| E9 | Large modules: engine 6,786 / worker 6,476 / store 4,705 / gui 5,385 lines with inline tests (N10) | **verified** | `wc -l`: 6786 / 6476 / 4705 / 5379 (gui -6 vs audit SHA; each has one `mod tests`) |
| E10 | yoke-derive documentation drift: dependency `yoke-derive = "0.8.4"` (compatible range) vs comment "Keep 0.8.2 pinned" | **verified** (still current) | `Cargo.toml` lines 75 and 89-91 |
| E11 | Concurrency comment intends per-main-commit evidence but does not guarantee it (N11/RR-06) | **verified** | `ci.yml` lines 10-13 comment + Register D1 semantics |
| E12 | Old fixture failures are source-remediated (synthetic passphrase wrapper; recovery fixture mode 0600) | **verified** | `src/bin/rr.rs` `with_headless_vault_input` (1810-1823, 9 call sites) + `perms.set_mode(0o600)` at 2114 before the exact IMPORT assertion at 2102 |
| E13 | The temp-env seam is inadequate: "a setter mutex does not coordinate every environment reader" (RR-01) | **verified** (technical soundness/test-isolation gap; no observed race — consistent with the manual's own P2 framing) | `temp_env::with_var` mutates the process environment inside parallel `cargo test` threads (harness runs tests concurrently); `src/vault.rs:207` reads `std::env::var(VAULT_PASSPHRASE_ENV)` from whatever thread opens a vault; temp-env 0.3's internal lock serializes only its own callers. Rust std docs (Register D6) state the guarantee is "not practically possible" and name `Command::env` as the sound alternative. `tests/cli_workspace.rs:66` already uses the sound per-child `Command.env` pattern. Fix = directive D1 |
| E14 | "Rust is pinned to 1.99.0" | **stale** | `rust-toolchain.toml` channel = 1.99.1 at `a5f346a`/`e1c0485` (bumped by commit `a5f346a`); the audit-SHA claim was accurate |
| E15 | Inventory "188 tracked files" | **stale** | 195 at `e1c0485` (Register B2) |
| E16 | "1,015 tests passed, zero skipped" (hosted deep-verification) | **stale** (as a current-state claim; valid historical evidence for `589b89f`) | Head moved 8 commits; deep-verification for `e1c0485` was still in progress at report time |

---

## 7. Gap register (14 verified gaps)

| # | Gap | Requirement | Status | Where |
|---|---|---|---|---|
| G1 | No engineering.toml / policy validator | S01 | **implemented** | `engineering.toml`, `tools/check_engineering_policy.py`, `tests/release/test_engineering_policy.py` |
| G2 | Shared baseline absent; Python line-length default conflict | S02 | exceptions EX-001/EX-002 recorded; baseline publication directed | `engineering.toml` [exceptions] |
| G3 | S03 vocabulary mapping undocumented | S03 | **implemented** | `engineering.toml` [commands], `CONTRIBUTING.md` |
| G4 | No aggregate verify job | S04 | directed (D5) | `.github/workflows/` |
| G5 | No server-side required status checks (`required_status_checks = null`) | S04/S05 | directed (D5, settings action by owner) | GitHub branch protection |
| G6 | Suppression records lack owner/review/removal fields; bare `RUSTSEC-2023-0086` ignore | S07 | **implemented** (docs) + directed (deny.toml, D3) | `docs/deepsource-dispositions.md`, `SECURITY.md` |
| G7 | Calibration oracle/input-validation defects; no calibration regression tests | S08 | directed (D2); concurrent repair observed | `training/calibrate_zero_fp.py`, `tests/release/` |
| G8 | Python coverage scope excludes `training/`+`tools/` | S09 | directed (D4) | `coverage.yml` |
| G9 | Orchestration extraction outstanding | S10 | directed (RR-05, D-list) | `src/engine.rs` etc. |
| G10 | Documentation drift (yoke comment, coverage step label, training README) | S14 | directed (D7) | `Cargo.toml`, `coverage.yml`, `training/README.md` |
| G11 | No receipt schema/validator | S15 | **implemented** (exact schemas + validator vendored); producer directed (D8) | `tools/contract/` |
| G12 | Research reports lack source/lock/qualification identity fields | §5 | directed (D9) | `docs/scale-campaign-report.md`, `docs/model-scale-report.md` |
| G13 | temp-env process-global test seam (RR-01) | S08 | directed (D1) | `src/bin/rr.rs`, `Cargo.toml` |
| G14 | Concurrency groups can replace pending per-commit evidence runs (RR-06) | S04 | directed (D6) | `ci.yml`, `supply-chain.yml` |

---

## 8. Implementation directives for the code/workflow owners

**D1 (RR-01, `src/bin/rr.rs` + `Cargo.toml`) — replace the process-global
temp-env seam.** In `src/bin/rr.rs`, delete `with_headless_vault_input`
(lines ~1804-1823) and its `temp_env::with_var` mutation (the only `temp_env`
use in the tree). Migrate its ten live-workspace call sites (lines 1901, 1977,
1991, 2020, 2044, 2077, 2103, 2150, 2191, …) to the repository's existing
sound pattern: the child-process harness in `tests/cli_workspace.rs:45-76`
(`rr_command()` + `headless_vault_seam()` provisioning `RR_VAULT_PASSPHRASE`
per child via `Command.env`). The fail-closed "missing production input still
fails" coverage must keep a child launched with the variable explicitly
removed. Then drop `temp-env` from `[dev-dependencies]` (`Cargo.toml` line 86)
and the `Cargo.lock` entry. Keep the 0600/0644 permission tests and the exact
IMPORT confirmation assertion unchanged. Acceptance: `grep -rn "temp_env\|set_var" src tests` is empty; `cargo test --locked --all-features` green on Linux and Windows; the recovery-confirmation test still reaches the exact IMPORT error.
Evidence basis: Rust std `set_var` safety contract (Register D6) + code
inspection (Register E13).

**D2 (RR-02, `training/calibrate_zero_fp.py` + `tests/release/`) — finish and
land the calibration repair as a regression.** A concurrent uncommitted
rewrite is in flight (boundary-based threshold 0.5002/TP 1 on the E1 case;
`ScoreRowError` on out-of-range input). When landing it, keep the manual's
acceptance exact: decision sets induced by observed finite scores with
documented `>=`/tie policy and explicit abstain-all; deterministic
tie-breaker; reject nonfinite/boolean/out-of-range/unknown-label/missing-field
rows and negative/non-integral budgets at the callable boundary too; preserve
the documented ambiguous-label-as-negative policy; emit an explicit
insufficient-data status instead of a misleading report; the reported
threshold must reproduce the reported counts (E3). Add deterministic CPU tests
(`tests/release/test_calibration_zero_fp.py`) covering the close-score case,
equal-score ties, endpoints 0/1, NaN/inf, score 2.0, boolean, unknown label,
negative budget, empty/all-positive/all-negative sets, and a small exhaustive
independent oracle comparison — no model downloads.

**D3 (RR-04, `deny.toml` + `Cargo.toml` + `supply-chain.yml`).**
(a) `deny.toml` line 20: convert the bare `"RUSTSEC-2023-0086"` ignore into the
same `{ id = "RUSTSEC-2023-0086", reason = "…" }` form as its siblings (reason
text already exists in `SECURITY.md`); (b) `Cargo.toml` lines 89-90: fix the
cargo-machete rationale — the dependency is `yoke-derive = "0.8.4"` (a
compatible range, not an exact pin) while the comment still says "Keep 0.8.2
pinned"; (c) `supply-chain.yml`: remove the duplicate unversioned
`cargo install cargo-audit --locked` advisories lane (lines 21-37) or pin it
identically to the rust-policy lane, so exactly one authoritative pinned
advisory execution remains per database, and give the advisories job a
`timeout-minutes` like its siblings.

**D4 (RR-03/N09, `release-tooling.yml` + `coverage.yml`).**
(a) `release-tooling.yml` line 29: extend `python -m py_compile` beyond the two
named files to the full operator surface (`tools/*.py scripts/*.py
training/*.py`) or record the deliberate exclusion in the step name/comment;
(b) `coverage.yml` line 71: extend `--source=scripts` to the release-chain
Python roots (`scripts tools training`, with test/fixture exclusions) or
comment the measured scope where the manual demands it recorded; (c) land D2's
calibration tests so the calibration family has an execution path.

**D5 (S04/S05, `.github/workflows/` + repo settings).** Add a stable aggregate
verify job (e.g. in `ci.yml`) with `needs:` over every required job and an
`if: always()` evaluation that fails on failure/cancellation/missing
output/unexpected skip; then configure `main` branch protection to require the
stable check names (owner settings action — GitHub currently reports
`required_status_checks: null`). A deliberate failing change must then block
the merge path (manual S04 acceptance event matrix).

**D6 (RR-06/N11, workflow concurrency).** Where per-main-commit evidence is
intended (`ci.yml`, `supply-chain.yml` comments), either use per-SHA
concurrency groups (as `coverage.yml` already does) or `queue: max` with a
burst-reconciliation step; `cancel-in-progress: false` alone does not retain
older pending runs (Register D1). Add the manual's three-commit-burst
reconciliation check and correct the `ci.yml` comment to match the chosen
strategy.

**D7 (S14 doc drift).** (a) `coverage.yml` line 47: step name "Rust 1.99.0 with
llvm-tools" -> "Rust 1.99.1 with llvm-tools" (matches `toolchain: 1.99.1` and
`rust-toolchain.toml`); (b) `training/README.md` lines 13-14 vs 27-32: resolve
the ROCm/WSL2 contradiction (the portability sentence must not claim WSL2 GPU
training while the supported-compute section documents that it cannot
initialize); (c) `training/README.md` line 60: re-validate the "maximal
recall" claim once D2 lands and state the comparison/tie policy.

**D8 (S15).** Implement the repository-specific receipt producer (manual
adoption-sequence step 3): execute the `engineering.toml` commands on their
supported hosts, record exact command strings, runtime versions, exit codes,
test-family collected/executed/passed/failed/skipped/blocked counts, input and
artifact digests into the `tools/contract/execution-receipt.schema.json`
shape, then validate with `python tools/contract/validate_contract.py`
(policy `engineering.toml`, current trusted target SHA, profile SHA). Keep
failed/skipped/blocked outcomes; a host that has not run stays BLOCKED.

**D9 (§5 research identity).** When the in-flight scale-campaign regeneration
lands, add an evidence-identity header to `docs/scale-campaign-report.md` and
`docs/model-scale-report.md`: source commit, `Cargo.lock` digest, corpus/seed
identity, denominators, unavailable metrics (null + reason) and an explicit
qualification label. Do not edit frozen historical evidence beyond adding
forward identity records.

---

## 9. Document errors and stale claims (with proof)

**E-doc-1 (material, S02 table):** "Python … a 100-character target line
length" is presented as the portfolio target default, but the maintainer's
actual pilot configuration uses 120: `FlitzZip/.ruff.toml` at the manual's own
cited snapshot `4e6a1bb0d144611a09dcbc65276faa676e923882` contains
`line-length = 120` (fetched read-only and verified 2026-10-28), and the
DeepSource Python analyzer is configured with `max_line_length` 120 per the
maintainer standard. Under the manual's own rule ("SHOULD is the default
unless a documented, dated exception explains why another implementation meets
the same contract") the 120 choice is conformant; the table should be read as
default-unless-documented-exception. Recorded as EX-002; the repo is **not**
declared non-conformant for the 120 choice.

**E-doc-2 (S05):** "all five detailed classic-protection reads returned
access-denied responses. Required-check names, bypass actors and review
requirements therefore remain unobservable" — superseded for
rejection-rejector: with the owner's authorized `gh` session the classic
protection endpoint returned the complete settings on 2026-10-28 (section A5
JSON). The manual's caution against inferring enforcement from
inaccessibility is correct; the unobservability statement itself is stale,
and the newly observable `required_status_checks: null` is a material
governance fact (gap G5) the audit could not see.

**E-doc-3 (stale):** "Rust is pinned to 1.99.0" (RR-01 notes) — current
`rust-toolchain.toml` pins 1.99.1 (commit `a5f346a`); the claim was true at
the audited SHA. Related repo-side drift: `coverage.yml`'s step label still
says 1.99.0 (directive D7a).

**E-doc-4 (stale):** the RR CI/nextest figures ("1,015 tests passed, zero
skipped", "11/12 successful … Mutation pending", "188 tracked files") describe
the audited snapshot `589b89f`; the default branch advanced eight commits
during this audit window and new runs were still executing at report time.
The manual timestamps these observations honestly, so they are stale rather
than wrong; do not restate them as current-head facts.

**E-doc-5 (minor precision, N03 wording):** "A cutoff of 0.50015 yields one
true positive and zero false positives" is true, but under the documented `>=`
semantics the smallest feasible cutoff is 0.5002 (the positive score itself);
the reproducer in this audit used 0.5002. Not a defect — recorded for
precision so the fix's tie policy is judged against the right boundary.

Claims that were checked and found **accurate** (no error): GitHub concurrency
semantics (D1/D2), uv lock semantics (D3), DeepSource analyzer versions (D4),
CodeQL Rust support (D5), `set_var` safety wording (D6), N05/N09/N10/N11
repo-state claims (Register E4-E11), the RR-01 remediation description
(E12), the RR-01 seam critique (E13), and the S03/S15 prose describing the
companion contract package (its 48-test suite and the three documented example
outcomes were reproduced exactly in this audit).

---

## 10. Part V requirement closure fields (S01-S15)

Owner for every row: strmt7 (sole maintainer). Review date: 2026-10-28; next
review 2027-04-28. "Result" uses the manual's states.

| Req | Applicable | Implementation path | Verification command | Environment | Result | Evidence artifact |
|---|---|---|---|---|---|---|
| S01 | yes | `engineering.toml` + `tools/check_engineering_policy.py` (new) | `python tools/check_engineering_policy.py` | python-operator | **PASS** | this doc; `tests/release/test_engineering_policy.py` (11 tests, green 08:2x) |
| S02 | yes | EX-001 (baseline pending) + EX-002 (120-char profile override) | `python tools/local_ci.py` (compensating) | rust/python | **BLOCKED** (baseline not published) | `engineering.toml` [exceptions]; `tools/contract` profile identity note |
| S03 | yes | command map in `engineering.toml` [commands] + CONTRIBUTING | `python tools/check_engineering_policy.py`; `python tools/local_ci.py` | rust-windows-msvc / python-operator | **PASS** (mapping) / execution receipts pending D8 | `engineering.toml`; `CONTRIBUTING.md` |
| S04 | yes | aggregate job + required checks (D5/D6) | `python tools/local_ci.py`; `actionlint` lane | CI | **FAIL** open (G4/G5), EX-003 | branch-protection API JSON (section A5); workflow inventory |
| S05 | yes | governance record | settings receipt (API JSON, 2026-10-28) | owner session | **PASS** (with S04 note) | section A5 |
| S06 | yes | locks + pinned tooling (existing) | `cargo deny check …`; `cargo fetch --locked` | rust-linux-gnu | **PASS** | `Cargo.lock`, `rust-toolchain.toml`, supply-chain.yml |
| S07 | yes | dispositions governance (new sections) + D3 remainder | `cargo audit …`; `cargo deny check advisories …` | rust-linux-gnu | **PASS** (docs) / D3 open for `deny.toml` | `docs/deepsource-dispositions.md`, `SECURITY.md` |
| S08 | yes | calibration repair (D2) + existing invariant suites | `cargo test --locked --all-features`; `python -m unittest discover -s tests/release` | rust / python | **FAIL** open (G7) | Register E1-E3 reproductions; suite logs |
| S09 | yes | coverage scope extension (D4) | `cargo llvm-cov …`; coverage-python | rust-linux-gnu | **FAIL** open (G8) | `coverage.yml`; `engineering.toml` coverage_scopes |
| S10 | yes | RR-05 extraction (directed) | `cargo clippy …`; `cargo test --locked --all-features` | rust | **FAIL** open (G9) | `wc -l` counts (Register E9) |
| S11 | yes | existing CAS/recovery machinery | `cargo test --locked --all-features` | rust | **PASS** | store/recovery test names (A11) |
| S12 | yes | existing boundaries | `cargo test --locked --all-features`; secret scan lane | rust / CI | **PASS** | A12 cites |
| S13 | yes | existing release machinery | `python scripts/verify_package.py …`; `python scripts/release_guard.py …` | python-operator / windows | **PASS** (unsigned default; signed kind explicitly not applicable) | `engineering.toml` artifact_kinds; release workflows |
| S14 | yes | doc drift fixes (D7) | review + `python tools/check_engineering_policy.py` | — | **FAIL** open (G10) | Register A14 |
| S15 | yes | `tools/contract/` (new) + producer (D8) | `python tools/contract/validate_contract.py …` | python-operator | **BLOCKED** (producer pending; schema/validator PASS) | `tools/contract/test-output.txt`, `test-results.json`, this doc |

Overall closure state: **BLOCKED** — required S04/S08/S09/S10/S14 work is
open and S02/S15 await external steps (shared baseline; receipt producer).
Per the manual's own rule, missing evidence is never PASS and the open items
cannot be waived into PASS by the recorded exceptions.

## 11. Section 12 final closure checklist mapping

1. Scope correct (13 repos; ZMB-UZH the only OMERO deployment repo) — n/a to
   this repository's implementation; audit scope here is RR only. **verified**
   as far as RR's placement (R11/RR-01..06) is exact.
2. Every applicable S01-S15 has a validated result and identity — **partially**:
   table above; open FAIL/BLOCKED rows listed.
3. Every task/finding maps to evidence or an explicit unresolved record —
   **yes** (Registers C1/E; directives D1-D9).
4. Checks execute at intended events and fail on defects — **open** (G5:
   required-check enforcement absent; D5).
5. Local/CI tools agree; canaries separate — **yes** for Rust/security tooling
   (A6); Python tooling version unification remains RR-03 work.
6. Independent contract + real-entry-point tests for identified failures —
   **open** for calibration (D2); verified for delivery/recovery/CLI.
7. State/retry/identity and input boundaries have negative/recovery cases —
   **yes** (A11/A12).
8. Generated output/cache/asset freshness evidence — **yes** for the release
   chain (repository-integrity, package verification); not applicable to
   external assets.
9. Exact artifacts pass install/journey/upgrade/restore; host evidence —
   **yes** for the documented Windows lane; live Gmail/GPU remain owner-environment
   acceptance as documented (README).
10. Documentation/rules/commands/lifecycle/updater policy agree — **open**
    (G10 doc drift; D7).
11. No raw secrets/invented results/unresolved placeholders in receipts —
    **yes** (this record and the vendored contract contain no secrets; example
    receipts are labelled synthetic).
12. A reviewer can reproduce the declared PASS — **yes** for every PASS row
    (commands printed); overall state correctly remains BLOCKED.

---

## 12. Evidence appendix — executed in this audit (2026-10-28)

| Command / probe | Result |
|---|---|
| `python -m unittest discover -s tests/release -v` (worktree at `a5f346a` state) | 173 tests, 0 failures, 0 skips (Windows host) |
| same, at 08:25 UTC with concurrent additions | 202 tests; 1 failure **in `test_lint_infra` (another agent's in-flight files)** — not attributable to this work |
| `python -m unittest tests.release.test_engineering_policy` | 11 tests OK (0.59 s) |
| `python tools/check_engineering_policy.py` | `{"result": "PASS", "errors": []}`, exit 0 |
| reference package manifest check | all 18 files byte-identical (`PACKAGE-MANIFEST.json`) |
| `tools/contract/validate_contract.py` × 3 documented examples | exit 2 / 1 / 2 with results BLOCKED / FAIL / BLOCKED exactly as documented |
| `python -B -m unittest test_validate_contract` (vendored reference suite) | 48 tests, 0 failures, 0 skips — matches the manual's "48 passing tests" claim |
| N03/N04 reproductions against committed `training/calibrate_zero_fp.py` | grid defect, NaN/bool/unknown-label/negative-budget acceptance, score-2.0 self-contradiction all reproduced (07:55 UTC) |
| GitHub API `branches/main/protection` | JSON in section A5 (2026-10-28 08:5x UTC) |
| workflow pinning scan | 0 non-full-SHA external `uses:` refs in 15 workflows |
| `gh run list --branch main` | head `a5f346a` runs in progress; earlier completed: Repository integrity, Workflow static analysis, Scorecard, Release tooling, Supply-chain (success) |
| primary-source fetches | GitHub concurrency + limits docs, uv sync docs, DeepSource core-analyzers, CodeQL languages, Rust `set_var` docs, FlitzZip `.ruff.toml` — each cited in registers |
| `python -m unittest discover -s tests/release -p "test_*.py"` (final lane, 09:0x UTC) | **223 tests, OK, exit 0** (includes this audit's 11 + concurrent agents' additions) |
| `cargo fmt --all -- --check` | exit 0 |
| `python -m py_compile` on touched Python | clean (all files above) |

Limitations: the full Rust suite (`cargo test --locked`) and the aggregate
`python tools/local_ci.py` gate were not run to completion here because
concurrent agents were editing `src/`, `tests/`, `tools/local_ci.py` (the gate
runner itself), `deny.toml` and nine workflow files during the window
(`git status` evidence); per the audit's coordination rule the exact
individual lanes covering this work were run instead (final row above), and
the Rust gates cannot be affected by this audit's changes (zero Rust files
touched). Windows-signed release, live Gmail and GPU qualification remain
owner-environment acceptance as the repository already documents.
