# Handover: state and operating guide for automated contributors

State as of 2026-10-28, commit `5aba8d4` and the follow-up documentation
batch. Read together with `AGENTS.md` (operational map and definition of
done) and `docs/LESSONS.md` (failure-derived rules). This file records what
is delivered and verified, what remains open, and the exact operating
recipes for the tooling the work depends on. It is written for an AI agent
picking up the repository cold.

## Verified state

- Every required CI lane is green on `main`: `lint`, `Rust CI`, `Rust
  coverage`, `Rust fuzzing`, `Rust public API compatibility` (semver),
  `CodeQL Rust security`, `Supply-chain security` (pinned cargo-audit +
  cargo-deny), `OpenSSF Scorecard`, `Release tooling tests`, `Workflow
  static analysis` (actionlint + zizmor, zero unsuppressed findings),
  `Repository integrity`, `Windows reproducibility`, `Enterprise deep
  verification`, `Mutation testing` (deep run, ~25-40 min per SHA).
- Test corpus at handover: 1,058 Rust tests, 232 release/operator Python
  tests, 24 model-free training tests. Coverage floors 95% lines / 90%
  functions are enforced by the coverage lane.
- DeepSource: findings fixed at source by professional rewrite only —
  suppressions of any kind are banned (owner policy, 2026-10-29; the
  standing policy lives in `docs/deepsource-dispositions.md`). All 15
  legacy ignore rules were deleted and the two dismissed code-scanning
  alerts reopened.
- Dependabot: zero open security alerts; the PR queue (7 upgrade PRs) is
  drained (auto-merged). All toolchain/action pins were independently
  re-audited against upstream releases, not just dependabot.
- Python lint enforcement covers the whole tree (`training/`, `tools/`,
  `tests/`): ruff check + format plus the D documentation contract
  (every module, class, function, `__init__` and magic method carries a
  docstring; presentation-only D205/D212/D213/D401 are out of contract by
  dated decision in `.ruff.toml`).

## What the 2026-10-28 waves delivered

1. **Enterprise-manual audit** (the 154-page implementation manual): four
   claim-by-claim auditors (common standard, RR code/tests, operational
   instructions, research/evaluation). Reports: `docs/audit-common-standard.md`,
   `docs/audit-rr-code-tests.md`, `docs/audit-operational-instructions.md`,
   `docs/audit-research-ai-evaluation.md`. Every claim carries a verdict
   with evidence; document errors are listed with proof. Key landings: the
   `temp_env` test seam removed (RR-01, `Command.env` per-child pattern),
   the execution-receipt contract vendored under `tools/contract/`, the
   calibration rebuilt on observed decision boundaries (RR-02), and the
   evaluation-report identity fields (build identity, sampling policy,
   unavailable-metric reasons).
2. **`rr live-selftest`** (`src/bin/rr.rs`, `src/engine.rs`,
   `src/mail.rs`): operator-invoked self-addressed probe through the
   configured transport with independent `find_sent` verification. Its
   first live run root-caused a shipping bug: the app-password SMTP path
   paired lettre's implicit-TLS `relay()` with the STARTTLS submission
   port (rustls `InvalidContentType` at handshake). TLS now follows IANA
   port semantics via `smtp_tls_mode()` (465 implicit, else STARTTLS),
   pinned by test. Live round trip verified (send -> accept -> sync pull).
3. **Test-wait overhaul** (`Worker::wait_for`): the load-flaky deadline
   tests (worker latch + `tui::draw_*`) synchronized via 10-second polling
   loops; nine sites now use one bounded, documented wait helper (60s
   hung-worker guard) with a contract test.
4. **Python lint + documentation contract**: 13 residual findings fixed at
   source (including `zip(strict=True)` semantics and byte-preserving wraps
   of the Japanese corpus banks - the corpus regenerates byte-identical,
   sha256 pinned in `docs/scale-campaign-report.md`), 134 docstrings
   written across the tree, overlapping except unions corrected, and the
   lint scope flipped to recursive globs with the scope pin updated.
5. **Mass-email validation**: 1,032 labeled emails x 12 languages through
   the real pipeline (`training/scale_campaign.py`, deterministic seed;
   diagonal confusion matrix). Root causes found and fixed live in the
   product: rejection-phrase bank gaps in 12 languages and quoted-history
   boundary leaks in 8. Evidence: `docs/scale-campaign-report.md`,
   `docs/model-scale-report.md`.

## Open items

- **CII-Best-Practices**: requires the human owner to register the project
  at bestpractices.dev. No agent can complete this. The code-scanning entry
  stays until then.
- **DeepSource analysis lag**: the dashboard reflects the last analyzed
  commit; findings fixed in later commits clear on the next analysis pass.
  Verify with the MCP counts script pattern (see recipes) before assuming
  regression.
- **Mutation deep-runs**: verify the per-SHA conclusion; a green lane here
  is the strongest behavioral evidence.
- **Live mailbox validation**: the product was exercised live against the
  owner's test mailbox (probe sent and round-tripped; classification
  scheduler processing the backlog). Never commit account addresses,
  credentials or mailbox contents anywhere in this public repository - the
  owner explicitly requires this. `rr live-selftest` is the only sanctioned
  live-send entry point and it fails closed without send scope.
- **Release**: no tag/package cut yet. Packaging is the manual *Attested
  Windows package* workflow with an explicit `PACKAGE` confirmation; the
  signed flavor fails closed without administrator-provisioned signing.

## Operating recipes (exact)

- **Commits**: `python tools/connector_commit.py --message "$(cat msgfile)"
  --set path=path ...` - enforces the verified contributor identity,
  normalizes text to LF (git clean-filter semantics; bypassing this caused
  whole-file phantom diffs and two red lanes once), and fails closed on
  missing files. Never commit with a random identity.
- **Gate**: `python tools/local_ci.py` must print `ALL GATES GREEN` before
  any push. Never chain the gate and `git push` in one command (push runs
  regardless of gate outcome). Never run two cargo builds in one target
  directory concurrently (E0460 "invalid metadata" is a build race, not
  corruption). Use `CARGO_BUILD_JOBS=4` locally. A background process
  running `target/debug/rr.exe` PE-locks the binary and fails `cargo test`
  relink ("failed to remove file") - run long-lived binaries from a copied
  path outside the target tree.
- **Package manifest**: after ANY change under `tools/contract/`, recompute
  the sha256 entries in `tools/contract/PACKAGE-MANIFEST.json`. The
  invariant test (`test_reference_package_matches_manifest`) fails exactly
  this drift.
- **DeepSource**: API access via the MCP endpoint with the token from the
  CLI session (`~/.deepsource/config.toml`); never print or commit the
  token. Policy (owner-set, 2026-10-29): every finding is fixed at source
  by professional rewrite; **suppressions of any kind are banned** — no
  ignore rules, no `report_false_positive` dispositions, no code-scanning
  dismissals. Genuinely unsolvable findings stay open and are listed in
  `docs/deepsource-dispositions.md`. Analyzer outages/slowness are waited
  out, never worked around.
- **Python**: line length 120 (documented, dated S02 exception with
  compensating controls; rationale block in `.ruff.toml`). Digests and
  pinned hashes are computed over LF bytes (the connector normalizes).
- **Subagents**: harvest every completion explicitly (report file +
  transcript `final` block) before building on the work; see
  `docs/LESSONS.md`. Silence is not completion.
- **Architecture invariants** (never weaken): at-most-once delivery,
  deterministic rejection gate (model output alone never authorizes
  sending), fail-closed emergency stop, encrypted SQLite payloads,
  Human-review default with sending disabled.

## Evidence index

| Artifact | Contents |
|---|---|
| `engineering.toml` + `tools/check_engineering_policy.py` | S01 policy record and read-only validator |
| `tools/contract/` | execution-receipt contract: validator, schemas, synthetic examples, 48-test suite, hash-pinned manifest |
| `docs/audit-*.md` (4 files) | claim-by-claim manual verification with evidence |
| `docs/deepsource-dispositions.md` | findings policy: fix at source, never suppress; accepted-open list |
| `docs/scale-campaign-report.md` | 1,032-case corpus results and the two product root causes |
| `docs/model-scale-report.md` | live model evidence incl. the evidence-identity header |
| `docs/TESTING.md`, `docs/OPERATIONS.md` | test and operations runbooks |
| `docs/LESSONS.md` | failure-derived generic engineering rules |
