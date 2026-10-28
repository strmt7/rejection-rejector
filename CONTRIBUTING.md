# Contributing and development policy

Rejection Rejector changes land through **pull requests with review before merge**. The default branch is protected: force pushes and deletion are blocked and at least one approving review is required, so every accepted change carries explicit review evidence.

## Atomic main development

A logical multi-file change must reach `main` as one atomic commit/tree update whenever practical. Do not intentionally leave `main` in an intermediate state where only part of a refactor, schema/API change, or safety control has landed.

Each commit should be independently reviewable and preserve the repository's fail-closed safety invariants. Formatting-only corrections should not be mixed with unrelated behavior unless they are the formatter output for the same atomic round.

External contributors should open an issue with a patch/diff, reproducible test case, or proposed change. The maintainer can apply accepted changes atomically to `main`. Do not include secrets, real mailbox data, proprietary employer correspondence, model weights, or local recovery material.

## No commit quotas or manufactured progress

Do not add/remove temporary files, append commit-number markers, or split comments
into commits merely to increase a commit count. Each change must have a reviewable
purpose and appropriate evidence. Commit counts, comments and test counts are not
production-readiness certificates. Use explicit UTF-8 writes; Git line-ending
rules do not repair mixed character encodings. Preserve the failed historical
record and use forward fixes rather than rewriting history to conceal defects.

## Quality bar

Before a change is treated as release-quality:

- `cargo fmt --all -- --check` passes on the pinned Rust toolchain;
- locked core and all-feature tests pass;
- Clippy passes with `-D warnings`;
- public Rust API SemVer validation passes or a deliberate versioning decision is documented;
- supply-chain policy, RustSec audit, license/source policy and secret scanning pass;
- safety-critical changes have deterministic, concurrency, recovery, generative, fuzz or mutation coverage appropriate to the change;
- public HTTP/OpenAPI compatibility remains additive unless an API-version change is deliberate;
- no lint, test or security check is disabled merely to obtain a green build.

## Evidence rules for contributors

These are the same verification rules the project applies to its own automation and AI
assistants (see `AGENTS.md`); they apply to human contributions too:

- **A skipped lane is not a green lane.** If a CI workflow did not run for your change
  (path filters), run its equivalent locally and say so in the PR description, or touch
  the paths that trigger it. Never report a check as passing because its job was skipped.
- **Claims carry evidence.** Statements such as "tests pass", "the API is unchanged" or
  "the mutant was caught" should name the command, run id, commit SHA or count that
  proves them. One verified fact beats ten plausible sentences.
- **`cmd | tail` reports tail's exit code.** Run verification commands un-piped (or
  check `PIPESTATUS`) before declaring success.
- **Verify upstream shapes before depending on them.** Check the actual API signature,
  package index or issue thread of any tool you install; known-broken version families
  are swapped, not patched with flags.
- **Generated edits are untrusted until re-read.** After scripted or regex edits, grep
  the result and confirm definition-before-use order.

## Verification command map (engineering standard S03)

The engineering policy record [`engineering.toml`](engineering.toml) is the
machine-readable command contract; the table below is its human summary. The
wrapper scripts (`tools/local_ci.py`, `scripts/build-windows.ps1`) delegate to
these exact commands and propagate their exit codes; they never mask failures.

| Standard command | Native entry point |
|---|---|
| setup | `cargo fetch --locked` (external prerequisites in docs/SETUP.md) |
| format / format-check | `cargo fmt --all` / `cargo fmt --all -- --check` |
| lint | `cargo clippy --locked --all-targets --all-features -- -D warnings` |
| typecheck | `cargo check --locked --all-targets --all-features` |
| test-fast | `cargo test --locked --lib --no-default-features` |
| test-integration | `cargo test --locked --all-features` |
| test (operator tools) | `python -m unittest discover -s tests/release -v` |
| audit | `cargo audit --deny warnings` with the documented ignores; `cargo deny check advisories licenses bans sources` |
| build | `cargo build --locked --release --bins` |
| verify | `python tools/local_ci.py` |
| release-check | `python scripts/verify_package.py --expected-commit <sha> --signing-mode unsigned <package.zip>` |

Policy conformance is checked read-only with
`python tools/check_engineering_policy.py`. Execution receipts use the exact
schemas and validator vendored in [`tools/contract/`](tools/contract/); see
[docs/audit-common-standard.md](docs/audit-common-standard.md) for the
requirement-by-requirement verification record and open items.

## Documentation standards

- Documentation aims at a technically rigorous but broadly readable audience: define
  terms on first use, prefer concrete examples, keep precision.
- Follow the Diátaxis structure (tutorials / how-to guides / reference / explanation)
  and the Google developer documentation style guide where they do not conflict with
  this repository's safety terminology.
- When a maintainer supplies replacement text, change words only — never alter
  user-owned formatting, layout, or structure (`README.md` in particular is words-only).
- Keep doc comments in house style: one-line purpose plus `Inputs:` and `Output:`
  sections naming parameters and behavior.
- Documentation claims follow the same evidence rules as code: cite the source and the
  date it was checked for anything outside this repository.

## Enterprise design rules

- The model is advisory; Rust policy owns authorization and external-write decisions.
- Untrusted email is data, never instructions or executable content.
- Ambiguous external writes are reconciled, never blindly retried.
- Secrets remain in encrypted or OS-protected storage and must never be logged.
- Monitoring stays privacy-safe and label-bounded; no mailbox, employer or candidate data becomes metrics labels.
- New externally constructible public Rust structs must be designed for evolution. Prefer additive functions or versioned types over accidental breaking field additions.
- Runtime/model/tool upgrades are evaluated for this application's task and threat model, not adopted merely because they are newer.
- Emergency stop documentation: When modifying emergency-stop related code, ensure consistency across `emergency.rs`, `diagnostics.rs`, `/v1/health` endpoint, `rr doctor` command, GUI status bar, and enterprise readiness documentation.
- Diagnostic JSON stability: The `report_version` field in diagnostics output should be incremented when making breaking changes to the JSON structure, and release notes should document any changes to the diagnostic schema.

See [the operations runbook](docs/OPERATIONS.md), [threat model](docs/THREAT_MODEL.md), and [enterprise readiness gate](docs/ENTERPRISE_READINESS.md).

## Sources (checked 2026-10-12)

- Rust API Guidelines (naming, documentation and interoperability conventions for the
  public Rust surface): https://rust-lang.github.io/api-guidelines/
- Diátaxis documentation framework: https://diataxis.fr/
- Google developer documentation style guide: https://developers.google.com/style

## Git Workflow (commit attribution and history policy)

Adapted from the portfolio standard (strmt7/FlitzZip operating guide, Git
Workflow section) and verified against this repository's own history on
2026-10-28.

- Develop and publish on `main`; do not create a development branch or pull
  request without an explicit task-specific maintainer exception.
- For agent-assisted publication, create commits through the authenticated
  official GitHub connector (the GitHub API through the authenticated
  `gh` session - see `tools/connector_commit.py`) and let it assign the
  contributor identity. Verify the returned author and committer; do not
  substitute an automation identity, override attribution through environment
  variables, or change global Git configuration. If the connector cannot
  perform an operation, report its specific limitation before choosing
  another publication method.
- Rewriting published history requires explicit authorization, a verified
  recovery copy, complete history-invariant checks (trees, parents, both date
  fields and full message bytes identical; only the authorized identity fields
  changed) and an expected-head lease. Preserve the original identities of
  captured test results when commit IDs change: the 2026-10-28 identity
  rewrite's old-to-new commit mapping is retained as
  `docs/history-rewrite-mapping-2026-10-28.json`.
- Inspect `git status --short` before staging. Stage only intentional
  source/docs/config changes. Never use destructive commands such as
  `git reset --hard` or `git checkout --` unless a maintainer explicitly
  requests them.
- Before pushing, run the checks selected by `tools/local_ci.py`. After
  pushing, verify the remote URL does not contain credentials and observe the
  workflow results for the exact pushed SHA.
