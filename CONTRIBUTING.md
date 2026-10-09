# Contributing and development policy

Rejection Rejector is developed by the repository owner directly on **`main`**. Normal maintainer development branches are not used for this project.

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
