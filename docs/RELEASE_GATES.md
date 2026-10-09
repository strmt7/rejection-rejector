# Source-bound release gates

The manual `Attested Windows package` workflow still requires `PACKAGE`. These changes do not publish a release, register a scheduled task, or authorize email delivery.

## Automated evidence

`scripts/release_guard.py evidence` checks seven exact-commit workflows and five deep verification workflows. It queries each workflow separately, never filters out failed or cancelled runs, and validates the workflow file, name, repository, branch, event, run ID, attempt, commit, completion and timestamp. A running or absent result is not success. Evidence older than eight days or with an invalid/future timestamp is rejected.

Deep evidence must come from an ancestor of the release commit with unchanged source, tests, fuzz targets, build configuration, workflow and checkout/encoding configuration, operator scripts, Windows resources and embedded API/policy contracts. An older green run cannot certify subsequently changed program inputs. Documentation-only changes may reuse recent ancestor evidence. Full Git history is required. The five deep workflows have matching invalidation triggers, verified by offline tests.

The release workflow checks the checkout identity, rejects tracked-file modifications, and checks remote main before and after collecting evidence. The committed-source integrity workflow is a mandatory exact-commit gate, not an advisory badge. It repeats the check immediately before uploading the package. Initial and final machine-readable reports retain run IDs, attempts and source commits. A moving main blocks publication. There remains an unavoidable interval between the last external-state read and upload; this is not a distributed lock on GitHub.

## Independent executable audits

`scripts/release_guard.py audit` invokes `cargo audit bin` separately for every shipped executable, stores separate logs, and stops on any failing, missing or timed-out audit. A successful second executable cannot mask a failed first audit. The workflow explicitly checks the script's exit status before continuing.

## Operator commands

From a full checkout of the release commit, with the GitHub CLI authenticated using read-only repository/Actions permissions:

```powershell
python scripts/release_guard.py evidence --repository strmt7/rejection-rejector --commit <40-character-source-SHA> --output artifacts/release-evidence.json
python scripts/release_guard.py audit --output artifacts target/release/rejection-rejector.exe target/release/rr.exe
python -m unittest discover -s tests/release -v
```

Python is standard-library CI/operator tooling only. The Rust desktop and CLI do not require a Python runtime. Tests use synthetic Git repositories and mocked audits, not real email accounts or signing services.

## What green automation does not prove

The report deliberately does not establish owner-environment acceptance. Publisher signing still requires configured credentials and verified signatures on the actual package. Real Gmail consent/delivery, independently labelled private-mailbox evaluation, physical GPU behavior, Windows Narrator/IME/DPI testing, deployment acceptance and external audit remain separate evidence requirements described in `ENTERPRISE_READINESS.md`. Never describe these as completed merely because the automated gate is green.

## Hardening recorded in this development round

- Failed startup retains its runtime-session marker; cleanup takes the workspace lock and cannot erase a successor's marker.
- OAuth callback requests require complete bounded HTTP headers, a unique literal-loopback Host and no body; absolute deadlines and cancellation checks precede code exchange.
- Temporary HTTP JSON buffers and OAuth client/token material use explicit zeroizing ownership. This does not claim to wipe all copies inside third-party libraries, operating-system memory or swap.

## Stable public-API reference after the corruption incident

The public Rust API workflow compares both all-feature and no-feature configurations
against two explicit references: the immediate parent **and** the fixed, pre-corruption
`8d4ada1527635ced0c04fc27e753e9c3603d2646` milestone recorded in
`.cargo/semver-baseline.txt`. No failed comparison is ignored and there is no search
for a conveniently passing baseline. Missing ancestry, invalid baseline identity,
compilation failure or an API violation blocks the check. Logs retain both references.

On repaired commit `1f244ce`, current code built but its immediate parent `803fb0b`
still contained the malformed character literal in `mail.rs`; the resulting SemVer
failure was a **baseline build error**, not a demonstrated incompatibility. That
historical failure remains in the record. Subsequent commits have a buildable parent
and must additionally satisfy the fixed baseline, preventing incremental API drift.
Updating the fixed reference is an explicit, separately reviewed compatibility-policy
change; it is not a way to dismiss an unexpected failure.

## Package consistency boundary

The final ZIP must pass the read-only verifier before attestation and must retain
the same checksum through the final pre-upload verification. Each signature record
is bound to the corresponding packaged executable hash. Only `NotSigned` is
accepted in unsigned mode; every other non-valid status fails closed. Docs/scripts
are taken from the committed Git archive, not untracked workspace contents.
See [Package verification](PACKAGE_VERIFICATION.md) for the independent operator
procedure and the distinction between internal checksums and publisher trust.
