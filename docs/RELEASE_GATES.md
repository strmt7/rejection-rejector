# Source-bound release gates

The manual `Attested Windows package` workflow still requires `PACKAGE`. These changes do not publish a release, register a scheduled task, or authorize email delivery.

## Automated evidence

`scripts/release_guard.py evidence` checks six exact-commit workflows and five deep verification workflows. It queries each workflow separately, never filters out failed or cancelled runs, and validates the workflow file, name, repository, branch, event, run ID, attempt, commit, completion and timestamp. A running or absent result is not success. Evidence older than eight days or with an invalid/future timestamp is rejected.

Deep evidence must come from an ancestor of the release commit with unchanged source, tests, fuzz targets, build configuration, workflow configuration, operator scripts, Windows resources and embedded API/policy contracts. An older green run cannot certify subsequently changed program inputs. Documentation-only changes may reuse recent ancestor evidence. Full Git history is required. The five deep workflows have matching invalidation triggers, verified by offline tests.

The release workflow checks the checkout and remote main before and after collecting evidence. It repeats the check immediately before uploading the package. Initial and final machine-readable reports retain run IDs, attempts and source commits. A moving main blocks publication. There remains an unavoidable interval between the last external-state read and upload; this is not a distributed lock on GitHub.

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
