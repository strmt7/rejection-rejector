---
name: rr-engineering
description: Use when changing rejection-rejector source, workflows, or release tooling. Safety invariants, root-cause-first debugging, and the push gate.
---

# rr-engineering

## Safety invariants (never weaken)

1. **At-most-once delivery**: every send path goes through `finish_send` with
   state+revision CAS guards and affected-row-count checks.
2. **Deterministic rejection gate**: unattended sending requires a literal
   rejection phrase in the current de-quoted message; model output never
   authorizes dispatch alone.
3. **Fail-closed emergency stop**: the outbound sentinel blocks every Gmail
   write independent of GUI/model/settings and is rechecked pre-dispatch.
4. **Encrypted payloads**: `vault.rs` is the only crypto boundary; nonces come
   from `fresh_nonce()` (OS CSPRNG), never literals.

## Root-cause-first debugging

- Reproduce before fixing; write the failing test first.
- For each bug ask: what invariant allowed this state? Fix the invariant, not
  the symptom; then scan for the same root cause in sibling code paths.
- Concurrency bugs: model the interleaving (crash between commit and dispatch,
  concurrent writers) and assert recovery outcomes, not just happy paths.

## Push gate (from git-push-gate discipline)

Before every push:
1. `cargo fmt --all` (a missing-indent line once failed CI `fmt --check`).
2. `cargo clippy --locked --all-targets --all-features -- -D warnings`.
3. `cargo test --locked` and `python3 -m unittest discover -s tests/release`.
4. Push, then watch `gh run list` until every workflow is green; re-check
   CodeQL/Scorecard alerts via `gh api repos/strmt7/rejection-rejector/...`.
5. Never claim done on local green alone; record SHAs and check counts.

## Token efficiency

- Read `AGENTS.md` and this skill instead of walking the tree.
- Batch tool calls; grep before reading whole files; keep `store.rs` reads
  targeted (2.9k lines).
- Prefer targeted `patch`-style edits over full-file rewrites.
