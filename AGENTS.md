# AGENTS.md

Operational map for automated contributors. Read this first; do not re-derive
the layout. The in-repo skill `.agents/skills/rr-engineering/SKILL.md` holds the
full engineering discipline.

## What this is

Native Rust (egui/eframe) desktop app: job-rejection detection, local Ollama
drafting, human-review or gated automatic Gmail replies. Safety invariants:
at-most-once delivery, deterministic rejection gate (model output alone never
authorizes sending), fail-closed emergency stop, encrypted SQLite payloads.

## Layout

| Path | Contents |
|---|---|
| `src/` | library + `bin/` CLIs; `store.rs` delivery state machine, `vault.rs` crypto, `policy.rs` enterprise policy, `recovery.rs` + `recovery/` restore, `gui/` screens |
| `tests/` | integration tests; `tests/release/` Python operator-tool tests |
| `scripts/` | `build-windows.ps1`, `release_guard.py`, `repository_integrity.py`, `verify_package.py` |
| `docs/` | SETUP, ARCHITECTURE, TESTING, INTEGRATION, ENTERPRISE_POLICY, THREAT_MODEL |
| `fuzz/` | cargo-fuzz targets |

## Commands

```
cargo fmt --all --check
cargo test --locked --lib --no-default-features
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
python3 -m unittest discover -s tests/release -v
```

After any edit under `src/`, always run `cargo fmt --all` before committing.

## Conventions

- Actions pinned by full commit SHA with `# vX.Y.Z` comments; `persist-credentials: false`.
- Workflow-level `permissions` are read-only; write scopes live at job level.
- Every function carries a doc comment stating its input/output contract.
- `finish_send`-style writes use state+revision CAS guards and affected-row checks.
- No new web stack, hosted inference, or Python in the product; keep it local-first.
- Commit style: conventional commits (`fix:`, `ci:`, `docs:`, `refactor:`, `test:`).

## Token-efficiency contract (all AI agents)

1. Read `AGENTS.md` and `.agents/skills/rr-engineering/SKILL.md` first; never
   walk the tree to re-derive structure.
2. Batch independent tool calls into one turn; prefer grep/search over full
   file reads; keep any single read under 200 lines unless editing that file.
3. Keep tool outputs small: filter with grep/awk before printing; never dump
   raw build logs; print only error lines and counts.
4. Make targeted edits (patch-style) instead of rewriting whole files.
5. Do not re-read a file to verify an edit a tool already confirmed.
6. Root-cause once, then scan sibling code paths for the same pattern instead
   of rediscovering the bug file by file.

## Definition of done

Local suite green (fmt, clippy, all tests, `tests/release`) AND pushed AND remote
workflows green on `main` AND CodeQL/Scorecard alerts re-checked via `gh api`.
Never report completion from local results alone.
