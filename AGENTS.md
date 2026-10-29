# AGENTS.md

Operational map for automated contributors. Read this first; do not re-derive
the layout. The in-repo skill `.agents/skills/rr-engineering/SKILL.md` holds the
full engineering discipline. `docs/HANDOVER.md` records the current verified
state, open items and the exact operating recipes (commits, gate, DeepSource,
manifest) - read it before non-trivial work.

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

```text
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

## Research-first mandate (all AI agents) — non-negotiable

Before implementing ANY new feature, library, tool, protocol, or non-trivial
logic — even when the operator did not ask — NEVER start by writing code.
Search in this order and stop at the first hit that fits:

1. **Harness capabilities first.** Enumerate the tools, skills, and plugins
   already available to the coding agent (tool catalog, skills list, installed
   CLIs, MCP servers) and use one if it fits — even if it must first be
   installed or enabled. Reusing the harness beats adding a new dependency.
2. **Community / online research next.** Search for existing crates, libraries,
   CLIs, or community tools that already do it. Prefer a mature, well-maintained
   dependency over hand-rolling.
3. **Build from scratch only as a last resort** when nothing suitable exists —
   and record why.

This is a hard rule: it saves tokens, reuses battle-tested code, and yields more
stable, professional results than reinventing it badly. Verify the chosen
tool/crate's real API and current version before use (Verification discipline
§2), and name the alternatives you rejected when the choice is non-obvious.

## Token-efficiency contract (all AI agents)

1. Read `AGENTS.md` and `.agents/skills/rr-engineering/SKILL.md` first; never
   walk the tree to re-derive structure. Mandatory skills: `caveman` (lite
   compression), `cocoindex-code-search` (semantic search discipline),
   `crawl4ai-research` (web research grounding), `rr-engineering` (safety).
2. Batch independent tool calls into one turn; prefer grep/search over full
   file reads; keep any single read under 200 lines unless editing that file.
3. Keep tool outputs small: filter with grep/awk before printing; never dump
   raw build logs; print only error lines and counts.
4. Make targeted edits (patch-style) instead of rewriting whole files.
5. Do not re-read a file to verify an edit a tool already confirmed.
6. Root-cause once, then scan sibling code paths for the same pattern instead
   of rediscovering the bug file by file.

## Verification discipline (all AI agents)

Never assume — verify against live sources, then re-verify after changes.

1. State facts only from tool output run this turn (CI status, versions,
   signatures, file contents) — never from memory, training data, or a
   stale result from an earlier turn.
2. Check the ACTUAL API signature / package index / upstream issue thread
   before using or installing anything. Assumed shapes break builds
   (two Trainer API breaks this way).
3. Version families: read the upstream issue tracker before debugging a
   failure. Known-broken families get swapped, not patched with flags.
4. After every push: confirm which workflows ran AND why any were skipped
   (path filters). A skipped lane is not a green lane — a change outside a
   lane's paths needs that lane's equivalent verified locally or by a lane
   that does cover those paths.
5. Platform-gated code needs platform-gated imports; verify with the CI's
   view (warnings denied, Linux + Windows) before claiming green.
6. Every claim in a report carries its evidence (SHA, run id, count).
   One verified fact beats ten plausible sentences; skip restating context.
   Caution costs one tool call — assumptions cost a crash.
7. Hardware-API thread affinity: accelerator/GPU APIs are called only from
   the thread that owns the workload. Probe from a side thread and the
   driver bridge races you (flaky probes, teardown hangs). Sample in a
   per-step callback on the owner thread and share the reading as data.
8. Read correction/withdrawn comments in issue threads before concluding —
   the scariest report may be retracted as the reporter's own harness bug.
   And `merged` != `shipped in your release`: verify the fix commit is in
   the tag/branch you actually run.
9. Programmatic (regex/generated) edits are untrusted until re-read: they
   can silently no-op or swallow a neighboring definition. After every one,
   grep the result and confirm definition-before-use order by line number.
10. `cmd | tail` reports tail's exit code, not cmd's. Run verification
    commands un-piped (or check PIPESTATUS) before claiming green.

## Coverage doctrine (all AI agents)

The goal is **not a single uncovered line of product code** — 100% line
coverage of the measured areas (Rust src/ and the Python operator tooling in
scripts/). This is a standing goal, not a CI gate: `--fail-under` thresholds
exist only as regression floors. Rules:

1. Only logical product code is measured and tested — never test code, never
   tests of tests.
2. Tests must be meaningful: they should fail if the code becomes subtly
   wrong (wrong order, off-by-one, dropped validation), not merely execute
   lines.
3. Every uncovered line left in a changed area must have a written reason
   (unreachable, platform-gated, or rendering glue).

## Findings policy (all AI agents) — fix at source, never suppress

Non-negotiable, owner-set policy (`docs/deepsource-dispositions.md` is the
full statement):

1. Every static-analysis finding (DeepSource, code scanning, linters) is
   fixed at source by a complete, professional rewrite — the rule's pattern
   must stop existing because the code became better.
2. **Never create a suppression of any kind**: no DeepSource ignore rules,
   no `report_false_positive` dispositions, no code-scanning dismissals
   ("false positive" or "won't fix"), no analyzer-silencing attributes.
   A previous suppression found anywhere is deleted on sight.
3. A finding that genuinely cannot be solved (external registration,
   deliberate governance decision) stays **open and listed** in
   `docs/deepsource-dispositions.md` — never hidden. Two or three such
   findings are acceptable.
4. Analyzer outages and slow analysis are waited out. Poll patiently; never
   escalate to support and never compensate with a suppression.

## Lessons learned (all AI agents)

Read `docs/LESSONS.md` before starting non-trivial work. It is a sanitized,
repo-wide record of generic engineering rules distilled from past failures —
each rule exists because it previously caused a real defect. Update it when
a genuinely new failure class appears (generic rules only: never incident
detail, personal data, or machine specifics — this repository is public).

## Definition of done

Local suite green (fmt, clippy, all tests, `tests/release`) AND pushed AND remote
workflows green on `main` AND CodeQL/Scorecard alerts re-checked via `gh api`.
Never report completion from local results alone.
