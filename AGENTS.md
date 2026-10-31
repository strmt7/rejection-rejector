# AGENTS.md

Operational doctrine for automated contributors. Judgment rules only —
derivable facts live in the repo. Read this first, then
`docs/HANDOVER.md` (verified state + operating recipes) before non-trivial
work, and `.agents/skills/rr-engineering/SKILL.md` for the full engineering
discipline. Enforced rules also live as executable checks in
`tests/release/test_agent_doctrine.py` — prose is not enforcement.

## What this is

Rejection Rejector: local-first email-rejection detection and reply engine.
Surface: `rr` CLI, `rr tui`, `rr web` (loopback console), `rr-tray`
(Windows tray shell). Safety invariants: at-most-once delivery, the
deterministic rejection gate (model output alone never authorizes sending),
fail-closed emergency stop, encrypted SQLite payloads, human review as the
default mode.

## Layout and commands

Discoverable from the tree and `docs/ARCHITECTURE.md`; do not re-derive
from memory. The single gate is `python tools/local_ci.py` (read its
printed verdict; run it AFTER the last edit). After any `src/` edit run
`cargo fmt --all` before committing. Commits go through
`tools/connector_commit.py` or `tools/commit_wave.py`.

## Conventions

- Actions pinned by full commit SHA with `# vX.Y.Z` comments;
  `persist-credentials: false`; workflow-level `permissions` read-only.
- Every function carries a doc comment stating its input/output contract.
- `finish_send`-style writes use state+revision CAS guards and
  affected-row checks. No new web stack, hosted inference, or Python in
  the product; keep it local-first. Conventional commit style.

## Research-first mandate (all AI agents) — non-negotiable

Before implementing ANY new feature, library, tool, protocol, or
non-trivial logic — even when unasked — never start by writing code.
Search in order, stopping at the first fit: (1) harness capabilities
(tools, skills, plugins, MCP servers; install/enable if needed), (2)
community crates/CLIs (a mature dependency beats hand-rolling), (3) build
from scratch only as a last resort and record why. Verify the chosen
tool's real API and current version before use, and name rejected
alternatives when the choice is non-obvious.

- Use the self-hosted [Crawl4AI research tool](docs/crawl4ai.md) for web
  research: index and search for broad concepts first, then verify the
  exact source before implementing.

## Tool-call economy (all AI agents) — monitor, learn, promote

Continuously watch your own tool calls, repetitive actions and mistakes;
turn the recurring ones into durable assets instead of re-deriving them at
model-token cost.

1. **Search `tools/` and `tests/` before building anything.** Existing
   repo tools are canonical; a re-derived client beside one is waste.
2. **Promote at the third occurrence** (3+ times per session, or the
   second cross-session scratch re-derivation) into a small tested
   `tools/` script. Promote actions, not accidents.
3. **Never ship one-off tools.** Single-use helpers stay in scratch.
   Promoted tools obey every standing rule (host-agnostic, Inputs/Output
   docstrings, pinning tests, ruff clean, zero embedded secrets or account
   identifiers — credentials come from env/config at runtime) and must be
   referenced by a test (enforced).
4. **Record the mistake class in `docs/LESSONS.md`**, not the incident.
5. **Snapshot first, reason second, tools on demand.** Batch state
   gathering into ONE deterministic pass, then reason. Software retrieves,
   joins, filters and calculates; the LLM interprets.
6. **A new fast path REPLACES the old slow path** — never stacks in front
   of it (an agent shown both runs both).
7. **Output discipline:** findings, anomalies, implications and decisions
   — never restate data the reader just received.

## Token-efficiency contract (all AI agents)

Read this file and the skill first; never walk the tree to re-derive
structure. Caveman and CocoIndex are mandatory for every session: load
`.agents/skills/caveman/SKILL.md` and
`.agents/skills/cocoindex-code-search/SKILL.md` before work; also load
the `crawl4ai-research` and `rr-engineering` skills when relevant.
Batch independent tool calls; prefer
grep/search over full reads (keep single reads under 200 lines unless
editing); filter tool outputs to error lines and counts; make targeted
edits; never re-read what a tool already confirmed; root-cause once, then
scan sibling code paths for the same pattern.

## Verification discipline (all AI agents)

Never assume — verify against live sources, then re-verify after changes.

1. State facts only from tool output run this turn (CI status, versions,
   signatures, contents) — never from memory or stale results.
2. Check the ACTUAL API signature / package index / upstream issue thread
   before using or installing anything. Version families: read the
   upstream issue tracker before debugging; known-broken families get
   swapped, not patched with flags.
3. After every push: confirm which workflows ran AND why any were
   skipped (path filters). A skipped lane is not a green lane.
4. Platform-gated code needs platform-gated imports; verify with the CI's
   view (warnings denied, Linux + Windows) before claiming green.
5. Every claim carries its evidence (SHA, run id, count). One verified
   fact beats ten plausible sentences; caution costs one tool call while
   assumptions cost a crash.
6. Accelerator/GPU APIs are called only from the thread that owns the
   workload; sample in a per-step callback and share readings as data.
7. Read correction/withdrawn comments before concluding; `merged` is not
   `shipped` — verify the fix commit is in the tag/branch you run.
8. Programmatic edits are untrusted until re-read (silent no-ops,
   swallowed neighbors); grep the result and confirm definition-before-use.
9. `cmd | tail` reports tail's exit code — verify un-piped.
10. Self-reported completion (yours or a subagent's) is a hypothesis:
    require harness-executed evidence after the last edit (command, exit
    code, output) and read remote state back after every mutation.

## Coverage doctrine (all AI agents)

Standing goal: not a single uncovered line of product code (Rust `src/`
and the Python tooling), never a CI gate — thresholds are regression
floors. Measure only logical product code. Tests must fail when code
becomes subtly wrong, not merely execute lines. Every uncovered line left
in a changed area carries a written reason.

## Findings policy (all AI agents) — fix at source, never suppress

Non-negotiable, owner-set (`docs/deepsource-dispositions.md` is the full
statement):

1. Every static-analysis finding is fixed at source by a complete,
   professional rewrite — the pattern must stop existing.
2. **Never create a suppression of any kind** (ignore rules, false-positive
   dispositions, dismissals, silencing attributes); an existing one is
   deleted on sight.
3. Genuinely unsolvable findings stay **open and listed** in the
   dispositions doc — never hidden; two or three are acceptable.
4. Analyzer outages and slow analysis are waited out patiently; never
   escalate and never compensate with a suppression.

## Dependency maintenance (all AI agents) — dependabot alerts and PRs

Every dependabot alert and PR is checked and applied/addressed — but only
after verifying it introduces no dependency conflicts and no other
problems in the repository. Triage every open security alert; apply the
patched version only after confirming compatibility with the pinned
toolchain and the graph, resolving conflicts first. Verify version bumps
are genuine (action SHAs resolve to the claimed tag; packages match the
registry), apply on top of current `main`, and gate-validate like any
change; when the identical change lands on `main` directly, let dependabot
close its PR (or close it citing the landed commit) — never merge stale
duplicates, never merge red, never drop an alert.

## Lessons learned (all AI agents)

Read `docs/LESSONS.md` before non-trivial work: generic rules distilled
from real defects. Update it when a genuinely new failure class appears
(generic rules only — never incident detail, personal data, or machine
specifics; this repository is public).

## Definition of done

Local gate green AND pushed AND remote workflows green on `main` (counted
from the complete listing) AND CodeQL/Scorecard/DeepSource re-checked.
Completion claims carry the evidence; never report done from local results
alone.
