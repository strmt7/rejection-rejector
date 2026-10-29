# Static-Analysis Findings Policy — Fix at Source, Never Suppress

DeepSource analyzes every commit on `main` through the GitHub integration
([dashboard](https://app.deepsource.com/gh/strmt7/rejection-rejector)); code
scanning runs through GitHub's own lanes. This repository operates under a
single, standing policy for every finding both systems report.

## Policy (standing, non-negotiable)

1. **Every finding is fixed at source by a complete, professional code
   change.** Rewrites, not patches: the shape that triggers the rule must
   stop existing because the code became better, never because the rule was
   silenced.
2. **No suppressions. Ever.** No DeepSource ignore rules, no
   `report_false_positive` dispositions, no code-scanning dismissals (not
   "false positive", not "won't fix"), no `# noqa`/`#[allow]`-style analyzer
   silencing introduced to make a finding disappear. This applies to agents
   and humans alike.
3. **A finding that genuinely cannot be solved stays open.** Two or three
   unsolvable findings are acceptable; a silenced finding is not. "Cannot be
   solved" means the rule contradicts a hard external constraint (an
   external registration, a governance decision the repository deliberately
   follows). Such findings are listed below with the exact constraint —
   visible and open, not hidden.
4. **Analyzer outages and slow analysis are waited out**, not worked around.
   Poll; do not escalate; do not compensate with suppressions.
5. If a previous session or contributor left a suppression behind, deleting
   it is the first action. Historical suppression records the platform does
   not let us delete are rendered void by fixing their patterns at source;
   they must never be cited as precedent.

## Accepted-open findings (visible, unsolved by design)

These code-scanning alerts stay open because no code change can close them.
They are the acceptable "2 or 3" category; everything else must be fixed.

| Alert | Rule | Why it cannot be solved in code |
|---|---|---|
| #9 | `CIIBestPracticesID` | Requires the human owner to register the project at bestpractices.dev. No code change affects it; no agent can complete the registration. |
| #8 | `CodeReviewID` | Scorecard's code-review criterion assumes a PR-reviewed merging model; this repository deliberately follows a documented main-only policy (CONTRIBUTING.md). Closing it would mean changing the governance decision, not the code. |
| #7 | `MaintainedID` | Scorecard's maintenance metric is computed from an external snapshot cadence the repository cannot influence from code. |

## History of this policy

Earlier waves used false-positive dispositions and file-level ignore rules
for findings whose rules we judged misfiring. The owner cancelled that
entire approach on 2026-10-29: every ignore rule was deleted (15 rules,
verified zero remaining), both manually dismissed code-scanning alerts were
reopened, and every previously disposed pattern (`SCT-A000`, `RS-E1011`,
`RS-E1015`, `RS-A1008`, `RS-W1079`, `RS-W1217`, `BAN-B310`) was eliminated
at source by professional rewrites. The twelve historical DeepSource
disposition records cannot be deleted through the platform API on this
account type (`unsuppressIssueForTeam` is refused); their patterns are
gone, so they remain as inert history only.
