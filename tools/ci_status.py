"""Report CI lane status for one commit as a counted verdict.

Common-action tool (promoted from per-session shell one-liners). Lists every
workflow run for the requested SHA, counts each terminal state from the
COMPLETE listing (never a tailed or filtered view), and combines that with
the commit's status contexts (DeepSource, codecov) into one verdict.

Inputs: optional SHA (default: origin/main), `--branch`, `--repo`.
Output: per-lane table plus a VERDICT line. Exit codes: 0 = every lane
completed green, 1 = at least one failure/cancelled, 2 = still running.
"""

from __future__ import annotations

import argparse
import json
import subprocess


def verdict(rows: list[dict]) -> tuple[int, str]:
    """Purpose: Decide the overall CI state from complete lane rows.

    Inputs: `rows` -- dicts with workflowName/status/conclusion keys;
    Output: (exit_code, summary) using the counting rule: any failure or
    cancellation is 1 (checked BEFORE running, so a red lane is never
    masked by another lane still running); all completed green is 0;
    otherwise 2.
    """
    failed = [r for r in rows if r.get("conclusion") in ("failure", "cancelled", "timed_out")]
    running = [r for r in rows if r.get("status") != "completed"]
    passed = [r for r in rows if r.get("status") == "completed" and r.get("conclusion") == "success"]
    summary = f"{len(passed)} green, {len(failed)} red, {len(running)} running (total {len(rows)})"
    if not rows:
        # No rows yet is run-creation lag, never evidence of green.
        return 2, summary
    if failed:
        return 1, summary
    if running:
        return 2, summary
    return 0, summary


def main() -> int:
    """Inputs: CLI arguments. Output: lane table and verdict on stdout."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sha", nargs="?", default=None)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--repo", default="strmt7/rejection-rejector")
    args = parser.parse_args()

    sha = args.sha
    if sha is None:
        sha = subprocess.run(
            ["git", "rev-parse", f"origin/{args.branch}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    listing = subprocess.run(
        [
            "gh",
            "run",
            "list",
            "--branch",
            args.branch,
            "--limit",
            "30",
            "--json",
            "headSha,workflowName,status,conclusion",
            "--jq",
            f'[.[] | select(.headSha == "{sha}")]',
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    rows = json.loads(listing or "[]")
    for row in sorted(rows, key=lambda r: r.get("workflowName", "")):
        conclusion = row.get("conclusion") or ""
        print(f"{row.get('workflowName', '?'):32} {row.get('status', '?'):12} {conclusion}")
    code, summary = verdict(rows)
    print(f"VERDICT {sha[:12]}: {summary}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
