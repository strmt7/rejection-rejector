"""Fail-closed release evidence and executable audits; standard library only.

This is CI/operator tooling, not a runtime dependency of the Rust application.
Never dispatch workflows, enable sending, or manufacture acceptance evidence.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode

EXACT = {
    "ci.yml": "Rust CI",
    "semver.yml": "Rust public API compatibility",
    "supply-chain.yml": "Supply-chain security",
    "codeql.yml": "CodeQL Rust security",
    "scorecard.yml": "OpenSSF Scorecard",
    "workflow-lint.yml": "Workflow static analysis",
    "repository-integrity.yml": "Repository integrity",
}
DEEP = {
    "fuzz.yml": "Rust fuzzing",
    "coverage.yml": "Rust coverage",
    "mutation.yml": "Mutation testing",
    "enterprise-deep-verification.yml": "Enterprise deep verification",
    "reproducibility.yml": "Windows reproducibility",
}
# Keep this conservative; workflow-trigger tests ensure it cannot outgrow CI.
INPUT_PREFIXES = ("src/", "tests/", "fuzz/", "scripts/", "config/", ".cargo/", ".github/", "windows/")
INPUT_FILES = frozenset({
    "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml",
    "rustfmt.toml", ".rustfmt.toml", "deny.toml",
    ".gitattributes", ".gitignore", ".editorconfig",
    "docs/openapi-v1.json", "docs/openapi-v1-baseline.json",
    "docs/enterprise-policy.schema.json",
})
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+\Z")
MAX_EVIDENCE_AGE = timedelta(days=8)
MAX_CLOCK_SKEW = timedelta(minutes=5)
PROJECTION = (
    ".workflow_runs | map({id,name,path,head_sha,head_branch,status,conclusion,"
    "event,run_attempt,updated_at,html_url,head_repository:.head_repository.full_name})"
)


class GateError(RuntimeError):
    """Terminal, actionable failure. Upstream response bodies are not echoed."""


class PendingEvidence(GateError):
    """A check is absent or incomplete, so the bounded wait may retry."""


def checked_output(args: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                                errors="strict", timeout=timeout, check=False)
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise GateError(f"Could not complete {args[0]} safely") from error
    if result.returncode:
        raise GateError(f"{args[0]} exited with code {result.returncode}")
    return result.stdout


def affects_evidence(path: str) -> bool:
    return path.startswith(INPUT_PREFIXES) or path in INPUT_FILES


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise GateError("Evidence timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise GateError("Evidence timestamp is invalid") from error
    if parsed.utcoffset() is None:
        raise GateError("Evidence timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def validate_run(run: dict[str, Any], workflow: str, repository: str,
                 commit: str, now: datetime) -> None:
    expected_name = {**EXACT, **DEEP}[workflow]
    if (run.get("name") != expected_name
            or run.get("path") != f".github/workflows/{workflow}"
            or run.get("head_branch") != "main"
            or run.get("head_repository") != repository
            or run.get("event") not in {"push", "schedule", "workflow_dispatch"}):
        raise GateError(f"{workflow}: untrusted workflow/repository/ref/event identity")
    run_id, attempt = run.get("id"), run.get("run_attempt")
    if (type(run_id) is not int or run_id <= 0
            or type(attempt) is not int or attempt <= 0):
        raise GateError(f"{workflow}: invalid run identity")
    head = run.get("head_sha")
    if not isinstance(head, str) or not SHA.fullmatch(head):
        raise GateError(f"{workflow}: invalid evidence commit")
    if workflow in EXACT and head != commit:
        raise GateError(f"{workflow}: evidence belongs to another commit")
    if run.get("status") != "completed":
        raise PendingEvidence(f"{workflow}: latest run is not complete")
    if run.get("conclusion") != "success":
        raise GateError(f"{workflow}: latest run did not succeed")
    age = now - parse_time(run.get("updated_at"))
    if age < -MAX_CLOCK_SKEW or age > MAX_EVIDENCE_AGE:
        raise GateError(f"{workflow}: evidence timestamp is stale or in the future")


def assert_unchanged_inputs(base: str, head: str,
                            execute: Callable[[list[str]], str] = checked_output) -> None:
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise GateError("Invalid commit for source comparison")
    # Full checkout history is mandatory. Missing or non-ancestor commits fail closed.
    execute(["git", "merge-base", "--is-ancestor", base, head])
    changed = execute(["git", "diff", "--name-only", "--no-renames", "-z", base, head, "--"])
    invalidating = [p for p in changed.split("\0") if p and affects_evidence(p)]
    if invalidating:
        raise GateError("Deep evidence predates changed build/test inputs; rerun the workflow on main")


def latest_run(repository: str, workflow: str, commit: str,
               execute: Callable[[list[str]], str] = checked_output) -> dict[str, Any]:
    params = {"branch": "main", "per_page": "1"}
    if workflow in EXACT:
        params["head_sha"] = commit
    endpoint = f"repos/{repository}/actions/workflows/{workflow}/runs?{urlencode(params)}"
    raw = execute(["gh", "api", endpoint, "--jq", PROJECTION])
    try:
        rows = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise GateError(f"{workflow}: invalid GitHub response") from error
    if not isinstance(rows, list) or len(rows) > 1:
        raise GateError(f"{workflow}: ambiguous GitHub response")
    if not rows:
        raise PendingEvidence(f"{workflow}: no matching run exists")
    if not isinstance(rows[0], dict):
        raise GateError(f"{workflow}: malformed run")
    # Do not filter for success: a newer failure/cancellation must mask old greens.
    return rows[0]


def check_main(repository: str, commit: str,
               execute: Callable[[list[str]], str] = checked_output) -> None:
    if execute(["git", "rev-parse", "HEAD"]).strip() != commit:
        raise GateError("Checkout does not match the release commit")
    # A matching HEAD is insufficient if a build or operator changed tracked files.
    execute(["git", "diff", "--exit-code", "HEAD", "--"])
    remote = execute(["gh", "api", f"repos/{repository}/git/ref/heads/main", "--jq", ".object.sha"])
    if remote.strip() != commit:
        raise GateError("main moved during release validation; use the new head")


def collect_evidence(repository: str, commit: str, now: datetime,
                     execute: Callable[[list[str]], str] = checked_output) -> dict[str, Any]:
    if (not REPO.fullmatch(repository) or repository.split("/")[-1] in {".", ".."}
            or not SHA.fullmatch(commit)):
        raise GateError("Invalid repository or release commit")
    check_main(repository, commit, execute)
    evidence = []
    for workflow in {**EXACT, **DEEP}:
        run = latest_run(repository, workflow, commit, execute)
        validate_run(run, workflow, repository, commit, now)
        if workflow in DEEP:
            assert_unchanged_inputs(run["head_sha"], commit, execute)
        evidence.append({"workflow": workflow, "run_id": run["id"],
                         "run_attempt": run["run_attempt"], "commit": run["head_sha"],
                         "updated_at": run["updated_at"], "conclusion": "success"})
    check_main(repository, commit, execute)
    return {"schema_version": 1, "repository": repository, "source_commit": commit,
            "checked_at": now.isoformat(), "automated_evidence": evidence,
            "owner_environment_acceptance": "not established by automated workflow evidence"}


def audit_binaries(paths: list[Path], output: Path,
                   run: Callable[..., Any] = subprocess.run) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise GateError(f"Expected regular release executable: {path.name}")
        try:
            result = run(["cargo", "audit", "bin", str(path)], capture_output=True,
                         text=True, encoding="utf-8", errors="strict", timeout=300, check=False)
        except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
            raise GateError(f"Binary audit did not complete: {path.name}") from error
        (output / f"{path.stem}-binary-audit.txt").write_text(
            result.stdout + result.stderr, encoding="utf-8")
        if result.returncode != 0:
            raise GateError(f"Binary audit failed: {path.name} (exit {result.returncode})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    evidence = sub.add_parser("evidence")
    evidence.add_argument("--repository", required=True)
    evidence.add_argument("--commit", required=True)
    evidence.add_argument("--output", type=Path, required=True)
    evidence.add_argument("--wait-seconds", type=int, default=0)
    audit = sub.add_parser("audit")
    audit.add_argument("--output", type=Path, required=True)
    audit.add_argument("binaries", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        if args.action == "audit":
            audit_binaries(args.binaries, args.output)
            return 0
        if not 0 <= args.wait_seconds <= 900:
            raise GateError("Evidence wait must be between 0 and 900 seconds")
        deadline = time.monotonic() + args.wait_seconds
        while True:
            try:
                report = collect_evidence(args.repository, args.commit, datetime.now(timezone.utc))
                break
            except PendingEvidence as error:
                if time.monotonic() >= deadline:
                    raise
                print(str(error), file=sys.stderr, flush=True)
                time.sleep(min(15, max(0, deadline - time.monotonic())))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("All automated release evidence matches the source/build inputs.")
        return 0
    except GateError as error:
        print(f"Release blocked: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
