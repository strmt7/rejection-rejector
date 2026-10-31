r"""Commit the worktree's changed files as one connector wave.

Common-action tool (promoted from per-session scratch drivers). Collects
modified, untracked and deleted paths from `git status --porcelain`, builds
the content-based `tools/connector_commit.py` invocation (one `--set` per
present file, one `--delete` per absent path), and prints the created
commit's SHA and connector-assigned identity. Path lists are written and
expanded LF-safe: a CRLF round-trip turns every path into a phantom
`--delete "path\\r"` and the trees API rejects it only as a cryptic 422.

Inputs: `--message-file` with the commit message; optional `--dry-run`
(print the operations without committing); optional `--repo`, `--branch`.
Output: the connector's commit SHA and identity readback on stdout.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_PARTS = ("__pycache__",)
SKIP_SUFFIXES = (".pyc", ".pyo")


def _skippable(path: str) -> bool:
    """Purpose: Recognize compiled-cache rows that never commit.

    Inputs: status path;
    Output: True for cache artifacts.
    """
    return any(part in path for part in SKIP_PARTS) or path.endswith(SKIP_SUFFIXES)


def _well_formed(path: str) -> bool:
    """Purpose: Validate one status path shape.

    Inputs: candidate path;
    Output: True when non-empty, trimmed and control-character free.
    """
    return bool(path) and path.strip() == path and not any(ord(character) < 32 for character in path)


def _operation_for(status: str, path: str, exists) -> tuple[str, str]:
    """Purpose: Map one status row to its connector operation.

    Inputs: the two-character porcelain status, the path, and a path
    predicate deciding `--set` (present) vs `--delete` (absent);
    Output: (kind, path) with kind in {"set", "delete"}; raises ValueError
    on unhandled statuses or a pending deletion whose file is still present.
    """
    deleted = "D" in status
    changed = "M" in status or "A" in status or "R" in status or "C" in status
    if not (deleted or changed or status == "??"):
        raise ValueError(f"unhandled status {status!r} for {path!r}")
    if deleted and exists(path):
        # A deleted-but-present path is a pending deletion the connector
        # cannot express (its --delete needs the file absent locally);
        # refusing beats silently re-uploading the file.
        raise ValueError(f"deletion pending but file still present: {path!r}")
    return ("delete" if deleted else "set", path)


def collect_operations(porcelain: str, exists) -> list[tuple[str, str]]:
    """Purpose: Classify git status rows into connector file operations.

    Inputs: `porcelain` -- `git status --porcelain -uall` output; `exists` --
    a path predicate deciding `--set` (present) vs `--delete` (absent);
    Output: ordered (kind, path) pairs with kind in {"set", "delete"};
    raises ValueError on an unhandled status or a malformed path.
    """
    operations: list[tuple[str, str]] = []
    for line in porcelain.splitlines():
        if not line.strip():
            continue
        status, path = line[:2], line[3:]
        if _skippable(path):
            continue
        if not _well_formed(path):
            raise ValueError(f"malformed status row: {line!r}")
        operations.append(_operation_for(status, path, exists))
    return operations


def main() -> int:
    """Inputs: CLI arguments. Output: connector commit readback; exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message-file", required=True, type=pathlib.Path)
    parser.add_argument("--repo", default="strmt7/rejection-rejector")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    message = args.message_file.read_text(encoding="utf-8").strip()
    if not message:
        raise ValueError("commit message is empty")
    git = shutil.which("git")
    if git is None:
        raise ValueError("git is not installed or not on PATH")
    status = subprocess.run(
        [git, "-C", str(ROOT), "status", "--porcelain", "-uall"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    operations = collect_operations(status, lambda rel: (ROOT / rel).is_file())
    if not operations:
        print("working tree clean; nothing to commit")
        return 0
    for kind, path in operations:
        print(f"{kind:6} {path}")
    if args.dry_run:
        return 0
    command = [
        sys.executable,
        str(ROOT / "tools" / "connector_commit.py"),
        f"--message={message}",
        f"--repo={args.repo}",
        f"--branch={args.branch}",
    ]
    for kind, path in operations:
        if kind == "set":
            command.append(f"--set={path}={ROOT / path}")
        else:
            command.append(f"--delete={path}")
    completed = subprocess.run(command, check=False, cwd=str(ROOT), capture_output=True, text=True)
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
