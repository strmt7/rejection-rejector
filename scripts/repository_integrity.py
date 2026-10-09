"""Inspect committed text and retain a bounded, reproducible Git history audit.

Standard-library CI/operator tooling only; never executes repository source,
rewrites history, changes tracked files, publishes releases or sends emails.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

TEXT_SUFFIXES = frozenset({
    ".rs", ".toml", ".md", ".json", ".yml", ".yaml", ".ps1", ".sh", ".py",
    ".xml", ".manifest", ".txt", ".lock", ".wxs", ".wxi",
})
TEXT_NAMES = frozenset({".gitignore", ".gitattributes", ".editorconfig", "LICENSE", ".env.example"})
MAX_TEXT_BYTES = 8 * 1024 * 1024
REVISION = re.compile(r"(?:[0-9a-f]{40}|HEAD(?:\^|~[0-9]{1,3})?)\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")


class AuditError(RuntimeError):
    """An incomplete audit cannot pass the integrity check."""


def git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, timeout=120, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AuditError("Git audit command did not complete") from error
    if result.returncode:
        raise AuditError(f"Git audit command failed (exit {result.returncode})")
    return result.stdout


def resolve(root: Path, revision: str) -> str:
    if not REVISION.fullmatch(revision):
        raise AuditError("Expected an exact commit SHA or a bounded HEAD revision")
    value = git(root, "rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode("ascii").strip()
    if not SHA.fullmatch(value):
        raise AuditError("Git returned an invalid commit identity")
    return value


def is_text(path: str) -> bool:
    name = PurePosixPath(path)
    return name.suffix.lower() in TEXT_SUFFIXES or name.name in TEXT_NAMES


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def inspect_text(path: str, data: bytes) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    def add(code: str, severity: str = "error") -> None:
        findings.append({"path": path, "code": code, "severity": severity})

    if len(data) > MAX_TEXT_BYTES:
        add("text_size_limit")
        return findings
    if b"\0" in data:
        add("nul_bytes_or_utf16_fragment")
    if data.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        add("unexpected_byte_order_mark")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        add("invalid_utf8")
        return findings
    if any(ord(c) < 32 and c not in "\t\r\n" for c in text) or "\x7f" in text:
        add("unescaped_control_character")
    if "\r" in text.replace("\r\n", ""):
        add("bare_carriage_return")
    if "\r\n" in text:
        add("noncanonical_crlf", "warning")
    if text and not text.endswith("\n"):
        add("missing_final_newline", "warning")
    if PurePosixPath(path).suffix.lower() == ".md" and re.search(r"(?m)^#\s+Commit\s+\d+\s*$", text):
        add("commit_count_padding")
    if findings and any(f["severity"] == "error" for f in findings):
        return findings
    try:
        suffix = PurePosixPath(path).suffix.lower()
        if suffix == ".toml" or PurePosixPath(path).name == "Cargo.lock":
            tomllib.loads(text)
        elif suffix == ".json":
            json.loads(text, object_pairs_hook=unique_object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        elif suffix == ".py":
            ast.parse(text, filename=path)
    except (ValueError, SyntaxError):
        add("invalid_structured_text")
    return findings


def inspect_tree(root: Path, revision: str) -> tuple[list[dict[str, str]], int]:
    findings: list[dict[str, str]] = []
    count = 0
    for record in git(root, "ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
        if not record:
            continue
        try:
            info, raw_path = record.split(b"\t", 1)
            mode, kind, sha = info.decode("ascii").split()
            path = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError) as error:
            raise AuditError("Invalid repository tree record") from error
        if not is_text(path):
            continue
        count += 1
        if kind != "blob" or mode not in {"100644", "100755"}:
            findings.append({"path": path, "code": "nonregular_source_file", "severity": "error"})
            continue
        size = int(git(root, "cat-file", "-s", sha).strip())
        if size > MAX_TEXT_BYTES:
            findings.append({"path": path, "code": "text_size_limit", "severity": "error"})
            continue
        findings.extend(inspect_text(path, git(root, "cat-file", "blob", sha)))
    return findings, count


def audit_history(root: Path, revision: str, count: int) -> list[dict[str, Any]]:
    if not 1 <= count <= 100:
        raise AuditError("History count must be 1 through 100")
    resolved = resolve(root, revision)
    commits = git(root, "rev-list", "--first-parent", f"--max-count={count}", resolved).decode("ascii").splitlines()
    if len(commits) != count:
        raise AuditError("Full requested history is unavailable; use a full checkout or a smaller count")
    records = []
    for sha in commits:
        raw = git(root, "show", "-s", "--format=%H%x00%P%x00%cI%x00%B%x00%T", sha).decode("utf-8", errors="replace").rstrip("\n")
        identity, parents, date, message, tree = raw.split("\0", 4)
        subject = message.splitlines()[0] if message else ""
        if identity != sha:
            raise AuditError("Commit identity changed during audit")
        parent_list = parents.split()
        changes = []
        if parent_list:
            stats = git(root, "diff", "--numstat", "-z", "--no-renames", "--no-ext-diff",
                        "--no-textconv", parent_list[0], sha, "--")
        else:
            stats = git(root, "diff-tree", "--no-commit-id", "--numstat", "-z", "--no-renames",
                        "--no-ext-diff", "--no-textconv", "--root", "-r", sha)
        for row in stats.split(b"\0"):
            if not row:
                continue
            added, removed, path = row.decode("utf-8", errors="replace").split("\t", 2)
            changes.append({"path": path, "added": None if added == "-" else int(added),
                            "removed": None if removed == "-" else int(removed)})
        records.append({"commit": sha, "parents": parent_list, "committed_at": date,
                        "subject": subject, "message": message.rstrip("\n"), "tree": tree, "changed_files": changes,
                        "empty_change": not changes,
                        "commit_count_language": bool(re.search(r"commit (?:count|counting|goal|\d+ marker)|goal of \d+ commits", message, re.I))})
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--history-ref", default="HEAD")
    parser.add_argument("--history-count", type=int, default=100)
    parser.add_argument("--patch-file", type=Path)
    parser.add_argument("--snapshot-file", type=Path)
    parser.add_argument("--bundle-file", type=Path, help="Optional standalone Git history for a reproducible offline audit")
    args = parser.parse_args()
    try:
        head = resolve(args.root, "HEAD")
        history_head = resolve(args.root, args.history_ref)
        findings, inspected = inspect_tree(args.root, head)
        history = audit_history(args.root, history_head, args.history_count)
        report = {"schema_version": 1, "source_commit": head, "history_head": history_head,
                  "history_count": len(history), "text_files_inspected": inspected,
                  "findings": findings, "commits": history,
                  "scope": "Encoding/syntax checks and full commit inventory are not a semantic security review."}
        for path in (args.report, args.patch_file, args.snapshot_file, args.bundle_file):
            if path is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
        if args.patch_file is not None:
            patch = git(args.root, "log", "--first-parent", f"--max-count={args.history_count}",
                        "--format=fuller", "--patch", "--binary", "--no-renames", "--no-ext-diff", "--no-textconv", history_head, "--")
            args.patch_file.write_bytes(patch)
            report["patch_sha256"] = hashlib.sha256(patch).hexdigest()
        if args.snapshot_file is not None:
            git(args.root, "archive", "--format=zip", head, "-o", str(args.snapshot_file.resolve()))
            report["snapshot_sha256"] = hashlib.sha256(args.snapshot_file.read_bytes()).hexdigest()
        if args.bundle_file is not None:
            git(args.root, "bundle", "create", str(args.bundle_file.resolve()), "HEAD")
            report["bundle_sha256"] = hashlib.sha256(args.bundle_file.read_bytes()).hexdigest()
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        for finding in findings:
            print(json.dumps(finding, ensure_ascii=True))
        errors = sum(f["severity"] == "error" for f in findings)
        print(f"Inspected {inspected} committed text files and {len(history)} commits: {errors} errors")
        return 1 if errors else 0
    except (AuditError, OSError, ValueError) as error:
        print(f"Repository audit incomplete: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
