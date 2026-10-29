#!/usr/bin/env python3
"""Read-only validator for Rejection Rejector gate/CI execution receipts.

Why: shared requirement S15 demands a machine-readable completion receipt, and
the engineering manual's proposed execution-receipt validator showed how to
check one for internal consistency. This is the repo-scoped adaptation: it
validates one gate/CI execution receipt (the record a release or deep run
produces) against this repository's canonical gate vocabulary and against the
actual evidence files it names. It never executes a command recorded in the
receipt, never imports application code, never touches the network and never
writes to disk. Failures never echo receipt field values (only ids and field
paths), so a receipt that accidentally carries a secret cannot leak it through
validator output.

Trust boundary (read this before quoting a PASS): a PASS means the receipt is
internally consistent and its named evidence bytes hash correctly. It does NOT
authenticate who ran the commands, prove the recorded exit codes are truthful,
or establish that the policy is adequate - pair it with
scripts/release_guard.py for hosted-run authenticity. A fabricated but
consistent receipt passes; that limit is inherited from the proposed design and
is deliberate, not fixable by more local checks.

Requires Python >= 3.11. Run from anywhere:
`python tools/validate_receipt.py --receipt R.json --evidence-root DIR`
prints a JSON verdict; exit 0 is PASS, 1 is FAIL, 2 is BLOCKED.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from json_input import decode_json  # noqa: E402

# Canonical gate vocabulary: mirrors the authoritative commands in
# tools/local_ci.py and .github/workflows. A qualifying receipt must record
# each gate exactly once; its command string must contain the canonical form
# (producers may append redirection/tee wrappers).
REQUIRED_GATES: dict[str, str] = {
    "fmt": "cargo fmt --all --check",
    "clippy": "cargo clippy --locked --all-targets --all-features -- -D warnings",
    "cargo-audit": "cargo audit --deny warnings",
    "cargo-deny": "cargo deny check advisories licenses bans sources",
    "cargo-test": "cargo test --locked --all-features",
    "release-suites": "python -m unittest discover -s tests/release -v",
}

# Gates whose receipt record must carry a test-family count block.
FAMILY_GATES = frozenset({"cargo-test", "release-suites"})

REPOSITORY = "strmt7/rejection-rejector"
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_CLOCK_SKEW = timedelta(minutes=5)
STATUSES = frozenset({"passed", "failed", "blocked"})
RESULTS = frozenset({"PASS", "FAIL", "BLOCKED"})


class ReceiptError(ValueError):
    """Terminal malformed-input failure; the offending value is never echoed."""


def parse_time(value: Any, field: str) -> datetime:
    """Return a timezone-aware UTC datetime parsed from one receipt timestamp.

    Inputs: raw field value and its field path (used in the error message).
    Output: the parsed datetime; raises ReceiptError when the value is not a
    timezone-aware ISO-8601 string.
    """
    if not isinstance(value, str):
        raise ReceiptError(f"{field}: timestamp missing or not a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReceiptError(f"{field}: timestamp invalid") from error
    if parsed.utcoffset() is None:
        raise ReceiptError(f"{field}: timestamp lacks a timezone")
    return parsed.astimezone(UTC)


def _int_field(value: Any, field: str, minimum: int = 0) -> int:
    """Return one non-negative integer field; reject bools and other types."""
    if type(value) is not int or value < minimum:
        raise ReceiptError(f"{field}: expected an integer >= {minimum}")
    return value


def _str_field(value: Any, field: str) -> str:
    """Return one nonblank string field; reject whitespace-only values."""
    if not isinstance(value, str) or not value.strip():
        raise ReceiptError(f"{field}: expected a nonblank string")
    return value


def load_receipt(path: Path) -> dict[str, Any]:
    """Load one bounded receipt file with strict JSON semantics.

    Inputs: receipt path. Output: the decoded object. Raises ReceiptError on
    oversize input, invalid encoding/JSON, duplicate properties or nonfinite
    numbers, and when the top level is not an object.
    """
    if not path.is_file() or path.is_symlink():
        raise ReceiptError("receipt: expected a regular file")
    if path.stat().st_size > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt: exceeds the 2 MiB input limit")
    try:
        decoded = decode_json(path.read_bytes())
    except (ValueError, RecursionError) as error:
        raise ReceiptError("receipt: strict JSON decode failed") from error
    if not isinstance(decoded, dict):
        raise ReceiptError("receipt: top level must be an object")
    return decoded


def _validate_identity(receipt: dict[str, Any]) -> list[str]:
    """Check repository, source commit and toolchain identity fields."""
    findings: list[str] = []
    try:
        if _str_field(receipt.get("repository"), "repository") != REPOSITORY:
            findings.append("identity.repository_mismatch")
        if not SHA.fullmatch(_str_field(receipt.get("source_commit"), "source_commit")):
            findings.append("identity.source_commit_malformed")
        toolchain = receipt.get("toolchain")
        if not isinstance(toolchain, dict):
            findings.append("identity.toolchain_missing")
        else:
            for key in ("rustc", "cargo", "python"):
                _str_field(toolchain.get(key), f"toolchain.{key}")
        parse_time(receipt.get("generated_at"), "generated_at")
    except ReceiptError as error:
        findings.append(f"identity.malformed:{error}")
    return findings


def _validate_family(family: Any, gate_id: str, findings: list[str]) -> None:
    """Check one test-family count block for arithmetic and zero-test defects."""
    field = f"family.{gate_id}"
    if not isinstance(family, dict):
        findings.append(f"{field}:missing")
        return
    try:
        collected = _int_field(family.get("collected"), f"{field}.collected")
        executed = _int_field(family.get("executed"), f"{field}.executed")
        passed = _int_field(family.get("passed"), f"{field}.passed")
        failed = _int_field(family.get("failed"), f"{field}.failed")
        skipped = _int_field(family.get("skipped"), f"{field}.skipped")
    except ReceiptError as error:
        findings.append(f"{field}:malformed:{error}")
        return
    if executed != passed + failed:
        findings.append(f"{field}:executed_count_mismatch")
    if collected != executed + skipped:
        findings.append(f"{field}:collected_count_mismatch")
    if collected == 0:
        findings.append(f"{field}:zero_tests_discovered")


def _validate_gates(receipt: dict[str, Any], now: datetime, generated_at: datetime | None) -> list[str]:
    """Check gate coverage, command strings, exit/status agreement, times."""
    findings: list[str] = []
    gates = receipt.get("gates")
    if not isinstance(gates, list):
        return ["gate.list_missing"]
    seen: dict[str, dict[str, Any]] = {}
    for index, gate in enumerate(gates):
        field = f"gate[{index}]"
        if not isinstance(gate, dict):
            findings.append(f"{field}:not_an_object")
            continue
        try:
            gate_id = _str_field(gate.get("id"), f"{field}.id")
        except ReceiptError as error:
            findings.append(f"{field}:malformed:{error}")
            continue
        if gate_id in seen:
            findings.append(f"gate.duplicate_id:{gate_id}")
            continue
        seen[gate_id] = gate
        if gate_id not in REQUIRED_GATES:
            findings.append(f"gate.unknown_id:{gate_id}")
            continue
        findings.extend(_validate_one_gate(gate, gate_id, field, now, generated_at))
    for required in REQUIRED_GATES:
        if required not in seen:
            findings.append(f"gate.missing:{required}")
    return findings

    return findings


def _validate_one_gate(
    gate: dict[str, Any],
    gate_id: str,
    field: str,
    now: datetime,
    generated_at: datetime | None,
) -> list[str]:
    """Check one parsed gate's fields, semantics and family link.

    Inputs: `gate` -- the gate record; `gate_id` -- its verified id; `field` --
    the receipt field label; `now` -- the validation clock; `generated_at` --
    the receipt generation time when known. Output: `list[str]` -- findings for
    this gate (empty when valid).
    """
    findings: list[str] = []
    try:
        command = _str_field(gate.get("command"), f"{field}.command")
        exit_code = _int_field(gate.get("exit_code"), f"{field}.exit_code", minimum=0)
        status = _str_field(gate.get("status"), f"{field}.status")
        started = parse_time(gate.get("started_at"), f"{field}.started_at")
        finished = parse_time(gate.get("finished_at"), f"{field}.finished_at")
    except ReceiptError as error:
        findings.append(f"{field}:malformed:{error}")
        return findings
    if status not in STATUSES:
        findings.append(f"gate.status_invalid:{gate_id}")
    if REQUIRED_GATES[gate_id] not in command:
        findings.append(f"gate.command_mismatch:{gate_id}")
    # The producer's exit code and status must tell the same story.
    if (status == "passed") != (exit_code == 0) or status == "blocked" and exit_code == 0:
        findings.append(f"gate.exit_status_contradiction:{gate_id}")
    if status == "blocked" and "reason" not in gate:
        findings.append(f"gate.blocked_without_reason:{gate_id}")
    if started > finished:
        findings.append(f"gate.time_order:{gate_id}")
    for label, moment in (("started", started), ("finished", finished)):
        if moment - now > MAX_CLOCK_SKEW:
            findings.append(f"gate.future_timestamp:{gate_id}:{label}")
    if generated_at is not None and finished - generated_at > MAX_CLOCK_SKEW:
        findings.append(f"gate.finished_after_receipt:{gate_id}")
    if gate_id in FAMILY_GATES:
        _validate_family(gate.get("test_family"), gate_id, findings)
    return findings


def _validate_artifacts(receipt: dict[str, Any], evidence_root: Path) -> list[str]:
    """Check declared artifact paths and byte digests under the evidence root."""
    findings: list[str] = []
    artifacts = receipt.get("artifacts")
    if artifacts is None:
        return findings
    if not isinstance(artifacts, list):
        return ["artifact.list_invalid"]
    seen: set[Path] = set()
    root = evidence_root.resolve()
    for index, artifact in enumerate(artifacts):
        field = f"artifact[{index}]"
        if not isinstance(artifact, dict):
            findings.append(f"{field}:not_an_object")
            continue
        try:
            rel = _str_field(artifact.get("path"), f"{field}.path")
            digest = _str_field(artifact.get("sha256"), f"{field}.sha256")
        except ReceiptError as error:
            findings.append(f"{field}:malformed:{error}")
            continue
        candidate = Path(rel)
        if candidate.is_absolute() or candidate.drive or ".." in candidate.parts:
            findings.append(f"artifact.path_escape:{index}")
            continue
        resolved = (root / candidate).resolve()
        if root not in resolved.parents:
            findings.append(f"artifact.path_escape:{index}")
            continue
        if resolved in seen:
            findings.append(f"artifact.duplicate_path:{index}")
            continue
        seen.add(resolved)
        if not SHA256.fullmatch(digest):
            findings.append(f"artifact.digest_malformed:{index}")
            continue
        if not resolved.is_file() or resolved.is_symlink():
            findings.append(f"artifact.missing:{index}")
            continue
        import hashlib

        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != digest:
            findings.append(f"artifact.digest_mismatch:{index}")
    return findings


def _validate_exceptions(receipt: dict[str, Any], now: datetime) -> list[str]:
    """Check exception records; exceptions never change the computed result."""
    findings: list[str] = []
    exceptions = receipt.get("exceptions")
    if exceptions is None:
        return findings
    if not isinstance(exceptions, list):
        return ["exception.list_invalid"]
    for index, exc in enumerate(exceptions):
        field = f"exception[{index}]"
        if not isinstance(exc, dict):
            findings.append(f"{field}:not_an_object")
            continue
        try:
            exc_id = _str_field(exc.get("id"), f"{field}.id")
            _str_field(exc.get("gate"), f"{field}.gate")
            _str_field(exc.get("reason"), f"{field}.reason")
            _str_field(exc.get("owner"), f"{field}.owner")
            expires = _str_field(exc.get("expires"), f"{field}.expires")
        except ReceiptError as error:
            findings.append(f"{field}:malformed:{error}")
            continue
        try:
            expiry = date.fromisoformat(expires)
        except ValueError:
            findings.append(f"exception.expires_malformed:{exc_id}")
            continue
        if expiry < now.date():
            findings.append(f"exception.expired:{exc_id}")
    return findings


def compute_result(findings: list[str], gates: Any) -> str:
    """Compute FAIL/BLOCKED/PASS from findings and gate statuses.

    Inputs: the finding list and the raw gates value. Output: the result
    string; precedence is FAIL over BLOCKED over PASS. Any structural finding
    forces FAIL; a clean receipt with an honest blocked gate is BLOCKED; only a
    clean all-passed receipt is PASS. Exceptions never downgrade a computed
    FAIL or BLOCKED (S15).
    """
    if findings:
        return "FAIL"
    if isinstance(gates, list):
        statuses = {g.get("status") for g in gates if isinstance(g, dict)}
        if not statuses or not statuses <= STATUSES or "failed" in statuses:
            return "FAIL"
        if "blocked" in statuses:
            return "BLOCKED"
        return "PASS"
    return "FAIL"


def validate(receipt: dict[str, Any], evidence_root: Path, now: datetime) -> dict[str, Any]:
    """Validate one decoded receipt; return the machine-readable verdict.

    Inputs: the decoded receipt object, the evidence root whose declared files
    are hashed, and the trusted current time (injectable for tests). Output:
    {"result", "findings"} where result is PASS/FAIL/BLOCKED. The producer's
    overall_status label is cross-checked and a contradiction forces FAIL.
    """
    findings: list[str] = []
    findings += _validate_identity(receipt)
    generated_at: datetime | None = None
    with contextlib.suppress(ReceiptError):
        generated_at = parse_time(receipt.get("generated_at"), "generated_at")
    findings += _validate_gates(receipt, now, generated_at)
    findings += _validate_artifacts(receipt, evidence_root)
    findings += _validate_exceptions(receipt, now)
    result = compute_result(findings, receipt.get("gates"))
    label = receipt.get("overall_status")
    if not isinstance(label, str) or label not in RESULTS or label != result:
        findings.append("result.label_contradiction")
        if result != "FAIL":
            result = "FAIL"
    return {"result": result, "findings": findings}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Inputs: optional argv. Output: 0 PASS, 1 FAIL, 2 BLOCKED."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = load_receipt(args.receipt)
    except ReceiptError as error:
        print(json.dumps({"result": "FAIL", "findings": [str(error)]}))
        return 1
    verdict = validate(receipt, args.evidence_root, datetime.now(UTC))
    print(json.dumps(verdict, indent=2))
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[verdict["result"]]


if __name__ == "__main__":
    raise SystemExit(main())
