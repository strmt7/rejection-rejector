#!/usr/bin/env python3
"""Read-only validator for the S01 engineering policy record (engineering.toml).

Why: shared requirement S01 of the engineering implementation manual demands a
policy record plus a read-only validator that detects missing fields,
nonexistent paths, expired exceptions, undefined commands and required lanes
without an execution path. This tool performs exactly those checks against the
repository's engineering.toml and additionally confirms structural conformance
with the exact reference schema vendored at tools/contract/. It never executes a
declared command, never modifies the policy or repository and never touches the
network. A PASS means the record is internally complete and consistent; it does
not certify that the declared commands pass or that the policy is adequate.

Requires Python >=3.11 (stdlib tomllib). Run from anywhere:
`python tools/check_engineering_policy.py` validates ./engineering.toml and
prints a JSON verdict; exit 0 is PASS and exit 1 is FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import tomllib
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_DIR = Path(__file__).resolve().parent / "contract"
STANDARD_IDS = [f"S{i:02d}" for i in range(1, 16)]
TASK_IDS = ["RR-01", "RR-02", "RR-03", "RR-04", "RR-05", "RR-06"]
TOP_REQUIRED = [
    "schema_version",
    "repo",
    "audit_baseline_sha",
    "profile",
    "owner",
    "lifecycle",
    "reviewed_on",
    "review_due",
    "roots",
    "input_files_reason",
    "input_files",
    "environments",
    "commands",
    "test_families",
    "artifact_kinds",
    "coverage_scopes",
    "standards",
    "tasks",
    "exceptions",
]


def load_policy(path: Path) -> dict:
    """Parse the engineering policy TOML record.

    Inputs: `path` -- path to engineering.toml. Output: the parsed policy
    mapping. Raises `FileNotFoundError`/`tomllib.TOMLDecodeError` unchanged so a
    broken file fails loudly instead of validating as empty.
    """
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _load_reference_validator():
    """Import the vendored reference validator module from tools/contract/.

    Inputs: none. Output: the imported `validate_contract` module, used only
    for its exact-schema `check_shape` so this tool cannot drift from the
    reference schema subset.
    """
    spec = importlib.util.spec_from_file_location("contract_validate_contract", CONTRACT_DIR / "validate_contract.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load reference validator from {CONTRACT_DIR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _index(records: list[dict], kind: str, errors: list[str]) -> dict[str, dict]:
    """Index a list of records by id, recording duplicates as errors.

    Inputs: `records` -- policy record list; `kind` -- record kind name for
    messages; `errors` -- shared error list appended in place. Output: mapping
    of id to record for unique ids.
    """
    out: dict[str, dict] = {}
    for rec in records:
        rid = rec.get("id")
        if not isinstance(rid, str) or not rid:
            errors.append(f"{kind}: record without a usable id: {rec!r}")
            continue
        if rid in out:
            errors.append(f"{kind}: duplicate id {rid!r}")
            continue
        out[rid] = rec
    return out


def _need_ref(index: dict[str, dict], label: str, rid: str, where: str, errors: list[str]) -> None:
    """Record an error when `rid` is not a declared record of `label`.

    Inputs: `index` -- id-indexed policy records; `label` -- record kind for
    the message; `rid` -- the referenced id; `where` -- referencing location;
    `errors` -- the shared error list. Output: none.
    """
    if rid not in index:
        errors.append(f"{where}: undefined {label} id {rid!r}")


def _check_required_fields(policy: dict, errors: list[str]) -> None:
    """Check required fields, canonical id sets and schema conformance.

    Inputs: `policy` -- parsed policy mapping; `errors` -- the shared error
    list. Output: none; findings are appended to `errors`.
    """
    # 1. Missing fields: exact reference schema shape plus the S01 named set.
    for key in TOP_REQUIRED:
        if key not in policy:
            errors.append(f"missing required field: {key}")
    # Canonical id sets are checked before the schema gate so a wrong
    # task/standard program is named explicitly, not only via schema drift.
    standard_ids = [rec.get("id") for rec in policy.get("standards", [])]
    if standard_ids != STANDARD_IDS:
        errors.append(f"standards must be exactly {STANDARD_IDS}, got {standard_ids}")
    task_ids = [rec.get("id") for rec in policy.get("tasks", [])]
    if task_ids != TASK_IDS:
        errors.append(f"tasks must be exactly {TASK_IDS}, got {task_ids}")
    try:
        reference = _load_reference_validator()
        schema = json.loads((CONTRACT_DIR / "engineering-policy.schema.json").read_text(encoding="utf-8"))
        reference.check_shape(policy, schema)
    except Exception as exc:  # noqa: BLE001 - surfaced as a validation error
        errors.append(f"schema conformance: {exc}")


def _check_paths_and_digests(policy: dict, repo_root: Path, errors: list[str]) -> None:
    """Check declared root paths exist and input digests match disk.

    Generated roots are build outputs that need not exist in a clean checkout,
    so existence is enforced for authored/vendor/fixture roots and the hashed
    input files only.

    Inputs: `policy` -- parsed policy mapping; `repo_root` -- repository root;
    `errors` -- the shared error list. Output: none.
    """
    # 2. Nonexistent paths and input digests. Generated roots are build
    # outputs that need not exist in a clean checkout, so existence is enforced
    # for authored/vendor/fixture roots and the hashed input files only.
    for group, paths in (policy.get("roots") or {}).items():
        if group == "generated":
            continue
        for rel in paths:
            if not (repo_root / rel).exists():
                errors.append(f"roots.{group}: nonexistent path {rel!r}")
    for rec in policy.get("input_files", []):
        target = repo_root / rec.get("path", "")
        if not target.is_file():
            errors.append(f"input_files[{rec.get('id')}]: nonexistent file {rec.get('path')!r}")
            continue
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if digest != rec.get("sha256"):
            errors.append(
                f"input_files[{rec.get('id')}]: sha256 mismatch for {rec.get('path')!r} "
                f"(recorded {rec.get('sha256')}, actual {digest})"
            )


def _check_dates(policy: dict, today: date, errors: list[str]) -> None:
    """Check exception expiry dates and the policy review deadline.

    Inputs: `policy` -- parsed policy mapping; `today` -- the current date;
    `errors` -- the shared error list. Output: none.
    """
    # 3. Expired exceptions and review deadlines.
    for exc_rec in policy.get("exceptions", []):
        expires = date.fromisoformat(exc_rec["expires_on"])
        if expires < today:
            errors.append(
                f"exceptions[{exc_rec['id']}]: expired on {exc_rec['expires_on']} "
                "(an expired exception must be renewed or removed)"
            )
    if date.fromisoformat(policy["review_due"]) < today:
        errors.append(f"review_due {policy['review_due']} is in the past; policy review is overdue")


def _check_container_references(
    policy: dict,
    commands: dict[str, dict],
    families: dict[str, dict],
    environments: dict[str, dict],
    errors: list[str],
) -> None:
    """Check test-family and artifact-kind references resolve to declared ids.

    Inputs: `policy` -- parsed policy mapping; `commands`/`families`/
    `environments` -- id-indexed record maps; `errors` -- the shared error
    list. Output: none.
    """
    for fam in policy.get("test_families", []):
        where = f"test_families[{fam['id']}]"
        _need_ref(commands, "command", fam.get("command_id", ""), where, errors)
        if fam.get("environment") not in environments:
            errors.append(f"{where}: undefined environment {fam.get('environment')!r}")
    for kind in policy.get("artifact_kinds", []):
        where = f"artifact_kinds[{kind['id']}]"
        for cid in kind.get("qualification_command_ids", []):
            _need_ref(commands, "command", cid, where, errors)
        for fid in kind.get("qualification_test_family_ids", []):
            _need_ref(families, "test family", fid, where, errors)
        if kind.get("environment") not in environments:
            errors.append(f"{where}: undefined environment {kind.get('environment')!r}")


def _check_scope_references(
    policy: dict,
    commands: dict[str, dict],
    families: dict[str, dict],
    kinds: dict[str, dict],
    errors: list[str],
) -> None:
    """Check coverage-scope and exception references resolve to declared ids.

    Inputs: `policy` -- parsed policy mapping; `commands`/`families`/`kinds` --
    id-indexed record maps; `errors` -- the shared error list. Output: none.
    """
    for cov in policy.get("coverage_scopes", []):
        where = f"coverage_scopes[{cov['id']}]"
        _need_ref(commands, "command", cov.get("command_id", ""), where, errors)
        _need_ref(kinds, "artifact kind", cov.get("artifact_kind", ""), where, errors)
    for exc_rec in policy.get("exceptions", []):
        where = f"exceptions[{exc_rec['id']}]"
        for cid in exc_rec.get("alternative_command_ids", []):
            _need_ref(commands, "command", cid, where, errors)
        for fid in exc_rec.get("alternative_test_family_ids", []):
            _need_ref(families, "test family", fid, where, errors)


def _check_references(
    policy: dict,
    commands: dict[str, dict],
    families: dict[str, dict],
    kinds: dict[str, dict],
    environments: dict[str, dict],
    errors: list[str],
) -> None:
    """Check every cross-record reference resolves to a declared id.

    Inputs: `policy` -- parsed policy mapping; `commands`/`families`/`kinds`/
    `environments` -- id-indexed record maps; `errors` -- the shared error
    list. Output: none.
    """
    # 4. Undefined references across commands, test families and artifact kinds.
    _check_container_references(policy, commands, families, environments, errors)
    _check_scope_references(policy, commands, families, kinds, errors)


def _lane_ok(
    entry: dict,
    where: str,
    commands: dict[str, dict],
    families: dict[str, dict],
    kinds: dict[str, dict],
    errors: list[str],
) -> None:
    """Check one standard/task entry has dependencies and applicable commands.

    Inputs: `entry` -- the standard/task record; `where` -- label for messages;
    `commands`/`families`/`kinds` -- id-indexed record maps; `errors` -- the
    shared error list. Output: none (errors appended in place).
    """
    deps = entry.get("command_ids", []) + entry.get("test_family_ids", []) + entry.get("artifact_kinds", [])
    if entry.get("applicable") and not deps:
        errors.append(f"{where}: applicable lane names no command, test family or artifact kind")
    for cid in entry.get("command_ids", []):
        _need_ref(commands, "command", cid, where, errors)
        if cid in commands and not commands[cid].get("applicable"):
            errors.append(f"{where}: references command {cid!r} which is marked not applicable")
    for fid in entry.get("test_family_ids", []):
        _need_ref(families, "test family", fid, where, errors)
    for kid in entry.get("artifact_kinds", []):
        _need_ref(kinds, "artifact kind", kid, where, errors)


def _check_execution_paths(
    policy: dict,
    commands: dict[str, dict],
    errors: list[str],
) -> None:
    """Check applicable families and scopes whose command is not applicable.

    Inputs: `policy` -- parsed policy mapping; `commands` -- id-indexed record
    map; `errors` -- the shared error list. Output: none.
    """
    for fam in policy.get("test_families", []):
        if fam.get("applicable"):
            cmd = commands.get(fam.get("command_id", ""))
            if cmd is not None and not cmd.get("applicable"):
                errors.append(
                    f"test_families[{fam['id']}]: required family has no execution path "
                    f"(command {fam.get('command_id')!r} is marked not applicable)"
                )
    for cov in policy.get("coverage_scopes", []):
        if cov.get("applicable"):
            cmd = commands.get(cov.get("command_id", ""))
            if cmd is not None and not cmd.get("applicable"):
                errors.append(
                    f"coverage_scopes[{cov['id']}]: applicable scope has no execution path "
                    f"(command {cov.get('command_id')!r} is marked not applicable)"
                )


def _check_lanes(
    policy: dict,
    commands: dict[str, dict],
    families: dict[str, dict],
    kinds: dict[str, dict],
    errors: list[str],
) -> None:
    """Check every required lane has a live execution path.

    Inputs: `policy` -- parsed policy mapping; `commands`/`families`/`kinds` --
    id-indexed record maps; `errors` -- the shared error list. Output: none.
    """
    # 5. Required lanes without an execution path and canonical id sets.
    for entry in policy.get("standards", []) + policy.get("tasks", []):
        _lane_ok(entry, f"{entry.get('id')}", commands, families, kinds, errors)
    _check_execution_paths(policy, commands, errors)


def validate_policy(policy: dict, repo_root: Path, today: date) -> dict:
    """Run every S01 acceptance check against a parsed policy.

    Inputs: `policy` -- parsed engineering.toml mapping; `repo_root` -- the
    repository root used to resolve declared root/input paths; `today` -- the
    current date used for expiry and review-deadline checks. Output: verdict
    dict with `result` ("PASS" or "FAIL") and `errors` (list of human-readable
    defect descriptions, empty on PASS).
    """
    errors: list[str] = []
    _check_required_fields(policy, errors)
    if errors:
        return {"result": "FAIL", "errors": errors}
    _check_paths_and_digests(policy, repo_root, errors)
    _check_dates(policy, today, errors)
    commands = _index(policy.get("commands", []), "commands", errors)
    families = _index(policy.get("test_families", []), "test_families", errors)
    kinds = _index(policy.get("artifact_kinds", []), "artifact_kinds", errors)
    environments = _index(policy.get("environments", []), "environments", errors)
    _check_references(policy, commands, families, kinds, environments, errors)
    _check_lanes(policy, commands, families, kinds, errors)
    return {"result": "PASS" if not errors else "FAIL", "errors": errors}


def main(argv: list[str] | None = None) -> int:
    """Entry point for the S01 policy validator.

    Inputs: `argv` -- optional argument list (`--policy` path override).
    Output: exit status 0 when the policy passes every check, 1 otherwise; the
    verdict is printed as JSON on stdout in both cases.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        type=Path,
        default=ROOT / "engineering.toml",
        help="Path to the engineering policy TOML (default: repository root)",
    )
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(json.dumps({"result": "FAIL", "errors": [f"policy unreadable: {exc}"]}, indent=2))
        return 1
    verdict = validate_policy(policy, ROOT, date.today())
    print(json.dumps(verdict, indent=2))
    return 0 if verdict["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
