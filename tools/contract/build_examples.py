"""Create explicitly synthetic contract examples; no project commands are run."""

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parent
DEST = ROOT / "examples"
SOURCE = "f455a4e36c0b9541edb6f0207b2870b0369b5f3a"
PROFILE = "1" * 40  # Deliberately fictitious, never a claimed deployed profile.


def q(value):
    """Render one value as compact JSON text.

    Inputs: `value` -- the object to serialize. Output: `str` -- its JSON text.
    """
    return json.dumps(value)


def digest(path):
    """Hash one file's bytes.

    Inputs: `path` -- file to read. Output: `str` -- lowercase hex SHA-256.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc(value):
    """Render a timestamp as RFC 3339 UTC text.

    Inputs: `value` -- aware datetime. Output: `str` -- ISO text with a `Z` suffix.
    """
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def build():
    """Write the synthetic example package to the output directory.

    Inputs: none. Output: none; creates the example receipts, fixtures and
    synthetic inputs under the package's examples/ directory.
    """
    DEST.mkdir(exist_ok=True)
    for directory in ("logs", "artifacts", "inputs"):
        (DEST / directory).mkdir(exist_ok=True)
    lock = DEST / "inputs/example.lock"
    lock.write_text("# SYNTHETIC EXAMPLE ONLY; not an installable dependency lock\n")
    now = datetime.now(UTC).replace(microsecond=0)
    review = (now - timedelta(days=1)).date().isoformat()
    due = (now + timedelta(days=30)).date().isoformat()
    lines = [
        "# SYNTHETIC EXAMPLE ONLY. Not an approved Qfales policy or actual test receipt.",
        'schema_version = "1.0"',
        'repo = "strmt7/qfales_fc_website"',
        f'audit_baseline_sha = "{SOURCE}"',
        'owner = "Example owner; no approval implied"',
        'lifecycle = "experiment"',
        f'reviewed_on = "{review}"',
        f'review_due = "{due}"',
        "exceptions = []",
        "",
        'input_files_reason = "One synthetic lock demonstrates exact input-byte binding; no product input is claimed"',
        "",
        "[profile]",
        'id = "synthetic-example-profile"',
        f'sha = "{PROFILE}"',
        f'source_url = "https://example.invalid/profile/{PROFILE}"',
        "",
        "[roots]",
        'authored = ["src"]',
        'generated = ["generated"]',
        'vendor = ["vendor"]',
        'fixture = ["tests/fixtures"]',
        "",
        "[[input_files]]",
        'id = "example-lock"',
        'kind = "lock"',
        'path = "inputs/example.lock"',
        f'sha256 = "{digest(lock)}"',
        "",
        "[[environments]]",
        'id = "example-host"',
        'description = "Synthetic metadata; no Node host was run"',
        "required = true",
        "[environments.tools]",
        'node = ["synthetic-version"]',
        "",
        "[[commands]]",
        'id = "example-check"',
        'command = "npm test"',
        'environment = "example-host"',
        "applicable = true",
        'reason = "Example command declaration, not evidence of execution"',
        "",
        "[[test_families]]",
        'id = "example-unit"',
        'environment = "example-host"',
        'command_id = "example-check"',
        "applicable = true",
        'reason = "Synthetic test inventory for validator demonstration"',
        "minimum_executed = 1",
        'required_test_ids = ["example-case"]',
        "allowed_skips = []",
        "",
        "[[artifact_kinds]]",
        'id = "example-report"',
        'environment = "example-host"',
        "applicable = true",
        'reason = "Synthetic artifact used to demonstrate local hashing"',
        "minimum_count = 1",
        'qualification_command_ids = ["example-check"]',
        'qualification_test_family_ids = ["example-unit"]',
        "",
        "[[coverage_scopes]]",
        'id = "example-coverage"',
        "applicable = true",
        'reason = "Synthetic scope only; no coverage was measured"',
        'environment = "example-host"',
        'command_id = "example-check"',
        'measurement = "line"',
        'included_roots = ["src"]',
        'excluded_roots = ["generated", "vendor", "tests/fixtures"]',
        'artifact_kind = "example-report"',
        "",
    ]
    standard_ids = [f"S{i:02d}" for i in range(1, 16)]
    task_ids = [f"QFALES-{i:02d}" for i in range(1, 7)]
    for collection, ids in [("standards", standard_ids), ("tasks", task_ids)]:
        for rid in ids:
            lines += [
                f"[[{collection}]]",
                f'id = "{rid}"',
                "applicable = true",
                'reason = "Example mapping only; real acceptance must be reviewed per requirement"',
                'command_ids = ["example-check"]',
                'test_family_ids = ["example-unit"]',
                'artifact_kinds = ["example-report"]',
                "",
            ]
    policy = DEST / "engineering.toml"
    policy.write_text("\n".join(lines) + "\n")
    log = DEST / "logs/example.log"
    log.write_text("SYNTHETIC EXAMPLE ONLY\nNo npm command, application or actual test was executed.\n")
    artifact = DEST / "artifacts/example-report.json"
    artifact.write_text(json.dumps({"synthetic": True, "purpose": "local hash illustration only"}, indent=2) + "\n")
    stamp = utc(now - timedelta(seconds=5))
    captured = utc(now - timedelta(seconds=10))
    finished = utc(now - timedelta(seconds=15))
    started = utc(now - timedelta(seconds=20))
    receipt = {
        "schema_version": "1.0",
        "repo": "strmt7/qfales_fc_website",
        "mode": "synthetic_example",
        "source_sha": SOURCE,
        "audit_baseline_sha": SOURCE,
        "profile_sha": PROFILE,
        "policy_sha256": digest(policy),
        "created_at": stamp,
        "overall_status": "PASS",
        "input_files": [{"id": "example-lock", "kind": "lock", "path": "inputs/example.lock", "sha256": digest(lock)}],
        "environments": [
            {
                "id": "example-host",
                "status": "available",
                "reason": "Synthetic metadata only",
                "tools": {"node": "synthetic-version"},
            }
        ],
        "commands": [
            {
                "id": "example-check",
                "command": "npm test",
                "status": "passed",
                "exit_code": 0,
                "started_at": started,
                "finished_at": finished,
                "reason": "Synthetic record, not execution",
                "evidence_ids": ["example-log"],
            }
        ],
        "test_families": [
            {
                "id": "example-unit",
                "status": "passed",
                "reason": "Synthetic inventory only",
                "evidence_ids": ["example-log"],
                "tests": [{"id": "example-case", "status": "passed", "reason": "Synthetic case"}],
                "counts": {"collected": 1, "executed": 1, "passed": 1, "failed": 0, "skipped": 0, "blocked": 0},
            }
        ],
        "artifacts": [
            {
                "id": "example-artifact",
                "kind": "example-report",
                "environment": "example-host",
                "path": "artifacts/example-report.json",
                "sha256": digest(artifact),
                "created_at": utc(now - timedelta(seconds=18)),
                "source_sha": SOURCE,
                "profile_sha": PROFILE,
                "evidence_kind": "synthetic",
                "qualification": {
                    "status": "passed",
                    "reason": "Synthetic qualification, no artifact was installed or exercised",
                    "command_ids": ["example-check"],
                    "test_family_ids": ["example-unit"],
                    "evidence_ids": ["example-log"],
                },
            }
        ],
        "coverage_scopes": [
            {
                "id": "example-coverage",
                "status": "passed",
                "reason": "Synthetic scope metadata only; no coverage measured",
                "environment": "example-host",
                "command_id": "example-check",
                "measurement": "line",
                "included_roots": ["src"],
                "excluded_roots": ["generated", "vendor", "tests/fixtures"],
                "artifact_ids": ["example-artifact"],
                "evidence_ids": ["example-log"],
            }
        ],
        "evidence": [
            {
                "id": "example-log",
                "path": "logs/example.log",
                "sha256": digest(log),
                "captured_at": captured,
                "source_sha": SOURCE,
                "profile_sha": PROFILE,
                "kind": "synthetic",
                "description": "Synthetic fixture; no real command log",
            }
        ],
        "standards": [
            {"id": rid, "status": "passed", "reason": "Synthetic example only", "evidence_ids": ["example-log"]}
            for rid in standard_ids
        ],
        "tasks": [
            {"id": rid, "status": "passed", "reason": "Synthetic example only", "evidence_ids": ["example-log"]}
            for rid in task_ids
        ],
        "exceptions": [],
    }

    def save(name, value):
        """Write one example JSON document.

        Inputs: `name` -- file name under the destination directory; `value` --
        the JSON-serializable document. Output: none.
        """
        (DEST / name).write_text(json.dumps(value, indent=2) + "\n")

    save("receipt-consistent-synthetic.json", receipt)
    false = copy.deepcopy(receipt)
    false["commands"][0]["exit_code"] = 7
    save("receipt-false-pass-synthetic.json", false)
    blocked = copy.deepcopy(receipt)
    blocked["overall_status"] = "BLOCKED"
    blocked["environments"][0]["status"] = "blocked"
    blocked["environments"][0]["tools"] = {}
    for key in ("commands", "test_families", "coverage_scopes", "standards", "tasks"):
        for item in blocked[key]:
            item.update(status="blocked", reason="Synthetic required host unavailable", evidence_ids=[])
    blocked["commands"][0]["exit_code"] = None
    blocked["test_families"][0]["tests"] = []
    blocked["test_families"][0]["counts"] = {key: 0 for key in blocked["test_families"][0]["counts"]}
    blocked["coverage_scopes"][0]["artifact_ids"] = []
    blocked["artifacts"] = []
    save("receipt-blocked-synthetic.json", blocked)
    print("Created three labelled synthetic examples. No project command ran.")


if __name__ == "__main__":
    build()
