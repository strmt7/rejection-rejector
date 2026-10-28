"""Record only this report package's checks; does not run application commands."""

import hashlib
import json
import sys
import unittest
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import validate_contract as vc

ROOT = Path(__file__).parent
stream = StringIO()
suite = unittest.defaultTestLoader.discover(str(ROOT), pattern="test_validate_contract.py")
count = suite.countTestCases()
run = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
output = stream.getvalue()
(ROOT / "test-output.txt").write_text(output)
files = [
    "validate_contract.py",
    "test_validate_contract.py",
    "engineering-policy.schema.json",
    "execution-receipt.schema.json",
]
receipt = {
    "kind": "real execution of report-validator unit tests; not project/application qualification",
    "command": "python3 -B record_checks.py",
    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "python": sys.version.split()[0],
    "collected": count,
    "executed": run.testsRun,
    "passed": run.testsRun - len(run.failures) - len(run.errors) - len(run.skipped),
    "failures": len(run.failures),
    "errors": len(run.errors),
    "skipped": len(run.skipped),
    "exit_code": 0 if run.wasSuccessful() else 1,
    "files": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files},
    "output_sha256": hashlib.sha256((ROOT / "test-output.txt").read_bytes()).hexdigest(),
    "limits": "All application/host records are synthetic fixtures; no repository command or remote operation ran.",
}
(ROOT / "test-results.json").write_text(json.dumps(receipt, indent=2) + "\n")
examples = []
for name in ("consistent", "false-pass", "blocked"):
    result = vc.validate(
        ROOT / "examples/engineering.toml",
        ROOT / f"examples/receipt-{name}-synthetic.json",
        ROOT / "examples",
        repo="strmt7/qfales_fc_website",
        target_sha="f455a4e36c0b9541edb6f0207b2870b0369b5f3a",
        profile_sha="1" * 40,
    )
    examples.append({"example": name, "result": result})
(ROOT / "example_validation_results.json").write_text(json.dumps(examples, indent=2) + "\n")
print(
    json.dumps(
        {
            "tests": receipt,
            "examples": [
                {k: v for k, v in e.items() if k != "result"}
                | {"result": e["result"]["result"], "consistency_result": e["result"]["consistency_result"]}
                for e in examples
            ],
        },
        indent=2,
    )
)
raise SystemExit(receipt["exit_code"])
