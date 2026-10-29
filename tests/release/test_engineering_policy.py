#!/usr/bin/env python3
"""Regression tests for the S01 engineering-policy validator and the vendored
reference contract package under tools/contract/.

Why: the policy record and its read-only validators are release-chain
artifacts; their defect classes (missing fields, nonexistent paths, expired
exceptions, undefined commands, lanes without an execution path, drifted
reference bytes) must fail these tests before the artifacts can be trusted.
Everything here is offline and stdlib-only; no declared command is executed.

Run: `python -m unittest discover -s tests/release -v` (CI operator suite).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import unittest
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "check_engineering_policy.py"
CONTRACT = REPO / "tools" / "contract"
POLICY = REPO / "engineering.toml"


def _load_tool():
    """Import tools/check_engineering_policy.py by path.

    Inputs: none. Output: the imported module. Raises ImportError when the
    file cannot be loaded, keeping fixture failures loud.
    """
    spec = importlib.util.spec_from_file_location("check_engineering_policy", TOOL)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {TOOL}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _real_policy() -> dict:
    """Parse the repository's real engineering.toml. Inputs: none. Output: the
    parsed policy mapping used as the baseline fixture.
    """
    tool = _load_tool()
    return tool.load_policy(POLICY)


class PolicyValidatorTests(unittest.TestCase):
    """S01 acceptance checks of tools/check_engineering_policy.py.

    Each test mutates a copy of the real policy into one defect class and
    asserts the validator names it; the untouched real policy must pass.
    """

    @staticmethod
    def _validate(policy: dict):
        """Validate one policy copy against the repository root.

        Inputs: `policy` -- candidate policy mapping. Output: the validator
        verdict dict.
        """
        tool = _load_tool()
        return tool.validate_policy(policy, REPO, date.today())

    def test_real_policy_passes_schema_and_s01_checks(self):
        """The shipped engineering.toml passes schema and every S01 check."""
        verdict = self._validate(_real_policy())
        self.assertEqual(verdict["result"], "PASS", verdict["errors"])
        proc = subprocess.run([sys.executable, str(TOOL)], cwd=REPO, capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["result"], "PASS")

    def test_missing_required_field_is_detected(self):
        """Dropping a required top-level field is reported by name."""
        policy = _real_policy()
        del policy["lifecycle"]
        verdict = self._validate(policy)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertTrue(any("missing required field: lifecycle" in e for e in verdict["errors"]))

    def test_nonexistent_root_path_is_detected(self):
        """An authored root path that does not exist fails the check."""
        policy = _real_policy()
        policy["roots"]["authored"] = policy["roots"]["authored"] + ["no/such/path"]
        verdict = self._validate(policy)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertTrue(any("nonexistent path 'no/such/path'" in e for e in verdict["errors"]))

    def test_expired_exception_is_detected(self):
        """An exception past its expiry date cannot keep passing."""
        policy = _real_policy()
        policy["exceptions"][0]["expires_on"] = "2020-01-01"
        verdict = self._validate(policy)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertTrue(any("expired on 2020-01-01" in e for e in verdict["errors"]))

    def test_undefined_command_reference_is_detected(self):
        """A family pointing at an undeclared command id is rejected."""
        policy = _real_policy()
        policy["test_families"][0]["command_id"] = "no-such-command"
        verdict = self._validate(policy)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertTrue(any("undefined command id 'no-such-command'" in e for e in verdict["errors"]))

    def test_required_family_without_execution_path_is_detected(self):
        """An applicable family whose command is disabled has no execution
        path and must be reported.
        """
        policy = _real_policy()
        for cmd in policy["commands"]:
            if cmd["id"] == "test-fast":
                cmd["applicable"] = False
        verdict = self._validate(policy)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertTrue(any("rust-core-tests" in e and "no execution path" in e for e in verdict["errors"]))

    def test_wrong_task_set_is_detected(self):
        """The policy must carry exactly the six canonical RR task ids."""
        policy = _real_policy()
        policy["tasks"] = policy["tasks"][:-1]
        verdict = self._validate(policy)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertTrue(any("tasks must be exactly" in e for e in verdict["errors"]))

    def test_input_digest_mismatch_is_detected(self):
        """A recorded input digest that no longer matches the file fails."""
        policy = _real_policy()
        policy["input_files"][0]["sha256"] = "0" * 64
        verdict = self._validate(policy)
        self.assertEqual(verdict["result"], "FAIL")
        self.assertTrue(any("sha256 mismatch" in e for e in verdict["errors"]))


class ReferenceContractTests(unittest.TestCase):
    """The vendored tools/contract/ reference package must stay byte-exact and
    keep its documented example outcomes.
    """

    def test_reference_package_matches_manifest(self):
        """Every packaged file still matches PACKAGE-MANIFEST.json hashes."""
        manifest = json.loads((CONTRACT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
        mismatches = []
        for rel, want in manifest["files"].items():
            got = hashlib.sha256((CONTRACT / rel).read_bytes()).hexdigest()
            if got != want:
                mismatches.append(rel)
        self.assertEqual(mismatches, [], f"reference package drifted: {mismatches}")

    def test_documented_example_outcomes(self):
        """The three synthetic examples reproduce the documented decisions:
        consistent-synthetic is BLOCKED/synthetic (exit 2), false-pass is FAIL
        (exit 1), blocked-synthetic is BLOCKED (exit 2).
        """
        common = [
            "--policy",
            "examples/engineering.toml",
            "--evidence-root",
            "examples",
            "--repo",
            "strmt7/qfales_fc_website",
            "--target-sha",
            "f455a4e36c0b9541edb6f0207b2870b0369b5f3a",
            "--profile-sha",
            "1" * 40,
        ]
        cases = [
            ("examples/receipt-consistent-synthetic.json", 2, "BLOCKED"),
            ("examples/receipt-false-pass-synthetic.json", 1, "FAIL"),
            ("examples/receipt-blocked-synthetic.json", 2, "BLOCKED"),
        ]
        for receipt, want_rc, want_result in cases:
            proc = subprocess.run(
                [sys.executable, "-B", "validate_contract.py", "--receipt", receipt] + common,
                cwd=CONTRACT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, want_rc, f"{receipt}: {proc.stdout}{proc.stderr}")
            body = json.loads(proc.stdout)
            self.assertEqual(body["result"], want_result, f"{receipt}: {body}")

    def test_schemas_declare_draft_2020_12(self):
        """Both vendored schemas name JSON Schema Draft 2020-12 and parse."""
        for name in ("engineering-policy.schema.json", "execution-receipt.schema.json"):
            schema = json.loads((CONTRACT / name).read_text(encoding="utf-8"))
            self.assertIn("2020-12", schema.get("$schema", ""), name)


if __name__ == "__main__":
    unittest.main()
