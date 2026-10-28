"""Adversarial tests for the proposed validator, not evidence of project tests.

Temporary fixtures sometimes simulate `real` metadata to test the decision branch.
Their log content stays explicitly synthetic: the validator cannot authenticate it.
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path

import validate_contract as vc

PACKAGE = Path(__file__).parent
REPO = "strmt7/qfales_fc_website"
SHA = "f455a4e36c0b9541edb6f0207b2870b0369b5f3a"
PROFILE = "1" * 40


class ContractTests(unittest.TestCase):
    """Fixture base for receipt-contract validation tests.

    Provides a copied example package primed as a production-mode receipt,
    plus save/run/assert helpers shared by the cases.
    """

    def setUp(self):
        """Build the example-package fixture.

        Inputs: none (unittest fixture hook). Output: none; copies examples/ into
        a temp directory and primes a production-mode receipt and validation clock.
        """
        self.temp = tempfile.TemporaryDirectory(prefix="contract-test-", dir=PACKAGE)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(PACKAGE / "examples", self.root, dirs_exist_ok=True)
        self.policy = self.root / "engineering.toml"
        self.receipt = self.root / "receipt.json"
        self.data = json.loads((self.root / "receipt-consistent-synthetic.json").read_text())
        self.clock = datetime.fromisoformat(self.data["created_at"].replace("Z", "+00:00")) + timedelta(minutes=1)
        self.data["mode"] = "production"
        for item in self.data["evidence"]:
            item["kind"] = "real"
        for item in self.data["artifacts"]:
            item["evidence_kind"] = "real"

    def save(self):
        """Persist the mutated receipt to disk.

        Inputs: none (serializes `self.data`). Output: none; writes receipt.json.
        """
        self.receipt.write_text(json.dumps(self.data, indent=2) + "\n")

    def run_check(self, **kwargs):
        """Run the validator over the fixture package.

        Inputs: `kwargs` -- forwarded to `validate()`. Output: the validation
        result dict (result status plus findings).
        """
        self.save()
        return vc.validate(
            self.policy,
            self.receipt,
            self.root,
            repo=REPO,
            target_sha=SHA,
            profile_sha=PROFILE,
            now=self.clock,
            **kwargs,
        )

    def assert_issue(self, result, code, status="FAIL"):
        """Assert one finding code and the overall result status.

        Inputs: `result` -- validator output; `code` -- expected finding code;
        `status` -- expected result status (default `FAIL`). Output: none.
        """
        self.assertEqual(result["result"], status, result)
        self.assertIn(code, {i["code"] for i in result["issues"]}, result)

    def update_policy(self, text):
        """Replace the policy text under test and rebind dependent fixture state.

        Inputs: `text` -- the new policy TOML. Output: none.
        """
        self.policy.write_text(text)
        self.data["policy_sha256"] = hashlib.sha256(self.policy.read_bytes()).hexdigest()

    def exception(self, days=1):
        """Add a dated policy exception and link it from the receipt fixture.

        Inputs: `days` -- expiry offset in days from the fixture clock.
        Output: none; rewrites the policy with `[[exceptions]]` and records the
        matching exception on the receipt.
        """
        text = self.policy.read_text().replace("exceptions = []\n", "")
        expires = (self.clock + timedelta(days=days)).date().isoformat()
        text += f'''\n[[exceptions]]
id = "E1"
requirement_id = "S01"
owner = "Example test owner"
reason = "Synthetic alternative proof; does not waive original requirements"
expires_on = "{expires}"
alternative_command_ids = ["example-check"]
alternative_test_family_ids = ["example-unit"]
'''
        self.update_policy(text)
        self.data["exceptions"] = [{"id": "E1", "evidence_ids": ["example-log"]}]

    def test_consistent_metadata_passes_without_claiming_log_authenticity(self):
        """Consistent metadata passes without claiming log authenticity."""
        result = self.run_check()
        self.assertEqual(result["result"], "PASS", result)
        self.assertFalse(result["declared_label_used_as_authority"])
        self.assertIn("SYNTHETIC", (self.root / "logs/example.log").read_text())
        self.assertTrue(any("truthfulness" in s for s in result["limitations"]))

    def test_synthetic_example_never_qualifies_production(self):
        """Synthetic example never qualifies production."""
        self.data["mode"] = "synthetic_example"
        result = self.run_check()
        self.assertEqual(result["consistency_result"], "PASS")
        self.assertEqual(result["result"], "BLOCKED")

    def test_missing_task_fails(self):
        """Missing task fails."""
        self.data["tasks"].pop()
        self.assert_issue(self.run_check(), "STRUCTURE")

    def test_wrong_task_id_fails_even_with_six_records(self):
        """Wrong task id fails even with six records."""
        self.data["tasks"][-1]["id"] = "QFALES-99"
        self.assert_issue(self.run_check(), "REQUIRED_IDS")

    def test_missing_standard_fails(self):
        """Missing standard fails."""
        self.data["standards"].pop()
        self.assert_issue(self.run_check(), "STRUCTURE")

    def test_stale_source_fails(self):
        """Stale source fails."""
        self.data["source_sha"] = "2" * 40
        self.assert_issue(self.run_check(), "STALE_SOURCE")

    def test_stale_profile_fails(self):
        """Stale profile fails."""
        self.data["profile_sha"] = "2" * 40
        self.assert_issue(self.run_check(), "STALE_PROFILE")

    def test_false_pass_nonzero_exit_fails(self):
        """False pass nonzero exit fails."""
        self.data["commands"][0]["exit_code"] = 9
        self.assert_issue(self.run_check(), "FALSE_PASS_EXIT")

    def test_receipt_command_must_match_declared_command(self):
        """Receipt command must match declared command."""
        self.data["commands"][0]["command"] = "echo different-check"
        self.assert_issue(self.run_check(), "COMMAND_IDENTITY")

    def test_overall_label_cannot_hide_a_failed_command(self):
        """Overall label cannot hide a failed command."""
        self.data["overall_status"] = "PASS"
        self.data["commands"][0].update(status="failed", exit_code=1)
        self.assert_issue(self.run_check(), "COMMAND_FAILED")

    def test_producer_fail_is_not_silently_upgraded(self):
        """Producer fail is not silently upgraded."""
        self.data["overall_status"] = "FAIL"
        self.assert_issue(self.run_check(), "OVERALL_STATUS_MISMATCH")

    def test_producer_blocked_is_not_silently_upgraded(self):
        """Producer blocked is not silently upgraded."""
        self.data["overall_status"] = "BLOCKED"
        self.assert_issue(self.run_check(), "OVERALL_STATUS_MISMATCH")

    def test_changed_evidence_fails(self):
        """Changed evidence fails."""
        (self.root / "logs/example.log").write_text("changed after receipt\n")
        self.assert_issue(self.run_check(), "FILE_HASH")

    def test_changed_artifact_fails(self):
        """Changed artifact fails."""
        (self.root / "artifacts/example-report.json").write_text("{}\n")
        self.assert_issue(self.run_check(), "FILE_HASH")

    def test_changed_input_lock_fails(self):
        """Changed input lock fails."""
        (self.root / "inputs/example.lock").write_text("different dependency input\n")
        self.assert_issue(self.run_check(), "FILE_HASH")

    def test_missing_input_record_fails(self):
        """Missing input record fails."""
        self.data["input_files"] = []
        self.assert_issue(self.run_check(), "RECORD_SET")

    def test_audit_baseline_mismatch_fails(self):
        """Audit baseline mismatch fails."""
        self.data["audit_baseline_sha"] = "2" * 40
        self.assert_issue(self.run_check(), "AUDIT_BASELINE")

    def test_changed_policy_digest_fails(self):
        """Changed policy digest fails."""
        self.policy.write_text(self.policy.read_text() + "\n# changed\n")
        self.assert_issue(self.run_check(), "POLICY_DIGEST")

    def test_unexpected_skip_fails(self):
        """Unexpected skip fails."""
        f = self.data["test_families"][0]
        f["tests"].append({"id": "unexpected-skipped-case", "status": "skipped", "reason": "no host"})
        f["counts"].update(collected=2, skipped=1)
        self.assert_issue(self.run_check(), "UNEXPECTED_SKIP")

    def test_zero_tests_fails(self):
        """Zero tests fails."""
        f = self.data["test_families"][0]
        f["tests"] = []
        f["counts"] = {key: 0 for key in f["counts"]}
        self.assert_issue(self.run_check(), "ZERO_OR_FEW_TESTS")

    def test_fabricated_test_counts_fail(self):
        """Fabricated test counts fail."""
        self.data["test_families"][0]["counts"]["executed"] = 100
        self.assert_issue(self.run_check(), "TEST_COUNTS")

    def test_required_test_cannot_be_replaced_by_other_pass(self):
        """Required test cannot be replaced by other pass."""
        self.data["test_families"][0]["tests"][0]["id"] = "unrelated-case"
        self.assert_issue(self.run_check(), "MISSING_TEST")

    def test_future_timestamp_fails(self):
        """Future timestamp fails."""
        self.data["evidence"][0]["captured_at"] = (self.clock + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        self.assert_issue(self.run_check(), "FUTURE_EVIDENCE")

    def test_duplicate_record_ids_fail(self):
        """Duplicate record ids fail."""
        self.data["commands"].append(dict(self.data["commands"][0]))
        self.assert_issue(self.run_check(), "DUPLICATE_ID")

    def test_duplicate_json_keys_fail(self):
        """Duplicate json keys fail."""
        self.save()
        text = self.receipt.read_text()
        self.receipt.write_text(text.replace("{", '{"repo":"strmt7/qfales_fc_website",', 1))
        result = vc.validate(
            self.policy, self.receipt, self.root, repo=REPO, target_sha=SHA, profile_sha=PROFILE, now=self.clock
        )
        self.assert_issue(result, "STRUCTURE")

    def test_expired_exception_fails_with_passing_alternative(self):
        """Expired exception fails with passing alternative."""
        self.exception(days=-1)
        self.assert_issue(self.run_check(), "EXPIRED_EXCEPTION")

    def test_exception_requires_passing_alternative(self):
        """Exception requires passing alternative."""
        self.exception()
        self.data["commands"][0].update(status="blocked", exit_code=None)
        self.assert_issue(self.run_check(), "UNPROVEN_ALTERNATIVE")

    def test_exception_never_waives_original_failure(self):
        """Exception never waives original failure."""
        self.exception()
        self.data["standards"][0]["status"] = "failed"
        self.assert_issue(self.run_check(), "REQUIREMENT_FAILED")

    def test_exception_never_waives_original_blocker(self):
        """Exception never waives original blocker."""
        self.exception()
        self.data["standards"][0]["status"] = "blocked"
        self.data["overall_status"] = "BLOCKED"
        self.assert_issue(self.run_check(), "REQUIREMENT_BLOCKED", "BLOCKED")

    def test_blank_exception_owner_fails(self):
        """Blank exception owner fails."""
        self.exception()
        self.update_policy(self.policy.read_text().replace('owner = "Example test owner"', 'owner = "   "'))
        self.assert_issue(self.run_check(), "STRUCTURE")

    def test_blank_command_fails(self):
        """Blank command fails."""
        self.update_policy(self.policy.read_text().replace('command = "npm test"', 'command = "   "'))
        self.data["commands"][0]["command"] = "   "
        self.assert_issue(self.run_check(), "STRUCTURE")

    def test_blank_na_artifact_reason_fails(self):
        """Blank na artifact reason fails."""
        self.update_policy(
            self.policy.read_text().replace(
                'reason = "Synthetic artifact used to demonstrate local hashing"', 'reason = "   "'
            )
        )
        self.assert_issue(self.run_check(), "STRUCTURE")

    def test_hardlink_cannot_inflate_artifact_count(self):
        """Hardlink cannot inflate artifact count."""
        original = self.root / "artifacts/example-report.json"
        duplicate = self.root / "artifacts/duplicate.json"
        os.link(original, duplicate)
        self.update_policy(self.policy.read_text().replace("minimum_count = 1", "minimum_count = 2"))
        artifact = json.loads(json.dumps(self.data["artifacts"][0]))
        artifact.update(id="duplicate-artifact", path="artifacts/duplicate.json")
        self.data["artifacts"].append(artifact)
        self.assert_issue(self.run_check(), "DUPLICATE_PHYSICAL_FILE")

    def test_coverage_scope_mismatch_fails(self):
        """Coverage scope mismatch fails."""
        self.data["coverage_scopes"][0]["included_roots"] = ["tests"]
        self.assert_issue(self.run_check(), "COVERAGE_IDENTITY")

    def test_coverage_needs_actual_qualified_report(self):
        """Coverage needs actual qualified report."""
        self.data["coverage_scopes"][0]["artifact_ids"] = []
        self.assert_issue(self.run_check(), "NO_COVERAGE_ARTIFACT")

    def test_artifact_qualification_cannot_be_empty(self):
        """Artifact qualification cannot be empty."""
        self.data["artifacts"][0]["qualification"]["command_ids"] = []
        self.assert_issue(self.run_check(), "QUALIFICATION_IDENTITY")

    def test_artifact_cannot_postdate_its_qualification_command(self):
        """Artifact cannot postdate its qualification command."""
        self.data["artifacts"][0]["created_at"] = self.data["created_at"]
        self.assert_issue(self.run_check(), "ARTIFACT_QUALIFICATION_TIME")

    def test_artifact_cannot_postdate_qualification_family_command(self):
        """Artifact cannot postdate qualification family command."""
        text = self.policy.read_text().replace('command_id = "example-check"', 'command_id = "early-check"', 1)
        text += """\n[[commands]]
id = "early-check"
command = "npm run earlier"
environment = "example-host"
applicable = true
reason = "Synthetic earlier family command for temporal counterexample"
"""
        self.update_policy(text)
        command = dict(self.data["commands"][0])
        command.update(id="early-check", command="npm run earlier")
        start = datetime.fromisoformat(command["started_at"].replace("Z", "+00:00"))
        command["finished_at"] = (start + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        self.data["commands"].append(command)
        self.assert_issue(self.run_check(), "ARTIFACT_QUALIFICATION_TIME")

    def test_undeclared_not_applicable_fails(self):
        """Undeclared not applicable fails."""
        self.data["tasks"][0]["status"] = "not_applicable"
        self.assert_issue(self.run_check(), "UNDECLARED_NA")

    def test_explicit_not_applicable_needs_matching_factual_reason(self):
        """Explicit not applicable needs matching factual reason."""
        text = self.policy.read_text()
        old = (
            'id = "S15"\napplicable = true\nreason = "Example mapping only; '
            'real acceptance must be reviewed per requirement"'
        )
        replacement = (
            'id = "S15"\napplicable = false\nreason = "Synthetic scoped '
            'alternative; no claim about actual S15 applicability"'
        )
        self.update_policy(text.replace(old, replacement))
        self.data["standards"][-1].update(status="not_applicable", reason="different unsupported reason")
        self.assert_issue(self.run_check(), "NA_REASON")

    def test_supported_unavailable_host_is_blocked(self):
        """Supported unavailable host is blocked."""
        self.data = json.loads((self.root / "receipt-blocked-synthetic.json").read_text())
        self.assert_issue(self.run_check(), "ENVIRONMENT_BLOCKED", "BLOCKED")

    def test_unsupported_tool_version_fails(self):
        """Unsupported tool version fails."""
        self.data["environments"][0]["tools"]["node"] = "unqualified-version"
        self.assert_issue(self.run_check(), "TOOL_VERSION")

    def test_blank_tool_name_cannot_replace_required_identity(self):
        """Blank tool name cannot replace required identity."""
        self.update_policy(
            self.policy.read_text().replace('node = ["synthetic-version"]', '"   " = ["synthetic-version"]')
        )
        self.data["environments"][0]["tools"] = {"   ": "synthetic-version"}
        self.assert_issue(self.run_check(), "TOOL_IDENTITY")

    def test_extra_blank_receipt_tool_name_fails(self):
        """Extra blank receipt tool name fails."""
        self.data["environments"][0]["tools"]["   "] = "synthetic-version"
        self.assert_issue(self.run_check(), "TOOL_IDENTITY")

    def test_paths_cannot_escape_evidence_root(self):
        """Paths cannot escape evidence root."""
        self.data["evidence"][0]["path"] = "../outside.log"
        self.assert_issue(self.run_check(), "FILE_PATH")

    def test_overlapping_source_categories_fail(self):
        """Overlapping source categories fail."""
        self.update_policy(self.policy.read_text().replace('vendor = ["vendor"]', 'vendor = ["src/vendor"]'))
        self.assert_issue(self.run_check(), "ROOT_OVERLAP")

    def test_command_text_is_never_executed(self):
        """Command text is never executed."""
        sentinel = self.root / "should-not-exist"
        command = f"python -c \"open({str(sentinel)!r}, 'w').write('wrong')\""
        self.update_policy(self.policy.read_text().replace('command = "npm test"', "command = " + json.dumps(command)))
        self.data["commands"][0]["command"] = command
        self.assertEqual(self.run_check()["result"], "PASS")
        self.assertFalse(sentinel.exists())

    def test_cli_exit_codes_match_computed_decision(self):
        """Cli exit codes match computed decision."""
        self.save()
        args = [
            "--policy",
            str(self.policy),
            "--receipt",
            str(self.receipt),
            "--evidence-root",
            str(self.root),
            "--repo",
            REPO,
            "--target-sha",
            SHA,
            "--profile-sha",
            PROFILE,
        ]
        with redirect_stdout(StringIO()):
            self.assertEqual(vc.main(args), 0)
        self.data["commands"][0]["exit_code"] = 1
        self.save()
        with redirect_stdout(StringIO()):
            self.assertEqual(vc.main(args), 1)
        self.data = json.loads((self.root / "receipt-consistent-synthetic.json").read_text())
        self.save()
        with redirect_stdout(StringIO()):
            self.assertEqual(vc.main(args), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
