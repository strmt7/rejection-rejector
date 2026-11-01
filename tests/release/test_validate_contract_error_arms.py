"""Why (coverage doctrine): the contract validator's refusal arms are the
release boundary — every malformed policy/receipt class must execute its
arm so broken evidence can never be silently accepted. These cases extend
the tools/contract fixture harness with deliberate breakage of each kind.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools" / "contract"))

import test_validate_contract as base  # noqa: E402
import validate_contract as vc  # noqa: E402


class ContractErrorArmTests(base.ContractTests):
    """Fixture-driven refusal cases on top of the shared example package."""

    """Fixture-driven refusal cases on top of the shared example package."""

    def test_missing_required_receipt_field_is_flagged(self) -> None:
        """Why: a required field vanishing must be a finding, not silence."""
        del self.data["created_at"]
        result = self.run_check()
        self.assertNotEqual(result["result"], "PASS")

    def test_unexpected_receipt_field_is_flagged(self) -> None:
        """Why: unexpected fields are refused so schema drift cannot creep."""
        self.data["surprise_field"] = 1
        result = self.run_check()
        self.assertNotEqual(result["result"], "PASS")

    def test_wrong_type_is_flagged(self) -> None:
        """Why: type violations are distinct refusal arms."""
        self.data["created_at"] = 7
        result = self.run_check()
        self.assertNotEqual(result["result"], "PASS")

    def test_bogus_gate_status_is_flagged(self) -> None:
        """Why: enum-constant violations must refuse."""
        self.data["commands"][0]["status"] = "mystery-status"
        result = self.run_check()
        self.assertNotEqual(result["result"], "PASS")

    def test_empty_commands_is_flagged(self) -> None:
        """Why: a receipt with no executed commands cannot claim a
        passing verdict.
        """
        self.data["commands"] = []
        result = self.run_check()
        self.assertNotEqual(result["result"], "PASS")

    def test_malformed_receipt_json_never_passes(self) -> None:
        """Why: malformed JSON must be refused — either as a typed
        ContractError or as a non-PASS report; silence is forbidden.
        """
        self.receipt.write_text("{broken", encoding="utf-8")
        try:
            result = vc.validate(
                self.policy,
                self.receipt,
                self.root,
                repo=base.REPO,
                target_sha=base.SHA,
                profile_sha=base.PROFILE,
                now=self.clock,
            )
        except vc.ContractError:
            return
        self.assertNotEqual(result["result"], "PASS")

    def test_oversized_receipt_never_passes(self) -> None:
        """Why: the 2 MiB input budget must be enforced before parsing."""
        self.receipt.write_text('{"pad": "' + "x" * (2 * 1024 * 1024 + 10) + '"}', encoding="utf-8")
        try:
            result = vc.validate(
                self.policy,
                self.receipt,
                self.root,
                repo=base.REPO,
                target_sha=base.SHA,
                profile_sha=base.PROFILE,
                now=self.clock,
            )
        except vc.ContractError:
            return
        self.assertNotEqual(result["result"], "PASS")

    def test_main_refuses_missing_arguments(self) -> None:
        """Why: the CLI's argument contract must fail with usage, not a
        traceback.
        """
        with self.assertRaises(SystemExit) as ctx:
            vc.main([])
        self.assertEqual(ctx.exception.code, 2)

    def test_main_refuses_nonexistent_paths(self) -> None:
        """Why: nonexistent inputs exit nonzero with a clear report."""
        code = vc.main(
            [
                "--policy",
                str(self.root / "no-policy.toml"),
                "--receipt",
                str(self.root / "no-receipt.json"),
                "--evidence-root",
                str(self.root),
                "--repo",
                "strmt7/rejection-rejector",
                "--target-sha",
                "0" * 40,
                "--profile-sha",
                "1" * 64,
            ]
        )
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
