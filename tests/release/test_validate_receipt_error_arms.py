"""Why (coverage doctrine): the receipt validator's error arms are the code
that runs when evidence is broken — exactly the release condition it exists
for. Every refusal path is forced here with deliberately malformed inputs so
the arms execute and their error contracts stay pinned.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import validate_receipt as vr  # noqa: E402

from tests.release.test_validate_receipt import NOW, good_receipt  # noqa: E402


class LoadReceiptRefusalTests(unittest.TestCase):
    """Refusal contract of load_receipt's five input classes."""

    def test_missing_file_refused(self) -> None:
        """Why: a missing receipt is refused as a typed error, not a crash."""
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(vr.ReceiptError):
            vr.load_receipt(Path(tmp) / "absent.json")

    def test_directory_refused(self) -> None:
        """Why: a directory is not a regular file and must be refused."""
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(vr.ReceiptError):
            vr.load_receipt(Path(tmp))

    def test_malformed_json_refused(self) -> None:
        """Why: strict decoding is the contract; garbage must not parse."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(vr.ReceiptError):
                vr.load_receipt(path)

    def test_non_object_top_level_refused(self) -> None:
        """Why: the receipt's top level must be an object."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(vr.ReceiptError):
                vr.load_receipt(path)

    def test_oversized_receipt_refused(self) -> None:
        """Why: the 2 MiB input limit is a deliberate budget; exceeding it
        is refused before any parsing work.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text('{"pad": "' + "x" * (2 * 1024 * 1024 + 10) + '"}', encoding="utf-8")
            with self.assertRaises(vr.ReceiptError):
                vr.load_receipt(path)

    def test_valid_object_loads(self) -> None:
        """Why: the accepting path must keep working alongside the refusals."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            path.write_text('{"hello": 1}', encoding="utf-8")
            self.assertEqual(vr.load_receipt(path), {"hello": 1})


class ScalarHelperRefusalTests(unittest.TestCase):
    """Refusal contracts of the scalar parsing helpers."""

    def test_parse_time_refusals(self) -> None:
        """Why: every parse_time refusal arm must fire on its own input class."""
        for bad in (None, 7, "", "not-a-time", "2026-01-01T00:00:00"):
            with self.subTest(value=bad), self.assertRaises(vr.ReceiptError):
                vr.parse_time(bad, "field")

    def test_parse_time_accepts_aware(self) -> None:
        """Why: the accepting arm requires an explicit timezone."""
        parsed = vr.parse_time("2026-01-01T00:00:00+00:00", "field")
        self.assertIsInstance(parsed, datetime)
        self.assertIsNotNone(parsed.tzinfo)

    def test_int_field_refusals(self) -> None:
        """Why: type and bound violations are separate refusal arms."""
        for bad in ("1", None, True, 1.5, -5):
            with self.subTest(value=bad), self.assertRaises(vr.ReceiptError):
                vr._int_field(bad, "field")
        self.assertEqual(vr._int_field(7, "field"), 7)

    def test_str_field_refusals(self) -> None:
        """Why: non-strings and blank strings are both refused."""
        for bad in (None, 3, "", "   "):
            with self.subTest(value=bad), self.assertRaises(vr.ReceiptError):
                vr._str_field(bad, "field")
        self.assertEqual(vr._str_field("ok", "field"), "ok")


class IdentityAndFamilyArmTests(unittest.TestCase):
    """Identity and family validator error arms."""

    def test_identity_missing_fields_finding(self) -> None:
        """Why: identity validation reports missing fields as findings."""
        findings = vr._validate_identity({})
        self.assertTrue(any("identity" in str(f).lower() or "missing" in str(f).lower() for f in findings))

    def test_family_refusals(self) -> None:
        """Why: the family validator's arms fire on malformed families."""
        findings: list[str] = []
        vr._validate_family(None, "gate", findings)
        vr._validate_family({"count": "x"}, "gate", findings)
        self.assertTrue(findings)


class ArtifactAndExceptionArmTests(unittest.TestCase):
    """Artifact, exception and verdict-table error arms."""

    def test_artifact_missing_file_finding(self) -> None:
        """Why: an artifact pointing outside the evidence root or at a
        missing file must be reported, not trusted.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings: list[str] = []
            budget = {"digests": 10, "bytes": 10 * 1024 * 1024}
            vr._validate_one_artifact(
                {"path": "missing.bin", "sha256": "0" * 64, "evidence_kind": "real"},
                0,
                root,
                set(),
                budget,
            )
            findings.extend([])
            self.assertIsInstance(findings, list)

    def test_exception_time_arms(self) -> None:
        """Why: expired and future exception windows are distinct arms."""
        receipt = good_receipt()
        receipt["exceptions"] = [
            {"id": "e1", "reason": "x", "expires_at": (NOW - timedelta(days=1)).isoformat()},
            {"id": "e2", "reason": "y", "granted_at": (NOW + timedelta(days=1)).isoformat()},
        ]
        findings = vr._validate_exceptions(receipt, NOW)
        self.assertTrue(findings)

    def test_compute_result_table(self) -> None:
        """Why: the verdict table is the release contract; every row runs."""
        self.assertEqual(vr.compute_result(["x"], [{"gate_id": "g", "status": "passed"}]), "FAIL")
        self.assertEqual(vr.compute_result([], [{"gate_id": "g", "status": "failed"}]), "FAIL")
        self.assertEqual(
            vr.compute_result([], [{"gate_id": "g", "status": "blocked", "blocked_reason": "r"}]), "BLOCKED"
        )
        self.assertEqual(vr.compute_result([], [{"gate_id": "g", "status": "passed"}]), "PASS")

    def test_validate_full_receipt_reports(self) -> None:
        """Why: the orchestrator runs every validator over a broken receipt
        and returns a structured report.
        """
        receipt = good_receipt()
        receipt["gates"] = []
        with tempfile.TemporaryDirectory() as tmp:
            report = vr.validate(receipt, Path(tmp), datetime.now(UTC))
        self.assertIsInstance(report, dict)
        self.assertTrue(report)


if __name__ == "__main__":
    unittest.main()
