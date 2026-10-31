#!/usr/bin/env python3
"""Tests for training/selective_eval.py (risk-coverage evaluation contract).

Covers: the exact curve accounting at a threshold (ambiguous rows always
deferred), the verdict selection as the HIGHEST-coverage qualifying
operating point (an ordering regression that flipped this once is pinned
here), the refusal path when no threshold meets the precision floor, and
the Wilson lower-bound identity used for the conservative floors.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

from selective_eval import (  # noqa: E402
    curve_point,
    evaluate,
    wilson_lower_bound,
)


def rows_fixture() -> list[dict]:
    """Purpose: Build the standard mixed fixture. Inputs: none; Output: 12
    rejections at 0.95..0.84 (rounded to counter binary-float drift),
    two not-rejections at 0.55 and 0.50, and one ambiguous at 0.95.
    """
    rows = [{"label": "rejection", "rejection_probability": round(0.95 - index * 0.01, 2)} for index in range(12)]
    rows.append({"label": "not_rejection", "rejection_probability": 0.55})
    rows.append({"label": "not_rejection", "rejection_probability": 0.50})
    rows.append({"label": "ambiguous", "rejection_probability": 0.95})
    return rows


class CurveAccountingTests(unittest.TestCase):
    """Pin the per-threshold accounting semantics."""

    def test_ambiguous_always_defers_and_counts_are_exact(self):
        """Why (product semantics): ambiguous mail goes to human review
        regardless of score, so it must never appear in the auto-acted set.
        """
        rows = rows_fixture()
        point = curve_point(rows, 0.84)
        # threshold 0.84: all 12 rejections + the 0.95 ambiguous score
        # qualify by score, but the ambiguous row still defers.
        self.assertEqual(point["auto_acted"], 12)
        self.assertEqual(point["wrong_sends"], 0)
        self.assertEqual(point["deferred"], 3)
        self.assertEqual(point["precision"], 1.0)
        self.assertAlmostEqual(point["coverage"], 12 / 15)

        low = curve_point(rows, 0.50)
        self.assertEqual(low["auto_acted"], 14)  # 12 correct + 2 wrong sends
        self.assertEqual(low["wrong_sends"], 2)
        self.assertAlmostEqual(low["precision"], 12 / 14)
        self.assertEqual(low["deferred"], 1)  # only the ambiguous row


class VerdictTests(unittest.TestCase):
    """Pin verdict selection and refusal semantics."""

    def test_verdict_is_highest_coverage_qualifying_point(self):
        """Why (the operating contract): among thresholds meeting the
        precision floor the operator gets the LARGEST auto-acted share —
        an ascending-scan regression once selected the most conservative
        point instead.
        """
        report = evaluate(rows_fixture(), 0.70)
        self.assertIsNotNone(report["verdict"])
        # 0.84 is the lowest score of the 12 clean rejections: at it the
        # auto-acted set is exactly those 12 (Wilson lower of 12/12 is
        # ~0.757, above the 0.70 floor). Lower thresholds pull in wrong
        # sends (bounds fall below the floor); higher ones qualify too but
        # cover less — the verdict must pick 0.84.
        self.assertEqual(report["verdict"]["threshold"], 0.84)
        self.assertAlmostEqual(report["verdict"]["precision_lower_95"], 0.757, places=2)

    def test_no_qualifying_threshold_refuses(self):
        """Why (fail-closed): an unachievable floor defers everything and
        says so; it never returns a best-effort operating point.
        """
        report = evaluate(rows_fixture(), 1.0)
        self.assertIsNone(report["verdict"])
        self.assertIn("deferring", report["verdict_reason"])

    def test_input_validation(self):
        """Empty input and out-of-range floors fail before any report."""
        with self.assertRaises(ValueError):
            evaluate([], 0.9)
        with self.assertRaises(ValueError):
            evaluate(rows_fixture(), 0.0)
        with self.assertRaises(ValueError):
            evaluate(rows_fixture(), 1.5)

    def test_cli_exit_codes(self):
        """The CLI exits 0 with a verdict and 2 when refusing."""
        import tempfile

        with tempfile.TemporaryDirectory() as owned:
            scores = Path(owned) / "scores.jsonl"
            scores.write_text(
                "\n".join(json.dumps(row) for row in rows_fixture()) + "\n",
                encoding="utf-8",
            )
            accepted = subprocess.run(
                [sys.executable, str(ROOT / "training" / "selective_eval.py"), str(scores), "--precision-floor", "0.7"],
                capture_output=True,
                text=True,
                check=False,
            )
            refused = subprocess.run(
                [sys.executable, str(ROOT / "training" / "selective_eval.py"), str(scores), "--precision-floor", "1.0"],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(accepted.returncode, 0, accepted.stderr[-400:])
        self.assertEqual(refused.returncode, 2, refused.stderr[-400:])


class WilsonBoundTests(unittest.TestCase):
    """Pin the conservative bound identities."""

    def test_identity_and_edge_cases(self):
        """The lower bound equals one minus the upper bound of the
        complementary proportion; zero trials bound to zero.
        """
        self.assertAlmostEqual(
            wilson_lower_bound(10, 10),
            1.0 - wilson_upper(0, 10),
        )
        self.assertEqual(wilson_lower_bound(0, 0), 0.0)
        self.assertAlmostEqual(wilson_lower_bound(10, 10), 0.7225, places=3)

    def test_monotonicity(self):
        """More clean evidence never lowers the bound."""
        self.assertLess(
            wilson_lower_bound(10, 10),
            math.nextafter(wilson_lower_bound(40, 40), 1.0),
        )


def wilson_upper(failures: int, trials: int) -> float:
    """Purpose: Reference the sibling implementation for the identity check.

    Inputs: failures, trials; Output: the upper bound from the shared
    calibrate_zero_fp implementation.
    """
    from calibrate_zero_fp import wilson_upper_bound

    return wilson_upper_bound(failures, trials)


if __name__ == "__main__":
    unittest.main()
