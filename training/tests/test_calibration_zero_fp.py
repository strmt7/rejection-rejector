#!/usr/bin/env python3
"""Tests for training/calibrate_zero_fp.py (RR-02 calibration contract).

Covers the documented acceptance: close-score cases achieve the feasible
zero-FP recall optimum, reported counts match the selected threshold, invalid
rows fail before any report, an explicit abstain-all outcome replaces any
out-of-range threshold, class-empty runs are labelled diagnostics with null
metrics and reasons, and a small independent exhaustive oracle agrees with the
selection on randomized data.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TRAINING = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TRAINING))

import calibrate_zero_fp as czf  # noqa: E402


def ref_optimum(neg_scores: list[float], pos_scores: list[float], target_fp: int) -> int:
    """Independent exhaustive reference: best achievable TP at 0.0001 resolution.

    Deliberately naive and separate from the production selection: a dense
    fixed grid recomputed with plain loops over raw float lists. Test scores
    are multiples of 0.0001, so this grid captures every decision set the
    `>=` rule can induce at the data's resolution. Output: best true-positive
    count among thresholds with fp <= target_fp (0 when none).
    """
    best_tp = 0
    k = 0
    while k <= 10000:
        threshold = k / 10000
        fp = 0
        for score in neg_scores:
            if score >= threshold:
                fp += 1
        if fp <= target_fp:
            tp = 0
            for score in pos_scores:
                if score >= threshold:
                    tp += 1
            if tp > best_tp:
                best_tp = tp
        k += 1
    return best_tp


def row(label: str, score: object) -> dict:
    return {"label": label, "rejection_probability": score}


class CloseScoreOptimum(unittest.TestCase):
    """RR-02: decision boundaries, not a coarse grid (manual finding N03)."""

    def test_manual_straddle_case_reaches_feasible_one_tp(self):
        # The audited 0.001-grid returned threshold 0.501 / TP 0 here; the
        # feasible cutoff region under `>=` is (0.5001, 0.5002] and the
        # canonical reported cutoff is the positive score itself: 0.5002.
        report = czf.calibrate([row("not_rejection", 0.5001), row("rejection", 0.5002)], 0)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["true_positives"], 1)
        self.assertEqual(report["false_positives"], 0)
        self.assertEqual(report["threshold"], 0.5002)

    def test_reported_counts_match_reported_threshold(self):
        rng = random.Random(7)
        for _ in range(20):
            rows = [row("not_rejection", round(rng.uniform(0.0, 1.0), 4)) for _ in range(rng.randint(1, 5))] + [
                row("rejection", round(rng.uniform(0.0, 1.0), 4)) for _ in range(rng.randint(1, 5))
            ]
            report = czf.calibrate(rows, rng.randint(0, 2))
            if report["status"] != "ok":
                continue
            neg = [r for r in rows if r["label"] != "rejection"]
            pos = [r for r in rows if r["label"] == "rejection"]
            fp, tp = czf.counts_at(neg, pos, report["threshold"])
            self.assertEqual((fp, tp), (report["false_positives"], report["true_positives"]))

    def test_agrees_with_independent_exhaustive_oracle(self):
        rng = random.Random(20261027)
        for _ in range(60):
            neg_scores = [round(rng.uniform(0.0, 1.0), 4) for _ in range(rng.randint(1, 6))]
            pos_scores = [round(rng.uniform(0.0, 1.0), 4) for _ in range(rng.randint(1, 6))]
            target = rng.randint(0, 1)
            report = czf.calibrate(
                [row("not_rejection", s) for s in neg_scores] + [row("rejection", s) for s in pos_scores],
                target,
            )
            expected_tp = ref_optimum(neg_scores, pos_scores, target)
            got_tp = report["true_positives"] if report["status"] == "ok" else 0
            self.assertEqual(got_tp, expected_tp, f"scores {neg_scores} / {pos_scores}")

    def test_close_score_pairs_reach_feasible_optimum(self):
        rng = random.Random(42)
        for _ in range(40):
            base = round(rng.uniform(0.2, 0.8), 4)
            neg_score = round(base + rng.uniform(-0.0005, 0.0), 4)
            pos_score = round(base + rng.uniform(0.0001, 0.0005), 4)
            report = czf.calibrate([row("not_rejection", neg_score), row("rejection", pos_score)], 0)
            # The feasible optimum for a straddling pair is always TP 1 / FP 0.
            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["true_positives"], 1)
            self.assertEqual(report["false_positives"], 0)


class TiesBudgetsAndAbstention(unittest.TestCase):
    """Manual RR-02 acceptance: ties, endpoints, budgets, abstain-all."""

    def test_equal_scores_cannot_be_separated(self):
        rows = [row("not_rejection", 0.5), row("rejection", 0.5)]
        strict = czf.calibrate(rows, 0)
        self.assertEqual(strict["status"], "abstain_all")
        loose = czf.calibrate(rows, 1)
        self.assertEqual(loose["status"], "ok")
        self.assertEqual(loose["threshold"], 0.5)
        self.assertEqual((loose["true_positives"], loose["false_positives"]), (1, 1))

    def test_score_endpoints(self):
        report = czf.calibrate([row("not_rejection", 0.0), row("rejection", 1.0)], 0)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["threshold"], 1.0)
        self.assertEqual(report["true_positives"], 1)
        # A positive at exactly 0.0 is captured at threshold 0.0 under >=.
        report = czf.calibrate([row("not_rejection", 0.0), row("rejection", 0.0)], 0)
        self.assertEqual(report["status"], "abstain_all")

    def test_permitted_target_fp_counts(self):
        rows = [
            row("not_rejection", 0.7),
            row("rejection", 0.75),
            row("rejection", 0.6),
        ]
        strict = czf.calibrate(rows, 0)
        self.assertEqual(strict["true_positives"], 1)
        self.assertEqual(strict["false_positives"], 0)
        loose = czf.calibrate(rows, 1)
        self.assertEqual(loose["true_positives"], 2)
        self.assertEqual(loose["false_positives"], 1)
        self.assertEqual(loose["threshold"], 0.6)

    def test_abstain_all_is_explicit(self):
        report = czf.calibrate([row("not_rejection", 0.9), row("rejection", 0.1)], 0)
        self.assertEqual(report["status"], "abstain_all")
        self.assertIsNone(report["threshold"])
        self.assertNotEqual(report.get("threshold"), 1.01)
        self.assertEqual(report["true_positives"], 0)
        self.assertEqual(report["false_positives"], 0)


class DiagnosticsAndValidation(unittest.TestCase):
    """Manual N04 acceptance: invalid rows fail; class-empty stays diagnostic."""

    def test_class_empty_diagnostics_keep_counts_and_null_metrics(self):
        empty = czf.calibrate([], 0)
        self.assertEqual(empty["status"], "insufficient_data")
        self.assertIsNone(empty["threshold"])
        self.assertEqual(empty["positives"], 0)
        self.assertEqual(empty["negatives"], 0)

        only_neg = czf.calibrate([row("not_rejection", 0.4)], 0)
        self.assertEqual(only_neg["status"], "insufficient_data")
        self.assertIsNone(only_neg["threshold"])
        self.assertIsNone(only_neg["recall"])
        self.assertEqual(only_neg["negatives"], 1)
        self.assertIn("recall", only_neg["metric_reasons"])

        only_pos = czf.calibrate([row("rejection", 0.4)], 0)
        self.assertEqual(only_pos["status"], "insufficient_data")
        self.assertIsNone(only_pos["false_positive_rate_upper_95"])
        self.assertEqual(only_pos["positives"], 1)
        self.assertIn("false_positive_rate_upper_95", only_pos["metric_reasons"])

    def test_ambiguous_is_explicitly_negative(self):
        report = czf.calibrate([row("ambiguous", 0.95), row("rejection", 0.9)], 0)
        self.assertEqual(report["status"], "abstain_all")
        self.assertEqual(report["ambiguous_in_negatives"], 1)
        self.assertEqual(report["negatives"], 1)

    def test_invalid_rows_fail_before_any_report(self):
        bad_rows = [
            row("not_rejection", float("nan")),
            row("not_rejection", float("inf")),
            row("not_rejection", -0.1),
            row("not_rejection", 1.5),
            row("not_rejection", 2.0),
            row("not_rejection", True),
            row("not_rejection", False),
            row("not_rejection", "0.5"),
            row("not_rejection", None),
            row("maybe", 0.5),
            {"rejection": 0.5},
            {"label": "rejection"},
            ["rejection", 0.5],
            "rejection",
        ]
        for bad in bad_rows:
            with self.subTest(bad=bad), self.assertRaises(czf.ScoreRowError):
                czf.calibrate([bad], 0)

    def test_target_fp_validation_in_public_api(self):
        rows = [row("not_rejection", 0.1), row("rejection", 0.9)]
        bad_budgets: list = [-1, 1.5, "0", True]
        for budget in bad_budgets:
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                czf.calibrate(rows, budget)

    def test_load_scores_reports_line_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scores.jsonl"
            path.write_text(
                '{"label": "rejection", "rejection_probability": 0.9}\n'
                '{"label": "maybe", "rejection_probability": 0.5}\n',
                encoding="utf-8",
            )
            with self.assertRaises(czf.ScoreRowError) as ctx:
                czf.load_scores(path)
            self.assertIn("line 2", str(ctx.exception))

            path.write_text("{not json\n", encoding="utf-8")
            with self.assertRaises(czf.ScoreRowError) as ctx:
                czf.load_scores(path)
            self.assertIn("line 1", str(ctx.exception))


class CliContract(unittest.TestCase):
    """The CLI reports the same contract and fails closed on invalid input."""

    def run_cli(self, body: str, *extra: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scores.jsonl"
            path.write_text(body, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(TRAINING / "calibrate_zero_fp.py"), "--scores", str(path), *extra],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )

    def test_valid_input_reports_identity_and_status(self):
        done = self.run_cli(
            '{"label": "not_rejection", "rejection_probability": 0.2}\n'
            '{"label": "rejection", "rejection_probability": 0.9}\n'
        )
        self.assertEqual(done.returncode, 0)
        report = json.loads(done.stdout)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["comparison"], "score >= threshold")
        self.assertEqual(report["split_role"], "calibration")
        self.assertIn("sha256", report["input"])
        self.assertEqual(report["input"]["rows"], 2)

    def test_invalid_input_exits_two_without_a_report(self):
        done = self.run_cli('{"label": "not_rejection", "rejection_probability": 2.0}\n')
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout.strip(), "")
        self.assertIn("line 1", done.stderr)

    def test_negative_budget_exits_two(self):
        done = self.run_cli(
            '{"label": "rejection", "rejection_probability": 0.9}\n'
            '{"label": "not_rejection", "rejection_probability": 0.1}\n',
            "--target-fp",
            "-1",
        )
        self.assertEqual(done.returncode, 2)


class WilsonBound(unittest.TestCase):
    """Zero observed false positives is never reported as zero risk."""

    def test_zero_failures_still_reports_a_positive_bound(self):
        bound = czf.wilson_upper_bound(0, 10)
        self.assertGreater(bound, 0.0)
        self.assertLessEqual(bound, 1.0)

    def test_zero_trials_is_undefined_but_conservative(self):
        self.assertEqual(czf.wilson_upper_bound(0, 0), 1.0)

    def test_bound_monotone_in_failures(self):
        bounds = [czf.wilson_upper_bound(f, 20) for f in range(0, 21)]
        self.assertEqual(bounds, sorted(bounds))


if __name__ == "__main__":
    unittest.main()
