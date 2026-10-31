#!/usr/bin/env python3
"""Tests for mine_enron's full mining pipeline (emit + verification).

Runs the complete miner over a small fixture maildir with genuine
decision language: distribution-constrained selection, post-serialization
redaction scanning, schema/leakage/count verification, and the report.
The same-seed corpus must reproduce byte for byte.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

import mine_enron  # noqa: E402


def fixture_corpus(root: pathlib.Path) -> pathlib.Path:
    """Purpose: Build a fixture maildir with genuine mining categories.

    Inputs: `root` -- working directory; Output: the corpus directory with
    one rejection, one hiring-other and one uncertain message.
    """
    corpus = root / "corpus"
    corpus.mkdir()
    mails = {
        "rejection.eml": (
            "Application update",
            "We regret to inform you that we will not be moving forward with "
            "your application for the engineer role at this time.",
        ),
        "other.eml": (
            "Open position",
            "We are recruiting for a software engineer position on our team and reviewing applications this week.",
        ),
        "uncertain.eml": (
            "Your candidacy",
            "Thank you for applying to the job; we are still reviewing your "
            "application and will respond about the position later.",
        ),
    }
    for name, (subject, body) in mails.items():
        (corpus / name).write_bytes(f"From: careers@example.invalid\r\nSubject: {subject}\r\n\r\n{body}".encode())
    return corpus


def run_miner(root: pathlib.Path, out: pathlib.Path) -> tuple[int, str]:
    """Purpose: Execute the full miner over the fixture corpus.

    Inputs: `root` -- working directory; `out` -- output directory;
    Output: (exit code, captured stdout).
    """
    argv = [
        "mine_enron.py",
        "--corpus",
        str(root / "corpus"),
        "--out-dir",
        str(out),
        "--target",
        "2",
        "--seed",
        "9",
    ]
    capture = io.StringIO()
    with mock.patch("sys.argv", argv), redirect_stdout(capture):
        code = mine_enron.main()
    return code, capture.getvalue()


class FullPipelineTests(unittest.TestCase):
    """Pin the complete mining pipeline over fixture data."""

    def test_full_run_verifies_and_reproduces_byte_identically(self):
        """The pipeline mines, redaction-scans, verifies and writes its
        outputs; a second same-seed run reproduces the corpus bytes
        exactly. A fixture-scale corpus exits 1 by design: the documented
        production envelope is 1000-3000 rows and the count checks report
        the shortfall — every OTHER check must pass.
        """
        outputs = []
        for _run in range(2):
            with tempfile.TemporaryDirectory() as owned:
                root = pathlib.Path(owned)
                fixture_corpus(root)
                out = root / "out"
                code, text = run_miner(root, out)
                self.assertEqual(code, 1, text[-600:])
                self.assertIn("VERIFICATION: FAIL", text)
                rows = out / "enron_mined_v1.jsonl"
                report = out / "enron_mined_report.json"
                self.assertTrue(rows.is_file())
                self.assertTrue(report.is_file())
                outputs.append(rows.read_bytes())
                parsed = json.loads(report.read_text(encoding="utf-8"))
                counts = parsed["validation"]["counts_recomputed_from_file"]
                self.assertFalse(counts["total_in_target_range"], counts)
                self.assertTrue(
                    all(value for key, value in counts.items() if key != "total_in_target_range"),
                    counts,
                )
                # The post-serialization sweep (security review finding 2)
                # must report clean totals on every shipped row.
                sweep = parsed["redaction"]["sweep_leftovers"]
                self.assertTrue(all(value == 0 for value in sweep.values()), sweep)
        self.assertEqual(outputs[0], outputs[1], "same seed must reproduce the mined corpus")

    def test_rows_match_the_reference_schema(self):
        """Every emitted row is a chat record with the audit meta."""
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            fixture_corpus(root)
            out = root / "out"
            code, text = run_miner(root, out)
            self.assertIn(code, (0, 1), text[-600:])
            lines = (out / "enron_mined_v1.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertTrue(lines, "fixture corpus must yield rows")
        for line in lines:
            row = json.loads(line)
            self.assertEqual(
                [message["role"] for message in row["messages"]],
                ["system", "user", "assistant"],
            )
            self.assertIn("id", row["meta"])


class DistributionPlanTests(unittest.TestCase):
    """Pin the distribution-constrained selection plan."""

    def test_plan_is_bounded_by_found_counts_and_target(self):
        """The plan never asks for more rows than exist per category and
        never exceeds the clamped total; even target 0 plans the smallest
        satisfiable total (documented: the count checks report any
        shortfall against the 1000-3000 envelope).
        """
        found = {"rejection": 5, "uncertain": 1, "opportunity": 0, "other": 3}
        plan = mine_enron.plan_distribution(found, 4)
        self.assertLessEqual(sum(plan.values()), 4)
        for category, count in plan.items():
            self.assertLessEqual(count, found[category], category)
        plan_zero = mine_enron.plan_distribution(found, 0)
        self.assertGreater(sum(plan_zero.values()), 0)
        for category, count in plan_zero.items():
            self.assertLessEqual(count, found[category], category)


if __name__ == "__main__":
    unittest.main()
