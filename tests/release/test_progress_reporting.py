"""Failure-mode tests for the live progress probe.

These pin the properties that make live probing trustworthy: no torn reads,
no invented progress, honest staleness, and bounded arithmetic.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "training"))
import progress  # noqa: E402


class ProgressReportingTest(unittest.TestCase):
    """Probes must distinguish slow from dead and never fabricate numbers."""

    def test_write_progress_is_atomic_for_readers(self):
        # Why: a probe reading a torn write would report garbage; the writer
        # must land complete JSON in one rename.
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "progress.json"
            progress.write_progress(path, {"step": 1, "total_steps": 2, "updated_at_unix": 1000.0})
            record = progress.load_heartbeat(path)
            self.assertEqual(record["step"], 1)

    def test_malformed_heartbeat_fails_closed(self):
        # Why: invented progress would hide a crashed job.
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "progress.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                progress.load_heartbeat(path)

    def test_summary_computes_rate_percent_and_eta(self):
        record = {"step": 50, "total_steps": 200, "elapsed_seconds": 100.0, "updated_at_unix": 1000.0, "status": "running"}
        summary = progress.summarize(record, now=1010.0)
        self.assertEqual(summary["percent"], 25.0)
        self.assertAlmostEqual(summary["rate_per_second"], 0.5)
        self.assertAlmostEqual(summary["eta_seconds"], 300.0)
        self.assertFalse(summary["stalled"])

    def test_stale_heartbeat_reports_stalled_even_while_status_says_running(self):
        # Why: a killed job leaves a "running" heartbeat; the probe must not
        # present it as healthy.
        record = {"step": 5, "total_steps": 10, "elapsed_seconds": 5.0, "updated_at_unix": 0.0, "status": "running"}
        summary = progress.summarize(record, now=10_000.0)
        self.assertTrue(summary["stalled"])

    def test_rate_and_eta_are_none_when_not_computable(self):
        record = {"step": 0, "total_steps": 10, "elapsed_seconds": 0.0, "updated_at_unix": 1.0, "status": "running"}
        summary = progress.summarize(record, now=2.0)
        self.assertIsNone(summary["rate_per_second"])
        self.assertIsNone(summary["eta_seconds"])
        self.assertEqual(summary["percent"], 0.0)


if __name__ == "__main__":
    unittest.main()
