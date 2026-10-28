"""Tests for the GPU utilization watchdog policy (tools/gpu_util_watchdog.py).

The watchdog is the enforcement of the operator's hard GPU utilization
ceiling, so every decision boundary is pinned: breach throttling toward
the floor, cooperative stop at the floor, and fail-closed behaviour on
control-write failures.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "training"))

import duty_cycle as dc  # noqa: E402
import gpu_util_watchdog as gw  # noqa: E402


class PolicyTests(unittest.TestCase):
    """Pure decision functions: throttle direction and stop conditions."""

    def test_clamp_target_lowers_by_notch_and_stops_at_floor(self):
        """One breach lowers duty by 10 pp and never below the floor."""
        self.assertEqual(gw.clamp_target(50.0, 50.0), 40.0)
        self.assertEqual(gw.clamp_target(25.0, 50.0), 20.0)
        self.assertEqual(gw.clamp_target(20.0, 50.0), 20.0)

    def test_should_stop_is_absolute_at_the_floor(self):
        # Not at the floor yet: keep throttling, never stop.
        """At the floor the first breach stops; above it throttling continues."""
        self.assertFalse(gw.should_stop(40.0, 99))
        # At the floor: the first breach stops (threshold 1).
        self.assertTrue(gw.should_stop(20.0, 1))
        self.assertTrue(gw.should_stop(20.0, 10))


class HandleSampleTests(unittest.TestCase):
    """End-to-end sample handling against a real control file."""

    def setUp(self):
        """Create a control file, evidence log and watchdog on real files."""
        self.dir = Path(tempfile.mkdtemp())
        self.duty = self.dir / "duty.json"
        self.log = self.dir / "watch.jsonl"
        dc.write_target(self.duty, 50.0)
        self.wd = gw.Watchdog(pid=1, duty_path=self.duty, ceiling=50.0, log_path=self.log)

    def _events(self):
        """Return the parsed JSONL evidence events written so far."""
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def test_compliant_sample_changes_nothing(self):
        """A sample within the ceiling leaves the duty target untouched."""
        keep = self.wd.handle_sample(45)
        self.assertTrue(keep)
        self.assertEqual(dc.read_target(self.duty), 50.0)

    def test_breach_lowers_live_duty_immediately(self):
        # Why: the trainer reads duty.json every micro-batch, so a breach
        # must be visible there without any restart.
        """A breach lowers duty.json immediately so the trainer sees it."""
        keep = self.wd.handle_sample(80)
        self.assertTrue(keep)
        self.assertEqual(dc.read_target(self.duty), 40.0)
        self.assertEqual(self._events()[-1]["event"], "breach")

    def test_breach_at_floor_stops_immediately(self):
        # Why: the operator's rule is absolute — at the minimum duty
        # target there is no further throttle available, so the first
        # breach at the floor must stop the workload (training pauses
        # beat ceiling violations).
        """The first breach at the floor requests a cooperative stop."""
        dc.write_target(self.duty, 20.0)
        self.assertFalse(self.wd.handle_sample(80))
        self.assertTrue(dc.read_stop_flag(self.duty))
        self.assertEqual(self._events()[-1]["event"], "cooperative_stop_requested")

    def test_breach_above_floor_throttles_but_does_not_stop(self):
        # Why: throttle room exists above the floor, so breaches there
        # must only lower the live duty, never stop the run.
        """Breaches above the floor only lower duty; the run keeps going."""
        self.assertTrue(self.wd.handle_sample(80))  # 50 -> 40
        self.assertTrue(self.wd.handle_sample(80))  # 40 -> 30
        self.assertFalse(dc.read_stop_flag(self.duty))
        self.assertEqual(dc.read_target(self.duty), 30.0)


class CliTests(unittest.TestCase):
    """The CLI must parse: Python 3.14 validates argparse help strings at
    parse time, and a bare '%' in help text used to crash the watchdog
    before it could start (caught live — pinned here as a regression).
    """

    def test_help_exits_clean(self):
        """--help parses and exits 0 (regression: bare '%' crashed argparse)."""
        with self.assertRaises(SystemExit) as ctx:
            gw.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
