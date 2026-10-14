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
        self.assertEqual(gw.clamp_target(50.0, 50.0), 40.0)
        self.assertEqual(gw.clamp_target(25.0, 50.0), 20.0)
        self.assertEqual(gw.clamp_target(20.0, 50.0), 20.0)

    def test_should_stop_only_at_floor_after_threshold(self):
        # Not at the floor yet: keep throttling, never stop.
        self.assertFalse(gw.should_stop(40.0, 99))
        # At the floor: stop after 3 consecutive breaches.
        self.assertFalse(gw.should_stop(20.0, 2))
        self.assertTrue(gw.should_stop(20.0, 3))
        self.assertTrue(gw.should_stop(20.0, 10))


class HandleSampleTests(unittest.TestCase):
    """End-to-end sample handling against a real control file."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.duty = self.dir / "duty.json"
        self.log = self.dir / "watch.jsonl"
        dc.write_target(self.duty, 50.0)
        self.wd = gw.Watchdog(pid=1, duty_path=self.duty, ceiling=50.0, log_path=self.log)

    def _events(self):
        return [json.loads(l) for l in self.log.read_text(encoding="utf-8").splitlines()]

    def test_compliant_sample_changes_nothing(self):
        keep = self.wd.handle_sample(45)
        self.assertTrue(keep)
        self.assertEqual(dc.read_target(self.duty), 50.0)

    def test_breach_lowers_live_duty_immediately(self):
        # Why: the trainer reads duty.json every micro-batch, so a breach
        # must be visible there without any restart.
        keep = self.wd.handle_sample(80)
        self.assertTrue(keep)
        self.assertEqual(dc.read_target(self.duty), 40.0)
        self.assertEqual(self._events()[-1]["event"], "breach")

    def test_breach_at_floor_stops_after_three_consecutive(self):
        dc.write_target(self.duty, 20.0)
        self.assertTrue(self.wd.handle_sample(80))
        self.assertTrue(self.wd.handle_sample(80))
        self.assertFalse(self.wd.handle_sample(80))
        self.assertTrue(dc.read_stop_flag(self.duty))
        self.assertEqual(self._events()[-1]["event"], "cooperative_stop_requested")

    def test_compliant_sample_between_breaches_resets_the_floor_count(self):
        dc.write_target(self.duty, 20.0)
        self.assertTrue(self.wd.handle_sample(80))
        self.assertTrue(self.wd.handle_sample(80))
        self.assertTrue(self.wd.handle_sample(10))  # resets
        self.assertTrue(self.wd.handle_sample(80))
        self.assertTrue(self.wd.handle_sample(80))
        self.assertFalse(self.wd.handle_sample(80))


class CliTests(unittest.TestCase):
    """The CLI must parse: Python 3.14 validates argparse help strings at
    parse time, and a bare '%' in help text used to crash the watchdog
    before it could start (caught live — pinned here as a regression)."""

    def test_help_exits_clean(self):
        with self.assertRaises(SystemExit) as ctx:
            gw.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
