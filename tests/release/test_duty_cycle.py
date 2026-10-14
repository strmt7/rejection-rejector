"""Tests for the duty-cycle GPU pacing contract (training/duty_cycle.py).

The duty.json control file is a shared contract between the Rust monitor
GUI and this Python trainer hook, so every boundary is pinned: target
validation, the pacing formula, fail-closed reads, atomic writes, and
sliced sleeping that keeps heartbeats fresh under deep throttling.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "training"))

import duty_cycle as dc  # noqa: E402


class ValidateTargetTests(unittest.TestCase):
    """Target bounds are a product decision: fan-noise floor vs runaway
    runtime. Out-of-range or non-finite input must be rejected so a
    corrupt file can never throttle a run into a stall."""

    def test_bounds_are_exact(self):
        self.assertEqual(dc.validate_target_pct(20.0), 20.0)
        self.assertEqual(dc.validate_target_pct(100.0), 100.0)
        self.assertEqual(dc.validate_target_pct("55"), 55.0)
        with self.assertRaises(ValueError):
            dc.validate_target_pct(19.999)
        with self.assertRaises(ValueError):
            dc.validate_target_pct(100.001)
        with self.assertRaises(ValueError):
            dc.validate_target_pct("nan")
        with self.assertRaises(ValueError):
            dc.validate_target_pct("not-a-number")
        with self.assertRaises(ValueError):
            dc.validate_target_pct(None)


class SleepSecondsTests(unittest.TestCase):
    """The formula is the core of the ceiling: off = on * (100 - t) / t.
    Exact at the boundaries; never negative."""

    def test_formula_matches_duty_cycle_definition(self):
        self.assertEqual(dc.sleep_seconds(10.0, 100.0), 0.0)
        self.assertAlmostEqual(dc.sleep_seconds(10.0, 50.0), 10.0)
        self.assertAlmostEqual(dc.sleep_seconds(10.0, 25.0), 30.0)
        self.assertEqual(dc.sleep_seconds(0.0, 50.0), 0.0)
        self.assertEqual(dc.sleep_seconds(-3.0, 50.0), 0.0)

    def test_invalid_target_never_paces(self):
        # Fail closed to uncapped rather than crashing the training step.
        self.assertEqual(dc.sleep_seconds(10.0, 999.0), 0.0)


class ControlFileTests(unittest.TestCase):
    """duty.json is written by the GUI and read every training step:
    reads must fail closed, writes must be atomic."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.path = self.dir / "duty.json"

    def test_round_trip(self):
        dc.write_target(self.path, 45.0)
        self.assertEqual(dc.read_target(self.path), 45.0)

    def test_read_fail_closed(self):
        self.assertIsNone(dc.read_target(self.path))  # missing
        self.path.write_text("garbage", encoding="utf-8")
        self.assertIsNone(dc.read_target(self.path))  # malformed
        self.path.write_text(json.dumps({"target_pct": 5.0}), encoding="utf-8")
        self.assertIsNone(dc.read_target(self.path))  # out of range
        self.path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
        self.assertIsNone(dc.read_target(self.path))  # wrong shape

    def test_write_rejects_out_of_range_and_keeps_last_value(self):
        dc.write_target(self.path, 55.0)
        with self.assertRaises(ValueError):
            dc.write_target(self.path, 5.0)
        self.assertEqual(dc.read_target(self.path), 55.0)

    def test_write_is_atomic_no_tmp_left(self):
        dc.write_target(self.path, 70.0)
        self.assertFalse((self.dir / "duty.json.tmp").exists())

    def test_control_path_is_sibling_of_progress(self):
        self.assertEqual(
            dc.control_path_for(Path("/run/progress.json")),
            Path("/run/duty.json"),
        )


class PacedSleepTests(unittest.TestCase):
    """Sliced sleeping keeps heartbeats fresh under deep throttling (the
    stall instruments watch heartbeat age, so long sleeps must touch)."""

    def test_slices_and_touches(self):
        slept = []
        touches = []

        def fake_sleep(s):
            slept.append(s)

        total = dc.paced_sleep(
            50.0,
            touch=lambda: touches.append(1),
            slice_s=20.0,
            sleep_fn=fake_sleep,
        )
        self.assertAlmostEqual(total, 50.0)
        self.assertEqual(len(slept), 3)  # 20 + 20 + 10
        self.assertAlmostEqual(slept[-1], 10.0)
        self.assertEqual(len(touches), 3)  # one refresh per slice

    def test_non_positive_returns_immediately(self):
        slept = []
        total = dc.paced_sleep(-1.0, sleep_fn=lambda s: slept.append(s))
        self.assertEqual(total, 0.0)
        self.assertEqual(slept, [])


if __name__ == "__main__":
    unittest.main()
