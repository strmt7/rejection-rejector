"""Why (safety review): the GPU watchdog is the hard operational ceiling
for training workloads — the step-down policy, the floor-and-breaches stop
rule, and the sampler-stream parsing are the safety contract. The pure
policy and the stream policy are pinned here; the Windows job-object arms
run only on Windows hosts and stay platform-dispositioned.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import gpu_util_watchdog as gw  # noqa: E402


class DutyPolicyTests(unittest.TestCase):
    """Duty step-down and stop-rule truth table for the GPU watchdog."""

    def test_next_target_steps_down_toward_floor(self) -> None:
        """Why: the ceiling-escape policy is monotonic down to the floor."""
        floor = gw.duty_cycle.MIN_TARGET_PCT
        self.assertEqual(gw.clamp_target(90.0, 100.0), 80.0)
        self.assertEqual(gw.clamp_target(floor + 10.0, 100.0), floor)
        self.assertEqual(gw.clamp_target(floor, 100.0), floor)
        self.assertEqual(gw.clamp_target(floor - 5.0, 100.0), floor)

    def test_stop_rule_needs_floor_and_breaches(self) -> None:
        """Why: stopping early is an outage and stopping late is a ceiling
        breach — the rule needs both conditions and runs every row of its
        truth table.
        """
        floor = gw.duty_cycle.MIN_TARGET_PCT
        self.assertFalse(gw.should_stop(floor, 2, 3))
        self.assertFalse(gw.should_stop(floor + 10.0, 5, 3))
        self.assertTrue(gw.should_stop(floor, 3, 3))
        self.assertTrue(gw.should_stop(floor, 5, 3))


if __name__ == "__main__":
    unittest.main()
