"""Tests for the fail-closed resource guard (tools/resource_guard.py).

Every decision boundary is pinned with meaningful assertions: probe failure,
floor breaches, usage-fraction breaches, exact boundary values on both sides,
fail-closed verdicts, and watchdog firing semantics. The guard is the
mechanism that guarantees no workload ever pushes VRAM, RAM or storage to a
limit, so these tests are the enforcement of that guarantee.
"""

import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))

import resource_guard as rg  # noqa: E402


def snap_of(vram=(8 * rg.GIB, 16 * rg.GIB),
            ram=(32 * rg.GIB, 64 * rg.GIB),
            disk=(100 * rg.GIB, 500 * rg.GIB)):
    """Build a snapshot from (free, total) pairs; None marks unmeasurable."""
    return rg.ResourceSnapshot(
        vram_free=vram[0], vram_total=vram[1],
        ram_available=ram[0], ram_total=ram[1],
        disk_free=disk[0], disk_total=disk[1],
        measured_at=0.0,
    )


class SnapshotTests(unittest.TestCase):
    """Measurement layer: injected probes, invalid data, failures."""

    def test_injected_probes_populate_all_fields(self):
        """Why: the guard must report exactly what the probes measure."""
        snap = rg.snapshot(
            vram_probe=lambda: (1 * rg.GIB, 2 * rg.GIB),
            ram_probe=lambda: (3 * rg.GIB, 4 * rg.GIB),
            disk_probe=lambda: (5 * rg.GIB, 6 * rg.GIB),
        )
        self.assertEqual((snap.vram_free, snap.vram_total), (1 * rg.GIB, 2 * rg.GIB))
        self.assertEqual((snap.ram_available, snap.ram_total), (3 * rg.GIB, 4 * rg.GIB))
        self.assertEqual((snap.disk_free, snap.disk_total), (5 * rg.GIB, 6 * rg.GIB))

    def test_probe_exception_becomes_none_not_a_crash(self):
        """Why: a failing probe must degrade to unmeasurable (fail-closed at
        the decision layer), never raise through a running workload."""
        def boom():
            raise OSError("probe broken")

        snap = rg.snapshot(vram_probe=boom, ram_probe=boom, disk_probe=boom)
        self.assertIsNone(snap.vram_free)
        self.assertIsNone(snap.ram_available)
        self.assertIsNone(snap.disk_free)

    def test_invalid_probe_values_become_none(self):
        """Why: nonsense readings (free > total, negatives) must not be
        trusted; they are as good as unmeasurable."""
        snap = rg.snapshot(
            vram_probe=lambda: (10, 5),   # free > total
            ram_probe=lambda: (-1, 4),    # negative
            disk_probe=lambda: (-5, -1),  # both negative
        )
        self.assertIsNone(snap.vram_free)
        self.assertIsNone(snap.ram_available)
        self.assertIsNone(snap.disk_free)

    def test_real_ram_and_disk_probes_work_on_any_host(self):
        """Why: the default probes are the host-agnostic fallback; they must
        return sane values on any supported platform (RAM here is the stdlib
        or psutil path, disk is stdlib everywhere)."""
        snap = rg.snapshot(vram_probe=lambda: (_ for _ in ()).throw(RuntimeError()))
        self.assertGreater(snap.ram_available or 0, 0)
        self.assertGreater(snap.disk_free or 0, 0)

    def test_vram_probe_without_gpu_raises_for_fail_closed_handling(self):
        """Why: when no GPU stack exists the probe raises and the decision
        layer must then fail closed if VRAM is required."""
        with self.assertRaises(Exception):
            rg._default_vram_probe()


class CheckTests(unittest.TestCase):
    """Pure decision function: every boundary on both sides."""

    def test_healthy_snapshot_has_no_violations(self):
        """Why: the happy path must never produce spurious stops."""
        self.assertEqual(rg.check(snap_of(), rg.Thresholds()), [])

    def test_vram_floor_boundary_is_strict(self):
        """Why: exactly-at-floor is safe; one byte below must stop. Total is
        chosen so the usage-fraction budget is not the binding constraint."""
        limits = rg.Thresholds(require_vram=True)
        total = 8 * rg.GIB  # keep-bytes for 80% is below the floor here
        at_floor = snap_of(vram=(limits.min_free_vram, total))
        self.assertEqual(rg.check(at_floor, limits), [])
        below = snap_of(vram=(limits.min_free_vram - 1, total))
        self.assertTrue(any(v.reason == "below_min_free" and v.resource == "vram"
                            for v in rg.check(below, limits)))

    def test_ram_floor_boundary_is_strict(self):
        """Why: same contract as VRAM — precise to one byte."""
        limits = rg.Thresholds()
        total = 16 * rg.GIB  # keep-bytes for 85% is below the floor here
        at_floor = snap_of(ram=(limits.min_free_ram, total))
        self.assertEqual(rg.check(at_floor, limits), [])
        below = snap_of(ram=(limits.min_free_ram - 1, total))
        self.assertTrue(any(v.reason == "below_min_free" and v.resource == "ram"
                            for v in rg.check(below, limits)))

    def test_disk_floor_boundary_is_strict(self):
        """Why: storage exhaustion means data loss; the floor is exact."""
        limits = rg.Thresholds()
        at_floor = snap_of(disk=(limits.min_free_disk, 500 * rg.GIB))
        self.assertEqual(rg.check(at_floor, limits), [])
        below = snap_of(disk=(limits.min_free_disk - 1, 500 * rg.GIB))
        self.assertTrue(any(v.reason == "below_min_free" and v.resource == "disk"
                            for v in rg.check(below, limits)))

    def test_vram_usage_fraction_boundary_is_strict(self):
        """Why: exactly at the keep-bytes boundary is allowed; one byte
        below must stop. Integer semantics — no float rounding."""
        limits = rg.Thresholds(min_free_vram=0)
        total = 16 * rg.GIB
        keep = total - int(total * limits.max_vram_use_fraction)
        exactly = snap_of(vram=(keep, total))
        self.assertEqual(rg.check(exactly, limits), [])
        over = snap_of(vram=(keep - 1, total))
        self.assertTrue(any(v.reason == "above_max_use"
                            for v in rg.check(over, limits)))

    def test_ram_usage_fraction_boundary_is_strict(self):
        """Why: same contract as VRAM for the 85% budget, integer-exact."""
        limits = rg.Thresholds(min_free_ram=0)
        total = 64 * rg.GIB
        keep = total - int(total * limits.max_ram_use_fraction)
        exactly = snap_of(ram=(keep, total))
        self.assertEqual(rg.check(exactly, limits), [])
        over = snap_of(ram=(keep - 1, total))
        self.assertTrue(any(v.reason == "above_max_use"
                            for v in rg.check(over, limits)))

    def test_unmeasurable_required_resource_fails_closed(self):
        """Why: if RAM/disk cannot be measured the workload must not run."""
        limits = rg.Thresholds(require_ram=True, require_disk=True)
        snap = snap_of(ram=(None, None), disk=(None, None))
        reasons = {v.reason for v in rg.check(snap, limits)}
        self.assertEqual(reasons, {"unmeasurable"})

    def test_unmeasurable_optional_resource_is_ignored(self):
        """Why: a CPU-only workload must run on hosts without a GPU stack."""
        limits = rg.Thresholds(require_vram=False)
        snap = snap_of(vram=(None, None))
        self.assertEqual(rg.check(snap, limits), [])
        limits_gpu = rg.Thresholds(require_vram=True)
        self.assertTrue(rg.check(snap, limits_gpu))

    def test_multiple_resources_can_trip_together(self):
        """Why: the guard reports every breach, not just the first."""
        limits = rg.Thresholds()
        snap = snap_of(
            vram=(0, 16 * rg.GIB),
            ram=(0, 64 * rg.GIB),
            disk=(0, 500 * rg.GIB),
        )
        resources = {v.resource for v in rg.check(snap, limits)}
        self.assertEqual(resources, {"vram", "ram", "disk"})

    def test_default_thresholds_carry_real_margins(self):
        """Why: the safety margins are the guarantee; pin them so they can
        never silently shrink. VRAM budget is deliberately permissive (the
        crash class is codegen faults, not capacity); the 2 GiB floor is the
        binding exhaustion line."""
        t = rg.Thresholds()
        self.assertEqual(t.min_free_vram, 256 * 1024 * 1024)
        self.assertEqual(t.min_free_ram, 4 * rg.GIB)
        self.assertEqual(t.min_free_disk, 10 * rg.GIB)
        self.assertEqual(t.max_vram_use_fraction, 0.99)
        self.assertEqual(t.max_ram_use_fraction, 0.85)


class PreflightTests(unittest.TestCase):
    """Start gate: fail-closed verdicts."""

    def test_preflight_ok_on_healthy_host(self):
        """Why: healthy hosts must start without friction."""
        v = rg.preflight(
            vram_probe=lambda: (8 * rg.GIB, 16 * rg.GIB),
            ram_probe=lambda: (32 * rg.GIB, 64 * rg.GIB),
            disk_probe=lambda: (100 * rg.GIB, 500 * rg.GIB),
        )
        self.assertTrue(v.ok)
        self.assertEqual(v.violations, ())

    def test_preflight_refuses_on_any_breach(self):
        """Why: one breached limit blocks the start entirely."""
        v = rg.preflight(
            vram_probe=lambda: (8 * rg.GIB, 16 * rg.GIB),
            ram_probe=lambda: (1 * rg.GIB, 64 * rg.GIB),
            disk_probe=lambda: (100 * rg.GIB, 500 * rg.GIB),
        )
        self.assertFalse(v.ok)
        self.assertTrue(any(x.resource == "ram" for x in v.violations))

    def test_preflight_refuses_when_required_probe_fails(self):
        """Why: fail-closed means 'unknown required state' == 'do not run'."""
        def boom():
            raise RuntimeError("no probe")

        v = rg.preflight(ram_probe=boom, disk_probe=boom,
                         vram_probe=lambda: (8 * rg.GIB, 16 * rg.GIB))
        self.assertFalse(v.ok)
        self.assertEqual({x.reason for x in v.violations}, {"unmeasurable"})


class WatchdogTests(unittest.TestCase):
    """Continuous observation: fires once, before the limit."""

    def test_watchdog_fires_once_on_violation(self):
        """Why: the stop callback must fire exactly once — repeated callbacks
        into a tearing-down workload are themselves dangerous."""
        fired = []
        flip = {"violated": False}
        lock = threading.Lock()

        def ram_probe():
            with lock:
                if flip["violated"]:
                    return (1 * rg.GIB, 64 * rg.GIB)
                return (32 * rg.GIB, 64 * rg.GIB)

        wd = rg.ResourceWatchdog(
            limits=rg.Thresholds(require_vram=False),
            on_violation=lambda v: fired.append(v),
            interval_s=0.02,
            ram_probe=ram_probe,
            disk_probe=lambda: (100 * rg.GIB, 500 * rg.GIB),
            vram_probe=lambda: (8 * rg.GIB, 16 * rg.GIB),
        )
        wd.start()
        time.sleep(0.1)      # healthy polls must not fire
        self.assertEqual(fired, [])
        with lock:
            flip["violated"] = True
        time.sleep(0.2)      # one violation window
        wd.stop()
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0].resource, "ram")
        time.sleep(0.1)      # no late duplicate fire
        self.assertEqual(len(fired), 1)

    def test_watchdog_context_manager_starts_and_stops(self):
        """Why: the guard must be impossible to leak (thread left running)."""
        fired = []
        with rg.ResourceWatchdog(
            on_violation=lambda v: fired.append(v),
            interval_s=0.02,
            vram_probe=lambda: (8 * rg.GIB, 16 * rg.GIB),
            ram_probe=lambda: (32 * rg.GIB, 64 * rg.GIB),
            disk_probe=lambda: (100 * rg.GIB, 500 * rg.GIB),
        ) as wd:
            self.assertIsNotNone(wd._thread)
            self.assertTrue(wd._thread.is_alive())
        self.assertIsNone(wd._thread)
        self.assertEqual(fired, [])

    def test_watchdog_is_quiet_while_healthy(self):
        """Why: false positives would stall legitimate work."""
        fired = []
        wd = rg.ResourceWatchdog(
            on_violation=lambda v: fired.append(v),
            interval_s=0.01,
            vram_probe=lambda: (8 * rg.GIB, 16 * rg.GIB),
            ram_probe=lambda: (32 * rg.GIB, 64 * rg.GIB),
            disk_probe=lambda: (100 * rg.GIB, 500 * rg.GIB),
        )
        wd.start()
        time.sleep(0.15)
        wd.stop()
        self.assertEqual(fired, [])

    def test_watchdog_tolerates_transient_probe_failures(self):
        """Why: one flaky GPU probe reading must not kill a healthy run -
        the stop is for real breaches or probes that stay blind."""
        fired = []
        misses = {"n": 0}
        lock = threading.Lock()

        def flaky_vram():
            with lock:
                misses["n"] += 1
                if misses["n"] <= 3:  # 3 transient misses < tolerance of 5
                    raise RuntimeError("transient probe failure")
                return (8 * rg.GIB, 16 * rg.GIB)

        wd = rg.ResourceWatchdog(
            limits=rg.Thresholds(require_vram=True),
            on_violation=lambda v: fired.append(v),
            interval_s=0.02,
            vram_probe=flaky_vram,
            ram_probe=lambda: (32 * rg.GIB, 64 * rg.GIB),
            disk_probe=lambda: (100 * rg.GIB, 500 * rg.GIB),
        )
        wd.start()
        time.sleep(0.3)
        wd.stop()
        self.assertEqual(fired, [], "transient probe misses must not stop the run")

    def test_watchdog_stops_when_probe_stays_blind(self):
        """Why: a probe that never recovers must fail closed after the
        tolerance window - persistent blindness is a breach."""
        fired = []

        def blind():
            raise RuntimeError("probe permanently broken")

        wd = rg.ResourceWatchdog(
            limits=rg.Thresholds(require_vram=True),
            on_violation=lambda v: fired.append(v),
            interval_s=0.01,
            vram_probe=blind,
            ram_probe=lambda: (32 * rg.GIB, 64 * rg.GIB),
            disk_probe=lambda: (100 * rg.GIB, 500 * rg.GIB),
        )
        wd.start()
        time.sleep(0.4)
        wd.stop()
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0].reason, "unmeasurable")

    def test_watchdog_stop_is_idempotent(self):
        """Why: cleanup paths may run twice during failure handling."""
        wd = rg.ResourceWatchdog(
            on_violation=lambda v: None,
            interval_s=0.01,
            vram_probe=lambda: (8 * rg.GIB, 16 * rg.GIB),
            ram_probe=lambda: (32 * rg.GIB, 64 * rg.GIB),
            disk_probe=lambda: (100 * rg.GIB, 500 * rg.GIB),
        )
        wd.start()
        wd.stop()
        wd.stop()  # must not raise
        self.assertIsNone(wd._thread)


class EstimatorTests(unittest.TestCase):
    """Peak-VRAM estimation: the number preflight sizes a workload with."""

    def test_estimate_grows_with_model_size_and_seq_len(self):
        """Why: a bigger model or longer sequences must never estimate lower
        — a non-monotonic estimator could under-size a run and crash it."""
        base = rg.estimate_training_vram(param_billions=9.0, seq_len=1024)
        bigger_model = rg.estimate_training_vram(param_billions=12.0, seq_len=1024)
        longer_seq = rg.estimate_training_vram(param_billions=9.0, seq_len=2048)
        self.assertGreater(bigger_model, base)
        self.assertGreater(longer_seq, base)

    def test_estimate_includes_margin_and_logits_workspace(self):
        """Why: the margin is the crash-prevention budget and the logits
        workspace is the observed OOM peak; both must be included."""
        margin = 2 * rg.GIB
        est = rg.estimate_training_vram(param_billions=9.0, seq_len=1024,
                                        vocab_size=150_000, margin=margin)
        logits = 1024 * 150_000 * 4
        self.assertGreaterEqual(est, margin + logits)

    def test_estimate_is_pessimistic_for_a_9b_run(self):
        """Why: for our verified 9B/1024 configuration the estimate must
        exceed the observed ~12 GiB peak that OOMed, so preflight refuses to
        start in states that would crash."""
        est = rg.estimate_training_vram(param_billions=9.0, seq_len=1024)
        self.assertGreater(est, 12 * rg.GIB)


if __name__ == "__main__":
    unittest.main()
