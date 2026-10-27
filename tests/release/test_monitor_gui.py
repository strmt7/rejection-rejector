"""Eight-point contract for the training monitor GUI (src/bin/rr-train-monitor.rs).

The monitor is window-system code the headless lanes cannot execute end to
end, so its written contract is pinned at the seams Python CAN execute:
(1) fixture marker output — the duty.json payload the Rust writer emits is
consumed verbatim by the trainer hook; (2) load-sample hooking — the
trainer re-reads that file every step; (3) no CWD probing; (4) no
persisted config path (the control file sibling is the monitor's only
side effect); (5) --slider-cap validation (the operator's 50% ceiling);
(6) slider-target parsing bounds; (7) pacing math parity; (8) the shared
heartbeat schema. Any drift between the two duty.json implementations
silently throttles or fails to throttle a live training run, so every
point here is load-bearing.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "training"))

import duty_cycle as dc  # noqa: E402
import progress as progress_mod  # noqa: E402

MONITOR_SRC = (ROOT / "src" / "bin" / "rr-train-monitor.rs").read_text(encoding="utf-8")
MONITOR_RUNTIME = MONITOR_SRC.split("#[cfg(test)]", 1)[0]
TRAIN_MONITOR_SRC = (ROOT / "src" / "train_monitor.rs").read_text(encoding="utf-8")
TRAINER_SRC = (ROOT / "training" / "train_lora.py").read_text(encoding="utf-8")


def rust_const(name: str) -> float:
    """One `pub const NAME: f64` from the Rust monitor data model."""
    match = re.search(rf"pub const {name}\s*:\s*f64\s*=\s*([0-9.]+)\s*;", TRAIN_MONITOR_SRC)
    if not match:
        raise AssertionError(f"Rust constant {name} not found in train_monitor.rs")
    return float(match.group(1))


def rust_runtime_source() -> str:
    """The non-test part of the Rust data model (#[cfg(test)] tail removed)."""
    return TRAIN_MONITOR_SRC.split("#[cfg(test)]", 1)[0]


class FixtureMarkerOutputTests(unittest.TestCase):
    """Point 1 — the exact bytes the Rust slider write leaves behind."""

    def test_monitor_write_fixture_is_consumed_by_the_trainer_hook(self):
        # Why: write_duty formats `{"target_pct":<pct>}` (f64 Display, so
        # 35.0 -> "35") via tmp + rename; the hook must parse that exact
        # shape or the GUI slider silently stops steering training.
        """The Rust slider payload shape is exactly what the hook parses."""
        self.assertIn(
            '{{\\"target_pct\\":{pct}}}',
            rust_runtime_source(),
            "write_duty payload shape drifted from the shared contract",
        )
        with tempfile.TemporaryDirectory() as tmp:
            control = Path(tmp) / "duty.json"
            control.write_text('{"target_pct":35}', encoding="utf-8")
            self.assertEqual(dc.read_target(control), 35.0)
            # The monitor must never trip the trainer's cooperative stop:
            # its payload carries no `stop` key at all.
            self.assertIs(dc.read_stop_flag(control), False)
        # Atomic replace: both sides name the tmp sibling duty.json.tmp and
        # leave nothing behind, so the trainer never reads a partial write.
        self.assertIn("json.tmp", rust_runtime_source())
        self.assertIn("rename", rust_runtime_source())
        with tempfile.TemporaryDirectory() as tmp:
            control = Path(tmp) / "duty.json"
            dc.write_target(control, 35.0)
            self.assertFalse((Path(tmp) / "duty.json.tmp").exists())
            self.assertEqual(json.loads(control.read_text(encoding="utf-8")), {"target_pct": 35.0})


class LoadSampleHookingTests(unittest.TestCase):
    """Point 2 — the trainer re-reads the monitor's file every step."""

    def test_trainer_hooks_the_control_file_end_to_end(self):
        # Why: the ceiling is applied per step by re-reading duty.json; if
        # the hook wiring (control_path_for/read_target/read_stop_flag/
        # sleep_seconds/paced_sleep) is dropped, the slider becomes a
        # placebo and the run sits at whatever ceiling was last applied.
        """The trainer wires every duty_cycle hook and sees slider moves."""
        for call in (
            "duty_cycle.control_path_for",
            "duty_cycle.read_target",
            "duty_cycle.read_stop_flag",
            "duty_cycle.sleep_seconds",
            "duty_cycle.paced_sleep",
        ):
            self.assertIn(call, TRAINER_SRC, f"trainer hook lost {call}")
        with tempfile.TemporaryDirectory() as tmp:
            progress_path = Path(tmp) / "progress.json"
            control = dc.control_path_for(progress_path)
            self.assertEqual(control, Path(tmp) / "duty.json")
            dc.write_target(control, 35.0)
            self.assertEqual(dc.read_target(control), 35.0)
            # A slider move lands as a new ceiling the next step observes.
            dc.write_target(control, 40.0)
            self.assertEqual(dc.read_target(control), 40.0)


class NoCwdProbingTests(unittest.TestCase):
    """Point 3 — file locations come from --progress, never from the CWD."""

    def test_monitor_sources_never_probe_the_working_directory(self):
        # Why: the monitor is launched from scripts and schedulers with
        # arbitrary working directories; resolving files against the CWD
        # would silently watch or write the wrong run.
        """Monitor sources resolve files from --progress, never the CWD."""
        runtime = rust_runtime_source() + MONITOR_RUNTIME
        for probe in ("current_dir", "set_current_dir", 'env::var("PWD")', "env::temp_dir"):
            self.assertNotIn(probe, runtime, f"monitor probes its CWD via {probe}")
        self.assertIn("duty_path_for(&progress_path)", MONITOR_SRC)


class PersistedConfigPathIsolationTests(unittest.TestCase):
    """Point 4 — the control-file sibling is the monitor's ONLY side effect."""

    def test_monitor_persists_nothing_besides_the_duty_sibling(self):
        # Why: the contract says the only side effect outside the window is
        # an atomic write of the trainer's duty.json; any persisted config
        # path, keyring or app-storage write would spread monitor state
        # across machines and profiles.
        """The duty.json sibling is the monitor's only side effect."""
        for forbidden in (
            "data_dir",
            "keyring",
            "set_value",
            "get_value",
            "storage",
            "HOME",
            "APPDATA",
        ):
            self.assertNotIn(
                forbidden, MONITOR_RUNTIME, f"monitor persists via {forbidden}"
            )
        self.assertEqual(dc.CONTROL_FILENAME, "duty.json")
        self.assertIn('CONTROL_FILENAME: &str = "duty.json"', rust_runtime_source())


class SliderCapValidationTests(unittest.TestCase):
    """Point 5 — the operator ceiling is 50% and the slider cannot exceed it."""

    def test_slider_cap_is_the_operator_ceiling(self):
        # Why: the operator's standing requirement is a hard 50% GPU
        # utilization maximum; the slider range is what enforces it in the
        # GUI, so a widened range is a product-level regression.
        """The slider maximum is the operator's 50% ceiling, enforced on write."""
        self.assertEqual(rust_const("SLIDER_MAX_PCT"), 50.0)
        self.assertIn("MIN_TARGET_PCT..=SLIDER_MAX_PCT", MONITOR_SRC)
        # The write path validates as well (fail closed, never trust the
        # widget): out-of-range targets are refused before touching disk.
        self.assertIn("validate_target(target_pct)", rust_runtime_source())


class SliderParsingTests(unittest.TestCase):
    """Point 6 — slider/target parsing bounds agree on both sides."""

    def test_target_bounds_match_the_trainer_hook(self):
        # Why: the Rust file contract and the Python hook must accept the
        # identical [20, 100] target range; a one-sided change would make
        # either the GUI or the trainer reject the other's valid writes.
        """Rust and Python accept the identical [20, 100] target range."""
        self.assertEqual(rust_const("MIN_TARGET_PCT"), dc.MIN_TARGET_PCT)
        self.assertEqual(rust_const("MAX_TARGET_PCT"), dc.MAX_TARGET_PCT)
        # Parsing fail-closed on both sides of the boundary.
        self.assertEqual(dc.validate_target_pct("20"), 20.0)
        self.assertEqual(dc.validate_target_pct("100"), 100.0)
        with self.assertRaises(ValueError):
            dc.validate_target_pct("nan")
        with self.assertRaises(ValueError):
            dc.validate_target_pct("19.9")


class PacingMathTests(unittest.TestCase):
    """Point 7 — off = on * (100 - t) / t, identical in both languages."""

    def test_pacing_formula_matches_the_rust_definition(self):
        # Why: the pacing formula IS the ceiling; the same boundaries are
        # pinned in train_monitor.rs (10 s at 50% -> 10 s sleep, at 25% ->
        # 30 s, at 100% -> none, negative -> none), so a formula change on
        # either side trips one suite while the other documents the drift.
        """The pacing formula is byte-identical in both implementations."""
        self.assertIn("* (MAX_TARGET_PCT - t) / t", rust_runtime_source())
        self.assertEqual(dc.sleep_seconds(10.0, 100.0), 0.0)
        self.assertAlmostEqual(dc.sleep_seconds(10.0, 50.0), 10.0)
        self.assertAlmostEqual(dc.sleep_seconds(10.0, 25.0), 30.0)
        self.assertEqual(dc.sleep_seconds(-1.0, 50.0), 0.0)
        self.assertEqual(dc.sleep_seconds(10.0, 999.0), 0.0)


class HeartbeatSchemaTests(unittest.TestCase):
    """Point 8 — the heartbeat schema shared with training/progress.py."""

    def test_heartbeat_fields_match_the_trainer_writer(self):
        # Why: the monitor parses the trainer's heartbeat into
        # ProgressSnapshot field-for-field; a renamed or dropped key shows
        # the operator placeholders ("—") or "waiting for trainer
        # heartbeat…" while the run is live.
        """ProgressSnapshot fields match the trainer heartbeat keys exactly."""
        struct = re.search(
            r"pub struct ProgressSnapshot \{(.*?)\n\}", TRAIN_MONITOR_SRC, re.S
        )
        self.assertIsNotNone(struct, "ProgressSnapshot not found")
        fields = set(re.findall(r"pub (\w+):", struct.group(1)))
        self.assertEqual(
            fields,
            {"step", "total_steps", "loss", "status", "elapsed_seconds", "updated_at_unix"},
        )
        # Everything the probe reads must exist in the Rust struct.
        probe_body = inspect.getsource(progress_mod.summarize)
        probe_keys = set(re.findall(r'record\.get\("(\w+)"', probe_body))
        self.assertTrue(probe_keys <= fields, f"probe reads unknown fields: {probe_keys - fields}")

    def test_probe_semantics_match_the_rust_snapshot(self):
        # Why: the same fixture must produce the same derived numbers in
        # both implementations — the Rust bounds pinned in train_monitor.rs
        # (fraction 0.0 on zero total, ETA 50/60 min for 5/10 steps at
        # 50 s elapsed, staleness at > 120 s) are these exact values.
        """The same fixture derives identical numbers in both implementations."""
        record = {
            "step": 5,
            "total_steps": 10,
            "loss": 0.5,
            "status": "running",
            "elapsed_seconds": 50.0,
            "updated_at_unix": 1_700_000_000.0,
        }
        view = progress_mod.summarize(record, now=1_700_000_010.0)
        self.assertEqual(view["percent"], 50.0)
        self.assertAlmostEqual(view["eta_seconds"] / 60.0, 50.0 / 60.0)
        self.assertFalse(view["stalled"])
        self.assertEqual(
            progress_mod.summarize({**record, "total_steps": 0}, now=1_700_000_010.0)["percent"],
            0.0,
        )
        # Staleness bound parity: Rust warns past this age, the probe
        # reports stalled at it.
        self.assertEqual(progress_mod.STALE_AFTER_SECONDS, rust_const("STALE_AFTER_SECONDS"))


if __name__ == "__main__":
    unittest.main()
