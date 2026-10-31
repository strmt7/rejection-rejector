#!/usr/bin/env python3
"""Tests for training/train_lora.py best-effort helpers.

Covers the two exception-discipline contracts of the GPU training loop's
telemetry helpers: the ROCm async-queue drain absorbs only the optional
dependency and CUDA-runtime failure classes (a real defect must
propagate), and the pace-log append honors its never-break-training
contract while reporting disk/parse failures instead of masking them.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

import train_lora  # noqa: E402


class DrainGpuQueueTests(unittest.TestCase):
    """Pin the optional-dependency/CUDA-only suppression."""

    def test_missing_torch_is_absorbed(self):
        """Without torch the mitigation is a no-op, never an error."""
        with mock.patch.dict(sys.modules, {"torch": None}):
            train_lora._drain_gpu_queue()

    @staticmethod
    def _fake_torch(sync):
        """Purpose: Build a torch stand-in for import substitution.

        Inputs: `sync` -- synchronize callable (may raise);
        Output: an object usable as sys.modules["torch"].
        """
        return types.SimpleNamespace(cuda=types.SimpleNamespace(is_available=lambda: True, synchronize=sync))

    def test_runtime_error_from_sync_is_absorbed(self):
        """CUDA sync failures surface as RuntimeError and are absorbed."""
        fake = self._fake_torch(lambda: (_ for _ in ()).throw(RuntimeError("cuda")))
        with mock.patch.dict(sys.modules, {"torch": fake}):
            train_lora._drain_gpu_queue()

    def test_unexpected_defects_propagate(self):
        """Why (never mask programming errors): a non-runtime defect in the
        mitigation path must surface, not vanish into a bare except.
        """
        fake = self._fake_torch(lambda: (_ for _ in ()).throw(AttributeError("bug")))
        with mock.patch.dict(sys.modules, {"torch": fake}), self.assertRaises(AttributeError):
            train_lora._drain_gpu_queue()


class PaceLogTests(unittest.TestCase):
    """Pin the never-break-training evidence append."""

    def test_append_writes_one_jsonl_record(self):
        """A healthy append writes exactly one JSONL evidence record."""
        with tempfile.TemporaryDirectory() as owned:
            progress_path = pathlib.Path(owned) / "progress.json"
            duty = pathlib.Path(owned) / "duty.json"
            duty.write_text('{"target_gpu_pct": 55}', encoding="utf-8")
            with mock.patch.object(train_lora, "duty_cycle") as duty_mock:
                duty_mock.read_target.return_value = 55
                train_lora._append_pace_log(progress_path, 3, 0.125, duty)
            log = (pathlib.Path(owned) / "pace-log.jsonl").read_text(encoding="utf-8")
        self.assertEqual(json.loads(log)["step"], 3)

    def test_os_and_parse_failures_skip_with_a_report(self):
        """The documented contract: environmental failures never break
        training — but they are reported to stderr, never silently masked.
        """
        with tempfile.TemporaryDirectory() as owned:
            progress_path = pathlib.Path(owned) / "progress.json"
            for raised in (OSError("disk"), ValueError("corrupt")):
                with mock.patch.object(train_lora, "duty_cycle") as duty_mock:
                    duty_mock.read_target.side_effect = raised
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        train_lora._append_pace_log(progress_path, 1, 0.1, "duty.json")
                self.assertIn("pace-log append skipped", stderr.getvalue())

    def test_programming_errors_propagate(self):
        """A genuine defect (e.g. AttributeError) breaks loudly in
        development instead of being swallowed by the telemetry.
        """
        with tempfile.TemporaryDirectory() as owned:
            progress_path = pathlib.Path(owned) / "progress.json"
            with mock.patch.object(train_lora, "duty_cycle") as duty_mock:
                duty_mock.read_target.side_effect = AttributeError("bug")
                with self.assertRaises(AttributeError):
                    train_lora._append_pace_log(progress_path, 1, 0.1, "duty.json")


if __name__ == "__main__":
    unittest.main()
