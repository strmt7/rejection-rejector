"""Why (coverage doctrine): the adapter evaluator's provenance helpers,
its input-refusal arms and its report pipeline are product code that must
run without a GPU. The inference loop itself is the documented GPU-host
structural residual; everything around it executes here.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "training"))

import evaluate_adapter as ea  # noqa: E402


class ProvenanceHelperTests(unittest.TestCase):
    """Artifact identity helpers used as release evidence."""

    def test_sha256_file_matches_hashlib(self) -> None:
        """Why: artifact identity is the release evidence root."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.bin"
            path.write_bytes(b"adapter-bytes")
            self.assertEqual(ea.sha256_file(path), hashlib.sha256(b"adapter-bytes").hexdigest())

    def test_path_identity_reports_file(self) -> None:
        """Why: the identity record carries path/size/hash for evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.bin"
            path.write_bytes(b"x")
            identity = ea.path_identity(path)
            self.assertIsInstance(identity, dict)
            self.assertTrue(identity)


class EvaluateAdapterMainTests(unittest.TestCase):
    """Fail-fast input validation and the dependency gate at the GPU entry."""

    def test_main_missing_adapter_fails_cleanly(self) -> None:
        """Why: a missing adapter must exit 2 with a clear message before
        the heavy training stack is imported — the fail-fast contract.
        """
        with tempfile.TemporaryDirectory() as tmp:
            argv = ["evaluate_adapter.py", "--adapter", str(Path(tmp) / "nope.safetensors")]
            with mock.patch.object(sys, "argv", argv):
                code = ea.main()
            self.assertEqual(code, 2)

    def test_main_missing_holdout_fails_cleanly(self) -> None:
        """Why: the holdout path is validated by the same fail-fast rule."""
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Path(tmp) / "adapter.safetensors"
            adapter.write_bytes(b"x")
            argv = ["evaluate_adapter.py", "--adapter", str(adapter), "--holdout", str(Path(tmp) / "nope.jsonl")]
            with mock.patch.object(sys, "argv", argv):
                code = ea.main()
            self.assertEqual(code, 2)

    def test_gpu_entry_is_dependency_gated_after_validation(self) -> None:
        """Why: past fail-fast validation the entry requires the training
        stack — pinned so no refactor moves GPU-dependent work back ahead
        of input validation.
        """
        with tempfile.TemporaryDirectory() as tmp:
            adapter = Path(tmp) / "adapter.safetensors"
            adapter.write_bytes(b"x")
            holdout = Path(tmp) / "holdout.jsonl"
            holdout.write_text("{}\n", encoding="utf-8")
            argv = ["evaluate_adapter.py", "--adapter", str(adapter), "--holdout", str(holdout)]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.dict(sys.modules, {"torch": None}),
                self.assertRaises(ModuleNotFoundError),
            ):
                ea.main()


if __name__ == "__main__":
    unittest.main()
