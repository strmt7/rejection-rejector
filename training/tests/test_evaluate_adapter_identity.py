#!/usr/bin/env python3
"""Tests for training/evaluate_adapter.py identity helpers (research contract).

Verifies that holdout/adapter content identity is stable, content-sensitive
and available without the heavy ML stack (the module imports torch only
inside `main`). Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TRAINING = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TRAINING))

import evaluate_adapter as ea  # noqa: E402


class PathIdentity(unittest.TestCase):
    def test_file_digest_is_stable_and_content_sensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "holdout.jsonl"
            path.write_text('{"a": 1}\n', encoding="utf-8")
            first = ea.path_identity(path)
            self.assertEqual(first, ea.path_identity(path))
            self.assertEqual(first["kind"], "file")
            self.assertEqual(len(first["sha256"]), 64)
            path.write_text('{"a": 2}\n', encoding="utf-8")
            self.assertNotEqual(first["sha256"], ea.path_identity(path)["sha256"])

    def test_directory_digest_covers_every_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "adapter"
            (root / "sub").mkdir(parents=True)
            (root / "a.bin").write_bytes(b"alpha")
            (root / "sub" / "b.bin").write_bytes(b"beta")
            first = ea.path_identity(root)
            self.assertEqual(first["kind"], "directory")
            self.assertEqual(first, ea.path_identity(root))
            (root / "sub" / "b.bin").write_bytes(b"beta!")
            self.assertNotEqual(first["sha256"], ea.path_identity(root)["sha256"])
            (root / "c.bin").write_bytes(b"gamma")
            self.assertNotEqual(first["sha256"], ea.path_identity(root)["sha256"])

    def test_count_rows_skips_blank_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            path.write_text('{"x": 1}\n\n{"x": 2}\n', encoding="utf-8")
            self.assertEqual(ea.count_rows(path), 2)

    def test_generation_policy_is_deterministic(self):
        self.assertFalse(ea.GENERATION["do_sample"])
        self.assertGreater(ea.GENERATION["max_new_tokens"], 0)

    def test_module_import_does_not_pull_the_ml_stack(self):
        self.assertNotIn("torch", sys.modules)


if __name__ == "__main__":
    unittest.main()
