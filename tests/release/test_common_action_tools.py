"""Tests for the promoted common-action tools: commit_wave and ci_status.

Inputs: none (unittest). Output: verifies the porcelain classifier and the
CI verdict counting rule without any network or git access.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import ci_status  # noqa: E402
import commit_wave  # noqa: E402


class CollectOperationsTests(unittest.TestCase):
    """Pin the git-status classification and LF-safety rules."""

    def test_classifies_set_delete_and_untracked(self):
        """Why (connector binary support): every wave re-derived this
        classification in scratch; the set/delete decision must stay pinned.
        """
        porcelain = " M src/a.rs\n D src/b.rs\n?? src/new.rs\n"
        present = {"src/a.rs", "src/new.rs"}
        ops = commit_wave.collect_operations(porcelain, present.__contains__)
        self.assertEqual(ops, [("set", "src/a.rs"), ("delete", "src/b.rs"), ("set", "src/new.rs")])

    def test_skips_bytecode_cache_rows(self):
        """Compiled cache artifacts never ride along in a commit wave."""
        porcelain = "?? tools/__pycache__/x.cpython-314.pyc\n M tools/x.py\n"
        ops = commit_wave.collect_operations(porcelain, lambda p: True)
        self.assertEqual(ops, [("set", "tools/x.py")])

    def test_pending_deletion_with_present_file_refuses(self):
        """Why (corpus-deletion lesson): a --delete with the file still
        present silently re-uploads it through --set; refusing is the only
        honest behavior.
        """
        porcelain = " D keepme.txt\n"
        with self.assertRaisesRegex(ValueError, "still present"):
            commit_wave.collect_operations(porcelain, lambda p: True)

    def test_rejects_control_characters_in_paths(self):
        """Why (CRLF path-list lesson): a stray control character turns the
        path into a phantom entry the trees API rejects only as a 422; the
        classifier refuses such rows up front.
        """
        porcelain = " M docs/bad\x00name.md\n"
        with self.assertRaisesRegex(ValueError, "malformed"):
            commit_wave.collect_operations(porcelain, lambda p: True)

    def test_crlf_porcelain_rows_are_consumed_cleanly(self):
        """CRLF line endings in the status text must not bleed into paths:
        splitlines consumes the CR as part of the break, so rows parse to
        clean paths (the LF-safe ingestion rule).
        """
        porcelain = " M a.rs\r\n?? b.rs\r\n"
        ops = commit_wave.collect_operations(porcelain, lambda p: True)
        self.assertEqual(ops, [("set", "a.rs"), ("set", "b.rs")])

    def test_unhandled_status_refuses(self):
        """Unknown porcelain states must fail closed, not be guessed."""
        with self.assertRaisesRegex(ValueError, "unhandled"):
            commit_wave.collect_operations("UU conflict.rs\n", lambda p: True)


class VerdictTests(unittest.TestCase):
    """Pin the counted-CI-verdict rule."""

    @staticmethod
    def _rows(*specs):
        """Purpose: Build verdict fixture rows.

        Inputs: (name, status, conclusion) tuples;
        Output: verdict-shaped row dicts.
        """
        return [
            {"workflowName": name, "status": status, "conclusion": conclusion} for name, status, conclusion in specs
        ]

    def test_all_green_is_zero(self):
        """Every lane completed green yields exit code 0."""
        rows = self._rows(("A", "completed", "success"), ("B", "completed", "success"))
        code, summary = ci_status.verdict(rows)
        self.assertEqual(code, 0)
        self.assertIn("2 green, 0 red, 0 running", summary)

    def test_any_red_wins_over_running(self):
        """Why (counted-checks lesson): a red lane must never be masked by
        another lane still running.
        """
        rows = self._rows(("A", "completed", "failure"), ("B", "in_progress", None))
        code, summary = ci_status.verdict(rows)
        self.assertEqual(code, 1)
        self.assertIn("1 red, 1 running", summary)

    def test_cancelled_counts_as_red(self):
        """A cancelled lane is not green evidence."""
        rows = self._rows(
            ("A", "completed", "cancelled"),
        )
        self.assertEqual(ci_status.verdict(rows)[0], 1)

    def test_running_only_is_two(self):
        """All-completed-green is the only zero; pending work yields 2."""
        rows = self._rows(("A", "in_progress", None), ("B", "completed", "success"))
        code, summary = ci_status.verdict(rows)
        self.assertEqual(code, 2)
        self.assertIn("1 green, 0 red, 1 running", summary)

    def test_empty_listing_is_two(self):
        """No rows yet is not evidence of green (run-creation lag)."""
        code, summary = ci_status.verdict([])
        self.assertEqual(code, 2)
        self.assertIn("total 0", summary)


if __name__ == "__main__":
    unittest.main()
