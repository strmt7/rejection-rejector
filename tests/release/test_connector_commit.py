"""Tests for tools/connector_commit.py: tree building and identity policy.

Inputs: none (unittest). Output: verifies the connector-commit helper's
argument parsing, tree-entry assembly and the contributor-identity policy
check without any network access.
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import connector_commit  # noqa: E402


class ParseSetTests(unittest.TestCase):
    """Contract tests for the --set argument parsing."""

    def test_set_reads_file_content(self):
        """A PATH=FILE spec yields the path and the file's exact content."""
        path, content = connector_commit.parse_set(__file__ + "=" + __file__)
        self.assertTrue(path.endswith("test_connector_commit.py"))
        self.assertIn("ParseSetTests", content)

    def test_set_dash_reads_stdin(self):
        """A PATH=- spec reads the content from standard input."""
        with mock.patch("sys.stdin", io.StringIO("from-stdin")):
            path, content = connector_commit.parse_set("docs/x.md=-")
        self.assertEqual((path, content), ("docs/x.md", "from-stdin"))

    def test_set_rejects_missing_separator(self):
        """A spec without PATH=FILE shape is rejected."""
        with self.assertRaises(ValueError):
            connector_commit.parse_set("just-a-path")


class TreeEntryTests(unittest.TestCase):
    """Contract tests for git tree-entry assembly."""

    def test_sets_become_blobs_and_deletes_null(self):
        """Updates carry blob shas; deletions carry a null sha."""
        entries = connector_commit.build_entries(
            [("a.md", "text"), ("b.rs", "code")], ["old.txt"],
            {"a.md": "sha-a", "b.rs": "sha-b"},
        )
        self.assertEqual(entries[0], {"path": "a.md", "mode": "100644", "type": "blob", "sha": "sha-a"})
        self.assertEqual(entries[2]["path"], "old.txt")
        self.assertIsNone(entries[2]["sha"])


class IdentityPolicyTests(unittest.TestCase):
    """Contract tests for the connector identity policy check."""

    def _commit(self, author, committer):
        return {"author": {"name": author[0], "email": author[1]},
                "committer": {"name": committer[0], "email": committer[1]}}

    def test_accepts_matching_contributor_identity(self):
        """The noreply contributor pair passes and is returned."""
        commit = self._commit(("Stratos", "28989754+strmt7@users.noreply.github.com"),
                              ("Stratos", "28989754+strmt7@users.noreply.github.com"))
        author, committer = connector_commit.verify_identity(commit)
        self.assertEqual(author, committer)

    def test_rejects_automation_identity(self):
        """A non-noreply identity is a policy violation (exit code 2)."""
        commit = self._commit(("docs-wave", "docs-wave@localhost"),
                              ("docs-wave", "docs-wave@localhost"))
        with self.assertRaises(SystemExit):
            connector_commit.verify_identity(commit)

    def test_rejects_author_committer_mismatch(self):
        """A mismatch between author and committer is a policy violation."""
        commit = self._commit(("Stratos", "28989754+strmt7@users.noreply.github.com"),
                              ("github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com"))
        with self.assertRaises(SystemExit):
            connector_commit.verify_identity(commit)


if __name__ == "__main__":
    unittest.main()
