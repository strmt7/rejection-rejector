"""Tests for tools/connector_commit.py: tree building and identity policy.

Inputs: none (unittest). Output: verifies the connector-commit helper's
argument parsing, tree-entry assembly and the contributor-identity policy
check without any network access.
"""

import base64
import io
import os
import pathlib
import sys
import tempfile
import unittest
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

    def test_set_normalizes_line_endings_to_lf(self):
        """Content is stored with LF per .gitattributes `* text=auto eol=lf`."""
        with mock.patch("sys.stdin", io.StringIO("a\r\nb\rc\n")):
            _path, content = connector_commit.parse_set("docs/x.md=-")
        self.assertEqual(content, "a\nb\nc\n")

    def test_set_bytes_encodes_binary_as_base64(self):
        """Why (connector binary support): provenance archives are binary; a
        PATH=FILE spec must reach the blob API as base64 with the matching
        encoding flag, never as mangled text.
        """
        with tempfile.TemporaryDirectory() as temporary:
            binary = pathlib.Path(temporary) / "asset.zip"
            binary.write_bytes(b"PK\x03\x04\xbc\xff\x00\x01")
            path, content, encoding = connector_commit.parse_set_bytes("third_party/asset.zip=" + str(binary))
        self.assertEqual(path, "third_party/asset.zip")
        self.assertEqual(encoding, "base64")
        self.assertEqual(base64.b64decode(content), b"PK\x03\x04\xbc\xff\x00\x01")

    def test_set_bytes_keeps_text_contract(self):
        """Text files keep the utf-8 LF-normalized contract unchanged."""
        stdin = mock.Mock(buffer=io.BytesIO(b"a\r\nb\r\n"))
        with mock.patch("sys.stdin", stdin):
            path, content, encoding = connector_commit.parse_set_bytes("docs/x.md=-")
        self.assertEqual((path, content, encoding), ("docs/x.md", "a\nb\n", "utf-8"))

    def test_set_and_delete_reject_control_characters_in_paths(self):
        """Why (connector binary support): a CRLF-corrupted path list once
        turned every --set into a --delete of a path carrying a CR, which the
        trees API rejects only as a cryptic 422. Control characters in paths
        must fail fast with a clear error.
        """
        with self.assertRaisesRegex(ValueError, "control characters"):
            connector_commit.parse_set("docs/bad\rname.md=-")
        with self.assertRaisesRegex(ValueError, "control characters"):
            connector_commit.parse_set_bytes("docs/bad\nname.md=-")

    def test_normalize_text_is_idempotent(self):
        """Normalizing LF text leaves it byte-identical."""
        self.assertEqual(connector_commit.normalize_text("a\nb\n"), "a\nb\n")

    def test_set_rejects_missing_separator(self):
        """A spec without PATH=FILE shape is rejected."""
        with self.assertRaises(ValueError):
            connector_commit.parse_set("just-a-path")


class TreeEntryTests(unittest.TestCase):
    """Contract tests for git tree-entry assembly."""

    def test_sets_become_blobs_and_deletes_null(self):
        """Updates carry blob shas; deletions carry a null sha."""
        entries = connector_commit.build_entries(
            [("a.md", "text"), ("b.rs", "code")],
            ["old.txt"],
            {"a.md": "sha-a", "b.rs": "sha-b"},
        )
        self.assertEqual(entries[0], {"path": "a.md", "mode": "100644", "type": "blob", "sha": "sha-a"})
        self.assertEqual(entries[2]["path"], "old.txt")
        self.assertIsNone(entries[2]["sha"])


class IdentityPolicyTests(unittest.TestCase):
    """Contract tests for the connector identity policy check."""

    @staticmethod
    def _commit(author, committer):
        """Build one commit identity-pair fixture.

        Inputs: `author`/`committer` -- (name, email) tuples. Output: `dict` --
        the commit payload shape consumed by the identity policy check.
        """
        return {
            "author": {"name": author[0], "email": author[1]},
            "committer": {"name": committer[0], "email": committer[1]},
        }

    def test_accepts_matching_contributor_identity(self):
        """The noreply contributor pair passes and is returned."""
        commit = self._commit(
            ("Stratos", "28989754+strmt7@users.noreply.github.com"),
            ("Stratos", "28989754+strmt7@users.noreply.github.com"),
        )
        author, committer = connector_commit.verify_identity(commit)
        self.assertEqual(author, committer)

    def test_rejects_automation_identity(self):
        """A non-noreply identity is a policy violation (exit code 2)."""
        commit = self._commit(("docs-wave", "docs-wave@localhost"), ("docs-wave", "docs-wave@localhost"))
        with self.assertRaises(SystemExit):
            connector_commit.verify_identity(commit)

    def test_rejects_author_committer_mismatch(self):
        """A mismatch between author and committer is a policy violation."""
        commit = self._commit(
            ("Stratos", "28989754+strmt7@users.noreply.github.com"),
            ("github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com"),
        )
        with self.assertRaises(SystemExit):
            connector_commit.verify_identity(commit)


NOREPLY = {"name": "Stratos", "email": "28989754+strmt7@users.noreply.github.com"}


class GhApiTests(unittest.TestCase):
    """Contract tests for the authenticated API seam."""

    @staticmethod
    def _completed(returncode, stdout):
        """Purpose: Build a scripted subprocess result. Inputs: exit code and
        stdout text; Output: the mock result object consumed by gh_api.
        """
        return mock.Mock(returncode=returncode, stdout=stdout, stderr="tail-error")

    def test_parses_json_and_defaults_empty(self):
        """JSON responses parse; empty responses are {}; failures raise with
        the endpoint and error tail named.
        """
        with mock.patch("connector_commit.subprocess.run", return_value=self._completed(0, '{"a": 1}')):
            self.assertEqual(connector_commit.gh_api("x/y"), {"a": 1})
        with mock.patch("connector_commit.subprocess.run", return_value=self._completed(0, "  ")):
            self.assertEqual(connector_commit.gh_api("x/y"), {})
        with (
            mock.patch("connector_commit.subprocess.run", return_value=self._completed(3, "")),
            self.assertRaisesRegex(RuntimeError, "x/y"),
        ):
            connector_commit.gh_api("x/y")

    def test_sends_method_and_payload(self):
        """POST-style calls forward the method and JSON payload."""
        seen = {}

        def runner(command, **kwargs):
            """Purpose: Record the gh invocation. Inputs: command/kwargs from
            subprocess.run; Output: a successful empty response.
            """
            seen["command"] = command
            seen["input"] = kwargs.get("input")
            return mock.Mock(returncode=0, stdout="{}", stderr="")

        with mock.patch("connector_commit.subprocess.run", side_effect=runner):
            connector_commit.gh_api("x/y", "POST", {"k": "v"})
        self.assertIn("-X", seen["command"])
        self.assertIn("POST", seen["command"])
        self.assertIn('"k": "v"', seen["input"])


class MainFlowTests(unittest.TestCase):
    """Contract tests for the full connector commit flow."""

    @staticmethod
    def _fake_api(calls, commit=None):
        """Purpose: Build the scripted gh_api seam. Inputs: the call log and
        an optional commit payload; Output: the routing function.
        """
        commit = commit or {"sha": "C1", "author": dict(NOREPLY), "committer": dict(NOREPLY)}

        def route(endpoint, method=None, payload=None):
            """Purpose: Answer one API call from the script. Inputs: the call
            arguments; Output: the canned response for that endpoint.
            """
            calls.append((endpoint, method))
            if endpoint.endswith("/git/ref/heads/main"):
                return {"object": {"sha": "H1"}}
            if endpoint.endswith("/git/commits/H1"):
                return {"tree": {"sha": "T1"}}
            if endpoint.endswith("/git/blobs"):
                return {"sha": "B1"}
            if endpoint.endswith("/git/trees"):
                return {"sha": "T2"}
            if endpoint.endswith("/git/commits"):
                return commit
            return {}

        return route

    @staticmethod
    def _argv(temporary, extra=()):
        """Purpose: Build the CLI argv for one commit. Inputs: the temp dir
        and extra arguments; Output: the argv list including one --set.
        """
        target = pathlib.Path(temporary) / "doc.md"
        target.write_text("content\n", encoding="utf-8")
        return [
            "--message=subject",
            f"--set=docs/doc.md={target}",
            *extra,
        ]

    def test_happy_path_commits_and_reads_back_identity(self):
        """The flow: ref -> parent -> blobs -> tree -> commit -> ref update,
        printing the SHA and both verified identities.
        """
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            argv = self._argv(temporary)
            with (
                mock.patch("sys.argv", ["connector_commit.py", *argv]),
                mock.patch.object(connector_commit, "gh_api", side_effect=self._fake_api(calls)),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                connector_commit.main()
        self.assertEqual(
            [endpoint.rsplit("/git/", 1)[-1] for endpoint, _ in calls],
            ["ref/heads/main", "commits/H1", "blobs", "trees", "commits", "refs/heads/main"],
        )
        printed = out.getvalue()
        self.assertIn("C1", printed)
        self.assertIn("author   :", printed)
        self.assertIn("committer:", printed)

    def test_foreign_identity_exits_2(self):
        """Why (identity policy): a non-contributor commit identity is a
        policy violation and exits 2 after the ref is NOT advanced.
        """
        calls = []
        commit = {
            "sha": "C1",
            "author": {"name": "docs-wave", "email": "docs-wave@localhost"},
            "committer": {"name": "docs-wave", "email": "docs-wave@localhost"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            argv = self._argv(temporary)
            with (
                mock.patch("sys.argv", ["connector_commit.py", *argv]),
                mock.patch.object(connector_commit, "gh_api", side_effect=self._fake_api(calls, commit)),
                mock.patch("sys.stdout", new_callable=io.StringIO),
                self.assertRaises(SystemExit) as raised,
            ):
                connector_commit.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse(
            [endpoint for endpoint, _ in calls if "/git/refs/" in endpoint],
            "the branch ref must never advance on an identity policy violation",
        )

    def test_argument_guards_refuse(self):
        """No operations, empty delete paths and control-character delete
        paths all refuse at the argument guard.
        """
        with mock.patch("sys.argv", ["connector_commit.py", "--message=m"]), self.assertRaises(SystemExit):
            connector_commit.main()
        for bad_delete in ("", "bad\x00path"):
            argv = ["connector_commit.py", "--message=m", f"--delete={bad_delete}"]
            with mock.patch("sys.argv", argv), self.assertRaises(SystemExit):
                connector_commit.main()


if __name__ == "__main__":
    unittest.main()
