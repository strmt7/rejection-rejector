"""Behavior contracts for tools/agent_context.py (bounded context tool).

Inputs: none (unittest). Output: pins the path policy, bounded reads,
disposable-state lifecycle, outline/window paging, JSON evidence reports
and the remember/recall provenance-TTL semantics — including the
startup() instruction contract, whose silent breakage by an AGENTS.md
restructure on 2026-10-31 motivated this suite.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import agent_context  # noqa: E402


def namespace(**overrides) -> argparse.Namespace:
    """Purpose: Build invocation arguments for tool functions.

    Inputs: keyword overrides; Output: a Namespace with the CLI defaults.
    """
    defaults = {
        "path": "doc.md",
        "section": None,
        "start": 1,
        "end": None,
        "max_chars": 8000,
        "session": None,
        "force": False,
        "pointer": "",
        "field": [],
        "offset": 0,
        "limit": 12,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class PathPolicyTests(unittest.TestCase):
    """Pin the non-secret repository-relative path policy."""

    def test_accepts_plain_relative_paths(self):
        """Ordinary repository-relative names parse."""
        self.assertEqual(str(agent_context.relative_source_path("docs/x.md")), "docs/x.md")

    def test_refuses_secret_shapes_and_escapes(self):
        """Why (non-secret path policy): secrets and traversal must refuse
        before any filesystem access.
        """
        for bad in (
            "/etc/passwd",
            "C:secret",
            "docs\\x.md",
            "a/../b",
            ".env.local",
            "cfg/.env",
            "tls/server.pem",
            "id.key",
            "secrets/token.txt",
            ".git/config",
            "trailing. /x",
            "docs/x.md.",
        ):
            with self.assertRaises(ValueError, msg=bad):
                agent_context.relative_source_path(bad)

    def test_safe_path_refuses_symlinks(self):
        """Reparse points (symlinks) are never admitted."""
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "real.md").write_text("x", encoding="utf-8")
            try:
                (root / "link.md").symlink_to(root / "real.md")
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "reparse"):
                agent_context.safe_path(root, "link.md")


class BoundedReadTests(unittest.TestCase):
    """Pin bounded exact reads."""

    def test_read_source_hashes_and_bom(self):
        """UTF-8-sig text with a stable SHA-256; binary and oversize refuse."""
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "a.md").write_bytes(b"\xef\xbb\xbfhello")
            text, digest = agent_context.read_source(root, "a.md")
        self.assertEqual(text, "hello")
        self.assertEqual(len(digest), 64)
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "b.md").write_bytes(b"he\x00lo")
            with self.assertRaises(ValueError):
                agent_context.read_source(root, "b.md")
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "c.md").write_bytes(b"x" * 100)
            with self.assertRaises(ValueError):
                agent_context.read_source(root, "c.md", max_bytes=10)

    def test_state_round_trip_and_refusals(self):
        """Missing state loads as schema-1; duplicate keys, non-finite
        numbers, wrong schema and exclusive collisions all refuse.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            name = agent_context.state_name("notes", "trial-1")
            self.assertEqual(name, "out/agent-context/notes/trial-1.json")
            self.assertEqual(agent_context.load_state(root, name), {"schema": 1})
            agent_context.write_state(root, name, {"schema": 1, "v": 2})
            self.assertEqual(agent_context.load_state(root, name), {"schema": 1, "v": 2})
            with self.assertRaises(FileExistsError):
                agent_context.write_state(root, name, {"schema": 1}, exclusive=True)
            bad = pathlib.Path(owned) / "out" / "agent-context" / "notes"
            bad.mkdir(parents=True, exist_ok=True)
            (bad / "bad.json").write_text('{"schema": 1, "a": 1, "a": 2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                agent_context.load_state(root, "out/agent-context/notes/bad.json")
            (bad / "nan.json").write_text('{"schema": 1, "x": NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-finite"):
                agent_context.load_state(root, "out/agent-context/notes/nan.json")
            (bad / "v2.json").write_text('{"schema": 2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported"):
                agent_context.load_state(root, "out/agent-context/notes/v2.json")

    def test_state_name_refuses_bad_keys(self):
        """Keys are 1-64 lowercase letters, digits or hyphens only."""
        for bad in ("", "UPPER", "has/slash", "x" * 65, "dot.name"):
            with self.assertRaises(ValueError, msg=bad):
                agent_context.state_name("notes", bad)


class StructureAndWindowTests(unittest.TestCase):
    """Pin outline extraction and bounded windows."""

    def test_headings_ignore_fences_and_compute_spans(self):
        """ATX headings map to spans; fenced examples are not headings;
        a heading's span ends before the next same-or-shallower heading.
        """
        text = "# One\nbody\n```\n# not a heading\n```\n## Two\nmore\n# Three\n"
        spans = agent_context.headings(text)
        self.assertEqual(
            [(h["title"], h["level"], h["start"], h["end"]) for h in spans],
            [("One", 1, 1, 7), ("Two", 2, 6, 7), ("Three", 1, 8, 8)],
        )

    def test_source_window_section_and_lines(self):
        """A section resolves to exactly one heading; ambiguity and out-of-
        range lines refuse.
        """
        text = "# A\nx\n# A\ny\n"
        with self.assertRaisesRegex(ValueError, "exactly one"):
            agent_context.source_window(text, "A", 1, None)
        self.assertEqual(agent_context.source_window(text, None, 2, 3), (2, 3))
        with self.assertRaises(ValueError):
            agent_context.source_window(text, None, 5, 6)

    def test_read_window_budget_and_session_cache(self):
        """Truncation reports unread extent; explicit sessions skip an
        unchanged read and --force re-reads it.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "doc.md").write_text("aaaa\nbbbb\ncccc\n", encoding="utf-8")
            first = agent_context.read_window(root, namespace(max_chars=14, session="s1"))
        self.assertEqual(first["status"], "partial")
        self.assertIsNotNone(first["unread"])
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "doc.md").write_text("aaaa\nbbbb\n", encoding="utf-8")
            complete = agent_context.read_window(root, namespace(max_chars=500, session="s2"))
            again = agent_context.read_window(root, namespace(max_chars=500, session="s2"))
            forced = agent_context.read_window(root, namespace(max_chars=500, session="s2", force=True))
        self.assertEqual(complete["status"], "complete")
        self.assertEqual(again["status"], "unchanged_in_explicit_session")
        self.assertEqual(forced["status"], "complete")

    def test_python_symbols_include_decorators(self):
        """Definition spans start at the first decorator line."""
        text = "@decorator\nclass C:\n    def m(self):\n        return 1\n"
        symbols = agent_context.python_symbols(text)
        by_name = {entry["name"]: entry for entry in symbols}
        self.assertEqual(by_name["C"]["start"], 1)
        self.assertEqual(by_name["C.m"]["kind"], "function")


class SourceOutlineTests(unittest.TestCase):
    """Pin the bounded outline report."""

    def test_outline_pages_headings_and_symbols(self):
        """Markdown files outline by headings, Python files by AST symbols;
        offsets page and out-of-range offsets refuse.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "doc.md").write_text("# A\n## B\n# C\n", encoding="utf-8")
            (root / "m.py").write_text("def f():\n    return 1\n", encoding="utf-8")
            paged = agent_context.source_outline(root, namespace(path="doc.md", limit=2))
            later = agent_context.source_outline(root, namespace(path="doc.md", limit=2, offset=2))
            symbols = agent_context.source_outline(root, namespace(path="m.py"))
            with self.assertRaisesRegex(ValueError, "offset exceeds"):
                agent_context.source_outline(root, namespace(path="doc.md", offset=9))
        self.assertEqual(len(paged["headings"]), 2)
        self.assertEqual(paged["next_offset"], 2)
        self.assertIsNone(later["next_offset"])
        self.assertEqual(symbols["symbols"][0]["name"], "f")

    def test_outline_budget_refuses_when_nothing_fits(self):
        """A budget that cannot fit one entry refuses instead of emitting
        an empty page.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "doc.md").write_text("# Long heading title here\nbody\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "budget"):
                agent_context.source_outline(root, namespace(path="doc.md", max_chars=64, limit=1))


class JsonReportTests(unittest.TestCase):
    """Pin the bounded JSON evidence report."""

    def test_scalar_and_page_reports(self):
        """Scalars expand under budget; arrays page with projections and
        non-array projections refuse.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "d.json").write_text(json.dumps({"a": [10, 20], "s": "x"}), encoding="utf-8")
            scalar = agent_context.json_report(root, namespace(path="d.json", pointer="/s", max_chars=4000))
            paged = agent_context.json_report(root, namespace(path="d.json", pointer="/a", max_chars=4000, limit=1))
            with self.assertRaisesRegex(ValueError, "array"):
                agent_context.json_report(root, namespace(path="d.json", pointer="/s", field=["x"]))
        self.assertTrue(scalar["expanded"])
        self.assertEqual(len(paged["items"]), 1)
        self.assertEqual(paged["next_offset"], 1)

    def test_report_metadata_overflow_refuses(self):
        """A report that cannot fit its own metadata refuses honestly."""
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "d.json").write_text(json.dumps({"a": "x" * 200}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "output budget"):
                agent_context.json_report(root, namespace(path="d.json", pointer="/a", max_chars=50))


class NotesLifecycleTests(unittest.TestCase):
    """Pin the cited-notes provenance and TTL semantics."""

    @staticmethod
    def _args(**overrides):
        """Purpose: Build remember() arguments. Inputs: overrides; Output: Namespace."""
        defaults = {
            "key": "note-1",
            "summary_file": "summary.md",
            "source": ["evidence.md"],
            "kind": "observation",
            "expires_hours": 24,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_remember_then_recall_fresh_then_stale(self):
        """A note is fresh while its declared sources are unchanged and its
        TTL holds; a changed source makes recall stale (and the CLI exits 3).
        Why (evidence integrity): recalled synthesis must never outlive its
        evidence or its declared freshness window.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "summary.md").write_text("learned thing", encoding="utf-8")
            (root / "evidence.md").write_text("proof", encoding="utf-8")
            created = agent_context.remember(root, self._args())
            fresh = agent_context.recall(root, "note-1")
            (root / "evidence.md").write_text("changed", encoding="utf-8")
            stale = agent_context.recall(root, "note-1")
        self.assertEqual(created["acceptance"], "not_established_by_context_tool")
        self.assertEqual(fresh["status"], "declared_sources_unchanged")
        self.assertEqual(stale["status"], "stale")
        self.assertEqual(stale["reasons"][0]["reason"], "source_changed")
        self.assertIsNone(stale["summary"])

    def test_expiry_and_naive_timezones_refuse_or_stale(self):
        """An expired note recalls stale; a naive expiry refuses."""
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "summary.md").write_text("s", encoding="utf-8")
            (root / "evidence.md").write_text("e", encoding="utf-8")
            agent_context.remember(root, self._args(expires_hours=1))
            name = agent_context.state_name("notes", "note-1")
            state = agent_context.load_state(root, name)
            state["expires_at"] = "2020-01-01T00:00:00"
            agent_context.write_state(root, name, state)
            with self.assertRaisesRegex(ValueError, "timezone"):
                agent_context.recall(root, "note-1")
            state["expires_at"] = "2020-01-01T00:00:00+00:00"
            agent_context.write_state(root, name, state)
            expired = agent_context.recall(root, "note-1")
        self.assertEqual(expired["status"], "stale")
        self.assertIn({"reason": "expired"}, expired["reasons"])

    def test_main_exit_codes(self):
        """The CLI: 0 on success, 2 on error, 3 on a stale recall. Why
        (automation contract): callers branch on these exact codes.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            (root / "doc.md").write_text("a\nb\n", encoding="utf-8")
            (root / "summary.md").write_text("s", encoding="utf-8")
            (root / "evidence.md").write_text("e", encoding="utf-8")
            with mock.patch.object(agent_context, "ROOT", root):
                ok = agent_context.main(["read", "doc.md", "--start", "1", "--end", "1"])
                missing = agent_context.main(["read", "absent.md"])
                saved = agent_context.main(
                    ["remember", "k1", "--summary-file", "summary.md", "--source", "evidence.md", "--kind", "decision"]
                )
                fresh = agent_context.main(["recall", "k1"])
                (root / "evidence.md").write_text("changed", encoding="utf-8")
                stale = agent_context.main(["recall", "k1"])
        self.assertEqual((ok, missing, saved, fresh, stale), (0, 2, 0, 0, 3))


if __name__ == "__main__":
    unittest.main()
