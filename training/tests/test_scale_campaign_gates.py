#!/usr/bin/env python3
"""Tests for training/scale_campaign.py deterministic gates.

Covers the mirror of the Rust pipeline's gate layer: the multilingual
quote-start attribution tables (the 12-language guarantee), current-text
extraction (quote breaks and '>' lines), clear-rejection and
conflict-language detection over subject + de-quoted body, the Gates
header parsing (Auto-Submitted semantics, completeness budget), and the
tri_state decision table that mirrors engine::analyze_job.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

import scale_campaign as campaign  # noqa: E402


def raw_message(subject: str, body: str, extra_headers: str = "") -> str:
    """Purpose: Build one CRLF raw message for the Gates parser.

    Inputs: `subject`/`body` -- message parts; `extra_headers` -- additional
    header lines; Output: the raw message string.
    """
    return f"Subject: {subject}\r\n{extra_headers}\r\n{body}"


class QuoteDetectionTests(unittest.TestCase):
    """Pin the multilingual quote-start tables."""

    def test_all_supported_attribution_lines_are_recognized(self):
        """Every language's generated attribution line opens a quote section
        (the 12-language guarantee).
        """
        for lang, template in campaign.QUOTE_ATTRIBUTION.items():
            line = campaign.fmt(template, {"name2": "X"}).lower()
            with self.subTest(lang=lang):
                self.assertTrue(campaign.is_quote_start(line), line)

    def test_forward_headings_and_markers_open_quotes(self):
        """Forwarded-message headings and the marker list are quote starts;
        ordinary prose is not.
        """
        for lang, heading in campaign.FORWARD_HEADING.items():
            with self.subTest(lang=lang):
                self.assertTrue(campaign.is_quote_start(heading.lower()))
        self.assertTrue(campaign.is_quote_start("on monday, x wrote:"))
        self.assertFalse(campaign.is_quote_start("on monday the team met"))
        self.assertFalse(campaign.is_quote_start("hello world"))
        self.assertFalse(campaign.is_quote_start("op maandag was het stil"))

    def test_per_language_attribution_edges(self):
        """Each attribution family's positive and near-miss negative."""
        self.assertTrue(campaign.is_quote_start("am 1. mai schrieb x:"))
        self.assertFalse(campaign.is_quote_start("am 1. mai war x da"))
        self.assertTrue(campaign.is_quote_start("el 20 de mayo escribió x:"))
        self.assertTrue(campaign.is_quote_start("x написал(а):"))
        self.assertFalse(campaign.is_quote_start("x написал письмо"))
        self.assertTrue(campaign.is_quote_start("2025年5月20日、x のメッセージ:"))
        self.assertTrue(campaign.is_quote_start("x写道："))
        self.assertTrue(campaign.is_quote_start("x ने लिखा:"))
        self.assertTrue(campaign.is_quote_start("x লিখেছেন"))
        self.assertTrue(campaign.is_quote_start("le 20 mai x a écrit :"))
        self.assertTrue(campaign.is_quote_start("em 20 de maio escreveu x:"))
        self.assertTrue(campaign.is_quote_start("στις 20 μαΐου έγραψε ο x:"))


class CurrentTextTests(unittest.TestCase):
    """Pin quote stripping in current-text extraction."""

    def test_strips_at_quote_break_and_quoted_lines(self):
        """Text after a quote-start line disappears; '>' lines disappear; CR
        line endings normalize.
        """
        body = "keep me\r\n> quoted line\r\n\r\nOn 2025-01-01, X wrote:\r\n> history"
        # Blank lines before the quote survive as empty entries (the mirror's
        # exact join semantics); everything from the quote start disappears.
        self.assertEqual(campaign.current_text(body), "keep me\n")
        self.assertEqual(campaign.current_text("a\nplain"), "a\nplain")


class LanguageGateTests(unittest.TestCase):
    """Pin clear-rejection and conflict-language detection."""

    def test_clear_rejection_uses_current_text_only(self):
        """A clear phrase in the current message (or subject) trips; the same
        phrase only inside quoted history does not.
        """
        phrase = sorted(campaign.CLEAR_PHRASES)[0]
        self.assertTrue(campaign.clear_rejection_language("", f"we {phrase} now"))
        self.assertTrue(campaign.clear_rejection_language(f"Re: {phrase}", ""))
        body = f"On 2025-01-01, X wrote:\n> {phrase}"
        self.assertFalse(campaign.clear_rejection_language("", body))

    def test_conflict_language_trips_the_same_way(self):
        """Conflict/injection phrases follow the same subject + current-text
        surface.
        """
        phrase = sorted(campaign.CONFLICT_PHRASES)[0]
        self.assertTrue(campaign.auto_language_conflict("", f"note {phrase} here"))
        self.assertFalse(campaign.auto_language_conflict("", f"On 2025-01-01, X wrote:\n> {phrase}"))


class GatesAndTriStateTests(unittest.TestCase):
    """Pin the gate parsing and the tri-state decision table."""

    def test_auto_submitted_semantics(self):
        """Any Auto-Submitted value except 'no' and 'auto-generated' marks the
        message; those two leave it unmarked (the documented mirror).
        """
        marked = campaign.Gates(raw_message("S", "body", "Auto-Submitted: auto-replied\r\n"))
        self.assertTrue(marked.auto_reply_marker)
        for value in ("no", "auto-generated"):
            clean = campaign.Gates(raw_message("S", "body", f"Auto-Submitted: {value}\r\n"))
            self.assertFalse(clean.auto_reply_marker, value)

    def test_complete_input_budget(self):
        """Oversized bodies and subjects fail the completeness budget."""
        ok = campaign.Gates(raw_message("S", "short body"))
        self.assertTrue(ok.complete_input)
        huge = campaign.Gates(raw_message("S", "x" * 70000))
        self.assertFalse(huge.complete_input)
        long_subject = campaign.Gates(raw_message("s" * 700, "body"))
        self.assertFalse(long_subject.complete_input)

    def test_tri_state_decision_table(self):
        """Rejection -> respond only when all gates pass (else hold);
        uncertain -> hold; anything else -> ignore.
        """
        phrase = sorted(campaign.CLEAR_PHRASES)[0]
        responding = campaign.Gates(raw_message("Re: job", f"update: {phrase}"))
        self.assertTrue(responding.clear)
        self.assertEqual(campaign.tri_state("rejection", responding), "respond")
        conflicted = campaign.Gates(raw_message("Re: job", f"update: {phrase}", "Auto-Submitted: auto-replied\r\n"))
        self.assertEqual(campaign.tri_state("rejection", conflicted), "hold")
        self.assertEqual(campaign.tri_state("uncertain", responding), "hold")
        self.assertEqual(campaign.tri_state("opportunity", responding), "ignore")
        self.assertEqual(campaign.tri_state("other", responding), "ignore")


if __name__ == "__main__":
    unittest.main()
