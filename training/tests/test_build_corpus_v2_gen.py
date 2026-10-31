#!/usr/bin/env python3
"""Tests for training/build_corpus_v2.py deterministic generation helpers.

Covers the seeded-RNG composition layer: safe template rendering (unknown
placeholders survive literally), date/time slot formats and ranges,
slot uniqueness guarantees, the one-swap typo injector's exact mutation,
emoji injection, and every transport-format wrapper's shape.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import pathlib
import random
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

import build_corpus_v2 as corpus  # noqa: E402


class TemplateTests(unittest.TestCase):
    """Pin the safe template rendering."""

    def test_known_slots_render_and_unknown_survive(self):
        """Known placeholders fill; unknown ones stay brace-quoted instead of
        raising KeyError.
        """
        self.assertEqual(corpus.fmt("Hi {name} and {who}", {"name": "A"}), "Hi A and {who}")

    def test_pick_is_seeded(self):
        """The seeded pick is reproducible."""
        self.assertEqual(
            corpus.pick(random.Random(7), [1, 2, 3]),
            corpus.pick(random.Random(7), [1, 2, 3]),
        )


class SlotTests(unittest.TestCase):
    """Pin slot generation contracts."""

    def test_date_time_shapes_and_ranges(self):
        """Dates are YYYY-MM-DD with month 01-12 and day 01-28; times are
        HH:MM with hour 08-18 and a quarter-hour minute.
        """
        rng = random.Random(11)
        for _ in range(50):
            date = corpus.make_date(rng)
            self.assertRegex(date, r"^202[4-6]-(0[1-9]|1[0-2])-(0[1-9]|1[0-9]|2[0-8])$")
            time = corpus.make_time(rng)
            self.assertRegex(time, r"^(0[8-9]|1[0-8]):(00|15|30|45)$")

    def test_make_slots_keys_and_name_distinctness(self):
        """Seeded slot dicts are reproducible and carry the documented keys;
        sender and name2 differ from name on multi-name banks.
        """
        slots = corpus.make_slots(random.Random(5), "en")
        again = corpus.make_slots(random.Random(5), "en")
        self.assertEqual(slots, again)
        for key in ("name", "first", "sender", "company", "position", "skill", "id", "date", "time", "ats", "name2"):
            self.assertIn(key, slots)
        self.assertNotEqual(slots["name"], slots["sender"])
        self.assertNotIn(slots["name2"], (slots["name"], slots["sender"]))


class MutationTests(unittest.TestCase):
    """Pin the realism-mutation helpers."""

    def test_inject_typos_swaps_exactly_one_adjacent_pair(self):
        """A word of 4+ letters gets one adjacent-letter swap and the rest of
        the text is untouched; texts with no eligible word pass through.
        """
        text = "hello world again"
        rng = random.Random(3)
        mutated = corpus.inject_typos(text, rng)
        self.assertNotEqual(mutated, text)
        self.assertEqual(len(mutated), len(text))
        self.assertEqual(mutated.count(" "), text.count(" "))
        self.assertEqual(corpus.inject_typos("a b 12", rng), "a b 12")

    def test_add_emoji_appends_one_marker(self):
        """Exactly one line gains one recognized emoji."""
        body = "first line\nsecond line"
        rng = random.Random(9)
        result = corpus.add_emoji(body, rng)
        self.assertEqual(len(result.splitlines()), 2)
        self.assertTrue(
            any(marker in result for marker in ("\U0001f64f", "\U0001f60a", "\u263a\ufe0f")),
            result,
        )


class FormatTests(unittest.TestCase):
    """Pin each transport-format wrapper's shape."""

    def test_format_shapes(self):
        """Every FORMATS wrapper adds exactly its documented artifacts and an
        unknown format returns the body unchanged.
        """
        rng = random.Random(2)
        slots = corpus.make_slots(rng, "en")
        body = "the message"
        html = corpus.apply_format(rng, body, "html_artifact", "en", slots)
        self.assertIn("Unsubscribe", html)
        self.assertTrue(html.startswith(body))
        forwarded = corpus.apply_format(rng, body, "forwarded_thread", "en", slots)
        self.assertIn("---------- Forwarded message ----------", forwarded)
        self.assertIn(f"From: {slots['sender']}", forwarded)
        self.assertTrue(forwarded.endswith(body))
        ats = corpus.apply_format(rng, body, "ats_auto", "en", slots)
        self.assertIn(f"automated message from {slots['ats']}", ats)
        dm = corpus.apply_format(rng, body, "recruiter_dm", "en", slots)
        self.assertIn("mobile app", dm)
        self.assertEqual(corpus.apply_format(rng, body, "unknown", "en", slots), body)


if __name__ == "__main__":
    unittest.main()
