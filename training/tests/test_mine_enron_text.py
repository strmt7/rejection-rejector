#!/usr/bin/env python3
"""Tests for training/mine_enron.py text and dedup utilities.

Covers the pure corpus-processing layer: normalization canonicalization
(e-mails/digits/punctuation), sentence splitting incl. CJK punctuation,
shingle construction incl. the short-text edge, Jaccard and the
near-duplicate size gate, deterministic stable_int, the never-raising
byte decoder's charset priority, RFC-2047 header decoding, and the
MIME plain/HTML part collectors with attachment skipping.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import email
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

import mine_enron  # noqa: E402


class NormalizationTests(unittest.TestCase):
    """Pin the dedup-normalization contract."""

    def test_canonicalizes_emails_digits_and_punctuation(self):
        """E-mails collapse to one token, digits to zero, punctuation to
        spaces, whitespace to one.
        """
        self.assertEqual(mine_enron.normalize_text("A@B.co and 42!"), "mail and 0")
        self.assertEqual(mine_enron.normalize_text("  Multi\n\n spaces\t"), "multi spaces")
        self.assertEqual(mine_enron.normalize_text("Straße 123"), "strasse 0")

    def test_sentence_splitting_handles_cjk_and_newlines(self):
        """Latin and CJK sentence punctuation split; newlines split; empties
        drop.
        """
        self.assertEqual(
            mine_enron.split_sentences("Hi. There! Ok\nEnd"),
            ["Hi.", "There!", "Ok", "End"],
        )
        # CJK punctuation splits only before whitespace, exactly like Latin.
        self.assertEqual(mine_enron.split_sentences("你好。 今天"), ["你好。", "今天"])
        self.assertEqual(mine_enron.split_sentences("你好。今天"), ["你好。今天"])

    def test_hash_text_matches_hashlib(self):
        """The dedup digest is plain SHA-256 of the UTF-8 text."""
        import hashlib

        self.assertEqual(mine_enron.hash_text("x"), hashlib.sha256(b"x").hexdigest())


class ShingleTests(unittest.TestCase):
    """Pin shingling and near-duplicate gating."""

    def test_shingles_short_text_edge(self):
        """Fewer words than n yields exactly one short gram (the documented
        max(1, ...) bound) instead of an empty set.
        """
        self.assertEqual(
            mine_enron.shingles("one two", n=3),
            frozenset({("one", "two")}),
        )
        self.assertEqual(
            mine_enron.shingles("a b c d", n=3),
            frozenset({("a", "b", "c"), ("b", "c", "d")}),
        )

    def test_jaccard_edges(self):
        """Identical sets are 1.0; disjoint or empty sets are 0.0."""
        a = frozenset({("x",)})
        self.assertEqual(mine_enron.jaccard(a, a), 1.0)
        self.assertEqual(mine_enron.jaccard(a, frozenset({("y",)})), 0.0)
        self.assertEqual(mine_enron.jaccard(frozenset(), frozenset()), 0.0)

    def test_near_dup_size_gate_and_threshold(self):
        """A hopeless size ratio refuses before the O(n^2) intersection; large
        similar sets and identical sets qualify.
        """
        small = frozenset({("a",)})
        large = frozenset({(f"w{i}",) for i in range(100)})
        self.assertFalse(mine_enron.maybe_near_dup(small, large))
        shared = frozenset({(f"w{i}",) for i in range(90)})
        self.assertTrue(mine_enron.maybe_near_dup(shared, large))
        self.assertTrue(mine_enron.maybe_near_dup(large, large))
        self.assertFalse(mine_enron.maybe_near_dup(frozenset(), large))

    def test_stable_int_is_deterministic_and_bounded(self):
        """The scan-order-independent hash lands in [0, mod) reproducibly."""
        first = mine_enron.stable_int("case", 97)
        self.assertEqual(first, mine_enron.stable_int("case", 97))
        self.assertTrue(0 <= first < 97)


class DecodingTests(unittest.TestCase):
    """Pin the never-raising decoders."""

    def test_decode_bytes_priority_chain(self):
        """Declared charset wins; invalid names fall through to utf-8 then
        latin-1; nothing raises.
        """
        self.assertEqual(mine_enron.decode_bytes("é".encode("latin-1"), "latin-1"), "é")
        self.assertEqual(mine_enron.decode_bytes(b"plain", "not-a-charset"), "plain")
        self.assertEqual(mine_enron.decode_bytes("é".encode("latin-1"), None), "é")
        self.assertEqual(mine_enron.decode_bytes("é".encode(), "utf-8"), "é")

    def test_decode_header_value_decodes_and_falls_back(self):
        """RFC-2047 words decode; missing headers are empty; undecodable
        values fall back to the raw string.
        """
        message = email.message_from_string("Subject: =?utf-8?b?w6k=?=\nX-None: \nX-Raw: plain\n\n")
        self.assertEqual(mine_enron.decode_header_value(message, "subject"), "é")
        self.assertEqual(mine_enron.decode_header_value(message, "missing"), "")
        self.assertEqual(mine_enron.decode_header_value(message, "x-raw"), "plain")

    def test_part_collectors_skip_attachments(self):
        """text/plain and text/html bodies collect; attachment parts skip."""
        message = email.message_from_string(
            "\n".join(
                [
                    "Content-Type: multipart/mixed; boundary=B",
                    "",
                    "--B",
                    "Content-Type: text/plain",
                    "",
                    "plain body",
                    "--B",
                    "Content-Type: text/html",
                    "",
                    "<p>html body</p>",
                    "--B",
                    'Content-Type: text/plain; name="f.txt"',
                    'Content-Disposition: attachment; filename="f.txt"',
                    "",
                    "attachment bytes",
                    "--B--",
                    "",
                ]
            )
        )
        plain = mine_enron._plain_parts(message)
        html = mine_enron._html_parts(message)
        self.assertEqual(len(plain), 1, plain)
        self.assertIn("plain body", plain[0])
        self.assertEqual(len(html), 1, html)
        self.assertIn("html body", html[0])


if __name__ == "__main__":
    unittest.main()
