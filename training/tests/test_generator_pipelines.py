#!/usr/bin/env python3
"""Tests for the corpus-emitting pipelines over fixture data.

Covers the deterministic generation pipelines end to end at small scale:
build_corpus_v2.generate_records (seeded determinism, exact quota
fulfilment, record schema, exact-hash dedup, the 12-language guarantee)
and build_sft_dataset (the corpus-to-SFT record transform and the
deterministic stratified split's category coverage and disjointness).

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import json
import pathlib
import random
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

import build_corpus_v2 as corpus  # noqa: E402
import build_sft_dataset as sft  # noqa: E402

HEX64 = re.compile(r"^[a-f0-9]{64}$")


def small_quotas(per_kind: int = 1) -> dict:
    """Purpose: Build quotas for every guaranteed language.

    Inputs: `per_kind` -- rows per category kind; Output: the quota dict
    keyed exactly like LANGUAGES expects.
    """
    return {lang: {"rejection": per_kind + 1, "negative": per_kind, "ambiguous": per_kind} for lang in corpus.LANGUAGES}


class GenerateRecordsTests(unittest.TestCase):
    """Pin the seeded corpus emitter end to end."""

    @classmethod
    def setUpClass(cls):
        """Purpose: Generate one small corpus once for the schema tests.

        Inputs: none; Output: none (class fixtures).
        """
        cls.quota = small_quotas()
        cls.records, cls.stats = corpus.generate_records(random.Random(20261031), cls.quota)

    def test_seeded_generation_is_deterministic(self):
        """The same seed reproduces every record and counter exactly."""
        again, stats_again = corpus.generate_records(random.Random(20261031), small_quotas())
        self.assertEqual(self.records, again)
        self.assertEqual(self.stats, stats_again)

    def test_quotas_are_met_exactly(self):
        """Every language and kind produces exactly its quota."""
        expected = sum(sum(kinds.values()) for kinds in self.quota.values())
        self.assertEqual(len(self.records), expected)
        self.assertEqual(self.stats["attempts"], expected + self.stats["exact_dupes_skipped"])

    def test_every_record_matches_the_sft_schema(self):
        """Records carry the three chat roles, the audit meta, 64-hex private
        hashes, and well-formed assistant/user JSON payloads.
        """
        seen_exact = set()
        languages = set()
        for record in self.records:
            roles = [message["role"] for message in record["messages"]]
            self.assertEqual(roles, ["system", "user", "assistant"])
            for key in ("id", "label", "category", "purpose"):
                self.assertIn(key, record["meta"])
            self.assertRegex(record["_exact_hash"], HEX64)
            self.assertRegex(record["_near_hash"], HEX64)
            self.assertNotIn(record["_exact_hash"], seen_exact)
            seen_exact.add(record["_exact_hash"])
            user = json.loads(record["messages"][1]["content"])
            self.assertIn("subject", user)
            self.assertIn("untrusted_email", user)
            assistant = json.loads(record["messages"][2]["content"])
            for key in ("category", "confidence", "evidence", "explanation", "company", "position", "language"):
                self.assertIn(key, assistant)
            self.assertIsInstance(assistant["confidence"], int)
            languages.add(assistant["language"])
        self.assertEqual(languages, set(corpus.LANGUAGES), "the 12-language guarantee")


class SftTransformTests(unittest.TestCase):
    """Pin the corpus-to-SFT transform and the stratified split."""

    @staticmethod
    def _sft_records(count_per_category: int = 4) -> list[dict]:
        """Purpose: Build synthetic SFT records across three categories.

        Inputs: `count_per_category`; Output: record list with meta.category.
        """
        return [
            {"messages": [], "meta": {"id": f"{cat}-{i}", "category": cat}}
            for cat in ("rejection", "negative", "ambiguous")
            for i in range(count_per_category)
        ]

    def test_build_record_transform(self):
        """One corpus entry becomes the chat-format record with the audit
        meta and assistant fields.
        """
        entry = {
            "id": "row-1",
            "label": "rejection",
            "subject": "Application update",
            "body": "Thank you for applying.",
            "rejection_style": "polite",
            "industry": "tech",
            "language": "en",
            "purpose": "evaluation",
        }
        record = sft.build_record(entry)
        self.assertEqual([m["role"] for m in record["messages"]], ["system", "user", "assistant"])
        self.assertEqual(record["meta"]["id"], "row-1")
        assistant = json.loads(record["messages"][2]["content"])
        self.assertIn("polite", assistant["explanation"])
        self.assertIn("tech", assistant["explanation"])
        user = json.loads(record["messages"][1]["content"])
        self.assertEqual(user["subject"], "Application update")

    def test_stratified_split_is_deterministic_and_complete(self):
        """Same seed reproduces the split; every category lands in both
        parts; the parts are disjoint; the holdout cut is at least one per
        category.
        """
        records = self._sft_records()
        train, holdout = sft.stratified_split(records, 0.25, seed=42)
        again_train, again_holdout = sft.stratified_split(self._sft_records(), 0.25, seed=42)
        self.assertEqual(train, again_train)
        self.assertEqual(holdout, again_holdout)
        self.assertEqual(len(train) + len(holdout), len(records))
        train_ids = {rec["meta"]["id"] for rec in train}
        holdout_ids = {rec["meta"]["id"] for rec in holdout}
        self.assertFalse(train_ids & holdout_ids)
        self.assertEqual(
            {rec["meta"]["category"] for rec in train},
            {rec["meta"]["category"] for rec in holdout},
        )
        self.assertTrue(holdout_ids)


if __name__ == "__main__":
    unittest.main()
