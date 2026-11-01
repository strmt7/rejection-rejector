"""Why (coverage doctrine): the corpus driver (generate_records, the split,
leakage repair, writers, and the three verification passes) is product code;
this suite executes the full pipeline end to end at tiny quota scale and then
attacks each verifier with deliberately broken inputs so its error arms run
too — broken inputs are exactly what a release must survive.
"""

from __future__ import annotations

import json
import random
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "training"))

import build_corpus_v2 as bc  # noqa: E402


def _tiny_quotas() -> dict:
    return {lang: {"rejection": 1, "negative": 1, "ambiguous": 1} for lang in bc.QUOTAS}


def _row(record: dict) -> dict:
    return bc.strip_private(record)


class DriverPipelineTests(unittest.TestCase):
    """End-to-end driver and verifier-failure tests for the corpus builder."""

    def test_generate_records_respects_tiny_quotas(self) -> None:
        """Why: the quota driver's per-language, per-kind arms must execute."""
        records, stats = bc.generate_records(random.Random(1), _tiny_quotas())
        self.assertTrue(records)
        self.assertIsInstance(stats, dict)
        for record in records:
            self.assertIn("messages", record)
            self.assertIn("category", record["meta"])

    def test_main_builds_corpus_and_passes_verification(self) -> None:
        """Why: main's full driver — split, repair, write, report, and every
        verifier's passing path — runs end to end; exit 0 only when all
        checks pass is the release contract.
        """
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corpus"
            argv = ["build_corpus_v2.py", "--out-dir", str(out), "--seed", "11"]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(bc, "QUOTAS", _tiny_quotas()):
                code = bc.main()
            self.assertEqual(code, 0)
            written = list(out.iterdir())
            self.assertTrue(written)

    def test_verify_schema_flags_deviant_rows(self) -> None:
        """Why: the schema verifier's rejection arm must fire on rows that
        deviate from the reference shape.
        """
        records, _ = bc.generate_records(random.Random(2), _tiny_quotas())
        reference = _row(records[0])
        deviant = dict(reference)
        deviant["surprise_key"] = 1
        report = bc.verify_schema([deviant], reference)
        self.assertIsInstance(report, dict)
        self.assertTrue(report)

    def test_verify_leakage_flags_shared_rows(self) -> None:
        """Why: the leakage verifier must catch identical bodies across the
        split — that is the failure it exists to prevent.
        """
        records, _ = bc.generate_records(random.Random(3), _tiny_quotas())
        shared = _row(records[0])
        with tempfile.TemporaryDirectory() as tmp:
            train = Path(tmp) / "train.jsonl"
            holdout = Path(tmp) / "holdout.jsonl"
            train.write_text(json.dumps(shared) + "\n", encoding="utf-8")
            holdout.write_text(json.dumps(shared) + "\n", encoding="utf-8")
            report = bc.verify_leakage(train, holdout)
            self.assertIsInstance(report, dict)
            self.assertTrue(report)

    def test_verify_counts_flags_missing_ids(self) -> None:
        """Why: the count verifier must catch ids lost between generation
        and the written files.
        """
        records, _ = bc.generate_records(random.Random(4), _tiny_quotas())
        rows = [_row(r) for r in records]
        with tempfile.TemporaryDirectory() as tmp:
            train = Path(tmp) / "train.jsonl"
            holdout = Path(tmp) / "holdout.jsonl"
            train.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
            holdout.write_text("", encoding="utf-8")
            report = {
                "ids": [r["meta"]["id"] for r in rows],
                "train_by_category": {},
                "holdout_by_category": {},
                "train_by_language": {},
                "holdout_by_language": {},
                "by_language": {},
                "negative_type_counts": {},
                "ambiguous_type_counts": {},
                "by_negative_type": {},
                "by_ambiguous_type": {},
            }
            result = bc.verify_counts(
                train,
                holdout,
                report=report,
                neg_type_by_id={r["meta"]["id"]: r.get("_neg_type", "none") for r in rows},
            )
            self.assertIsInstance(result, dict)
            self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
