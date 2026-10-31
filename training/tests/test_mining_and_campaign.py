#!/usr/bin/env python3
"""Tests for the mining corpus seams and the campaign-builder driver.

Covers mine_enron's corpus iterators (directory and tar sources with the
containment rules, unsupported-source refusal), the raw-message parser,
the miner's stats-only driver over a fixture maildir, and
scale_campaign.main end to end: seeded byte-identical outputs, the
minimum-corpus self-check, summary emission and row shape.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

import mine_enron  # noqa: E402
import scale_campaign  # noqa: E402


def write_mail(root: pathlib.Path, name: str, subject: str, body: str) -> None:
    """Purpose: Write one fixture RFC822 message.

    Inputs: `root` -- fixture directory; `name` -- file name; `subject`/`body`
    -- message parts; Output: none.
    """
    (root / name).write_bytes(f"From: sender@example.invalid\r\nSubject: {subject}\r\n\r\n{body}".encode())


class CorpusIteratorTests(unittest.TestCase):
    """Pin the corpus-source seams."""

    def test_directory_source_yields_contained_files(self):
        """Recursive walk yields every contained regular file's bytes; the
        source key is the file name.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned) / "corpus"
            nested = root / "user" / "inbox"
            nested.mkdir(parents=True)
            write_mail(root, "top.eml", "S1", "b1")
            write_mail(nested, "inner.eml", "S2", "b2")
            found = {name: data for name, data in mine_enron.iter_raw_messages(root)}
        self.assertEqual(set(found), {"top.eml", "inner.eml"})
        self.assertIn(b"Subject: S1", found["top.eml"])
        self.assertIn(b"Subject: S2", found["inner.eml"])

    def test_tar_source_streams_without_extracting(self):
        """A .tar.gz source yields its members as raw bytes (never extracted
        to disk).
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            archive = root / "corpus.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for name, subject in (("m1.eml", "A"), ("m2.eml", "B")):
                    payload = f"Subject: {subject}\r\n\r\nbody".encode()
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
            found = {name: data for name, data in mine_enron.iter_raw_messages(archive)}
        self.assertEqual(set(found), {"m1.eml", "m2.eml"})
        self.assertIn(b"Subject: A", found["m1.eml"])

    def test_unsupported_source_refuses(self):
        """A non-corpus file path refuses instead of guessing."""
        with tempfile.TemporaryDirectory() as owned:
            plain = pathlib.Path(owned) / "notes.txt"
            plain.write_text("not a corpus", encoding="utf-8")
            with self.assertRaises(SystemExit):
                list(mine_enron.iter_raw_messages(plain))

    def test_parse_message_normalizes_and_refuses_empty(self):
        """Subjects and bodies extract with CRLF normalization and blank-line
        collapse; messages with neither subject nor body refuse.
        """
        subject, body, _message = mine_enron.parse_message(b"Subject: Job update\r\n\r\nline1\r\n\r\n\r\n\r\nline2")
        self.assertEqual(subject, "Job update")
        self.assertEqual(body, "line1\n\nline2")
        self.assertIsNone(mine_enron.parse_message(b"From: x\r\n\r\n"))
        self.assertIsNone(mine_enron.parse_message(b""))


class MinerDriverTests(unittest.TestCase):
    """Pin the stats-only mining driver over a fixture maildir."""

    def test_stats_only_scan_completes_over_fixture_corpus(self):
        """The full scan pipeline (walk, parse, topic gate, counters) runs
        over a mixed fixture corpus and exits 0 without emitting rows.
        """
        with tempfile.TemporaryDirectory() as owned:
            root = pathlib.Path(owned)
            corpus = root / "corpus"
            corpus.mkdir()
            write_mail(
                corpus,
                "job.eml",
                "Your application",
                "Thank you for applying to the software engineer position.",
            )
            write_mail(
                corpus,
                "recruiter.eml",
                "Open role",
                "We are recruiting for a job opening on our team.",
            )
            write_mail(corpus, "noise.eml", "Lunch", "The cafeteria menu changed.")
            out = root / "out"
            argv = [
                "mine_enron.py",
                "--corpus",
                str(corpus),
                "--out-dir",
                str(out),
                "--target",
                "1",
                "--stats-only",
            ]
            with mock.patch("sys.argv", argv), redirect_stdout(io.StringIO()):
                code = mine_enron.main()
        self.assertEqual(code, 0)


class CampaignDriverTests(unittest.TestCase):
    """Pin the scale-campaign generator driver end to end."""

    def test_campaign_generation_is_deterministic_and_complete(self):
        """Two same-seed runs produce byte-identical corpora and summaries;
        the self-checks pass (>=1000 rows) and rows carry language and
        category.
        """
        outputs = []
        for _run in range(2):
            with tempfile.TemporaryDirectory() as owned:
                root = pathlib.Path(owned)
                out = root / "corpus.jsonl"
                summary = root / "summary.json"
                # main(argv) passes argv straight to parse_args: no program
                # name belongs in it.
                argv = ["--out", str(out), "--summary", str(summary), "--seed", "7"]
                with redirect_stdout(io.StringIO()):
                    code = scale_campaign.main(argv)
                self.assertEqual(code, 0)
                outputs.append((out.read_bytes(), summary.read_bytes()))
        self.assertEqual(outputs[0], outputs[1], "same seed must reproduce the corpus byte for byte")
        rows = [json.loads(line) for line in outputs[0][0].decode("utf-8").splitlines()]
        self.assertGreaterEqual(len(rows), 1000)
        first = rows[0]
        self.assertIn("language", first)
        self.assertIn("category", first)
        summary = json.loads(outputs[0][1])
        self.assertIsInstance(summary, dict)


if __name__ == "__main__":
    unittest.main()
