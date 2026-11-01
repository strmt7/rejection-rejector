"""Why (coverage doctrine): the scale-campaign CLI main and its output
writers are product surface; the corpus contract (>=1000 records, every
self-check passing, byte-for-byte determinism per seed) must hold at the
entry point, not only in the driver's internals.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "training"))

import scale_campaign as sc  # noqa: E402


class ScaleCampaignMainTests(unittest.TestCase):
    """CLI-main and determinism contracts of the scale-campaign generator."""

    def test_main_writes_corpus_and_summary(self) -> None:
        """Why: the full generation pass, self-checks and both writers run;
        exit 0 is only reachable when every check passed.
        """
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corpus.jsonl"
            summary = Path(tmp) / "summary.json"
            code = sc.main(["--out", str(out), "--summary", str(summary), "--seed", "7"])
            self.assertEqual(code, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertGreaterEqual(len(rows), 1000)
            report = json.loads(summary.read_text(encoding="utf-8"))
            self.assertIsInstance(report, dict)

    def test_main_survives_legacy_console_encoding(self) -> None:
        """Why (Windows release review): the generator prints Greek and
        Cyrillic statistics; on a cp1252 console that used to crash the
        run with UnicodeEncodeError. The UTF-8 reconfiguration must make
        the CLI survive any console encoding.
        """
        import io

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "corpus.jsonl"
            summary = Path(tmp) / "summary.json"
            args = ["--out", str(out), "--summary", str(summary), "--seed", "7"]
            legacy_out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
            legacy_err = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
            with (
                mock.patch.object(sys, "argv", ["scale_campaign.py", *args]),
                mock.patch.object(sys, "stdout", legacy_out),
                mock.patch.object(sys, "stderr", legacy_err),
            ):
                code = sc.main(args)
            self.assertEqual(code, 0)
            self.assertTrue(out.is_file())

    def test_main_is_deterministic_per_seed(self) -> None:
        """Why: the corpus is evaluation material — the same seed must
        reproduce byte-identical output (the driver's determinism contract,
        asserted at the entry point).
        """
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "a.jsonl"
            second = Path(tmp) / "b.jsonl"
            with (
                open(Path(tmp) / "sa.json", "w", encoding="utf-8") as fa,
                open(Path(tmp) / "sb.json", "w", encoding="utf-8") as fb,
            ):
                fa.close()
                fb.close()
            self.assertEqual(sc.main(["--out", str(first), "--summary", str(Path(tmp) / "sa.json"), "--seed", "11"]), 0)
            self.assertEqual(
                sc.main(["--out", str(second), "--summary", str(Path(tmp) / "sb.json"), "--seed", "11"]), 0
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
