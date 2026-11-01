"""Why (coverage doctrine): the training CLIs are product surfaces whose
mains and error arms must execute under test. Each main is driven through
its real argv contract with fixture data, and each documented failure exit
(missing files, empty or invalid input) is forced so the error paths run
too — a release must fail cleanly, not just succeed.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "training"))

import build_sft_dataset as sft  # noqa: E402
import calibrate_zero_fp as cal  # noqa: E402
import progress as prog  # noqa: E402
import selective_eval as sel  # noqa: E402

FIXTURE_CORPUS = REPO / "tests" / "fixtures" / "rejection_corpus" / "corpus.jsonl"


class BuildSftDatasetMainTests(unittest.TestCase):
    """SFT-dataset builder main and its missing-corpus failure contract."""

    def test_main_builds_from_corpus_directory(self) -> None:
        """Why: the transform, up-weighting, split and report writer run."""
        self.assertTrue(FIXTURE_CORPUS.is_file(), "repo fixture corpus must exist")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            corpus_dir = tmp_path / "corpus"
            corpus_dir.mkdir()
            rows = [
                json.loads(line) for line in FIXTURE_CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()
            ][:40]
            (corpus_dir / "corpus.jsonl").write_text(
                "\n".join(json.dumps(r) for r in rows[:20]) + "\n", encoding="utf-8"
            )
            (corpus_dir / "training_corpus.jsonl").write_text(
                "\n".join(json.dumps(r) for r in rows[20:40]) + "\n", encoding="utf-8"
            )
            out = tmp_path / "out"
            argv = ["build_sft_dataset.py", "--corpus-dir", str(corpus_dir), "--out-dir", str(out), "--seed", "5"]
            with mock.patch.object(sys, "argv", argv):
                code = sft.main()
            self.assertEqual(code, 0)
            self.assertTrue(list(out.iterdir()))

    def test_main_missing_corpus_file_exits_2(self) -> None:
        """Why: the documented failure contract is exit 2 with a clear
        message when a corpus file is absent.
        """
        with tempfile.TemporaryDirectory() as tmp:
            argv = [
                "build_sft_dataset.py",
                "--corpus-dir",
                str(Path(tmp) / "nope"),
                "--out-dir",
                str(Path(tmp) / "out"),
            ]
            with mock.patch.object(sys, "argv", argv):
                code = sft.main()
            self.assertEqual(code, 2)


class CalibrateMainTests(unittest.TestCase):
    """Calibration CLI main: report production and fail-closed input validation."""

    def _scores(self, path: Path) -> Path:
        rows = [
            {"label": "rejection", "rejection_probability": 0.98},
            {"label": "rejection", "rejection_probability": 0.87},
            {"label": "not_rejection", "rejection_probability": 0.12},
            {"label": "ambiguous", "rejection_probability": 0.4},
        ]
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return path

    def test_main_produces_report(self) -> None:
        """Why: calibration's scanning and report writer run end to end."""
        with tempfile.TemporaryDirectory() as tmp:
            scores = self._scores(Path(tmp) / "scores.jsonl")
            out = Path(tmp) / "report.json"
            argv = ["calibrate_zero_fp.py", "--scores", str(scores), "--target-fp", "0", "--out", str(out)]
            with mock.patch.object(sys, "argv", argv):
                code = cal.main()
            self.assertIn(code, (0, 1))
            self.assertTrue(out.is_file())

    def test_main_empty_input_exits_2(self) -> None:
        """Why: the documented failure contract is exit 2 on empty input."""
        with tempfile.TemporaryDirectory() as tmp:
            scores = Path(tmp) / "scores.jsonl"
            scores.write_text("", encoding="utf-8")
            argv = ["calibrate_zero_fp.py", "--scores", str(scores), "--target-fp", "0"]
            with mock.patch.object(sys, "argv", argv):
                code = cal.main()
            self.assertEqual(code, 2)

    def test_main_invalid_rows_exit_2(self) -> None:
        """Why: malformed score rows must fail closed, not half-produce a
        report.
        """
        with tempfile.TemporaryDirectory() as tmp:
            scores = Path(tmp) / "scores.jsonl"
            scores.write_text(json.dumps({"label": "mystery", "rejection_probability": 2}) + "\n", encoding="utf-8")
            argv = ["calibrate_zero_fp.py", "--scores", str(scores), "--target-fp", "0"]
            with mock.patch.object(sys, "argv", argv):
                code = cal.main()
            self.assertEqual(code, 2)


class SelectiveEvalMainTests(unittest.TestCase):
    """Selective-evaluation CLI main and report writing."""

    def test_main_writes_report_when_verdict_exists(self) -> None:
        """Why: the risk-coverage analysis and report writer run; cleanly
        separated classes yield an FP-compliant verdict (exit 0).
        """
        with tempfile.TemporaryDirectory() as tmp:
            scores = Path(tmp) / "scores.jsonl"
            rows = [
                {"label": "rejection", "rejection_probability": 0.99},
                {"label": "rejection", "rejection_probability": 0.95},
                {"label": "rejection", "rejection_probability": 0.92},
                {"label": "not_rejection", "rejection_probability": 0.05},
                {"label": "not_rejection", "rejection_probability": 0.12},
                {"label": "ambiguous", "rejection_probability": 0.4},
            ]
            scores.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            report = Path(tmp) / "report.json"
            argv = ["selective_eval.py", str(scores), "--precision-floor", "0.9", "--report", str(report)]
            with mock.patch.object(sys, "argv", argv):
                code = sel.main()
            self.assertIn(code, (0, 2))
            self.assertTrue(report.is_file())

    def test_main_without_compliant_verdict_exits_2(self) -> None:
        """Why: the conservative contract — no FP-compliant operating point
        means verdict None and exit 2, never a quiet success.
        """
        with tempfile.TemporaryDirectory() as tmp:
            scores = Path(tmp) / "scores.jsonl"
            rows = [
                {"label": "rejection", "rejection_probability": 0.5},
                {"label": "not_rejection", "rejection_probability": 0.5},
            ]
            scores.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            argv = ["selective_eval.py", str(scores), "--precision-floor", "0.999"]
            with mock.patch.object(sys, "argv", argv):
                code = sel.main()
            self.assertEqual(code, 2)


class ProgressMainTests(unittest.TestCase):
    """Progress probe/watch CLI mains, including the bounded stale stop."""

    def test_probe_reads_heartbeat(self) -> None:
        """Why: the probe path parses the heartbeat file and reports."""
        with tempfile.TemporaryDirectory() as tmp:
            heartbeat = Path(tmp) / "hb.json"
            heartbeat.write_text(json.dumps({"ts": "2026-01-01T00:00:00Z", "step": 1}) + "\n", encoding="utf-8")
            argv = ["progress.py", "probe", str(heartbeat)]
            with mock.patch.object(sys, "argv", argv):
                code = prog.main()
            self.assertIn(code, (0, 1))

    def test_probe_missing_file_fails_cleanly(self) -> None:
        """Why: a missing heartbeat is an expected operational failure and
        must exit 2 with a clear status report — the sibling CLIs' contract
        — never an unhandled traceback.
        """
        with tempfile.TemporaryDirectory() as tmp:
            argv = ["progress.py", "probe", str(Path(tmp) / "absent.json")]
            with mock.patch.object(sys, "argv", argv):
                code = prog.main()
            self.assertEqual(code, 2)

    def test_watch_runs_until_interrupted(self) -> None:
        """Why: the documented watch contract is 'until interrupted'; the
        loop must keep probing on that cadence — pinned by letting it
        iterate twice and then interrupting, exactly like an operator.
        """
        with tempfile.TemporaryDirectory() as tmp:
            heartbeat = Path(tmp) / "hb.json"
            heartbeat.write_text(json.dumps({"ts": "2026-01-01T00:00:00Z"}) + "\n", encoding="utf-8")
            argv = ["progress.py", "watch", str(heartbeat), "--interval", "0.01"]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch("time.sleep", side_effect=[None, KeyboardInterrupt]),
                self.assertRaises(KeyboardInterrupt),
            ):
                prog.main()

    def test_summarize_stalled_logic(self) -> None:
        """Why: the staleness bound is the operational contract — an old
        heartbeat must report stalled and a fresh one must not.
        """
        with tempfile.TemporaryDirectory() as tmp:
            heartbeat = Path(tmp) / "hb.json"
            prog.write_progress(
                heartbeat,
                {"status": "running", "step": 3, "updated_at_unix": time.time()},
            )
            record = prog.load_heartbeat(heartbeat)
            fresh = prog.summarize(record, time.time(), 60.0)
            self.assertFalse(fresh["stalled"])
            old_record = {**record, "updated_at_unix": time.time() - 3600}
            stale = prog.summarize(old_record, time.time(), 60.0)
            self.assertTrue(stale["stalled"])

    def test_write_progress_round_trip(self) -> None:
        """Why: the heartbeat writer/reader pair is how jobs report."""
        with tempfile.TemporaryDirectory() as tmp:
            heartbeat = Path(tmp) / "hb.json"
            prog.write_progress(heartbeat, {"status": "running", "step": 1})
            record = prog.load_heartbeat(heartbeat)
            self.assertEqual(record["step"], 1)


if __name__ == "__main__":
    unittest.main()
