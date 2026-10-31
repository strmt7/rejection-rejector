#!/usr/bin/env python3
"""Tests for training/probe_llm_limits.py pure analysis helpers.

Covers the model-independent layer of the LLM capability probe: the
deterministic stratified sampler, the assistant-answer parser, accuracy
and fail-closed accounting (including the parse-failure overlap rule),
latency statistics, and the atomic progress writer. The live-Ollama
loop (call_ollama, probe_one_row, run_condition, main) requires a
running model and is exercised by the probe workflow itself.

Run from the repository root:
    python -m unittest discover -s training/tests -v
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "training"))

import probe_llm_limits as probe  # noqa: E402


class SamplingTests(unittest.TestCase):
    """Pin the stratified sampler."""

    def test_load_stratified_caps_per_class_in_file_order(self):
        """Each class contributes at most per_class rows, taken as the first
        rows in file order (the documented determinism).
        """
        with tempfile.TemporaryDirectory() as owned:
            path = pathlib.Path(owned) / "holdout.jsonl"
            rows = []
            for category in ("rejection", "other", "uncertain"):
                for index in range(4):
                    rows.append({"meta": {"category": category, "id": f"{category}-{index}"}})
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            sampled = probe.load_stratified(path, 2)
        self.assertEqual(len(sampled), 6)
        by_category = {}
        for row in sampled:
            by_category.setdefault(row["meta"]["category"], []).append(row["meta"]["id"])
        self.assertEqual(
            by_category,
            {
                "other": ["other-0", "other-1"],
                "rejection": ["rejection-0", "rejection-1"],
                "uncertain": ["uncertain-0", "uncertain-1"],
            },
        )


class ParsingTests(unittest.TestCase):
    """Pin the assistant-answer parser."""

    def test_parse_answer_extracts_the_json_object(self):
        """A JSON object embedded in prose parses; missing, empty and
        malformed objects return None (counted as parse failures).
        """
        self.assertEqual(probe.parse_answer('thinking... {"category": "rejection"} tail'), {"category": "rejection"})
        self.assertIsNone(probe.parse_answer("no object here"))
        self.assertIsNone(probe.parse_answer("{broken"))
        self.assertIsNone(probe.parse_answer("{not json}"))
        self.assertIsNone(probe.parse_answer(""))


class AccountingTests(unittest.TestCase):
    """Pin accuracy, fail-closed and latency accounting."""

    def test_accuracy_of_rounds_and_handles_empty(self):
        """Exact-match accuracy rounds to 4 places; empty input is None."""
        self.assertIsNone(probe.accuracy_of([]))
        results = [{"pred": "rejection", "true": "rejection"}, {"pred": "other", "true": "rejection"}]
        self.assertEqual(probe.accuracy_of(results), 0.5)

    def test_fail_closed_counts_and_the_parse_overlap_rule(self):
        """False acceptances (non-rejection predicted rejection) and safe
        misses (rejection missed) count separately; a parse failure on a
        true rejection ALSO counts as a safe miss (the conservative
        overlap the code documents).
        """
        results = [
            {"pred": "rejection", "true": "other"},
            {"pred": "other", "true": "rejection"},
            {"pred": "parse_failure", "true": "rejection"},
            {"pred": "parse_failure", "true": "other"},
            {"pred": "rejection", "true": "rejection"},
        ]
        counts = probe.fail_closed_counts(results)
        self.assertEqual(counts["false_acceptances"], 1)
        self.assertEqual(counts["safe_misses"], 2)
        self.assertEqual(counts["parse_failures"], 2)

    def test_latency_stats_and_summary_shape(self):
        """Means round; budget truncations count; the summary assembles the
        accuracy, confusion and fail-closed blocks.
        """
        results = [
            {"pred": "rejection", "true": "rejection", "latency_s": 1.0, "thinking_chars": 10, "done_reason": "stop"},
            {"pred": "other", "true": "other", "latency_s": 2.0, "thinking_chars": 30, "done_reason": "length"},
        ]
        stats = probe.latency_stats(results)
        self.assertEqual(stats["latency_s_mean"], 1.5)
        self.assertEqual(stats["thinking_chars_mean"], 20)
        self.assertEqual(stats["truncated_by_budget"], 1)
        empty = probe.latency_stats([])
        self.assertIsNone(empty["latency_s_mean"])
        summary = probe.summarize_condition(results, {"rejection": Counter({"rejection": 1})})
        self.assertEqual(summary["accuracy"], 1.0)
        self.assertEqual(summary["fail_closed"]["false_acceptances"], 0)
        self.assertEqual(summary["parse_failures"], 0)
        self.assertEqual(summary["confusion"], {"rejection": {"rejection": 1}})


class ProgressWriterTests(unittest.TestCase):
    """Pin the atomic progress writer."""

    def test_write_progress_replaces_atomically(self):
        """The marker lands as parseable JSON and overwrites in place."""
        with tempfile.TemporaryDirectory() as owned:
            path = pathlib.Path(owned) / "progress.json"
            probe.write_progress(path, {"job": "probe_llm_limits", "done": 1})
            probe.write_progress(path, {"job": "probe_llm_limits", "done": 2})
            record = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(path.with_suffix(".tmp").exists())
        self.assertEqual(record["done"], 2)


if __name__ == "__main__":
    unittest.main()
