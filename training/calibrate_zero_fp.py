#!/usr/bin/env python3
"""Calibrate a rejection-probability threshold for a practically-zero false
positive rate.

False positives (a non-rejection treated as a rejection) are the critical
error class: an assertive reply would target the wrong message. This tool
sweeps thresholds over labeled scores and selects the highest-recall threshold
whose observed false-positive count meets the target, reporting the binomial
upper bound so a "zero observed" result is never mistaken for zero risk.

Host-agnostic: scores arrive as JSONL via argument; no network or model access.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path


def wilson_upper_bound(failures: int, trials: int, z: float = 1.96) -> float:
    """Wilson score upper bound on a binomial proportion.

    Inputs: `failures` — observed negative outcomes; `trials` — total trials;
    `z` — normal quantile (1.96 = 95%). Output: upper bound in [0, 1].
    """
    if trials == 0:
        return 1.0
    p = failures / trials
    denom = 1 + z * z / trials
    centre = p + z * z / (2 * trials)
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    return min(1.0, (centre + margin) / denom)


def load_scores(path: Path) -> list[dict]:
    """Load labeled score records.

    Inputs: `path` — JSONL where each line has `label` (rejection or
    not_rejection; ambiguous counts as not_rejection for FP purposes) and
    `rejection_probability` in [0, 1]. Output: list of parsed records.
    """
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            rows.append(row)
    return rows


def calibrate(rows: list[dict], target_fp: int) -> dict:
    """Select the threshold meeting the FP target with maximal recall.

    Inputs: `rows` — labeled scores; `target_fp` — maximum acceptable observed
    false positives on the calibration set. Output: report dict with the chosen
    threshold, observed confusion counts, and the FP-rate upper bound.
    """
    positives = [r for r in rows if r["label"] == "rejection"]
    negatives = [r for r in rows if r["label"] != "rejection"]
    best = None
    for threshold in [i / 1000 for i in range(0, 1001)]:
        fp = sum(1 for r in negatives if r["rejection_probability"] >= threshold)
        tp = sum(1 for r in positives if r["rejection_probability"] >= threshold)
        if fp > target_fp:
            continue
        recall = tp / len(positives) if positives else 0.0
        candidate = {"threshold": threshold, "true_positives": tp, "false_positives": fp, "recall": recall}
        if best is None or candidate["recall"] > best["recall"]:
            best = candidate
    if best is None:
        best = {"threshold": 1.01, "true_positives": 0, "false_positives": 0, "recall": 0.0}
    best.update(
        {
            "positives": len(positives),
            "negatives": len(negatives),
            "target_false_positives": target_fp,
            "false_positive_rate_upper_95": wilson_upper_bound(best["false_positives"], len(negatives)),
        }
    )
    return best


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scores", type=Path, required=True, help="JSONL of label + rejection_probability")
    parser.add_argument("--target-fp", type=int, default=0)
    parser.add_argument("--out", type=Path, help="Optional report JSON output path")
    args = parser.parse_args()

    rows = load_scores(args.scores)
    if not rows:
        print("no score rows", file=sys.stderr)
        return 2
    report = calibrate(rows, args.target_fp)
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
