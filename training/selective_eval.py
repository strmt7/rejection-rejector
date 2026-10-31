"""Selective-classification evaluation: risk-coverage, per-class bounds, deferral.

This tool answers the operating question the single-threshold calibrator
cannot: across EVERY decision threshold, what share of traffic would be
auto-acted on, and what is the statistical risk on that share? The report
is the evidence an operator uses to pick the threshold; the precision
verdict uses conservative Wilson LOWER bounds so "zero observed errors"
never reads as zero risk.

Selection semantics match the runtime classification contract and
`calibrate_zero_fp`: a row is predicted positive exactly when
`rejection_probability >= threshold`. Ambiguous ground-truth rows are
always part of the deferred set in the verdict accounting because the
product sends ambiguous mail to human review by design.

Input contract: JSONL rows of
`{"label": "rejection"|"not_rejection"|"ambiguous", "rejection_probability": 0..1}`
(the exact contract of `calibrate_zero_fp` and the evaluation campaigns).

Inputs: `scores` -- JSONL file path; `--precision-floor` -- minimum
acceptable precision on auto-acted positives (Wilson lower bound,
default 0.99); `--report` -- optional output path for the JSON report.
Output: the report on stdout (and the optional file): the full
risk-coverage curve, per-class precision/recall with 95% bounds at the
verdict threshold, deferral accounting, and the verdict itself
(highest-coverage threshold meeting the floor) or a refusal when no
threshold meets it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from calibrate_zero_fp import load_scores, wilson_upper_bound  # noqa: E402

# Normal quantile for the two-sided 95% interval (same convention as
# calibrate_zero_fp.wilson_upper_bound's default).
Z95 = 1.96


def wilson_lower_bound(successes: int, trials: int, z: float = Z95) -> float:
    """Purpose: Bound a success proportion from below.

    Inputs: `successes` -- observed successes; `trials` -- total trials
    (0 trials yields 0.0); `z` -- normal quantile (1.96 = 95%);
    Output: lower bound in [0, 1]; the conservative side for precision
    floors.
    """
    if trials == 0:
        return 0.0
    return 1.0 - wilson_upper_bound(trials - successes, trials, z)


def curve_point(rows: list[dict], threshold: float) -> dict:
    """Purpose: Evaluate one decision threshold.

    Inputs: validated rows and the threshold;
    Output: dict with coverage/risk accounting: total, deferred (including
    every ambiguous row), auto_acted, correct_positives, wrong_sends
    (predicted positive on non-rejection ground truth), precision and its
    Wilson bounds, plus recall over ground-truth rejections.
    """
    total = len(rows)
    deferred = 0
    auto_acted = 0
    correct_positives = 0
    wrong_sends = 0
    ground_truth_positives = sum(1 for row in rows if row["label"] == "rejection")
    for row in rows:
        predicted_positive = row["rejection_probability"] >= threshold
        if row["label"] == "ambiguous" or not predicted_positive:
            deferred += 1
            continue
        auto_acted += 1
        if row["label"] == "rejection":
            correct_positives += 1
        else:
            wrong_sends += 1
    precision = correct_positives / auto_acted if auto_acted else 1.0
    recall = correct_positives / ground_truth_positives if ground_truth_positives else 1.0
    return {
        "threshold": threshold,
        "total": total,
        "auto_acted": auto_acted,
        "deferred": deferred,
        "correct_positives": correct_positives,
        "wrong_sends": wrong_sends,
        "coverage": auto_acted / total if total else 0.0,
        "defer_rate": deferred / total if total else 0.0,
        "precision": precision,
        "precision_lower_95": wilson_lower_bound(correct_positives, auto_acted),
        "precision_upper_95": wilson_upper_bound(wrong_sends, auto_acted),
        "recall": recall,
    }


def evaluate(rows: list[dict], precision_floor: float) -> dict:
    """Purpose: Build the full risk-coverage report and verdict.

    Inputs: validated rows and the minimum acceptable precision floor;
    Output: the report dict containing every candidate threshold point
    (the distinct observed scores, ascending, plus 1.0 for the empty-accept
    end), the verdict point (highest coverage whose precision Wilson lower
    bound meets the floor) or None, and the refusal reason when none
    qualifies.
    """
    if not rows:
        raise ValueError("selective evaluation requires at least one scored row")
    if not 0.0 < precision_floor <= 1.0:
        raise ValueError("precision floor must lie in (0, 1]")
    # Ascending thresholds enumerate descending coverage: the first
    # qualifying point is therefore the HIGHEST-coverage operating point
    # meeting the floor.
    thresholds = sorted({row["rejection_probability"] for row in rows})
    curve = [curve_point(rows, threshold) for threshold in thresholds]
    verdict = None
    for point in curve:
        if point["precision_lower_95"] >= precision_floor:
            verdict = point
            break
    report = {
        "rows": len(rows),
        "precision_floor": precision_floor,
        "curve": curve,
        "verdict": verdict,
        "verdict_reason": (
            "highest-coverage threshold whose precision Wilson lower bound meets the floor"
            if verdict is not None
            else "no threshold meets the precision floor; keep deferring (human review)"
        ),
    }
    return report


def main() -> int:
    """Purpose: Run the selective evaluation CLI. Inputs: CLI arguments; Output: report on stdout/file, exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scores", type=Path, help="JSONL rows: label + rejection_probability")
    parser.add_argument("--precision-floor", type=float, default=0.99)
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args()
    rows = load_scores(args.scores)
    report = evaluate(rows, args.precision_floor)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.report is not None:
        args.report.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["verdict"] is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
