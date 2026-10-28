#!/usr/bin/env python3
"""Calibrate a rejection-probability threshold for a practically-zero false
positive rate.

False positives (a non-rejection treated as a rejection) are the critical
error class: an assertive reply would target the wrong message. This tool
selects the highest-recall operating threshold whose observed false-positive
count meets the target and reports the binomial upper bound so a "zero
observed" result is never mistaken for zero risk.

Selection semantics (the runtime classification contract): a row is predicted
positive exactly when `rejection_probability >= threshold` (`>=`, matching the
application's decision gate). Candidate thresholds are exactly the distinct
observed scores, which enumerate every decision set that `>=` can induce, so
the optimum over feasible thresholds is exact — never a coarse grid
approximation. Equal positive/negative scores cannot be separated by any
threshold; the tie is resolved deterministically by the `>=` rule.

Input contract: JSONL rows of
`{"label": "rejection"|"not_rejection"|"ambiguous", "rejection_probability": 0..1}`.
The documented policy keeps `ambiguous` in the negative class for false-positive
purposes. Any other label, a boolean/non-numeric/non-finite/out-of-range
probability, or a missing field is rejected before any report is produced.

Report statuses:
- `ok`: a qualifying threshold was found; counts are recounted at that
  threshold and always match it.
- `abstain_all`: no threshold meets the false-positive budget with any true
  positive; the explicit abstain-all outcome (never an out-of-range threshold
  smuggled in as a mode).
- `insufficient_data`: a required class is empty, so recall and/or the
  false-positive rate are undefined; they stay null with reasons.

Host-agnostic: scores arrive as JSONL via argument; no network or model access.
A threshold selected on calibration data qualifies only calibration behavior;
an independent generalization claim additionally requires a separately
identified evaluation split (`split_role` records which split this is).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

# The only declared labels. `ambiguous` is explicitly permitted and counts as
# negative for FP purposes (see module docstring); any other label is invalid.
VALID_LABELS = ("rejection", "not_rejection", "ambiguous")
COMPARISON = "score >= threshold"


class ScoreRowError(ValueError):
    """One invalid score record; the message names the offending line/row."""


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


def validate_row(row: object, where: str) -> dict:
    """Validate one score record against the documented input contract.

    Inputs: `row` — parsed JSON value; `where` — location label ("line N" or
    "row N") used in error messages. Output: the normalized record with a
    string `label` and a float `rejection_probability`. Raises
    [`ScoreRowError`] for a non-record, missing/undeclared label, or a
    boolean, non-numeric, non-finite or out-of-[0, 1] probability.
    """
    if not isinstance(row, dict):
        raise ScoreRowError(f"{where}: expected a JSON object, got {type(row).__name__}")
    label = row.get("label")
    if not isinstance(label, str):
        raise ScoreRowError(f"{where}: missing or non-string 'label'")
    if label not in VALID_LABELS:
        raise ScoreRowError(f"{where}: unknown label {label!r}; declared labels are {list(VALID_LABELS)}")
    if "rejection_probability" not in row:
        raise ScoreRowError(f"{where}: missing 'rejection_probability'")
    score = row["rejection_probability"]
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ScoreRowError(f"{where}: 'rejection_probability' must be a number, not {type(score).__name__}")
    score = float(score)
    if not math.isfinite(score):
        raise ScoreRowError(f"{where}: 'rejection_probability' must be finite, got {score!r}")
    if not 0.0 <= score <= 1.0:
        raise ScoreRowError(f"{where}: 'rejection_probability' out of [0, 1]: {score!r}")
    return {"label": label, "rejection_probability": score}


def validate_rows(rows: list) -> list[dict]:
    """Validate in-memory score records against the input contract.

    Inputs: `rows` — parsed records. Output: normalized records. Raises
    [`ScoreRowError`] naming the first offending row index.
    """
    return [validate_row(row, f"row {index + 1}") for index, row in enumerate(rows)]


def load_scores(path: Path) -> list[dict]:
    """Load and validate labeled score records from JSONL.

    Inputs: `path` — JSONL where each line has `label` (rejection,
    not_rejection or ambiguous; ambiguous counts as negative for FP purposes)
    and `rejection_probability` in [0, 1]. Output: validated records. Raises
    [`ScoreRowError`] with the line number for malformed JSON, invalid rows or
    missing fields; nothing is silently dropped.
    """
    rows = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ScoreRowError(f"line {line_no}: malformed JSON: {error}") from error
        rows.append(validate_row(row, f"line {line_no}"))
    return rows


def is_positive(row: dict) -> bool:
    """Whether a validated row is in the positive (rejection) class.

    Inputs: `row` — validated record. Output: `bool` — true only for the
    declared `rejection` label (`ambiguous` is negative per documented policy).
    """
    return row["label"] == "rejection"


def counts_at(negatives: list[dict], positives: list[dict], threshold: float) -> tuple[int, int]:
    """Count FP/TP at one threshold.

    Inputs: `negatives` — labeled negative scores; `positives` — labeled
    positive scores; `threshold` — cutoff in [0, 1]. Output:
    `(false_positives, true_positives)` as ints.
    """
    fp = sum(1 for r in negatives if r["rejection_probability"] >= threshold)
    tp = sum(1 for r in positives if r["rejection_probability"] >= threshold)
    return fp, tp


def select_best(negatives: list[dict], positives: list[dict], target_fp: int) -> dict | None:
    """Sweep the observed decision boundaries; keep the FP-compliant optimum.

    Inputs: `negatives`/`positives` — validated labeled scores; `target_fp` —
    maximum acceptable observed false positives (nonnegative int; validated
    here, not only in the CLI). Output: the winning candidate dict
    `{threshold, true_positives, false_positives, recall}`, or `None` when no
    threshold meets the budget with at least one true positive (the explicit
    abstain-all outcome).

    Candidate thresholds are the distinct observed scores: under `score >=
    threshold` these enumerate every inducible decision set exactly, so the
    selection is the true recall optimum — a coarser grid can silently miss
    feasible optima on close scores. Deterministic policy: maximize
    true positives first, then minimize false positives, then take the highest
    threshold (the most conservative cutoff). Distinct observed-score
    candidates cannot tie on (tp, fp) — each boundary adds or removes whole
    rows — but the rule is stated explicitly so any future candidate scheme
    keeps a deterministic order. The reported threshold is the smallest
    observed score achieving the selected decision set (e.g. the straddling
    pair 0.5001/0.5002 yields threshold 0.5002 under `>=`, not an interpolated
    0.50015).
    """
    if isinstance(target_fp, bool) or not isinstance(target_fp, int):
        raise ValueError(f"target_fp must be an integer, got {type(target_fp).__name__}")
    if target_fp < 0:
        raise ValueError(f"target_fp must be >= 0, got {target_fp}")
    candidates = sorted(
        {r["rejection_probability"] for r in negatives} | {r["rejection_probability"] for r in positives}
    )
    best: dict | None = None
    for threshold in candidates:
        fp, tp = counts_at(negatives, positives, threshold)
        if fp > target_fp:
            continue
        recall = tp / len(positives) if positives else 0.0
        candidate = {
            "threshold": threshold,
            "true_positives": tp,
            "false_positives": fp,
            "recall": recall,
        }
        if best is None:
            best = candidate
            continue
        key = (candidate["true_positives"], -candidate["false_positives"], candidate["threshold"])
        best_key = (best["true_positives"], -best["false_positives"], best["threshold"])
        if key > best_key:
            best = candidate
    if best is not None and best["true_positives"] == 0:
        # A recall-zero threshold is never useful; report abstain-all instead.
        return None
    return best


def calibrate(rows: list, target_fp: int, input_identity: dict | None = None) -> dict:
    """Select the FP-compliant threshold with maximal recall; build the report.

    Inputs: `rows` — labeled scores (validated here against the input
    contract); `target_fp` — maximum acceptable observed false positives on
    the calibration set (nonnegative int); `input_identity` — optional
    `{path, sha256, rows}` of the source file. Output: report dict with
    status, threshold (null for abstain-all/insufficient-data), observed
    confusion counts recounted at the reported threshold, and the FP-rate
    upper bound (null with a reason when a required class is empty).
    """
    validated = validate_rows(rows)
    if isinstance(target_fp, bool) or not isinstance(target_fp, int):
        raise ValueError(f"target_fp must be an integer, got {type(target_fp).__name__}")
    if target_fp < 0:
        raise ValueError(f"target_fp must be >= 0, got {target_fp}")
    positives = [r for r in validated if is_positive(r)]
    negatives = [r for r in validated if not is_positive(r)]
    ambiguous = sum(1 for r in validated if r["label"] == "ambiguous")
    base = {
        "comparison": COMPARISON,
        "split_role": "calibration",
        "target_false_positives": target_fp,
        "positives": len(positives),
        "negatives": len(negatives),
        "ambiguous_in_negatives": ambiguous,
    }
    if input_identity:
        base["input"] = dict(input_identity)
    if not positives or not negatives:
        reasons = {}
        if not positives:
            reasons["recall"] = "no positive (rejection) rows"
        if not negatives:
            reasons["false_positive_rate_upper_95"] = "no negative rows"
        base.update(
            {
                "status": "insufficient_data",
                "threshold": None,
                "true_positives": None,
                "false_positives": None,
                "recall": None,
                "false_positive_rate_upper_95": None,
                "metric_reasons": reasons,
            }
        )
        return base
    best = select_best(negatives, positives, target_fp)
    if best is None:
        base.update(
            {
                "status": "abstain_all",
                "threshold": None,
                "true_positives": 0,
                "false_positives": 0,
                "recall": 0.0,
                "false_positive_rate_upper_95": wilson_upper_bound(0, len(negatives)),
            }
        )
        return base
    # Recount at the reported threshold so the counts provably match it.
    fp, tp = counts_at(negatives, positives, best["threshold"])
    assert (fp, tp) == (best["false_positives"], best["true_positives"])
    base.update(
        {
            "status": "ok",
            "threshold": best["threshold"],
            "true_positives": tp,
            "false_positives": fp,
            "recall": tp / len(positives),
            "false_positive_rate_upper_95": wilson_upper_bound(fp, len(negatives)),
        }
    )
    return base


def file_identity(path: Path) -> dict:
    """Content identity of a scores file for the report's input receipt.

    Inputs: `path` — the scores JSONL. Output: `{path, sha256, rows}` where
    `rows` counts non-empty lines before validation.
    """
    data = path.read_bytes()
    rows = sum(1 for line in data.splitlines() if line.strip())
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "rows": rows}


def main() -> int:
    """Validate labeled scores and print the calibration report.

    Inputs: argv (`--scores` JSONL, `--target-fp`, optional `--out`).
    Output: exit status 0 when a report is produced (any status), 2 when the
    input is empty or invalid (no report is produced for invalid input).
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scores", type=Path, required=True, help="JSONL of label + rejection_probability")
    parser.add_argument(
        "--target-fp",
        type=int,
        default=0,
        help="Maximum acceptable observed false positives (nonnegative integer)",
    )
    parser.add_argument("--out", type=Path, help="Optional report JSON output path")
    args = parser.parse_args()
    try:
        rows = load_scores(args.scores)
        if not rows:
            print("no score rows", file=sys.stderr)
            return 2
        report = calibrate(rows, args.target_fp, input_identity=file_identity(args.scores))
    except (ValueError, OSError) as error:
        print(f"invalid calibration input: {error}", file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
