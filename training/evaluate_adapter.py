"""Holdout evaluation for a trained rejection-detection LoRA adapter.

Loads the base model with the adapter (4-bit, GPU when available) and runs
every holdout row through the exact training prompt format, parsing the
assistant JSON answer. Reports accuracy, per-class confusion, confidence
calibration buckets and the fail-closed analysis (which errors would have
authorized a send vs which correctly held).

Inputs:
    --base-model  base model tag (default: XiaomiMiMo/MiMo-V2.6-Distill-Qwen-9B)
    --adapter     path to the LoRA adapter directory
    --holdout     holdout JSONL (default: training/data/sft_holdout.jsonl)
    --out         output report path (default: evaluation-report.json)
    --limit       optional row cap for smoke runs
    --device      cuda|cpu (default: cuda when available)

Output: a JSON report with counts, per-class precision/recall, confusion
pairs, fail-closed analysis, a per-row results array and an `identity` block
(dataset/adapter digests, requested/resolved model identity, split role and
the deterministic generation policy). A progress marker
(`<out>.progress.json`) is written after every row so live probing works.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections import Counter, defaultdict
from pathlib import Path


def sha256_file(path: Path) -> str:
    """Digest one file. Inputs: `path`. Output: lowercase hex SHA-256."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def path_identity(path: Path) -> dict:
    """Content identity for a file or directory of files.

    Inputs: `path` — a file, or a directory (e.g. a LoRA adapter). Output:
    `{path, kind, sha256}` where a directory digest covers the sorted
    per-file names and contents, so any changed member changes the digest.
    """
    if path.is_dir():
        digest = hashlib.sha256()
        for member in sorted(p for p in path.rglob("*") if p.is_file()):
            digest.update(member.relative_to(path).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(member.read_bytes())
            digest.update(b"\0")
        return {"path": str(path), "kind": "directory", "sha256": digest.hexdigest()}
    return {"path": str(path), "kind": "file", "sha256": sha256_file(path)}


def count_rows(path: Path) -> int:
    """Count non-empty JSONL rows. Inputs: `path`. Output: `int`."""
    with path.open(encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


# Deterministic generation policy for holdout scoring (greedy decoding is
# seed-independent; recorded in the report as the sampling identity).
GENERATION = {"do_sample": False, "max_new_tokens": 96}


def load_rows(path: Path, limit: int | None) -> list[dict]:
    """Load holdout rows. Inputs: path, optional limit. Output: row list."""
    rows = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
            if limit and len(rows) >= limit:
                break
    return rows


def build_prompt(row: dict, tokenizer) -> str:
    """Render the training prompt for one row. Inputs: row, tokenizer.
    Output: the full chat-rendered prompt (same format as training).
    """
    messages = [
        {"role": "system", "content": row["messages"][0]["content"]},
        {"role": "user", "content": row["messages"][1]["content"]},
    ]
    return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)


def parse_answer(text: str) -> dict | None:
    """Extract the assistant JSON object from generated text.
    Inputs: raw model output. Output: parsed dict or None on failure.
    """
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def write_progress(path: Path, record: dict) -> None:
    """Atomically write the live-probe progress marker. Inputs: path, record.
    Output: none (best-effort).
    """
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    tmp.replace(path)


def generate_answer(model, tokenizer, prompt: str) -> str:
    """Generate and decode one answer. Inputs: loaded model, tokenizer,
    rendered prompt. Output: the decoded generated text.
    """
    import torch

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=GENERATION["max_new_tokens"],
            do_sample=GENERATION["do_sample"],
            pad_token_id=tokenizer.eos_token_id,
        )
    return tokenizer.decode(out[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True)


def per_class_stats(confusion: dict) -> dict:
    """Precision/recall per class from the confusion tally. Inputs:
    `confusion` — true->pred->count tallies. Output: per-class report dict.
    """
    per_class = {}
    for cat in sorted(confusion):
        tp = confusion[cat][cat]
        pred_total = sum(confusion[c][cat] for c in confusion)
        true_total = sum(confusion[cat].values())
        per_class[cat] = {
            "support": true_total,
            "recall": round(tp / true_total, 4) if true_total else None,
            "precision": round(tp / pred_total, 4) if pred_total else None,
        }
    return per_class


def fail_closed_split(results: list[dict]) -> dict[str, int]:
    """Count the dangerous vs safe error classes. Inputs: result records.
    Output: the fail-closed split for the report.
    """
    # Fail-closed analysis: predicted 'rejection' on a non-rejection is the
    # dangerous error class (could authorize a reply); the reverse is a miss.
    false_rejection = sum(1 for r in results if r["true"] != "rejection" and r["pred"] == "rejection")
    missed_rejection = sum(1 for r in results if r["true"] == "rejection" and r["pred"] != "rejection")
    return {
        "false_rejection_would_authorize": false_rejection,
        "missed_rejection_fails_closed": missed_rejection,
    }


def main() -> int:
    """Evaluate a trained adapter on the holdout set.

    Inputs: argv (base model, adapter, holdout, output path, limit,
    device). Output: exit status 0; writes the evaluation report and the
    `<out>.progress.json` marker.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-model", default="XiaomiMiMo/MiMo-V2.6-Distill-Qwen-9B")
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--holdout", type=Path, default=Path("training/data/sft_holdout.jsonl"))
    parser.add_argument("--out", type=Path, default=Path("evaluation-report.json"))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--device", default="cuda")
    args = parser.parse_args()

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    device = args.device if args.device != "cuda" or torch.cuda.is_available() else "cpu"
    rows = load_rows(args.holdout, args.limit)
    print(f"evaluating {len(rows)} holdout rows on {device}", flush=True)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(args.base_model, quantization_config=quant, device_map=device)
    model = PeftModel.from_pretrained(model, str(args.adapter))
    model.eval()
    try:
        resolved_revision = getattr(model.get_base_model().config, "_commit_hash", None)
    except Exception:  # noqa: BLE001 - provenance is best-effort, never fatal
        resolved_revision = None

    results = []
    confusion: dict[str, Counter] = defaultdict(Counter)
    progress_path = args.out.with_name(args.out.name + ".progress.json")
    began = time.time()
    for i, row in enumerate(rows):
        expected = json.loads(row["messages"][2]["content"])
        prompt = build_prompt(row, tokenizer)
        generated = generate_answer(model, tokenizer, prompt)
        got = parse_answer(generated)
        true_cat = expected["category"]
        pred_cat = got.get("category") if got else "parse_failure"
        confusion[true_cat][pred_cat] += 1
        results.append(
            {
                "id": row["meta"]["id"],
                "true": true_cat,
                "pred": pred_cat,
                "confidence": got.get("confidence") if got else None,
                "raw": generated[:400],
            }
        )
        write_progress(
            progress_path,
            {
                "job": "evaluate_adapter",
                "done": i + 1,
                "total": len(rows),
                "elapsed_seconds": time.time() - began,
                "status": "running",
            },
        )
        if (i + 1) % 25 == 0:
            print(f"{i + 1}/{len(rows)}", flush=True)

    total = len(results)
    correct = sum(1 for r in results if r["pred"] == r["true"])
    report = {
        "base_model": args.base_model,
        "adapter": str(args.adapter),
        "rows": total,
        "accuracy": round(correct / total, 4) if total else None,
        "per_class": per_class_stats(confusion),
        "confusion": {k: dict(v) for k, v in confusion.items()},
        "fail_closed": fail_closed_split(results),
        "results": results,
        "torch": torch.__version__,
        "device": device,
        "identity": {
            "split_role": "holdout_evaluation",
            "holdout": {
                **path_identity(args.holdout),
                "rows_available": count_rows(args.holdout),
                "rows_evaluated": total,
                "limit": args.limit,
            },
            "adapter": path_identity(args.adapter),
            "base_model_requested": args.base_model,
            "base_model_resolved_revision": resolved_revision,
            "base_model_resolved_note": (
                None
                if resolved_revision
                else "provider-resolved revision unavailable from the loaded snapshot; identity stays unknown"
            ),
            "sampling": dict(GENERATION),
            "sampling_note": "greedy decoding is seed-independent; scores are not calibrated probabilities",
        },
    }
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_progress(progress_path, {"job": "evaluate_adapter", "status": "complete", "done": total, "total": total})
    print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
