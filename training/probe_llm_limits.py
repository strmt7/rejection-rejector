"""Probe the local LLM's capability ceiling on rejection detection.

Runs the product's exact classification contract (category, confidence,
evidence, explanation, language) against a stratified holdout subset under
multiple reasoning conditions, so the ceiling of the UN-tuned local model
is measured before any fine-tuning decision. Conditions vary the Ollama
`think` control and the generation budget (the documented levers:
`think` true/false per /api/show metadata; budget via `num_predict`).

Inputs:
    --model       Ollama model tag (default: qwen3.5:9b-q8_0)
    --holdout     holdout JSONL (default: training/data/sft_holdout_v2.jsonl)
    --per-class   rows sampled per class (default: 15 -> 60-row probe)
    --out         evidence report path (default: llm-limits-report.json)
    --conditions  comma list of condition ids (default: low,default,max)

Output: a JSON report with per-condition accuracy, per-class precision and
recall, fail-closed split (false acceptances vs safe misses), parse-failure
counts, latency and thinking-length statistics, plus per-row results. A
`<out>.progress.json` marker is updated after every row for live probing.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"

# Condition matrix: (id, think_value, num_predict, temperature).
# 'max' gives the model the largest documented answer budget at
# temperature 0 — the "reasoning as high as possible" arm.
CONDITIONS = {
    "low": (False, 1024, 0.0),
    "default": (None, 2048, 0.0),
    "max": (True, 8192, 0.0),
}


def load_stratified(path: Path, per_class: int) -> list[dict]:
    """Sample rows evenly across classes. Inputs: holdout path, per-class
    cap (deterministic: first N of each class in file order). Output: rows."""
    by_class: dict[str, list[dict]] = defaultdict(list)
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                by_class[row["meta"]["category"]].append(row)
    rows = []
    for cat in sorted(by_class):
        rows.extend(by_class[cat][:per_class])
    return rows


def call_ollama(model: str, system: str, user: str, think, num_predict: int,
                temperature: float, timeout_s: float = 300.0) -> dict:
    """One chat call. Inputs: model tag, prompt parts, think control
    (bool|None), budget, temperature. Output: raw response dict with
    thinking/content/duration fields."""
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {"num_predict": num_predict, "temperature": temperature,
                    "num_ctx": 32768},
    }
    if think is not None:
        body["think"] = think
    req = urllib.request.Request(
        OLLAMA_URL, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        return json.loads(resp.read())


def parse_answer(text: str) -> dict | None:
    """Extract the assistant JSON object. Inputs: raw content. Output: dict
    or None (counted as a parse failure)."""
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def write_progress(path: Path, record: dict) -> None:
    """Atomically write the live-probe marker. Inputs: path, record. Output: none."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    tmp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="qwen3.5:9b-q8_0")
    parser.add_argument("--holdout", type=Path, default=Path("training/data/sft_holdout_v2.jsonl"))
    parser.add_argument("--per-class", type=int, default=15)
    parser.add_argument("--out", type=Path, default=Path("llm-limits-report.json"))
    parser.add_argument("--conditions", default="low,default,max")
    args = parser.parse_args()

    rows = load_stratified(args.holdout, args.per_class)
    conds = [c.strip() for c in args.conditions.split(",") if c.strip() in CONDITIONS]
    print(f"probe: {len(rows)} rows x conditions {conds} on {args.model}", flush=True)

    progress_path = args.out.with_name(args.out.name + ".progress.json")
    report: dict = {"model": args.model, "rows": len(rows), "conditions": {}}
    began = time.time()
    for cond in conds:
        think, num_predict, temperature = CONDITIONS[cond]
        results, confusion = [], defaultdict(Counter)
        for row in rows:
            expected = json.loads(row["messages"][2]["content"])
            t0 = time.time()
            try:
                resp = call_ollama(
                    args.model, row["messages"][0]["content"], row["messages"][1]["content"],
                    think, num_predict, temperature,
                )
            except Exception as exc:  # transport failure = recorded, not fatal
                results.append({"id": row["meta"]["id"], "true": expected["category"],
                                "pred": "transport_failure", "error": repr(exc)[:200]})
                continue
            msg = resp.get("message", {})
            got = parse_answer(msg.get("content", ""))
            latency = time.time() - t0
            pred = got.get("category") if got else "parse_failure"
            confusion[expected["category"]][pred] += 1
            results.append({
                "id": row["meta"]["id"], "true": expected["category"], "pred": pred,
                "confidence": got.get("confidence") if got else None,
                "latency_s": round(latency, 2),
                "thinking_chars": len(msg.get("thinking") or ""),
            })
            write_progress(progress_path, {
                "job": "probe_llm_limits", "condition": cond,
                "done": len(results), "total": len(rows),
                "elapsed_seconds": round(time.time() - began, 1), "status": "running",
            })
        total = len(results)
        correct = sum(1 for r in results if r["pred"] == r["true"])
        false_accept = sum(1 for r in results if r["true"] != "rejection" and r["pred"] == "rejection")
        missed = sum(1 for r in results if r["true"] == "rejection" and r["pred"] != "rejection")
        parse_fail = sum(1 for r in results if r["pred"] == "parse_failure")
        lat = [r["latency_s"] for r in results if "latency_s" in r]
        think_chars = [r["thinking_chars"] for r in results if "thinking_chars" in r]
        report["conditions"][cond] = {
            "accuracy": round(correct / total, 4) if total else None,
            "confusion": {k: dict(v) for k, v in confusion.items()},
            "fail_closed": {"false_acceptances": false_accept, "safe_misses": missed},
            "parse_failures": parse_fail,
            "latency_s_mean": round(sum(lat) / len(lat), 2) if lat else None,
            "thinking_chars_mean": round(sum(think_chars) / len(think_chars)) if think_chars else 0,
            "results": results,
        }
        print(f"condition {cond}: accuracy={report['conditions'][cond]['accuracy']} "
              f"false_accept={false_accept} parse_fail={parse_fail}", flush=True)

    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_progress(progress_path, {"job": "probe_llm_limits", "status": "complete",
                                   "elapsed_seconds": round(time.time() - began, 1)})
    summary = {c: {k: v for k, v in d.items() if k != "results"}
               for c, d in report["conditions"].items()}
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
