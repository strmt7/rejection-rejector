# Local-LLM capability limits — measured verdict (2026-10-14)

Method: `training/probe_llm_limits.py` on a stratified 60-row slice of the
v2 adversarial holdout (15 per class: rejection / opportunity / other /
uncertain), under the product's verbatim classification prompt and its
schema-constrained output (`src/ollama.rs`), temperature 0.

| condition | accuracy | false acceptances | safe misses | parse fails | latency mean |
|---|---|---|---|---|---|
| low (thinking off, 1536 budget) | 65.0% | 8 | — | 0 | 0.8 s |
| default (model-default thinking, 8192) | 63.3% | 6 | 1 | 3 | 85.3 s |
| max (explicit `think: true`, 8192) | 63.3% | 6 | 1 | 3 | 79.9 s |

Findings (each verifiable in `projects/rr/evidence/llm-limits-report.json`):

1. Reasoning effort does not raise the ceiling. Default and max are
   identical in every measured respect (same accuracy, same confusion,
   same 16.6k mean thinking chars): `qwen3.5:9b-q8_0` already thinks by
   default and this tag exposes no higher level (`/api/show`:
   `values: [false, true]`). Thinking costs ~100x latency (0.8 s -> 85 s)
   for zero accuracy gain on this task.
2. The fail-closed class is the weakest: 14 of 15 `uncertain` rows were
   misclassified (11 -> other, 3 -> rejection), and each run produced 6
   false acceptances (non-rejections classified as rejection) — the
   safety-critical error class the product's deterministic gates must and
   do hold, but which the classifier itself must learn to avoid.
3. Budget truncation persists even at 8192 tokens (3/60 runs ended
   `done_reason: length`), matching the product's own measurement that
   think-enabled runs spend ~6.5k tokens reasoning before any schema JSON.
4. Failure concentration: `uncertain` -> `other` is the single largest
   confusion pair (11/22 errors). Surface-vocabulary cues do not transfer;
   the model needs examples of the ambiguous class itself.

Conclusion: max reasoning alone is NOT sufficient for generic scenarios.
Adaptation (fine-tuning on diverse generic scenarios with adversarial
hard negatives and explicit fail-closed ambiguous cases — exactly the v2
corpus design) is necessary. The product's deterministic safety gates
remain the enforcement layer regardless.

Probe conditions verified against official sources before use: Ollama
thinking API (`think` field semantics, `/api/show` metadata) and the
product's own measured budgets (`src/ollama.rs structured_predict`).
