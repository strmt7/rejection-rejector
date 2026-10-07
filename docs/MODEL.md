# Model selection and 16 GiB qualification

Default candidate for new workspaces: **`qwen3.5:9b-q8_0`** in Ollama, 8,192 context, one request/model at a time.

## Why this provisional default

This selection is intentionally **task-specific**, not a generic leaderboard choice. For Rejection Rejector the useful proxies are strict instruction following, multilingual understanding, structured output, text classification, grounded extraction and concise professional writing—not coding or math scores by themselves.

As of 2026-09-27:

- **`qwen3.5:9b-q8_0`** is about **11 GB** in Ollama with a 256K model context. Qwen's published 9B results include IFEval 91.5, MultiChallenge 54.5, MMMLU 81.2 and MMLU-ProX 76.3. Those are unusually relevant to this app's instruction-following and multilingual classification workload, and Q8 leaves materially more VRAM headroom than 13–14 GB alternatives.
- **`granite4.2:8b-q8_0`** is about **9.3 GB** and is a particularly relevant recent challenger: IBM explicitly lists text classification, extraction, multilingual business dialogue, thinking and structured JSON among Granite 4.2's supported capabilities. Its published 8B IFBench score is 79.33.
- **`gemma4:12b-it-q8_0`** is about **13 GB**. Gemma 4 12B is a newer dense model with strong broad reasoning and multilingual results and native system-prompt support; it has less VRAM headroom, so it must prove both task quality and full residency locally.
- **`ministral-3:14b`** is about **9.1 GB** and explicitly targets multilingual use, system-prompt adherence and JSON output. It remains a useful challenger despite being older than Granite 4.2/Gemma 4.
- **`qwen3.5:9b`** (~6.6 GB Q4) remains the lower-VRAM fallback.
- **`gpt-oss:20b`** (~14 GB MXFP4) remains a reasoning baseline, but its training mix was mostly English and its memory headroom is tight for a 16 GiB card.

Very new models are not automatically added merely because of release date. For example, Qwen3.8-Flash-Next (~105 GB local), NVIDIA Nemotron 3.5 Lightning (~25 GB) and Muse Glimmer (~18 GB) fail the fully-resident 16 GiB constraint before task quality is considered.

The app therefore treats Qwen3.5 9B Q8 as a **provisional default only**. Use **Compare installed candidates** or:

```powershell
.\rr.exe compare-models --out .\model-bakeoff.json
```

The bake-off evaluates only candidates that you explicitly installed. It runs the complete classification → draft → verification pipeline on **72** stratified synthetic recruiting fixtures. Cases are tagged for multilingual mail, ATS automation, interviews, offers, assessments, recruiter corrections, quoted history, prompt injection, ambiguity, pending-status wording, talent pools, role closure, application-action requests and surveys. Reports include per-tag completion/correctness/false-positive/unsafe-draft counts instead of hiding risky errors inside one aggregate score.

A recommendation is emitted only when a model completes every case, has **zero rejection false positives**, produces **zero drafts for non-rejections**, completes every critical hard-negative case, has **zero critical hard-negative rejection false positives or drafts**, reaches at least **90% rejection recall**, **90% deterministic rejection-evidence recall**, **90% verified rejection-pipeline success**, at least **85% multilingual rejection recall and verified-pipeline success**, and passes the full-GPU-residency gate. Critical hard negatives include interviews, offers, recruiter corrections, quoted-history cases, prompt-injection cases and ambiguous mixed outcomes.

The task score still weights global non-rejection false-positive avoidance most heavily, but recommendation eligibility now adds explicit hard gates for the critical-negative cohort. This prevents a superficially high average from masking a catastrophic reply to an interview, offer, corrected rejection, quoted historical decision or injected message.

Explicit tags are used for presets. The app pins the exact installed digest after qualification because registry tags can change. It requires **Ollama 0.35.0 or newer**. The production generative pipeline still uses local `/api/chat`; 0.35 additionally provides `/v1/systemone`, which the repository uses only in a separate non-sending typed decision-model evaluation lane until task-specific evidence justifies any production promotion. Local transport timeout/connect failures trigger one explicit unload-and-retry recovery; semantic/model/policy failures are never retried until they pass.

The app uses local `/api/chat`, thinking, schema-constrained JSON, deterministic seeding and low temperature. Email text is untrusted data. Input budgets and incomplete generations fail closed for Automatic mode.

## Typed decision-model R&D lane (Ollama 0.35+)

Ollama 0.35 introduced the local `/v1/systemone` typed-decision API. Rejection Rejector keeps this capability **outside the production authorization path** until it earns task-specific evidence.

The first candidate is **`nimble:9b-q8_0`**, a roughly 9.5 GB Q8 decision model from Bespoke Labs fine-tuned from Qwen3.5-9B. It returns a closed choice plus per-choice scores rather than free-form prose. **`tev1:4b`** is retained as a smaller experimental baseline. This architecture is attractive for the first-stage rejection/opportunity/other/uncertain decision because constrained outputs and contrastive decision training map directly to the problem, but generic decision benchmarks do not prove multilingual recruiting-email safety.

Evaluate an explicitly installed decision model with:

```powershell
.\rr.exe evaluate-decision --model nimble:9b-q8_0 --out .\decision-evaluation.json
```

The evaluator uses the same 72 synthetic recruiting fixtures, sends only de-quoted synthetic subject/current-message data to the local loopback endpoint, and records no fixture text in its result rows. Recommendation eligibility requires every case to complete, a valid four-category probability contract, **zero rejection false positives**, **zero critical-negative rejection false positives**, at least **90% rejection recall**, and full Ollama-reported GPU residency after the suite.

For model-to-model R&D, run:

```powershell
.\rr.exe compare-decision-models --out .\decision-model-bakeoff.json
```

The comparison evaluates only explicitly installed candidates and ranks only models that already pass the hard safety eligibility gates. Ranking is lexicographic: higher rejection recall, then lower rejection Brier score, lower maximum rejection probability on critical-negative cases, and lower latency. Reports also include multiclass Brier score and mean/max critical-negative rejection scores. These are proper-scoring diagnostics for this corpus, **not calibrated real-world probabilities** and not promotion authority.

This is an R&D recommendation only. It does not write `task_qualification`, change the configured production classifier, enable sending, connect Gmail, or create a delivery reservation. Promotion into the Automatic pipeline requires a separate architecture change, target-GPU profiling and independently labelled private multilingual mailbox acceptance.

Current upstream references checked 2026-10-01:
- https://github.com/ollama/ollama/releases/tag/v0.35.0
- https://ollama.com/library/nimble
- https://ollama.com/library/nimble:9b-q8_0
- https://ollama.com/library/tev1

## Independent enterprise verifier

High-assurance Automatic mode can use a second local model only for the verification pass. The default candidate is **`granite4.2:8b-q8_0`**. Ollama lists this Q8 build at about **9.3 GB** with 128K context, and IBM positions Granite 4.2 for enterprise text classification, extraction, multilingual dialogue and structured JSON. The primary and verifier run sequentially, never intentionally resident together.

Smaller **`granite4.2:3b-q8_0`** (~3.9 GB) and **`qwen3.5:4b`** (~3.4 GB default quantization) remain lower-latency verifier candidates. Every primary/verifier pair must still pass the repository's task-specific evaluation on the target machine.

Independent verification reduces correlated model error but does not make model failures mathematically independent or replace deterministic Rust gates. If enabled, verifier failure blocks unattended action rather than falling back to the primary model.

Sources checked 2026-09-29:
- https://ollama.com/library/granite4.2
- https://ollama.com/library/granite4.2/tags
- https://ollama.com/library/qwen3.5:4b

## Qualification

**Qualify & pin** is an end-to-end application test, not a download check. It:

1. requires installed local model metadata and rejects Ollama remote/cloud markers;
2. validates the selected model name and inspected digest;
3. performs a synthetic warm-up before private inference;
4. runs a synthetic rejection through classification;
5. requires a valid structured, concise assertive draft with the configured signature;
6. runs the separate same-model verification pass and requires it to pass;
7. inspects `/api/ps` and requires exactly one matching loaded model, positive size, `size_vram >= size`, reported VRAM at or below the app's **14 GiB** budget, and at least the requested context;
8. only then stores the digest pin.

The 14 GiB application budget deliberately leaves nominal room on a 16 GiB card. A model tag/digest or context/origin change invalidates the pin and disarms delivery.

This does **not** identify the physical GPU, prove single-device allocation on every backend, measure transient whole-device peaks, include every display workload, or stress-test every near-capacity prompt. It may reject workable configurations and is not hardware certification. Existing Ollama servers are not silently reconfigured.

Before Automatic, run `rr doctor`, evaluate the configured model, and preferably compare the installed challengers with `rr compare-models --out model-bakeoff.json`. Independently label private messages including real rejections, offers, invitations, quoted threads and suspicious instructions. Measure false rejections, precision/recall, unsupported claims and unsafe responses separately. Record digest, prompt version, context, runtime/backend/driver, latency and whole-device peaks. Re-evaluate after changes.

Bundled synthetic cases are regression/smoke tests, not representative mailbox accuracy. Same-model verification is correlated, and model confidence scores are not calibrated probabilities.

Sources checked 2026-09-27:
- https://ollama.com/library/qwen3.5/tags
- https://huggingface.co/Qwen/Qwen3.5-9B
- https://ollama.com/library/granite4.2
- https://huggingface.co/ibm-granite/granite-4.2-8b
- https://ollama.com/library/gemma4/tags
- https://ollama.com/library/ministral-3
- https://ollama.com/library/gpt-oss
- https://openai.com/index/gpt-oss-model-card/
- https://github.com/ollama/ollama/releases
