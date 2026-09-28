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

A recommendation is emitted only when a model completes every case, has **zero rejection false positives**, produces **zero drafts for non-rejections**, completes every critical hard-negative case, has **zero critical hard-negative rejection false positives or drafts**, reaches at least **90% rejection recall** and **90% verified rejection-pipeline success**, and passes the full-GPU-residency gate. Critical hard negatives include interviews, offers, recruiter corrections, quoted-history cases, prompt-injection cases and ambiguous mixed outcomes.

The task score still weights global non-rejection false-positive avoidance most heavily, but recommendation eligibility now adds explicit hard gates for the critical-negative cohort. This prevents a superficially high average from masking a catastrophic reply to an interview, offer, corrected rejection, quoted historical decision or injected message.

Explicit tags are used for presets. The app pins the exact installed digest after qualification because registry tags can change. It also requires **Ollama 0.34.4 or newer**. This release improves structured outputs for thinking models, which is directly relevant to the schema-constrained classification/drafting pipeline. Local transport timeout/connect failures trigger one explicit unload-and-retry recovery; semantic/model/policy failures are never retried until they pass.

The app uses local `/api/chat`, thinking, schema-constrained JSON, deterministic seeding and low temperature. Email text is untrusted data. Input budgets and incomplete generations fail closed for Automatic mode.

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
