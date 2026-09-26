# Model selection and 16 GiB qualification

Default candidate for new workspaces: **`qwen3.5:9b`** in Ollama, 8,192 context, one request/model at a time.

## Why this default

The selection is use-case-specific rather than a generic leaderboard claim. On 2026-09-26, Ollama lists Qwen3.5 9B at about **6.6 GB** with thinking support and a 256K model context. Qwen's published model-card comparison reports Qwen3.5 9B ahead of gpt-oss-20B on several measures especially relevant here, including IFEval, MultiChallenge, MMMLU, MMLU-ProX, NOVA-63 and MAXIFE. Those public benchmark results do not prove superiority on this application's mailbox task, so the app still requires local qualification and offers a synthetic task-specific evaluation.

Two useful alternatives remain selectable in the GUI:
- **`gpt-oss:20b`** — about **14 GB** in Ollama, 128K context. OpenAI describes it as delivering results similar to o3-mini on common benchmarks and requiring about 16 GB of memory. It is a strong reasoning candidate but leaves much less headroom on a 16 GiB GPU.
- **`gemma4:12b-it-qat`** — about **7.2 GB** in Ollama and a conservative memory choice retained for comparison/compatibility.

Explicit tags are used for defaults/presets. The app pins the exact installed digest after qualification because registry tags can change.

The app uses local `/api/chat`, thinking, structured JSON, a fixed seed and low temperature. Email text is treated as untrusted data. Byte budgets and completion checks fail closed for automatic delivery.

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

Before Automatic, run `rr doctor` and the synthetic evaluation from the Local AI tab (or `rr evaluate --out model-evaluation.json`). Independently label private messages including real rejections, offers, invitations, quoted threads and suspicious instructions. Measure false rejections, precision/recall, unsupported claims and unsafe responses separately. Record digest, prompt version, context, runtime/backend/driver, latency and whole-device peaks. Re-evaluate after changes.

Bundled synthetic cases are regression/smoke tests, not representative mailbox accuracy. Same-model verification is correlated, and model confidence scores are not calibrated probabilities.

Sources checked 2026-09-26:
- https://ollama.com/library/qwen3.5
- https://huggingface.co/Qwen/Qwen3.5-9B
- https://ollama.com/library/gpt-oss:20b
- https://openai.com/index/introducing-gpt-oss/
- https://registry.ollama.com/library/gemma4/tags
- https://github.com/ollama/ollama/blob/main/docs/context-length.mdx
