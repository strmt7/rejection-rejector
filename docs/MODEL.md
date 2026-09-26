# Model selection and 16 GiB qualification

Default candidate: **`gemma4:12b-it-qat`** in Ollama, 8,192 context, one request/model at a time. The Ollama catalog checked on 2026-09-26 lists this QAT tag at about **7.2 GB**; the current Gemma 4 12B tag is about 7.6 GB. Package size is not VRAM, so the app does not approve a model from download size alone.

The choice is intentionally conservative rather than a claim that one public benchmark proves a universally smartest model. Current alternatives examined include Qwen3.5 9B at about 6.6 GB and DeepSeek-R1-Distill-Qwen 14B at about 9.0 GB. Larger current candidates exceed the app's headroom rule before runtime overhead: Qwen3.5 27B is about 17 GB and Gemma 4 26B A4B QAT is about 16 GB. The application therefore keeps Gemma 4 12B QAT as the default strong workstation-class candidate while allowing an advanced user to choose another local Ollama model and requiring that exact model to pass the same qualification gates.

This also matches the default tag used by the owner's VulnerabilityScreener profiling work. No code is copied from that project; its vendor-neutral use of Ollama runtime counters informed this app's measurement approach.

The app uses local `/api/chat`, thinking, structured JSON, a fixed seed and low temperature. Email text is treated as untrusted data. Byte budgets and completion checks fail closed for automatic delivery.

## Qualification

**Qualify & pin** is an end-to-end application test, not a download check. It:

1. requires an installed local GGUF model and rejects Ollama remote/cloud markers;
2. validates the selected model name and inspected digest;
3. runs a synthetic rejection through classification;
4. requires a valid structured assertive draft;
5. runs the separate same-model verification pass and requires it to pass;
6. inspects `/api/ps` and requires exactly one matching loaded model, positive size, `size_vram >= size`, reported VRAM at or below the app's **14 GiB** budget, and at least the requested context;
7. only then stores the digest pin.

The 14 GiB application budget deliberately leaves nominal room on a 16 GiB card. A model tag change invalidates the pin. Changing model, context, or Ollama origin also invalidates qualification.

This does **not** identify the physical GPU, prove single-device allocation on every backend, measure transient whole-device peaks, include every display workload, or stress-test every near-capacity prompt. It may reject workable configurations and is not hardware certification. Existing Ollama servers are not silently reconfigured.

Before Automatic, run `rr doctor` and, for a representative model check, `rr evaluate --out model-evaluation.json` with the GUI closed. Independently label private messages including real rejections, offers, invitations, quoted threads and suspicious instructions. Measure false rejections, precision/recall, unsupported claims and unsafe responses separately. Record digest, prompt version, context, runtime/backend/driver, latency and whole-device peaks. Re-evaluate after changes.

Bundled synthetic cases are regression/smoke tests, not representative mailbox accuracy. Same-model verification is correlated, and model confidence scores are not calibrated probabilities.

Sources:
- https://ollama.com/library/gemma4:12b-it-qat
- https://ollama.com/library/gemma4/tags
- https://ollama.com/library/qwen3.5
- https://ollama.com/library/deepseek-r1:14b
- https://docs.ollama.com/api/chat
- https://docs.ollama.com/api/ps
- https://docs.ollama.com/api/pull
- https://docs.ollama.com/faq
- https://github.com/strmt7/VulnerabilityScreener/blob/main/scripts/profile_vram.py
