# Model selection and 16 GiB qualification

Initial candidate: **gemma4:12b-it-qat** in Ollama, 8,192 context, one request/model at a time. The catalog checked on 2026-09-26 describes an approximately 11.9B Q4_0 model and 7.2 GB package. Download size is not VRAM. The app pins the digest after qualification because tags can change.

This matches the default tag in the owner's VulnerabilityScreener profiling script and is a practical strong candidate, **not an empirically proven smartest model** for this mailbox/GPU. No comparative hardware/mailbox evaluation was performed during implementation. No code was copied from the scanner; its vendor-neutral Ollama-counter approach informed the checks.

The app uses local /api/chat, thinking, structured JSON, fixed seed and low temperature. These are application heuristics, not a reproduction of publisher benchmark sampling. Byte budgets and completion checks fail closed for automatic delivery.

## Qualification

Require installed GGUF metadata and no remote-model markers. Run a synthetic rejection classification. Inspect /api/ps: exactly one loaded model, matching name/digest, positive size, size_vram >= size, VRAM <=14 GiB, context >= requested. This leaves nominal room on a 16 GiB card.

This does **not** identify the physical GPU, prove single-device allocation, measure transient whole-device peaks, include every display workload or stress-test near-capacity prompts. It may reject working configurations and is not a hardware certification. Existing Ollama servers are not silently reconfigured.

Before Automatic, verify backend/driver support, actual single-device residency and representative near-limit input. Run `rr evaluate --out model-evaluation.json` with the GUI closed. Independently label private messages including genuine rejections, offers, invitations, quoted threads and suspicious instructions. Measure false rejections, precision/recall, unsupported claims and unsafe responses separately. Record digest, prompt version, context, runtime/backend/driver, latency and whole-device peaks. Re-evaluate after changes.

The 12 bundled synthetic cases are regression smoke tests, not representative accuracy. Same-model verification is correlated, and model scores are not calibrated probabilities.

Sources:
- https://ollama.com/library/gemma4:12b-it-qat
- https://docs.ollama.com/api/chat
- https://docs.ollama.com/api/ps
- https://docs.ollama.com/api/pull
- https://docs.ollama.com/faq
- https://github.com/strmt7/VulnerabilityScreener/blob/main/scripts/profile_vram.py
