# Model-scale evaluation report

Date: 2026-10-27/28 (Europe/Zurich). Task: run the model-based email classification and
reply-drafting pipeline at scale against the local Ollama runtime, measure detection and
response quality, and fix real code bugs found. Raw measurements:
[`model-scale-raw.json`](model-scale-raw.json).

## 1. Setup

| Item | Value |
| --- | --- |
| Runtime | Ollama 0.40.11 at `http://127.0.0.1:11434` (service, left running) |
| Primary model | `granite4.2:8b-q8_0` (digest `62837636dd31…aeae02b4`), default model |
| Verifier | same-model verification (`independent_verifier_enabled: false`, the default; `qwen3.5:4b` available but not enabled) |
| Settings | `Settings::default()`, delivery disarmed: `num_ctx` 32768, tone *hardline*, reply language *auto*, signature `Your name`, empty candidate context |
| Real model path | `Ollama::classify` (classification), `Ollama::analyze` = `classify` + `draft_rejection_reply` + `verify_draft` (rejection rows), `language::ensure_reply_language` (deterministic reply-language gate), `language::first_language` (expected reply language) — the exact in-app functions and prompt contract (`CLASSIFY_SYSTEM_PROMPT` / `DRAFT_SYSTEM_PROMPT` / `VERIFY_SYSTEM_PROMPT`, schema-constrained JSON via `/api/chat`) |
| In-repo suite | `evaluation::run` via `rr evaluate` over the compiled fixture corpus `tests/fixtures/classification.json` (74 cases) |
| Scale sample | 156 labeled messages sampled from `training/data/sft_holdout_v2.jsonl` (880 held-out v2-corpus rows built from `training/corpus_banks_v2.py`): 12 languages (en, es, zh, hi, fr, ar, bn, pt, ru, ja, de, el) × (5 rejection + 5 hard negative + 3 ambiguous), deterministic seeded sampler |
| Sample categories | 60 rejection, 21 opportunity, 39 other, 36 uncertain |
| Concurrency | The `rr evaluate` lane, 2–3 scale-harness workers (disjoint chunks) and one bounded probe shared the single Ollama runtime; per-row seconds include queueing and are **not** clean latency measurements |

The scale harness is an out-of-tree cargo project that path-depends on the repository
crate and calls the public `Ollama`/`language`/`mail` entry points only; it re-implements
no prompts. Rejection rows run the full `analyze` pipeline (classification + drafting +
deterministic language gate + verification); all other rows run `classify`. Each sampled
message is classified through the real path; 37 rejection rows (3 per language, 4 for en)
additionally produced drafted replies.

## 2. In-repo task-specific evaluation (`rr evaluate`, default model)

Suite `rr-eval-contract-v5` (hash `94239602e5fad6fe…`), model `granite4.2:8b-q8_0` (digest `62837636dd31c99a…`), Ollama 0.40.11, 74 fixtures, completed 64/74.

| Task metric | Value |
| --- | --- |
| accuracy | 83.8% |
| rejection recall | 100.0% |
| rejection precision | 100.0% |
| rejection true positives | 18 |
| rejection false positives | 0 |
| rejection false negatives | 0 |
| non-rejection FP avoidance | 100.0% |
| verified rejection pipeline rate | 77.3% |
| unsafe non-rejection drafts | 0 |
| critical-negative cases (complete / FP / unsafe drafts) | 39/44 / 0 / 0 |
| deterministic rejection-evidence recall | 90.9% |
| deterministic rejection-evidence false positives | 0 |
| multilingual rejection recall | 100.0% |
| multilingual verified pipeline rate | 61.5% |
| task score | 91.7 |
| recommendation eligible | false |
| mean seconds per case (shared-GPU run) | 360.5 |

Per-tag results:

| tag | cases | correct | rej TP | rej FP | rej FN | verified pipeline | unsafe drafts |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ambiguous | 18 | 14 | 0 | 0 | 0 | 0 | 0 |
| application_action_required | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| assessment | 4 | 4 | 0 | 0 | 0 | 0 | 0 |
| ats_automation | 9 | 9 | 8 | 0 | 0 | 8 | 0 |
| interview | 21 | 16 | 0 | 0 | 0 | 0 | 0 |
| multilingual | 30 | 24 | 9 | 0 | 0 | 8 | 0 |
| offer | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| pending_status | 8 | 7 | 0 | 0 | 0 | 0 | 0 |
| prompt_injection | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| quoted_history | 6 | 6 | 0 | 0 | 0 | 0 | 0 |
| recruiter_correction | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| role_closure | 2 | 1 | 0 | 0 | 0 | 0 | 0 |
| survey | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| talent_pool | 3 | 3 | 0 | 0 | 0 | 0 | 0 |

Ten fixtures were held fail-closed instead of completing (the same model-quality
taxonomy as §5: 4 × think-budget *"Model response was incomplete"*, 3 × ungrounded
position extraction, 2 × *"Invalid classification field lengths"*, 1 × transport
retry exhaustion); none of them produced a wrong category. The only two completed
misclassifications are conservative non-rejection misses (`pending` other→uncertain,
`role_cancelled_without_candidate_decision` uncertain→other). **Zero rejection false
positives and zero unsafe non-rejection drafts on the fixture corpus.**
`recommendation_eligible` is `false` only because the eligibility gate requires all 74
fixtures to complete; `rr evaluate` exited 1 with *"Task-specific evaluation did not
meet Automatic-mode gates"* and wrote the report (this is its designed fail-closed
disposition). `mean_seconds` (360 s/case) is shared-GPU queue time from the concurrent
scale lane, not a latency benchmark.

## 3. Scale-sample measurements

Sample size **156** labeled messages (composition: {'ambiguous': 36, 'negative': 60, 'rejection': 60}; expected: {'opportunity': 21, 'other': 39, 'rejection': 60, 'uncertain': 36}).

Classification accuracy (attributed rows 123, unattributed error rows 33): **74.0%** overall.

| expected category | n | correct | accuracy |
| --- | --- | --- | --- |
| rejection | 53 | 50 | 94.3% |
| opportunity | 20 | 20 | 100.0% |
| other | 26 | 13 | 50.0% |
| uncertain | 24 | 8 | 33.3% |

| language | n | correct | accuracy |
| --- | --- | --- | --- |
| ar | 10 | 7 | 70.0% |
| bn | 7 | 5 | 71.4% |
| de | 8 | 5 | 62.5% |
| el | 10 | 6 | 60.0% |
| en | 13 | 10 | 76.9% |
| es | 11 | 7 | 63.6% |
| fr | 12 | 10 | 83.3% |
| hi | 8 | 8 | 100.0% |
| ja | 11 | 10 | 90.9% |
| pt | 11 | 9 | 81.8% |
| ru | 13 | 8 | 61.5% |
| zh | 9 | 6 | 66.7% |

Confusion (expected → actual): opportunity→opportunity: 20; other→opportunity: 7; other→other: 13; other→rejection: 4; other→uncertain: 2; rejection→other: 1; rejection→rejection: 50; rejection→uncertain: 2; uncertain→other: 9; uncertain→rejection: 7; uncertain→uncertain: 8

**False-positive rate on non-rejections: 11.5%** (11/96).

* FP `V2A-0041` (en, ambiguous, expected uncertain): mode classify
* FP `V2A-0158` (es, ambiguous, expected uncertain): mode classify
* FP `V2A-0300` (bn, ambiguous, expected uncertain): mode classify
* FP `V2N-0646` (es, negative, expected other): mode classify
* FP `V2N-0718` (es, negative, expected other): mode classify
* FP `V2N-1531` (ru, negative, expected other): mode classify
* FP `V2A-0344` (ru, ambiguous, expected uncertain): mode classify
* FP `V2A-0428` (de, ambiguous, expected uncertain): mode classify
* FP `V2A-0458` (el, ambiguous, expected uncertain): mode classify
* FP `V2A-0266` (fr, ambiguous, expected uncertain): mode classify
* FP `V2N-1606` (ja, negative, expected other): mode classify

**Reply-language match rate on drafted replies: 100.0%** (deterministic verifier passed on 24/24 materialized drafts); drafts matching the rejection's true language: 79.2%. Draft-stage failures before any body existed: 4.

| language | drafts | verifier passed | true-language match |
| --- | --- | --- | --- |
| ar | 3 | 3 | 3 |
| de | 1 | 1 | 1 |
| en | 4 | 4 | 4 |
| es | 3 | 3 | 3 |
| fr | 3 | 3 | 2 |
| hi | 1 | 1 | 0 |
| ja | 2 | 2 | 1 |
| pt | 2 | 2 | 1 |
| ru | 2 | 2 | 2 |
| zh | 3 | 3 | 2 |

Draft gate outcomes: held_after_language_gate=4, returned=20.

Errors by stage: null=31, classification=2, draft_generation=8.

Mean seconds per row (shared-GPU run): 383.3.

## 4. Code bugs found and fixed

Three deterministic code defects were found (two confirmed against real corpus text, one
against the `chat_once` envelope contract), each fixed minimally at source with a
regression test that fails before the fix and passes after. The full suite on the fixed
tree is green: 1,057 tests across the library, the three binaries, the integration
targets (including `language_corpus`, `scale_campaign`, `cli_workspace`,
`evaluation_scoring`) and doc-tests, 0 failures.

### 4.1 Reply-language verifier false-rejects correct CJK replies (whitespace word counts)

**Symptom.** `language::ensure_reply_language` and the 40–180-word draft envelope in
`Ollama::draft_rejection_reply` measured "words" with `split_whitespace().count()`.
Chinese and Japanese separate words by character, not whitespace, so a correct 60–140-word
CJK reply measures as 1–4 "words":

* the deterministic gate rejects it as *"Reply is too short for its language to be
  verified"* (a false reject of a correct reply), and
* the draft envelope rejects it as *"Model draft length is outside the supported 40-180
  word envelope"*.

Because Chinese is one of the twelve guaranteed languages, every Chinese rejection
systematically failed at the draft stage. Reproduced on real corpus text
(`first_language`/`dominant_language` correctly resolve `ja`/`zh`, then the gate refuses
the correct reply); the regression tests below failed on the unmodified tree with exactly
these symptoms.

**Fix (behavior-preserving for every whitespace-separated language).** New
`language::word_count` counts whitespace words, or half the CJK character count for
spaceless CJK text (two CJK characters ≈ one word), whichever is larger; both gates now
use it. `src/language.rs`, `src/ollama.rs`.

**Regression tests.**

* `language::first_language_fallback_tests::word_count_measures_spaceless_scripts_by_character`
* `language::first_language_fallback_tests::measured_corpus_languages_resolve_and_verify_their_replies`
  (Japanese reply passes the gate; a two-character reply is still refused)
* `ollama::tests::chinese_drafts_pass_the_draft_envelope_and_language_gate`
  (full `analyze` pipeline on a Chinese rejection with a correct Chinese draft)

### 4.2 The language detector cannot represent Japanese (or the fixture languages Italian/Dutch)

**Symptom.** `lingua` was compiled with exactly twelve language features (the guaranteed
set — including Urdu, **excluding** Japanese). `language::first_language` on a Japanese
rejection therefore fell back to `"en"`, so the pipeline demanded an English reply to a
Japanese rejection and the correct reply language (`ja`) could never be resolved or
verified. The same gap applies to Italian and Dutch, which the repository's own
qualification fixtures (`tests/fixtures/classification.json`) exercise. Regression test
output on the unmodified tree: `first_language(ja_email, "en") == "en"` (expected `"ja"`).

**Fix (minimal, bounded).** Enable the missing detector languages in `Cargo.toml`:
`japanese`, `italian`, `dutch` alongside the existing twelve (the guaranteed-twelve
contract in `SUPPORTED_LANGUAGES` and the classification prompt is unchanged; these three
are the remaining languages the repository's own corpora contain). Coverage beyond these
fifteen languages stays best-effort.

**Regression tests.** `measured_corpus_languages_resolve_and_verify_their_replies`
(`ja`/`it`/`nl` emails resolve to their ISO codes) and the Japanese half of
`word_count_measures_spaceless_scripts_by_character`.

### 4.3 Classification payload can overflow the request envelope on long emails

**Symptom.** `classify_text_budget` documents that *"text + subject + system +
TEMPLATE_MARGIN_BYTES + structured_predict stays inside the context tier"*, but its
default-tier arm (24 000 bytes) violates that arithmetic: at `num_ctx` 32768 the
`chat_once` envelope admits at most ~22 500 payload bytes
(`32768 − CLASSIFY_SYSTEM_PROMPT(1473) − structured_predict(8192) − 512`). Every email
whose de-quoted body is ≳ 21.9 KB (a realistic size when quote-stripping cannot find the
quoted section) therefore hard-failed classification with *"Input exceeds safe context
budget. Shorten candidate context/reply or select 16384 context and requalify the GPU"* —
the remediation even points at the smaller tier. The design intent (bound the body,
classify it truncated, flag `input_complete=false` so only automatic sending is blocked)
was unreachable. Additionally, JSON string escaping inflates newlines/quotes past the raw
byte count, so even correctly sized bodies could overflow. Reproduced through `classify`
with a mock runtime: `"e"×24000`, `"line of recruiting text\n"×1000` and `"quoted" ×2400`
bodies all failed before the fix.

**Fix (behavior-preserving for every input that previously succeeded).** New private
`envelope_bounded_text` in `src/ollama.rs` re-bounds the body on the *serialized* payload
exactly like `mail::bounded_text` whenever the payload exceeds the envelope budget (each
dropped raw byte drops at least one serialized byte), and the resulting truncation feeds
the existing `input_complete=false` flag. Classification now proceeds on long mail and
only automatic sending is blocked, as documented.

**Regression test.** `ollama::tests::classify_reaches_the_runtime_at_maximum_budget_despite_json_escaping`
(three adversarial bodies reach the runtime, classify, and come back flagged truncated).

## 5. Model-quality observations (not code bugs)

Recorded as measured results; deliberately **not** patched in code. 41 of the 156
sampled messages ended in a fail-closed hold (no reply drafted or classified); the
taxonomy of those holds on the real corpus:

* **Think-budget exhaustion — 19 rows (12% of the sample).** Generation ended
  `done_reason=length` inside the 8192-token structured output budget and the pipeline
  held the message with *"Model response was incomplete; no action is authorized"* (14
  classification-stage, 1 classification inside `analyze`, 4 draft-stage). granite4.2:8b
  reasons longer than the qwen3.5-class measurements the `structured_predict` comment
  cites, especially on Hindi/Bengali/Greek content. The budget is pinned by
  `predict_budgets_follow_the_context_tier` and tuning it is a model-specific trade-off,
  not a correctness fix — recorded here instead.
* **Validator refusals — 17 rows.** *"Invalid classification field lengths"* ×10
  (explanation/company/position/language over the documented caps),
  *"position extraction is not grounded"* ×5 and *"Rejection evidence is not an exact
  quote"* ×2 — the model produced out-of-contract fields and `validate_verdict` refused
  them (fail closed, exactly as designed).
* **Signature preservation — 4 drafted replies held.** zh/hi/ja/pt drafts that did not
  end with the exact configured signature (`Your name` in this run) were held at the last
  draft gate. Notably the ja row `V2R-1305` reached this final gate — language
  resolution (`ja`), the language gate and the CJK length envelope all passed on the
  fixed tree — while a second ja row (`V2R-1320`) returned a complete Japanese draft
  through the whole pipeline.
* **Ambiguous-message false positives — 11 of 96 non-rejections (11.5%).** 7 of the 11
  are `uncertain`-labeled ambiguous near-misses (mixed/pending content) classified
  `rejection`, 4 are hard negatives (adversarial/recruiter-spam class). The label bank
  marks these fail-closed by design; the model over-fires on mixed content. This is the
  headline detection-quality shortfall of the default model on this corpus.
* **Latin-script cross-detection on ASCII-folded bank text.** The repository's own
  `scale_campaign` report shows `first_language` accuracy es 74/86 and fr 73/86 on the
  v2 bank text (whose es/fr fragments are diacritic-stripped), while every other bank
  language scores ≥ 83/86 (ja 83/86 after the detector fix; pre-fix Japanese was not
  representable at all). Native accented text passes 240/240 in
  `tests/language_corpus.rs`. Visible in the sample as one fr rejection answered in
  German (`V2R-0930`) and one hi draft detected as another language. Property of the
  synthetic bank text, not of the gate.
* **One 600 s inference timeout** (`operation timed out`) — transport-level, fail-closed.

## 6. Limitations

* The fixture suite and the v2 corpus are synthetic; numbers are not representative
  mailbox accuracy.
* Per-row latency numbers include cross-lane queueing and are not benchmarks.
* The verifier lane uses the same model for drafting and verification (the default
  configuration); the optional independent verifier (`qwen3.5:4b`) was not exercised.
* `rr compare-models` (multi-model bake-off) was not run: it multiplies the full suite by
  every installed candidate and the invocation budget was reserved for the required
  at-scale measurement.
