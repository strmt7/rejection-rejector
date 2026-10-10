# Multilingual Evaluation Corpus

`multilingual_eval.jsonl` extends rejection-detection evaluation coverage to **12 languages** (240 entries, 20 per language).

All companies, people and email addresses are fictional (`example.com`-style). Bodies are written natively in each
language, using realistic local business phrasing rather than translated boilerplate.

## Schema

One JSON object per line, matching `corpus.jsonl`:

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique, prefixed with the language code (e.g. `ZH001`, `HI014`). |
| `label` | string | `rejection`, `not_rejection` or `ambiguous`. |
| `subject` | string | Email subject line, in the entry language. |
| `body` | string | Email body, 80-400 words, in native script where applicable (Han for zh, Devanagari for hi, Arabic script for ar/ur, Bengali for bn, Cyrillic for ru, Greek for el). |
| `industry` | string | Industry vertical (same vocabulary as `corpus.jsonl`). |
| `seniority` | string | Role seniority (same vocabulary as `corpus.jsonl`). |
| `rejection_style` | string | Style/genre of the message (same vocabulary as `corpus.jsonl`). |
| `language` | string | ISO 639-1 code: en, zh, hi, es, fr, ar, bn, pt, ru, ur, de, el. |
| `expects_reply` | bool | Whether a human reply is expected/invited. |

## Composition

Per language (20 entries): 10 clear rejections, 5 clear non-rejections, 3 ambiguous, 2 mixed-language rejections.

The two mixed-language entries per language begin with a brief greeting and contain a short phrase in another
language, while the body stays predominantly in the entry's own language and script — these exist to test
first-substantive-language detection (the body language must win).

## Counts

Total entries: **240**

| Language | Name | Entries | rejection | not_rejection | ambiguous |
|---|---|---|---|---|---|
| en | English | 20 | 12 | 5 | 3 |
| zh | Mandarin Chinese | 20 | 12 | 5 | 3 |
| hi | Hindi | 20 | 12 | 5 | 3 |
| es | Spanish | 20 | 12 | 5 | 3 |
| fr | French | 20 | 12 | 5 | 3 |
| ar | Arabic | 20 | 12 | 5 | 3 |
| bn | Bengali | 20 | 12 | 5 | 3 |
| pt | Portuguese | 20 | 12 | 5 | 3 |
| ru | Russian | 20 | 12 | 5 | 3 |
| ur | Urdu | 20 | 12 | 5 | 3 |
| de | German | 20 | 12 | 5 | 3 |
| el | Greek | 20 | 12 | 5 | 3 |
| **Total** | | **240** | **144** | **60** | **36** |

## Validation performed

- every line parses as JSON (round-trip verified after write)
- 240 entries total, 20 per language across all 12 languages
- all ids unique
- label mix per language is exactly 12 rejection (incl. 2 mixed-language) / 5 not_rejection / 3 ambiguous
- body lengths within 80-400 words (character-equivalent range for zh, which is unsegmented)
- non-Latin bodies verified to be predominantly in the expected script
