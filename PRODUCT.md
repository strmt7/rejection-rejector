# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Job seekers managing application outcomes from their own Windows desktop. They
check incoming mail for acceptances/rejections, review what the tool found, and
decide whether a drafted reply goes out. A secondary audience is the operator of
an enterprise deployment (admin/IT) who configures policy and audits sending.
[Users inferred from repository evidence after the product-truth probe timed out
unanswered; labeled per the init interview rule.]

## Product Purpose

Detect job-application rejection emails across a Gmail account (and connected
local mail), classify them with a local model, and prepare empathetic reply
drafts — while guaranteeing that no email is ever sent without human confirmation
and a deterministic gate. Success means: zero unreviewed sends ever, high-quality
rejection detection at scale (hundreds to thousands of messages), and complete
audit evidence for every outbound write.

## Positioning

The deterministic send gate: model output alone never authorizes a send. Human
confirmation, exact-body hashing, pinned revisions, policy, and emergency stop
are independent layers that all must pass. No neighboring tool combines local-
first classification with this level of send-safety engineering.

## Operating Context

Local-first Windows workstation (also runs on Linux/macOS via the same Rust
core). Gmail via OAuth (Google Desktop client) or IMAP/SMTP app passwords;
credential storage in the OS credential manager and an authenticated encrypted
vault. Local LLM runtime: Ollama with digest-pinned models. Surfaces: `rr` CLI,
`rr tui`, `rr web` local loopback console (the primary interface), `rr-tray`
Windows tray shell. Offline operation with local training/corpus tooling.

## Capabilities and Constraints

Confirmed: multi-language rejection detection (12 guaranteed corpus languages),
review queue with revision-pinned edits, deterministic send gate, task
qualification before automatic mode, enterprise policy contracts (v2, digest-
pinned), emergency stop (fail-closed), audit anchoring, encrypted backups with
recovery drills, bounded resource behavior, OpenAPI contract with compatibility
tests. Technical constraints: no `unsafe`, loopback-only API with bearer token,
no telemetry, Python tooling capped at 120-char lines, all configuration
validated. The web console's behavior, flows and API contract are pinned by
tests and MUST NOT change in a visual redesign. [Untouched-behavior constraint
inferred from the brief's "design/redesign the web gui" scope and the test
discipline; labeled after probe timeout.]

## Brand Commitments

- The product name is "Rejection Rejector"; MIT licensed; professional, sober,
  trustworthy voice — it handles sensitive career moments.
- The user directed that the web GUI be designed "using all visual skills as
  well as the other repo [smart-job-seeker] … iteratively and completely" —
  smart-job-seeker's design language is the binding visual reference.
  [Binding-ness inferred from the directive's wording; labeled after probe
  timeout.]
- Security posture is a brand trait: fail-closed, no workarounds, no
  suppression, honest state reporting (e.g. "not_configured" rather than fake
  green).

## Evidence on Hand

- `src/web_ui.html` — the incumbent console (1,082 lines) to be redesigned; its
  behavior is the functional spec.
- smart-job-seeker repository (read-only reference) — design language source.
- `docs/` — full contract, accessibility (WCAG 2.2), testing and policy record.
- Deterministic readiness/evidence commands (`rr doctor`, `build-info`,
  `contract-info`) produce verifiable JSON evidence.

## Product Principles

1. Send safety outranks convenience: every gate is independent and deterministic.
2. Honest state: the interface never shows green for unverified things.
3. Local-first: user data, models and keys stay on the user's machine.
4. Evidence or it didn't happen: every action leaves reviewable evidence.
5. Professional calm: the product serves stressful moments; it must feel
   composed, precise and in control — never playful at the user's expense.

## Accessibility & Inclusion

WCAG 2.2 for the console (screen readers, keyboard-only, IME composition,
zoom/reflow), keyboard-only TUI; documented in docs/ACCESSIBILITY.md with a
release-candidate human acceptance checklist.
