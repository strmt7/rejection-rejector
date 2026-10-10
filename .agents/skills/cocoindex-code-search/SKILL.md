---
name: cocoindex-code-search
description: Route broad conceptual code searches through semantic index when available, then always verify exact source with rg.
origin: adapted from strmt7/FlitzZip .agents/skills/cocoindex-code-search/SKILL.md
---

# CocoIndex Code Search

Mandatory for broad or fuzzy repository code navigation, before opening many
files. Direct `rg` stays first for exact symbols, strings, counts, and small
known scopes. [cocoindex-code](https://github.com/cocoindex-io/cocoindex-code)
is a development aid only and is never part of product runtime.

## Workflow

1. Use the `AGENTS.md` reading map to identify the likely domain before any
   search.
2. Exact lookups: run `rg -n` directly. Conceptual questions ("where is
   delivery state handled?"): run semantic search through `cocoindex` when
   installed (`pipx install cocoindex` if missing), scoped to the repository.
3. Confirm each candidate with `rg -n` and an exact source read. Semantic
   ranking is a hint, not evidence. Never change code from a semantic hit
   alone.
4. If semantic results miss the target, use bounded `rg -l` and refine once.
5. If the tool is unavailable or fails twice, proceed with bounded `rg` — a
   development tool must never block a correctness fix.

Search receipts are development evidence only; they never replace source reads
or the verification gates in `AGENTS.md`.
