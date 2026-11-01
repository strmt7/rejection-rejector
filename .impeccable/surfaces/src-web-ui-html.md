---
version: 1
slug: "src-web-ui-html"
primary_target: "src/web_ui.html"
related_targets: ["src/web.rs"]
---

# Surface brief — rr web console (src/web_ui.html)

Scope: the product's primary interface (Operate mode). Visitor = the operator/
job seeker completing review-and-reply tasks, often in stressful moments.
Job: triage detected rejections, confirm or edit a reply, dispatch safely.
Proof/content: real queue items, revisions, gate states, audit evidence.
Constraints: behavior, flows and API contract are pinned by tests and must not
change; WCAG 2.2 keyboard/screen-reader/zoom acceptance applies; loopback-only
web app, no external requests except self-hosted assets.

Chosen direction: Carbon Copy Docket (roll assignment, seed key 8345aab6;
user confirmed "Carbon Copy Docket — THE ROLL"). Memorable moment: every
confirmed action visibly stamps its three copies — GATE, AUDIT, BACKUP — so
evidence is seen, not promised.

## Direction contract

THESIS: the console is one continuous carbon-copy docket — every write is a
docketed triplicate; it refuses the category's three-pane mail client and the
card-dashboard rut.

OWN-WORLD: NCR carbonless stock (bone #F4EFE2, pale pink #E9D8C6,
pale green #DCE7D7) under process ink #26221D; rubber-stamp vermilion #B23A2E for
dispositions; ballpoint blue #33506E for human sign-off. Form-printed type:
tracked small-caps box labels (Archivo), typewriter values (Courier Prime).
Perforated stub rail; ruled boxes with corner labels; visible hairline
construction grid in empty ground (raise: Grid Specimen). Stamp marks and
rule form (solid/dashed/struck) carry state; hue never carries state alone.

STORY: the operator reads the docket, sees exactly which gate layers pass,
edits or signs, and the send visibly tears its copies into the audit trail.
Nothing is sent that is not stamped.

FIRST VIEWPORT: docket header band (form no., docket id·revision, gate
posture, pinned model, triplicate copy legend) over a perforated stub rail
(queue as tear-off stubs, pinned item marked) and the working form centre:
detection box (from/subject/received/revision/state plus the policy
disclosure), the drafted reply as typed copy in a ruled box, the three-layer
gate checklist (1 human confirmation / 2 body hash · pinned revision /
3 policy & limits), and the action strip with the VOID — GATE BLOCKED stamp
and the sign-off margin (raise: Design Annual — the machine never signs for
you). AMENDED 2026-11-01 after finish review: the first draft of this block
named a "send cap" header cell and a "confidence box"; the routes the page
consumes expose neither a daily send-cap counter (/v1/metrics carries
send_attempts_24h but the console does not fetch it) nor a confidence score,
and no route carries the model identity. The header therefore shows real
fields only: docket id·revision, gate posture (sending_enabled × mode), and
last poll. The detection facts ride review-sub and the policy disclosure. A
second amendment on the same day replaced an interim gate-posture cell that
read a phantom gmail_send_scope field (it lives in /v1/metrics, not /v1/status)
and would have shown a permanent false "scope missing" signal.

FORM: Carbon Copy Docket, grounded candidate 7 of 7, roll assignment from
seed key 8345aab6.

FINISH: unreviewed and undocumented is unfinished; this build ends with the
finish review, the verdict, DESIGN.md, and every shipping raster carrying its
provenance.

Unresolved: none blocking. Structural verification only (no browser on this
host); the finish review is text/structure-based by necessity and this
substitution is disclosed at finish. The script is no longer byte-identical
to the incumbent: after the finish review it was minimally augmented for
WCAG 2.1.1 keyboard reachability of the queue rows and for the signature
triplicate stamping this contract promises. Flows, commands and the API are
unchanged; the full local suite is the behavior authority.
