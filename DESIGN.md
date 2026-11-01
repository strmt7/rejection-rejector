---
name: Carbon Copy Docket
description: The rr web console as one continuous NCR carbon-copy dispatch docket — every write is a docketed triplicate, stamped, tearable, and nothing is sent that is not stamped.
colors:
  bone: "#f4efe2"
  pink: "#e9d8c6"
  green: "#dce7d7"
  ink: "#26221d"
  stamp: "#b23a2e"
  stamp-ink: "#8f2c1d"
  pen: "#33506e"
  ink-70: "rgba(38, 34, 29, 0.72)"
  ink-45: "rgba(38, 34, 29, 0.5)"
  ink-25: "rgba(38, 34, 29, 0.25)"
  ink-12: "rgba(38, 34, 29, 0.12)"
  grid-faint: "rgba(38, 34, 29, 0.055)"
typography:
  display:
    fontFamily: "Archivo, 'Segoe UI', system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 700
    letterSpacing: ".04em"
  headline:
    fontFamily: "Archivo, 'Segoe UI', system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 700
    letterSpacing: ".04em"
  title:
    fontFamily: "Archivo, 'Segoe UI', system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 700
    letterSpacing: ".16em"
  body:
    fontFamily: "Archivo, 'Segoe UI', system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Archivo, 'Segoe UI', system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 700
    letterSpacing: ".14em"
  typed:
    fontFamily: "'Courier Prime', 'Courier New', Consolas, monospace"
    fontSize: "13px"
    fontWeight: 400
    fontFeature: "tabular-nums"
rounded:
  none: "0px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "14px"
  lg: "18px"
  xl: "26px"
components:
  form-box:
    backgroundColor: "{colors.bone}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "26px 22px 22px"
    typography: "{typography.body}"
  form-box-label:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bone}"
    rounded: "{rounded.none}"
    padding: "5px 11px 4px"
    typography: "{typography.headline}"
  action-button:
    backgroundColor: "{colors.bone}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "9px 13px"
    typography: "{typography.label}"
  action-button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bone}"
    rounded: "{rounded.none}"
    padding: "9px 13px"
    typography: "{typography.label}"
  chip:
    backgroundColor: "{colors.bone}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "5px 10px 4px"
    typography: "{typography.label}"
  chip-ok:
    backgroundColor: "{colors.green}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "5px 10px 4px"
    typography: "{typography.label}"
  chip-void:
    backgroundColor: "{colors.pink}"
    textColor: "{colors.stamp-ink}"
    rounded: "{rounded.none}"
    padding: "5px 10px 4px"
    typography: "{typography.label}"
  void-stamp:
    textColor: "{colors.stamp-ink}"
    rounded: "{rounded.none}"
    padding: "6px 14px 5px"
    typography: "{typography.headline}"
  sign-line:
    textColor: "{colors.pen}"
    rounded: "{rounded.none}"
    height: "26px"
    width: "240px"
---

# Design System: Carbon Copy Docket

## Overview

### Creative North Star: "Carbon Copy Docket"

The console is one continuous carbon-copy docket. Every write is a docketed
triplicate — the send gate, the audit anchor and the encrypted backup are the
three copies you can see — and the interface refuses the category's three-pane
mail client and the card-dashboard rut outright. The world is NCR carbonless
business-form printing, 1950s–70s: bone / pale-pink / pale-green stock under
process ink, rubber-stamp vermilion for dispositions, ballpoint blue for human
sign-off. The page reads as one form you work down: docket header band,
perforated stub rail, ruled working boxes, stamp strip, sign-off margin. The
memorable moment is the triplicate press: a confirmed action visibly stamps its
three copies — GATE, AUDIT, BACKUP — so evidence is seen, not promised.

Provenance: roll assignment from seed key `8345aab6`, grounded candidate 7 of 7,
user-confirmed as "Carbon Copy Docket — THE ROLL"; the approved sketch is
`.impeccable/mocks/decision/assigned.html` and the decision round is recorded in
`.impeccable/mocks/decision/payload.json`. Two named raises were carried into
the build and are invariants of this system: from the Design Annual challenger,
every confirmed send carries a human sign-off mark in the margin — **the machine
never signs for you**; from the Grid Specimen challenger, the construction grid
stays visible as hairline ruling in empty ground — **the machine shows its work**.

Honesty is the personality, per PRODUCT.md's brand commitments: unverified
things are never shown green, states say "not_configured" rather than faking
health, and stamps fire only on actual command outcomes. Two API-driven
substitutions (recorded as amendments in the surface brief on 2026-11-01) keep
the docket honest: the header carries only fields the live routes expose —
docket id · revision, gate posture (`sending_enabled × mode`), last poll — with
no "send cap", "confidence" or model-identity cells, and no phantom
`gmail_send_scope` signal.

### Key Characteristics

- One continuous form: ruled boxes with inverted ink corner labels, never cards.
- Triplicate logic everywhere: three stock tints map to GATE / AUDIT / BACKUP.
- State is a stamp mark (✓ ✕ ·, struck line, double rule, rotated VOID) — hue only reinforces.
- Form-printed type: tracked Archivo small caps as printed labels, Courier Prime as typed values.
- Flat, square, hairline-ruled: zero border-radius, zero shadows; the construction grid shows in empty ground.
- One motion moment only: the stamp press.

## Colors

The palette is three carbonless stock tints, one process ink with a transparency
ladder, and two marking inks — exactly the materials of the roll, plus one
artifact-added deep stamp ink.

### Primary (process ink)

- **Process Ink** (#26221d): the only structural color — all rules, borders, primary buttons, body text. Never a large fill except inverted labels and the active tab.

### Secondary (marking inks)

- **Stamp Vermilion** (#b23a2e): rubber-stamp dispositions — VOID stamp rule and text, danger buttons, error text. Marks a negative outcome; never decorative.
- **Stamp Ink Deep** (#8f2c1d): the darker ink of a struck impression — VOID stamp lettering, void chip text, struck layer marks. Added by the implementation beyond the roll's recorded palette (see Provenance & Conflicts).
- **Ballpoint Blue** (#33506e): everything human — links, focus ring, dirty-flag, sign-off margin. The machine's ink is black; the human's is blue.

### Tertiary (stock copies)

- **Bone Stock** (#f4efe2): the ground. First copy (GATE). Background of every surface; the `::selection` background is its pink sibling instead. World override: this cream ground *is* NCR carbonless stock, not a generic off-white.
- **Pale Pink Stock** (#e9d8c6): second copy (AUDIT). Also the only hover/selection tint and the ground of every warn/void state.
- **Pale Green Stock** (#dce7d7): third copy (BACKUP). Also the only ok tint and the hover color of the primary button's text.

### Neutral (ink transparency ladder)

- **Ink 70** (rgba(38,34,29,.72)): secondary text, placeholders, field-group headings.
- **Ink 45** (rgba(38,34,29,.5)): quiet borders (neutral stub state, quiet buttons).
- **Ink 25** (rgba(38,34,29,.25)): hairline cell dividers, scrollbar thumb, exact-copy rules.
- **Ink 12** (rgba(38,34,29,.12)): row separators and settings-row rules.
- **Grid Faint** (rgba(38,34,29,.055)): the visible construction grid — the Grid Specimen raise.

### Browser surfaces

Selection is pink-on-ink; the caret is ink; the webkit scrollbar is 10px with an
ink-25 thumb inside a 3px bone border on a transparent track. These are themed
on purpose — a default blue scrollbar or selection would break the stock world.

### Named Rules

**The Hue-Never-Alone Rule.** Hue never carries state alone. Every state is a
stamp mark first — a glyph (✓ ✕ ·), a struck line-through, a double rule, a
rotated band, an inverted fill — and the tint only reinforces it. Removing all
color must leave every state readable.

**The Honest Green Rule.** Pale green means exactly two things: third copy, or a
verified pass. Nothing is green until a real outcome says so — unconfigured
states print "not_configured", never a friendly tint.

**The Three-Copy Rule.** Bone / pink / green always read as copy 1 GATE /
2 AUDIT / 3 BACKUP in that order (the header legend and the impression strip
both spell it out). Do not reuse the tints in a new meaning without a spelled-
out legend.

Contrast floors (verified against the token values): ink on bone 13.8:1, ink on
pink 11.4:1, ink on green 12.4:1; stamp-ink on pink 5.9:1; pen on bone 7.3:1;
ink-70 blended on bone 5.9:1; stamp on bone 5.2:1. All meet WCAG AA for their
sizes; none are borderline.

## Typography

**Display Font:** Archivo (variable 100–900), embedded as self-hosted woff2; fallback "Segoe UI", system-ui, sans-serif.
**Typed-Value Font:** Courier Prime (400/700), embedded as self-hosted woff2; fallback "Courier New", Consolas, monospace.

**Character:** a form came off a printer and someone typed into it. Archivo is
the pre-printed stationery — tracked, uppercase, small, authoritative; Courier
Prime is the typewriter — human data entered into the blanks. The two never mix
inside a phrase: a label is printed, a value is typed. Fonts are embedded
(base64 woff2) because the console is loopback-only and makes no external
requests.

### Hierarchy

- **Display** (Archivo 700, 17px, tracking .04em, uppercase): form and pane titles (h1). The brand lockup variant is 15px at .12em tracking.
- **Headline** (Archivo 700, 14px, tracking .04em, uppercase): the inverted corner labels on ruled boxes (h2).
- **Title** (Archivo 700, 11px, tracking .16em, uppercase, ink-70): field-group headings (h3) — the widest tracking in the system.
- **Body** (Archivo 400, 14px, line-height 1.55): running text; body color ink, supporting copy ink-70.
- **Label** (Archivo 700, 11px, tracking .14em, uppercase, ink-70): the `.lbl` system — every structural label on the form (docket cells, copy legend, gate layers, settings rows). Buttons and chips use the same voice at 11px/.10–.12em.
- **Typed** (Courier Prime 400/700, 12–13px, tabular numerals): every machine- or user-entered value — docket ids, timestamps, mail bodies (13px/1.6), the reply editor (13px/1.7), form inputs (13px), impression marks (11px/.06em), countdowns (700, tabular-nums).

### Named Rules (Typography)

**The Printed-vs-Typed Rule.** Structure is printed (Archivo tracked caps);
content is typed (Courier Prime). A value never appears in Archivo and a label
never appears in Courier. `code` tokens get a pink ground to stay visibly typed.

**The Tabular Rule.** Anything numeric that can change — countdowns, impression
timestamps — uses tabular numerals (`font-variant-numeric: tabular-nums`) so the
type doesn't jitter as values tick.

## Layout

The page is one form in three bands: a docket header band (flex row of hairline-
divided cells: brand + form number, docket record cells, triplicate legend,
status chips flush right), then a two-column main — perforated stub rail
(`minmax(300px, 26%)`) and working form (`minmax(0, 1fr)`) at
`height: calc(100dvh - 62px)` with independent scroll areas (`overscroll-behavior:
contain`, `scrollbar-gutter: stable`). This is deliberately not a three-pane
mail client: one rail of tear-off queue stubs, one working form.

The stub rail carries the queue as tear-off stubs — 1px ink-12 separators, a
2px dashed ink right rule, and the perforation itself (bone radial-gradient
punch dots on a 12×16px repeat, edge-aligned). The workspace scrolls under a
sticky file-folder pane nav (tabs with 1.5px ink sides, no bottom rule, negative
1.5px overlap; active tab inverts to ink-on-bone).

Spacing rhythm is the 4/8/14/18/26 scale (xs→xl): 4px between stacked meta
lines, 8px between chips and buttons, 13–14px inside controls and rows, 18–20px
between blocks, 22–26px inside ruled boxes. Density is form-density: tight but
never cramped, with generous ruled boxes around dense typed content.

Responsive: at 980px the review grid and settings rows drop to one column and
the gate strip wraps; at 850px the docket stacks — rail becomes a full-width
band (dashed rule moves to the bottom, perforation hidden), the main grid goes
single-column, header cells reflow and lose their right rules. Nothing
disappears; the form just refills.

### Named Rules (Layout)

**The One-Docket Rule.** The whole console is one form. Regions are boxes with
corner labels or hairline-divided cells — never floating cards, never nested
panels.

## Elevation & Depth

Flat. There are zero box-shadows and zero border-radii in this system — depth is
conveyed by stock tint (the three copies), rule weight (1px hairline → 1.5px
form rule → 2px structural → 3px double stamp), and inverted corner labels. The
visible hairline construction grid (grid-faint, 24px pitch, both axes) runs
under all empty ground — the Grid Specimen raise: the machine shows its work.

### Named Rules (Elevation & Depth)

**The No-Shadow Rule.** Depth comes from tint and rule weight only. Adding a
shadow or a radius imports a different world.

**The Hairline Grid Rule.** Empty ground always shows the construction grid at
grid-faint strength (and the reply editor carries the same ruling at one-axis
pitch). It is the honesty of the medium — the grid the form was printed on.

## Shapes

Everything is square: border-radius is 0px system-wide. The recurring silhouette
is the ruled box with an inverted corner label (a 1.5px ink rectangle whose
heading sits in an ink-filled tab pinned at the top-left corner, overlapping the
rule). The border ladder is strict: 1px ink-alpha hairlines (dividers, quiet
containers), 1.5px ink form rules (boxes, buttons, chips, inputs), 2px ink
structural rules (header bottom, dialog edge, selected stub edges), 3px double
stamp (the VOID mark only). The only curve in the system is the perforation
punch dots; the only tilt is the stamp angle (−4deg), reserved for stamp marks.
Voided check marks carry an actual `line-through`, not just a color change.

### Named Rules (Shapes)

**The Stamp Angle Rule.** Rotation is a stamp privilege. Nothing else in the
system is ever rotated.

## Components

### Docket header band

Hairline-divided flex cells on bone under a 2px ink bottom rule: brand lockup
(dashed-rectangle brand mark + form number `RR-11`), docket record cells
(printed `.lbl` over typed values), the triplicate legend (three bordered swatch
chips — `1 Gate` bone, `2 Audit` pink, `3 Backup` green), status chips flush
right.

### Stamp chips (status)

- **Shape:** 1.5px ink rule, square, padding 5px 10px 4px, label type 11px/.12em.
- **Default:** bone on ink. **ok:** green ground (verified pass only). **warn:** pink ground with stamp border *and* stamp-ink text — border and text change, not just hue. **ai:** pen border and text (model-generated, a different actor).

### Form box (ruled container)

Bone ground, 1.5px ink rule, padding 26px 22px 22px, with the inverted corner
label (h2) in an ink tab at the top-left. The dialog variant thickens to a 2px
rule; the token-gate card is the same component centered at `min(680px, …)`.

### Buttons

- **Shape:** square, 1.5px ink rule, label type (Archivo 700 11px, .1em, uppercase), padding 9px 13px.
- **Primary:** ink fill, bone text; hover turns the text green (the third copy lights up). Used only for the decisive action ("Review & send…", "Send this exact reply now").
- **Soft:** green ground (filed, non-destructive commands). **Quiet:** bone with ink-45 rule (pagination). **Danger:** stamp text and rule on bone; hover goes pink ground with stamp-ink text. **Hover** on plain actions is pink. **Disabled:** opacity .45, default cursor. **Focus:** 2px pen outline, 2px offset (`:focus-visible`).

### Queue stubs (rail items)

Dense typed stubs on bone with 1px ink-12 separators; hover tints pink; the
selected stub gets 2px ink rules top and bottom, a pink ground and a 3px indent
— a stub chosen from the pad. State chips print inline (`review` = pink ground,
stamp rule, stamp-ink text). The pinned item is marked in the header context,
not with decoration.

### Send-gate layer checklist

A 1.5px ink strip of three cells (1px ink-25 dividers): an 18px checkbox mark
plus a printed layer name. Marks: `·` pending (empty box), `✓` ok (green
ground), `✕` void (pink ground, stamp rule, stamp-ink, struck through). The
layers are spelled out — `1 Human confirmation`, `2 Body hash · pinned
revision`, `3 Policy & limits` — never icon-only.

### Impression strip (the triplicate record)

Three typewriter chips — `1 GATE`, `2 AUDIT`, `3 BACKUP` — neutral at rest
(1.5px ink-45 rule), stamped on success (ink rule, green ground, `✓` + time),
void on refusal (stamp rule, pink ground, `— VOID`). This is the memorable
moment and it obeys the honesty rules below.

### The VOID stamp

`3px double` stamp-ink rule and lettering ("VOID — GATE BLOCKED"), rotated
−4deg, appearing inline in the action strip with `role="status"`. It is the
gate's own mark and the only double-ruled, only rotated object in the system.

### Sign-off margin (raise: Design Annual)

In the confirm dialog: a printed line "Confirmed by operator — the machine never
signs for you" in ballpoint blue over a 240px × 26px pen-ruled signature line.
A blank you sign, not a checkbox the machine ticks.

### Form fields & settings rows

Settings rows are a 240px label column (printed label + ink-70 small print)
against controls: 1.5px ink inputs/selects, Courier 13px, max 420px wide; 16px
checkboxes with ink accent. Ruled key-value grids (`.kv`) pair printed terms
with typed values. Disclosures open in ink-25-ruled boxes with pen-colored
tracked summaries.

### Motion: the single press

- **stamp-press** (`0.32s cubic-bezier(.19, 1, .22, 1)`): scale 1.18→1 with opacity 0→1 (opacity complete by 60%), landing on the stamp's −4deg rest angle. Fires only when a stamp impression is actually laid down — impression chips under `.press`, or the VOID stamp revealing. It is the only animation in the system; there are no hover transitions beyond instant tint swaps.
- Under `prefers-reduced-motion: reduce` the press is disabled entirely (`animation: none`) and smooth scrolling reverts to `auto`. Stamps still appear — evidence must not depend on motion.

### Named Rules (Components)

**The Machine-Never-Signs Rule.** (raise) Human sign-off is a blank margin in
ballpoint blue. The interface may ask for a signature; it never produces one.

**The Outcome-Stamped Rule.** Stamps reflect actual command outcomes only. A
filed (non-send) write stamps copies 2 and 3 — AUDIT and BACKUP — and leaves
the GATE copy bare, because no send happened. A refused send strikes the GATE
copy `— VOID`, marks layers 2 and 3 with struck ✕ and raises the VOID stamp. A
completed send stamps all three copies with ✓ + time and marks all three layers
✓. Nothing is pre-stamped, estimated, or stamped in anticipation.

## Do's and Don'ts

### Do

- **Do** carry every state as a mark plus a rule form plus text — ✓/✕/· glyphs, struck lines, double rules, inverted fills — and let the tint only reinforce it (the Hue-Never-Alone Rule).
- **Do** print structure in tracked Archivo caps and type values in Courier Prime with tabular numerals (the Printed-vs-Typed Rule).
- **Do** keep the construction grid visible at grid-faint (24px pitch) in empty ground and the editor (the Hairline Grid Rule).
- **Do** show only fields the live API actually exposes in docketed header/record cells — the amendments to the surface brief exist precisely for this; unverified state prints its real word ("not_configured"), never a friendly tint.
- **Do** give every interactive element the 2px pen `:focus-visible` ring at 2px offset, and keep queue rows and tabs keyboard-reachable (WCAG 2.1.1).
- **Do** stamp impressions only after the command resolves (the Outcome-Stamped Rule).

### Don't

- **Don't** use hue alone for state, and don't use pale green for anything unverified (the Honest Green Rule).
- **Don't** add border-radius (0px is the system) or shadows (the No-Shadow Rule).
- **Don't** add motion beyond the stamp press; under reduced motion, don't substitute a different flourish.
- **Don't** rotate anything but stamps, or double-rule anything but the VOID mark (the Stamp Angle Rule).
- **Don't** decorate with stamps, perforations or triplicate legends: the risk of this world is bureaucratic costume — the stamps stay marks of control, never clutter.
- **Don't** build three-pane mail-client layouts or card dashboards; regions are ruled boxes with corner labels (the One-Docket Rule).
- **Don't** mix the two type voices inside a phrase, or render a value in Archivo / a label in Courier.

## Provenance & Conflicts

- World: Carbon Copy Docket — grounded candidate 7 of 7 from the roll (NCR triplicate carbon-copy business forms and dockets, 1950s–70s), seed key `8345aab6`, confirmed by the user. Approved sketch `.impeccable/mocks/decision/assigned.html`; decision round `.impeccable/mocks/decision/payload.json`.
- Carried raises: human sign-off mark (from `challenger-design-annual`) and visible hairline construction grid (from `challenger-crouwel` / Grid Specimen). Both are documented as invariants above.
- World overrides, per the direction contract: the cream ground (#f4efe2) is NCR carbonless stock, not a neutral preset; the repeating hairline grid in empty ground is the Grid Specimen raise.
- Where this document's method schema (Stitch DESIGN.md format) conflicted with the artifact's reality, the artifact won:
  1. The schema's Material-derived color roles (Primary/Secondary/Tertiary/Neutral) were re-mapped to the world's material roles (process ink / marking inks / stock copies / ink ladder). A stock tint is not a "tertiary accent"; the three copies are co-equal materials with fixed triplicate meanings.
  2. The schema's display/headline/title scale presumes marketing-scale type; the artifact's hierarchy is deliberately flat form-print (17/14/11px). The artifact sizes are normative.
  3. The roll's recorded palette (`payload.json`) lists six colors; the implementation adds **Stamp Ink Deep** (#8f2c1d) as the struck-impression ink. Artifact wins; the token is included above.
  4. The schema's component sub-token props cannot carry borders, motion or focus rings; those live in `.impeccable/design.json` (sidecar) per the method's own extension path.
- Behavior note: flows, commands and API are pinned by the test suite and unchanged by this visual system; the script was minimally augmented post-review for keyboard reachability of queue rows (WCAG 2.1.1) and for the signature triplicate stamping documented here.
