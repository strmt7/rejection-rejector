# Interfaces: Desktop, Terminal, and Local Web

Every user-facing surface is a thin presentation shell over the same core.
No interface owns business logic: the `Engine`/`Worker`/`Snapshot` trio in the
library is the single source of truth for queue state, safety gates, and
dispatch, and every interface drives it through the same `Command` channel.

## The three surfaces

| Surface | Entry point | Rendering | Intended use |
|---|---|---|---|
| Desktop GUI | `rejection-rejector.exe` | native egui/eframe | primary daily driver |
| Interactive CLI | `rr tui` | ratatui (full-screen terminal) | servers, SSH, keyboard-first workflows |
| Local web UI | `rr web` | embedded static page on the loopback API | browsers, remote-desktop convenience |

All three implement the same workflow: Overview → Review (original + editable
reply) → confirm exact reply → send; Activity; Settings (including the four
tones, reply-language policy, and the cooldown-gated Automatic arming); Local
AI actions (qualify, compare, evaluate).

## Shared rules (enforced in code, not per-UI)

- `send_gate` (library) computes whether a job is a valid send candidate
  (exact persisted draft, bound editor revision, no hard blocks, sending
  enabled, not demo, not paused). GUI, TUI and web all call it; none
  reimplements the logic. The confirm-exact-reply modal is mandatory in all
  three before any send command is issued.
- The 30-second Automatic-arm cooldown (`AutomaticArmGate`) is a library
  state machine; every surface renders its own confirmation affordance but
  none can bypass the timer.
- The review editor binds to (message id, revision); stale editors can never
  save or send in any surface.
- Demo mode is honored identically: no dispatch, ever.

## Terminal UI (`rr tui`)

- Key-driven panes: Queue list, Review (original left / editor right),
  Activity log, Settings; `?` opens help; `q` quits with the same
  unsaved-work close confirmation as the desktop app.
- The TUI never talks to the database or Gmail directly; it issues
  `Command`s and renders `Snapshot`s like the desktop UI.
- Pure presentation-state helpers (selection movement, action enablement,
  editor dirty tracking) live in testable functions, not in the draw loop.

## Local web UI (`rr web`)

- Served by the existing loopback HTTP server; assets are embedded in the
  binary (`include_str!`) — no Node, no external CDNs, no telemetry.
- Binds only to the configured literal loopback address; the existing bearer
  token protects every endpoint, and state-changing endpoints require the
  same token (POST). Read endpoints stay read-only.
- The page sets a strict Content-Security-Policy (`default-src 'none'`,
  inline script/style only for the embedded page) and never renders email
  HTML as markup (text only).
- API extensions follow the existing OpenAPI contract process: versioned
  document, regenerated fingerprint, baseline update, and the same typed
  operation status, stable error codes and request IDs as the read API.
- The web server never widens the threat model: no listening on non-loopback
  interfaces, no request bodies larger than the existing limits, no
  execution of content that arrives from mail.

## Windows installer (component selection)

Inno Setup script (`windows/installer.iss`) with three tasks, all selected by
default, at least one required:

- `[x] Desktop application` — `rejection-rejector.exe` + Start-menu shortcut.
- `[x] Command-line tools` — `rr.exe` (includes `rr tui` and `rr web`).
- `[x] Local web interface` — Start-menu shortcut for `rr web` plus loopback
  firewall note (loopback needs no rule; documented, not configured).

The script refuses to continue with zero tasks selected (Wizard script check),
installs the shared library prerequisites documentation (VC++ runtime note),
and keeps everything per-user (no admin requirement, consistent with the
existing least-privilege posture).

## Testing contract

- Shared gates: unit tests in the library (already pinned).
- TUI helpers: unit tests for selection/dirty/enablement logic.
- Web: HTTP tests against the embedded server (auth required, read routes,
  write routes reject without token, CSP headers present).
- Installer: a release-tool test parses the `.iss` and asserts the three
  tasks exist, are default-checked, and the at-least-one rule is present.
