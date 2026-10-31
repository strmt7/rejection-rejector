# Accessibility and keyboard acceptance

This page describes what Rejection Rejector currently offers people who cannot use a
standard mouse-and-monitor setup, and exactly what must be verified by a human before a
release is called accessible. **Accessibility** here covers screen readers (software that
speaks the interface aloud), keyboard-only operation, text composition with an **IME**
(input method editor — the Windows component used to type languages such as Chinese,
Japanese or Hindi), and display scaling (DPI) / zoom.

Rejection Rejector ships three surfaces: the **`rr web` console** (a local web page
served on the loopback API and rendered by the user's browser), the **`rr tui`**
terminal interface, and the **`rr-tray`** Windows tray shell. The console carries the
browser's accessibility stack: semantic HTML with explicitly associated labels and
native controls, which exposes Name, Role and Value (WCAG 2.2 success criterion 4.1.2)
to browser-attached screen readers such as Narrator and NVDA. The tray shell uses
native Windows controls, exposed through Microsoft UI Automation. Nothing relies on
screen scraping.

## Keyboard navigation

Every core task is reachable without a mouse (WCAG 2.2 success criteria 2.1.1 Keyboard
and 2.1.2 No Keyboard Trap):

- **Tab / Shift+Tab** — browser focus traversal through the console's actionable
  controls in logical reading order.
- **Esc** — cancel the currently open dialog without accepting its destructive/send
  action.
- **Enter/Space** — activate the focused control (native browser semantics).
- The Review shortcut is deliberately inactive in Automatic mode, because review is
  disabled there (see [SETUP.md](SETUP.md)).

`Esc` always cancels: it never accepts the dialog's send or destructive action. The
confirm-exact-reply modal is mandatory before any send command reaches the engine
(the deterministic gate, not the UI, is the final authority).

The `rr tui` interface is keyboard-only by construction: every action is a typed
command or key binding, no mouse is required at any point.

## Labels and spoken names

Critical editable fields are explicitly associated with their visible labels,
including the review reply editor, Ollama/model fields, signature, candidate facts,
send limits, retention and API port. A field with a meaningful spoken name lets a
screen-reader user know what they are editing and in what state it is.

## What CI proves

CI proves the behavior under the surfaces: engine and API contracts (including the
send gate and emergency stop), the deterministic policy gates, the tray shell
contract, and the release-evidence pipeline. It does **not** certify screen readers,
IME composition or display scaling — those require a real desktop session and human
observation. A passing test proves behavior, not interaction.

## Required release-candidate acceptance

Run the exact release-candidate binary on Windows 11 and record the binary SHA-256
plus the following observations (open the console through `rr web` in a current
browser; record the browser and version too):

1. **Keyboard only:** complete every core flow (overview, review, reply, settings)
   using only the keyboard; Esc must cancel dialogs rather than accept the action;
   the confirm-exact-reply modal cannot be bypassed by keyboard.
2. **Screen readers:** with Narrator and with NVDA, verify navigation, the editable
   reply, signature, candidate facts, model fields, numeric limits and API port have
   meaningful spoken names and state, and that the reply editor is fully usable.
3. **IME:** compose and edit non-Latin text in the candidate-facts field and reply
   editor; focus changes must not unexpectedly destroy in-progress composition.
4. **Zoom and reflow:** repeat the core flow at browser zoom 200% and at a 320 CSS-pixel
   viewport width (WCAG 2.2 success criterion 1.4.10); no critical button, modal action
   or review editor may be clipped or unreachable.
5. **TUI:** complete the core flow keyboard-only in a terminal, including at small
   window sizes.
6. **Tray:** the tray menu opens and acts from the keyboard where the platform allows;
   the tooltip identifies the application.

A failed or not-tested item remains a release-readiness gap. Human observations apply
only to the exact tested binary (identified by its recorded SHA-256) and are not an
accessibility certification. Record results as evidence with the binary identity, the
Windows build, the browser and version, the display configuration and the observer —
the same evidence rules used elsewhere in this repository (see [TESTING.md](TESTING.md)).

## Sources (checked 2026-10-12)

- W3C, "Web Content Accessibility Guidelines (WCAG) 2.2" (W3C Recommendation 5 October
  2023, updated 12 December 2024): https://www.w3.org/TR/WCAG22/
- W3C, "Accessible Rich Internet Applications (WAI-ARIA) 1.2" (W3C Recommendation):
  https://www.w3.org/TR/wai-aria-1.2/
- Microsoft, "Complete guide to Narrator":
  https://support.microsoft.com/en-us/accessibility/windows/narrator/complete-guide-to-narrator
- NV Access, "NVDA screen reader" documentation: https://www.nvaccess.org/
