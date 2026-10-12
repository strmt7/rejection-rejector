# Windows accessibility and keyboard acceptance

This page describes what Rejection Rejector currently offers people who cannot use a
standard mouse-and-monitor setup, and exactly what must be verified by a human before a
release is called accessible. **Accessibility** here covers screen readers (software that
speaks the interface aloud), keyboard-only operation, text composition with an **IME**
(input method editor — the Windows component used to type languages such as Chinese,
Japanese or Hindi), and display scaling (DPI) / zoom.

Rejection Rejector uses the native eframe/egui stack with the `accesskit` feature
enabled. **AccessKit** exposes the native widget tree — each control's role, name and
state — to platform accessibility adapters such as Microsoft UI Automation, which is
what Windows Narrator consumes. This matches the W3C "Name, Role, Value" model
(WCAG 2.2 success criterion 4.1.2) instead of relying on screen scraping.

## Keyboard navigation

Every core task is reachable without a mouse (WCAG 2.2 success criteria 2.1.1 Keyboard
and 2.1.2 No Keyboard Trap):

- **Ctrl/Cmd+1** — Overview
- **Ctrl/Cmd+2** — Review (Human Review mode only)
- **Ctrl/Cmd+3** — Activity
- **Ctrl/Cmd+4** — Local AI
- **Ctrl/Cmd+5** — Settings
- **F5** — Check Gmail now when a real Gmail account is connected and the worker is idle
- **Esc** — cancel the currently open application dialog without accepting its destructive/send action
- **Tab / Shift+Tab** — platform/egui focus traversal through actionable controls

`Esc` always cancels: it never accepts the dialog's send or destructive action. The
Review shortcut is deliberately inactive in Automatic mode, because review is disabled
there (see [SETUP.md](SETUP.md)).

## Labels and spoken names

Critical editable fields are explicitly associated with their visible labels through
AccessKit, including the review reply editor, Ollama/model fields, signature, candidate
facts, send limits, retention and API port. A field with a meaningful spoken name lets a
screen-reader user know what they are editing and in what state it is.

## What CI proves

Linux native GUI capture/geometry tests prove that key screens render and that Review
controls are visible in the tested viewport. Rust tests prove shortcut mode boundaries
and compile the AccessKit-enabled native application on Windows.

These checks **do not certify Windows Narrator, IME or display scaling**. Those require
a real Windows desktop session and human observation. A screenshot proves rendering,
not interaction.

## Required release-candidate Windows acceptance

Run the exact release-candidate binary on Windows 11 and record the binary SHA-256 plus
the following observations:

1. **Keyboard only:** navigate every view with Ctrl+1…5; traverse controls using Tab/Shift+Tab; activate buttons/checkboxes/combo boxes without a mouse; confirm Review cannot be opened by shortcut in Automatic mode.
2. **Dialogs:** open the send confirmation, unsaved-edit dialog and installer confirmation; Esc must cancel rather than accept the action.
3. **Narrator:** verify navigation buttons, editable reply, signature, candidate facts, model fields, numeric limits and API port have meaningful spoken names and state.
4. **IME:** compose and edit non-Latin text in the candidate-facts field and reply editor; focus changes must not unexpectedly destroy in-progress composition.
5. **Display scaling:** repeat the core flow at Windows 100%, 125%, 150% and 200% scaling; no critical button, modal action or review editor may be clipped or unreachable.
6. **Zoom:** exercise egui's native zoom controls and confirm text remains usable without hiding critical actions.

A failed or not-tested item remains a release-readiness gap. Human observations apply
only to the exact tested binary (identified by its recorded SHA-256) and are not an
accessibility certification. Record results as evidence with the binary identity, the
Windows build, the display configuration and the observer — the same evidence rules
used elsewhere in this repository (see [TESTING.md](TESTING.md)).

## Sources (checked 2026-10-12)

- W3C, "Web Content Accessibility Guidelines (WCAG) 2.2" (W3C Recommendation 5 October
  2023, updated 12 December 2024): https://www.w3.org/TR/WCAG22/
- W3C, "Accessible Rich Internet Applications (WAI-ARIA) 1.2" (W3C Recommendation):
  https://www.w3.org/TR/wai-aria-1.2/
- AccessKit project: https://accesskit.dev/
- Microsoft, "UI Automation overview":
  https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-uiautomationoverview
- Microsoft, "Complete guide to Narrator":
  https://support.microsoft.com/en-us/accessibility/windows/narrator/complete-guide-to-narrator
