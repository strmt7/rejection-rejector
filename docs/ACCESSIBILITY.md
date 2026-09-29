# Windows accessibility and keyboard acceptance

Rejection Rejector uses the native eframe/egui stack with the `accesskit` feature enabled. AccessKit exposes the native widget tree to platform accessibility adapters. The application also provides explicit keyboard navigation:

- **Ctrl/Cmd+1** — Overview
- **Ctrl/Cmd+2** — Review (Human Review mode only)
- **Ctrl/Cmd+3** — Activity
- **Ctrl/Cmd+4** — Local AI
- **Ctrl/Cmd+5** — Settings
- **F5** — Check Gmail now when a real Gmail account is connected and the worker is idle
- **Esc** — cancel the currently open application dialog without accepting its destructive/send action
- **Tab / Shift+Tab** — platform/egui focus traversal through actionable controls

Critical editable fields are explicitly associated with their visible labels through AccessKit, including the review reply editor, Ollama/model fields, signature, candidate facts, send limits, retention and API port.

## What CI proves

Linux native GUI capture/geometry tests prove that key screens render and that Review controls are visible in the tested viewport. Rust tests prove shortcut mode boundaries and compile the AccessKit-enabled native application on Windows.

These checks **do not certify Windows Narrator, IME or display scaling**. Those require a real Windows desktop session and human observation.

## Required release-candidate Windows acceptance

Run the exact release-candidate binary on Windows 11 and record the binary SHA-256 plus the following observations:

1. **Keyboard only:** navigate every view with Ctrl+1…5; traverse controls using Tab/Shift+Tab; activate buttons/checkboxes/combo boxes without a mouse; confirm Review cannot be opened by shortcut in Automatic mode.
2. **Dialogs:** open the send confirmation, unsaved-edit dialog and installer confirmation; Esc must cancel rather than accept the action.
3. **Narrator:** verify navigation buttons, editable reply, signature, candidate facts, model fields, numeric limits and API port have meaningful spoken names and state.
4. **IME:** compose and edit non-Latin text in the candidate-facts field and reply editor; focus changes must not unexpectedly destroy in-progress composition.
5. **Display scaling:** repeat the core flow at Windows 100%, 125%, 150% and 200% scaling; no critical button, modal action or review editor may be clipped or unreachable.
6. **Zoom:** exercise egui's native zoom controls and confirm text remains usable without hiding critical actions.

A failed or not-tested item remains a release-readiness gap. Human observations apply only to the exact tested binary and are not an accessibility certification.
