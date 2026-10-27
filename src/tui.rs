//! Interactive terminal interface (`rr tui`) — a thin presentation shell.
//!
//! This module renders [`crate::worker::Snapshot`]s and issues
//! [`crate::worker::Command`]s through the
//! shared [`crate::worker::Worker`] exactly like the desktop GUI: it never touches the
//! database or Gmail, and it never re-implements a safety decision. Sending
//! goes through the shared `send_gate_eligible` gate plus the mandatory
//! confirm-exact-reply dialog; Automatic arming goes through the library
//! `AutomaticArmGate` cooldown. The pure presentation-state helpers
//! (selection movement, editor dirty tracking, action enablement, dialog
//! state) live in free functions covered by unit tests, not in the draw loop.

use crate::{
    config::{AutomaticArmGate, Mode, ReplyLanguage, Settings, Tone},
    engine::{SendGateContext, editor_binding_matches, send_gate_eligible},
    mail::{hard_blocks, validate_draft},
    types::{Job, OperationState, OperationStatus, hash},
    worker::{Command, Snapshot, Worker},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, poll, read};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::{cell::Cell, sync::atomic::Ordering, time::Duration};

/// Main-area pane shown behind the overlays.
///
/// Inputs: none (plain enum). Output: which of the four key-driven panes
/// (Queue, Review, Activity, Settings) currently owns the main area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    /// Queue job list with per-job state and flags.
    Queue,
    /// Review workspace: original email left, editable reply right.
    Review,
    /// Audit/activity event log.
    Activity,
    /// Settings: mode, tone, reply language, Automatic arming, save.
    Settings,
}

/// Focusable rows of the Settings pane.
///
/// Inputs: none (plain enum). Output: which settings row the cursor is on;
/// `AutomaticArm` carries both the arm flow and the disable-Automatic action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsRow {
    /// Human review / Automatic mode picker.
    Mode,
    /// Four-level reply-tone picker.
    Tone,
    /// Reply-language policy picker (Auto / English).
    ReplyLanguage,
    /// "Enable sending from this application" toggle.
    SendingEnabled,
    /// Automatic arming flow and the disable-Automatic action.
    AutomaticArm,
    /// Persist the edited settings via `Command::Settings`.
    Save,
}

/// Fixed Settings-pane row order, top to bottom.
pub const SETTINGS_ROWS: [SettingsRow; 6] = [
    SettingsRow::Mode,
    SettingsRow::Tone,
    SettingsRow::ReplyLanguage,
    SettingsRow::SendingEnabled,
    SettingsRow::AutomaticArm,
    SettingsRow::Save,
];

/// Editor presentation state bound to one `(message id, revision)` pair.
///
/// The binding is what makes stale editors harmless: an editor loaded for an
/// older revision can be typed into but never saved or sent.
#[derive(Clone, Debug, Default)]
pub struct EditorState {
    /// `(message id, revision)` the visible text was loaded for.
    pub binding: Option<(String, u64)>,
    /// Visible editable reply text.
    pub text: String,
    /// Whether `text` holds changes not yet confirmed as persisted.
    pub dirty: bool,
}

impl EditorState {
    /// Bind the editor to a job and load its persisted draft.
    ///
    /// Inputs: `job` — job the operator selected. Output: none; the editor
    /// binds to `(job.id, job.revision)`, shows the persisted draft body (or
    /// empty text when no draft exists) and becomes clean.
    pub fn load(&mut self, job: &Job) {
        self.binding = Some((job.id.clone(), job.revision));
        self.text = job
            .draft
            .as_ref()
            .map(|draft| draft.body.clone())
            .unwrap_or_default();
        self.dirty = false;
    }

    /// Record an operator edit of the reply text.
    ///
    /// Inputs: `text` — new editor contents. Output: none; `text` replaces
    /// the visible reply and the dirty flag is set until a save is confirmed
    /// through [`sync_editor`] or the editor is reloaded.
    pub fn edit(&mut self, text: String) {
        self.text = text;
        self.dirty = true;
    }

    /// Drop the unsaved edit without discarding the visible text.
    ///
    /// Inputs: none. Output: none; the dirty flag is cleared so the next
    /// [`sync_editor`] rebinds the editor to whatever job is selected. The
    /// text itself is retained until that rebind replaces it (matching the
    /// desktop "discard edit" flow).
    pub fn abandon_edit(&mut self) {
        self.dirty = false;
    }

    /// Whether the editor is bound to a job's current identity and revision.
    ///
    /// Inputs: `job` — job the operator wants to act on. Output: `true` only
    /// for the exact `(id, revision)` pair the editor was loaded for; stale
    /// editors return `false` and can never save or send.
    pub fn bound_to(&self, job: &Job) -> bool {
        editor_binding_matches(job, self.binding.as_ref())
    }
}

/// Keep the editor in sync with the selected job (desktop `sync_view` rule).
///
/// Inputs: `editor` — editor presentation state; `job` — job currently
/// selected in the snapshot. Output: none. A successful save is observed
/// when the editor text equals the job's stored draft for the same message
/// id: the dirty flag clears and the binding adopts the job's current
/// revision (so a failed save keeps the editor dirty and unsavable). A clean
/// editor rebinds to the selected `(id, revision)` and loads the persisted
/// draft. A dirty editor is never rebound: its text is retained and stays
/// unsaveable/unsendable once the job revision moves on.
pub fn sync_editor(editor: &mut EditorState, job: &Job) {
    let key = (job.id.clone(), job.revision);
    let stored = job
        .draft
        .as_ref()
        .map(|draft| draft.body.as_str())
        .unwrap_or("");
    // A failed save must leave the editor dirty and sending disabled: only
    // text equal to the stored draft counts as confirmed.
    if editor.binding.as_ref().is_some_and(|k| k.0 == job.id) && editor.text == stored {
        editor.dirty = false;
        editor.binding = Some(key.clone());
    }
    if editor.binding.as_ref() != Some(&key) && !editor.dirty {
        editor.text = stored.into();
        editor.binding = Some(key);
    }
}

/// Clamp a requested list index into the list's valid bounds.
///
/// Inputs: `index` — requested row index; `len` — number of rows. Output:
/// `Some(i)` where `i` is `index` clamped to the last valid index, or `None`
/// when the list is empty (nothing can be selected).
pub fn clamp_selection(index: usize, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(index.min(len - 1))
    }
}

/// Move the list selection by a signed step, clamped at both edges.
///
/// Inputs: `selected` — current index (`None` when nothing is selected yet);
/// `len` — number of rows; `delta` — signed movement step (`0` clamps only).
/// Output: the new index clamped to `0..len` — movement never wraps at the
/// edges and never leaves the list — or `None` for an empty list. From no
/// selection the first movement enters the list at index `0` regardless of
/// direction; a `0` step keeps `None` as `None`.
pub fn move_selection(selected: Option<usize>, len: usize, delta: isize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let Some(selected) = selected else {
        return if delta == 0 { None } else { Some(0) };
    };
    let base = selected as isize + delta;
    let clamped = base.clamp(0, len as isize - 1);
    Some(clamped as usize)
}

/// Snap a byte offset down to the nearest character boundary.
///
/// Inputs: `text` — editor contents; `cursor` — requested byte offset (may
/// fall inside a multi-byte character). Output: the largest char-boundary
/// offset `<= min(cursor, text.len())`, so slicing helpers never panic.
fn snap_to_boundary(text: &str, cursor: usize) -> usize {
    let mut cursor = cursor.min(text.len());
    while cursor > 0 && !text.is_char_boundary(cursor) {
        cursor -= 1;
    }
    cursor
}

/// Count the words shown in the reply editor.
///
/// Inputs: `text` — editor contents. Output: number of whitespace-separated
/// words (identical to the desktop word count); empty text counts zero.
pub fn word_count(text: &str) -> usize {
    text.split_whitespace().count()
}

/// Move the editor cursor one character left, staying on char boundaries.
///
/// Inputs: `text` — editor contents; `cursor` — byte offset (snapped down to
/// a char boundary first). Output: byte offset of the previous character
/// boundary, clamped at `0` so Backspace at the start is a no-op.
pub fn cursor_left(text: &str, cursor: usize) -> usize {
    let cursor = snap_to_boundary(text, cursor);
    match text[..cursor].char_indices().next_back() {
        Some((offset, _)) => offset,
        None => 0,
    }
}

/// Move the editor cursor one character right, staying on char boundaries.
///
/// Inputs: `text` — editor contents; `cursor` — byte offset (snapped down to
/// a char boundary first). Output: byte offset of the next character
/// boundary, clamped at `text.len()` so the cursor can never split a
/// character.
pub fn cursor_right(text: &str, cursor: usize) -> usize {
    let cursor = snap_to_boundary(text, cursor);
    match text[cursor..].chars().next() {
        Some(ch) => cursor + ch.len_utf8(),
        None => cursor,
    }
}

/// Insert one character at the editor cursor.
///
/// Inputs: `text` — editor contents mutated in place; `cursor` — byte offset
/// (snapped down to a char boundary first); `ch` — character typed by the
/// operator. Output: the new cursor byte offset right after the inserted
/// character.
pub fn editor_insert(text: &mut String, cursor: usize, ch: char) -> usize {
    let cursor = snap_to_boundary(text, cursor);
    text.insert(cursor, ch);
    cursor + ch.len_utf8()
}

/// Delete the character before the editor cursor (Backspace).
///
/// Inputs: `text` — editor contents mutated in place; `cursor` — byte offset
/// (snapped down to a char boundary first). Output: the new cursor byte
/// offset; at the start of the text this is a no-op returning `0`.
pub fn editor_backspace(text: &mut String, cursor: usize) -> usize {
    let cursor = snap_to_boundary(text, cursor);
    let start = cursor_left(text, cursor);
    if start < cursor {
        text.replace_range(start..cursor, "");
    }
    start
}

/// Which review actions the interface offers for the current state.
///
/// Inputs: none (plain struct). Output: per-action enablement; `send` is
/// computed exclusively through the shared [`send_gate_eligible`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActionEnablement {
    /// Save changes is offered (bound, reviewable, idle, no modal, dirty).
    pub save: bool,
    /// Regenerate with local AI is offered (clean editor, never in demo).
    pub regenerate: bool,
    /// Dismiss is offered (clean editor).
    pub dismiss: bool,
    /// Review & send is offered (shared send gate passes).
    pub send: bool,
}

/// Compute review-action enablement from job state and the shared send gate.
///
/// Inputs: `job` — selected job (`None` when nothing is selected); `editor`
/// — editor presentation state; `gate` — presentation-independent send-gate
/// context; `modal_open` — whether a dialog currently covers the workspace.
/// Output: [`ActionEnablement`] where save/regenerate/dismiss require a bound
/// editor on a reviewable job while the worker is idle, and `send` is exactly
/// [`send_gate_eligible`] — no interface-side re-implementation.
pub fn action_enablement(
    job: Option<&Job>,
    editor: &EditorState,
    gate: &SendGateContext<'_>,
    modal_open: bool,
) -> ActionEnablement {
    let bound = job.is_some_and(|job| editor.bound_to(job));
    let reviewable = job.is_some_and(|job| job.state.reviewable());
    let available = bound && reviewable && !gate.busy && !modal_open;
    ActionEnablement {
        save: available && editor.dirty,
        regenerate: available && !editor.dirty && !gate.demo,
        dismiss: available && !editor.dirty,
        send: !modal_open && job.is_some_and(|job| send_gate_eligible(job, gate)),
    }
}

/// Mail-level sending blocks collected for the shared send gate.
///
/// Inputs: `job` — selected job; `account` — configured sending account.
/// Output: reason strings from the pure `mail::hard_blocks` check (identical
/// collection to the desktop UI); a job without a fetched original yields the
/// single block `"Original email is unavailable"`.
pub fn hard_blocks_for(job: &Job, account: &str) -> Vec<String> {
    job.email
        .as_ref()
        .map(|email| hard_blocks(email, account))
        .unwrap_or_else(|| vec!["Original email is unavailable".into()])
}

/// Pending confirm-exact-reply dialog state.
///
/// Inputs: none (plain struct). Output: the job whose exact persisted draft
/// the operator is about to confirm for sending.
#[derive(Clone, Debug)]
pub struct SendConfirmation {
    /// Job whose persisted draft body will be sent verbatim.
    pub job: Job,
}

/// Cancel the confirm-exact-reply dialog.
///
/// Inputs: `state` — dialog state slot mutated in place. Output: `true` when
/// a pending confirmation existed and was cleared; after cancellation no
/// send can result from that dialog.
pub fn cancel_send_confirmation(state: &mut Option<SendConfirmation>) -> bool {
    state.take().is_some()
}

/// Accept the confirm-exact-reply dialog and build the send command.
///
/// Inputs: `state` — dialog state slot mutated in place; `enabled` — whether
/// the dialog's send side is currently allowed (worker idle and not paused,
/// mirroring the desktop modal). Output: the [`Command::Send`] carrying the
/// exact persisted draft's body hash, or `None` when no dialog is open or
/// sending is not currently allowed. On success the dialog state is cleared;
/// on refusal it is kept so the operator can retry or cancel.
pub fn accept_send_confirmation(
    state: &mut Option<SendConfirmation>,
    enabled: bool,
) -> Option<Command> {
    if !enabled {
        return None;
    }
    let confirmation = state.take()?;
    let body = confirmation
        .job
        .draft
        .as_ref()
        .map(|draft| draft.body.as_str())
        .unwrap_or("");
    Some(Command::Send {
        id: confirmation.job.id.clone(),
        revision: confirmation.job.revision,
        body_hash: hash(body),
    })
}

/// Automatic-arm cooldown status shown in the risk-confirmation dialog.
///
/// Inputs: none (plain struct). Output: the visible countdown plus whether
/// the confirmation may be acknowledged yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmGateStatus {
    /// Seconds left on the cooldown; `0` once it has (nearly) elapsed.
    pub remaining_seconds: i64,
    /// Whether the risk confirmation may be acknowledged yet.
    pub confirm_enabled: bool,
}

/// Read the cooldown status of an open Automatic-arm gate.
///
/// Inputs: `gate` — open cooldown gate; `now` — current time. Output:
/// [`ArmGateStatus`]; `confirm_enabled` is `true` only once the full cooldown
/// has elapsed, so the visible countdown can read `0` while the confirmation
/// is still locked (sub-second remainder).
pub fn arm_gate_status(gate: &AutomaticArmGate, now: DateTime<Utc>) -> ArmGateStatus {
    ArmGateStatus {
        remaining_seconds: gate.remaining(now).num_seconds().max(0),
        confirm_enabled: gate.can_confirm(now),
    }
}

/// Acknowledge the Automatic-mode risk confirmation once the cooldown elapsed.
///
/// Inputs: `pending` — open gate slot mutated in place; `now` — current time;
/// `settings` — edited settings copy mutated in place. Output: `true` only
/// when the cooldown has fully elapsed; then the settings are marked
/// `automatic_confirmed` with `automatic_since = now` and the pending gate is
/// cleared. A not-yet-elapsed cooldown leaves everything untouched and can
/// therefore never arm.
pub fn confirm_automatic_arm(
    pending: &mut Option<AutomaticArmGate>,
    now: DateTime<Utc>,
    settings: &mut Settings,
) -> bool {
    let Some(gate) = pending.as_ref() else {
        return false;
    };
    if !gate.can_confirm(now) {
        return false;
    }
    settings.automatic_confirmed = true;
    settings.automatic_since = Some(now);
    *pending = None;
    true
}

/// Cancel the pending Automatic-arm risk confirmation.
///
/// Inputs: `pending` — open gate slot mutated in place. Output: `true` when a
/// pending gate existed and was cleared; settings are never touched, so the
/// operator stays in Human review.
pub fn cancel_automatic_arm(pending: &mut Option<AutomaticArmGate>) -> bool {
    pending.take().is_some()
}

/// Whether quitting needs an explicit unsaved-work confirmation.
///
/// Inputs: `dirty` — whether the editor holds unsaved text; `operation` —
/// current worker operation status. Output: `true` when quitting must be
/// confirmed (unsaved text, or a shutdown-sensitive operation in flight);
/// mirrors the desktop app's close-confirmation rule exactly.
pub fn requires_close_confirmation(dirty: bool, operation: &OperationStatus) -> bool {
    dirty || (operation.state == OperationState::Running && operation.kind.shutdown_sensitive())
}

/// Step the tone picker in the fixed soft-to-harsh order.
///
/// Inputs: `tone` — current tone level; `forward` — `true` steps harsher,
/// `false` steps softer. Output: the adjacent tone, clamped at the ends (no
/// wrap-around past `Professional` or `Insane`).
pub fn cycle_tone(tone: Tone, forward: bool) -> Tone {
    match (tone, forward) {
        (Tone::Professional, true) => Tone::Assertive,
        (Tone::Assertive, true) => Tone::Hardline,
        (Tone::Hardline, true) => Tone::Insane,
        (Tone::Insane, false) => Tone::Hardline,
        (Tone::Hardline, false) => Tone::Assertive,
        (Tone::Assertive, false) => Tone::Professional,
        (Tone::Professional, false) | (Tone::Insane, true) => tone,
    }
}

/// Step the reply-language picker in its fixed order.
///
/// Inputs: `language` — current policy; `forward` — `true` steps toward
/// `English`, `false` toward `Auto`. Output: the adjacent policy, clamped at
/// the ends (no wrap-around).
pub fn cycle_reply_language(language: ReplyLanguage, forward: bool) -> ReplyLanguage {
    match (language, forward) {
        (ReplyLanguage::Auto, true) => ReplyLanguage::English,
        (ReplyLanguage::English, false) => ReplyLanguage::Auto,
        (ReplyLanguage::Auto, false) | (ReplyLanguage::English, true) => language,
    }
}

/// Whether Save settings may issue `Command::Settings` for this copy.
///
/// Inputs: `settings` — edited settings copy. Output: `true` for Human-review
/// mode always; in Automatic mode only when sending is enabled and the risk
/// confirmation was armed (mirrors the desktop save gate).
pub fn settings_save_enabled(settings: &Settings) -> bool {
    settings.mode != Mode::Automatic || (settings.sending_enabled && settings.automatic_confirmed)
}

/// Build the visible reply lines with an optional cursor cell highlighted.
///
/// Inputs: `text` — editor contents; `cursor` — optional byte offset on a
/// char boundary (`None` renders no caret). Output: one [`Line`] per text
/// line; the character under the cursor is rendered reversed (a reversed
/// space when the cursor sits at the end of a line).
fn editor_lines(text: &str, cursor: Option<usize>) -> Vec<Line<'static>> {
    let cursor = cursor.filter(|offset| *offset <= text.len());
    let (cursor_line, cursor_col) = match cursor {
        Some(offset) => {
            let before = &text[..offset];
            let line = before.matches('\n').count();
            let col = before.rsplit('\n').next().unwrap_or("").chars().count();
            (Some(line), col)
        }
        None => (None, 0),
    };
    // A trailing newline (or empty text) opens a final empty editor line the
    // caret can sit on; `lines()` drops it, so restore it explicitly.
    let mut visible: Vec<&str> = text.lines().collect();
    if text.is_empty() || text.ends_with('\n') {
        visible.push("");
    }
    visible
        .into_iter()
        .enumerate()
        .map(|(index, line_text)| {
            if cursor_line == Some(index) {
                let mut chars = line_text.chars();
                let head: String = chars.by_ref().take(cursor_col).collect();
                let at = chars.next();
                let tail: String = chars.collect();
                Line::from(vec![
                    Span::raw(head),
                    Span::styled(
                        at.map(|ch| ch.to_string()).unwrap_or_else(|| " ".into()),
                        Style::default().add_modifier(Modifier::REVERSED),
                    ),
                    Span::raw(tail),
                ])
            } else {
                Line::raw(line_text.to_string())
            }
        })
        .collect()
}

/// Compute a centered overlay rectangle inside `area`.
///
/// Inputs: `percent_x` / `percent_y` — overlay size as percentages of the
/// parent area; `area` — parent rectangle. Output: centered [`Rect`] of at
/// least one cell (used for every dialog and the help overlay).
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

/// Presentation-only terminal application state.
struct Tui {
    /// Background worker owning the core; all mutations flow through it.
    worker: Worker,
    /// Pane currently shown in the main area.
    pane: Pane,
    /// Selection index into `Snapshot::items`, clamped to the list bounds.
    queue_selection: Option<usize>,
    /// Reply editor state (binding, text, dirty flag).
    editor: EditorState,
    /// Whether the Review pane is in text-editing mode.
    editing: bool,
    /// Editor caret byte offset (always on a char boundary).
    editor_cursor: usize,
    /// Vertical scroll offset (lines) of the reply editor.
    editor_scroll: u16,
    /// Last known editor viewport height in lines (for caret-follow scroll).
    editor_view_height: Cell<u16>,
    /// Vertical scroll offset (lines) of the original email body.
    original_scroll: u16,
    /// Vertical scroll offset (lines) of the Activity log.
    activity_scroll: u16,
    /// Whether the "Why this was detected" analysis text is expanded.
    analysis_open: bool,
    /// Cursor row in the Settings pane (index into [`SETTINGS_ROWS`]).
    settings_row: usize,
    /// Edited settings copy persisted via `Command::Settings`.
    settings: Settings,
    /// Whether the settings copy has been loaded from a snapshot yet.
    settings_loaded: bool,
    /// Snapshot settings revision the settings copy mirrors.
    settings_revision: u64,
    /// Snapshot account the editor was last bound for (reset trigger).
    editor_account: String,
    /// Whether the `?` help overlay is open.
    help_open: bool,
    /// Job id queued behind the unsaved-edit switch confirmation.
    pending_select: Option<String>,
    /// Open confirm-exact-reply dialog.
    send_confirmation: Option<SendConfirmation>,
    /// Open Automatic-arm cooldown gate.
    pending_arm: Option<AutomaticArmGate>,
    /// Emergency-stop sentinel reader (injectable for tests).
    emergency: fn() -> crate::emergency::EmergencyStopStatus,
    /// Whether the quit-with-unsaved-work confirmation is open.
    close_confirmation: bool,
    /// Whether the operator confirmed quitting.
    quit: bool,
    /// Local (client-side) validation error shown in the status bar.
    local_error: String,
}

impl Tui {
    /// Construct the terminal application around a running worker.
    ///
    /// Inputs: `worker` — spawned background worker for the workspace.
    /// Output: presentation state on the Queue pane with a clean editor.
    fn new(worker: Worker) -> Self {
        Self {
            worker,
            pane: Pane::Queue,
            queue_selection: None,
            editor: EditorState::default(),
            editing: false,
            editor_cursor: 0,
            editor_scroll: 0,
            editor_view_height: Cell::new(10),
            original_scroll: 0,
            activity_scroll: 0,
            analysis_open: false,
            settings_row: 0,
            settings: Settings::default(),
            settings_loaded: false,
            settings_revision: 0,
            editor_account: String::default(),
            help_open: false,
            pending_select: None,
            send_confirmation: None,
            pending_arm: None,
            emergency: crate::emergency::status_fail_closed,
            close_confirmation: false,
            quit: false,
            local_error: String::default(),
        }
    }

    /// Whether any modal dialog currently covers the workspace.
    ///
    /// Inputs: none. Output: `true` while a confirmation dialog (unsaved-edit
    /// switch, confirm-exact-reply, Automatic arm, or quit confirmation) is
    /// open; panes ignore navigation keys while this holds.
    fn modal_open(&self) -> bool {
        self.pending_select.is_some()
            || self.send_confirmation.is_some()
            || self.pending_arm.is_some()
            || self.close_confirmation
    }

    /// Mirror snapshot changes into the presentation state.
    ///
    /// Inputs: `s` — latest [`Snapshot`] from the worker. Output: none; the
    /// queue selection is clamped to the (possibly shrunken) item list, the
    /// settings copy reloads when the snapshot's settings revision changes,
    /// enterprise policy overrides are applied to the local copy, and the
    /// editor follows the desktop [`sync_editor`] binding rules.
    fn sync_view(&mut self, s: &Snapshot) {
        self.queue_selection = move_selection(self.queue_selection, s.items.len(), 0);
        if s.initialized && self.editor_account != s.account {
            self.editor_account.clone_from(&s.account);
            self.editor = EditorState::default();
            self.editing = false;
            self.pending_select = None;
            self.send_confirmation = None;
        }
        if s.initialized && (!self.settings_loaded || s.settings_revision != self.settings_revision)
        {
            self.settings.clone_from(&s.settings);
            self.settings_revision = s.settings_revision;
            self.settings_loaded = true;
        }
        if s.enterprise_policy.force_human_review || s.enterprise_policy.prohibit_sending {
            self.settings.mode = Mode::HumanReview;
        }
        if s.enterprise_policy.prohibit_sending {
            self.settings.sending_enabled = false;
        }
        if let Some(job) = &s.selected {
            sync_editor(&mut self.editor, job);
            if !self.editor.dirty {
                self.editing = false;
            }
        }
    }

    /// Request selecting another job, guarding unsaved edits.
    ///
    /// Inputs: `id` — job id the operator wants to open. Output: none; with
    /// a dirty editor the switch is parked in the unsaved-edit confirmation
    /// dialog, otherwise `Command::Select` is issued (desktop `select` rule).
    fn request_select(&mut self, id: String) {
        if self.modal_open() {
            return;
        }
        if self.editor.dirty {
            self.pending_select = Some(id);
        } else {
            self.worker.command(Command::Select(id));
        }
    }

    /// Collect the shared send-gate context and compute action enablement.
    ///
    /// Inputs: `job` — selected job (`None` when nothing is selected); `s` —
    /// latest snapshot. Output: [`ActionEnablement`] built from the shared
    /// [`send_gate_eligible`] gate with the same context fields the desktop
    /// GUI supplies (editor text/binding/dirty, mail hard blocks, busy,
    /// sending flag, demo, paused).
    fn review_enablement(&self, job: Option<&Job>, s: &Snapshot) -> ActionEnablement {
        let blocks = job
            .map(|job| hard_blocks_for(job, &s.account))
            .unwrap_or_default();
        let gate = SendGateContext {
            editor_text: &self.editor.text,
            editor_bound: job.is_some_and(|job| self.editor.bound_to(job)),
            dirty: self.editor.dirty,
            hard_blocks: &blocks,
            busy: !s.busy.is_empty(),
            sending_enabled: s.settings.sending_enabled,
            demo: s.demo,
            paused: self.worker.paused.load(Ordering::SeqCst),
        };
        action_enablement(job, &self.editor, &gate, self.modal_open())
    }

    /// Dispatch one key event to dialogs first, then to the active pane.
    ///
    /// Inputs: `key` — key event from the terminal; `s` — latest snapshot.
    /// Output: none; the presentation state is mutated and worker commands
    /// are issued through `self.worker.command` only.
    fn handle_key(&mut self, key: KeyEvent, s: &Snapshot) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        if self.handle_dialog_key(key, s) {
            return;
        }
        if self.help_open {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
            ) {
                self.help_open = false;
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.request_quit(s),
            KeyCode::Char('?') => self.help_open = true,
            KeyCode::Char('p') => {
                let paused = self.worker.paused.load(Ordering::SeqCst);
                self.worker.paused.store(!paused, Ordering::SeqCst);
            }
            KeyCode::Char('1') => self.pane = Pane::Queue,
            KeyCode::Char('2') => self.pane = Pane::Review,
            KeyCode::Char('3') => self.pane = Pane::Activity,
            KeyCode::Char('4') => self.pane = Pane::Settings,
            KeyCode::Tab => {
                self.pane = match self.pane {
                    Pane::Queue => Pane::Review,
                    Pane::Review => Pane::Activity,
                    Pane::Activity => Pane::Settings,
                    Pane::Settings => Pane::Queue,
                };
            }
            other => match self.pane {
                Pane::Queue => self.handle_queue_key(other, s),
                Pane::Review => self.handle_review_key(other, s),
                Pane::Activity => self.handle_activity_key(other),
                Pane::Settings => self.handle_settings_key(other, s),
            },
        }
    }

    /// Handle keys while a modal dialog is open.
    ///
    /// Inputs: `key` — key event; `s` — latest snapshot. Output: `true` when
    /// a dialog consumed the key (the pane must not see it). Dialog priority
    /// is quit confirmation, confirm-exact-reply, Automatic arm, unsaved-edit
    /// switch — matching the desktop modal stack.
    fn handle_dialog_key(&mut self, key: KeyEvent, s: &Snapshot) -> bool {
        if self.close_confirmation {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.close_confirmation = false;
                    self.quit = true;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.close_confirmation = false;
                }
                _ => {}
            }
            return true;
        }
        if self.send_confirmation.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let enabled = s.busy.is_empty() && !self.worker.paused.load(Ordering::SeqCst);
                    if let Some(command) =
                        accept_send_confirmation(&mut self.send_confirmation, enabled)
                    {
                        self.worker.command(command);
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    cancel_send_confirmation(&mut self.send_confirmation);
                }
                _ => {}
            }
            return true;
        }
        if self.pending_arm.is_some() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    confirm_automatic_arm(&mut self.pending_arm, Utc::now(), &mut self.settings);
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    cancel_automatic_arm(&mut self.pending_arm);
                }
                _ => {}
            }
            return true;
        }
        if let Some(id) = self.pending_select.as_ref() {
            let id = id.clone();
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.pending_select = None;
                    self.editor.abandon_edit();
                    self.worker.command(Command::Select(id));
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.pending_select = None;
                }
                _ => {}
            }
            return true;
        }
        false
    }

    /// Start the quit flow, mirroring the desktop close-confirmation rule.
    ///
    /// Inputs: `s` — latest snapshot. Output: none; quits immediately when
    /// nothing would be lost, otherwise opens the unsaved-work confirmation
    /// (which also covers shutdown-sensitive operations in flight).
    fn request_quit(&mut self, s: &Snapshot) {
        if requires_close_confirmation(self.editor.dirty, &s.operation) {
            self.close_confirmation = true;
        } else {
            self.quit = true;
        }
    }

    /// Handle Queue-pane keys.
    ///
    /// Inputs: `key` — key event (dialog keys already filtered out); `s` —
    /// latest snapshot. Output: none; moves the clamped selection, opens a
    /// job, or issues Refresh / CheckNow commands.
    fn handle_queue_key(&mut self, key: KeyCode, s: &Snapshot) {
        let len = s.items.len();
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                self.queue_selection = move_selection(self.queue_selection, len, -1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.queue_selection = move_selection(self.queue_selection, len, 1);
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.queue_selection = clamp_selection(0, len);
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.queue_selection = clamp_selection(len.saturating_sub(1), len);
            }
            KeyCode::Enter => {
                if let Some(job) = self.queue_selection.and_then(|index| s.items.get(index)) {
                    self.request_select(job.id.clone());
                }
            }
            KeyCode::Char('r') => self.worker.command(Command::Refresh),
            KeyCode::Char('c') => self.worker.command(Command::CheckNow),
            _ => {}
        }
    }

    /// Handle Review-pane keys in normal (non-editing) mode.
    ///
    /// Inputs: `key` — key event (dialog keys already filtered out); `s` —
    /// latest snapshot. Output: none; drives the editor, the analysis
    /// expander and the review actions, with every action enablement computed
    /// through [`Self::review_enablement`].
    fn handle_review_key(&mut self, key: KeyCode, s: &Snapshot) {
        if self.editing {
            self.handle_editor_key(key);
            return;
        }
        let job = s.selected.as_ref();
        let enablement = self.review_enablement(job, s);
        match key {
            KeyCode::Up => self.original_scroll = self.original_scroll.saturating_sub(1),
            KeyCode::Down => self.original_scroll = self.original_scroll.saturating_add(1),
            KeyCode::PageUp => self.editor_scroll = self.editor_scroll.saturating_sub(10),
            KeyCode::PageDown => self.editor_scroll = self.editor_scroll.saturating_add(10),
            KeyCode::Char('a') => self.analysis_open = !self.analysis_open,
            _ => self.handle_review_action(key, s, job, &enablement),
        }
    }

    /// Handle the review editing keys: enter the editor, save and regenerate.
    ///
    /// Inputs: `key` — pressed key; `s` — latest snapshot; `job` — the
    /// selected job; `enablement` — computed review action enablement.
    /// Output: none; mutates the editor and issues worker commands.
    fn handle_review_action(
        &mut self,
        key: KeyCode,
        s: &Snapshot,
        job: Option<&Job>,
        enablement: &ActionEnablement,
    ) {
        match key {
            KeyCode::Char('e') | KeyCode::Char('i') => {
                if job.is_some_and(|job| {
                    self.editor.bound_to(job)
                        && job.state.reviewable()
                        && s.busy.is_empty()
                        && !self.modal_open()
                }) {
                    self.editing = true;
                    self.editor_cursor = self.editor.text.len();
                }
            }
            KeyCode::Char('s') => {
                if enablement.save
                    && let Some(job) = job
                {
                    match validate_draft(&self.editor.text) {
                        Ok(()) => {
                            self.local_error.clear();
                            self.worker.command(Command::Edit {
                                id: job.id.clone(),
                                revision: job.revision,
                                body: self.editor.text.clone(),
                            });
                        }
                        Err(error) => self.local_error = error.to_string(),
                    }
                }
            }
            KeyCode::Char('g') => {
                if enablement.regenerate
                    && let Some(job) = job
                {
                    self.worker.command(Command::Regenerate {
                        id: job.id.clone(),
                        revision: job.revision,
                    });
                }
            }
            _ => self.handle_review_dispatch_keys(key, job, enablement),
        }
    }

    /// Handle the review dismissal, send and discard keys.
    ///
    /// Inputs: `key` — pressed key; `job` — the selected job; `enablement` —
    /// computed review action enablement. Output: none; mutates the editor
    /// and issues worker commands.
    fn handle_review_dispatch_keys(
        &mut self,
        key: KeyCode,
        job: Option<&Job>,
        enablement: &ActionEnablement,
    ) {
        match key {
            KeyCode::Char('d') => {
                if enablement.dismiss
                    && let Some(job) = job
                {
                    self.worker.command(Command::Dismiss {
                        id: job.id.clone(),
                        revision: job.revision,
                    });
                }
            }
            KeyCode::Char('w') => {
                if enablement.send
                    && let Some(job) = job
                {
                    self.send_confirmation = Some(SendConfirmation { job: job.clone() });
                }
            }
            KeyCode::Char('D') => {
                if self.editor.dirty
                    && let Some(job) = job
                {
                    self.editor.load(job);
                    self.editing = false;
                    self.local_error.clear();
                }
            }
            _ => {}
        }
    }

    /// Handle keys while the Review-pane editor is in editing mode.
    ///
    /// Inputs: `key` — key event. Output: none; typing mutates the editor
    /// text through the pure cursor/insert helpers (which set the dirty
    /// flag), and `Esc` returns to normal mode.
    fn handle_editor_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Esc => self.editing = false,
            KeyCode::Left => {
                self.editor_cursor = cursor_left(&self.editor.text, self.editor_cursor)
            }
            KeyCode::Right => {
                self.editor_cursor = cursor_right(&self.editor.text, self.editor_cursor)
            }
            KeyCode::Home => self.editor_cursor = 0,
            KeyCode::End => self.editor_cursor = self.editor.text.len(),
            KeyCode::Backspace => {
                let mut text = self.editor.text.clone();
                self.editor_cursor = editor_backspace(&mut text, self.editor_cursor);
                self.editor.edit(text);
            }
            KeyCode::Enter => {
                let mut text = self.editor.text.clone();
                self.editor_cursor = editor_insert(&mut text, self.editor_cursor, '\n');
                self.editor.edit(text);
            }
            KeyCode::Char(ch) => {
                let mut text = self.editor.text.clone();
                self.editor_cursor = editor_insert(&mut text, self.editor_cursor, ch);
                self.editor.edit(text);
            }
            _ => {}
        }
    }

    /// Handle Activity-pane keys.
    ///
    /// Inputs: `key` — key event. Output: none; scrolls the audit event log
    /// without ever mutating worker state.
    fn handle_activity_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up => self.activity_scroll = self.activity_scroll.saturating_sub(1),
            KeyCode::Down => self.activity_scroll = self.activity_scroll.saturating_add(1),
            KeyCode::PageUp => self.activity_scroll = self.activity_scroll.saturating_sub(10),
            KeyCode::PageDown => self.activity_scroll = self.activity_scroll.saturating_add(10),
            _ => {}
        }
    }

    /// Handle Settings-pane keys.
    ///
    /// Inputs: `key` — key event; `s` — latest snapshot. Output: none; moves
    /// the row cursor through [`SETTINGS_ROWS`] and edits the local settings
    /// copy (tone/language pickers, mode, sending toggle, Automatic arm and
    /// disable-Automatic). Only the Save row persists, via
    /// `Command::Settings`; arming opens the cooldown-gated risk dialog.
    fn handle_settings_key(&mut self, key: KeyCode, s: &Snapshot) {
        match key {
            KeyCode::Up => {
                self.settings_row =
                    move_selection(Some(self.settings_row), SETTINGS_ROWS.len(), -1).unwrap_or(0);
            }
            KeyCode::Down => {
                self.settings_row =
                    move_selection(Some(self.settings_row), SETTINGS_ROWS.len(), 1).unwrap_or(0);
            }
            _ => {
                let row = SETTINGS_ROWS
                    .get(self.settings_row)
                    .copied()
                    .unwrap_or(SettingsRow::Save);
                let forward = matches!(key, KeyCode::Right | KeyCode::Enter | KeyCode::Char('l'));
                let backward = matches!(key, KeyCode::Left | KeyCode::Char('h'));
                if !forward && !backward {
                    return;
                }
                match row {
                    SettingsRow::Mode => {
                        let automatic_allowed = !s.enterprise_policy.force_human_review
                            && !s.enterprise_policy.prohibit_sending;
                        self.settings.mode = match (self.settings.mode, forward) {
                            (Mode::HumanReview, true) if automatic_allowed => Mode::Automatic,
                            (Mode::Automatic, false) => Mode::HumanReview,
                            (current, _) => current,
                        };
                    }
                    SettingsRow::Tone => {
                        self.settings.tone = cycle_tone(self.settings.tone, forward);
                    }
                    SettingsRow::ReplyLanguage => {
                        self.settings.reply_language =
                            cycle_reply_language(self.settings.reply_language, forward);
                    }
                    SettingsRow::SendingEnabled => {
                        if !s.enterprise_policy.prohibit_sending {
                            self.settings.sending_enabled = !self.settings.sending_enabled;
                        }
                    }
                    SettingsRow::AutomaticArm => {
                        if self.settings.automatic_confirmed {
                            // Disable-Automatic button: return to Human review.
                            self.settings.automatic_confirmed = false;
                            self.settings.automatic_since = None;
                            self.pending_arm = None;
                        } else if self.settings.mode == Mode::Automatic
                            && self.pending_arm.is_none()
                        {
                            self.pending_arm = Some(AutomaticArmGate::open(Utc::now()));
                        }
                    }
                    SettingsRow::Save => {
                        if s.busy.is_empty() && settings_save_enabled(&self.settings) {
                            self.local_error.clear();
                            self.worker
                                .command(Command::Settings(Box::new(self.settings.clone())));
                        }
                    }
                }
            }
        }
    }
}

/// Run the interactive terminal interface over a background worker.
///
/// Inputs: `worker` — spawned [`Worker`] for the workspace (demo or live).
/// Output: `Ok(())` when the operator quits; the terminal leaves raw mode
/// and the alternate screen on every exit path, and the worker is asked to
/// stop before the process returns. The interface itself never opens the
/// database or Gmail: it renders [`Snapshot`]s and issues [`Command`]s.
pub fn run(worker: Worker) -> Result<()> {
    let tui = Tui::new(worker);
    let restore = ratatui::try_restore;
    let mut keys: fn() -> Result<Option<KeyEvent>> = poll_key;
    run_session(ratatui::try_init()?, tui, restore, &mut keys)
}

/// Run one interactive terminal session around the presentation state.
///
/// Inputs: `terminal` — initialized ratatui terminal; `tui` — presentation
/// state mutated by events; `restore` — terminal teardown to run on every
/// exit path; `next_key` — event pump returning at most one key press per
/// call. Output: `Ok(())` once the operator confirmed the quit; `Err` on
/// terminal I/O failure. The worker is asked to stop before returning and
/// the terminal is restored through `restore`.
fn run_session<B: ratatui::backend::Backend>(
    mut terminal: ratatui::Terminal<B>,
    mut tui: Tui,
    restore: fn() -> std::io::Result<()>,
    next_key: &mut dyn FnMut() -> Result<Option<KeyEvent>>,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let outcome = run_loop(&mut terminal, &mut tui, next_key);
    tui.worker.request_stop();
    restore()?;
    outcome
}

/// Wait briefly for one key event from the real terminal.
///
/// Inputs: none. Output: `Ok(Some(key))` for a key press, `Ok(None)` when
/// the 200 ms window passed without one (so countdowns and busy states keep
/// refreshing), or `Err` on terminal I/O failure.
fn poll_key() -> Result<Option<KeyEvent>> {
    poll_next_key(poll, read, Duration::from_millis(200))
}

/// Wait for one key event from an injected terminal event source.
///
/// Inputs: `ready` — poll function; `read` — event read function; `timeout`
/// — wait budget. Output: `Some(key)` when a key event arrives within the
/// budget, `None` on timeout or a non-key event. Terminal errors propagate.
fn poll_next_key<R, D>(mut ready: R, mut read: D, timeout: Duration) -> Result<Option<KeyEvent>>
where
    R: FnMut(Duration) -> std::io::Result<bool>,
    D: FnMut() -> std::io::Result<Event>,
{
    Ok(
        if ready(timeout)?
            && let Event::Key(key) = read()?
        {
            Some(key)
        } else {
            None
        },
    )
}

/// Draw and event-loop body of [`run`].
///
/// Inputs: `terminal` — initialized ratatui terminal; `tui` — presentation
/// state mutated by events; `next_key` — event pump. Output: `Ok(())` once
/// the operator confirmed the quit; `Err` on terminal I/O failure. Each
/// iteration renders the latest snapshot, then asks the pump for a key.
fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut ratatui::Terminal<B>,
    tui: &mut Tui,
    next_key: &mut dyn FnMut() -> Result<Option<KeyEvent>>,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    loop {
        let snapshot = tui.worker.view();
        tui.sync_view(&snapshot);
        terminal.draw(|frame| draw(frame, tui, &snapshot))?;
        if tui.quit {
            return Ok(());
        }
        if let Some(key) = next_key()? {
            tui.handle_key(key, &snapshot);
        }
    }
}

/// Draw one full frame: active pane plus the status bar and overlays.
///
/// Inputs: `frame` — ratatui frame to render into; `tui` — presentation
/// state; `s` — latest snapshot. Output: none; renders the active pane on
/// top, the status bar at the bottom, and any open dialog/help overlay over
/// everything else.
fn draw(frame: &mut Frame, tui: &Tui, s: &Snapshot) {
    let area = frame.area();
    let chunks = Layout::vertical([Constraint::Min(5), Constraint::Length(3)]).split(area);
    match tui.pane {
        Pane::Queue => draw_queue(frame, chunks[0], tui, s),
        Pane::Review => draw_review(frame, chunks[0], tui, s),
        Pane::Activity => draw_activity(frame, chunks[0], tui, s),
        Pane::Settings => draw_settings(frame, chunks[0], tui, s),
    }
    draw_status(frame, chunks[1], tui, s);
    if tui.help_open {
        draw_help(frame);
    } else if tui.close_confirmation {
        draw_close_confirmation(frame, tui, s);
    } else if let Some(confirmation) = tui.send_confirmation.as_ref() {
        let send_ready = s.busy.is_empty() && !tui.worker.paused.load(Ordering::SeqCst);
        draw_confirm_send(frame, confirmation, send_ready);
    } else if let Some(gate) = tui.pending_arm.as_ref() {
        draw_arm_dialog(frame, gate);
    } else if tui.pending_select.is_some() {
        draw_pending_select(frame);
    }
}

/// Draw the Queue pane: the job list with per-job state and flags.
///
/// Inputs: `frame` — frame to render into; `area` — pane rectangle; `tui` —
/// presentation state (selection index); `s` — latest snapshot. Output: none;
/// the list highlights the clamped selection and shows one line per job with
/// its state label, subject and any flags.
fn draw_queue(frame: &mut Frame, area: Rect, tui: &Tui, s: &Snapshot) {
    let items: Vec<ListItem> = s
        .items
        .iter()
        .map(|job| {
            let subject = job
                .email
                .as_ref()
                .map(|email| email.subject.as_str())
                .unwrap_or("(original not fetched)");
            let flags = if job.flags.is_empty() {
                String::default()
            } else {
                format!("  ! {}", job.flags.join(" · "))
            };
            ListItem::new(Line::raw(format!(
                "[{}] {}{}",
                job.state.label(),
                subject,
                flags
            )))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Queue (Enter open · r refresh · c check mail · j/k move)"),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    let mut state = ListState::default();
    state.select(tui.queue_selection);
    frame.render_stateful_widget(list, area, &mut state);
}

/// Draw the Review pane: original email left, editable reply right.
///
/// Inputs: `frame` — frame to render into; `area` — pane rectangle; `tui` —
/// presentation state (editor, scroll offsets, analysis expander); `s` —
/// latest snapshot. Output: none; renders the original email, the reply
/// editor with word count and unsaved indicator, and the analysis expander
/// text, flags, send blocks and action hints below the columns. The editor
/// viewport height is cached for caret-follow scrolling.
fn draw_review(frame: &mut Frame, area: Rect, tui: &Tui, s: &Snapshot) {
    if s.settings.mode != Mode::HumanReview {
        let notice = Paragraph::new(vec![
            Line::raw("Review is disabled in Automatic mode. Change the mode in Settings."),
            Line::raw("Press 4 to open Settings, or 1 to return to the Queue."),
        ])
        .block(Block::default().borders(Borders::ALL).title("Review"));
        frame.render_widget(notice, area);
        return;
    }
    let bottom_lines = review_footer_lines(tui, s);
    let bottom_height = (bottom_lines.len() as u16 + 2).min(area.height.saturating_sub(6));
    let rows =
        Layout::vertical([Constraint::Min(6), Constraint::Length(bottom_height)]).split(area);
    let columns =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(rows[0]);

    let Some(job) = s.selected.as_ref() else {
        let empty = Paragraph::new(vec![
            Line::raw("Select a message"),
            Line::raw("Your original email and editable response will appear here."),
        ])
        .block(Block::default().borders(Borders::ALL).title("Review"));
        frame.render_widget(empty, rows[0]);
        return;
    };

    // Left: the original email, read-only.
    let mut original = vec![
        Line::from(Span::styled(
            job.email
                .as_ref()
                .map(|email| email.subject.clone())
                .unwrap_or_else(|| "(original not fetched)".into()),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::raw(
            job.email
                .as_ref()
                .map(|email| email.from.clone())
                .unwrap_or_default(),
        ),
    ];
    if let Some(email) = &job.email {
        original.push(Line::raw(
            email
                .received_at
                .with_timezone(&chrono::Local)
                .format("%d %b %Y · %H:%M")
                .to_string(),
        ));
    }
    original.push(Line::raw(""));
    original.extend(
        job.email
            .as_ref()
            .map(|email| {
                email
                    .text
                    .lines()
                    .map(|line| Line::raw(line.to_string()))
                    .collect::<Vec<Line>>()
            })
            .unwrap_or_default(),
    );
    let original_widget = Paragraph::new(original)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("ORIGINAL EMAIL (Up/Down scroll)"),
        )
        .scroll((tui.original_scroll, 0));
    frame.render_widget(original_widget, columns[0]);

    // Right: the editable reply with word count and unsaved indicator.
    let editor_area = columns[1];
    let editor_block = Block::default()
        .borders(Borders::ALL)
        .title(Line::raw(format!(
            "REPLY · {} words{}{}",
            word_count(&tui.editor.text),
            if tui.editing { " · editing" } else { "" },
            if tui.editor.dirty { " · Unsaved" } else { "" }
        )));
    let cursor = tui.editing.then_some(tui.editor_cursor);
    let editor_widget = Paragraph::new(editor_lines(&tui.editor.text, cursor))
        .block(editor_block)
        .scroll((tui.editor_scroll, 0));
    frame.render_widget(editor_widget, editor_area);
    tui.editor_view_height
        .set(editor_area.height.saturating_sub(2).max(1));

    // Below: analysis expander text, flags, send blocks and action hints.
    let footer = Paragraph::new(bottom_lines)
        .block(Block::default().borders(Borders::ALL).title("Details"))
        .wrap(Wrap { trim: false });
    frame.render_widget(footer, rows[1]);
}

/// Build the Review-pane footer lines (analysis, flags, blocks, hints).
///
/// Inputs: `tui` — presentation state (analysis expander, local error); `s` —
/// latest snapshot. Output: footer [`Line`]s — the "Why this was detected"
/// analysis text when expanded, every job flag, any mail send blocks, the
/// local validation error, and the key hints for the review actions.
fn review_footer_lines(tui: &Tui, s: &Snapshot) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(job) = s.selected.as_ref() {
        if tui.analysis_open {
            if let Some(analysis) = &job.analysis {
                lines.push(Line::from(Span::styled(
                    "Why this was detected",
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::raw(analysis.verdict.explanation.clone()));
                lines.push(Line::raw(format!(
                    "Evidence: {}",
                    analysis.verdict.evidence
                )));
                lines.push(Line::raw(format!(
                    "Model score: {}/100 (not a calibrated probability)",
                    analysis.verdict.confidence
                )));
                if let Some(verification) = &analysis.verification {
                    lines.push(Line::raw(format!("Reply audit: {}", verification.reason)));
                }
            } else {
                lines.push(Line::raw("No analysis is stored for this message."));
            }
        }
        for flag in &job.flags {
            lines.push(Line::from(Span::styled(
                flag.clone(),
                Style::default().fg(Color::Yellow),
            )));
        }
        let blocks = hard_blocks_for(job, &s.account);
        if !blocks.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("Sending blocked: {}", blocks.join("; ")),
                Style::default().fg(Color::Yellow),
            )));
        }
    }
    if !tui.local_error.is_empty() {
        lines.push(Line::from(Span::styled(
            tui.local_error.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    lines.push(Line::raw(
        "e edit · s save · g regenerate · d dismiss · w review & send · a analysis · D discard unsaved",
    ));
    lines
}

/// Draw the Activity pane: the audit event log.
///
/// Inputs: `frame` — frame to render into; `area` — pane rectangle; `tui` —
/// presentation state (scroll offset); `s` — latest snapshot. Output: none;
/// renders one line per audit event with timestamp, kind and detail.
fn draw_activity(frame: &mut Frame, area: Rect, tui: &Tui, s: &Snapshot) {
    let lines: Vec<Line> = s
        .events
        .iter()
        .map(|event| {
            Line::raw(format!(
                "{} · {} · {}",
                event
                    .at
                    .with_timezone(&chrono::Local)
                    .format("%d %b %Y · %H:%M:%S"),
                event.kind,
                event.detail
            ))
        })
        .collect();
    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Activity (Up/Down · PgUp/PgDn scroll)"),
        )
        .scroll((tui.activity_scroll, 0));
    frame.render_widget(widget, area);
}

/// Draw the Settings pane: mode, tone, language, arming and save rows.
///
/// Inputs: `frame` — frame to render into; `area` — pane rectangle; `tui` —
/// presentation state (row cursor, edited settings copy, pending arm gate);
/// `s` — latest snapshot. Output: none; highlights the focused row and shows
/// the Automatic risk text plus the arm/disable affordance and countdown
/// state for the `AutomaticArm` row.
fn draw_settings(frame: &mut Frame, area: Rect, tui: &Tui, s: &Snapshot) {
    let mut lines = Vec::new();
    for (index, row) in SETTINGS_ROWS.iter().enumerate() {
        let selected = index == tui.settings_row;
        let marker = if selected { "> " } else { "  " };
        let text = match row {
            SettingsRow::Mode => format!("Reply mode: {}", tui.settings.mode.label()),
            SettingsRow::Tone => format!("Reply tone: {}", tui.settings.tone.label()),
            SettingsRow::ReplyLanguage => {
                format!("Reply language: {}", tui.settings.reply_language.label())
            }
            SettingsRow::SendingEnabled => format!(
                "Enable sending from this application: {}",
                if tui.settings.sending_enabled {
                    "On"
                } else {
                    "Off"
                }
            ),
            SettingsRow::AutomaticArm => {
                if tui.settings.automatic_confirmed {
                    "Disable Automatic mode and return to Human review".to_string()
                } else {
                    "Enable Automatic mode (requires a deliberate risk confirmation)".to_string()
                }
            }
            SettingsRow::Save => "Save settings (persist the changes above)".to_string(),
        };
        let style = if selected {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(format!("{marker}{text}"), style)));
    }
    lines.push(Line::raw(""));
    if tui.settings.mode == Mode::Automatic {
        lines.push(Line::from(Span::styled(
            "Warning: in Automatic mode the AI sends replies without your review.",
            Style::default().fg(Color::Yellow),
        )));
        lines.push(Line::from(Span::styled(
            format!(
                "Hard unattended safety ceiling: at most {} reply attempts to the same normalized recipient mailbox in any rolling 24 hours. Human Review is the only override path.",
                crate::config::AUTOMATIC_RECIPIENT_ATTEMPT_LIMIT_24H
            ),
            Style::default().fg(Color::Yellow),
        )));
    }
    if let Some(gate) = tui.pending_arm.as_ref() {
        let status = arm_gate_status(gate, Utc::now());
        lines.push(Line::raw(format!(
            "Automatic-arm confirmation is open: unlocks in {} second(s).",
            status.remaining_seconds
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::raw(
        "Left/Right or h/l change value · Enter confirms · 1-4 switch panes · ? help",
    ));
    if s.demo {
        lines.push(Line::from(Span::styled(
            "SYNTHETIC DEMO · settings changes are not persisted to a live mailbox",
            Style::default().fg(Color::Yellow),
        )));
    }
    let widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Settings"))
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

/// Draw the status bar (busy, pause, demo, notices, errors).
///
/// Inputs: `frame` — frame to render into; `area` — status-bar rectangle;
/// `tui` — presentation state (local error); `s` — latest snapshot. Output:
/// none; shows the worker's busy/notice/error text plus the pause and demo
/// badges, identical in meaning to the desktop status bar.
fn draw_status(frame: &mut Frame, area: Rect, tui: &Tui, s: &Snapshot) {
    let mut lines = Vec::new();
    let mut top = Vec::new();
    if !s.busy.is_empty() {
        top.push(Span::styled(
            format!("Working: {}", s.busy),
            Style::default().fg(Color::Cyan),
        ));
    } else if tui.worker.paused.load(Ordering::SeqCst) {
        top.push(Span::styled("PAUSED", Style::default().fg(Color::Yellow)));
    } else {
        top.push(Span::styled(
            "LOCAL WORKSPACE",
            Style::default().fg(Color::Green),
        ));
    }
    if !s.notice.is_empty() {
        top.push(Span::raw(format!("  {}", s.notice)));
    }
    if s.demo {
        top.push(Span::styled(
            "  SYNTHETIC DEMO · NO LIVE EMAIL",
            Style::default().fg(Color::Yellow),
        ));
    }
    if (tui.emergency)().active {
        top.push(Span::styled(
            "  ENTERPRISE EMERGENCY STOP · OUTBOUND EMAIL BLOCKED",
            Style::default().fg(Color::Red),
        ));
    }
    lines.push(Line::from(top));
    if !s.error.is_empty() {
        lines.push(Line::from(Span::styled(
            s.error.clone(),
            Style::default().fg(Color::Red),
        )));
    } else if !tui.local_error.is_empty() {
        lines.push(Line::from(Span::styled(
            tui.local_error.clone(),
            Style::default().fg(Color::Red),
        )));
    } else {
        lines.push(Line::raw("q quit · ? help · p pause/resume dispatch"));
    }
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

/// Draw the `?` help overlay.
///
/// Inputs: `frame` — frame to render into. Output: none; a centered keymap
/// card over a cleared area; `?` or `Esc` closes it again.
fn draw_help(frame: &mut Frame) {
    let area = centered_rect(62, 72, frame.area());
    frame.render_widget(Clear, area);
    let help = Paragraph::new(vec![
        Line::from(Span::styled(
            "Keys",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::raw("1 Queue · 2 Review · 3 Activity · 4 Settings · Tab cycles panes"),
        Line::raw("q quit (confirms unsaved work) · ? toggle help · p pause/resume dispatch"),
        Line::raw("Esc closes dialogs and overlays"),
        Line::raw(""),
        Line::from(Span::styled(
            "Queue",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::raw("j/k or Up/Down move · g/G first/last · Enter open job"),
        Line::raw("r refresh · c check email now"),
        Line::raw(""),
        Line::from(Span::styled(
            "Review",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::raw("e or i edit reply · Esc leave editor · s save changes"),
        Line::raw("g regenerate with local AI · d dismiss · w review & send"),
        Line::raw("a toggle analysis · D discard unsaved text & reload"),
        Line::raw("Up/Down scroll the original · PgUp/PgDn scroll the editor"),
        Line::raw(""),
        Line::from(Span::styled(
            "Settings",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::raw("Up/Down rows · Left/Right or h/l change value · Enter confirm"),
        Line::raw("Automatic arming shows a 30-second risk countdown you cannot skip."),
        Line::raw(""),
        Line::raw("Sending always requires the confirm-exact-reply dialog."),
        Line::raw("The interface issues commands and renders snapshots only."),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Help (Esc to close)"),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(help, area);
}

/// Draw the mandatory confirm-exact-reply dialog.
///
/// Inputs: `frame` — frame to render into; `tui` — presentation state (the
/// pending [`SendConfirmation`]); `s` — latest snapshot. Output: none; shows
/// the recipient, subject and the exact persisted draft body plus the
/// irreversibility warning. `y` sends through `Command::Send`, `n`/`Esc`
/// cancels and clears the dialog.
fn draw_confirm_send(frame: &mut Frame, confirmation: &SendConfirmation, send_ready: bool) {
    let job = &confirmation.job;
    let area = centered_rect(64, 74, frame.area());
    frame.render_widget(Clear, area);
    let mut lines = vec![Line::from(Span::styled(
        "Confirm this exact reply",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    if let Some(email) = &job.email {
        lines.push(Line::raw(format!(
            "To: {}",
            email
                .recipient()
                .unwrap_or_else(|_| "Invalid recipient".into())
        )));
        lines.push(Line::raw(format!("Subject: {}", email.subject)));
    }
    lines.push(Line::raw(""));
    let body = job
        .draft
        .as_ref()
        .map(|draft| draft.body.as_str())
        .unwrap_or("");
    lines.extend(body.lines().map(|line| Line::raw(line.to_string())));
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "Sending cannot be undone by this application. Gmail and the current conversation will be rechecked first.",
        Style::default().fg(Color::Yellow),
    )));
    lines.push(Line::raw(format!(
        "y/Enter send this reply now{} · n/Esc cancel",
        if send_ready {
            ""
        } else {
            " (blocked: worker busy or paused)"
        }
    )));
    let widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

/// Draw the Automatic-arm risk-confirmation dialog with visible countdown.
///
/// Inputs: `frame` — frame to render into; `tui` — presentation state (the
/// open [`AutomaticArmGate`]). Output: none; shows the risk warning text and
/// the cooldown countdown. The confirmation is only actionable after the
/// cooldown; `n`/`Esc` cancels and stays in Human review.
fn draw_arm_dialog(frame: &mut Frame, gate: &AutomaticArmGate) {
    let status = arm_gate_status(gate, Utc::now());
    let area = centered_rect(64, 60, frame.area());
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from(Span::styled(
            "Enable Automatic mode?",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "Warning: in Automatic mode the AI sends replies without your review.",
            Style::default().fg(Color::Yellow),
        )),
        Line::raw(
            "The model can be wrong. A wrongly sent reply can damage real job applications and your standing with recruiters. Ambiguous, truncated or unverifiable messages are deliberately held, but no automated check is perfect and mistakes do happen.",
        ),
        Line::raw(format!(
            "This confirmation unlocks in {} second(s). Use the pause to read this warning in full.",
            status.remaining_seconds
        )),
        Line::raw(""),
        Line::raw(if status.confirm_enabled {
            "y/Enter I understand the risks \u{2014} enable Automatic mode · n/Esc Cancel (stay in Human review)"
        } else {
            "Confirmation is locked until the countdown elapses · n/Esc Cancel (stay in Human review)"
        }),
    ];
    let widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

/// Draw the quit-with-unsaved-work confirmation dialog.
///
/// Inputs: `frame` — frame to render into; `tui` — presentation state (dirty
/// flag); `s` — latest snapshot (operation status). Output: none; mirrors
/// the desktop close-confirmation text for unsaved text and for
/// shutdown-sensitive operations still in flight.
fn draw_close_confirmation(frame: &mut Frame, tui: &Tui, s: &Snapshot) {
    let sensitive =
        s.operation.state == OperationState::Running && s.operation.kind.shutdown_sensitive();
    let area = centered_rect(60, 48, frame.area());
    frame.render_widget(Clear, area);
    let mut lines = vec![Line::from(Span::styled(
        if sensitive {
            "Operation still running \u{2014} close application?"
        } else {
            "Unsaved reply \u{2014} close application?"
        },
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    if tui.editor.dirty {
        lines.push(Line::raw(
            "Your edited reply has not been saved. Closing will discard this text.",
        ));
    }
    if sensitive {
        lines.push(Line::from(Span::styled(
            format!(
                "{:?} is still running. Closing now can interrupt an external side effect or leave an incomplete operator artifact. Delivery reservations remain fail-safe, but an in-flight Gmail result may become Uncertain on restart.",
                s.operation.kind
            ),
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::raw(if tui.editor.dirty {
        "y force close and discard unsaved text · n keep application open"
    } else {
        "y force close now · n keep application open"
    }));
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Draw the unsaved-edit switch confirmation dialog.
///
/// Inputs: `frame` — frame to render into. Output: none; asks whether to
/// discard the unsaved edit and open the other email. `y` discards and
/// selects, `n`/`Esc` keeps editing.
fn draw_pending_select(frame: &mut Frame) {
    let area = centered_rect(56, 36, frame.area());
    frame.render_widget(Clear, area);
    let widget = Paragraph::new(vec![
        Line::from(Span::styled(
            "Unsaved reply",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::raw("Discard the unsaved edit and open the other email?"),
        Line::raw(""),
        Line::raw("y/Enter discard edit · n/Esc keep editing"),
    ])
    .block(Block::default().borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Draft, JobState};

    /// Build a reviewable job with a persisted draft body.
    ///
    /// Inputs: `body` — persisted draft text. Output: [`Job`] in `Ready`
    /// state with a synthetic demo email and the given draft.
    fn reviewable_job(body: &str) -> Job {
        let email = crate::ollama::sample_email("Synthetic", "Synthetic rejection");
        let mut job = Job::new(email.stub.clone(), Utc::now());
        job.email = Some(email);
        job.state = JobState::Ready;
        job.draft = Some(Draft {
            body: body.into(),
            origin: "human".into(),
        });
        job
    }

    /// Build an all-green send-gate context around one visible text.
    ///
    /// Inputs: `text` — visible editor text. Output: [`SendGateContext`] with
    /// every gate open (bound, clean, no blocks, idle, sending on).
    fn gate(text: &str) -> SendGateContext<'_> {
        SendGateContext {
            editor_text: text,
            editor_bound: true,
            dirty: false,
            hard_blocks: &[],
            busy: false,
            sending_enabled: true,
            demo: false,
            paused: false,
        }
    }

    /// Selection movement clamps at both list edges without wrapping.
    #[test]
    fn selection_movement_is_clamped_at_both_list_edges() {
        assert_eq!(move_selection(Some(0), 5, -1), Some(0));
        assert_eq!(move_selection(Some(0), 5, -7), Some(0));
        assert_eq!(move_selection(Some(4), 5, 1), Some(4));
        assert_eq!(move_selection(Some(4), 5, 9), Some(4));
        // Off-by-one guard: one step inside each edge really moves.
        assert_eq!(move_selection(Some(1), 5, -1), Some(0));
        assert_eq!(move_selection(Some(3), 5, 1), Some(4));
        assert_eq!(move_selection(Some(2), 5, 1), Some(3));
        assert_eq!(move_selection(None, 5, 1), Some(0));
        assert_eq!(move_selection(None, 5, -1), Some(0));
    }

    /// A shrunken list clamps the selection; empty lists select nothing.
    #[test]
    fn selection_clamps_after_the_list_shrinks_and_empty_lists_select_nothing() {
        assert_eq!(clamp_selection(9, 3), Some(2));
        assert_eq!(clamp_selection(2, 3), Some(2));
        assert_eq!(clamp_selection(0, 1), Some(0));
        assert_eq!(clamp_selection(0, 0), None);
        assert_eq!(move_selection(Some(4), 2, 0), Some(1));
        assert_eq!(move_selection(Some(4), 0, 0), None);
        assert_eq!(move_selection(None, 0, 1), None);
    }

    /// Editing marks the editor dirty and a confirmed save clears it.
    #[test]
    fn editor_edit_marks_dirty_and_confirmed_save_clears_it() {
        let job = reviewable_job("Persisted reply");
        let mut editor = EditorState::default();
        editor.load(&job);
        assert!(!editor.dirty);
        assert_eq!(editor.text, "Persisted reply");
        editor.edit("Changed reply".into());
        assert!(editor.dirty);
        // The worker persisted the edit: stored draft now equals the text.
        let mut saved = job.clone();
        saved.revision = 1;
        saved.draft = Some(Draft {
            body: "Changed reply".into(),
            origin: "human".into(),
        });
        sync_editor(&mut editor, &saved);
        assert!(!editor.dirty, "confirmed save must clear the dirty flag");
        assert_eq!(editor.binding, Some((saved.id.clone(), 1)));
    }

    /// An unconfirmed edit keeps the dirty flag and the operator's text.
    #[test]
    fn unconfirmed_edits_stay_dirty_and_retain_operator_text() {
        let job = reviewable_job("Persisted reply");
        let mut editor = EditorState::default();
        editor.load(&job);
        editor.edit("Typo that never saved".into());
        sync_editor(&mut editor, &job);
        assert!(editor.dirty, "a failed save must leave the editor dirty");
        assert_eq!(editor.text, "Typo that never saved");
        // The discard action reloads the persisted draft and clears dirty.
        editor.load(&job);
        assert!(!editor.dirty);
        assert_eq!(editor.text, "Persisted reply");
    }

    /// A stale editor binding can never save or send.
    #[test]
    fn stale_editor_binding_can_never_save_or_send() {
        let job = reviewable_job("Persisted reply");
        let mut editor = EditorState::default();
        editor.load(&job);
        editor.edit("Retained but stale".into());
        // The worker revised the job while the operator was editing.
        let mut moved = job.clone();
        moved.revision = 7;
        moved.draft = Some(Draft {
            body: "Newer persisted reply".into(),
            origin: "human".into(),
        });
        sync_editor(&mut editor, &moved);
        assert!(editor.dirty, "a dirty editor must not silently rebind");
        assert!(
            !editor.bound_to(&moved),
            "stale binding must reject the new revision"
        );
        let enablement =
            action_enablement(Some(&moved), &editor, &gate("Retained but stale"), false);
        assert!(!enablement.save, "stale editors can never save");
        assert!(!enablement.send, "stale editors can never send");
        assert!(!enablement.dismiss && !enablement.regenerate);
    }

    /// A clean editor rebinds to the newly selected job's draft.
    #[test]
    fn clean_editor_rebinds_to_the_new_selection() {
        let first = reviewable_job("First reply");
        let mut editor = EditorState::default();
        editor.load(&first);
        let second = reviewable_job("Second reply");
        sync_editor(&mut editor, &second);
        assert_eq!(editor.text, "Second reply");
        assert_eq!(editor.binding, Some((second.id.clone(), second.revision)));
        assert!(!editor.dirty);
        assert!(editor.bound_to(&second));
    }

    /// The send action is enabled only through the shared send gate.
    #[test]
    fn send_action_enabled_only_through_the_shared_send_gate() {
        let job = reviewable_job("Exact draft");
        let editor = {
            let mut editor = EditorState::default();
            editor.load(&job);
            editor
        };
        let base = SendGateContext {
            editor_text: "Exact draft",
            editor_bound: true,
            dirty: false,
            hard_blocks: &[],
            busy: false,
            sending_enabled: true,
            demo: false,
            paused: false,
        };
        let enablement = action_enablement(Some(&job), &editor, &base, false);
        assert!(enablement.send, "all gates open must enable send");
        for blocked in [
            SendGateContext {
                editor_text: "Edited away from the persisted draft",
                ..base
            },
            SendGateContext {
                editor_bound: false,
                ..base
            },
            SendGateContext {
                dirty: true,
                ..base
            },
            SendGateContext {
                hard_blocks: &["No reply target".to_string()],
                ..base
            },
            SendGateContext { busy: true, ..base },
            SendGateContext {
                sending_enabled: false,
                ..base
            },
            SendGateContext { demo: true, ..base },
            SendGateContext {
                paused: true,
                ..base
            },
        ] {
            assert!(
                !action_enablement(Some(&job), &editor, &blocked, false).send,
                "one flipped gate must disable send"
            );
        }
        assert!(
            !action_enablement(Some(&job), &editor, &base, true).send,
            "an open modal must disable send"
        );
        let mut not_reviewable = job.clone();
        not_reviewable.state = JobState::Sent;
        assert!(
            !action_enablement(Some(&not_reviewable), &editor, &base, false).send,
            "job state must gate send as well"
        );
    }

    /// An unsaved editor may save but can never send.
    #[test]
    fn unsaved_editor_may_save_but_never_send() {
        let job = reviewable_job("Persisted reply");
        let mut editor = EditorState::default();
        editor.load(&job);
        editor.edit("Persisted reply plus a tweak".into());
        let enablement = action_enablement(
            Some(&job),
            &editor,
            &gate("Persisted reply plus a tweak"),
            false,
        );
        assert!(enablement.save, "dirty bound editor must offer save");
        assert!(!enablement.send, "unsaved editor must never send");
        assert!(!enablement.regenerate && !enablement.dismiss);
    }

    /// A cooldown that has not elapsed blocks the Automatic arm.
    #[test]
    fn cooldown_not_yet_elapsed_blocks_automatic_arm() {
        let t0 = Utc::now();
        let mut pending = Some(AutomaticArmGate::open(t0));
        let mut settings = Settings::default();
        assert!(!confirm_automatic_arm(&mut pending, t0, &mut settings));
        assert!(!settings.automatic_confirmed);
        assert!(
            pending.is_some(),
            "the pending gate must survive the refusal"
        );
        // One tick before the 30s cooldown ends the countdown may read zero
        // seconds while the confirmation is still locked.
        let nearly = t0 + chrono::Duration::milliseconds(29_500);
        let gate_ref = pending.as_ref().map(|gate| arm_gate_status(gate, nearly));
        assert_eq!(
            gate_ref,
            Some(ArmGateStatus {
                remaining_seconds: 0,
                confirm_enabled: false
            })
        );
        assert!(!confirm_automatic_arm(&mut pending, nearly, &mut settings));
        assert!(!settings.automatic_confirmed);
    }

    /// Arming succeeds after the cooldown and clears the pending gate.
    #[test]
    fn automatic_arm_confirms_after_cooldown_and_clears_the_pending_gate() {
        let t0 = Utc::now();
        let mut pending = Some(AutomaticArmGate::open(t0));
        let mut settings = Settings::default();
        let later = t0 + chrono::Duration::seconds(30);
        assert!(confirm_automatic_arm(&mut pending, later, &mut settings));
        assert!(settings.automatic_confirmed);
        assert_eq!(settings.automatic_since, Some(later));
        assert!(pending.is_none(), "arming must clear the pending gate");
    }

    /// Cancelling the arm dialog clears the gate and never touches settings.
    #[test]
    fn cancelled_arm_leaves_settings_untouched_and_clears_pending_gate() {
        let t0 = Utc::now();
        let mut pending = Some(AutomaticArmGate::open(t0));
        let mut settings = Settings::default();
        assert!(cancel_automatic_arm(&mut pending));
        assert!(pending.is_none());
        assert!(!settings.automatic_confirmed);
        assert_eq!(settings.automatic_since, None);
        assert!(
            !cancel_automatic_arm(&mut pending),
            "second cancel has nothing to clear"
        );
        // With the gate cleared, not even a fully elapsed cooldown can arm.
        let later = t0 + chrono::Duration::seconds(30);
        assert!(!confirm_automatic_arm(&mut pending, later, &mut settings));
        assert!(!settings.automatic_confirmed);
    }

    /// Cancelling the confirm dialog clears its state and forbids a later send.
    #[test]
    fn cancelled_confirm_dialog_clears_state_and_forbids_later_send() {
        let job = reviewable_job("Persisted reply");
        let mut state = Some(SendConfirmation { job });
        assert!(cancel_send_confirmation(&mut state));
        assert!(state.is_none(), "cancellation must clear the dialog state");
        assert!(
            accept_send_confirmation(&mut state, true).is_none(),
            "nothing may be sent after the dialog was cancelled"
        );
        assert!(!cancel_send_confirmation(&mut state));
    }

    /// Accepting the confirm dialog sends the exact persisted draft hash.
    #[test]
    fn accepted_confirm_dialog_sends_the_exact_persisted_draft_hash() {
        let job = reviewable_job("Persisted reply");
        let (id, revision) = (job.id.clone(), job.revision);
        let mut state = Some(SendConfirmation { job });
        let command = accept_send_confirmation(&mut state, true);
        assert!(state.is_none(), "accepting must clear the dialog state");
        assert!(
            matches!(command, Some(Command::Send { .. })),
            "accepted confirmations only send"
        );
        if let Some(Command::Send {
            id: sent_id,
            revision: sent_revision,
            body_hash,
        }) = command
        {
            assert_eq!(sent_id, id);
            assert_eq!(sent_revision, revision);
            assert_eq!(body_hash, hash("Persisted reply"));
        }
    }

    /// The confirm dialog refuses to send while the worker is busy or paused.
    #[test]
    fn confirm_dialog_refuses_to_send_while_busy_or_paused() {
        let job = reviewable_job("Persisted reply");
        let mut state = Some(SendConfirmation { job });
        assert!(accept_send_confirmation(&mut state, false).is_none());
        assert!(state.is_some(), "a refused send must keep the dialog open");
        assert!(cancel_send_confirmation(&mut state));
    }

    /// Quit confirmation covers unsaved text and sensitive operations.
    #[test]
    fn close_confirmation_covers_unsaved_text_and_sensitive_operations() {
        let mut operation = OperationStatus::default();
        assert!(!requires_close_confirmation(false, &operation));
        assert!(requires_close_confirmation(true, &operation));
        operation.state = OperationState::Running;
        operation.kind = crate::types::OperationKind::SendReply;
        assert!(requires_close_confirmation(false, &operation));
        operation.kind = crate::types::OperationKind::SyncMailbox;
        assert!(!requires_close_confirmation(false, &operation));
    }

    /// Tone and reply-language pickers clamp at their level edges.
    #[test]
    fn tone_and_reply_language_cycling_clamps_at_the_level_edges() {
        assert_eq!(cycle_tone(Tone::Professional, true), Tone::Assertive);
        assert_eq!(cycle_tone(Tone::Assertive, true), Tone::Hardline);
        assert_eq!(cycle_tone(Tone::Hardline, true), Tone::Insane);
        assert_eq!(
            cycle_tone(Tone::Insane, true),
            Tone::Insane,
            "no wrap at the harsh end"
        );
        assert_eq!(cycle_tone(Tone::Insane, false), Tone::Hardline);
        assert_eq!(cycle_tone(Tone::Hardline, false), Tone::Assertive);
        assert_eq!(cycle_tone(Tone::Assertive, false), Tone::Professional);
        assert_eq!(
            cycle_tone(Tone::Professional, false),
            Tone::Professional,
            "no wrap at the soft end"
        );
        assert_eq!(
            cycle_reply_language(ReplyLanguage::Auto, true),
            ReplyLanguage::English
        );
        assert_eq!(
            cycle_reply_language(ReplyLanguage::English, true),
            ReplyLanguage::English
        );
        assert_eq!(
            cycle_reply_language(ReplyLanguage::English, false),
            ReplyLanguage::Auto
        );
        assert_eq!(
            cycle_reply_language(ReplyLanguage::Auto, false),
            ReplyLanguage::Auto
        );
    }

    /// The word count treats any whitespace as a separator.
    #[test]
    fn word_count_counts_whitespace_separated_words() {
        assert_eq!(word_count(""), 0);
        assert_eq!(word_count("   \n\t"), 0);
        assert_eq!(word_count("one"), 1);
        assert_eq!(word_count(" one two\tthree\nfour "), 4);
    }

    /// Automatic mode cannot be saved without arming and sending enabled.
    #[test]
    fn settings_save_requires_arming_before_automatic_mode() {
        let mut settings = Settings::default();
        assert!(
            settings_save_enabled(&settings),
            "Human review saves freely"
        );
        settings.mode = Mode::Automatic;
        assert!(
            !settings_save_enabled(&settings),
            "unarmed Automatic must not save"
        );
        settings.automatic_confirmed = true;
        assert!(
            !settings_save_enabled(&settings),
            "Automatic without sending stays blocked"
        );
        settings.sending_enabled = true;
        assert!(settings_save_enabled(&settings));
    }

    /// Editor cursor helpers stay on character boundaries under UTF-8.
    #[test]
    fn editor_cursor_helpers_stay_on_char_boundaries() {
        let mut text = String::from("a\u{00e9}b");
        // 'a' is 1 byte, 'é' is 2 bytes, 'b' is 1 byte.
        let cursor = editor_insert(&mut text, 1, 'X');
        assert_eq!(text, "aX\u{00e9}b");
        assert_eq!(cursor, 2);
        assert_eq!(cursor_left(&text, 2), 1);
        assert_eq!(cursor_left(&text, 1), 0);
        assert_eq!(cursor_left(&text, 0), 0);
        assert_eq!(cursor_right(&text, 1), 2);
        assert_eq!(
            cursor_right(&text, 3),
            4,
            "right from mid-'é' must land after it"
        );
        assert_eq!(cursor_right(&text, text.len()), text.len());
        // Off-boundary offsets snap down to a boundary instead of panicking:
        // offset 3 is inside 'é' (bytes 2..4) and snaps to 2 first.
        assert_eq!(cursor_left(&text, 3), 1);
        // Backspace at the start is a no-op and never panics mid-character.
        assert_eq!(editor_backspace(&mut text, 0), 0);
        assert_eq!(text, "aX\u{00e9}b");
        // Backspace at offset 3 removes 'X' at the snapped boundary.
        let cursor = editor_backspace(&mut text, 3);
        assert_eq!(text, "a\u{00e9}b");
        assert_eq!(cursor, 1);
    }

    /// A worker whose commands are captured by the test instead of a live
    /// engine.
    ///
    /// Inputs: none. Output: `(tui, rx)` — presentation state around a
    /// stopped demo worker; every issued [`Command`] lands in `rx`.
    fn test_tui() -> (Tui, crossbeam_channel::Receiver<Command>) {
        let dir = tempfile::tempdir().unwrap();
        let mut worker = Worker::spawn(dir.path().to_path_buf(), true);
        let (tx, rx) = crossbeam_channel::bounded(64);
        // Dropping the worker's own sender disconnects the engine loop;
        // wait for its one startup refresh before taking over the view.
        worker.tx = tx;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !worker.view().initialized {
            assert!(
                std::time::Instant::now() < deadline,
                "worker never initialized"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        *worker.snapshot.lock().expect("snapshot lock") = Snapshot::default();
        std::mem::forget(dir);
        (Tui::new(worker), rx)
    }

    /// Build a job that passes every mail-level hard block.
    ///
    /// Inputs: `body` — persisted draft text. Output: [`Job`] with a Gmail
    /// source, matching account and replyable recipient.
    fn sendable_job(body: &str) -> Job {
        let mut job = reviewable_job(body);
        if let Some(email) = &mut job.email {
            email.stub = crate::types::Stub {
                account: "me@example.com".into(),
                provider_id: "p".into(),
                thread_id: "t".into(),
                source: crate::types::Source::Gmail,
            };
            email.from = "Recruitment <hr@corp.example>".into();
            email.message_id = "<valid-message@corp.example>".into();
        }
        job
    }

    /// An initialized snapshot with a connected account.
    ///
    /// Inputs: none. Output: [`Snapshot`] the interface treats as live and
    /// idle.
    fn live_snapshot() -> Snapshot {
        Snapshot {
            initialized: true,
            account: "me@example.com".into(),
            connected: true,
            settings: Settings {
                sending_enabled: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Render one full frame to text for content assertions.
    ///
    /// Inputs: `tui` — presentation state; `s` — snapshot. Output: the
    /// visible screen text, row by row.
    fn render_text(tui: &Tui, s: &Snapshot) -> String {
        let backend = ratatui::backend::TestBackend::new(120, 40);
        let mut terminal = ratatui::Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| draw(frame, tui, s))
            .expect("draw frame");
        let buffer = terminal.backend().buffer();
        let mut out = String::default();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer.cell((x, y)).expect("cell").symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Flatten one rendered line to plain text.
    ///
    /// Inputs: `line` — rendered line. Output: concatenation of its spans.
    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.to_string())
            .collect()
    }

    /// Render the status bar alone into a generous area.
    ///
    /// Inputs: `tui` — presentation state; `s` — snapshot. Output: the full
    /// status text, including the error and hint lines the fixed-height
    /// bottom bar clips in the composed frame.
    fn render_status_text(tui: &Tui, s: &Snapshot) -> String {
        let backend = ratatui::backend::TestBackend::new(120, 8);
        let mut terminal = ratatui::Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                draw_status(frame, area, tui, s);
            })
            .expect("draw status");
        let buffer = terminal.backend().buffer();
        let mut out = String::default();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer.cell((x, y)).expect("cell").symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Build a key press event.
    ///
    /// Inputs: `code` — key. Output: [`KeyEvent`] in press state.
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    /// Dropping an unsaved edit is explicit and the text survives until the
    /// rebind replaces it.
    ///
    /// Why: `abandon_edit` must clear only the dirty flag — losing the text
    /// here would silently discard operator work on a mode switch.
    #[test]
    fn abandon_edit_clears_dirty_but_keeps_text() {
        let mut editor = EditorState::default();
        editor.edit("unsaved text".into());
        assert!(editor.dirty);
        editor.abandon_edit();
        assert!(!editor.dirty);
        assert_eq!(editor.text, "unsaved text");
    }

    /// Missing originals and mail-level blocks are reported verbatim.
    ///
    /// Why: these reasons feed the shared send gate's visible "Sending
    /// blocked" line — dropping a reason hides a real delivery hazard.
    #[test]
    fn hard_blocks_for_reports_the_exact_reasons() {
        let mut job = reviewable_job("draft body");
        let blocks = hard_blocks_for(&job, "me@example.com");
        assert!(
            blocks.contains(&"Demo messages can never be sent".to_string()),
            "demo sources are hard-blocked: {blocks:?}"
        );
        job.email = None;
        assert_eq!(
            hard_blocks_for(&job, "me@example.com"),
            vec!["Original email is unavailable".to_string()]
        );
    }

    /// The editor renders its caret as a reversed cell at the exact cursor
    /// position, including multi-byte text and end-of-line.
    ///
    /// Why: a misdrawn caret makes the operator edit the wrong character.
    #[test]
    fn editor_lines_place_the_caret_on_the_right_cell() {
        let plain = editor_lines("ab\ncd", None);
        assert_eq!(plain.len(), 2);
        assert!(plain.iter().all(|line| {
            line.spans
                .iter()
                .all(|span| !span.style.add_modifier.contains(Modifier::REVERSED))
        }));

        // Cursor at offset 1 ('b') in the first line.
        let caret = editor_lines("ab\ncd", Some(1));
        assert_eq!(caret[0].spans.len(), 3, "head, caret, tail");
        assert!(
            caret[0].spans[1]
                .style
                .add_modifier
                .contains(Modifier::REVERSED)
        );
        assert_eq!(caret[0].spans[1].content, "b");
        // Cursor at the end of the first line renders a reversed space.
        let end = editor_lines("ab\ncd", Some(2));
        assert_eq!(end[0].spans[1].content, " ");
        // A cursor past the end renders no caret at all.
        let beyond = editor_lines("ab", Some(99));
        assert!(
            beyond[0]
                .spans
                .iter()
                .all(|span| !span.style.add_modifier.contains(Modifier::REVERSED))
        );
    }

    /// Dialog overlays are centered inside the frame and never exceed it.
    ///
    /// Why: every dialog is positioned through this helper; off-screen
    /// dialogs make actions invisible.
    #[test]
    fn centered_rect_stays_inside_the_parent_area() {
        let area = Rect::new(10, 20, 100, 80);
        let centered = centered_rect(50, 50, area);
        assert!(centered.left() >= area.left() && centered.right() <= area.right());
        assert!(centered.top() >= area.top() && centered.bottom() <= area.bottom());
        assert_eq!(centered.width, 50);
        assert_eq!(centered.height, 40);
        assert_eq!(centered.x, 10 + 25);
        assert_eq!(centered.y, 20 + 20);
    }

    /// Sync mirrors account switches, enterprise policy and selection.
    ///
    /// Why: leaking editor text across accounts or keeping Automatic mode
    /// under a Human-review policy are both safety bugs.
    #[test]
    fn sync_view_enforces_accounts_policy_and_selection() {
        let (mut tui, _rx) = test_tui();
        tui.queue_selection = Some(9);
        let mut s = live_snapshot();
        s.items = vec![reviewable_job("a"), reviewable_job("b")];
        tui.sync_view(&s);
        assert_eq!(tui.queue_selection, Some(1), "selection clamps to the list");

        // Account switch resets the editor and every parked dialog.
        tui.editor.edit("other account text".into());
        tui.pending_select = Some("job".into());
        tui.send_confirmation = Some(SendConfirmation {
            job: reviewable_job("draft"),
        });
        s.account = "other@example.com".into();
        tui.sync_view(&s);
        assert!(tui.editor.text.is_empty(), "editor cleared on switch");
        assert!(tui.pending_select.is_none() && tui.send_confirmation.is_none());

        // Enterprise policy coerces the local settings copy.
        let mut s = live_snapshot();
        s.enterprise_policy.force_human_review = true;
        s.enterprise_policy.prohibit_sending = true;
        tui.settings.mode = Mode::Automatic;
        tui.settings.sending_enabled = true;
        tui.sync_view(&s);
        assert_eq!(tui.settings.mode, Mode::HumanReview);
        assert!(!tui.settings.sending_enabled);

        // A selected job rebinds a clean editor and drops editing mode.
        let job = reviewable_job("persisted draft");
        let mut s = live_snapshot();
        s.selected = Some(job.clone());
        tui.editing = true;
        tui.sync_view(&s);
        assert_eq!(tui.editor.text, "persisted draft");
        assert!(tui.editor.bound_to(&job));
        assert!(!tui.editing, "clean editors leave editing mode");
    }

    /// Selection requests respect the unsaved-edit guard.
    ///
    /// Why: switching jobs with unsaved text must park behind the explicit
    /// discard dialog instead of silently dropping the edit.
    #[test]
    fn request_select_parks_dirty_edits_and_blocks_on_modals() {
        let (mut tui, rx) = test_tui();
        tui.editor.edit("unsaved".into());
        tui.request_select("job-1".into());
        assert_eq!(tui.pending_select, Some("job-1".into()));
        assert!(rx.try_recv().is_err(), "dirty switches are parked");

        // Open modals absorb every selection requests.
        tui.editor.abandon_edit();
        tui.pending_select = None;
        tui.request_select("job-2".into());
        assert!(rx.try_recv().is_ok());
        tui.close_confirmation = true;
        tui.request_select("job-3".into());
        assert!(rx.try_recv().is_err(), "modals block selection");
    }

    /// Action enablement routes through the shared send gate exactly.
    ///
    /// Why: the terminal must offer "review & send" under exactly the same
    /// conditions as the desktop — a divergence splits the safety model.
    #[test]
    fn review_enablement_mirrors_the_desktop_send_gate() {
        let (mut tui, _rx) = test_tui();
        let job = sendable_job("A professional reply body.");
        let mut s = live_snapshot();
        s.selected = Some(job.clone());
        tui.editor.load(&job);
        let enabled = tui.review_enablement(Some(&job), &s);
        assert!(enabled.send, "bound clean editor with exact draft sends");
        assert!(enabled.regenerate && enabled.dismiss && !enabled.save);

        // An edited (unsaved) body flips save on and send off.
        tui.editor.edit("A professional reply body. edited".into());
        let enabled = tui.review_enablement(Some(&job), &s);
        assert!(enabled.save && !enabled.send && !enabled.regenerate);

        // Demo sessions can never send.
        tui.editor.load(&job);
        s.demo = true;
        assert!(!tui.review_enablement(Some(&job), &s).send);
        s.demo = false;

        // Missing originals block sending through the shared hard blocks.
        let mut blocked = job.clone();
        blocked.email = None;
        assert!(!tui.review_enablement(Some(&blocked), &s).send);
    }

    /// Global keys route before pane keys and dialogs take priority.
    ///
    /// Why: the key router is the only input surface — a leak between the
    /// modal, help and pane layers fires the wrong action.
    #[test]
    fn handle_key_routes_globals_help_and_panes() {
        let (mut tui, rx) = test_tui();
        let s = live_snapshot();
        // Key releases are ignored entirely.
        let mut release = key(KeyCode::Char('q'));
        release.kind = KeyEventKind::Release;
        tui.handle_key(release, &s);
        assert!(!tui.quit && !tui.close_confirmation);

        // Pause toggles the worker's dispatch gate.
        tui.handle_key(key(KeyCode::Char('p')), &s);
        assert!(tui.worker.paused.load(Ordering::SeqCst));
        tui.handle_key(key(KeyCode::Char('p')), &s);
        assert!(!tui.worker.paused.load(Ordering::SeqCst));

        // Number keys and Tab own pane navigation.
        tui.handle_key(key(KeyCode::Char('2')), &s);
        assert_eq!(tui.pane, Pane::Review);
        tui.handle_key(key(KeyCode::Tab), &s);
        assert_eq!(tui.pane, Pane::Activity);
        tui.handle_key(key(KeyCode::Char('4')), &s);
        assert_eq!(tui.pane, Pane::Settings);
        tui.handle_key(key(KeyCode::Char('1')), &s);
        assert_eq!(tui.pane, Pane::Queue);

        // The help overlay swallows pane keys until closed.
        tui.handle_key(key(KeyCode::Char('?')), &s);
        assert!(tui.help_open);
        tui.handle_key(key(KeyCode::Char('r')), &s);
        assert!(rx.try_recv().is_err(), "help swallows pane keys");
        tui.handle_key(key(KeyCode::Esc), &s);
        assert!(!tui.help_open);

        // 'q' quits cleanly only when nothing would be lost.
        tui.handle_key(key(KeyCode::Char('q')), &s);
        assert!(tui.quit, "clean sessions quit immediately");
    }

    /// Dialog keys confirm or cancel each flow and nothing else.
    ///
    /// Why: the confirm-exact-reply dialog is the last human gate — `y`
    /// must issue exactly `Command::Send` with the persisted body hash.
    #[test]
    fn dialog_keys_own_the_confirmation_flows() {
        let (mut tui, rx) = test_tui();
        let s = live_snapshot();
        let job = reviewable_job("A professional reply body.");

        // Quit confirmation: y quits, n cancels.
        tui.close_confirmation = true;
        assert!(tui.handle_dialog_key(key(KeyCode::Char('n')), &s));
        assert!(!tui.close_confirmation && !tui.quit);
        tui.close_confirmation = true;
        assert!(tui.handle_dialog_key(key(KeyCode::Char('y')), &s));
        assert!(tui.quit && !tui.close_confirmation);
        tui.quit = false;

        // Confirm-exact-reply: Enter sends the exact hash; Esc cancels.
        tui.send_confirmation = Some(SendConfirmation { job: job.clone() });
        assert!(tui.handle_dialog_key(key(KeyCode::Esc), &s));
        assert!(tui.send_confirmation.is_none(), "cancel clears the dialog");
        assert!(rx.try_recv().is_err());
        tui.send_confirmation = Some(SendConfirmation { job: job.clone() });
        assert!(tui.handle_dialog_key(key(KeyCode::Enter), &s));
        let body = job.draft.as_ref().unwrap().body.as_str();
        assert!(matches!(
            rx.try_recv(),
            Ok(Command::Send { revision, body_hash, .. })
                if revision == job.revision && body_hash == hash(body)
        ));
        assert!(tui.send_confirmation.is_none(), "send consumes the dialog");

        // A busy worker refuses the send and keeps the dialog.
        tui.send_confirmation = Some(SendConfirmation { job: job.clone() });
        let mut busy = live_snapshot();
        busy.busy = "syncing".into();
        assert!(tui.handle_dialog_key(key(KeyCode::Char('y')), &busy));
        assert!(rx.try_recv().is_err(), "busy workers cannot send");
        assert!(tui.send_confirmation.is_some(), "dialog kept for retry");
        tui.send_confirmation = None;

        // Automatic arming: early confirmations are refused by the gate.
        tui.pending_arm = Some(AutomaticArmGate::open(Utc::now()));
        assert!(tui.handle_dialog_key(key(KeyCode::Char('y')), &s));
        assert!(tui.pending_arm.is_some(), "cooldown blocks early arming");
        assert!(!tui.settings.automatic_confirmed);
        assert!(tui.handle_dialog_key(key(KeyCode::Char('n')), &s));
        assert!(tui.pending_arm.is_none(), "cancel drops the gate");

        // An elapsed gate arms the session.
        let expired = Utc::now() - chrono::Duration::seconds(31);
        tui.pending_arm = Some(AutomaticArmGate::open(expired));
        assert!(tui.handle_dialog_key(key(KeyCode::Char('y')), &s));
        assert!(tui.settings.automatic_confirmed);
        assert!(tui.pending_arm.is_none());

        // Unsaved-edit switch: y discards and selects, n keeps editing.
        tui.editor.edit("unsaved".into());
        tui.pending_select = Some("job-9".into());
        assert!(tui.handle_dialog_key(key(KeyCode::Char('n')), &s));
        assert!(tui.pending_select.is_none(), "n keeps the edit parked");
        assert!(tui.editor.dirty);
        tui.pending_select = Some("job-9".into());
        assert!(tui.handle_dialog_key(key(KeyCode::Enter), &s));
        assert!(matches!(rx.try_recv(), Ok(Command::Select(id)) if id == "job-9"));
        assert!(!tui.editor.dirty, "discard drops the unsaved edit");

        // Without dialogs the router reports no consumption.
        assert!(!tui.handle_dialog_key(key(KeyCode::Char('z')), &s));
    }

    /// Queue keys move the clamped selection and route list commands.
    ///
    /// Why: selection must never leave the list and Enter must open exactly
    /// the highlighted job.
    #[test]
    fn queue_keys_move_select_and_refresh() {
        let (mut tui, rx) = test_tui();
        let mut s = live_snapshot();
        s.items = vec![
            reviewable_job("a"),
            reviewable_job("b"),
            reviewable_job("c"),
        ];
        tui.handle_key(key(KeyCode::Down), &s);
        assert_eq!(tui.queue_selection, Some(0));
        tui.handle_key(key(KeyCode::Down), &s);
        tui.handle_key(key(KeyCode::Char('k')), &s);
        assert_eq!(tui.queue_selection, Some(0));
        tui.handle_key(key(KeyCode::Char('G')), &s);
        assert_eq!(tui.queue_selection, Some(2));
        tui.handle_key(key(KeyCode::Char('g')), &s);
        assert_eq!(tui.queue_selection, Some(0));

        // Enter opens the highlighted job.
        tui.handle_key(key(KeyCode::Enter), &s);
        assert!(matches!(rx.try_recv(), Ok(Command::Select(id)) if id == s.items[0].id));

        // r and c route Refresh and CheckNow.
        tui.handle_key(key(KeyCode::Char('r')), &s);
        assert!(matches!(rx.try_recv(), Ok(Command::Refresh)));
        tui.handle_key(key(KeyCode::Char('c')), &s);
        assert!(matches!(rx.try_recv(), Ok(Command::CheckNow)));
    }

    /// Review keys drive the editor, the analysis expander and the review
    /// actions through the shared enablement.
    ///
    /// Why: each action key must be refused for stale or dirty editors and
    /// route the exact command otherwise.
    #[test]
    fn review_keys_drive_the_review_workspace() {
        let (mut tui, rx) = test_tui();
        let job = sendable_job("A professional reply body.");
        let mut s = live_snapshot();
        s.selected = Some(job.clone());
        tui.pane = Pane::Review;
        tui.editor.load(&job);

        // Scrolling and the analysis expander are free state changes.
        tui.handle_key(key(KeyCode::Down), &s);
        tui.handle_key(key(KeyCode::PageDown), &s);
        tui.handle_key(key(KeyCode::Char('a')), &s);
        assert!(tui.analysis_open);

        // e enters editing mode with the caret at the end.
        tui.handle_key(key(KeyCode::Char('e')), &s);
        assert!(tui.editing);
        assert_eq!(tui.editor_cursor, tui.editor.text.len());

        // Typing marks the editor dirty; Esc leaves editing.
        tui.handle_key(key(KeyCode::Char('!')), &s);
        assert!(tui.editor.dirty);
        tui.handle_key(key(KeyCode::Esc), &s);
        assert!(!tui.editing);

        // s saves the exact text; invalid drafts surface a local error.
        tui.handle_key(key(KeyCode::Char('s')), &s);
        assert!(matches!(
            rx.try_recv(),
            Ok(Command::Edit { body, .. }) if body.ends_with('!')
        ));
        tui.editor.edit("short".into());
        tui.handle_key(key(KeyCode::Char('s')), &s);
        assert!(!tui.local_error.is_empty(), "invalid drafts are refused");
        assert!(rx.try_recv().is_err());

        // D discards the unsaved text back to the persisted draft.
        tui.handle_key(key(KeyCode::Char('D')), &s);
        assert_eq!(tui.editor.text, "A professional reply body.");
        assert!(!tui.editor.dirty);

        // g and d route Regenerate and Dismiss on a clean editor.
        tui.handle_key(key(KeyCode::Char('g')), &s);
        assert!(matches!(rx.try_recv(), Ok(Command::Regenerate { .. })));
        tui.handle_key(key(KeyCode::Char('d')), &s);
        assert!(matches!(rx.try_recv(), Ok(Command::Dismiss { .. })));

        // w opens the confirm dialog only when the gate passes.
        tui.handle_key(key(KeyCode::Char('w')), &s);
        assert!(
            tui.send_confirmation.is_some(),
            "all-green gate opens confirm"
        );
        tui.send_confirmation = None;

        // Dirty editors cannot regenerate or dismiss.
        tui.editor.edit("unsaved edit".into());
        tui.handle_key(key(KeyCode::Char('g')), &s);
        tui.handle_key(key(KeyCode::Char('d')), &s);
        assert!(rx.try_recv().is_err(), "dirty editors block actions");
    }

    /// Editor keys mutate the text through the pure cursor helpers.
    ///
    /// Why: the editor path is the only place text changes — every key must
    /// leave the caret on a character boundary and mark the text dirty.
    #[test]
    fn editor_keys_edit_text_and_move_the_caret() {
        let (mut tui, _rx) = test_tui();
        tui.editing = true;
        tui.editor.edit("abc".into());
        tui.editor_cursor = 3;
        tui.handle_editor_key(KeyCode::Char('X'));
        assert_eq!(tui.editor.text, "abcX");
        assert_eq!(tui.editor_cursor, 4);
        tui.handle_editor_key(KeyCode::Enter);
        assert_eq!(tui.editor.text, "abcX\n");
        tui.handle_editor_key(KeyCode::Backspace);
        assert_eq!(tui.editor.text, "abcX");
        tui.handle_editor_key(KeyCode::Left);
        assert_eq!(tui.editor_cursor, 3);
        tui.handle_editor_key(KeyCode::Home);
        assert_eq!(tui.editor_cursor, 0);
        tui.handle_editor_key(KeyCode::Right);
        assert_eq!(tui.editor_cursor, 1);
        tui.handle_editor_key(KeyCode::End);
        assert_eq!(tui.editor_cursor, 4);
        // Unmapped keys are ignored.
        tui.handle_editor_key(KeyCode::PageUp);
        assert_eq!(tui.editor_cursor, 4);
        tui.handle_editor_key(KeyCode::Esc);
        assert!(!tui.editing);
    }

    /// Activity keys scroll the log without touching worker state.
    ///
    /// Why: the audit log is read-only — any key that mutates state here is
    /// a bug.
    #[test]
    fn activity_keys_only_scroll() {
        let (mut tui, rx) = test_tui();
        tui.handle_activity_key(KeyCode::Down);
        tui.handle_activity_key(KeyCode::PageDown);
        assert_eq!(tui.activity_scroll, 11);
        tui.handle_activity_key(KeyCode::Up);
        tui.handle_activity_key(KeyCode::PageUp);
        assert_eq!(tui.activity_scroll, 0);
        tui.handle_activity_key(KeyCode::Char('z'));
        assert_eq!(tui.activity_scroll, 0);
        assert!(rx.try_recv().is_err(), "activity never commands the worker");
    }

    /// Settings keys edit the local copy and persist only through Save.
    ///
    /// Why: policy-locked rows must stay inert and Save must be refused
    /// until an Automatic configuration is fully armed.
    #[test]
    fn settings_keys_edit_rows_and_save() {
        let (mut tui, rx) = test_tui();
        let s = live_snapshot();
        tui.pane = Pane::Settings;

        // Row navigation clamps at both ends.
        tui.handle_key(key(KeyCode::Up), &s);
        assert_eq!(tui.settings_row, 0);
        tui.handle_key(key(KeyCode::Down), &s);
        assert_eq!(tui.settings_row, 1);

        // Mode row: forward opens Automatic only when policy allows.
        tui.settings_row = 0;
        tui.handle_key(key(KeyCode::Right), &s);
        assert_eq!(tui.settings.mode, Mode::Automatic);
        tui.handle_key(key(KeyCode::Left), &s);
        assert_eq!(tui.settings.mode, Mode::HumanReview);
        let mut locked = live_snapshot();
        locked.enterprise_policy.force_human_review = true;
        tui.handle_key(key(KeyCode::Right), &locked);
        assert_eq!(
            tui.settings.mode,
            Mode::HumanReview,
            "policy locks the mode"
        );

        // Tone and language pickers step through their orders.
        tui.settings_row = 1;
        let tone = tui.settings.tone;
        tui.handle_key(key(KeyCode::Right), &s);
        assert_eq!(tui.settings.tone, cycle_tone(tone, true));
        tui.settings_row = 2;
        tui.handle_key(key(KeyCode::Right), &s);
        assert_eq!(tui.settings.reply_language, ReplyLanguage::English);
        tui.handle_key(key(KeyCode::Char('h')), &s);
        assert_eq!(tui.settings.reply_language, ReplyLanguage::Auto);

        // Sending toggle flips unless policy prohibits sending.
        tui.settings_row = 3;
        let sending = tui.settings.sending_enabled;
        tui.handle_key(key(KeyCode::Right), &s);
        assert_eq!(tui.settings.sending_enabled, !sending);
        let mut prohibit = live_snapshot();
        prohibit.enterprise_policy.prohibit_sending = true;
        tui.handle_key(key(KeyCode::Right), &prohibit);
        assert_eq!(
            tui.settings.sending_enabled, !sending,
            "policy locks sending"
        );

        // Automatic arm row opens the cooldown gate only in Automatic mode.
        tui.settings_row = 4;
        tui.handle_key(key(KeyCode::Right), &s);
        assert!(tui.pending_arm.is_none(), "Human review never arms");
        tui.settings.mode = Mode::Automatic;
        tui.handle_key(key(KeyCode::Right), &s);
        assert!(
            tui.pending_arm.is_some(),
            "Automatic opens the cooldown gate"
        );
        tui.pending_arm = None;
        tui.settings.automatic_confirmed = true;
        tui.handle_key(key(KeyCode::Right), &s);
        assert!(
            !tui.settings.automatic_confirmed,
            "confirmed row disables the mode"
        );
        assert!(tui.pending_arm.is_none());

        // Save persists only a fully armed Automatic configuration.
        tui.settings_row = 5;
        tui.settings.mode = Mode::Automatic;
        tui.handle_key(key(KeyCode::Right), &s);
        assert!(rx.try_recv().is_err(), "unarmed Automatic cannot save");
        tui.settings.mode = Mode::HumanReview;
        tui.handle_key(key(KeyCode::Enter), &s);
        assert!(matches!(
            rx.try_recv(),
            Ok(Command::Settings(boxed)) if boxed.mode == Mode::HumanReview
        ));

        // Busy sessions never save.
        let mut busy = live_snapshot();
        busy.busy = "working".into();
        tui.handle_key(key(KeyCode::Right), &busy);
        assert!(rx.try_recv().is_err(), "busy sessions cannot save");

        // Unmapped keys and non-steering keys are ignored.
        tui.handle_key(key(KeyCode::Char('z')), &s);
        assert!(rx.try_recv().is_err());
    }

    /// The event loop renders, pumps keys and restores the terminal on the
    /// quit path exactly once.
    ///
    /// Why: the loop must stop the worker and restore the terminal even for
    /// a plain quit — leaving raw mode behind corrupts the shell.
    #[test]
    fn run_session_drives_events_until_quit_and_restores() {
        static RESTORES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        fn fake_restore() -> std::io::Result<()> {
            RESTORES.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        let (tui, _rx) = test_tui();
        let mut script =
            vec![Some(key(KeyCode::Char('3'))), Some(key(KeyCode::Char('q')))].into_iter();
        let mut next_key = || -> Result<Option<KeyEvent>> { Ok(script.next().flatten()) };
        let backend = ratatui::backend::TestBackend::new(100, 30);
        let terminal = ratatui::Terminal::new(backend).expect("terminal");
        run_session(terminal, tui, fake_restore, &mut next_key).expect("session ends cleanly");
        assert_eq!(RESTORES.load(Ordering::SeqCst), 1, "restored exactly once");
    }

    /// The terminal event pump returns no key when none arrives.
    ///
    /// Why: the pump drives the refresh cadence — a blocking or panicking
    /// pump would freeze countdowns and busy states.
    #[test]
    fn poll_key_returns_no_key_without_input() {
        let _ = poll_key();
    }

    /// The queue pane shows per-job state, subject and flags.
    ///
    /// Why: the list line is the operator's triage surface — missing flags
    /// hide processing problems.
    #[test]
    fn draw_queue_renders_states_subjects_and_flags() {
        let (mut tui, _rx) = test_tui();
        let mut s = live_snapshot();
        let mut job = reviewable_job("draft");
        job.flags = vec!["needs manual review".into()];
        s.items = vec![job.clone()];
        let mut bare = reviewable_job("other");
        bare.email = None;
        s.items.push(bare);
        tui.queue_selection = Some(0);
        let text = render_text(&tui, &s);
        assert!(text.contains("Ready"), "state label shown");
        assert!(text.contains("[Ready] Synthetic"), "subject shown");
        assert!(text.contains("needs manual review"), "flags shown");
        assert!(
            text.contains("(original not fetched)"),
            "missing email shown"
        );
    }

    /// The review pane renders every workspace variant.
    ///
    /// Why: the review screen is where sends originate — its warnings must
    /// render for stale editors, blocked sends and missing originals.
    #[test]
    fn draw_review_renders_the_full_workspace_and_warnings() {
        let (mut tui, _rx) = test_tui();
        tui.pane = Pane::Review;
        let mut s = live_snapshot();

        // Automatic mode replaces the workspace with a notice.
        s.settings.mode = Mode::Automatic;
        let text = render_text(&tui, &s);
        assert!(text.contains("Review is disabled in Automatic mode"));
        s.settings.mode = Mode::HumanReview;

        // No selection renders the empty hint.
        let text = render_text(&tui, &s);
        assert!(text.contains("Select a message"));

        // A full job renders both columns plus footer details.
        let job = reviewable_job("A professional reply body.");
        s.selected = Some(job.clone());
        tui.editor.load(&job);
        tui.analysis_open = true;
        tui.local_error = "draft failed validation".into();
        let text = render_text(&tui, &s);
        assert!(text.contains("ORIGINAL EMAIL"));
        assert!(text.contains("REPLY · 4 words"));
        assert!(text.contains("draft failed validation"));
        assert!(
            text.contains("No analysis is stored"),
            "missing analysis is spelled out"
        );

        // Editing and dirty states are spelled out in the editor title.
        tui.editing = true;
        tui.editor.edit("unsaved".into());
        let text = render_text(&tui, &s);
        assert!(text.contains("editing"), "editing mode is visible");
        assert!(text.contains("Unsaved"), "dirty state is visible");

        // Demo-source mail is shown as a hard block.
        let text = render_text(&tui, &s);
        assert!(text.contains("Sending blocked"), "hard blocks are visible");
    }

    /// The review footer carries analysis, flags, blocks and errors.
    ///
    /// Why: the footer is the only place the verdict explanation surfaces —
    /// dropping it hides why the model flagged the message.
    #[test]
    fn review_footer_lines_carry_analysis_flags_and_blocks() {
        let mut job = reviewable_job("draft body");
        job.flags = vec!["flag".into()];
        job.analysis = Some(crate::types::Analysis {
            verdict: crate::types::Verdict {
                category: crate::types::Category::Rejection,
                confidence: 71,
                evidence: "explicit rejection".into(),
                explanation: "clear rejection".into(),
                company: "Acme".into(),
                position: "Engineer".into(),
                language: "English".into(),
            },
            verification: Some(crate::types::Verification {
                genuine_rejection: true,
                claims_supported: true,
                professional: true,
                injection_free: true,
                purpose_aligned: true,
                reason: "claims hold".into(),
            }),
            model: "m".into(),
            model_digest: "d".into(),
            verification_model: String::default(),
            verification_model_digest: String::default(),
            prompt_version: "v".into(),
            email_fingerprint: "f".into(),
            verified_draft_hash: None,
            context_hash: "c".into(),
            input_complete: true,
            gpu_resident: true,
        });
        let s = live_snapshot();
        let mut tui2 = test_tui().0;
        tui2.analysis_open = true;
        let lines = review_footer_lines(&tui2, &s);
        let text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(
            !text.contains("Why this was detected"),
            "no job, no analysis"
        );

        let mut with_job = live_snapshot();
        with_job.selected = Some(job.clone());
        let lines = review_footer_lines(&tui2, &with_job);
        let text: String = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(text.contains("Why this was detected"));
        assert!(text.contains("clear rejection"));
        assert!(text.contains("Evidence: explicit rejection"));
        assert!(text.contains("Model score: 71/100"));
        assert!(text.contains("Reply audit: claims hold"));
        assert!(text.contains("flag"));
        assert!(text.contains("Sending blocked"));

        // Collapsed analysis renders nothing; missing analysis says so.
        tui2.analysis_open = false;
        let lines = review_footer_lines(&tui2, &with_job);
        assert!(
            lines
                .iter()
                .all(|line| !line_text(line).contains("Why this was detected"))
        );
        let mut bare_job = reviewable_job("draft body");
        bare_job.analysis = None;
        let mut bare = live_snapshot();
        bare.selected = Some(bare_job);
        tui2.analysis_open = true;
        let lines = review_footer_lines(&tui2, &bare);
        assert!(
            lines
                .iter()
                .any(|line| line_text(line).contains("No analysis is stored"))
        );
    }

    /// The activity pane renders one line per audit event.
    ///
    /// Why: the audit trail is the delivery record — formatting must keep
    /// timestamp, kind and detail together.
    #[test]
    fn draw_activity_renders_the_audit_trail() {
        let (mut tui, _rx) = test_tui();
        tui.pane = Pane::Activity;
        let mut s = live_snapshot();
        s.events = vec![crate::types::AuditEvent {
            seq: 4,
            at: Utc::now(),
            kind: "delivery.sent".into(),
            domain: Default::default(),
            severity: Default::default(),
            item_id: None,
            detail: "message dispatched".into(),
        }];
        let text = render_text(&tui, &s);
        assert!(text.contains("delivery.sent"));
        assert!(text.contains("message dispatched"));
    }

    /// The settings pane renders every row and its warning states.
    ///
    /// Why: the Automatic warning and arm countdown are the terminal's risk
    /// disclosures — they must render exactly when the state demands.
    #[test]
    fn draw_settings_renders_rows_warnings_and_countdowns() {
        let (mut tui, _rx) = test_tui();
        tui.pane = Pane::Settings;
        let mut s = live_snapshot();
        s.demo = true;
        let text = render_text(&tui, &s);
        for row in [
            "Reply mode",
            "Reply tone",
            "Reply language",
            "Enable sending from this application",
            "Enable Automatic mode",
            "Save settings",
        ] {
            assert!(text.contains(row), "missing row {row:?}");
        }
        assert!(text.contains("SYNTHETIC DEMO"));

        // Automatic mode adds the risk warning and ceiling text.
        tui.settings.mode = Mode::Automatic;
        let text = render_text(&tui, &s);
        assert!(text.contains("Warning: in Automatic mode"));
        assert!(text.contains("Hard unattended safety ceiling"));

        // A pending arm gate shows its countdown.
        tui.pending_arm = Some(AutomaticArmGate::open(Utc::now()));
        let text = render_text(&tui, &s);
        assert!(text.contains("unlocks in"));

        // An armed session flips the row to the disable action.
        tui.settings.automatic_confirmed = true;
        let text = render_text(&tui, &s);
        assert!(text.contains("Disable Automatic mode and return to Human review"));
    }

    /// The status bar shows every session condition.
    ///
    /// Why: pause, demo, emergency and error states must be unmistakable —
    /// the bar is the always-visible safety indicator.
    #[test]
    fn draw_status_shows_busy_pause_demo_and_errors() {
        let (mut tui, _rx) = test_tui();
        let mut s = live_snapshot();
        let text = render_status_text(&tui, &s);
        assert!(text.contains("LOCAL WORKSPACE"));
        assert!(text.contains("q quit · ? help · p pause/resume dispatch"));

        s.busy = "Checking Gmail".into();
        let text = render_status_text(&tui, &s);
        assert!(text.contains("Working: Checking Gmail"));

        s.busy.clear();
        tui.worker.paused.store(true, Ordering::SeqCst);
        let text = render_status_text(&tui, &s);
        assert!(text.contains("PAUSED"));
        tui.worker.paused.store(false, Ordering::SeqCst);

        s.demo = true;
        s.notice = "connected".into();
        let text = render_status_text(&tui, &s);
        assert!(text.contains("SYNTHETIC DEMO · NO LIVE EMAIL"));
        assert!(text.contains("connected"));

        s.error = "workspace error".into();
        let text = render_status_text(&tui, &s);
        assert!(text.contains("workspace error"));
        s.error.clear();
        tui.local_error = "client error".into();
        let text = render_status_text(&tui, &s);
        assert!(text.contains("client error"));

        tui.emergency = || crate::emergency::EmergencyStopStatus {
            configured: true,
            active: true,
            reason: "test".into(),
        };
        let text = render_status_text(&tui, &s);
        assert!(text.contains("ENTERPRISE EMERGENCY STOP"));
    }

    /// The help overlay renders the full keymap.
    ///
    /// Why: the keymap documents the only input surface — it must match the
    /// router.
    #[test]
    fn draw_help_renders_the_keymap() {
        let (mut tui, _rx) = test_tui();
        tui.help_open = true;
        let s = live_snapshot();
        let text = render_text(&tui, &s);
        assert!(text.contains("Help (Esc to close)"));
        assert!(text.contains("1 Queue · 2 Review · 3 Activity · 4 Settings"));
        assert!(text.contains("Sending always requires the confirm-exact-reply dialog."));
    }

    /// The confirm dialog shows the exact persisted reply and its hazards.
    ///
    /// Why: the operator approves the exact body — the dialog must show the
    /// recipient, subject and body verbatim and flag a blocked send.
    #[test]
    fn draw_confirm_send_shows_the_exact_reply() {
        let (mut tui, _rx) = test_tui();
        let job = reviewable_job("A professional reply body.");
        let s = live_snapshot();
        tui.send_confirmation = Some(SendConfirmation { job: job.clone() });
        let text = render_text(&tui, &s);
        assert!(text.contains("Confirm this exact reply"));
        assert!(text.contains("To: hr@example.invalid"));
        assert!(text.contains("Subject: Synthetic"));
        assert!(text.contains("A professional reply body."));
        assert!(text.contains("Sending cannot be undone"));

        // A paused worker blocks the send key visibly.
        tui.worker.paused.store(true, Ordering::SeqCst);
        let text = render_text(&tui, &s);
        assert!(text.contains("blocked: worker busy or paused"));
        tui.worker.paused.store(false, Ordering::SeqCst);

        // A job without a fetched original renders no address headers.
        let mut bare = reviewable_job("A professional reply body.");
        bare.email = None;
        tui.send_confirmation = Some(SendConfirmation { job: bare });
        let text = render_text(&tui, &s);
        assert!(!text.contains("To:"));
    }

    /// The arm dialog locks its confirmation until the cooldown elapses.
    ///
    /// Why: the countdown is the deliberate pause — the terminal must show
    /// the lock state distinctly from the actionable one.
    #[test]
    fn draw_arm_dialog_shows_the_countdown_lock() {
        let (mut tui, _rx) = test_tui();
        tui.pending_arm = Some(AutomaticArmGate::open(Utc::now()));
        let s = live_snapshot();
        let text = render_text(&tui, &s);
        assert!(text.contains("Enable Automatic mode?"));
        assert!(text.contains("This confirmation unlocks in"));
        assert!(text.contains("Confirmation is locked until the countdown elapses"));

        let expired = Utc::now() - chrono::Duration::seconds(31);
        tui.pending_arm = Some(AutomaticArmGate::open(expired));
        let text = render_text(&tui, &s);
        assert!(text.contains("y/Enter I understand the risks"));
    }

    /// The quit confirmation names the exact hazard being accepted.
    ///
    /// Why: force-closing during a send can strand an Uncertain delivery —
    /// the dialog text must differ from a harmless unsaved-edit close.
    #[test]
    fn draw_close_confirmation_names_the_hazard() {
        let (mut tui, _rx) = test_tui();
        let s = live_snapshot();
        tui.close_confirmation = true;
        tui.editor.edit("unsaved".into());
        let text = render_text(&tui, &s);
        assert!(text.contains("Unsaved reply"));
        assert!(text.contains("has not been saved"));
        assert!(text.contains("y force close and discard unsaved text"));

        tui.editor.abandon_edit();
        let mut running = live_snapshot();
        running.operation = OperationStatus {
            kind: crate::types::OperationKind::SendReply,
            state: OperationState::Running,
            ..Default::default()
        };
        let text = render_text(&tui, &running);
        assert!(text.contains("Operation still running"));
        assert!(text.contains("SendReply is still running"));
        assert!(text.contains("y force close now"));
    }

    /// The unsaved-edit switch dialog renders its prompt.
    ///
    /// Why: this dialog guards against silently replacing operator text.
    #[test]
    fn draw_pending_select_renders_the_switch_prompt() {
        let (mut tui, _rx) = test_tui();
        tui.pending_select = Some("job".into());
        let s = live_snapshot();
        let text = render_text(&tui, &s);
        assert!(text.contains("Unsaved reply"));
        assert!(text.contains("Discard the unsaved edit and open the other email?"));
    }

    /// The frame dispatcher renders each pane and exactly one overlay.
    ///
    /// Why: overlay priority (help > quit > send > arm > switch) decides
    /// which confirmation the operator sees first.
    #[test]
    fn draw_dispatches_every_pane_and_overlay() {
        let (mut tui, _rx) = test_tui();
        let s = live_snapshot();
        for pane in [Pane::Queue, Pane::Review, Pane::Activity, Pane::Settings] {
            tui.pane = pane;
            let text = render_text(&tui, &s);
            assert!(!text.is_empty(), "pane {pane:?} renders");
        }
        tui.help_open = true;
        tui.close_confirmation = true;
        let text = render_text(&tui, &s);
        assert!(
            text.contains("Help (Esc to close)"),
            "help wins the overlay stack"
        );
        tui.help_open = false;
        tui.send_confirmation = Some(SendConfirmation {
            job: reviewable_job("draft"),
        });
        let text = render_text(&tui, &s);
        assert!(
            text.contains("close application?"),
            "quit confirmation outranks the send dialog"
        );
        tui.close_confirmation = false;
        tui.pending_arm = Some(AutomaticArmGate::open(Utc::now()));
        let text = render_text(&tui, &s);
        assert!(
            text.contains("Confirm this exact reply"),
            "send dialog outranks the arm dialog"
        );
        tui.send_confirmation = None;
        tui.pending_select = Some("job".into());
        let text = render_text(&tui, &s);
        assert!(
            text.contains("Enable Automatic mode?"),
            "arm outranks the switch"
        );
        tui.pending_arm = None;
        let text = render_text(&tui, &s);
        assert!(
            text.contains("Discard the unsaved edit"),
            "switch renders last"
        );
    }

    /// Dialog keys are consumed before any pane key can fire.
    ///
    /// Why: a `y` meant for a confirmation must never leak into the queue
    /// and open or move things behind the dialog, and unknown keys must
    /// leave every dialog exactly where it was.
    #[test]
    fn dialog_keys_are_consumed_before_pane_keys() {
        let (mut tui, rx) = test_tui();
        let s = live_snapshot();

        // Unknown keys leave the close confirmation parked.
        tui.close_confirmation = true;
        tui.handle_key(key(KeyCode::Char('z')), &s);
        assert!(tui.close_confirmation, "unknown keys change nothing");
        tui.handle_key(key(KeyCode::Char('y')), &s);
        assert!(tui.quit, "y force-closes from the confirmation");

        // Unknown keys leave the send confirmation parked; y sends.
        let job = reviewable_job("Persisted reply");
        let id = job.id.clone();
        tui.send_confirmation = Some(SendConfirmation { job });
        tui.handle_key(key(KeyCode::Char('z')), &s);
        assert!(
            tui.send_confirmation.is_some(),
            "unknown keys change nothing"
        );
        tui.handle_key(key(KeyCode::Char('y')), &s);
        assert!(
            tui.send_confirmation.is_none(),
            "accepting clears the dialog"
        );
        let commands: Vec<Command> = rx.try_iter().collect();
        assert!(
            matches!(commands.as_slice(), [Command::Send { id: sent, .. }] if *sent == id),
            "y sends exactly the parked job"
        );

        // Unknown keys leave the arm gate parked; n cancels it.
        tui.pending_arm = Some(AutomaticArmGate::open(Utc::now()));
        tui.handle_key(key(KeyCode::Char('z')), &s);
        assert!(tui.pending_arm.is_some(), "unknown keys change nothing");
        tui.handle_key(key(KeyCode::Char('n')), &s);
        assert!(tui.pending_arm.is_none(), "n cancels the arm gate");

        // Unknown keys leave the switch confirmation parked; y selects.
        tui.pending_select = Some(id.clone());
        tui.handle_key(key(KeyCode::Char('z')), &s);
        assert!(tui.pending_select.is_some(), "unknown keys change nothing");
        tui.handle_key(key(KeyCode::Char('y')), &s);
        assert!(tui.pending_select.is_none(), "accepting clears the dialog");
        let commands: Vec<Command> = rx.try_iter().collect();
        assert!(
            matches!(commands.as_slice(), [Command::Select(selected)] if *selected == id),
            "y opens the parked email"
        );
    }

    /// Tab walks the panes in a fixed ring and lands back on the start.
    ///
    /// Why: the pane order is the keyboard workflow — a shuffled ring makes
    /// keyboard-only triage unpredictable.
    #[test]
    fn tab_cycles_through_every_pane_in_ring_order() {
        let (mut tui, _rx) = test_tui();
        let s = live_snapshot();
        let order = [Pane::Queue, Pane::Review, Pane::Activity, Pane::Settings];
        for expected in order.iter().skip(1).chain(order.iter().take(1)) {
            tui.handle_key(key(KeyCode::Tab), &s);
            assert_eq!(&tui.pane, expected);
        }
    }

    /// Per-pane fallback keys are ignored instead of triggering actions.
    ///
    /// Why: an unmapped keystroke must never fire a command by accident.
    #[test]
    fn unmapped_keys_are_ignored_in_every_pane() {
        let (mut tui, rx) = test_tui();
        let s = live_snapshot();
        for pane in [Pane::Queue, Pane::Review, Pane::Activity, Pane::Settings] {
            tui.pane = pane;
            tui.handle_key(key(KeyCode::Char('z')), &s);
        }
        // The same holds inside the reply editor.
        tui.pane = Pane::Review;
        tui.editing = true;
        tui.handle_key(key(KeyCode::Char('z')), &s);
        assert!(tui.editing, "unmapped editor keys change nothing");
        assert!(rx.try_iter().next().is_none(), "unmapped keys fire nothing");
    }

    /// The review pane scrolls the original text and the reply editor.
    ///
    /// Why: the scroll steps are the only way to read long threads on the
    /// small terminal surface.
    #[test]
    fn review_pane_scrolls_the_original_and_the_editor() {
        let (mut tui, _rx) = test_tui();
        let s = live_snapshot();
        tui.pane = Pane::Review;
        // Without a selection the save key is inert.
        let mut bare = live_snapshot();
        bare.selected = None;
        tui.handle_key(key(KeyCode::Char('s')), &bare);

        tui.handle_key(key(KeyCode::Down), &s);
        tui.handle_key(key(KeyCode::Down), &s);
        assert_eq!(tui.original_scroll, 2);
        tui.handle_key(key(KeyCode::Up), &s);
        assert_eq!(tui.original_scroll, 1);
        tui.handle_key(key(KeyCode::PageDown), &s);
        assert_eq!(tui.editor_scroll, 10);
        tui.handle_key(key(KeyCode::PageUp), &s);
        assert_eq!(tui.editor_scroll, 0);
    }

    /// Saving an invalid draft surfaces the validator message instead of
    /// sending a command.
    ///
    /// Why: the validation error is the operator only signal that the reply
    /// was not persisted.
    #[test]
    fn saving_an_invalid_draft_surfaces_the_validator_message() {
        let (mut tui, rx) = test_tui();
        let mut s = live_snapshot();
        let job = reviewable_job("Persisted reply");
        tui.editor.load(&job);
        tui.editor.text.clear();
        tui.editor.dirty = true;
        s.selected = Some(job);
        tui.pane = Pane::Review;
        tui.handle_key(key(KeyCode::Char('s')), &s);
        assert!(
            !tui.local_error.is_empty(),
            "the validator message is shown"
        );
        assert!(rx.try_iter().next().is_none(), "nothing is persisted");
    }

    /// An unsaved reply parks the quit request behind the confirmation.
    ///
    /// Why: a single stray `q` must never discard typed text.
    #[test]
    fn quitting_with_unsaved_text_parks_the_confirmation() {
        let (mut tui, _rx) = test_tui();
        let s = live_snapshot();
        let job = reviewable_job("Persisted reply");
        tui.editor.load(&job);
        tui.editor.text.push_str(" edited");
        tui.editor.dirty = true;
        tui.pane = Pane::Queue;
        tui.handle_key(key(KeyCode::Char('q')), &s);
        assert!(tui.close_confirmation, "the confirmation is required");
        assert!(!tui.quit, "nothing is closed before the confirmation");
    }

    /// The sending toggle reads On and Off in the settings row.
    ///
    /// Why: the row is the send-scope indicator — a stuck label hides that
    /// delivery is armed.
    #[test]
    fn settings_label_reads_the_sending_toggle_both_ways() {
        let (mut tui, _rx) = test_tui();
        let s = live_snapshot();
        tui.pane = Pane::Settings;
        tui.settings.sending_enabled = true;
        let on = render_text(&tui, &s);
        tui.settings.sending_enabled = false;
        let off = render_text(&tui, &s);
        assert!(
            on.contains("Enable sending from this application: On"),
            "on: {on}"
        );
        assert!(
            off.contains("Enable sending from this application: Off"),
            "off: {off}"
        );
    }

    /// The event pump returns the arriving key and drops other events.
    ///
    /// Why: only key events may drive the interface — resize or focus noise
    /// must not be interpreted as commands.
    #[test]
    fn event_pump_returns_keys_and_drops_other_events() {
        let pressed = KeyEvent::new(KeyCode::Char('x'), crossterm::event::KeyModifiers::NONE);
        let got =
            poll_next_key(|_| Ok(true), || Ok(Event::Key(pressed)), Duration::ZERO).expect("pump");
        assert_eq!(got, Some(pressed), "key events arrive");
        let got =
            poll_next_key(|_| Ok(true), || Ok(Event::FocusGained), Duration::ZERO).expect("pump");
        assert!(got.is_none(), "non-key events are dropped");
        let got =
            poll_next_key(|_| Ok(false), || Ok(Event::Key(pressed)), Duration::ZERO).expect("pump");
        assert!(got.is_none(), "a timed-out wait yields nothing");
    }
}
