//! Local web interface (`rr web`) request handling and pure gate composition.
//!
//! The web surface is a thin presentation shell like the desktop and terminal
//! interfaces: the embedded page ( [`WEB_PAGE_HTML`] ) is served by the
//! loopback API and drives the worker exclusively through the same `Command`
//! channel. This module holds everything that is decidable without side
//! effects — request payload validation, body-size caps, the write-gate
//! composition built on the shared [`crate::engine::send_gate_eligible`] gate,
//! and the `AutomaticArmGate` cooldown checks — so the failure modes are unit
//! testable and no interface re-implements a safety decision.
//!
//! Rendering rule for the embedded page: email content is always inserted as
//! plain text (`textContent`), never as HTML markup.

use crate::{
    config::{self, AutomaticArmGate, Mode, ReplyLanguage, Settings, Tone},
    engine::{SendGateContext, editor_binding_matches, send_gate_eligible, visible_draft_matches},
    mail::validate_draft,
    types::{Job, OperationKind, OperationStatus},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Embedded single-page UI (HTML + CSS + JS, no external assets).
///
/// Included verbatim at compile time; the server may never load anything
/// from the network on the page's behalf.
pub const WEB_PAGE_HTML: &str = include_str!("web_ui.html");

/// Content type for the embedded page.
pub const WEB_PAGE_CONTENT_TYPE: &str = "text/html; charset=utf-8";

/// Strict Content-Security-Policy set on every response.
///
/// Nothing may load except the embedded page's own inline style/script and
/// same-origin API calls (`connect-src 'self'`); images, fonts, frames, form
/// submissions and external origins are all denied.
pub const WEB_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; \
script-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; font-src 'none'; \
object-src 'none'; media-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Hard cap on any state-changing request body, in bytes.
///
/// The largest accepted payload is an edited draft (6000 bytes of text per
/// [`validate_draft`]); the cap leaves JSON-escaping headroom while ensuring
/// an oversized body is refused before parsing or dispatch.
pub const MAX_WRITE_BODY_BYTES: usize = 16_384;

/// Write route: edit the persisted draft of one reviewable job.
pub const EDIT_DRAFT_ROUTE: &str = "/v1/commands/edit-draft";
/// Write route: discard the draft and request a fresh local analysis.
pub const REGENERATE_ROUTE: &str = "/v1/commands/regenerate";
/// Write route: dismiss one reviewable job without sending.
pub const DISMISS_ROW_ROUTE: &str = "/v1/commands/dismiss";
/// Write route: send the exact persisted draft after confirm-exact-reply.
pub const SEND_ROUTE: &str = "/v1/commands/send";
/// Write route: persist edited settings (tone, reply language, sending, mode).
pub const UPDATE_SETTINGS_ROUTE: &str = "/v1/commands/update-settings";
/// Write route: drive the cooldown-gated Automatic-mode arming flow.
pub const AUTOMATIC_ARM_ROUTE: &str = "/v1/commands/automatic-arm";

/// Stable machine-readable error code: the request body or JSON shape was rejected.
pub const CODE_INVALID_REQUEST: &str = "invalid_request";
/// Stable machine-readable error code: the request body exceeded [`MAX_WRITE_BODY_BYTES`].
pub const CODE_REQUEST_BODY_TOO_LARGE: &str = "request_body_too_large";
/// Stable machine-readable error code: the write targeted an unknown route.
pub const CODE_ROUTE_NOT_FOUND: &str = "route_not_found";
/// Stable machine-readable error code: the route exists but not for this method.
pub const CODE_METHOD_NOT_ALLOWED: &str = "method_not_allowed";
/// Stable machine-readable error code: the referenced message does not exist here.
pub const CODE_ITEM_NOT_FOUND: &str = "item_not_found";
/// Stable machine-readable error code: the (id, revision) binding is stale or the message is no longer reviewable.
pub const CODE_STALE_REVISION: &str = "stale_revision";
/// Stable machine-readable error code: the confirm-exact-reply payload does not match the persisted draft.
pub const CODE_CONFIRM_REPLY_MISMATCH: &str = "confirm_reply_mismatch";
/// Stable machine-readable error code: the shared send gate refused the send.
pub const CODE_SEND_GATE_BLOCKED: &str = "send_gate_blocked";
/// Stable machine-readable error code: the reply text is not a valid sendable draft.
pub const CODE_INVALID_DRAFT: &str = "invalid_draft";
/// Stable machine-readable error code: the command needs Human review mode.
pub const CODE_WRONG_MODE: &str = "wrong_mode";
/// Stable machine-readable error code: the command is unavailable in demonstration mode.
pub const CODE_DEMO_BLOCKED: &str = "demo_blocked";
/// Stable machine-readable error code: the Automatic-arm cooldown has not elapsed yet.
pub const CODE_AUTOMATIC_ARM_COOLDOWN: &str = "automatic_arm_cooldown";
/// Stable machine-readable error code: no Automatic-arm cooldown gate is open.
pub const CODE_AUTOMATIC_ARM_NOT_OPEN: &str = "automatic_arm_not_open";
/// Stable machine-readable error code: Automatic mode requires arming and sending first.
pub const CODE_AUTOMATIC_NOT_ARMED: &str = "automatic_not_armed";
/// Stable machine-readable error code: the engine refused the write without a typed dispatch code.
pub const CODE_WRITE_REJECTED: &str = "write_rejected";

/// Typed rejection of one state-changing request.
///
/// Inputs: none (plain struct). Output: the HTTP status, the stable error
/// `code`, a human-readable `message` (never echoing request content) and the
/// `retryable` flag of the stable error envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteError {
    /// HTTP status code for the response.
    pub status: u16,
    /// Stable machine-readable error code (see the `CODE_*` constants).
    pub code: String,
    /// Human-readable explanation that never echoes private request content.
    pub message: String,
    /// Whether a bounded retry may succeed without operator action.
    pub retryable: bool,
}

impl WriteError {
    /// Build a non-retryable typed rejection.
    ///
    /// Inputs: `status` — HTTP status; `code` — stable error code; `message`
    /// — human-readable explanation. Output: [`WriteError`] with
    /// `retryable = false`.
    pub fn reject(status: u16, code: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            retryable: false,
        }
    }
}

/// Actions of the cooldown-gated Automatic-arm flow.
///
/// Inputs: none (plain enum). Output: which arm step a request performs;
/// `Confirm` is only accepted after the server-side cooldown elapses.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticArmAction {
    /// Start the 30-second cooldown and show the risk warning.
    Open,
    /// Acknowledge the risk warning once the cooldown elapsed.
    Confirm,
    /// Abandon the pending arming; stay in Human review.
    Cancel,
}

/// One parsed state-changing web request, mirroring the worker `Command` channel.
///
/// Inputs: none (plain enum). Output: the typed command the worker will be
/// asked to run, already payload-validated but not yet gate-checked.
#[derive(Clone, Debug, PartialEq)]
pub enum WriteRequest {
    /// Persist an operator-edited reply draft (`Command::Edit`).
    EditDraft {
        /// Message id (64 hex characters).
        id: String,
        /// Revision the editor was loaded for.
        revision: u64,
        /// New reply text.
        body: String,
    },
    /// Discard the draft and request a fresh local analysis (`Command::Regenerate`).
    Regenerate {
        /// Message id (64 hex characters).
        id: String,
        /// Revision the editor was loaded for.
        revision: u64,
    },
    /// Dismiss the message without sending (`Command::Dismiss`).
    Dismiss {
        /// Message id (64 hex characters).
        id: String,
        /// Revision the editor was loaded for.
        revision: u64,
    },
    /// Send the exact persisted draft (`Command::Send`).
    Send {
        /// Message id (64 hex characters).
        id: String,
        /// Revision the approval was given for.
        revision: u64,
        /// Exact reply text the operator confirmed; must equal the persisted draft.
        confirm_reply: String,
    },
    /// Persist edited settings (`Command::Settings`); `None` fields stay unchanged.
    UpdateSettings {
        /// New operating mode, if changed.
        mode: Option<Mode>,
        /// New reply-tone level, if changed.
        tone: Option<Tone>,
        /// New reply-language policy, if changed.
        reply_language: Option<ReplyLanguage>,
        /// New sending toggle, if changed.
        sending_enabled: Option<bool>,
    },
    /// Drive the Automatic-arm cooldown gate.
    AutomaticArm {
        /// Which arm step to perform.
        action: AutomaticArmAction,
    },
}

impl WriteRequest {
    /// Worker operation kind recorded for this request.
    ///
    /// Inputs: none. Output: the [`OperationKind`] the worker marks for the
    /// operation lifecycle (same kinds the desktop and terminal commands use).
    pub fn operation_kind(&self) -> OperationKind {
        match self {
            Self::EditDraft { .. } => OperationKind::EditDraft,
            Self::Regenerate { .. } => OperationKind::RegenerateDraft,
            Self::Dismiss { .. } => OperationKind::DismissItem,
            Self::Send { .. } => OperationKind::SendReply,
            Self::UpdateSettings { .. } | Self::AutomaticArm { .. } => {
                OperationKind::UpdateSettings
            }
        }
    }
}

/// Outcome of one executed (or rejected) write, ready for the wire.
///
/// Inputs: none (plain struct). Output: the HTTP status plus the response
/// body fragment — the success payload for `status < 400`, otherwise the
/// stable `error` object `{code, message, retryable}`.
#[derive(Clone, Debug, PartialEq)]
pub struct WriteOutcome {
    /// HTTP status code for the response.
    pub status: u16,
    /// Success payload or stable error object.
    pub body: Value,
}

impl WriteOutcome {
    /// Build a successful outcome carrying the typed operation status.
    ///
    /// Inputs: `operation` — finished operation status. Output:
    /// [`WriteOutcome`] with status 200 and body
    /// `{"accepted": true, "operation": ...}`.
    pub fn accepted(operation: &OperationStatus) -> Self {
        Self {
            status: 200,
            body: json!({ "accepted": true, "operation": operation }),
        }
    }

    /// Build a successful outcome with an extra payload fragment.
    ///
    /// Inputs: `payload` — JSON object merged into the response (for example
    /// the arm countdown or the resulting settings view). Output:
    /// [`WriteOutcome`] with status 200 and body `{"accepted": true, ...}`.
    pub fn accepted_with(payload: Value) -> Self {
        let mut body = json!({ "accepted": true });
        if let (Some(target), Some(source)) = (body.as_object_mut(), payload.as_object()) {
            target.extend(
                source
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        Self { status: 200, body }
    }

    /// Build a typed rejection outcome from a [`WriteError`].
    ///
    /// Inputs: `error` — typed rejection. Output: [`WriteOutcome`] carrying
    /// the error's status and stable `{code, message, retryable}` body.
    pub fn error(error: &WriteError) -> Self {
        Self {
            status: error.status,
            body: json!({
                "code": error.code,
                "message": error.message,
                "retryable": error.retryable
            }),
        }
    }

    /// Merge an extra payload fragment into a successful outcome.
    ///
    /// Inputs: `payload` — JSON object whose fields are added to `body`.
    /// Output: none; error outcomes are left untouched so the stable error
    /// object can never gain foreign fields.
    pub fn merge_payload(&mut self, payload: Value) {
        if self.status < 400
            && let (Some(target), Some(source)) = (self.body.as_object_mut(), payload.as_object())
        {
            target.extend(
                source
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
    }
}

/// Wrap a write outcome in the stable response envelope.
///
/// Inputs: `request_id` — per-request correlation UUID; `outcome` — write
/// outcome. Output: JSON carrying `api_version`, `request_id` and either the
/// success payload fields or `error {code, message, retryable}` — the same
/// envelope the read API uses.
pub fn response_envelope(request_id: &str, outcome: &WriteOutcome) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("api_version".into(), json!(crate::api::API_VERSION));
    map.insert("request_id".into(), json!(request_id));
    if outcome.status >= 400 {
        map.insert("error".into(), outcome.body.clone());
    } else if let Some(source) = outcome.body.as_object() {
        map.extend(
            source
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
    Value::Object(map)
}

/// Non-secret settings fields the embedded page renders.
///
/// Inputs: `settings` — current settings. Output: JSON object with `mode`,
/// `tone`, `reply_language`, `sending_enabled`, `automatic_confirmed` and the
/// `automatic_arm_cooldown_seconds` the countdown uses; no credentials, paths
/// or mailbox identity are ever exposed.
pub fn settings_view(settings: &Settings) -> Value {
    json!({
        "mode": settings.mode,
        "tone": settings.tone,
        "reply_language": settings.reply_language,
        "sending_enabled": settings.sending_enabled,
        "automatic_confirmed": settings.automatic_confirmed,
        "automatic_arm_cooldown_seconds": config::AUTOMATIC_ARM_COOLDOWN_SECONDS
    })
}

/// Cooldown status of the Automatic-arm gate shown by the page.
///
/// Inputs: none (plain struct). Output: the visible countdown plus whether
/// the risk confirmation may be acknowledged yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ArmGateView {
    /// Seconds left on the cooldown; `0` once it has elapsed.
    pub remaining_seconds: i64,
    /// Whether the risk confirmation may be acknowledged yet.
    pub confirm_enabled: bool,
}

/// Read the cooldown status of an open Automatic-arm gate.
///
/// Inputs: `gate` — open cooldown gate; `now` — current time. Output:
/// [`ArmGateView`]; `confirm_enabled` is `true` only once the full
/// [`config::AUTOMATIC_ARM_COOLDOWN_SECONDS`] cooldown has elapsed.
pub fn arm_gate_view(gate: &AutomaticArmGate, now: DateTime<Utc>) -> ArmGateView {
    ArmGateView {
        remaining_seconds: gate.remaining(now).num_seconds().max(0),
        confirm_enabled: gate.can_confirm(now),
    }
}

/// Validate a message identifier from a write payload.
///
/// Inputs: `id` — untrusted identifier string. Output: `Ok(())` for exactly
/// 64 ASCII hex characters (the persisted id shape), otherwise a typed
/// [`WriteError`] with code [`CODE_INVALID_REQUEST`].
pub fn validate_item_id(id: &str) -> Result<(), WriteError> {
    if id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(WriteError::reject(
            400,
            CODE_INVALID_REQUEST,
            "Message identifiers must be 64 hex characters",
        ))
    }
}

/// Whether `route` is one of the state-changing write routes.
///
/// Inputs: `route` — request path including any query string. Output:
/// `true` only for the exact write-route constants (a query suffix makes the
/// path a different route and is rejected).
pub fn is_write_route(route: &str) -> bool {
    matches!(
        route,
        EDIT_DRAFT_ROUTE
            | REGENERATE_ROUTE
            | DISMISS_ROW_ROUTE
            | SEND_ROUTE
            | UPDATE_SETTINGS_ROUTE
            | AUTOMATIC_ARM_ROUTE
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditDraftPayload {
    id: String,
    revision: u64,
    body: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionPayload {
    id: String,
    revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SendPayload {
    id: String,
    revision: u64,
    confirm_reply: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateSettingsPayload {
    mode: Option<Mode>,
    tone: Option<Tone>,
    reply_language: Option<ReplyLanguage>,
    sending_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutomaticArmPayload {
    action: AutomaticArmAction,
}

/// Parse one state-changing request body into a typed [`WriteRequest`].
///
/// Inputs: `route` — exact write route; `body` — raw request body. Output:
/// the parsed request, or a typed [`WriteError`]: oversized bodies fail with
/// [`CODE_REQUEST_BODY_TOO_LARGE`] before parsing, unknown routes with
/// [`CODE_ROUTE_NOT_FOUND`], and malformed or unknown-field JSON with
/// [`CODE_INVALID_REQUEST`] (never echoing the submitted content).
pub fn parse_write_request(route: &str, body: &[u8]) -> Result<WriteRequest, WriteError> {
    if !is_write_route(route) {
        return Err(WriteError::reject(
            404,
            CODE_ROUTE_NOT_FOUND,
            "Unknown state-changing route",
        ));
    }
    if body.len() > MAX_WRITE_BODY_BYTES {
        return Err(WriteError::reject(
            413,
            CODE_REQUEST_BODY_TOO_LARGE,
            "The request body exceeds the fixed local write limit",
        ));
    }
    let invalid = || {
        WriteError::reject(
            400,
            CODE_INVALID_REQUEST,
            "The request body is not a valid payload for this command",
        )
    };
    match route {
        EDIT_DRAFT_ROUTE => {
            let payload: EditDraftPayload = serde_json::from_slice(body).map_err(|_| invalid())?;
            validate_item_id(&payload.id)?;
            Ok(WriteRequest::EditDraft {
                id: payload.id,
                revision: payload.revision,
                body: payload.body,
            })
        }
        REGENERATE_ROUTE | DISMISS_ROW_ROUTE => {
            let payload: RevisionPayload = serde_json::from_slice(body).map_err(|_| invalid())?;
            validate_item_id(&payload.id)?;
            let (id, revision) = (payload.id, payload.revision);
            Ok(if route == REGENERATE_ROUTE {
                WriteRequest::Regenerate { id, revision }
            } else {
                WriteRequest::Dismiss { id, revision }
            })
        }
        SEND_ROUTE => {
            let payload: SendPayload = serde_json::from_slice(body).map_err(|_| invalid())?;
            validate_item_id(&payload.id)?;
            Ok(WriteRequest::Send {
                id: payload.id,
                revision: payload.revision,
                confirm_reply: payload.confirm_reply,
            })
        }
        UPDATE_SETTINGS_ROUTE => {
            let payload: UpdateSettingsPayload =
                serde_json::from_slice(body).map_err(|_| invalid())?;
            Ok(WriteRequest::UpdateSettings {
                mode: payload.mode,
                tone: payload.tone,
                reply_language: payload.reply_language,
                sending_enabled: payload.sending_enabled,
            })
        }
        AUTOMATIC_ARM_ROUTE => {
            let payload: AutomaticArmPayload =
                serde_json::from_slice(body).map_err(|_| invalid())?;
            Ok(WriteRequest::AutomaticArm {
                action: payload.action,
            })
        }
        _ => Err(WriteError::reject(
            404,
            CODE_ROUTE_NOT_FOUND,
            "Unknown state-changing route",
        )),
    }
}

/// Reject a write whose `(id, revision)` binding is no longer current.
///
/// Inputs: `job` — looked-up job; `revision` — revision the request was
/// issued for. Output: `Ok(())` only while the job is reviewable at exactly
/// that revision; anything else is [`CODE_STALE_REVISION`] so a stale editor
/// can never overwrite or act on a newer state.
pub fn guard_review_write(job: &Job, revision: u64) -> Result<(), WriteError> {
    if job.state.reviewable() && job.revision == revision {
        Ok(())
    } else {
        Err(WriteError::reject(
            409,
            CODE_STALE_REVISION,
            "Message changed; reload before editing",
        ))
    }
}

/// Gate composition for dismissing a reviewable job without sending.
///
/// Inputs: `job` — looked-up job; `revision` — revision the request was
/// issued for. Output: `Ok(())` only while the job is reviewable at exactly
/// that revision, otherwise [`CODE_STALE_REVISION`].
pub fn guard_dismiss(job: &Job, revision: u64) -> Result<(), WriteError> {
    guard_review_write(job, revision)
}

/// Validate an edited reply before it is persisted.
///
/// Inputs: `body` — proposed reply text. Output: `Ok(())` when
/// [`validate_draft`] accepts the text, otherwise a typed [`WriteError`] with
/// code [`CODE_INVALID_DRAFT`] so unsendable drafts are never stored.
pub fn guard_draft_body(body: &str) -> Result<(), WriteError> {
    validate_draft(body).map_err(|_| {
        WriteError::reject(
            400,
            CODE_INVALID_DRAFT,
            "Reply must be 20..6000 bytes, at most 400 words and free of unsafe control characters",
        )
    })
}

/// Gate composition for editing a draft (Human review only).
///
/// Inputs: `job` — looked-up job; `revision` — revision the editor was bound
/// to; `body` — proposed reply text; `mode` — current operating mode.
/// Output: `Ok(())` when the edit may proceed; otherwise a typed
/// [`WriteError`] ([`CODE_WRONG_MODE`], [`CODE_STALE_REVISION`] or
/// [`CODE_INVALID_DRAFT`]).
pub fn guard_edit(job: &Job, revision: u64, body: &str, mode: Mode) -> Result<(), WriteError> {
    if mode != Mode::HumanReview {
        return Err(WriteError::reject(
            409,
            CODE_WRONG_MODE,
            "Editing is available only in Human review mode",
        ));
    }
    guard_review_write(job, revision)?;
    guard_draft_body(body)
}

/// Gate composition for requesting a fresh local analysis.
///
/// Inputs: `job` — looked-up job; `revision` — revision the editor was bound
/// to; `mode` — current operating mode; `demo` — demonstration-mode flag.
/// Output: `Ok(())` when regeneration may proceed; otherwise a typed
/// [`WriteError`] ([`CODE_WRONG_MODE`], [`CODE_STALE_REVISION`] or
/// [`CODE_DEMO_BLOCKED`]).
pub fn guard_regenerate(
    job: &Job,
    revision: u64,
    mode: Mode,
    demo: bool,
) -> Result<(), WriteError> {
    if mode != Mode::HumanReview {
        return Err(WriteError::reject(
            409,
            CODE_WRONG_MODE,
            "Regeneration is available only in Human review mode",
        ));
    }
    guard_review_write(job, revision)?;
    if demo {
        return Err(WriteError::reject(
            409,
            CODE_DEMO_BLOCKED,
            "Demo does not run a local model",
        ));
    }
    Ok(())
}

/// Parameters of a send request as confirmed by the operator.
///
/// Inputs: none (plain struct). Output: the identity binding and the exact
/// reply text whose byte-for-byte match with the persisted draft is the
/// confirm-exact-reply rule.
pub struct SendRequest<'a> {
    /// Message id the approval names.
    pub id: &'a str,
    /// Revision the approval was given for.
    pub revision: u64,
    /// Exact reply text shown in the confirm dialog.
    pub confirm_reply: &'a str,
}

/// Presentation-independent runtime state feeding the shared send gate.
///
/// Inputs: none (plain struct). Output: the same [`SendGateContext`] inputs
/// the desktop and terminal interfaces collect from their own state.
pub struct SendRuntime<'a> {
    /// Mail-level sending blocks that apply to the original message.
    pub hard_blocks: &'a [String],
    /// Whether background work is currently in flight.
    pub busy: bool,
    /// Whether sending has been explicitly enabled in settings.
    pub sending_enabled: bool,
    /// Whether the workspace runs in demonstration mode.
    pub demo: bool,
    /// Whether the background worker is paused.
    pub paused: bool,
}

/// Compose the shared send-gate context for one web send request.
///
/// Inputs: `job` — candidate job; `request` — confirmed send request;
/// `runtime` — current runtime state. Output: the [`SendGateContext`] handed
/// to [`send_gate_eligible`]; the editor is bound to
/// `(request.id, request.revision)` via [`editor_binding_matches`] and shows
/// exactly `request.confirm_reply` (a web editor holds no unsaved state: only
/// the confirmed exact text ever reaches a send).
pub fn send_gate_context<'a>(
    job: &Job,
    request: &SendRequest<'a>,
    runtime: &SendRuntime<'a>,
) -> SendGateContext<'a> {
    let key = (request.id.to_string(), request.revision);
    SendGateContext {
        editor_text: request.confirm_reply,
        editor_bound: editor_binding_matches(job, Some(&key)),
        dirty: false,
        hard_blocks: runtime.hard_blocks,
        busy: runtime.busy,
        sending_enabled: runtime.sending_enabled,
        demo: runtime.demo,
        paused: runtime.paused,
    }
}

/// Gate composition for sending the confirmed exact reply.
///
/// Inputs: `job` — candidate job; `request` — confirmed send request;
/// `runtime` — current runtime state. Output: `Ok(())` only when the editor
/// binding is current ([`CODE_STALE_REVISION`]), the confirm payload matches
/// the persisted draft byte for byte ([`CODE_CONFIRM_REPLY_MISMATCH`]) and
/// the shared [`send_gate_eligible`] gate passes
/// ([`CODE_SEND_GATE_BLOCKED`]); the shared gate stays authoritative and this
/// function only composes it.
pub fn guard_send(
    job: &Job,
    request: &SendRequest<'_>,
    runtime: &SendRuntime<'_>,
) -> Result<(), WriteError> {
    let context = send_gate_context(job, request, runtime);
    if !context.editor_bound {
        return Err(WriteError::reject(
            409,
            CODE_STALE_REVISION,
            "Approval is stale or names a different message; reload before sending",
        ));
    }
    if !visible_draft_matches(job, request.confirm_reply) {
        return Err(WriteError::reject(
            409,
            CODE_CONFIRM_REPLY_MISMATCH,
            "The confirmed reply does not match the persisted draft byte for byte",
        ));
    }
    if !send_gate_eligible(job, &context) {
        return Err(WriteError::reject(
            409,
            CODE_SEND_GATE_BLOCKED,
            "The shared send gate refuses this send right now",
        ));
    }
    Ok(())
}

/// Gate composition for persisting an edited settings copy.
///
/// Inputs: `settings` — merged settings candidate. Output: `Ok(())` for
/// Human-review mode always; in Automatic mode only when sending is enabled
/// and the risk confirmation was armed (the same save gate the desktop and
/// terminal interfaces enforce), otherwise [`CODE_AUTOMATIC_NOT_ARMED`].
pub fn guard_settings(settings: &Settings) -> Result<(), WriteError> {
    if settings.mode != Mode::Automatic
        || (settings.sending_enabled && settings.automatic_confirmed)
    {
        Ok(())
    } else {
        Err(WriteError::reject(
            409,
            CODE_AUTOMATIC_NOT_ARMED,
            "Automatic mode requires sending to be enabled and the risk confirmation to be armed",
        ))
    }
}

/// Gate composition for acknowledging the Automatic-arm risk warning.
///
/// Inputs: `pending` — open cooldown gate (`None` when no arm dialog is
/// open); `now` — current time. Output: the resulting [`ArmGateView`] once
/// the full cooldown has elapsed, or a typed [`WriteError`]:
/// [`CODE_AUTOMATIC_ARM_NOT_OPEN`] without an open gate and
/// [`CODE_AUTOMATIC_ARM_COOLDOWN`] while the countdown still runs — the
/// warning can never be clicked through in one motion, server-side.
pub fn guard_arm_confirm(
    pending: Option<&AutomaticArmGate>,
    now: DateTime<Utc>,
) -> Result<ArmGateView, WriteError> {
    let Some(gate) = pending else {
        return Err(WriteError::reject(
            409,
            CODE_AUTOMATIC_ARM_NOT_OPEN,
            "No Automatic-arm confirmation is pending",
        ));
    };
    let view = arm_gate_view(gate, now);
    if view.confirm_enabled {
        Ok(view)
    } else {
        Err(WriteError::reject(
            409,
            CODE_AUTOMATIC_ARM_COOLDOWN,
            format!(
                "The Automatic-arm confirmation unlocks in {} second(s)",
                view.remaining_seconds
            ),
        ))
    }
}

/// Merge a partial settings edit into a copy of the current settings.
///
/// Inputs: `current` — effective settings; `mode`, `tone`, `reply_language`,
/// `sending_enabled` — optional edits (`None` keeps the current value).
/// Output: the merged candidate ready for [`guard_settings`] and
/// `Engine::update_settings`; every non-edited field (model, limits, API
/// configuration) is preserved verbatim.
pub fn merge_settings(
    current: &Settings,
    mode: Option<Mode>,
    tone: Option<Tone>,
    reply_language: Option<ReplyLanguage>,
    sending_enabled: Option<bool>,
) -> Settings {
    let mut merged = current.clone();
    merged.mode = mode.unwrap_or(merged.mode);
    merged.tone = tone.unwrap_or(merged.tone);
    merged.reply_language = reply_language.unwrap_or(merged.reply_language);
    merged.sending_enabled = sending_enabled.unwrap_or(merged.sending_enabled);
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Draft, JobState};

    /// Build a reviewable job with a persisted draft and a non-zero revision.
    ///
    /// Inputs: `body` — persisted draft text. Output: [`Job`] in `Ready`
    /// state with a synthetic email, the given draft and revision 3 (so a
    /// default `0` revision can never accidentally pass a binding check).
    fn reviewable_job(body: &str) -> Job {
        let email = crate::ollama::sample_email("Synthetic", "Synthetic rejection");
        let mut job = Job::new(email.stub.clone(), Utc::now());
        job.email = Some(email);
        job.state = JobState::Ready;
        job.draft = Some(Draft {
            body: body.into(),
            origin: "human".into(),
        });
        job.revision = 3;
        job
    }

    /// Build an all-green runtime for the shared send gate.
    ///
    /// Inputs: none. Output: [`SendRuntime`] with every runtime gate open.
    fn open_runtime() -> SendRuntime<'static> {
        SendRuntime {
            hard_blocks: &[],
            busy: false,
            sending_enabled: true,
            demo: false,
            paused: false,
        }
    }

    const CONFIRM_TEXT: &str =
        "Please reconsider this rejection against the advertised requirements.";

    // why: an oversized body must never reach the JSON parser or the worker;
    // the cap is what keeps the loopback listener memory-bounded.
    #[test]
    fn oversized_write_body_is_rejected_before_parsing() {
        let body = vec![b'x'; MAX_WRITE_BODY_BYTES + 1];
        let error = parse_write_request(EDIT_DRAFT_ROUTE, &body).unwrap_err();
        assert_eq!(error.code, CODE_REQUEST_BODY_TOO_LARGE);
        assert_eq!(error.status, 413);
        assert_eq!(
            parse_write_request(EDIT_DRAFT_ROUTE, &body[..MAX_WRITE_BODY_BYTES])
                .unwrap_err()
                .code,
            CODE_INVALID_REQUEST
        );
    }

    // why: payload validation must fail closed on unknown routes, unknown
    // fields and malformed shapes instead of silently dropping data.
    #[test]
    fn write_payloads_reject_unknown_routes_fields_and_shapes() {
        let unknown_route = parse_write_request("/v1/commands/unknown", b"{}").unwrap_err();
        assert_eq!(unknown_route.code, CODE_ROUTE_NOT_FOUND);
        let query_suffix = parse_write_request(&format!("{SEND_ROUTE}?x=1"), b"{}").unwrap_err();
        assert_eq!(query_suffix.code, CODE_ROUTE_NOT_FOUND);
        for body in [
            &b"{\"id\":\"a\",\"revision\":1,\"body\":\"x\",\"extra\":true}"[..],
            &b"{\"revision\":1}"[..],
            &b"not json"[..],
            &b"{\"id\":\"zz\",\"revision\":1,\"body\":\"x\"}"[..],
            &b"{\"id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"revision\":-1,\"body\":\"x\"}"[..],
        ] {
            let error = parse_write_request(EDIT_DRAFT_ROUTE, body).unwrap_err();
            assert_eq!(error.code, CODE_INVALID_REQUEST, "body: {}", String::from_utf8_lossy(body));
        }
    }

    // why: a stale editor must never overwrite a newer revision, and a job
    // that left review can never be edited, regenerated or dismissed again.
    #[test]
    fn stale_revision_writes_are_rejected_for_every_review_command() {
        let job = reviewable_job(CONFIRM_TEXT);
        for revision in [2, 4] {
            let error = guard_review_write(&job, revision).unwrap_err();
            assert_eq!(error.code, CODE_STALE_REVISION);
            assert_eq!(error.status, 409);
        }
        let mut dismissed = reviewable_job(CONFIRM_TEXT);
        dismissed.state = JobState::Dismissed;
        assert_eq!(
            guard_review_write(&dismissed, dismissed.revision)
                .unwrap_err()
                .code,
            CODE_STALE_REVISION
        );
        assert!(guard_review_write(&job, job.revision).is_ok());
    }

    // why: the wrong-mode and invalid-draft refusals are safety-adjacent
    // (they keep unsendable drafts and mode bypasses off the wire) and must
    // surface as stable codes rather than engine prose.
    #[test]
    fn edit_rejects_wrong_mode_and_invalid_drafts() {
        let job = reviewable_job(CONFIRM_TEXT);
        assert_eq!(
            guard_edit(&job, job.revision, CONFIRM_TEXT, Mode::Automatic)
                .unwrap_err()
                .code,
            CODE_WRONG_MODE
        );
        assert_eq!(
            guard_edit(&job, job.revision, "too short", Mode::HumanReview)
                .unwrap_err()
                .code,
            CODE_INVALID_DRAFT
        );
        assert!(guard_edit(&job, job.revision, CONFIRM_TEXT, Mode::HumanReview).is_ok());
    }

    // why: regeneration runs the local model, which demo mode must never do,
    // and only Human review may discard a draft.
    #[test]
    fn regenerate_is_blocked_in_demo_and_automatic_mode() {
        let job = reviewable_job(CONFIRM_TEXT);
        assert_eq!(
            guard_regenerate(&job, job.revision, Mode::Automatic, false)
                .unwrap_err()
                .code,
            CODE_WRONG_MODE
        );
        assert_eq!(
            guard_regenerate(&job, job.revision, Mode::HumanReview, true)
                .unwrap_err()
                .code,
            CODE_DEMO_BLOCKED
        );
        assert!(guard_regenerate(&job, job.revision, Mode::HumanReview, false).is_ok());
    }

    // why: the confirm-exact-reply rule is byte-for-byte; a payload that
    // differs in any byte (even whitespace) must never authorize a send.
    #[test]
    fn send_with_non_matching_confirm_payload_is_rejected() {
        let job = reviewable_job(CONFIRM_TEXT);
        let request = SendRequest {
            id: &job.id,
            revision: job.revision,
            confirm_reply: &format!("{CONFIRM_TEXT} "),
        };
        let error = guard_send(&job, &request, &open_runtime()).unwrap_err();
        assert_eq!(error.code, CODE_CONFIRM_REPLY_MISMATCH);
        assert_eq!(error.status, 409);
    }

    // why: the send command must carry the exact (id, revision) pair the
    // approval was given for; a stale or foreign binding can never send.
    #[test]
    fn send_with_stale_editor_binding_is_rejected() {
        let job = reviewable_job(CONFIRM_TEXT);
        let stale = SendRequest {
            id: &job.id,
            revision: job.revision + 1,
            confirm_reply: CONFIRM_TEXT,
        };
        assert_eq!(
            guard_send(&job, &stale, &open_runtime()).unwrap_err().code,
            CODE_STALE_REVISION
        );
        let foreign = SendRequest {
            id: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            revision: job.revision,
            confirm_reply: CONFIRM_TEXT,
        };
        assert_eq!(
            guard_send(&job, &foreign, &open_runtime())
                .unwrap_err()
                .code,
            CODE_STALE_REVISION
        );
    }

    // why: the shared send gate is authoritative; every runtime block the
    // desktop honors (busy, paused, demo, disabled sending, hard blocks)
    // must block the web exactly the same way, with no local re-logic.
    #[test]
    fn send_is_composed_through_the_shared_send_gate() {
        let job = reviewable_job(CONFIRM_TEXT);
        let request = SendRequest {
            id: &job.id,
            revision: job.revision,
            confirm_reply: CONFIRM_TEXT,
        };
        assert!(guard_send(&job, &request, &open_runtime()).is_ok());
        let blocked = vec!["Message is blocked by mailbox safety checks".to_string()];
        let variants = [
            SendRuntime {
                busy: true,
                ..open_runtime()
            },
            SendRuntime {
                paused: true,
                ..open_runtime()
            },
            SendRuntime {
                demo: true,
                ..open_runtime()
            },
            SendRuntime {
                sending_enabled: false,
                ..open_runtime()
            },
            SendRuntime {
                hard_blocks: &blocked,
                ..open_runtime()
            },
        ];
        for runtime in variants {
            assert_eq!(
                guard_send(&job, &request, &runtime).unwrap_err().code,
                CODE_SEND_GATE_BLOCKED
            );
        }
    }

    // why: the 30-second cooldown is server-side; a confirm issued early must
    // be refused with the visible remainder so the page cannot click through
    // the risk warning in one motion.
    #[test]
    fn automatic_arm_confirm_before_cooldown_is_rejected() {
        let gate = AutomaticArmGate::open(Utc::now());
        let error = guard_arm_confirm(Some(&gate), Utc::now()).unwrap_err();
        assert_eq!(error.code, CODE_AUTOMATIC_ARM_COOLDOWN);
        assert_eq!(error.status, 409);
        assert!(error.message.contains("second(s)"));
    }

    // why: confirming without an open gate must fail closed, and the same
    // gate must open up exactly when the documented cooldown elapsed.
    #[test]
    fn automatic_arm_confirm_requires_an_open_gate_and_passes_after_the_cooldown() {
        let now = Utc::now();
        assert_eq!(
            guard_arm_confirm(None, now).unwrap_err().code,
            CODE_AUTOMATIC_ARM_NOT_OPEN
        );
        let gate = AutomaticArmGate::open(now);
        let elapsed = now + chrono::Duration::seconds(config::AUTOMATIC_ARM_COOLDOWN_SECONDS + 1);
        let view = guard_arm_confirm(Some(&gate), elapsed).unwrap();
        assert!(view.confirm_enabled);
        assert_eq!(view.remaining_seconds, 0);
    }

    // why: the desktop save gate forbids saving Automatic mode without
    // sending enabled and an acknowledged risk confirmation; the web applies
    // the identical rule instead of a local variant.
    #[test]
    fn automatic_settings_save_requires_arming_and_sending() {
        let unconfirmed = Settings {
            mode: Mode::Automatic,
            ..Settings::default()
        };
        assert_eq!(
            guard_settings(&unconfirmed).unwrap_err().code,
            CODE_AUTOMATIC_NOT_ARMED
        );
        let armed_without_sending = Settings {
            mode: Mode::Automatic,
            automatic_confirmed: true,
            ..Settings::default()
        };
        assert_eq!(
            guard_settings(&armed_without_sending).unwrap_err().code,
            CODE_AUTOMATIC_NOT_ARMED
        );
        let armed = Settings {
            mode: Mode::Automatic,
            automatic_confirmed: true,
            sending_enabled: true,
            ..Settings::default()
        };
        assert!(guard_settings(&armed).is_ok());
        let human_review = Settings::default();
        assert!(guard_settings(&human_review).is_ok());
    }

    // why: settings edits must be partial merges; changing one row may never
    // reset the model, limits or API configuration stored alongside it.
    #[test]
    fn settings_merge_preserves_every_unedited_field() {
        let current = Settings {
            model: "pinned-model".into(),
            daily_send_limit: 7,
            ..Settings::default()
        };
        let merged = merge_settings(
            &current,
            Some(Mode::Automatic),
            Some(Tone::Insane),
            Some(ReplyLanguage::English),
            Some(true),
        );
        assert_eq!(merged.mode, Mode::Automatic);
        assert_eq!(merged.tone, Tone::Insane);
        assert_eq!(merged.reply_language, ReplyLanguage::English);
        assert!(merged.sending_enabled);
        assert_eq!(merged.model, "pinned-model");
        assert_eq!(merged.daily_send_limit, 7);
    }

    // why: integrations key on the stable error-code strings; renaming one
    // silently would break every consumer that branches on it.
    #[test]
    fn error_codes_and_envelope_are_stable() {
        let job = reviewable_job(CONFIRM_TEXT);
        assert_eq!(
            guard_review_write(&job, 0).unwrap_err().code,
            "stale_revision"
        );
        let request = SendRequest {
            id: &job.id,
            revision: job.revision,
            confirm_reply: "x",
        };
        assert_eq!(
            guard_send(&job, &request, &open_runtime())
                .unwrap_err()
                .code,
            "confirm_reply_mismatch"
        );
        let outcome =
            WriteOutcome::error(&guard_send(&job, &request, &open_runtime()).unwrap_err());
        assert_eq!(outcome.status, 409);
        let envelope = response_envelope("request-123", &outcome);
        assert_eq!(envelope["api_version"], crate::api::API_VERSION);
        assert_eq!(envelope["request_id"], "request-123");
        assert_eq!(envelope["error"]["code"], "confirm_reply_mismatch");
        assert_eq!(envelope["error"]["retryable"], false);
        assert!(envelope.get("accepted").is_none());
        let accepted = WriteOutcome::accepted_with(json!({"arm": {"remaining_seconds": 30}}));
        let envelope = response_envelope("request-456", &accepted);
        assert_eq!(envelope["accepted"], true);
        assert_eq!(envelope["arm"]["remaining_seconds"], 30);
        assert!(envelope.get("error").is_none());
    }

    // why: the parsed command must mirror the worker Command channel exactly;
    // a mapping slip would dispatch the wrong operation kind and journal it.
    #[test]
    fn parsed_requests_map_to_their_worker_operation_kinds() {
        let id = "a".repeat(64);
        let edit = parse_write_request(
            EDIT_DRAFT_ROUTE,
            format!(r#"{{"id":"{id}","revision":2,"body":"{}"}}"#, CONFIRM_TEXT).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            edit,
            WriteRequest::EditDraft {
                id: id.clone(),
                revision: 2,
                body: CONFIRM_TEXT.into()
            }
        );
        assert_eq!(edit.operation_kind(), OperationKind::EditDraft);
        let send = parse_write_request(
            SEND_ROUTE,
            format!(
                r#"{{"id":"{id}","revision":2,"confirm_reply":"{}"}}"#,
                CONFIRM_TEXT
            )
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(send.operation_kind(), OperationKind::SendReply);
        let arm = parse_write_request(AUTOMATIC_ARM_ROUTE, b"{\"action\":\"open\"}").unwrap();
        assert_eq!(
            arm,
            WriteRequest::AutomaticArm {
                action: AutomaticArmAction::Open
            }
        );
        assert_eq!(arm.operation_kind(), OperationKind::UpdateSettings);
        let settings = parse_write_request(
            UPDATE_SETTINGS_ROUTE,
            b"{\"tone\":\"insane\",\"reply_language\":\"english\",\"sending_enabled\":true}",
        )
        .unwrap();
        assert_eq!(
            settings,
            WriteRequest::UpdateSettings {
                mode: None,
                tone: Some(Tone::Insane),
                reply_language: Some(ReplyLanguage::English),
                sending_enabled: Some(true)
            }
        );
    }

    // why: regenerate and dismiss are the two remaining write routes whose
    // parsing arms and worker-operation mapping were never exercised; a
    // swapped arm (dismiss parsing as regenerate) would silently issue the
    // wrong worker command for the same payload shape.
    #[test]
    fn regenerate_and_dismiss_parse_and_map_to_their_operations() {
        let id = "b".repeat(64);
        let regen = parse_write_request(
            REGENERATE_ROUTE,
            format!(r#"{{"id":"{id}","revision":7}}"#).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            regen,
            WriteRequest::Regenerate {
                id: id.clone(),
                revision: 7
            }
        );
        assert_eq!(regen.operation_kind(), OperationKind::RegenerateDraft);
        let dismiss = parse_write_request(
            DISMISS_ROW_ROUTE,
            format!(r#"{{"id":"{id}","revision":9}}"#).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            dismiss,
            WriteRequest::Dismiss {
                id: id.clone(),
                revision: 9
            }
        );
        assert_eq!(dismiss.operation_kind(), OperationKind::DismissItem);
    }

    // why: the revision is the CAS binding for every state change; u64::MAX
    // must be representable exactly while 2^64, negatives and fractions must
    // fail closed instead of wrapping or truncating into a live revision.
    #[test]
    fn revision_parsing_fails_closed_at_the_u64_boundary() {
        let id = "c".repeat(64);
        let max = parse_write_request(
            DISMISS_ROW_ROUTE,
            format!(r#"{{"id":"{id}","revision":18446744073709551615}}"#).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            max,
            WriteRequest::Dismiss {
                id: id.clone(),
                revision: u64::MAX
            }
        );
        for bad in ["18446744073709551616", "-1", "1.5", "\"7\"", "null"] {
            let body = format!(r#"{{"id":"{id}","revision":{bad}}}"#);
            let error = parse_write_request(DISMISS_ROW_ROUTE, body.as_bytes()).unwrap_err();
            assert_eq!(error.code, CODE_INVALID_REQUEST, "{bad} must not parse");
        }
    }

    // why: the dismiss gate must bind to the same reviewable revision as the
    // edit gate; a looser binding would let a stale editor discard a job that
    // has already moved on.
    #[test]
    fn dismiss_gate_binds_to_the_same_reviewable_revision() {
        let job = reviewable_job(CONFIRM_TEXT);
        assert!(guard_dismiss(&job, 3).is_ok());
        for stale in [0, 2, 4, u64::MAX] {
            assert_eq!(
                guard_dismiss(&job, stale).unwrap_err().code,
                CODE_STALE_REVISION
            );
        }
    }

    // why: success outcomes are assembled on the wire; `accepted` must carry
    // the typed operation status, merges must only extend success bodies, and
    // a non-object payload must be a no-op instead of a panic or a corrupted
    // envelope. Error bodies must never gain foreign fields.
    #[test]
    fn write_outcomes_merge_extras_only_into_success_bodies() {
        let accepted = WriteOutcome::accepted(&OperationStatus::default());
        assert_eq!(accepted.status, 200);
        assert_eq!(accepted.body["accepted"], true);
        assert!(accepted.body.get("operation").is_some());

        let mut merged = WriteOutcome::accepted_with(json!({"operation": {"kind": "edit_draft"}}));
        assert_eq!(merged.status, 200);
        assert_eq!(merged.body["operation"]["kind"], "edit_draft");
        let scalar = WriteOutcome::accepted_with(json!("plain"));
        assert_eq!(scalar.body["accepted"], true);
        assert_eq!(scalar.body.as_object().unwrap().len(), 1);

        merged.merge_payload(json!({"extra": 1}));
        assert_eq!(merged.body["extra"], 1);
        let mut scalar_target = WriteOutcome::accepted_with(json!({"a": 1}));
        scalar_target.merge_payload(json!("nope"));
        assert_eq!(scalar_target.body["a"], 1);

        let mut rejected =
            WriteOutcome::error(&WriteError::reject(409, CODE_STALE_REVISION, "stale"));
        rejected.merge_payload(json!({"extra": 1}));
        assert!(rejected.body.get("extra").is_none());
        assert_eq!(rejected.body["code"], CODE_STALE_REVISION);
    }

    // why: the response envelope is the stable integration contract;
    // successful bodies must merge their payload fields at the top level
    // while rejections must wrap the stable error object and nothing else.
    #[test]
    fn response_envelope_merges_success_fields_and_wraps_errors() {
        let ok = WriteOutcome::accepted_with(json!({"operation": {"kind": "send_reply"}}));
        let envelope = response_envelope("req-1", &ok);
        assert_eq!(envelope["api_version"], crate::api::API_VERSION);
        assert_eq!(envelope["request_id"], "req-1");
        assert_eq!(envelope["accepted"], true);
        assert_eq!(envelope["operation"]["kind"], "send_reply");
        assert!(envelope.get("error").is_none());

        let bad = WriteOutcome::error(&WriteError::reject(413, CODE_REQUEST_BODY_TOO_LARGE, "big"));
        let envelope = response_envelope("req-2", &bad);
        assert_eq!(envelope["request_id"], "req-2");
        assert_eq!(envelope["error"]["code"], CODE_REQUEST_BODY_TOO_LARGE);
        assert!(envelope.get("accepted").is_none());

        // A success carrying a non-object body must still emit the stable
        // envelope instead of panicking or dropping the correlation id.
        let non_object = WriteOutcome {
            status: 200,
            body: json!("scalar"),
        };
        let envelope = response_envelope("req-3", &non_object);
        assert_eq!(envelope["request_id"], "req-3");
        assert!(envelope.get("accepted").is_none());
    }
}
