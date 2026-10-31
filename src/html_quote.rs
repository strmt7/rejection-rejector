//! Structural current-versus-quoted extraction for HTML mail bodies.
//!
//! Mail clients wrap forwarded and reply history in semantic blockquotes and
//! well-known classed containers. Flattening HTML to text before deciding
//! provenance lets stale quoted rejection language read as current content
//! (security review finding 13). This module prunes quoted-history subtrees
//! from the HTML structurally — using the full html5ever tokenizer, not
//! pattern matching — and reports ambiguity instead of guessing: a container
//! that carries quote-like markers but is not a known quote shape keeps its
//! text and marks the capture incomplete, so Automatic mode fails closed.

use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
};
use std::cell::RefCell;

/// How one element relates to the current message versus quoted history.
///
/// Inputs: none (plain enum). Output: the classification driving pruning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuoteRole {
    /// Ordinary current-message content.
    Current,
    /// Quoted history: removed from the extracted text entirely.
    Removed,
    /// Quote-like but unrecognized: text is kept but the capture is marked
    /// incomplete so unattended sending fails closed.
    Ambiguous,
}

/// Known mail-client quoted-history markers matched against an element's
/// `class` and `id` attributes (ASCII-lowercased substring match).
///
/// Inputs: none (constant). Output: the marker list whose matches remove an
/// element subtree as quoted history.
const REMOVED_MARKERS: &[&str] = &[
    "gmail_quote",
    "yahoo_quoted",
    "proton_quote",
    "moz-cite",
    "ilmo_quote",
    "divrplyfwdmsg",
    "quoted-content",
    "quotedcontent",
    "quoted-reply",
    "quotedreply",
    "mail_quote",
    "mailquote",
];

/// Quote-like markers that are not recognized client containers: their
/// presence marks the capture ambiguous (incomplete) rather than removing
/// content.
///
/// Inputs: none (constant). Output: the marker list whose matches flag
/// ambiguity.
const AMBIGUOUS_MARKERS: &[&str] = &["quote", "quoted", "citation", "fwdmsg", "forwarded"];

/// Classify one start tag as current, removed quoted history, or ambiguous.
///
/// Inputs: `name` — lowercased element name; `class_id` — the concatenated
/// ASCII-lowercased `class` and `id` attribute values; `cite_typed` — whether
/// the element carries `type="cite"`. Output: [`QuoteRole`].
fn classify(name: &str, class_id: &str, cite_typed: bool) -> QuoteRole {
    if name == "blockquote" || cite_typed {
        return QuoteRole::Removed;
    }
    if REMOVED_MARKERS.iter().any(|m| class_id.contains(m)) {
        return QuoteRole::Removed;
    }
    if AMBIGUOUS_MARKERS.iter().any(|m| class_id.contains(m)) {
        return QuoteRole::Ambiguous;
    }
    QuoteRole::Current
}

/// Escape text for HTML re-emission.
///
/// Inputs: `text` — raw character data. Output: `String` with `&`, `<` and
/// `>` entity-escaped.
fn escape_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Escape an attribute value for HTML re-emission.
///
/// Inputs: `value` — raw attribute value. Output: `String` with `&`, `<`,
/// `>` and `"` entity-escaped.
fn escape_attr(value: &str) -> String {
    escape_text(value).replace('"', "&quot;")
}

/// Token sink that re-emits the document with quoted-history subtrees
/// removed and ambiguity recorded.
///
/// Inputs: none (plain struct). Output: the cleaned HTML, the open-element
/// stack and the ambiguity flag held behind interior mutability (the
/// tokenizer sink API takes `&self`).
struct QuotePruner {
    /// Cleaned HTML accumulated so far.
    out: RefCell<String>,
    /// Open elements as `(lowercased name, started a removed subtree)`.
    stack: RefCell<Vec<(String, bool)>>,
    /// Whether an ambiguous quote-like container was seen.
    ambiguous: RefCell<bool>,
}

impl QuotePruner {
    /// Create an empty pruner.
    ///
    /// Inputs: none. Output: `Self`.
    fn new() -> Self {
        Self {
            out: RefCell::new(String::new()),
            stack: RefCell::new(Vec::new()),
            ambiguous: RefCell::new(false),
        }
    }

    /// Whether any open element is a removed subtree root.
    ///
    /// Inputs: none beyond the sink. Output: `true` while inside quoted
    /// history.
    fn dropping(&self) -> bool {
        self.stack.borrow().iter().any(|(_, dropped)| *dropped)
    }
}

impl TokenSink for QuotePruner {
    type Handle = ();

    /// Process one tokenizer event.
    ///
    /// Inputs: `token` — the tokenizer event; `_line_number` — source line
    /// (unused). Output: `TokenSinkResult::Continue` always; the cleaned HTML
    /// accumulates in the sink.
    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<Self::Handle> {
        match token {
            Token::CharacterTokens(text) => {
                if !self.dropping() {
                    self.out.borrow_mut().push_str(&escape_text(&text));
                }
            }
            Token::TagToken(tag) => match tag.kind {
                TagKind::StartTag => {
                    let name = (*tag.name).to_lowercase();
                    let mut class_id = String::new();
                    let mut cite_typed = false;
                    for attr in &tag.attrs {
                        let key = (*attr.name.local).to_lowercase();
                        match key.as_str() {
                            "class" | "id" => {
                                class_id.push_str(&attr.value.to_lowercase());
                                class_id.push(' ');
                            }
                            "type" => cite_typed = attr.value.eq_ignore_ascii_case("cite"),
                            _ => {}
                        }
                    }
                    let role = classify(&name, &class_id, cite_typed);
                    let dropping = self.dropping();
                    if !dropping && role == QuoteRole::Ambiguous {
                        *self.ambiguous.borrow_mut() = true;
                    }
                    if tag.self_closing {
                        if !dropping && role != QuoteRole::Removed {
                            let mut out = self.out.borrow_mut();
                            out.push('<');
                            out.push_str(&name);
                            for attr in &tag.attrs {
                                out.push(' ');
                                out.push_str(&attr.name.local);
                                out.push_str("=\"");
                                out.push_str(&escape_attr(&attr.value));
                                out.push('"');
                            }
                            out.push_str(" />");
                        }
                        return TokenSinkResult::Continue;
                    }
                    if role == QuoteRole::Removed {
                        self.stack.borrow_mut().push((name, true));
                        return TokenSinkResult::Continue;
                    }
                    if !dropping {
                        let mut out = self.out.borrow_mut();
                        out.push('<');
                        out.push_str(&name);
                        for attr in &tag.attrs {
                            out.push(' ');
                            out.push_str(&attr.name.local);
                            out.push_str("=\"");
                            out.push_str(&escape_attr(&attr.value));
                            out.push('"');
                        }
                        out.push('>');
                    }
                    self.stack.borrow_mut().push((name, false));
                }
                TagKind::EndTag => {
                    let name = (*tag.name).to_lowercase();
                    let mut stack = self.stack.borrow_mut();
                    let mut closed_removed = false;
                    let mut matched = false;
                    while let Some((open, dropped)) = stack.pop() {
                        closed_removed |= dropped;
                        if open == name {
                            matched = true;
                            break;
                        }
                    }
                    drop(stack);
                    if matched && !closed_removed && !self.dropping() {
                        self.out.borrow_mut().push_str(&format!("</{name}>"));
                    }
                }
            },
            // Comments, doctypes and parse errors are never message content.
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

/// Extract current-message text from one HTML mail body.
///
/// Quoted-history subtrees (semantic blockquotes and known mail-client
/// containers) are removed structurally before flattening, so stale quoted
/// language can never read as current evidence. Unrecognized quote-like
/// containers keep their text but mark the capture incomplete, failing
/// Automatic mode closed.
///
/// Inputs: `html` — the raw text/html body of one MIME part. Output:
/// `(String, bool)` — the flattened current-message text and whether the
/// current-versus-quoted split was structurally confident.
pub(crate) fn current_html_to_text(html: &str) -> (String, bool) {
    let sink = QuotePruner::new();
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let buffer = BufferQueue::default();
    buffer.push_back(StrTendril::from(html));
    let _ = tokenizer.feed(&buffer);
    tokenizer.end();
    let cleaned = tokenizer.sink.out.into_inner();
    let confident = !*tokenizer.sink.ambiguous.borrow();
    match html2text::from_read(cleaned.as_bytes(), 100) {
        Ok(text) => (text, confident),
        // A conversion failure keeps no evidence and loses confidence: the
        // message must not proceed automatically (fail closed).
        Err(_) => (String::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // why (security review finding 13): stale rejection language inside a
    // well-known client quote container must never mint current-message
    // evidence for an automatic reply.
    #[test]
    fn client_quote_containers_never_supply_rejection_evidence() {
        let html = "<div>Thank you for applying.</div><div class=\"gmail_quote\">\
            <blockquote>we are not moving forward with your application</blockquote></div>";
        let (text, confident) = current_html_to_text(html);
        assert!(
            !text.to_lowercase().contains("not moving forward"),
            "{text}"
        );
        assert!(text.contains("Thank you for applying"), "{text}");
        assert!(confident, "known containers are confident removals");
    }

    // why (security review finding 13): semantic blockquotes are quoted
    // history in mail, whatever the client.
    #[test]
    fn semantic_blockquotes_are_quoted_history() {
        let html = "<p>On reflection:</p><blockquote>Not selected.</blockquote>";
        let (text, confident) = current_html_to_text(html);
        assert!(!text.to_lowercase().contains("not selected"), "{text}");
        assert!(confident);
    }

    // why: current-message HTML rejection language must remain eligible —
    // the pruning must not over-remove ordinary content.
    #[test]
    fn current_message_html_rejection_remains_evidence() {
        let html = "<p>Dear candidate,</p><p>We have decided not to move \
            forward with your application.</p><p>Kind regards</p>";
        let (text, confident) = current_html_to_text(html);
        assert!(
            text.to_lowercase().contains("not to move forward"),
            "{text}"
        );
        assert!(confident);
    }

    // why (security review finding 13): an unrecognized quote-like container
    // keeps its text for Human Review but must mark the capture incomplete,
    // so unattended sending fails closed instead of guessing provenance.
    #[test]
    fn unrecognized_quote_like_containers_fail_closed() {
        let html = "<div class=\"reply-quoted-material\">Not selected.</div>";
        let (text, confident) = current_html_to_text(html);
        assert!(text.to_lowercase().contains("not selected"), "{text}");
        assert!(!confident, "unrecognized quote shapes must be ambiguous");
    }

    // why: current content on both sides of a removed quote must survive
    // intact and in order.
    #[test]
    fn current_text_around_removed_quotes_survives() {
        let html = "<p>before</p><blockquote>history</blockquote><p>after</p>";
        let (text, _confident) = current_html_to_text(html);
        let before = text.find("before").expect("before kept");
        let after = text.find("after").expect("after kept");
        assert!(before < after);
        assert!(!text.contains("history"));
    }

    // why (state-machine arms): self-closing tags in current content pass
    // through without disturbing the drop state, and text on both sides
    // survives in order.
    #[test]
    fn self_closing_current_tags_keep_the_stream_intact() {
        let html = "<p>a<br class=\"x\"/>b</p>";
        let (text, confident) = current_html_to_text(html);
        assert!(confident, "current content is never ambiguous");
        let a = text.find('a').expect("a kept");
        let b = text.find('b').expect("b kept");
        assert!(a < b);
    }

    // why (state-machine arms): self-closing tags inside a removed quote are
    // removed with the subtree — nothing leaks into the current message.
    #[test]
    fn self_closing_tags_inside_removed_quotes_never_leak() {
        let html = "<blockquote class=\"gmail_quote\"><hr/></blockquote>after";
        let (text, confident) = current_html_to_text(html);
        assert!(confident);
        assert!(text.contains("after"));
        assert!(
            !text.contains("hr"),
            "quoted self-closing tags leak: {text}"
        );
    }

    // why (state-machine arms): type="cite" removes the subtree exactly like
    // the known client markers, and unrecognized attribute names pass through
    // classification untouched.
    #[test]
    fn type_cite_removes_and_unknown_attributes_pass_through() {
        let (text, confident) = current_html_to_text("<div type=\"cite\">old</div>new");
        assert!(confident);
        assert!(text.contains("new"), "{text}");
        assert!(!text.contains("old"), "{text}");
        let (text, confident) = current_html_to_text("<a data-x=\"1\" href=\"u\">t</a>");
        assert!(confident);
        assert!(text.contains("t"), "{text}");
    }

    // why (state-machine arms): an end tag with no matching open tag pops
    // the whole stack without emitting anything and without dropping
    // subsequent current text.
    #[test]
    fn orphan_end_tags_pop_silently() {
        let (text, confident) = current_html_to_text("left</p></div>right");
        assert!(confident);
        assert!(text.contains("left") && text.contains("right"), "{text}");
        assert!(!text.contains("</p>") && !text.contains("</div>"), "{text}");
    }

    // why (state-machine arms): an end tag that closes current text across
    // a dropped subtree never re-emits the dropped interior's closing tag,
    // and the surrounding current text survives.
    #[test]
    fn end_tag_across_a_dropped_subtree_stays_removed() {
        let html = "<em>keep<blockquote>q</em>after";
        let (text, confident) = current_html_to_text(html);
        assert!(confident);
        assert!(text.contains("keep") && text.contains("after"), "{text}");
        assert!(!text.contains('q'), "{text}");
        assert!(!text.contains("</em>"), "{text}");
    }
}
