#![no_main]

use libfuzzer_sys::fuzz_target;
use rejection_rejector::mail::{
    auto_language_conflict, automatic_draft_conflict, clear_rejection_language, current_text,
    validate_draft,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let current = current_text(&text);

    // Policy helpers must remain total for arbitrary hostile email text.
    let rejection = clear_rejection_language("", &text);
    let conflict = auto_language_conflict("", &text);
    let _ = validate_draft(&text);
    let _ = automatic_draft_conflict(&text, "");

    // A quoted-only historical rejection must never become stronger after
    // current-message extraction.
    if current.is_empty() {
        assert!(!clear_rejection_language("", &current));
    }

    // Deterministic policy functions must be stable across identical inputs.
    assert_eq!(rejection, clear_rejection_language("", &text));
    assert_eq!(conflict, auto_language_conflict("", &text));
});
