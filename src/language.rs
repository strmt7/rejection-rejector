//! Deterministic language detection and reply-language enforcement.
//!
//! Model output alone never decides the reply language: the expected language
//! is derived here from the current (de-quoted) email text, and the drafted
//! reply is verified against it before the draft can proceed.

use anyhow::{Result, ensure};
use lingua::{Language, LanguageDetector, LanguageDetectorBuilder};

/// The twelve fully supported languages (ISO 639-1 code, English name).
///
/// These are named explicitly in the prompt contract and covered by the
/// evaluation fixtures. Other languages are attempted best-effort through the
/// same pipeline when `reply_language` is `auto`.
pub const SUPPORTED_LANGUAGES: [(&str, &str); 12] = [
    ("en", "English"),
    ("zh", "Mandarin Chinese"),
    ("hi", "Hindi"),
    ("es", "Spanish"),
    ("fr", "French"),
    ("ar", "Arabic"),
    ("bn", "Bengali"),
    ("pt", "Portuguese"),
    ("ru", "Russian"),
    ("ur", "Urdu"),
    ("de", "German"),
    ("el", "Greek"),
];

/// Minimum words before a leading segment is considered substantive.
const SUBSTANTIVE_SEGMENT_WORDS: usize = 3;

/// Minimum words before a drafted reply's language counts as verifiable.
const MIN_VERIFIABLE_REPLY_WORDS: usize = 5;

fn detector() -> LanguageDetector {
    LanguageDetectorBuilder::from_all_languages()
        .with_preloaded_language_models()
        .build()
}

/// Map a detected language to its ISO 639-1 code.
///
/// Inputs: `language` — a lingua `Language`. Output: lowercase two-letter code.
fn iso_code(language: Language) -> String {
    language.iso_code_639_1().to_string().to_lowercase()
}

/// Detect the reply language of an email: its first substantive language.
///
/// Inputs: `text` — the current de-quoted email body. Output: ISO 639-1 code
/// of the first language segment that is substantive: at least three words and
/// at least 40% of the longest segment's word count. Interjection-length
/// openers ("Hello! Thank you for your message.") therefore never decide the
/// language over the actual rejection body. Falls back to the dominant
/// language of the whole text, then to `fallback`.
pub fn first_language(text: &str, fallback: &str) -> String {
    let det = detector();
    let segments = det.detect_multiple_languages_of(text);
    let longest = segments
        .iter()
        .map(lingua::DetectionResult::word_count)
        .max()
        .unwrap_or(0);
    for segment in &segments {
        if segment.word_count() >= SUBSTANTIVE_SEGMENT_WORDS
            && segment.word_count() * 10 >= longest * 4
        {
            return iso_code(segment.language());
        }
    }
    det.detect_language_of(text)
        .map(iso_code)
        .unwrap_or_else(|| fallback.to_string())
}

/// Detect the dominant language of a text.
///
/// Inputs: `text` — any text. Output: ISO 639-1 code, or `None` when the
/// detector cannot decide.
pub fn dominant_language(text: &str) -> Option<String> {
    detector().detect_language_of(text).map(iso_code)
}

/// Enforce that a drafted reply is written in the expected language.
///
/// Inputs: `reply` — drafted reply body; `expected` — ISO 639-1 code required
/// for the reply. Output: `Ok(())` when the draft's dominant language matches;
/// an error naming both languages otherwise, so a mismatched draft is held
/// rather than sent. A draft too short to detect is rejected as unverifiable.
pub fn ensure_reply_language(reply: &str, expected: &str) -> Result<()> {
    ensure!(
        reply.split_whitespace().count() >= MIN_VERIFIABLE_REPLY_WORDS,
        "Reply is too short for its language to be verified"
    );
    let detected = dominant_language(reply)
        .ok_or_else(|| anyhow::anyhow!("Reply language could not be verified"))?;
    ensure!(
        detected == expected,
        "Reply language mismatch: drafted in '{detected}' but the reply language is '{expected}'"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_list_covers_the_twelve_required_languages() {
        let codes: Vec<&str> = SUPPORTED_LANGUAGES.iter().map(|(code, _)| *code).collect();
        for required in [
            "en", "zh", "hi", "es", "fr", "ar", "bn", "pt", "ru", "ur", "de", "el",
        ] {
            assert!(codes.contains(&required), "missing {required}");
        }
    }

    #[test]
    fn first_language_uses_the_first_substantive_segment() {
        let mixed = "Hello! Thank you for your message.\n\nNous avons etudie votre candidature avec attention et nous ne donnerons pas suite.";
        assert_eq!(first_language(mixed, "en"), "fr");
    }

    #[test]
    fn opener_interjections_do_not_decide_the_language() {
        let de = "Dear candidate,\n\nvielen Dank fuer Ihre Bewerbung. Wir haben uns gegen Sie entschieden.";
        assert_eq!(first_language(de, "en"), "de");
    }

    #[test]
    fn greek_and_german_first_segments_are_detected() {
        let el = "Καλημερα σας. Ευχαριστουμε για το ενδιαφερον σας για τη θεση του μηχανικου λογισμικου.";
        assert_eq!(first_language(el, "en"), "el");
        let de = "Guten Tag, vielen Dank fuer Ihre Bewerbung als Ingenieur.";
        assert_eq!(first_language(de, "en"), "de");
    }

    #[test]
    fn reply_language_gate_accepts_matching_and_rejects_mismatched() {
        let reply_de = "Sehr geehrte Damen und Herren, ich fordere eine individuelle Begruendung gegenueber den Stellenanforderungen.";
        assert!(ensure_reply_language(reply_de, "de").is_ok());
        assert!(ensure_reply_language(reply_de, "en").is_err());
        assert!(ensure_reply_language("ok", "en").is_err());
    }

    #[test]
    fn dominant_language_falls_back_gracefully() {
        assert_eq!(
            dominant_language("The quick brown fox jumps over the lazy dog").unwrap(),
            "en"
        );
    }
}
