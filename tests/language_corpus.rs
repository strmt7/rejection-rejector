//! Corpus-validated language detection: the reply-language rule must agree
//! with ground truth across the twelve guaranteed languages.

use rejection_rejector::language::first_language;
use serde::Deserialize;

#[derive(Deserialize)]
struct Entry {
    id: String,
    body: String,
    language: String,
}

fn load() -> Vec<Entry> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rejection_corpus/multilingual_eval.jsonl"
    );
    std::fs::read_to_string(path)
        .expect("multilingual corpus present")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid corpus line"))
        .collect()
}

/// First-substantive-language detection must match the corpus language label
/// for every native entry: this is the reply-language decision the draft gate
/// enforces, so a mismatch here would draft in the wrong language.
#[test]
fn first_language_matches_the_corpus_across_twelve_languages() {
    let mut mismatches = Vec::new();
    for entry in load() {
        let detected = first_language(&entry.body, "en");
        if detected != entry.language {
            mismatches.push(format!(
                "{}: expected {} got {}",
                entry.id, entry.language, detected
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "reply-language detection mismatches:\n{}",
        mismatches.join("\n")
    );
}
