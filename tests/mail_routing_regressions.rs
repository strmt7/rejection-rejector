//! Synthetic parser regressions. No provider calls, model inference or sending.
use rejection_rejector::{gmail, mail, ollama, types::Source};

const ACCOUNT: &str = "candidate@example.invalid";

fn message(from: &str) -> rejection_rejector::types::Email {
    let mut email = ollama::sample_email("Application", "Not selected.");
    email.stub.source = Source::Gmail;
    email.stub.account = ACCOUNT.into();
    email.from = from.into();
    email
}

fn blocked(email: &rejection_rejector::types::Email, reason: &str) -> bool {
    mail::hard_blocks(email, ACCOUNT)
        .iter()
        .any(|value| value == reason)
}

#[test]
fn nonreplyable_local_parts_are_case_and_separator_insensitive() {
    for address in [
        "NO.REPLY@example.invalid",
        "no-reply@example.invalid",
        "do_not_reply@example.invalid",
        "mailer-daemon@example.invalid",
        "postmaster@example.invalid",
    ] {
        let email = message(address);
        assert!(blocked(&email, "Recipient does not accept replies"));
    }
}

#[test]
fn malformed_reply_to_never_falls_back_to_a_valid_from() {
    for address in [
        "",
        "missing-at",
        "@example.invalid",
        "one@example.invalid, two@example.invalid",
    ] {
        let mut email = message("recruiter@example.invalid");
        email.reply_to = Some(address.into());
        assert!(email.recipient().is_err());
        assert!(blocked(&email, "Recipient is not a single valid mailbox"));
    }
}

#[test]
fn explicit_valid_reply_to_is_used_but_nonreplyable_override_is_blocked() {
    let mut email = message("noreply@example.invalid");
    email.reply_to = Some("Hiring Team <recruiter@example.invalid>".into());
    assert_eq!(email.recipient().unwrap(), "recruiter@example.invalid");
    assert!(mail::hard_blocks(&email, ACCOUNT).is_empty());

    email.from = "recruiter@example.invalid".into();
    email.reply_to = Some("no-reply@example.invalid".into());
    assert!(blocked(&email, "Recipient does not accept replies"));
}

#[test]
fn self_reply_and_duplicate_reply_to_are_blocked() {
    let mut email = message(ACCOUNT);
    assert!(blocked(&email, "Self-reply blocked"));
    email.from = "recruiter@example.invalid".into();
    let destinations = vec!["one@example.invalid".into(), "two@example.invalid".into()];
    email.headers.insert("reply-to".into(), destinations);
    assert!(blocked(&email, "Ambiguous duplicate reply-to header"));
}

#[test]
fn mime_input_is_bytes_and_long_unicode_output_is_bounded() {
    let invalid_body = b"Content-Type: text/plain\r\n\r\n\xff\xfe";
    for data in [invalid_body.as_slice(), b"\xff\0\xfe\0".as_slice()] {
        if let Ok((text, _)) = gmail::parse_mime_text(data) {
            assert!(text.len() <= 65_536);
        }
    }
    let header = "Content-Type: text/plain; charset=utf-8\r\n\r\n";
    let raw = format!("{header}{}", "λ".repeat(40_000));
    let (text, complete) = gmail::parse_mime_text(raw.as_bytes()).unwrap();
    assert!(text.len() <= 65_536);
    assert!(!complete);
}

#[test]
fn rejection_text_inside_an_attachment_is_never_analysis_input() {
    let header = "Content-Type: text/plain\r\nContent-Disposition: attachment\r\n\r\n";
    let raw = format!("{header}Your application was not selected.");
    let (text, _) = gmail::parse_mime_text(raw.as_bytes()).unwrap();
    assert!(text.is_empty());
}
