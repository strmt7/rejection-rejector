//! Entirely synthetic MIME/identity tests; nothing is sent.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use mailparse::MailHeaderMap;
use rand::{Rng, SeedableRng, rngs::StdRng};
use rejection_rejector::{config::Settings, mail, ollama, types::*};

fn candidate() -> (Job, Settings) {
    let mut email =
        ollama::sample_email("Bewerbung — Δοκιμή", "Your application was not selected.");
    email.stub.account = "candidate@example.com".into();
    email.stub.source = Source::Gmail;
    email.from = "recruiter@example.com".into();
    let mut job = Job::new(email.stub.clone(), Utc::now());
    job.state = JobState::Ready;
    job.email = Some(email);
    job.draft = Some(Draft {
        body: "Please explain the assessment criteria.\n\nRegards,\nTest Applicant".into(),
        origin: "human".into(),
    });
    (
        job,
        Settings {
            signature: "Test Applicant".into(),
            sending_enabled: true,
            ..Default::default()
        },
    )
}

#[test]
fn unicode_reply_roundtrips_with_one_recipient_and_thread_headers() {
    let (job, settings) = candidate();
    let raw = mail::raw_reply(&job, &settings, "candidate@example.com", Utc::now()).unwrap();
    let bytes = URL_SAFE_NO_PAD.decode(raw).unwrap();
    let parsed = mailparse::parse_mail(&bytes).unwrap();
    let original = job.email.as_ref().unwrap();
    assert_eq!(
        parsed.headers.get_first_value("To").unwrap(),
        "recruiter@example.com"
    );
    assert_eq!(
        parsed.headers.get_first_value("Subject").unwrap(),
        original.subject
    );
    assert_eq!(
        parsed.headers.get_first_value("In-Reply-To").unwrap(),
        original.message_id
    );
    assert_eq!(
        parsed.headers.get_first_value("Message-ID").unwrap(),
        mail::outgoing_id(&job)
    );
    assert!(parsed.headers.get_first_value("Bcc").is_none());
    assert_eq!(
        parsed.get_body().unwrap().trim().replace("\r\n", "\n"),
        job.draft.as_ref().unwrap().body
    );
}
#[test]
fn cross_message_or_thread_payload_cannot_be_composed() {
    for mutate in [0, 1, 2, 3] {
        let (mut job, settings) = candidate();
        match mutate {
            0 => job.id = "different-job".into(),
            1 => job.email.as_mut().unwrap().stub.provider_id = "different-message".into(),
            2 => job.email.as_mut().unwrap().stub.thread_id = "different-thread".into(),
            _ => job.email.as_mut().unwrap().stub.account = "another@example.com".into(),
        }
        assert!(mail::raw_reply(&job, &settings, "candidate@example.com", Utc::now()).is_err());
    }
}
#[test]
fn ambiguous_subject_and_auto_submitted_headers_are_blocked() {
    for header in [
        "subject",
        "auto-submitted",
        "from",
        "reply-to",
        "message-id",
    ] {
        let (mut job, _) = candidate();
        let email = job.email.as_mut().unwrap();
        email
            .headers
            .insert(header.into(), vec!["first".into(), "second".into()]);
        assert!(
            mail::hard_blocks(email, "candidate@example.com")
                .iter()
                .any(|r| r.contains("duplicate"))
        );
    }
}
#[test]
fn disabled_sending_and_demo_source_cannot_be_composed() {
    let (mut job, mut settings) = candidate();
    settings.sending_enabled = false;
    assert!(mail::raw_reply(&job, &settings, "candidate@example.com", Utc::now()).is_err());
    settings.sending_enabled = true;
    job.email.as_mut().unwrap().stub.source = Source::Demo;
    assert!(mail::raw_reply(&job, &settings, "candidate@example.com", Utc::now()).is_err());
}

#[test]
fn randomized_utf8_bounding_is_prefix_safe_and_never_splits_codepoints() {
    let mut rng = StdRng::seed_from_u64(0x4d41_494c_2026_0929);
    let alphabet = [
        "a", "Z", "7", " ", "-", "_", "é", "ä", "λ", "Δ", "ς", "日", "本", "🙂", "🚀",
    ];

    for case_index in 0..512u32 {
        let units = rng.gen_range(0..=180);
        let mut input = String::new();
        for _ in 0..units {
            input.push_str(alphabet[rng.gen_range(0..alphabet.len())]);
        }
        let limit = rng.gen_range(0..=input.len().saturating_add(8));
        let (bounded, complete) = mail::bounded_text(&input, limit);

        assert!(
            bounded.len() <= limit,
            "case {case_index} exceeded byte bound"
        );
        assert!(
            input.starts_with(bounded),
            "case {case_index} did not preserve an exact UTF-8 prefix"
        );
        assert_eq!(
            complete,
            input.len() <= limit,
            "case {case_index} reported the wrong completeness flag"
        );
    }
}

#[test]
fn randomized_quoted_rejection_history_never_survives_current_message_boundary() {
    let mut rng = StdRng::seed_from_u64(0x5155_4f54_4544_2026);
    let markers = [
        "On Tuesday Recruiter wrote:",
        "Am Dienstag schrieb Recruiter:",
        "Le mardi Recruiter a écrit :",
        "Il martedì Recruiter ha scritto:",
        "El martes Recruiter escribió:",
        "Em terça-feira Recruiter escreveu:",
        "Op dinsdag schreef Recruiter:",
        "Στις Τρίτη ο Recruiter έγραψε:",
        "-----Original Message-----",
        "---------- Forwarded message ----------",
        "Messaggio inoltrato",
        "Mensaje reenviado",
        "Mensagem encaminhada",
        "Oorspronkelijk bericht",
        "Αρχικό μήνυμα",
    ];
    let current_lines = [
        "We would like to invite you to an interview.",
        "Your application is still under review.",
        "Please choose a time for the next conversation.",
        "We are pleased to continue with your application.",
    ];

    for case_index in 0..512u32 {
        let current = current_lines[rng.gen_range(0..current_lines.len())];
        let marker = markers[rng.gen_range(0..markers.len())];
        let quoted = format!(
            "{current}\n{marker}\nWe have decided not to move forward with your application."
        );
        let stripped = mail::current_text(&quoted);
        assert!(
            stripped.contains(current),
            "case {case_index} lost the current message"
        );
        assert!(
            !stripped
                .to_lowercase()
                .contains("decided not to move forward"),
            "case {case_index} leaked quoted rejection history"
        );
    }
}
