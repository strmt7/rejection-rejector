//! Entirely synthetic MIME/identity tests; nothing is sent.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use mailparse::MailHeaderMap;
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
        assert!(mail::hard_blocks(email, "candidate@example.com")
            .iter()
            .any(|r| r.contains("duplicate")));
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
