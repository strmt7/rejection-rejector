//! Race two independent SQLite connections. No provider and no mail dispatch.
use chrono::Utc;
use rejection_rejector::{
    ollama,
    store::Store,
    types::{Job, JobState, Source, Stub},
    vault::Vault,
};
use std::{
    sync::{Arc, Barrier},
    thread,
};

fn ready(db: &mut Store, message: &str, conversation: &str) -> Job {
    let stub = Stub {
        account: "candidate@example.com".into(),
        provider_id: message.into(),
        thread_id: conversation.into(),
        source: Source::Gmail,
    };
    let id = stub.id();
    db.insert_stub(stub, Utc::now()).unwrap();
    let mut j = db.get(&id).unwrap();
    j.state = JobState::Ready;
    db.save(&mut j, "test", "Synthetic reservation candidate")
        .unwrap();
    j
}
fn race(same_thread: bool, cap: u16) -> usize {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let key = Vault::random();
    let mut left = Store::open(&path, key.clone()).unwrap();
    let a = ready(&mut left, "one", "conversation-one");
    let b = ready(
        &mut left,
        "two",
        if same_thread {
            "conversation-one"
        } else {
            "conversation-two"
        },
    );
    let mut right = Store::open(&path, key).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let gate = barrier.clone();
    let first = thread::spawn(move || {
        gate.wait();
        left.reserve_send(&a, cap, Utc::now()).is_ok()
    });
    let second = thread::spawn(move || {
        barrier.wait();
        right.reserve_send(&b, cap, Utc::now()).is_ok()
    });
    usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
}
fn race_same_recipient(recipient_cap: u16) -> usize {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let key = Vault::random();
    let mut left = Store::open(&path, key.clone()).unwrap();
    let mut a = ready(&mut left, "recipient-one", "recipient-thread-one");
    let mut b = ready(&mut left, "recipient-two", "recipient-thread-two");
    for job in [&mut a, &mut b] {
        let mut email = ollama::sample_email(
            "Synthetic rejection",
            "We have decided not to move forward with your application.",
        );
        email.stub = job.stub.clone();
        email.from = "Recruiter <recruiter@example.com>".into();
        email.reply_to = None;
        job.email = Some(email);
        left.save(job, "test", "Hydrate recipient concurrency fixture")
            .unwrap();
    }

    let mut right = Store::open(&path, key).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let gate = barrier.clone();
    let first = thread::spawn(move || {
        gate.wait();
        left.reserve_send_with_recipient_limit(&a, 10, Some(recipient_cap), Utc::now())
            .is_ok()
    });
    let second = thread::spawn(move || {
        barrier.wait();
        right
            .reserve_send_with_recipient_limit(&b, 10, Some(recipient_cap), Utc::now())
            .is_ok()
    });
    usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
}

#[test]
fn concurrent_same_conversation_has_only_one_reservation() {
    for _ in 0..20 {
        assert_eq!(race(true, 10), 1);
    }
}
#[test]
fn concurrent_different_conversations_cannot_exceed_attempt_cap() {
    for _ in 0..20 {
        assert_eq!(race(false, 1), 1);
    }
}

#[test]
fn concurrent_same_recipient_cannot_exceed_automatic_recipient_cap() {
    for _ in 0..20 {
        assert_eq!(race_same_recipient(1), 1);
    }
}
