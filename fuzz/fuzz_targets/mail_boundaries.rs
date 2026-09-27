#![no_main]

use libfuzzer_sys::fuzz_target;
use rejection_rejector::mail;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    let _ = mail::mailbox(&text);
    let _ = mail::valid_message_id(&text);
    let _ = mail::current_text(&text);

    let budget = data
        .get(..2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
        .unwrap_or(0);
    let (bounded, complete) = mail::bounded_text(&text, budget);
    assert!(bounded.len() <= text.len());
    if complete {
        assert_eq!(bounded.len(), text.len());
    } else {
        assert!(bounded.len() <= budget);
    }
});
