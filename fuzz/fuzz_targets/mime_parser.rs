#![no_main]
use libfuzzer_sys::fuzz_target;
use rejection_rejector::gmail;

fuzz_target!(|data: &[u8]| {
    // Input is arbitrary RFC 5322 bytes, not assumed to be UTF-8. Successful
    // output is already a Rust String; its meaningful invariant is the bound.
    if let Ok((text, _complete)) = gmail::parse_mime_text(data) {
        assert!(text.len() <= 65_536);
    }

    // Rejection-looking bytes inside an attachment must not become model input.
    let mut attachment = b"Content-Type: text/plain\r\n".to_vec();
    attachment.extend_from_slice(b"Content-Disposition: attachment; filename=note.txt\r\n\r\n");
    attachment.extend_from_slice(data);
    if let Ok((text, _complete)) = gmail::parse_mime_text(&attachment) {
        assert!(text.is_empty());
    }
});
