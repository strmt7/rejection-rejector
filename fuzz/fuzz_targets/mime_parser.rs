#![no_main]

use libfuzzer_sys::fuzz_target;
use rejection_rejector::gmail;

fuzz_target!(|data: &[u8]| {
    if let Ok((text, _complete)) = gmail::parse_mime_text(data) {
        assert!(text.len() <= 65_536);
    }
});
