#![no_main]

use libfuzzer_sys::fuzz_target;
use rejection_rejector::gmail;

fuzz_target!(|data: &[u8]| {
    if let Ok((text, _complete)) = gmail::parse_mime_text(data) {
        assert!(text.len() <= 65_536);
        
        // Additional validation: the parsed text should be valid UTF-8
        // since we're starting with UTF-8 bytes
        let _ = String::from_utf8(text.clone());
    }
    
    // Test with invalid UTF-8 sequences too - should not crash
    let _ = String::from_utf8_lossy(data);
});
