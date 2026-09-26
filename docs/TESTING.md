# Tests and acceptance

CI runs locked core tests, native GUI/CLI builds, all-feature tests, clippy and synthetic headless demo on Windows and Ubuntu. Linux additionally runs the actual GUI under Xvfb/Openbox and asserts that its native screenshot event saves a PNG. An external diagnostic screenshot never substitutes for that assertion. Windows builds optimized executables and packages source/commit/toolchain evidence.

```text
cargo fmt --all -- --check
cargo test --locked --lib --no-default-features
cargo build --locked --bins
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features
cargo run --locked --no-default-features --bin rr -- demo
```

Tests cover preset validation/default disarming, encryption/tampering/key mismatch, locks, dedup/stale revisions, crash reservations/caps, plaintext-secret absence, mailbox injection, MIME/quotes, OAuth state, sync failure/replay, exact LLM evidence and stale profile hashes. GUI tests ensure unsaved content is not a persisted send candidate; worker tests assert demo initialization/selection.

`rr evaluate --out report.json` records actual configured-model results on12 synthetic fixtures without sending email. This is not a production accuracy claim.

Manual acceptance still required: Windows DPI/accessibility/navigation/edit/send-confirmation; dedicated test Gmail OAuth and one controlled reply; lookback boundaries, pause, changed conversations, model/profile changes, interrupted delivery reconciliation; actual 16GiB GPU/driver residency and worst-case prompts. CI does not access the owner's inbox, send real email, measure their physical GPU or prove comprehensive Windows visual correctness. Always inspect the exact run conclusion and build commit.
