# Engineering Lessons (sanitized, repo-wide)

Generic rules distilled from past engineering failures. No incident details,
no personal data, no machine specifics — only the transferable rules. Each
rule exists because it previously caused a real defect or delay.

## Parallel work

- Never stage or commit a file whose owning worker is mid-edit: partial
  integration captures half-written code and breaks builds. Stage only files
  whose owner has finished, or the whole verified tree at once.
- Never run whole-tree measurements (coverage, full test runs) while a worker
  is editing the same tree: mid-edit compiles produce phantom failures.
  Measure at integration time and re-verify against the committed tree.
- Verify in an isolated git worktree when the shared tree is busy.

## Testing

- Every test must assert behavior that fails on subtle breakage; never pad
  tests to inflate coverage. A covered line must be observable.
- Platform-gated code needs matching test-helper gates (a helper used only by
  `#[cfg(windows)]` tests must itself be `#[cfg(windows)]`), or Linux builds
  fail the deny-warnings policy.
- Beware TOCTOU port races in tests: bind-then-drop patterns let parallel
  tests steal the port. Use eternally unconnectable destinations (port 0) or
  hold reservations until the last moment.
- Cross-process shared state (credential stores, registries) needs a
  cross-process lock (file lock), not an in-process mutex.
- A test fixture that triggers a production safety gate (e.g. file
  permissions) must satisfy the gate to exercise the intended path.

## Upstream and versions

- When stuck on a component version, check its upstream issue tracker for the
  exact version family FIRST. If it is known-broken upstream, switch to the
  community/verified-working version family instead of debugging around it.
- Official vendor guides take precedence over ad-hoc stack assembly; follow
  their "uninstall first" and pairing rules exactly.
- Pin toolchain/dependency updates through the project's own verification
  gates (full suite + lints) before landing.

## Documentation

- When the user supplies replacement text, change words only — never alter
  user-owned formatting, layout, or structure.
- Keep doc comments in house style: one-line purpose plus `Inputs:` and
  `Output:` sections naming parameters and behavior.
- Sanitize everything committed: no credentials, personal data, hostnames,
  or machine specifics in code, docs, tests, or commit messages.
