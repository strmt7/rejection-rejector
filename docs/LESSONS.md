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

## Concurrency and runtime

- Accelerator/GPU APIs are owned by one thread: never probe or query a
  device from a watchdog or side thread while the workload thread drives
  it — the bridge races you. Sample in a per-step callback on the owner
  thread and share the reading as plain data.
- Cooperative stops must reach a well-defined exit: a run that receives a
  stop flag can still wedge in its teardown path. Bounded checkpoints
  (save every N steps, keep K) cap the cost of any hang.
- Fail-closed belongs at start gates and persistent blindness, not at a
  single flaky reading mid-run: tolerate a small consecutive-miss window
  before stopping a healthy workload.

## Editing and verification

- Generated/regex edits are untrusted until re-read: they can silently
  no-op (matching the wrong anchor) or swallow a neighboring definition.
  After every one, grep the result and check definition-before-use order
  by line number; a compiling file can still fail at first dynamic use.
- `cmd | tail` reports tail's exit code. Run verification un-piped (or
  check PIPESTATUS) before declaring success.
- Read correction and withdrawal comments in upstream issue threads before
  concluding — a severe report may be retracted as the reporter's own test
  artifact. And a merged fix is not proof it is in the release you run:
  check the merge commit against that release's tag or branch.
- Before a large workload, run the exact fault-class operations as small
  probes with wall-clock timeouts (the crash gate). Clean probes earn the
  right to the full run.
