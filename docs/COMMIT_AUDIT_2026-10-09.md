# Commit-history incident review — 9 October 2026

## Exact scope and limits

The requested original window is the **100 first-parent commits** ending at
`43e2921bb0af6898dde56ea64505f0b24c5330a8` (the "commit 818 marker" commit).
The oldest included commit is `1fb66a117449b7177edbfa7c5051666aa7fca13f`;
the exclusive baseline is its parent
`031c9e2aa75ac699b7a4ef0183663c5ed56ace7e`.

All 100 commit identities, messages, first-parent relationships and changed-file
statistics were inventoried. There are **72 distinct changed paths** when transient
add/remove files are included. **46 subjects begin with `docs:`**, and **10 messages
explicitly refer to commit-counting goals or markers**. Those are descriptions of
the history, not quality metrics. A documentation label does not establish that a
change is safe: several such commits corrupted executable build configuration.

The accompanying review targeted source corruption, misleading comments, parser
and fuzz regressions, retry behavior, source/compatibility evidence and release
routing. Inventory coverage is not a claim that every possible semantic defect in
all 100 commits has been ruled out. No external security certification is asserted.

## Confirmed findings and forward repairs

| Finding | Evidence in original history/current pipeline | Resolution |
|---|---|---|
| Mixed character encodings broke build inputs | UTF-16LE/NUL append fragments in `build.rs`, `rust-toolchain.toml`, `deny.toml`, `LICENSE`, `.gitignore` and README; examples include `825bcf1a`, `efbc5143` and `2d04ec46`. | `803fb0b` removed corrupt append fragments while preserving the substantive implementation, added explicit encoding rules and a committed-blob integrity gate. |
| Commit-count padding and temporary-file churn | The three README marker commits plus multiple temporary-file add/remove pairs explicitly aimed at a numerical commit target. | `803fb0b` removed marker/temporary-file residue. History was preserved. Contributor rules now prohibit manufacturing commits for quotas. |
| The "recipient edge cases" change did not compile | `b0fcf891` changed the valid `'.'` character literal in `mail.rs` into an unterminated literal. | `1f244ce` restored valid parsing and added synthetic routing regressions for nonreplyable recipients, malformed Reply-To, self-replies and duplicate headers. |
| The MIME fuzz enhancement did not compile | `8b0ae75e` passed an existing Rust `String` to `String::from_utf8`, which expects bytes; another new operation merely exercised standard-library lossy conversion. | `1f244ce` replaced it with arbitrary-byte MIME and attachment-isolation checks rather than a redundant UTF-8 assertion. |
| Retry jitter could panic on an entropy failure | `b242489f` switched to the infallible `OsRng` convenience API and described scheduling jitter as a security boundary. | `1f244ce` used fallible entropy acquisition and retained bounded backoff on error, with deterministic failure/boundary tests. |
| Comments overstated guarantees | Recent annotations described private GUI `Snapshot` data as export-safe, overstated atomic delivery guarantees and described checks/metrics not actually present. | `1f244ce` removed those incorrect assurances without removing the substantive runtime guards. |
| Parent-only API checks inherited an uncompilable baseline | The fixed current code in `1f244ce` compiled, but `803fb0b` still contained the bad `mail.rs` literal when used as its SemVer baseline. | `6dd0310` retained the parent check and added a fixed pre-corruption milestone, with both all-feature and no-feature comparisons. The failed historical check was not hidden. |
| Source integrity was not originally a release prerequisite | A new encoding gate alone did not make it mandatory for packaging. | `6dd0310` added exact-commit repository-integrity evidence, tracked-source cleanliness and checkout/encoding invalidation to the release gate. |
| Unsigned packaging accepted invalid signature states | The release step rejected `Valid` in unsigned mode but did not require `NotSigned`; error states could pass as unsigned. | `22a8bef` requires the exact expected status, publisher/timestamp metadata for signed mode and executable-digest-bound signature records. |
| Directory copies could include untracked package contents | Copying `scripts` recursively could include interpreter caches or other untracked files. | `22a8bef` stages committed sources through Git archive, enforces exact package/checksum coverage and verifies the ZIP before attestation and again before upload. |
| Ordinary CI offered an alternate deployable ZIP | `ci.yml` retained `workflow_dispatch.inputs.package_windows`, a release build and `Compress-Archive`, outside the attested gate. | This change removes that alternate packaging path. Normal CI/manual verification, local builds and reproducibility diagnostics remain. |

## Reproduce the original inventory

Use a full repository checkout. These commands read Git objects and write audit
artifacts; they do not run the application, rewrite commits or contact a mailbox.

```powershell
python scripts/repository_integrity.py --history-ref 43e2921bb0af6898dde56ea64505f0b24c5330a8 --history-count 100 --report artifacts/original-100-audit.json --patch-file artifacts/original-100.patch
python -m unittest discover -s tests/release -v
```

The JSON's `commits` array describes the fixed historical window. Its `findings`
array scans the **current committed tree**, not every historical tree; keeping
those scopes distinct avoids falsely describing an old corrupt commit as clean.
The patch file preserves the actual historical diffs, including binary/encoding
changes. Audit output is bounded, and incomplete history is an error rather than
an empty or supposedly complete report.

## Release decision

The repairs restore verifiability and close identified release-control gaps. They
do not by themselves authorize deployment or unattended email. Use exact-commit
CI and the [release gate](RELEASE_GATES.md), independently verify the
[package](PACKAGE_VERIFICATION.md), and complete the owner-environment acceptance
requirements in [enterprise readiness](ENTERPRISE_READINESS.md). Source control,
passing checks, internal package hashes and a real publisher trust decision are
different kinds of evidence.
