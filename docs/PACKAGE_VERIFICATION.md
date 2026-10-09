# Verify a Windows release package before deployment

The ZIP verifier is read-only: it never extracts files, starts an executable, opens a
workspace, connects to Gmail, or changes sending authorization. Use Python 3.11 or
newer and the verifier from a **trusted source checkout for the release being
verified**. Do not run scripts obtained from an unverified ZIP.

## Integrity, provenance and publisher identity are different checks

`verify_package.py` checks internal package consistency and can compare the ZIP
against an independently obtained SHA-256. The manifest and JSON files inside a
package are not independently trustworthy merely because they agree. An attacker
who replaces a package can also replace those files. The verifier consequently
reports `authenticode_checked: false` and `attestation_checked: false`.

First authenticate the artifact against the expected repository, workflow and
source commit. For the current GitHub CLI:

```powershell
$Commit = '<expected 40-character source commit from the trusted release record>'
$Package = '.\rejection-rejector-windows-x64-signed.zip'
gh attestation verify $Package --repo strmt7/rejection-rejector --signer-workflow strmt7/rejection-rejector/.github/workflows/release.yml --source-ref refs/heads/main --source-digest $Commit --deny-self-hosted-runners
if ($LASTEXITCODE -ne 0) { throw 'Package provenance verification failed' }
gh attestation verify $Package --repo strmt7/rejection-rejector --signer-workflow strmt7/rejection-rejector/.github/workflows/release.yml --source-ref refs/heads/main --source-digest $Commit --deny-self-hosted-runners --predicate-type https://cyclonedx.org/bom
if ($LASTEXITCODE -ne 0) { throw 'Package SBOM attestation verification failed' }
```

Then, from that trusted source checkout, inspect the archive before extraction:

```powershell
python scripts/verify_package.py $Package --expected-commit $Commit --signing-mode azure-artifact-signing --expected-sha256 '<SHA-256 from a trusted release record>' --report package-verification.json
if ($LASTEXITCODE -ne 0) { throw 'Package contents did not verify' }
```

For an explicitly unsigned evaluation package, select `--signing-mode unsigned`.
Only `NotSigned` is acceptable for that flavor. Hash mismatch, untrusted,
unsupported, incompatible and unknown-error signature states are not synonyms
for unsigned. Unsigned packages do not establish publisher identity.

After successful archive/provenance verification and extraction to a fresh
non-privileged directory, inspect both executables with `Get-AuthenticodeSignature`.
For a signed release, require `Valid`, a signer certificate and a timestamp
certificate, and confirm the signer is the publisher your organization expects.
A status label by itself is not a substitute for an independently established
publisher trust policy. Do not run either executable during verification.

## What the read-only verifier enforces

- Bounded single-disk ZIP input, central directory, entry count, individual files,
  metadata and streamed decompressed total; ZIP64, unsupported compression,
  encrypted entries, symlinks and special files are refused.
- No absolute/traversing paths, Windows device names, alternate streams,
  backslash ambiguity, NUL names, case collisions or file/directory collisions.
- Required files and an exact checksum manifest: an omitted, duplicated, changed
  or unexpected executable/cache/secret file fails verification.
- Source commit, Windows x64/release metadata, the Rust build-identity hash,
  Cargo.lock and API/policy contract hashes must agree.
- Complete successful workflow-evidence records with the correct exact-commit
  identities. Evidence age is measured at the recorded packaging time, not the
  later download date. This is consistency checking, not a new GitHub API audit.
- Signing records must describe both exact executable hashes. Signed mode requires
  publisher/timestamp metadata; unsigned mode requires `NotSigned` without
  contradictory certificate metadata.

The package workflow stages docs/scripts from `git archive`, not from a directory
copy that could include untracked caches. It checks the completed ZIP before
attestation and checks the same archive hash again before upload. No release or
live-email operation is triggered by installing these checks.

Changes to the supported package format, signing record fields or required gates
must update the verifier and its synthetic ZIP regression tests together.

## Reference contracts

- [Microsoft SignatureStatus definitions](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.signaturestatus)
- [Python ZIP decompression pitfalls](https://docs.python.org/3.13/library/zipfile.html#decompression-pitfalls)
- [GitHub artifact attestations and their limits](https://docs.github.com/en/actions/concepts/security/artifact-attestations)

Automated package validation does not establish live Gmail behavior, target-GPU
model accuracy, Windows accessibility acceptance, organization-specific deployment
approval, or an external security audit. See [Enterprise readiness](ENTERPRISE_READINESS.md).
