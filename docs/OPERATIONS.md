# Operations and incident runbook

This runbook covers the local operator surface. It does not replace Gmail/Google Workspace administration, Windows endpoint management, or an organization's incident-response process.

## Process model

The native GUI and `rr run` use the same exclusive workspace lock. Run **one** of them for a data directory. Do not start a second worker against the same workspace. The application must be running for scheduled mailbox checks.

Use the CLI with the GUI/worker closed for maintenance operations that open the workspace exclusively.

## Readiness and monitoring

Use the strictest readiness level appropriate to the deployment:

```powershell
.\rr.exe doctor --require workspace
.\rr.exe doctor --require mailbox
.\rr.exe doctor --require analysis
.\rr.exe doctor --require automatic
```

`automatic` intentionally requires the local workspace, Gmail/send permission, current model pin/task qualification, Automatic-mode consent, storage headroom and configured safety gates.

Privacy-safe monitoring is available as JSON or OpenMetrics:

```powershell
.\rr.exe metrics
.\rr.exe metrics --openmetrics
```

When the authenticated read-only integration API is enabled, use its versioned live/health/readiness/metrics endpoints. Metrics are intentionally label-free for mailbox, employer and candidate values. Runtime operation durations are retained locally as aggregate supportability evidence; they are **not** a product SLA.

For a local support report:

```powershell
.\rr.exe diagnostics --out .\rejection-rejector-diagnostics.json
```

The app never uploads this report automatically. Review it before sharing.

Before enabling unattended delivery, generate a read-only shadow audit:

```powershell
.\rr.exe shadow-automatic --out .\automatic-shadow.json
```

The shadow audit temporarily simulates the Automatic arm state **in memory only** and includes existing reviewable backlog inside the selected age window. It reports aggregate stable policy-block codes, active/uncertain thread blocking, daily-capacity remaining, Gmail/send-scope readiness, task qualification, enterprise-policy permission, storage headroom and pause state. It does **not** run the fresh Gmail conversation preflight and therefore cannot prove that any candidate would actually be sent. It performs no reservation, send or other external write and omits mailbox/employer/message/draft content.

## Gmail incident

If Gmail becomes unavailable or authorization expires:

1. pause Automatic dispatch or switch to Human Review;
2. do not delete synchronization state or edit Gmail history cursors manually;
3. reconnect through the supported OAuth flow when needed;
4. run `rr doctor --require mailbox`;
5. allow incremental synchronization to resume.

A failed page does not advance the durable history cursor; replay is deduplicated by message identity.

## Ollama or model incident

If Ollama is unavailable, obsolete, the digest changed, or GPU residency no longer qualifies:

1. keep delivery paused;
2. restore/start the supported loopback Ollama runtime;
3. use **Qualify & pin** for the smoke/residency test;
4. rerun the full task-specific model evaluation;
5. run `rr doctor --require analysis`, then `--require automatic` only if unattended delivery is intended.

Queued messages remain durable. A global inference-runtime outage must not consume per-message retries.

## Uncertain Gmail delivery

If a send may have crossed Gmail's write boundary, Rejection Rejector records **Uncertain** and retains the durable reservation.

Never resend merely because no immediate acknowledgement was observed. In the GUI use **Activity → Reconcile with Gmail Sent**. A missing Sent match does not prove non-delivery; the reservation remains authoritative.

There is currently no headless `rr reconcile` command. Do not invent one in automation.

## Database integrity and storage

Check the active store:

```powershell
.\rr.exe integrity
```

If disk headroom is low, stop new work before the filesystem fills. After a verified backup and when operationally appropriate:

```powershell
.\rr.exe compact
```

If integrity fails, stop the worker. Do not replace files in the live SQLite/WAL set manually. Verify a known backup and exercise the isolated production restore path first.

## Backup and recovery

Create and verify a same-vault backup:

```powershell
.\rr.exe backup --out D:\RR-Backups\rr-2026-09-29
.\rr.exe verify-backup D:\RR-Backups\rr-2026-09-29
.\rr.exe recovery-drill D:\RR-Backups\rr-2026-09-29
```

Restore is destructive and requires explicit acknowledgement:

```powershell
.\rr.exe restore-backup D:\RR-Backups\rr-2026-09-29 --confirm RESTORE
```

Prefer a backup destination on a different physical or administrative failure domain. The app reports when a scheduled destination appears to share the workspace filesystem.

For portable disaster recovery, store the encrypted recovery-key envelope **separately** from the backup:

```powershell
.\rr.exe export-recovery-key --out E:\Offline\rr-key.json --passphrase-file C:\Secure\rr-passphrase.txt
.\rr.exe verify-recovery-key --backup D:\RR-Backups\rr-2026-09-29 --recovery-key E:\Offline\rr-key.json --passphrase-file C:\Secure\rr-passphrase.txt
```

Import requires explicit acknowledgement and never overwrites an existing credential automatically:

```powershell
.\rr.exe import-recovery-key --backup D:\RR-Backups\rr-2026-09-29 --recovery-key E:\Offline\rr-key.json --passphrase-file C:\Secure\rr-passphrase.txt --confirm IMPORT
```

Protect the passphrase file with OS ACLs. Do not store it beside both the backup and recovery-key envelope.

## Audit-chain incident

Export an independent audit point periodically or before sensitive maintenance:

```powershell
.\rr.exe audit-anchor --out E:\Offline\rr-audit-anchor.json
```

Later verify that the active semantic audit chain still extends it:

```powershell
.\rr.exe verify-audit-anchor E:\Offline\rr-audit-anchor.json
```

If verification fails, treat it as an integrity incident. Preserve the workspace and evidence; do not delete audit rows to make the check pass.

## Enterprise-policy incident

Inspect effective policy:

```powershell
.\rr.exe policy-status
```

Validate a candidate policy without applying it:

```powershell
.\rr.exe validate-policy C:\ProgramData\RejectionRejector\enterprise-policy.json
```

A signature, hash or revision failure is fail-closed. Fix the policy artifact/deployment process; do not bypass authentication or lower the revision floor.

## Release and deployment evidence

A release candidate is built only from the exact current `main` commit. The attested package workflow checks exact-commit CI, Rust public-API compatibility and security evidence plus recent deep-quality evidence before packaging.

The source provides native Windows artifacts, checksums, embedded build identity, embedded compatibility-contract identity, binary RustSec audit, CycloneDX SBOM and GitHub attestations. The manual package workflow has two explicit flavors: `unsigned` and `azure-artifact-signing`. Signed mode uses GitHub OIDC with Azure login and Microsoft Artifact Signing, then requires Windows `Get-AuthenticodeSignature` to report `Valid` for both `rejection-rejector.exe` and `rr.exe`; otherwise packaging stops. The package records `signing.json`, `build-info.json` and `contract-info.json`. MSI/MSIX/Intune packaging remains separate release-engineering work.

### Azure publisher-signing provisioning

Use the signed flavor only after an administrator has created an Azure Artifact Signing account/certificate profile and a GitHub OIDC federated identity for this repository/workflow. Configure repository variables `AZURE_ARTIFACT_SIGNING_ENDPOINT`, `AZURE_ARTIFACT_SIGNING_ACCOUNT`, and `AZURE_ARTIFACT_SIGNING_PROFILE`; configure `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_ID` in the repository's protected secret channel. No long-lived Azure client secret is required by the workflow.

From GitHub Actions, run **Attested Windows package**, type `PACKAGE`, and choose `azure-artifact-signing`. The workflow rechecks exact-main CI/security/deep evidence, builds auditable binaries, validates `build-info` and `contract-info`, signs both executables, verifies Authenticode, emits `signing.json`, then creates and attests the signed ZIP. Choosing `unsigned` creates a separately named unsigned ZIP and explicitly refuses to relabel an already publisher-signed binary as unsigned.

Microsoft's newer WinApp CLI is intentionally not a production dependency here while it remains public preview; stable Windows SDK/Artifact Signing primitives remain the release foundation.

## Escalation principles

- Preserve evidence before repair.
- Prefer fail-closed Human Review over forcing Automatic mode.
- Never bypass an at-most-once delivery reservation.
- Never copy secrets into diagnostics, tickets or chat.
- Never treat "no error observed" as proof of delivery, backup recoverability, GPU residency or model quality.


## Windows background worker

For a workstation deployment where the user remains signed in but the GUI should not stay open, prefer the built-in per-user Task Scheduler registration over a Windows service:

```powershell
.\rr.exe autostart install
.\rr.exe autostart status
```

The registered task triggers 30 seconds after the current user logs on, uses `InteractiveToken` + `LeastPrivilege`, runs the same workspace through `rr.exe --data-dir <workspace> run`, sets `MultipleInstancesPolicy=IgnoreNew`, does not stop on battery transition, has no execution-time limit, and retries failure after one minute up to three times.

`autostart status` checks the exported task XML for the expected executable, workspace arguments, least-privilege principal, single-instance rule and restart policy. A task that exists but has drifted is reported as mismatched; reinstall rather than silently trusting it.

Remove it with `.\rr.exe autostart remove`.

This is intentionally not a LocalSystem service. The vault key is protected in the signed-in user's Credential Manager, so changing to a service identity would change the secret-access boundary. Logoff ends this availability model. Domain policy can prohibit scheduled-task creation, and the application does not attempt to bypass such policy.
