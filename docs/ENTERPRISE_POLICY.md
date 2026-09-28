# Enterprise policy

Rejection Rejector supports an optional, local administrator policy overlay. It is intentionally file-based and local-first: no management server is required, and the application remains usable in disconnected enterprise environments.

## Default locations

- Windows: `%PROGRAMDATA%\RejectionRejector\policy.json`
- Linux: `/etc/rejection-rejector/policy.json`
- Explicit override: absolute path in `RR_ENTERPRISE_POLICY`

A configured relative override is rejected. A malformed or unsupported policy fails startup rather than silently disabling policy enforcement.

For higher-assurance deployments, Rejection Rejector supports **two independent policy-authentication controls**:

- `RR_ENTERPRISE_POLICY_SHA256`: exact 64-hex SHA-256 digest pin of the deployed policy bytes.
- `RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY`: standard-base64 raw 32-byte Ed25519 public key. When present, the exact policy bytes must have a valid detached signature in `policy.json.sig` (or the absolute path in `RR_ENTERPRISE_POLICY_SIGNATURE`).

The signature file is bounded to 4 KiB, rejects symlinks and unknown JSON fields, and uses the extensible envelope `{"version":1,"algorithm":"ed25519","signature":"BASE64"}`. The signature is over the **exact policy file bytes**, so whitespace changes require re-signing. SHA-256 pinning and Ed25519 verification may be enabled together; both must pass. The public key or digest should be provisioned independently from the policy/signature files through MDM, image management, or another administrator-controlled channel.

## Policy formats

Policy v1 remains readable for backward compatibility, but it has no local anti-rollback identity. New managed deployments should use **policy v2**.

### Policy v2

```json
{
  "version": 2,
  "policy_id": "example-org-production",
  "revision": 17,
  "not_before": "2026-09-28T00:00:00Z",
  "expires_at": "2027-09-28T00:00:00Z",
  "force_human_review": true,
  "prohibit_sending": true,
  "prohibit_integration_api": true,
  "prohibit_recovery_key_export": true,
  "require_external_audit_anchor": true,
  "max_daily_send_limit": 3,
  "min_cooldown_minutes": 90,
  "min_retention_days": 365,
  "allowed_models": ["granite4.2:8b-q8_0"]
}
```

For v2, `version`, `policy_id`, and `revision` are required. `policy_id` is a stable administrative namespace and `revision` is a monotonically increasing integer. `not_before` and `expires_at` are optional UTC timestamps. Omitted enforcement controls use their non-restrictive default.

The encrypted workspace remembers the highest accepted revision **and exact digest** for every v2 `policy_id`. A lower revision is rejected as rollback, and different bytes reusing the same revision are rejected. A higher revision advances the floor atomically with any settings restrictions that policy applies. Use a stable `policy_id`; deliberately changing it starts a new revision namespace.

Policy v1 is still supported, but the revision-floor mechanism does not apply to v1.

- `policy_id`: stable identifier for the managed policy lineage. ASCII letters, digits, `.`, `_`, `:`, and `-` only.
- `revision`: monotonic revision within that `policy_id`; increment it for every changed policy payload.
- `not_before`: optional activation time; future policies fail closed until active.
- `expires_at`: optional expiry time; expired policies fail closed. Correct host time is therefore part of the trust model.
- `force_human_review`: prevents Automatic mode.
- `prohibit_sending`: disables application sending and prevents requesting Gmail send scope.
- `prohibit_integration_api`: disables the local integration API.
- `prohibit_recovery_key_export`: prevents creation of portable recovery-key envelopes while still allowing ordinary backup/restore operations.
- `require_external_audit_anchor`: requires rollback evidence outside the SQLite workspace. Satisfy it with a valid absolute `RR_AUDIT_ANCHOR_FILE`, or on Windows/macOS with `RR_OS_AUDIT_ANCHOR=required`, which stores a monotonic anchor in the OS credential store. The OS mode is checked before startup mutations and checkpointed after operation boundaries.
- `max_daily_send_limit`: upper bound for send attempts per rolling 24 hours.
- `min_cooldown_minutes`: lower bound between detection and unattended dispatch.
- `min_retention_days`: lower bound for completed-content retention.
- `allowed_models`: exact Ollama tag allow-list. Empty means no model restriction.

Policy can only make the user configuration more restrictive. It never grants capabilities.

## Deployment workflow

1. Start from `config/enterprise-policy.example.json`.
2. For v2, increment `revision` whenever the policy bytes/meaning change. Keep `policy_id` stable for the same deployment lineage.
3. Validate before deployment:
   ```powershell
   rr.exe validate-policy C:\staging\policy.json
   ```
4. Compute the exact policy digest from the bytes that will be deployed:
   ```powershell
   (Get-FileHash C:\staging\policy.json -Algorithm SHA256).Hash.ToLowerInvariant()
   ```
5. Deploy the policy to the machine-wide default path with administrator-controlled ACLs.
6. For high-assurance environments, choose one or both independent authentication controls:
   - provision the exact digest as `RR_ENTERPRISE_POLICY_SHA256`; and/or
   - sign the **exact policy bytes** with your organization-held Ed25519 private key, deploy the detached JSON signature as `policy.json.sig`, and provision the corresponding raw 32-byte public key as standard base64 in `RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY`. If the signature lives elsewhere, set `RR_ENTERPRISE_POLICY_SIGNATURE` to its absolute path.
7. Restart Rejection Rejector.
8. Verify the effective policy:
   ```powershell
   rr.exe policy-status
   ```
9. Export redacted diagnostics if audit evidence is needed:
   ```powershell
   rr.exe diagnostics --out diagnostics.json
   ```

The runtime exposes the policy digest and effective constraints through diagnostics and the authenticated loopback health endpoint. The digest identifies exact policy bytes without exposing secrets; policy files must not contain secrets.

## Security model

- Symlink policy files are rejected.
- Files larger than 64 KiB are rejected.
- Unknown JSON fields are rejected.
- Model tags are validated with the same local-model restrictions as user settings.
- A disallowed persisted model is replaced by the first approved model at startup, and model/task qualification is invalidated.
- Interactive selection of a disallowed model fails instead of being silently rewritten.
- Invalid policy is a startup failure.
- If `RR_ENTERPRISE_POLICY_SHA256` is configured, missing or modified policy bytes fail closed.
- If `RR_ENTERPRISE_POLICY_ED25519_PUBLIC_KEY` is configured, a missing, malformed, symlinked, oversized or invalid detached signature fails closed. The signer public-key SHA-256 fingerprint is exposed in policy status for inventory/audit without exposing private material.
- V2 policies reject future `not_before`, expired `expires_at`, revision rollback, and same-revision byte drift.
- The revision floor is encrypted in the local workspace and survives restart. It is not a substitute for independently protecting the policy file/digest-pin provisioning channel.
- A new `policy_id` intentionally starts a new rollback namespace; administrators should not rotate IDs merely to change settings.
- Policy status reports whether digest pin enforcement is active and whether the loaded bytes match.
- Policy application is re-run on every settings mutation and hot-reload.
- Recovery-key export checks the machine policy directly in the CLI path, so administrators cannot bypass the restriction by avoiding the desktop UI.

This is an enforcement mechanism, not full Windows Group Policy/MDM integration. Ed25519 signatures authenticate policy provenance when the public-key provisioning channel is independently protected; the optional SHA-256 pin can additionally lock a machine to one exact byte representation. Policy v2's encrypted revision floor adds local rollback resistance. Enterprise packaging and signed application deployment remain separate release concerns.
