# Enterprise policy

Rejection Rejector supports an optional, local administrator policy overlay. It is intentionally file-based and local-first: no management server is required, and the application remains usable in disconnected enterprise environments.

## Default locations

- Windows: `%PROGRAMDATA%\RejectionRejector\policy.json`
- Linux: `/etc/rejection-rejector/policy.json`
- Explicit override: absolute path in `RR_ENTERPRISE_POLICY`

A configured relative override is rejected. A malformed or unsupported policy fails startup rather than silently disabling policy enforcement.

For higher-assurance deployments, provision `RR_ENTERPRISE_POLICY_SHA256` independently from the policy file. It must contain the exact 64-hex SHA-256 digest of the deployed policy bytes. When configured, a missing policy file or any byte-level drift fails startup/reload closed. This is an integrity/provenance pin, not a digital signature: protect the environment/MDM source that provisions the pin separately from the policy file.

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
5. Deploy the policy to the machine-wide default path with administrator-controlled ACLs. For high-assurance environments, separately provision the digest as `RR_ENTERPRISE_POLICY_SHA256` through the enterprise configuration mechanism.
6. Restart Rejection Rejector.
7. Verify the effective policy:
   ```powershell
   rr.exe policy-status
   ```
8. Export redacted diagnostics if audit evidence is needed:
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
- V2 policies reject future `not_before`, expired `expires_at`, revision rollback, and same-revision byte drift.
- The revision floor is encrypted in the local workspace and survives restart. It is not a substitute for independently protecting the policy file/digest-pin provisioning channel.
- A new `policy_id` intentionally starts a new rollback namespace; administrators should not rotate IDs merely to change settings.
- Policy status reports whether digest pin enforcement is active and whether the loaded bytes match.
- Policy application is re-run on every settings mutation and hot-reload.
- Recovery-key export checks the machine policy directly in the CLI path, so administrators cannot bypass the restriction by avoiding the desktop UI.

This is an enforcement mechanism, not full Windows Group Policy/MDM integration. The SHA-256 pin plus v2 rollback floor provide integrity, provenance pinning and replay resistance when the pin/provisioning channel is independently protected, but they are **not an asymmetric digital signature**. A signed policy format remains a future extension. Enterprise packaging and signed deployment remain separate release concerns.
