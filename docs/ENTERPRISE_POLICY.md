# Enterprise policy

Rejection Rejector supports an optional, local administrator policy overlay. It is intentionally file-based and local-first: no management server is required, and the application remains usable in disconnected enterprise environments.

## Default locations

- Windows: `%PROGRAMDATA%\RejectionRejector\policy.json`
- Linux: `/etc/rejection-rejector/policy.json`
- Explicit override: absolute path in `RR_ENTERPRISE_POLICY`

A configured relative override is rejected. A malformed or unsupported policy fails startup rather than silently disabling policy enforcement.

For higher-assurance deployments, provision `RR_ENTERPRISE_POLICY_SHA256` independently from the policy file. It must contain the exact 64-hex SHA-256 digest of the deployed policy bytes. When configured, a missing policy file or any byte-level drift fails startup/reload closed. This is an integrity/provenance pin, not a digital signature: protect the environment/MDM source that provisions the pin separately from the policy file.

## Policy v1

```json
{
  "version": 1,
  "force_human_review": true,
  "prohibit_sending": true,
  "prohibit_integration_api": true,
  "max_daily_send_limit": 3,
  "min_cooldown_minutes": 90,
  "min_retention_days": 365,
  "allowed_models": ["granite4.2:8b-q8_0"]
}
```

All fields are optional except `version`; omitted controls use their non-restrictive default.

- `force_human_review`: prevents Automatic mode.
- `prohibit_sending`: disables application sending and prevents requesting Gmail send scope.
- `prohibit_integration_api`: disables the local integration API.
- `max_daily_send_limit`: upper bound for send attempts per rolling 24 hours.
- `min_cooldown_minutes`: lower bound between detection and unattended dispatch.
- `min_retention_days`: lower bound for completed-content retention.
- `allowed_models`: exact Ollama tag allow-list. Empty means no model restriction.

Policy can only make the user configuration more restrictive. It never grants capabilities.

## Deployment workflow

1. Start from `config/enterprise-policy.example.json`.
2. Validate before deployment:
   ```powershell
   rr.exe validate-policy C:\staging\policy.json
   ```
3. Compute the exact policy digest from the bytes that will be deployed:
   ```powershell
   (Get-FileHash C:\staging\policy.json -Algorithm SHA256).Hash.ToLowerInvariant()
   ```
4. Deploy the policy to the machine-wide default path with administrator-controlled ACLs. For high-assurance environments, separately provision the digest as `RR_ENTERPRISE_POLICY_SHA256` through the enterprise configuration mechanism.
5. Restart Rejection Rejector.
6. Verify the effective policy:
   ```powershell
   rr.exe policy-status
   ```
7. Export redacted diagnostics if audit evidence is needed:
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
- Policy status reports whether digest pin enforcement is active and whether the loaded bytes match.
- Policy application is re-run on every settings mutation and hot-reload.

This is an enforcement mechanism, not full Windows Group Policy/MDM integration. Enterprise packaging and signed deployment remain separate release concerns.
