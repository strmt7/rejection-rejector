# Enterprise policy

Rejection Rejector supports an optional, local administrator policy overlay. It is intentionally file-based and local-first: no management server is required, and the application remains usable in disconnected enterprise environments.

## Default locations

- Windows: `%PROGRAMDATA%\RejectionRejector\policy.json`
- Linux: `/etc/rejection-rejector/policy.json`
- Explicit override: absolute path in `RR_ENTERPRISE_POLICY`

A configured relative override is rejected. A malformed or unsupported policy fails startup rather than silently disabling policy enforcement.

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
3. Deploy to the machine-wide default path with administrator-controlled ACLs.
4. Restart Rejection Rejector.
5. Verify the effective policy:
   ```powershell
   rr.exe policy-status
   ```
6. Export redacted diagnostics if audit evidence is needed:
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
- Policy application is re-run on every settings mutation.

This is an enforcement mechanism, not full Windows Group Policy/MDM integration. Enterprise packaging and signed deployment remain separate release concerns.
