# Support

## How to get help

- **Usage, setup and troubleshooting:** start with [README.md](README.md) and
  [docs/SETUP.md](docs/SETUP.md); the runbooks in [docs/](docs/) cover the
  enterprise deployment, transport, model, audit and accessibility surfaces.
- **Bugs and feature requests:** open a GitHub issue on this repository with the
  version, the platform, and the exact reproduction steps. Redact credentials,
  addresses and message bodies from every report (the repository's leakage rules
  apply to issues too).
- **Security issues:** follow [SECURITY.md](SECURITY.md) — do not open a public
  issue for a suspected vulnerability.

## What support covers

This project is provided as-is under the [MIT License](LICENSE). Issues are
triaged on a best-effort basis; there is no contracted support SLA unless a
separate written agreement says otherwise.

## Scope boundaries

- Provider outages (Gmail/IMAP/SMTP, model runtimes) are upstream problems; the
  tool's diagnostics (`rr doctor`, `rr diagnostics`) produce the evidence needed
  to tell provider problems from product problems.
- Credential setup (Google OAuth clients, app passwords) is documented in
  [docs/SETUP.md](docs/SETUP.md); support cannot create or manage credentials
  on a user's behalf.
