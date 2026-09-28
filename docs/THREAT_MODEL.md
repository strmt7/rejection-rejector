# Threat model and data-flow security invariants

This document defines Rejection Rejector's security model for engineering and release review. It is intentionally stricter than a feature overview: a control is useful only when its trust boundary, failure mode and enforcement point are explicit.

## Security objectives

1. **No unintended outbound email.** A model, incoming message, UI race or retry must not create an unapproved/unsafe external write.
2. **No duplicate delivery after ambiguity.** Once a send may have crossed Gmail's write boundary, the application must reconcile rather than retry blindly.
3. **Mailbox/profile confidentiality.** Real message content, OAuth data, API tokens, signature/candidate facts and the vault master key must not enter source control, hosted AI, diagnostic logs or release artifacts.
4. **Local-model containment.** Private inference is permitted only through the configured literal loopback Ollama origin; cloud-backed model markers and redirected inference are rejected.
5. **Durable state integrity.** Database corruption, wrong keys, stale UI revisions, invalid state transitions and audit-chain modification must fail closed.
6. **Recoverability without silent key exposure.** Backups remain encrypted; portable recovery uses an independently passphrase-wrapped key envelope rather than plaintext master-key export.
7. **Managed-policy integrity.** Enterprise policy must not be silently weakened, rolled back or replaced with unauthenticated bytes where pin/signature enforcement is configured.
8. **Verifiable release provenance.** Shipped artifacts must be tied to a specific source commit, audited dependencies, SBOM and release workflow evidence.
9. **Supportability without surveillance.** Health, metrics, operation correlation and runtime journaling must remain local and privacy-minimal by construction.

## Data classification and storage map

| Data / capability | Classification | Stored at rest | Permitted egress | Primary enforcement |
|---|---|---|---|---|
| Gmail OAuth refresh/client credentials | Secret | authenticated encrypted SQLite payloads | Google OAuth/Gmail endpoints only | OAuth + vault/store modules |
| Vault 256-bit master key | Critical secret | Windows Credential Manager / macOS Keychain; Linux derives from explicit passphrase | never exported plaintext | vault module |
| Recovery-key envelope | Sensitive recovery material | user-selected file, AEAD-wrapped | only where user explicitly saves it | vault/recovery modules |
| Gmail message body, subject, headers, recipients | Private mailbox data | authenticated encrypted SQLite payloads while retained | Gmail; local Ollama for inference; authenticated local API where explicitly enabled | Gmail/store/engine/API |
| Candidate facts and signature | Personal/private | encrypted settings | local Ollama and intentional outgoing reply | config/engine |
| Generated reply draft | Private | encrypted store | Gmail only after policy + human/automatic gates | engine/store |
| Message/provider/thread identifiers | Sensitive metadata | encrypted payload plus hashed/index metadata where needed | local integration API under bearer auth | store/API |
| Database counts/timestamps/state indexes | Sensitive metadata | SQLite clear metadata | privacy-safe local metrics/API | store/metrics |
| Integration API bearer token | Secret | encrypted metadata; may be briefly revealed in GUI | local client explicitly receiving it | worker/API |
| Enterprise policy | Administrative security data | administrator-provisioned file + encrypted revision/digest floor | local process only | policy module |
| Policy verification key/digest | Trust anchor | independently provisioned machine configuration | local process only | policy module |
| Ollama model weights | Local third-party code/data asset | Ollama-managed model store | loopback Ollama only | ollama module |
| Runtime journal | Operational metadata | bounded private JSONL rotation | none automatically | runtime_log |
| Semantic audit journal | Integrity/security record | encrypted SQLite hash chain | authenticated API anchor/events | store/API |
| SBOM/release hashes/attestations | Public release evidence | GitHub Actions/release artifacts | public GitHub release/evidence | CI/release workflows |

## Trust boundaries

### TB1 — Untrusted incoming email → parser/policy/model

Recruiters, ATS systems and attackers can control email subject/body/headers. Email is **data, never instructions**. It receives no tool authority. MIME parsing is bounded; attachments are not executed. Model classifications are structured and verified, but model output is never itself an authorization token.

Security consequence: prompt injection inside an email cannot directly call Gmail send, alter settings or grant Automatic eligibility.

### TB2 — System browser / Google OAuth → local callback

OAuth uses a system browser, random loopback callback port, S256 PKCE and random state with bounded lifetime. The callback accepts only the expected state/code shape. OAuth client JSON is user-provided; the application never ships a shared secret identity.

Security consequence: browser content is not trusted merely because it arrived through localhost.

### TB3 — Gmail REST → local state machine

Gmail is the authoritative provider for source-message/thread state and Sent reconciliation. Provider identifiers are validated before URL construction. A fresh conversation preflight occurs before dispatch. The write boundary is protected by a durable local reservation written before the network send.

Security consequence: timeout/server ambiguity becomes **Uncertain**, never an automatic retry.

### TB4 — Encrypted SQLite ↔ OS credential store

Application payloads are AEAD encrypted with associated-data binding. The database itself is not full-file encrypted: indexes/counts/timestamps/hash metadata can remain visible. The master key is stored separately in the OS credential store on Windows/macOS; Linux requires an explicit passphrase.

Security consequence: copying only the database does not reveal payloads, but same-user malware/process memory/OS compromise remain outside this boundary.

### TB5 — Local process → Ollama

Inference origin must be a literal loopback HTTP origin. Environment proxies are bypassed for local inference. Redirects/cloud markers are rejected. The configured model/digest/context is qualified and a separate task-specific evaluation must match the exact Automatic-mode configuration.

Security consequence: changing model, digest, context, signature, tone or candidate facts invalidates unattended-send qualification.

### TB6 — Native GUI/API → single worker

The native UI and optional local API submit work through a bounded command channel to one worker owning the data directory. Stale UI revisions fail optimistic concurrency checks. The HTTP API is read-only, loopback-only, bearer-authenticated, rejects browser Origin, uses stable request IDs and returns no-store responses.

Security consequence: integrations must use the API/library contract; SQLite internals are not an external synchronization contract.

### TB7 — Worker → external send

Human Review requires exact persisted draft confirmation. Automatic mode requires deterministic current-message rejection evidence, a qualified local-model pipeline, cooldown/rate limits, current source/draft/model identities and fresh provider preflight. A durable per-message reservation is created before Gmail dispatch.

Security consequence: no model-generated result can independently mint permission to send.

### TB8 — Backup/recovery media ↔ live workspace

Backups are checksum- and audit-head-bound encrypted database images with manifest/vault identity. Restore stages and verifies before replacing live files and keeps rollback material. Portable recovery-key envelopes are stored separately and passphrase-wrapped with Argon2id + XChaCha20-Poly1305.

Security consequence: a backup is not equivalent to a plaintext mailbox export. Losing both OS key and recovery envelope/passphrase is intentionally unrecoverable.

### TB9 — Administrator policy → application

Managed policy is bounded, schema-strict and non-symlinked. Deployments can enforce exact SHA-256 bytes, Ed25519 provenance or both. A per-policy encrypted revision/digest floor rejects downgrade and same-revision drift.

Security consequence: invalid managed policy fails closed rather than silently falling back to user-controlled settings.

### TB10 — Source repository → release binary

CI pins source/toolchain/actions, runs format/test/clippy/security/supply-chain/deep-quality gates, embeds auditable dependency metadata, emits an SBOM and can create GitHub artifact/SBOM attestations. Manual packaging verifies exact-main gates and deep-quality evidence lineage.

Security consequence: SHA-256 alone is not treated as publisher identity; Authenticode/MSI/MSIX signing remains a separate open control.

## Threats, abuse cases and mitigations

| Threat | Attacker/failure capability | Required behavior |
|---|---|---|
| Email prompt injection asks model to ignore rules/send elsewhere | controls message text | content remains inert; structured parsing + deterministic Rust gates; no model tool authority |
| Interview/offer contains quoted historical rejection | controls thread text | current-message quote stripping + positive/conflict guards block Automatic |
| Same model misclassifies and self-verifies | correlated model error | independent deterministic clear-rejection requirement + critical fixture qualification |
| HTML/MIME/header ambiguity | crafted email | bounded parsing; duplicate sensitive headers/hard blocks; Human Review on uncertainty |
| No-reply/list/auto-reply loop | crafted/system sender | mailbox/auto-submitted/list suppression guards |
| UI edits after review | user/UI race | revision + exact draft hash binding; changed draft invalidates verification |
| Duplicate click/concurrent sends | UI/API concurrency | immediate SQLite reservation and unique per-message delivery record |
| Gmail timeout after write | provider/network ambiguity | keep reservation, mark Uncertain, reconcile Sent; never retry blindly |
| Crash during send | process failure | startup converts unresolved Sending to Uncertain; reservation remains authoritative |
| Crash during backup/restore | process/storage failure | staged artifact/rollback path; exclusive workspace lock; recovery drill |
| Database tampering | local filesystem write without key | AEAD payload auth + audit hash chain + structural checks |
| Whole-database rollback | attacker/operator restores older internally valid DB | detectable when a prior sequence/hash audit point is retained outside that rollback. Use an external anchor file under another trust domain or the Windows/macOS OS credential-store monotonic anchor; protected anchors are verified before runtime recovery mutates state |
| Stolen local API token | same-user/local compromise | read-only API, loopback/Host/Origin checks, token rotation; token still grants private read access |
| Local malicious process talks to Ollama/API | same OS user | loopback is not authentication; API bearer token protects API, Ollama is assumed under user's local trust boundary |
| Malicious/compromised model package | model supply-chain compromise | explicit download, local-only use, digest pin, task evaluation; model weights are still third-party trust |
| Enterprise policy rollback | local admin/user replaces policy | revision/digest floor + optional external digest/signature trust anchors |
| Recovery envelope theft | attacker gets envelope | Argon2id passphrase wrapping; envelope remains sensitive and must be separated from passphrase/backup |
| GitHub dependency/action compromise | upstream supply-chain attack | pinned actions, Cargo.lock, RustSec/deny/machete, CodeQL, SBOM, attestations, release lineage gates |
| Logs leak mailbox data | developer/operator mistake | runtime log schema has no arbitrary message/error fields; secret-canary tests; semantic details remain encrypted |
| Resource exhaustion / poison queue | malformed messages/model failures | bounded input/response sizes, timeouts, bounded command queue, per-message retry cap then Human Review |

## Security invariants — must remain testable

The following are release-level invariants. A change that invalidates one requires an explicit architecture/security update, not a silent workaround.

1. Constructing the library or opening a workspace never sends email.
2. Human Review is the default and application sending is disabled by default.
3. Automatic mode cannot validate without both an exact model pin and current task-specific qualification.
4. Incoming email/model output cannot directly authorize a Gmail write.
5. The current rejection message must independently satisfy deterministic Automatic-mode evidence and conflict checks.
6. A specific rejection message can obtain at most one durable delivery reservation.
7. An ambiguous external write is never automatically retried.
8. Stale revisions/draft hashes cannot be sent.
9. A changed model/context/profile/tone/signature invalidates relevant model qualification.
10. Remote/cloud inference endpoints are rejected; private inference is loopback-only.
11. Existing vault IDs never mint replacement keys when credentials are missing.
12. Backup verification authenticates schema, checksum, vault identity and audit head before restore.
13. Restore never overwrites a running workspace and has rollback material before replacing live state.
14. Portable recovery never writes the raw master key to disk.
15. Managed policy rollback/same-revision drift is rejected when policy v2 state exists.
16. The integration API remains read-only; write-route enablement requires a future explicit API version/security design.
17. Runtime journal records cannot contain mailbox bodies/subjects/addresses, OAuth/API secrets, signature, candidate facts or arbitrary exception strings.
18. Public API operations and runtime records expose only locally generated correlation/request identifiers, never private identifiers.
19. Release packaging uses the exact triggering `main` commit and cannot accept a newer failed deep-quality run hidden behind older green evidence.
20. Security/dependency scans and SBOM generation run from pinned tools/actions and locked Rust dependencies.
21. Deep-quality gates (coverage/mutation/fuzz/recovery) must fail or become stale when relevant source changes invalidate their evidence.
22. Demo/synthetic fixtures can never be delivered to Gmail.

## Residual risks and explicit non-goals

- Same-user malware, administrator compromise, process-memory extraction, OS paging, clipboard compromise and a malicious kernel are outside the application cryptographic boundary.
- Full local rollback detection requires an audit anchor stored outside the rolled-back workspace. The built-in API exposes anchors, but independently protected automatic anchoring is not yet implemented.
- The model verifier is not independent because the same selected model performs the second pass. Deterministic Rust policy reduces but cannot eliminate semantic model error.
- Physical GPU peak-memory certification is external to Ollama-reported residency.
- Gmail/provider semantics can change; live controlled acceptance remains required.
- Authenticode-signed Windows binaries, MSI/MSIX/Intune packaging and a signed update channel are not implemented.
- No external penetration test or compliance certification is claimed.

## Review checklist for future changes

Before accepting a change, reviewers should answer:

1. Does it introduce a new external write or make an existing write retryable?
2. Does untrusted email/model/browser content cross into an authorization decision?
3. Does it add a new place where secrets/private text can be stored, logged or exported?
4. Does it change the API/recovery/settings/policy format and therefore require versioning/migration evidence?
5. Does it weaken a fail-closed condition into fallback behavior?
6. Does it make a deep-quality workflow stale without triggering that workflow?
7. Does it introduce an OS/process trust assumption not captured above?
8. Does the release evidence still prove the exact source and relevant quality lineage?

If any answer is yes, the associated code, test, documentation and release gate should change together.
