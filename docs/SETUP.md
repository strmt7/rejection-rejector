# Setup and operation

## Windows runtime

The x64 binaries require Microsoft Visual C++ v14 Redistributable. See [WINDOWS-RUNTIME.md](WINDOWS-RUNTIME.md) for the official source and missing-DLL guidance.

## Safe preview and storage

Run `rejection-rejector.exe --demo` for synthetic offline data. It uses a temporary encrypted database and cannot connect to Gmail or send anything. Real data goes to the OS local application-data directory; override with `--data-dir <absolute-path>`. Never choose a public repository or shared/synchronized directory.

## Gmail OAuth

1. Create/select your own Google Cloud project and enable **Gmail API**.
2. Configure Google Auth Platform/consent-screen branding and audience. For an external project in Testing, add your Gmail address as a test user.
3. Configure `https://www.googleapis.com/auth/gmail.readonly` and optionally `https://www.googleapis.com/auth/gmail.send`.
4. Create an OAuth client of type **Desktop app**, not Web application. Download its JSON containing an `installed` object.
5. In Settings, choose whether to request send permission, then **Choose OAuth JSON & connect**. Sign in using the browser on the same computer. The random loopback callback uses PKCE/state and expires after five minutes.
6. Confirm the account and replace the placeholder signature. Reconnecting always disables application delivery and restores Human review.

Credentials are encrypted locally. The original downloaded JSON remains where you saved it; protect that copy. The app does not ship a shared OAuth identity. Google verification, Workspace administrator restrictions and consent expiry still apply. External projects in Testing can receive seven-day refresh tokens for Gmail scopes; reconnect as needed. Distribution to other users requires reviewing Google's current verification requirements.

Official references:
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/identity/protocols/oauth2#expiration
- https://developers.google.com/workspace/gmail/api/auth/scopes

## Ollama and local AI

Open **Local AI**, using `gemma4:12b-it-qat` and 8,192 context initially.

1. **Install Ollama** asks for confirmation and invokes the official `Ollama.Ollama` package through Windows Package Manager. Approve the installer. If winget is unavailable, install from https://ollama.com/download/windows.
2. **Start Ollama** starts a loopback daemon if one is not already responding. App-started servers use no cloud, one parallel request, one loaded model, flash attention and q8_0 KV cache. Existing servers are not killed or silently reconfigured.
3. **Download model** retrieves weights through the local Ollama API with progress. No email is sent to the registry.
4. **Qualify & pin** checks local GGUF metadata and cloud markers, pins the inspected digest temporarily, then runs the complete synthetic pipeline: rejection classification, reply drafting, same-model verification, and Ollama GPU-residency checks. The pin is saved only if every stage passes. Qualification does not authorize email sending.

Equivalent environment for a server you start yourself:

```powershell
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_NUM_PARALLEL = '1'
$env:OLLAMA_MAX_LOADED_MODELS = '1'
$env:OLLAMA_FLASH_ATTENTION = '1'
$env:OLLAMA_KV_CACHE_TYPE = 'q8_0'
$env:OLLAMA_HOST = '127.0.0.1:11434'
ollama serve
```

Do not start a second server on an occupied port. Environment variables do not retroactively change an existing process. GPU compatibility depends on Ollama/backend/driver. The app does not guarantee every 16 GiB card works identically.

### Readiness check

Close the GUI, then run:

```powershell
.\rr.exe doctor
```

This prints only non-sensitive readiness state: Gmail connection/send-scope flags, selected schedule/mode, Ollama reachability, model pin/install match and current Ollama GPU-residency status. It does not print message bodies, refresh tokens or OAuth client secrets. A healthy point-in-time residency report does not replace **Qualify & pin**, which exercises the full local AI pipeline.

## Human review

Save the check interval and age window. Use **Check email now** to populate the durable queue. Only missing provider identities are inserted; Gmail pages are committed in batches. Non-rejection bodies are discarded after classification while identities remain. Tightening the age window immediately removes older reviewable items from the queue and clears their stored body/draft/analysis while retaining the identity tombstone for deduplication.

Select a rejection in Review. Read the original and response, edit/save or regenerate it, then confirm the exact recipient, subject and body before sending. A failed save must remain unsaved. Sending requires Google send scope **and** the app's Enable sending switch. The conversation is rechecked before dispatch.

## Automatic

Select Automatic, enable sending and explicitly authorize automatic replies. The enrollment time is recorded on saving. Backlog is excluded unless you explicitly include older rejections within the selected window. Cooldown and rolling send-attempt limits apply. Review is disabled in Automatic; switch back for held cases. Activity remains readable.

Pause blocks future dispatch but cannot recall a request already sent to Gmail. An active model request may run until its timeout. Closing the app stops its scheduler, not necessarily the Ollama daemon. Close the GUI before using `rr.exe run`; one process may own a data directory.

## Recovery and retention

A send timeout becomes Uncertain with a permanent conversation reservation. Use Activity → Reconcile with Gmail Sent. No match does not prove non-delivery; automatic retry is not offered.

Pruning removes old completed content, not deduplication/reservation identities. Pending/uncertain records remain. Invoke pruning explicitly; it is not automatic physical erasure. Close the app before copying database files. A database copy without its Credential Manager key is not portable. Do not delete the OS credential or vault-id; key loss is unrecoverable in v0.1.

## Troubleshooting

- Lock error: close the other GUI/worker, do not bypass a live lock.
- Changed model/context/Ollama endpoint: saving the new configuration disarms delivery and returns to Human Review; inspect and explicitly qualify/pin again before re-enabling sending/Automatic.
- GPU check failed: close other models/workloads; verify backend GPU support and context.
- Input too long: review manually, shorten optional candidate facts, or use 16,384 context and requalify.
- Google refresh failed: check consent expiry/admin policy and reconnect.
- Newer thread activity: inspect/handle in Gmail instead of blindly replying.
- API busy: retry later with backoff; do not bypass the worker by editing SQLite.

Linux development requires desktop libraries and a strong private `RR_VAULT_PASSPHRASE` of 20+ characters for a real workspace. Argon2 derives the key. Demo needs no passphrase. Never commit the passphrase.

Linux runtime note: X11 rendering requires `libxkbcommon-x11-0` in addition to the build libraries. CI installs `libxkbcommon-x11-dev`, which supplies the runtime dependency.
