# Architecture

Native egui desktop / rr CLI → bounded command channel → single Rust worker → encrypted SQLite, Gmail REST and loopback Ollama. Optional read-only API calls the same worker. No browser wrapper or server database is required. Network/model/database work does not run on the UI thread; atomic Pause/Stop flags gate dispatch.

## Incremental sync

Take a Gmail history baseline before the initial date-bounded listing. Insert each missing account/message identity with an encrypted durable queue record. Save the cursor only after every page succeeds. Later polls consume messageAdded history. Replayed pages are deduplicated. Expired history (404) or a changed lookback triggers reconciliation. The pre-list baseline catches arrivals racing with listing on a subsequent poll.

Actual message dates/folders are checked by the worker. Out-of-window messages become Deferred and their bodies are discarded; expanding the window requeues them. Previously processed mail is not refetched/classified each poll. Non-rejections retain identities, not full bodies. Gmail label-change subscriptions and push/pubsub are outside v0.1.

## State and delivery

Queued → Ready / Attention / Other / Deferred. Editing a reviewable reply invalidates verification and moves to Attention. Regeneration requeues it. Dismissal records Dismissed. Confirmed human sends or eligible automatic replies transition through Sending → Sent / Uncertain. Positive Sent reconciliation resolves Uncertain.

A send must match the current revision and exact persisted draft hash. Account, source message and newer conversation activity are rechecked. An IMMEDIATE transaction enforces the rolling attempt cap and creates one permanent delivery record for that specific rejection message before HTTP dispatch. A thread may have only one **reserved or uncertain** delivery at a time; a completed Sent record does not prevent a later, distinct rejection in the same Gmail thread from receiving its own reply. The same rejection message can never obtain a second delivery record. Crashed Sending records recover as Uncertain.

Known pre-dispatch cancellation or a definite provider-side rejection releases the unsent reservation and returns the message to Human Review. Ambiguous network/server outcomes retain an Uncertain record and block further replies in that thread until reconciliation. This prioritizes avoiding duplicate delivery over guaranteed delivery. It is at-most-once **per rejection message at the application level**, not a distributed exactly-once guarantee. The deterministic outgoing Message-ID supports reconciliation.

## Trust boundary

Email is inert untrusted data, never tools/instructions. Attachments are not executed; HTML becomes text. Structured outputs and exact evidence checks reject malformed or unsupported classifications. Model/prompt/context/source/draft hashes bind a verification to its inputs. The same model performs the second pass, so its errors are correlated. Automatic mode therefore also requires a deterministic affirmative rejection phrase in the current de-quoted message, in addition to rejecting conflicting opportunity/prompt-injection language. Human review remains the recommended initial mode.

SQLite WAL/FULL synchronization, authenticated encrypted payloads, optimistic revisions and an exclusive directory lock protect integrity. Metadata indexes are not encrypted. The DB layout is private; use the library/API as the integration contract.
