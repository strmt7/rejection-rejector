# DeepSource Dispositions

DeepSource analyzes every commit on `main` through the GitHub integration
([dashboard](https://app.deepsource.com/gh/strmt7/rejection-rejector)). Findings
are remediated at the source wherever the finding reflects a real defect. This
document records the **exact-source false-positive dispositions** — findings the
analyzer reports that the surrounding source proves harmless — so acceptance
never rests on a dashboard ignore alone.

Inventory retrieval (complete active occurrence list for a commit) uses the
documented DeepSource repository occurrence API through the official CLI's
stored session; see `docs/OPERATIONS.md` for the review loop.

## Policy

1. A finding is fixed at source when the source can be improved (semantics,
   safety, style, documentation). A cleaner source that also removes the
   pattern is preferred over suppression.
2. A finding is dispositioned here only when the analyzer's rule contradicts
   what the exact source proves — and the proof is written below with the
   precise item types involved.
3. Dashboard "ignore" actions alone are never an acceptance basis. If an
   ignore is applied, the same reasoning is recorded here first.

## Dispositions (current analysis run, commit `f7cfd8d`)

### SECRETS — `SCT-A000` (5 findings)

All five are low-entropy fixture strings or documentation words that the
secret scanner's entropy heuristic flags for audit. None is a credential:
none authenticates anywhere, all are compile-time literals in test fixtures or
prose.

| Location | Flagged literal | Exact-source evidence |
|---|---|---|
| `src/gmail.rs:1382-1383` | `client-secret`, `refresh-token` | Test-fixture `Credentials` struct in a `#[cfg(test)]` helper; the strings are placeholder values passed through a constructor, never used against a network endpoint. |
| `src/oauth.rs:375` | `private-access-token` | Test-fixture `Tokens` value in `token_wiping_clears_both_secrets`, whose assertions verify the zeroization of the fixture; the literal exists to be wiped. |
| `src/store.rs:3328` | `forged-thread` | SQL fixture value in a tamper-detection test (`UPDATE deliveries SET thread_key='forged-thread'`); it simulates a forged thread key and must be a recognizable constant. |
| `docs/INTEGRATION.md:41` | `Read-Host` | The PowerShell `Read-Host` cmdlet name in an example that prompts the operator for a local API token; documentation prose, not a value. |

### BUG_RISK — `RS-E1011` "drop with a `Copy` type" (5 findings)

Every flagged `drop(x)` argument is a **non-`Copy`** type; each call performs a
real, intended lifetime action. The rule's `Copy` premise does not hold for any
of them:

| Location | Dropped value (exact type) | Why the drop is intentional |
|---|---|---|
| `src/oauth.rs:203` | `Zeroizing<Vec<u8>>` (`config_bytes`) | Forces zeroization of the OAuth client secret bytes before the parsed config is used further. |
| `src/oauth.rs:251` | `std::net::TcpListener` (`listener`) | Closes the loopback consent listener before the token exchange begins; a live listener would accept stray requests. |
| `src/recovery.rs:268` | backup output file handle (`output`) | Closes the destination file before `fs::remove_file` on the error path; Windows cannot remove an open file. |
| `src/recovery/restore.rs:172` | `Store` (`probe`) | Closes the probe database before the staging store reopens the same directory; SQLite files must not be double-opened through two handles. |
| `tests/decision_protocol.rs:227` | `std::sync::MutexGuard` (`calls`) | Releases the recording lock before the serialized report file is read below; without the drop the mutex stays held. |

### BUG_RISK — `RS-E1015` "arguments contain the unit type" (3 findings)

| Location | Flagged call | Exact-source evidence |
|---|---|---|
| `src/worker.rs:1096` | `crate::recovery::create_backup(...)` | The call returns a backup path which `.map(|_| ())` deliberately discards for a `report_write(...)` that only carries success/failure. No argument is `()`. |
| `src/gmail.rs:292` | `Zeroizing::new(std::mem::take(&mut t.access_token))` | `String::take` yields the owned `String` (moved out of the parsed token response); the wrapper deliberately zeroizes it on drop. No argument is `()`. |
| `src/bin/rr.rs:393` | `Ok(match action { ... })` | The match arms serialize `AutostartStatus` values (`background::install`/`status` return `Result<AutostartStatus>`), producing `serde_json::Value`. No arm returns `()`. |

### BUG_RISK — `RS-A1008` "call returning `Self` in `default()`" (1 finding)

`src/worker.rs:171` — `impl Default for WorkerPulse { fn default() -> Self { Self::new() } }`.
Delegating `Default` to `Self::new()` is the pattern `clippy::new_without_default`
recommends and the repository's clippy gate (CI parity, `-D warnings`) requires;
inlining the constructor body would duplicate it and drift.

### BUG_RISK — `PTC-W0063` "unwrapped `next()`" (remediated at source)

`training/build_corpus_v2.py` (`generate_records`) iterates `itertools.cycle`, which is
infinite, so `StopIteration` is impossible. The source was still improved: the
call now passes an explicit default (`next(it, fallback)`), which removes the
rule pattern and documents the fallback.

## Remediated at source (analysis run at commit `f7cfd8d`)

The 2026-10-27 review wave remediated the remaining ~1,470 findings at the
source across `training/`, `tools/`, `scripts/`, `tests/`, `build.rs`, `fuzz/`,
`windows/` and all of `src/`: rustdoc added for every undocumented public item,
line length normalized to 100 columns, `clone_from`/`map_or`/`unwrap_or_else`
idioms applied where the rule prescribes them, `create_dir_all` hardening,
`assert!` rewrites for boolean comparisons, subprocess `check=` made explicit,
`urlopen` restricted to https (loopback excepted), `assert`-based input
validation replaced with explicit raises, `ls`-based discovery replaced with
`find`, and the cyclomatic-complexity rule satisfied by decomposition in all but
the functions below.

### Deferred: `RS-R1000` cyclomatic complexity (14 functions)

Decomposition of these functions is a compile-verified refactor on its own
track; each is verified behavior-bearing code and was left intact rather than
rushed:

| Function | Complexity |
|---|---|
| `src/bin/rr.rs` `main` | 144 |
| `src/worker.rs` `run` | 112 |
| `src/gui.rs` `settings` | 90 |
| `src/gui.rs` `local_ai` | 63 |
| `src/engine.rs` `send_attempt` | 73 |
| `src/engine.rs` `open` | 58 |
| `src/store.rs` `verify_application_invariants_connection` | 51 |
| `src/engine.rs` `automatic_policy` | 40 |
| `src/worker.rs` `api_query_with_operation` | 39 |
| `src/store.rs` `open` | 38 |
| `src/worker.rs` `handle_api_write` | 37 |
| `src/store.rs` `verify_backup_file` | 35 |
| `src/worker.rs` `kind` | 34 |
| `src/evaluation.rs` `evaluate` | 42 |

## Review loop

1. Push the change and wait for the DeepSource statuses on the exact commit
   (the bot posts one status per analyzer).
2. Retrieve the complete active inventory for the new default-branch head and
   diff it against the run recorded here.
3. New findings are fixed at source or dispositioned in this file before the
   change is considered accepted. A green check on an older commit proves
   nothing about the new head.
