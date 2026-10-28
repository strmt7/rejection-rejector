# Proposed engineering policy and execution receipt contract

This is a small **report deliverable**, not a change already installed in any repository. It supplies a read-only reference validator, two JSON Schemas, and explicitly synthetic examples. The validator computes a local contract decision from required records, identities, counts, dependencies, timestamps and actual file hashes. It never executes a command string, imports application code, downloads a dependency or changes a remote setting.

**A local PASS does not authenticate the producer or prove that a log is truthful.** It means the supplied records are internally consistent with the supplied reviewed policy and trusted target inputs. Repository-hosted checks, branch enforcement, signed provenance and supported-host acceptance remain separate responsibilities. This implements the mechanical part of the manual's S15 receipt requirement; it cannot establish that a weak policy adequately tests the product.

## Contents and prerequisites

| File | Purpose |
| --- | --- |
| `validate_contract.py` | Standalone stdlib validator; stdout JSON and exit status only. |
| `engineering-policy.schema.json` | Closed structure for the JSON-equivalent data parsed from `engineering.toml`. |
| `execution-receipt.schema.json` | Closed structure for execution/evidence receipt JSON. |
| `test_validate_contract.py` | Positive controls and adversarial contract tests; no application commands. |
| `examples/engineering.toml` | Synthetic Qfales-shaped policy using fictitious tools/profile identity; not an approved repository policy. |
| `examples/receipt-*-synthetic.json` | Consistent, false-pass and unavailable-host examples. |
| `build_schemas.py`, `build_examples.py` | Rebuild only the report package's schemas/examples. They write files; the validator itself is read-only. |
| `record_checks.py` | Run the validator's unit tests and examples, then save their report-package receipts. |

Use **Python 3.11 or newer** in a dedicated analysis/tooling environment. No third-party package is required. The stdlib [`tomllib`](https://docs.python.org/3.11/library/tomllib.html) parser was introduced in Python 3.11. This requirement does not change an application's Python version or an Imaris/Ice bundled ABI. On Windows, select an installed compatible interpreter explicitly (for example `py -3.11`); on Linux, the examples below use `python3`. No shell-specific activation or PowerShell 7 syntax is required by this Python tool.

The schemas declare [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-core). The stdlib validator implements only the closed keyword subset used by these two bundled schemas plus the stated semantic rules. It is not a general JSON Schema engine, does not load remote schemas and rejects unsupported schema keywords. Dates/timestamps and cross-record rules are checked by the semantic validator rather than delegated to optional schema `format` handling. Contract input files are limited to 2 MiB; artifact hashing is streamed. Large test inventories must be scoped deliberately within that limit; automatic receipt merging/sharding is not implemented.

## Run the examples

Run these from this package directory. The source SHA identifies the reviewed Qfales snapshot; the all-ones profile SHA and `example.invalid` locator are deliberately fictitious. The log explicitly says no project command ran.

```sh
python3 -B validate_contract.py --policy examples/engineering.toml --receipt examples/receipt-consistent-synthetic.json --evidence-root examples --repo strmt7/qfales_fc_website --target-sha f455a4e36c0b9541edb6f0207b2870b0369b5f3a --profile-sha 1111111111111111111111111111111111111111
```

Expected: `consistency_result` is `PASS`, but the final `result` is **BLOCKED** with `qualification: synthetic_example_only`; exit code **2**. Synthetic evidence cannot qualify a real capability, even when every hash and counter is consistent.

```sh
python3 -B validate_contract.py --policy examples/engineering.toml --receipt examples/receipt-false-pass-synthetic.json --evidence-root examples --repo strmt7/qfales_fc_website --target-sha f455a4e36c0b9541edb6f0207b2870b0369b5f3a --profile-sha 1111111111111111111111111111111111111111
```

Expected: **FAIL**, exit code **1**. Its command claims success with exit code 7; the validator computes failure independently and rejects the contradictory overall label. Dependent test/task results cannot repair that contradiction.

```sh
python3 -B validate_contract.py --policy examples/engineering.toml --receipt examples/receipt-blocked-synthetic.json --evidence-root examples --repo strmt7/qfales_fc_website --target-sha f455a4e36c0b9541edb6f0207b2870b0369b5f3a --profile-sha 1111111111111111111111111111111111111111
```

Expected: **BLOCKED**, exit code **2**. A required unavailable host is not a pass and is not disguised as an intentional skip. Missing execution from an honestly blocked family remains a blocker. A passed family claiming zero execution is a failure.

Run the validator's own tests and save a reproducible report receipt:

```sh
python3 -B -m unittest -v test_validate_contract
python3 -B record_checks.py
```

The package currently contains 48 tests, including missing/wrong task IDs, stale source/profile/baseline, false PASS, changed evidence/artifact/input/policy bytes, unexpected skips, zero and fabricated counts, absent required tests, future or impossible qualification timestamps, duplicate records/JSON keys, unsupported or blank tool identities, path escape, overlapping source categories, hard-link count inflation, whitespace-only fields, coverage/qualification omissions and exception misuse. `test-results.json` is the authoritative count for the delivered revision. A positive test intentionally shows that consistent metadata labelled “real” can pass even when the fixture log text says synthetic: this exposes the authenticity limit rather than concealing it. No sample distributed receipt is presented as real execution evidence.

## Policy fields and review responsibility

The policy identifies the canonical repository, audit-baseline SHA, immutable shared-profile SHA/locator, owner, lifecycle, last review and next review deadline. Lifecycle uses the manual's exact values: `maintained`, `maintenance-only`, `experiment`, `superseded`. The receipt repeats the policy's audit-baseline SHA; those values must match. This baseline is historical traceability: future implementation commits may differ from it. The receipt source must instead equal the **current trusted target SHA** passed on the command line. The policy and receipt profile must equal the independently supplied profile SHA. The profile locator must contain that SHA; existence, signature and approval of the remote profile are not checked here.

The policy lists supported environments and allowed exact tool-version strings. Mark every environment needed for a promised capability `required = true`; optional environments are explicitly outside that completion promise. Declared commands include their exact string, environment, applicability and factual reason. Receipt command IDs and strings must match those declarations, and passing commands require exit code 0 plus an available supported environment and hashed evidence.

`roots.authored`, `roots.generated`, `roots.vendor` and `roots.fixture` are relative, nonoverlapping scope declarations. Empty categories are allowed. The tool checks their syntax/overlap, not whether they exhaust the repository or whether coverage measured the declared source. Build the actual inventory and exclusions in the repository's proposed adapter; a typed scope list alone is insufficient.

Both policy and receipt must contain exactly **S01–S15** and the repository's six canonical task IDs. The validator fixes the report's prefix mapping: FZ, RR, OZC, VS, TF, MPL, SAT, SJS, AISC, OMERO, QFALES, IMARIS-UI and AIR-DEFENSE. Its `PREFIXES` table names the exact 13 repositories. A renamed/new repository or changed task program requires an explicit validator/profile revision; unknown identities do not silently pass.

Every applicable standard/task names required commands, test families and/or artifact kinds. These dependencies must exist and have passing/available results. The validator computes the result independently, then cross-checks the producer's `overall_status`; a contradictory label fails validation, so a producer FAIL/BLOCKED is never silently upgraded to PASS. For explicitly synthetic examples, this field describes internal consistency; final qualification remains BLOCKED. A failure has precedence over a blocker; a blocker has precedence over a pass.

Each applicable test family names its environment, command, minimum executed count and required test IDs. Individual test records determine collected, executed, passed, failed, skipped and blocked counts; supplied counters must agree. Executed means passed plus failed. Required tests must pass. An optional skip requires a policy-declared test ID and the same factual reason; it cannot stand in for a required test. Duplicate IDs, zero execution and unexplained skips are rejected. The tool validates the supplied inventory; it does not independently discover omitted project test cases.

Artifact kinds declare environment, required count and qualification command/test-family IDs. Each artifact records the matching qualification dependencies, result and evidence. It counts toward a required kind only when its bytes are verified and its declared qualification commands/families pass. `created_at` describes artifact creation, not later receipt collection; it cannot be after any direct qualification command or command underlying a qualification test family finished. Creation during a combined build/test command is allowed. These checks bind the claimed command/result to the artifact record and reject impossible ordering; they do not independently prove that a producer exercised those exact bytes. Each artifact and evidence record supplies a relative path, SHA-256, UTC timestamp, current source/profile identity and real/synthetic classification.

The validator reads and hashes each file under `--evidence-root`; absolute/parent/drive paths and resolved escapes are rejected. Duplicate resolved paths or device/inode identities within one collection cannot inflate its file count. A filesystem that supplies no stable nonzero file identity is BLOCKED for this reference implementation; no cross-platform fallback is claimed. Evidence may legitimately be referenced by several requirements, but reviewers must still judge whether it supports each claim. Concurrent hostile filesystem changes are outside this tool's guarantees.

### Input digests and coverage scope

Policy and receipt both contain `input_files` with exact IDs, kind (`lock`, `asset`, `configuration`, `dataset`), path and SHA-256. The sets and all values must match, and each actual file is hashed. `input_files_reason` documents the chosen scope, including a factual reason if the list is empty. These paths, artifact paths and log paths are relative to the **evidence root**; authored/generated/vendor/fixture roots remain metadata relative to the **repository root**. For example, a run bundle can contain `inputs/uv.lock`, `artifacts/application.whl` and `logs/tests.txt`. A producer may instead choose a common read-only parent containing both a verified cache and its receipt artifacts; the validator reads only declared files. It does not copy or download large inputs. If the declared input is only an asset manifest, the validator verifies that manifest's bytes, not every external asset named inside it; full asset validation needs its own passing command/test evidence.

`coverage_scopes` explicitly records applicability, environment, command, line/branch mode, included roots and exclusions. Receipt values must match the reviewed policy. Applicable coverage needs a passing command on the matching available environment and at least one qualified artifact of the declared report kind. A coverage scope cannot disappear just because no instrumented run happened. N/A still needs prior policy applicability and the same factual reason/evidence. This tool does not parse LCOV, Cobertura or other formats, calculate percentages, enforce numeric floors or prove instrumentation followed the declared scope. Those content checks belong to the declared coverage command/test family and its retained hashed report. This explicit limit prevents metadata-only validation being called full S09/S15 coverage qualification.

## N/A, exceptions and time

For commands, test families, coverage scopes, standards and tasks, N/A requires prior policy applicability set to false, a nonblank factual policy reason, the same reason in the receipt, and local evidence. It cannot be introduced only in the receipt. An excluded artifact kind is different: its policy says `applicable = false`, supplies the reason and sets `minimum_count = 0`; there is no separate receipt kind-status record when no artifact exists. Support that exclusion through the associated canonical requirement's evidence and policy review. An applicable requirement depending on the excluded kind still cannot pass. Required runtime capability absence belongs in BLOCKED, not N/A. The validator cannot establish whether a reason is factually true or whether an owner approved a scope reduction; review those facts before accepting the policy.

Exceptions have an ID, owner, requirement, reason and expiry date, plus declared alternative commands and test families. The corresponding receipt must provide evidence, and alternatives must pass on supported environments. **Exceptions never delete or downgrade an unresolved FAIL or BLOCKED result.** This intentionally small implementation does not implement a general waiver engine. Changing the policy to erase a known failure is not an acceptance procedure. A legitimate changed product scope needs an independently reviewed policy/profile change and an explicit record of the previous limitation.

UTC receipt, command, evidence and artifact times cannot be in the future; command start/end and receipt/evidence ordering are checked. Review dates cannot be in the future. Expired policy review blocks acceptance; an expired exception fails. Expiry dates are inclusive through that UTC date. The CLI uses the current machine clock and offers no time override; the internal Python test API injects a clock only for deterministic tests. Maintain a trustworthy clock in the real receipt-producing environment.

## Proposed adoption sequence

1. Review the manual's exact six tasks and S01–S15 applicability for the repository. Author a real `engineering.toml` with actual source roots, supported environments, commands, case inventories, artifacts and owner decisions; do not adopt the synthetic sample as a finished policy.
2. Pin and review a real shared profile. Keep the current source/profile inputs outside untrusted receipt data, supplied by a trusted checkout/CI context. The validator does not run Git or prove that a supplied policy file belongs to that checkout; the caller must bind those facts.
3. Implement a repository-specific receipt producer that executes existing/proposed checks on their supported hosts, records exact commands/runtime versions/results and saves logs/artifacts before hashing them. Preserve failed, skipped and blocked outcomes. This producer is not supplied here because each repository has different service and host contracts.
4. Run the read-only validator against that policy, receipt, evidence directory and independent current identities. Keep its JSON output and original files together. A host that has not run remains BLOCKED; an internally consistent fake receipt cannot substitute for trustworthy execution.
5. Test a deliberate failing change through the actual required-check path. That server-side enforcement, remote authenticity and any signing/provenance policy require their own evidence. No repository, workflow, branch rule, deployment or release was changed while producing this package.
