# Lint infrastructure report - rejection-rejector

Date: 2026-10-28 (Europe/Zurich). Author: lint-infrastructure subagent.
Reference: strmt7/FlitzZip (read-only), fetched via `gh api` from branch main.

## 1. What this deliverable contains

The complete FlitzZip-mirrored lint machinery for this repository: ruff
profile, PowerShell lint driver, CI workflow, hash-pinned linter
requirements, YAML and Markdown lint configs, local gate lanes, and tests.
Nothing was committed or pushed; nothing was remediated (the tree is
concurrently owned by other agents). The exact remediation plan is in
section 5.

## 2. Files created and modified

Created (all new):

- `.ruff.toml`
- `.yamllint`
- `.pymarkdown.json`
- `tools/lint.ps1`
- `.github/workflows/lint.yml`
- `.github/requirements/requirements-lint-windows.txt`
- `tests/release/test_lint_infra.py`

Modified (the only two existing files this task was allowed to touch):

- `tools/local_ci.py` - appended two ruff gate lanes (advisory, see section 7)
- `.gitignore` - added `.venv-lint/`

## 3. Line-length coherence with the DeepSource change

Verified: FlitzZip `.ruff.toml` (fetched 2026-10-28 from strmt7/FlitzZip via
the GitHub contents API) contains `line-length = 120`. The user's DeepSource
Python analyzer change (max_line_length = 120) is therefore coherent: both
sides of the portfolio enforce the same cap. This repository's `.ruff.toml`
copies the FlitzZip profile exactly (`line-length = 120`,
`target-version = "py313"`, select E/F/I/B/UP/SIM/PLW1510,
`[format] line-ending = "lf"`).

### 3.1 Documented profile exception (manual S02)

The engineering manual S02 table prescribes a 100-character target line
length for Python, which conflicts with the 120 convention. Resolved with
the manual's own SHOULD-exception mechanism. Exception text (also recorded
as a comment block at the top of `.ruff.toml`):

> Profile exception (documented, dated): 2026-10-28, owner: the repository
> maintainer. The engineering manual S02 table prescribes a 100-character
> target line length for Python; this profile deliberately uses
> line-length = 120 instead. Per the manual's own mechanism, SHOULD is the
> default unless a documented, dated exception explains why another
> implementation meets the same contract. Reason: 120 matches the
> established portfolio convention - verified in strmt7/FlitzZip
> (.ruff.toml `line-length = 120`) - and the maintainer's explicit
> standardization decision. Compensating control: ruff E501 enforces the
> hard cap at 120 (E is in the selected rule set) and the DeepSource Python
> analyzer is configured with max_line_length = 120; both are consistent, so
> line-length drift is still detected, only at 120 rather than 100. The rest
> of S02 (four-space indentation, double quotes) is unaffected: ruff format
> enforces double quotes and PEP 8 indentation unchanged.

## 4. Supply-chain pinning verification

- `requirements-lint-windows.txt` pins 16 packages with 396 sha256 hashes
  (all published artifacts per version, mirroring FlitzZip's
  pip-compile `--generate-hashes` format). Pinned top-level tools:
  ruff==0.17.2, pymarkdownlnt==0.9.41, yamllint==1.38.0 (the exact version
  found in FlitzZip's file), zizmor==1.31.1.
- Hash provenance is real: every wheel was downloaded
  (`pip download --only-binary=:all: --platform win_amd64 --python-version 3.14`)
  and hashed locally with sha256sum; every local digest was then
  cross-checked against the PyPI JSON digest for the same artifact (all 16
  matched). Overlapping artifacts match FlitzZip's recorded hashes
  byte-for-byte (for example application-file-scanner 49c211c6..., pathspec
  a00ce642...).
- Verified by real install: `python -m pip install --require-hashes
  --only-binary=:all: -r .github/requirements/requirements-lint-windows.txt`
  into `.venv-lint` (Python 3.14.9) succeeded (16 packages). Tools
  confirmed at pinned versions afterwards.
- actionlint 1.7.12 is pinned in `lint.yml` as a GitHub-release download with
  SHA256 verification (6E7241B51E6817EA6A047693D8E6FED13B31819C9A0DD6C5A726E1592D22F6E9,
  cross-checked against the upstream `actionlint_1.7.12_checksums.txt`).
  It cannot go in the hash-pinned requirements file because it is a Go
  binary with no PyPI artifact; the download-then-verify-SHA256 pattern is
  the same reviewed mechanism the PSScriptAnalyzer 1.25.0 nupkg uses.
- PSScriptAnalyzer 1.25.0 pin and hash are byte-identical to FlitzZip's.

## 5. Remediation plan (NOT applied - other agents own these files)

Snapshot: 2026-10-28 ~09:20, scope = training/*.py, tools/*.py,
tests/**/*.py (33 files). The tree is being concurrently extended, so
counts drift; re-run the commands below for live numbers.

### 5.1 ruff check: 48 findings (30 safe-autofix, 4 unsafe-fix, 14 manual)

Per rule (total, safe-autofixable):

- UP045 (21, 21): tools/resource_guard.py 21
- E501 (11, 0): training/corpus_banks_v2.py 7, tests/release/test_progress_reporting.py 1, tests/release/test_repository_integrity.py 1, tests/release/test_verify_package.py 1, training/scale_campaign.py 1
- UP017 (3, 3): tools/validate_receipt.py 2, tests/release/test_release_guard.py 1
- B905 (3, 0): training/build_corpus_v2.py 2, training/train_lora.py 1
- I001 (2, 2): tests/release/test_deepsource_inventory.py 1, training/train_lora.py 1
- F401 (2, 2): tools/check_engineering_policy.py 1, training/train_lora.py 1
- E741 (1, 0): tests/release/test_gpu_util_watchdog.py 1
- B017 (1, 0): tests/release/test_resource_guard.py 1
- UP035 (1, 1): tools/resource_guard.py 1
- UP037 (1, 1): tools/resource_guard.py 1
- SIM105 (1, 0): tools/validate_receipt.py 1
- B007 (1, 0): training/build_corpus_v2.py 1

Per file totals: tools/resource_guard.py 23, training/corpus_banks_v2.py 7,
tools/validate_receipt.py 3, training/build_corpus_v2.py 3,
training/train_lora.py 3, training/scale_campaign.py 1,
tools/check_engineering_policy.py 1, and one each in
tests/release/test_deepsource_inventory.py,
tests/release/test_gpu_util_watchdog.py,
tests/release/test_progress_reporting.py, tests/release/test_release_guard.py,
tests/release/test_repository_integrity.py, tests/release/test_resource_guard.py,
tests/release/test_verify_package.py.

The 3 unsafe-fix findings are B905 (zip without strict) and friends; they
need review before `--unsafe-fixes`. The 14 unfixable findings (E501,
E741, B017, SIM105, B007) need hand edits (line wrapping, variable renames,
contextlib.suppress, enumerate).

### 5.2 ruff format: 26 of 33 scope files would be reformatted

All of training/*.py except none; specifically:
training/build_corpus_v2.py, training/build_sft_dataset.py,
training/calibrate_zero_fp.py, training/corpus_banks_v2.py,
training/duty_cycle.py, training/evaluate_adapter.py, training/mine_enron.py,
training/probe_llm_limits.py, training/progress.py, training/scale_campaign.py,
training/train_lora.py, tools/check_engineering_policy.py,
tools/deepsource_inventory.py, tools/gpu_util_watchdog.py, tools/local_ci.py,
tools/resource_guard.py, tools/validate_receipt.py (newest names drift),
tests/release/test_engineering_policy.py, tests/release/test_monitor_gui.py,
tests/release/test_powershell_syntax.py, tests/release/test_progress_reporting.py,
tests/release/test_release_guard.py, tests/release/test_release_routing.py,
tests/release/test_repository_integrity.py, tests/release/test_resource_guard.py,
tests/release/test_verify_package.py. Already formatted:
tests/release/test_agent_skills.py, test_deepsource_inventory.py,
test_duty_cycle.py, test_gpu_util_watchdog.py, test_installer_tasks.py,
test_lint_infra.py, tools/json_input.py.

### 5.3 Exact remediation commands (run once, when the tree is free)

1. `.venv-lint/Scripts/ruff.exe check --fix training tools tests` (30 safe fixes)
2. `.venv-lint/Scripts/ruff.exe format training tools tests` (26 files)
3. Hand-fix the 14 unfixable + review the 4 unsafe-fix findings
   (per-rule list in section 5.1)
4. Flip `RUFF_LANES_ENFORCING = True` in tools/local_ci.py (remove the
   TODO comment) so the lanes gate instead of advise
5. yamllint: shorten the 18 over-long lines listed in section 6
6. pymarkdown: fix the 125 findings listed in section 6 (81 are MD034 bare
   URLs: wrap in angle brackets or convert to markdown links)
7. zizmor: 2 findings (section 6)

## 6. Current violations of the strict configs (kept strict on purpose)

- yamllint (config identical to FlitzZip's): 0 errors, 18 warnings, all
  `line-length` (max 140, warning level). Files:
  .github/workflows/ci.yml 2, enterprise-deep-verification.yml 3,
  fuzz.yml 3, mutation.yml 2, release.yml 5, reproducibility.yml 3.
- pymarkdown (config identical to FlitzZip's), 125 findings in 21 tracked
  markdown files: MD034 bare URL 81, MD022 14, MD032 13, MD031 7, MD012 6,
  MD040 3, MD024 1. Worst files: docs/MODEL.md 23, docs/SETUP.md 15,
  docs/ENTERPRISE_POLICY.md 11, docs/THREAT_MODEL.md 10, CHANGELOG.md 7.
- actionlint 1.7.12 over the 16 workflow files: clean (exit 0).
- zizmor 1.31.1 (offline, regular persona) over the 16 workflow files:
  2 findings (27 more suppressed by the default persona):
  medium - template-injection, .github/workflows/release.yml:313
  (steps.package.outputs.package_path expanded in a run block; auto-fixable);
  informational - artipacked, .github/workflows/release-tooling.yml:27
  (checkout without persist-credentials: false; auto-fixable).
  Exit-code contract (verified against zizmor docs): 0 clean, 1 internal
  error, 11-14 findings by worst severity (13 = medium here), so the stage
  fails on findings exactly like the other linters.

## 7. local_ci.py gate choice (stated explicitly)

Choice made: advisory-on-red, xfail-style (the preferred option). The two
appended lanes (`ruff check`, `ruff format --check` over the Python scope)
always run and print finding counts, but while `RUFF_LANES_ENFORCING = False`
a red lane prints `ADVISORY RED (xfail until format pass)` and does NOT fail
the gate. The constant, its comment, and a TODO referencing the pending
format pass sit next to the lanes (see section 5.3 step 4 for the flip).
Ruff resolution: `.venv-lint` (Scripts/ then bin/) before PATH.

## 8. Divergences from FlitzZip (with technical reason)

1. Python scope: FlitzZip's .github/openvas + mcp + tools -> RR's
   training/*.py, tools/*.py, tests/**/*.py (RR has no mcp/ or
   .github/openvas/; Python tooling lives in training/tools/tests).
   The changed-file regex `^(training|tools|tests)/.*\.py$` is deeper than
   the all-scan globs, exactly mirroring FlitzZip's own glob/regex
   asymmetry: changed files are linted at any depth, all-scans use the
   shallow globs above.
2. PowerShell scope extended to tools/*.ps1(m1), scripts/*.ps1(m1),
   windows/**/*.ps1(m1) (FlitzZip: tools only).
3. Markdown scope drops the third_party exclusion (RR has no third_party).
4. cmake-lint and clang-format stages dropped entirely (RR is Rust, not
   C++/CMake), together with the Select-FlitzZipCppLintFile helper. The
   scope-detection machinery (Resolve-LintToolPath, Invoke-LintCommand,
   Get-TrackedLintFile, Get-ChangedLintFile, Select-LintFile,
   Test-LintConfigChange, Test-LintToolchainChange, Get-LintTargetFile,
   Assert-PowerShellSyntax, Invoke-PowerShellLint) is verbatim FlitzZip.
5. Parameter `-CppMode` renamed `-LintMode` (same ValidateSet Changed/All/
   Off; there is no C++ stage to own that name; "Off" now skips only the
   Rust reminder stage).
6. Unittest hook mirrors FlitzZip's cocoindex hook with RR's target:
   when tools/deepsource_inventory.py or tests/release/test_deepsource_inventory.py
   change, `python -m unittest tests.release.test_deepsource_inventory`
   runs (FlitzZip invoked `py -3`; RR's tooling standard is `python`).
7. Added a print-only stage `lint step=rust-clippy delegated=tools/local_ci.py`
   (clippy is already gated by tools/local_ci.py and ci.yml; the stage
   records the delegation and must not duplicate the build).
8. Added workflow-actionlint and workflow-zizmor stages (manual S04 requires
   actionlint + zizmor or reviewed equivalents; not present in FlitzZip).
   actionlint is installed by a hash-pinned release download in lint.yml
   (Go binary, no PyPI artifact - reviewed-equivalent pinning, same
   mechanism as the PSScriptAnalyzer nupkg) and resolves via PATH;
   zizmor is hash-pinned from PyPI in the requirements file like ruff.
   actionlint 1.7.x takes `-color=false` (boolean flag), not `-color=never`.
9. requirements file: dropped clang-format, cmakelang and their transitive
   dependency six (C++/CMake tooling not used by RR); added zizmor==1.31.1;
   kept every FlitzZip pin version otherwise (ruff 0.17.2, pymarkdownlnt
   0.9.41, yamllint 1.38.0) and the exact hash-list breadth convention.
10. lint.yml env names FLITZZIP_* -> REJECTIONREJECTOR_* (repo identity);
    everything else (runner windows-2022, Python 3.14.8 via
    actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0,
    hash-pinned pip install, PSScriptAnalyzer 1.25.0 + SHA256, event-mode
    dispatch with HEAD~1 fallback, concurrency lint-${{ github.ref }},
    permissions contents: read, timeout-minutes 30) is structurally
    identical to FlitzZip's lint.yml.
11. `.ruff.toml` carries the dated S02 profile-exception comment block
    (section 3.1); the config body is byte-equivalent to FlitzZip's.

## 9. Verification evidence

- `pip install --require-hashes` from the requirements file into
  `.venv-lint` (Python 3.14.9): SUCCESS, 16 packages, tools report the
  pinned versions (ruff 0.17.2, yamllint 1.38.0, zizmor 1.31.1).
- `pwsh [Management.Automation.Language.Parser]::ParseFile(tools/lint.ps1)`:
  parse OK, 0 errors.
- `pwsh -File tools/lint.ps1 -LintMode Changed -BaseRef HEAD -HeadRef HEAD`
  (empty diff dry run): all six stage dispatches and the Rust reminder
  print behave exactly as wired; exit 0.
- `python -m unittest tests.release.test_lint_infra
  tests.release.test_powershell_syntax tests.release.test_deepsource_inventory`:
  35 tests, OK.
- ruff lanes exercised through tools/local_ci.py's run_ruff_lane:
  advisory prints and gate-neutral results confirmed.
- Snapshot caveat: sibling agents added tools/contract/,
  training/tests/, tools/validate_receipt.py and other files during this
  task; the counts above are a dated snapshot, and files outside the
  declared all-scan globs are still linted when they change (divergence 1).
