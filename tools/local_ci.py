#!/usr/bin/env python3
"""Run the EXACT repository gates locally, in one command.

Every edit must pass this BEFORE being committed or claimed green. The
script exists because a test edit once shipped without the CI clippy
flags and red-denied every CI lane: partial local gates are not gates.

Commands run here mirror .github/workflows exactly (clippy with
`-D warnings`, fmt --check, full test suite, Python release suites).
Inputs: optional `--fast` (skips the full Rust test suite). Output: the
combined verdict as text; exit code 0 only when EVERY gate is green.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GATES = [
    ("fmt", ["cargo", "fmt", "--all", "--check"]),
    (
        "clippy (exact CI flags)",
        ["cargo", "clippy", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"],
    ),
    # Advisory gate (RUSTSEC/OSV). The four ignores are the documented triage
    # in SECURITY.md / deny.toml / osv-scanner.toml: three Linux-only
    # accessibility-stack unmaintained notices (accesskit_unix -> atspi ->
    # zvariant 5 / zbus_names 4; unreachable in the shipped Windows binary; no
    # in-range patched version) plus the RUSTSEC-2023-0086 lexical-core/imap-2
    # record (SECURITY.md; removal criterion already met 2026-10-28 - the
    # imap-2 path left Cargo.lock - drop at the 2027-04-28 policy review).
    # Owner: strmt7; a11y review/removal date 2027-04-01 (mirrors
    # osv-scanner.toml). Any NEW advisory must block this gate until it is
    # fixed or triaged with reasons.
    (
        "cargo audit (advisories)",
        [
            "cargo",
            "audit",
            "--deny",
            "warnings",
            "--ignore",
            "RUSTSEC-2026-0370",
            "--ignore",
            "RUSTSEC-2026-0371",
            "--ignore",
            "RUSTSEC-2026-0372",
            "--ignore",
            "RUSTSEC-2023-0086",
        ],
    ),
]

# Transient network fetches must not flip the gate: per-gate retry budget.
GATE_ATTEMPTS = {"cargo audit (advisories)": 3}

# Ruff lint lanes are xfail-style until the pending ruff format pass: the
# Python tree predates the FlitzZip-mirrored .ruff.toml profile, so findings
# are expected today. The lanes run and print counts but must NOT flip the
# gate on red. TODO(pending format pass): after the one-time
# `ruff check --fix` + `ruff format` pass over training/, tools/ and tests/,
# flip RUFF_LANES_ENFORCING to True so red becomes red.
RUFF_LANES_ENFORCING = False


def find_ruff() -> str | None:
    """Resolve the pinned ruff executable.

    Inputs: none — prefers the repo-local .venv-lint (the hash-pinned
    install from .github/requirements/requirements-lint-windows.txt) and
    falls back to PATH. Output: executable path, or None when ruff is not
    installed.
    """
    for candidate in (
        ROOT / ".venv-lint" / "Scripts" / "ruff.exe",
        ROOT / ".venv-lint" / "bin" / "ruff",
    ):
        if candidate.exists():
            return str(candidate)
    return shutil.which("ruff")


def python_scope_file() -> list[str]:
    """List the Python lint scope.

    Inputs: none. Output: sorted repo-relative paths covering training/*.py,
    tools/*.py and tests/**/*.py (the scope owned by tools/lint.ps1).
    """
    files = list((ROOT / "training").glob("*.py"))
    files += list((ROOT / "tools").glob("*.py"))
    files += list((ROOT / "tests").rglob("*.py"))
    return sorted(str(p.relative_to(ROOT)).replace("\\", "/") for p in files)


def run_ruff_lane(name: str, args: list[str]) -> bool:
    """Run one ruff lane over the Python scope.

    Inputs: display name and ruff argv without the file list. Output: True
    when green; while RUFF_LANES_ENFORCING is False a red lane prints its
    finding count and still reports green (xfail-style, see the pending
    format pass note above), so the gate never fails on the known
    unformatted tree.
    """
    ruff = find_ruff()
    if ruff is None:
        print(
            f"== {name}: WARNING - ruff not found; create .venv-lint "
            "(hash-pinned install from .github/requirements/"
            "requirements-lint-windows.txt)"
        )
        return not RUFF_LANES_ENFORCING
    files = python_scope_file()
    proc = subprocess.run([ruff, *args, *files], cwd=ROOT, capture_output=True, text=True, check=False)
    output = proc.stdout + proc.stderr
    if proc.returncode == 0:
        print(f"== {name}: GREEN")
        return True
    count = sum(1 for line in output.splitlines() if re.search(r"^\S+:\d+:\d+: ", line))
    if count == 0:
        count = sum(1 for line in output.splitlines() if line.startswith("Would reformat: "))
    verdict = "RED" if RUFF_LANES_ENFORCING else "ADVISORY RED (xfail until format pass)"
    print(f"== {name}: {verdict} - {count} finding(s)")
    return not RUFF_LANES_ENFORCING


def run(name: str, cmd: list[str], env: dict | None = None, attempts: int = 1) -> bool:
    """Run one gate. Inputs: display name, argv, optional env, and retry
    attempts (for network-dependent steps whose transient fetch failures must
    not flip the gate). Output: True when green on any attempt.
    """
    print(f"== {name}: {' '.join(cmd)}")
    ok = False
    for attempt in range(1, attempts + 1):
        proc = subprocess.run(cmd, cwd=ROOT, env=env, check=False)
        ok = proc.returncode == 0
        if ok:
            break
        if attempt < attempts:
            print(f"== {name}: transient failure (exit {proc.returncode}); retrying")
    print(f"== {name}: {'GREEN' if ok else f'RED (exit {proc.returncode})'}")
    return ok


def check_credential_store() -> None:
    """Warn when leaked test credentials are filling the Windows credential store.

    Why: integration tests mint one OS credential per temporary workspace, and
    any test that panics before its cleanup guard runs leaks that entry. The
    Windows store has a quota; once full, every later credential write fails
    (error 8) and unrelated OS-anchor tests go red for an environmental reason.

    Inputs: none. Output: none — prints a warning when the count is high; it
    never deletes credentials (a real vault key is indistinguishable from a
    leaked test key, so cleanup stays a deliberate operator action).
    """
    if sys.platform != "win32":
        return
    try:
        cmdkey = shutil.which("cmdkey")
        if cmdkey is None:
            return
        out = subprocess.run([cmdkey, "/list"], capture_output=True, text=True, check=False).stdout
    except OSError:
        return
    n = sum(1 for line in out.splitlines() if "rejection-rejector" in line.lower())
    if n >= 100:
        print(
            f"== credential store: WARNING — {n} 'rejection-rejector' entries. "
            "Leaked test keys can fill the Windows quota and fail unrelated tests. "
            "Purge stale ones with: cmdkey /delete:<target> (only rejection-rejector targets)."
        )
    else:
        print(f"== credential store: {n} 'rejection-rejector' entries (ok)")


def main(argv: list[str] | None = None) -> int:
    """Entry point. Input: optional argv. Output: 0 when all gates green."""
    parser = argparse.ArgumentParser(description="Run the exact CI gates locally")
    parser.add_argument("--fast", action="store_true", help="Skip the full Rust test suite")
    args = parser.parse_args(argv)

    check_credential_store()
    results = [run(name, cmd, attempts=GATE_ATTEMPTS.get(name, 1)) for name, cmd in GATES]
    # Ruff lint lanes (see RUFF_LANES_ENFORCING): xfail-style GATES entries —
    # counts print on red but the gate is not flipped until the pending ruff
    # format pass lands and the constant is set to True.
    results.append(run_ruff_lane("ruff check", ["check", "--output-format", "concise"]))
    results.append(run_ruff_lane("ruff format --check", ["format", "--check", "--output-format", "concise"]))
    # Rustdoc gate: deny warnings so doc-link regressions (e.g. public docs
    # linking a private item) fail here, not only in the deep-verification
    # workflow. Matches the CI command (RUSTDOCFLAGS=-D warnings cargo doc).
    import os

    results.append(
        run(
            "rustdoc (warnings are errors)",
            ["cargo", "doc", "--locked", "--all-features", "--no-deps"],
            env={**os.environ, "RUSTDOCFLAGS": "-D warnings"},
        )
    )
    if not args.fast:
        results.append(run("cargo test (full)", ["cargo", "test", "--locked"]))
    results.append(
        run(
            "python release suites",
            [sys.executable, "-m", "unittest", "discover", "-s", "tests/release", "-p", "test_*.py"],
        )
    )
    if all(results):
        if args.fast:
            print(
                "ALL GATES GREEN (FAST MODE: `cargo test` SKIPPED — "
                "run `python tools/local_ci.py` without --fast before committing)"
            )
        else:
            print("ALL GATES GREEN")
        return 0
    print(f"GATES RED: {results.count(False)} failing")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
