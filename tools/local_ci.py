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
    # Advisory gate (RUSTSEC/OSV). The three ignores are the documented triage
    # in osv-scanner.toml: Linux-only accessibility stack (accesskit_unix ->
    # atspi -> zvariant 5 / zbus_names 4), unreachable in the shipped Windows
    # binary, "unmaintained" notices with no in-range patched version. Any NEW
    # advisory must block this gate until it is fixed or triaged with reasons.
    (
        "cargo audit (advisories)",
        [
            "cargo", "audit", "--deny", "warnings",
            "--ignore", "RUSTSEC-2026-0370",
            "--ignore", "RUSTSEC-2026-0371",
            "--ignore", "RUSTSEC-2026-0372", "--ignore", "RUSTSEC-2023-0086",
        ],
    ),
]


def run(name: str, cmd: list[str], env: dict | None = None) -> bool:
    """Run one gate. Input: display name + argv + optional env. Output: True when green."""
    print(f"== {name}: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=ROOT, env=env, check=False)
    ok = proc.returncode == 0
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
    results = [run(name, cmd) for name, cmd in GATES]
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
            [sys.executable, "-m", "unittest", "discover",
             "-s", "tests/release", "-p", "test_*.py"],
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
