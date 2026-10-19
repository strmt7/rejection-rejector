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
]


def run(name: str, cmd: list[str]) -> bool:
    """Run one gate. Input: display name + argv. Output: True when green."""
    print(f"== {name}: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=ROOT)
    ok = proc.returncode == 0
    print(f"== {name}: {'GREEN' if ok else f'RED (exit {proc.returncode})'}")
    return ok


def main(argv: list[str] | None = None) -> int:
    """Entry point. Input: optional argv. Output: 0 when all gates green."""
    parser = argparse.ArgumentParser(description="Run the exact CI gates locally")
    parser.add_argument("--fast", action="store_true", help="Skip the full Rust test suite")
    args = parser.parse_args(argv)

    results = [run(name, cmd) for name, cmd in GATES]
    if not args.fast:
        results.append(run("cargo test (full)", ["cargo", "test", "--locked"]))
    results.append(
        run(
            "python release suites",
            [sys.executable, "-m", "unittest", "discover", "-s", "tests/release", "-p", "test_*.py"],
        )
    )
    if all(results):
        print("ALL GATES GREEN")
        return 0
    print(f"GATES RED: {results.count(False)} failing")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
