#!/usr/bin/env python3
"""Live progress probing for long-running training and evaluation jobs.

Every long job writes a small JSON heartbeat (atomically, so a probe never
reads a torn file) and this tool probes it on demand or in watch mode. A
heartbeat older than the staleness bound is reported as stalled: probes must
distinguish "slow" from "dead".

Host-agnostic: all paths are arguments; defaults resolve relative to this
file. No network, no machine specifics.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

# A heartbeat older than this many seconds is reported as stalled.
STALE_AFTER_SECONDS = 120.0


def write_progress(path: Path, record: dict) -> None:
    """Atomically write a progress heartbeat.

    Inputs: `path` — heartbeat file; `record` — progress fields (job, step,
    total_steps, loss, status, updated_at). Output: none; the file is written
    via a temporary sibling and renamed so readers never see partial JSON.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def summarize(record: dict, now: float, stale_after: float = STALE_AFTER_SECONDS) -> dict:
    """Compute the probe summary from one heartbeat.

    Inputs: `record` — a parsed heartbeat; `now` — current unix seconds;
    `stale_after` — staleness bound in seconds. Output: dict with `percent`,
    `rate_per_second`, `eta_seconds`, `stalled`, and `age_seconds`. Steps per
    second is derived from the record's `elapsed_seconds`; ETA is total minus
    step at that rate, or None when the rate cannot be computed. `stalled` is
    true whenever the heartbeat is older than the bound or the job reports a
    terminal status other than complete.
    """
    step = float(record.get("step", 0))
    total = float(record.get("total_steps", 0))
    elapsed = float(record.get("elapsed_seconds", 0.0))
    updated = float(record.get("updated_at_unix", 0.0))
    age = max(0.0, now - updated) if updated else float("inf")
    rate = step / elapsed if elapsed > 0 and step > 0 else None
    eta = ((total - step) / rate) if rate and total > step else None
    status = str(record.get("status", "unknown"))
    return {
        "percent": (100.0 * step / total) if total > 0 else 0.0,
        "rate_per_second": rate,
        "eta_seconds": eta,
        "age_seconds": age,
        "stalled": age > stale_after or (status not in ("running", "complete") and age > stale_after),
    }


def load_heartbeat(path: Path) -> dict:
    """Load one heartbeat file.

    Inputs: `path` — heartbeat JSON. Output: the parsed record; a missing or
    malformed file is an error so probes fail closed instead of reporting
    invented progress.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("probe", "watch"))
    parser.add_argument("path", type=Path, help="heartbeat file written by the job")
    parser.add_argument("--interval", type=float, default=10.0, help="watch polling interval in seconds")
    parser.add_argument("--stale-after", type=float, default=STALE_AFTER_SECONDS)
    args = parser.parse_args()

    def probe_once() -> dict:
        record = load_heartbeat(args.path)
        summary = summarize(record, time.time(), args.stale_after)
        view = {**record, **summary}
        print(json.dumps(view, indent=2))
        return view

    if args.command == "probe":
        probe_once()
        return 0
    while True:
        try:
            probe_once()
        except FileNotFoundError:
            print(json.dumps({"status": "waiting-for-heartbeat"}))
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
