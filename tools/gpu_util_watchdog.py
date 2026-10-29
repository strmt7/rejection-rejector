"""GPU utilization watchdog: hard enforcement of the operator's ceiling.

Samples the Windows GPU Engine utilization counters (the SAME PDH-backed
data Task Manager's GPU page displays) for a target process and enforces
a hard maximum GPU utilization percentage:

- every sample above the ceiling lowers the live duty target in the
  trainer's control file (the trainer reads it every micro-batch), and
- if the ceiling is still exceeded at the minimum duty target, the
  watchdog requests a COOPERATIVE stop (control-file flag; the trainer
  ends cleanly with checkpoints intact — no signals, no kills).

Fail-closed by construction: losing the counter stream, the control file
or the sampler child also results in a cooperative stop request, because
an unobserved workload must never run unbounded under this policy.

Inputs: `--pid` target process id (its GPU Engine instances are matched
the way Task Manager attributes them), `--duty` path to the trainer's
`duty.json`, `--ceiling` maximum allowed percentage (default 50),
`--log` JSONL evidence path. Output: JSONL samples + actions; exit 0 on
clean stop, 3 when enforcement had to stop the run.

The watchdog is pure host-side observation and control-file writes: no
driver, fan, clock or power interaction of any kind.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "training"))

import duty_cycle  # noqa: E402

# PowerShell sampler: one long-lived process streaming utilization
# samples from PDH "\GPU Engine(*)\Utilization Percentage" — the same
# performance data Task Manager's GPU page displays (the WMI shim
# Win32_PerfFormattedData_GPUEngine returns zero rows on current
# Windows 11 builds; verified empirically). Each line is "max,sum" over
# the target's engine instances: `max` is what a per-engine meter shows,
# `sum` is the total across engines (kept for evidence).
SAMPLER_SCRIPT = """
param([int]$TargetPid, [string]$MatchName)
$pids = @()
if ($TargetPid -gt 0) { $pids += $TargetPid }
if ($MatchName -ne "") {
    foreach ($nm in ($MatchName -split ",")) {
        $pids += Get-Process -Name ("*" + $nm.Trim() + "*") -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Id }
    }
}
$pids = @($pids | Select-Object -Unique)
$counter = "\\GPU Engine(*)\\Utilization Percentage"
while ($true) {
    try {
        $sample = Get-Counter -Counter $counter -MaxSamples 1 -ErrorAction Stop
        $sum = 0
        $max = 0
        foreach ($c in $sample.CounterSamples) {
            foreach ($p in $pids) {
                if ($c.Path -like ("*pid_" + $p + "*")) {
                    $v = [int]$c.CookedValue
                    $sum += $v
                    if ($v -gt $max) { $max = $v }
                }
            }
        }
        Write-Output ("" + $max + "," + $sum)
    } catch {
        Write-Output "-1,-1"
    }
    Start-Sleep -Milliseconds 200
}
"""


def clamp_target(current: float, _ceiling_pct: float) -> float:
    """Next duty target after one breach.

    Input: current duty target percentage and the enforced ceiling. The
    ceiling argument is intentionally unused (underscore-prefixed): the
    clamp is a fixed 10 pp notch toward the floor regardless of where the
    ceiling sits; the argument documents the call-site policy.
    Output: the target lowered by one notch (10 pp) toward the pacing
    floor (MIN_TARGET_PCT), or the floor itself when already low.
    """
    return max(duty_cycle.MIN_TARGET_PCT, current - 10.0)


def should_stop(target_pct: float, breaches_at_floor: int, threshold: int = 1) -> bool:
    """Decide whether to request a cooperative stop.

    Input: current duty target, breach count while at the floor, and the
    breach threshold.
    Output: True when the ceiling is exceeded at the minimum duty target
    — the operator's rule is absolute (never exceed the ceiling), so ANY
    breach at the floor stops the workload immediately; training pauses
    are always preferable to a ceiling violation.
    """
    return target_pct <= duty_cycle.MIN_TARGET_PCT and breaches_at_floor >= threshold


class Watchdog:
    """Enforcement loop over the sampler stream (see module docstring)."""

    def __init__(
        self,
        pid: int,
        duty_path: Path,
        ceiling: float,
        log_path: Path,
        match_name: str = "",
    ):
        """Configure one watchdog instance.

        Inputs: `pid` -- target process id (0 = none); `duty_path` -- trainer
        duty.json path; `ceiling` -- max GPU utilization percent; `log_path` --
        JSONL evidence path; `match_name` -- extra process-name substring to
        watch. Output: none.
        """
        self.pid = pid
        self.match_name = match_name
        self.duty_path = duty_path
        self.ceiling = ceiling
        self.log_path = log_path
        self._breaches_at_floor = 0
        self._lock = threading.Lock()

    def _log(self, event: dict) -> None:
        """Append one JSONL evidence event with a timestamp. Output: none."""
        event = {"ts": round(time.time(), 3), **event}
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")

    def handle_sample(self, sample_pct: int, sum_pct: int | None = None) -> bool:
        """Process one utilization sample.

        Input: per-engine max utilization percentage for the target
        process (the meter-visible value) and optionally the cross-engine
        sum (evidence only).
        Output: True to keep running, False when the watchdog has
        requested a cooperative stop.
        """
        with self._lock:
            current = duty_cycle.read_target(self.duty_path) or duty_cycle.MAX_TARGET_PCT
            if sample_pct <= self.ceiling:
                if sample_pct > 0:
                    self._breaches_at_floor = 0
                self._log(
                    {
                        "event": "sample",
                        "gpu_pct": sample_pct,
                        "gpu_sum_pct": sum_pct,
                        "duty": current,
                    }
                )
                return True

            # Breach: lower the live ceiling immediately (the trainer
            # reads it every micro-batch) and record evidence.
            new_target = clamp_target(current, self.ceiling)
            try:
                duty_cycle.write_target(self.duty_path, new_target)
            except Exception as exc:
                self._log({"event": "control_write_failed", "error": repr(exc)})
                duty_cycle.write_stop_flag(self.duty_path)
                return False
            self._log(
                {
                    "event": "breach",
                    "gpu_pct": sample_pct,
                    "duty_before": current,
                    "duty_after": new_target,
                }
            )
            if new_target <= duty_cycle.MIN_TARGET_PCT:
                self._breaches_at_floor += 1
                if should_stop(new_target, self._breaches_at_floor):
                    self._log({"event": "cooperative_stop_requested"})
                    duty_cycle.write_stop_flag(self.duty_path)
                    return False
            return True

    def _stream_loop(self, cmd: list[str]) -> int:
        """Consume a sampler's CSV stream until stop or death.

        Input: sampler argv emitting "max,sum" lines (" -1,-1" on error).
        Output: process exit code (0 clean, 3 enforcement stop, 4 sampler
        failure -> fail-closed stop).
        """
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            if proc.stdout is None:
                raise RuntimeError("watchdog subprocess produced no stdout")
            bad_samples = 0
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                if len(parts) != 2 or not parts[0].lstrip("-").isdigit():
                    continue
                max_pct, sum_pct = int(parts[0]), int(parts[1])
                if max_pct < 0:
                    # Transient sampler failure: tolerate briefly, fail closed
                    # when the stream goes dark (an unobserved workload must
                    # never run unbounded).
                    bad_samples += 1
                    self._log({"event": "sample_error", "consecutive": bad_samples})
                    if bad_samples >= 5:
                        self._log({"event": "sampler_dark_fail_closed"})
                        duty_cycle.write_stop_flag(self.duty_path)
                        return 4
                    continue
                bad_samples = 0
                if not self.handle_sample(max_pct, sum_pct):
                    return 3
            # Stream ended unexpectedly: fail closed.
            self._log({"event": "sampler_died"})
            duty_cycle.write_stop_flag(self.duty_path)
            return 4
        finally:
            proc.terminate()

    def run(self) -> int:
        """Run the sampler loop until stop or sampler death.

        Input: none (state in the constructor).
        Output: process exit code (see _stream_loop).
        """
        shell = _find_powershell()
        if shell is not None:
            with tempfile_script() as script_path:
                return self._stream_loop(
                    [
                        shell,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(script_path),
                        "-TargetPid",
                        str(self.pid),
                        "-MatchName",
                        self.match_name,
                    ]
                )
        # No PowerShell (bare-metal Linux): a native sysfs / nvidia-smi sampler
        # keeps enforcement host-agnostic instead of depending on Windows.
        self._log({"event": "powershell_unavailable_linux_fallback"})
        return self._stream_loop(["sh", "-c", LINUX_SAMPLER])


def _find_powershell() -> str | None:
    """Locate a PowerShell executable across Windows, WSL, and pwsh installs.

    Input: none. Output: an executable path, or None when no PowerShell is
    reachable (bare-metal Linux) so the caller can fall back to a native
    sampler. Tries PATH names first, then WSL/Windows interop locations that a
    detached launch may not inherit via PATH.
    """
    import os
    import shutil

    for name in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
        found = shutil.which(name)
        if found:
            return found
    for candidate in (
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    ):
        if os.path.exists(candidate):
            return candidate
    return None


# Native Linux GPU-busy sampler for hosts without PowerShell. Emits the same
# "max,sum" CSV contract (with "-1,-1" on read failure) at ~5 Hz so the stream
# loop is identical to the PowerShell path. Reads AMD sysfs first, then
# nvidia-smi, so it is host-agnostic across common Linux GPU stacks.
LINUX_SAMPLER = """\
while :; do
    busy=-1
    for f in /sys/class/drm/card*/device/gpu_busy_percent; do
        [ -r "$f" ] || continue
        busy=$(tr -dc '0-9' < "$f" 2>/dev/null)
        [ -n "$busy" ] && break
    done
    if [ -z "$busy" ] || [ "$busy" = "-1" ]; then
        busy=$(nvidia-smi --query-gpu=utilization.gpu --format=csv,noheader,nounits 2>/dev/null |
            head -1 | tr -dc '0-9')
    fi
    if [ -n "$busy" ] && [ "$busy" != "-1" ]; then echo "$busy,$busy"; else echo "-1,-1"; fi
    sleep 0.2
done
"""


class tempfile_script:
    """Context manager writing the sampler script to a temp file."""

    def __init__(self) -> None:
        """Own a placeholder for the temp directory created on entry."""
        self._dir: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> Path:
        """Write the sampler script to a fresh temp file and return its path."""
        self._dir = tempfile.TemporaryDirectory(prefix="rr_gpu_watch_")
        path = Path(self._dir.name) / "sampler.ps1"
        path.write_text(SAMPLER_SCRIPT, encoding="utf-8")
        return path

    def __exit__(self, *exc) -> None:
        """Remove the temp directory. Inputs/Output: none."""
        if self._dir is not None:
            self._dir.cleanup()


def main(argv: list[str] | None = None) -> int:
    """Entry point. Input: optional argv. Output: exit code (see run)."""
    parser = argparse.ArgumentParser(description="GPU utilization ceiling watchdog")
    parser.add_argument("--pid", type=int, default=0, help="Target process id (0 = none)")
    parser.add_argument(
        "--match-name",
        default="",
        help="Additional process-name substring to watch (e.g. 'vmmem' for "
        "WSL GPU workloads, whose engine activity is attributed to the "
        "VM host process)",
    )
    parser.add_argument("--duty", type=Path, required=True, help="Trainer duty.json path")
    parser.add_argument(
        "--ceiling",
        type=float,
        default=50.0,
        help="Max GPU utilization percent (hard operator ceiling)",
    )
    parser.add_argument("--log", type=Path, required=True, help="JSONL evidence path")
    args = parser.parse_args(argv)
    watchdog = Watchdog(args.pid, args.duty, args.ceiling, args.log, match_name=args.match_name)
    return watchdog.run()


if __name__ == "__main__":
    raise SystemExit(main())
