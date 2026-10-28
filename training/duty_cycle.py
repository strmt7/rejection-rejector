"""Duty-cycle GPU pacing for local training (software-only utilization cap).

Caps the TIME-AVERAGED GPU utilization of a training run by inserting
host-side sleeps between steps. This is the only workload-independent way
to cap utilization without touching drivers, fan curves, clocks or power
limits (which this project never does): PyTorch core guidance is that
utilization can only be reduced by reducing the workload
(https://discuss.pytorch.org/t/is-there-a-way-to-specify-gpu-duty-cycle-while-training/118041).
The sleep formula follows the validated duty-cycle controller in
godweiyang/GrabGPU: ``off = on * (1/u - 1)``, recomputed from the measured
on-time every cycle so the running average tracks the target even when
step times jitter (thermal throttling, PCIe contention).

Everything here is pure host-side timing: no hardware registers, no
driver calls, no fan or clock control. Fail-closed everywhere: an
unreadable or invalid control file keeps the last valid target and never
raises into the training step.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from pathlib import Path

# Bounds: below 20% the inter-step sleeps dominate so heavily that run
# time explodes while fan-noise gains flatten; 100% disables pacing.
MIN_TARGET_PCT = 20.0
MAX_TARGET_PCT = 100.0
# Longest single sleep before yielding back (keeps heartbeats fresh and
# the stall watchdog quiet under deep throttling).
MAX_SLEEP_SLICE_S = 20.0
CONTROL_FILENAME = "duty.json"


def validate_target_pct(value: object) -> float:
    """Validate a utilization target.

    Input: any object (CLI strings, ints, floats).
    Output: float percentage clamped-free and strictly within
    [MIN_TARGET_PCT, MAX_TARGET_PCT].
    Raises: ValueError for non-numeric input or out-of-range values.
    """
    try:
        pct = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"utilization target must be numeric, got {value!r}") from exc
    if not MIN_TARGET_PCT <= pct <= MAX_TARGET_PCT:
        raise ValueError(f"utilization target must be within [{MIN_TARGET_PCT}, {MAX_TARGET_PCT}], got {pct}")
    return pct


def sleep_seconds(step_seconds: float, target_pct: float) -> float:
    """Compute the off-time for one duty cycle.

    Input: measured on-time of the step in seconds (> 0), target
    utilization percentage.
    Output: seconds to sleep so the running average matches the target
    (0.0 at 100%; ``step_seconds * (100 - t) / t`` otherwise; never
    negative). Fail-safe: an invalid/corrupt target yields 0.0 (uncapped)
    rather than raising — a bad ceiling must never disturb the run.
    """
    try:
        target = validate_target_pct(target_pct)
    except ValueError:
        return 0.0
    if step_seconds <= 0.0:
        return 0.0
    if target >= MAX_TARGET_PCT:
        return 0.0
    off = step_seconds * (MAX_TARGET_PCT - target) / target
    return max(0.0, off)


def control_path_for(progress_path: Path) -> Path:
    """Derive the live control file path from the progress file path.

    Input: path to the trainer's progress.json.
    Output: the sibling ``duty.json`` control-file path.
    """
    return Path(progress_path).parent / CONTROL_FILENAME


def read_target(path: Path) -> float | None:
    """Read the live utilization target (fail-closed).

    Input: control-file path (``{"target_pct": <float>}``).
    Output: the validated target, or None when the file is missing,
    unreadable, malformed or out of range (caller keeps its last value).
    Never raises.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None
        return validate_target_pct(data.get("target_pct"))
    except Exception:
        return None


def read_stop_flag(path: Path) -> bool:
    """Read the cooperative-stop flag from the control file.

    Input: control-file path (``{"stop": true}`` asks the trainer to end
    cleanly; any other value or state means "keep going").
    Output: True only for an explicit ``{"stop": true}``. Never raises;
    a corrupt file means no stop (the ceiling path stays fail-closed).
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return bool(isinstance(data, dict) and data.get("stop") is True)
    except Exception:
        return False


def write_stop_flag(path: Path) -> None:
    """Atomically request a cooperative training stop.

    Input: control-file path.
    Output: the control file rewritten as ``{"stop": true}`` via a tmp +
    rename so the trainer never observes a partial write. Preserves the
    current target when present so the stop takes effect at the current
    ceiling rather than an unthrottled step.
    """
    path = Path(path)
    target = read_target(path) or MAX_TARGET_PCT
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"target_pct": target, "stop": True}), encoding="utf-8")
    os.replace(tmp, path)


def write_target(path: Path, target_pct: float) -> None:
    """Atomically write the live utilization target.

    Input: control-file path, validated target percentage.
    Output: file replaced atomically (tmp + os.replace) so the trainer
    never observes a partial write. Raises ValueError for invalid input.
    """
    target = validate_target_pct(target_pct)
    path = Path(path)
    payload = json.dumps({"target_pct": target})
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, path)


def paced_sleep(
    total_seconds: float,
    touch: Callable[[], None] | None = None,
    slice_s: float = MAX_SLEEP_SLICE_S,
    sleep_fn: Callable[[float], None] | None = None,
) -> float:
    """Sleep in bounded slices, optionally touching a heartbeat between.

    Input: total seconds to sleep (<= 0 returns immediately), an optional
    zero-argument ``touch`` callback invoked after every slice (heartbeat
    refresh), the per-slice ceiling, and an injectable ``sleep_fn`` for
    tests (defaults to ``time.sleep``).
    Output: the seconds actually slept (0.0 when input <= 0).
    """
    if total_seconds <= 0.0:
        return 0.0
    sleep = sleep_fn or time.sleep
    slept = 0.0
    remaining = float(total_seconds)
    step = max(1.0, float(slice_s))
    while remaining > 1e-9:
        chunk = min(step, remaining)
        sleep(chunk)
        slept += chunk
        remaining -= chunk
        if touch is not None:
            touch()
    return slept
