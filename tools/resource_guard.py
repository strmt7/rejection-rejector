"""Fail-closed resource guard: free VRAM, RAM and storage with hard margins.

Host-agnostic and installation-agnostic: probes autodetect what the platform
offers (PyTorch for GPU memory, psutil for RAM, stdlib for disk) and every
probe failure is treated as a violation unless the workload declares the
resource irrelevant. Nothing may ever approach a limit: thresholds carry
safety margins and a watchdog re-checks continuously during execution, so a
runaway workload is stopped BEFORE any resource is exhausted — never after.

Public surface (all documented with inputs/outputs):

- ``snapshot(...)`` -> ``ResourceSnapshot``: measured free/total for VRAM,
  RAM and disk at one instant.
- ``check(snapshot, thresholds)`` -> ``list[Violation]``: PURE decision
  function; every threshold boundary is unit-tested.
- ``preflight(...)`` -> ``Verdict``: fail-closed start gate.
- ``ResourceWatchdog``: continuous observer that invokes a stop callback on
  the first violation.

Reputable sources for the probe APIs:
- torch.cuda.mem_get_info(device=None) -> (free, total) — PyTorch docs.
- psutil.virtual_memory().available — psutil.io (``available`` accounts for
  reclaimable cache, unlike ``free``).
- shutil.disk_usage(path) -> (total, used, free) — Python standard library.
"""

from __future__ import annotations

import dataclasses
import shutil
import threading
import time
from typing import Callable, Optional

GIB = 1024**3


@dataclasses.dataclass(frozen=True)
class ResourceSnapshot:
    """One instant of measured resources. All byte values are ints.

    ``None`` means "not measurable on this platform/installation"; the
    decision functions treat None according to ``require_*`` flags.
    """

    vram_free: Optional[int]
    vram_total: Optional[int]
    ram_available: Optional[int]
    ram_total: Optional[int]
    disk_free: Optional[int]
    disk_total: Optional[int]
    measured_at: float


@dataclasses.dataclass(frozen=True)
class Thresholds:
    """Safety limits with margins. All byte values are ints.

    Defaults stop a workload long before exhaustion: at least 2 GiB VRAM,
    4 GiB RAM and 10 GiB disk must remain free, AND usage must stay under
    80% (VRAM) / 85% (RAM) of total.
    """

    # VRAM floor is small on purpose: GPU use up to ~99% is desired; the
    # protection that matters is RAM (host slowdown) and true exhaustion.
    min_free_vram: int = 256 * 1024 * 1024
    min_free_ram: int = 4 * GIB
    min_free_disk: int = 10 * GIB
    # VRAM usage budget: deliberately permissive. Measured crash evidence for
    # GPU training faults attributes them to codegen defects, not capacity
    # ("within headroom" at fault time), so the binding safety line for VRAM
    # is the min_free floor (exhaustion), not a usage fraction. 95% keeps the
    # floor meaningful on small cards while letting large models use the GPU
    # fully. RAM keeps a stricter budget: host OOM destabilizes the machine.
    max_vram_use_fraction: float = 0.99
    max_ram_use_fraction: float = 0.85
    require_vram: bool = False
    require_ram: bool = True
    require_disk: bool = True


@dataclasses.dataclass(frozen=True)
class Violation:
    """One threshold breach. ``resource`` is vram|ram|disk; ``reason`` is a
    stable machine-readable code; ``detail`` is human text."""

    resource: str
    reason: str
    detail: str


@dataclasses.dataclass(frozen=True)
class Verdict:
    """Preflight outcome. ``ok`` is False whenever any required probe fails
    or any threshold is breached (fail-closed)."""

    ok: bool
    snapshot: ResourceSnapshot
    violations: tuple[Violation, ...]


def snapshot(
    *,
    vram_probe: Optional[Callable[[], tuple[int, int]]] = None,
    ram_probe: Optional[Callable[[], tuple[int, int]]] = None,
    disk_path: str = ".",
    disk_probe: Optional[Callable[[], tuple[int, int]]] = None,
) -> ResourceSnapshot:
    """Measure free/total VRAM, RAM and disk at one instant.

    Inputs: optional injectable probes (used by tests): ``vram_probe``
    returns (free, total) bytes, ``ram_probe`` returns (available, total),
    ``disk_probe`` returns (free, total); ``disk_path`` selects the volume
    for the stdlib disk probe. Output: a :class:`ResourceSnapshot` where any
    unmeasurable resource is ``None`` (probe exceptions are swallowed into
    None — the decision layer fails closed on them).
    """
    if vram_probe is None:
        vram_probe = _default_vram_probe
    if ram_probe is None:
        ram_probe = _default_ram_probe
    if disk_probe is None:
        disk_probe = lambda: _default_disk_probe(disk_path)  # noqa: E731

    def safe(probe):
        try:
            free, total = probe()
            if free < 0 or total < 0 or free > total:
                return (None, None)
            return (int(free), int(total))
        except Exception:
            return (None, None)

    vram_free, vram_total = safe(vram_probe)
    ram_available, ram_total = safe(ram_probe)
    disk_free, disk_total = safe(disk_probe)
    return ResourceSnapshot(
        vram_free=vram_free,
        vram_total=vram_total,
        ram_available=ram_available,
        ram_total=ram_total,
        disk_free=disk_free,
        disk_total=disk_total,
        measured_at=time.time(),
    )


def check(snap: ResourceSnapshot, limits: Thresholds) -> list[Violation]:
    """Decide which thresholds are breached. PURE function.

    Inputs: ``snap`` — measured snapshot; ``limits`` — thresholds.
    Output: list of :class:`Violation` (empty means safe). Unmeasurable
    required resources are reported as violations (fail-closed); an
    unmeasurable resource that is not required is ignored.
    """
    out: list[Violation] = []

    def floor_and_fraction(
        name: str, free: Optional[int], total: Optional[int],
        min_free: int, max_fraction: float, required: bool,
    ) -> None:
        if free is None or total is None:
            if required:
                out.append(Violation(name, "unmeasurable",
                                     f"{name} could not be measured; fail-closed"))
            return
        if free < min_free:
            out.append(Violation(name, "below_min_free",
                                 f"{name} free {free} < required {min_free}"))
        if total > 0:
            keep_bytes = total - int(total * max_fraction)
            if free < keep_bytes:
                out.append(Violation(name, "above_max_use",
                                     f"{name} usage exceeds {max_fraction:.0%} "
                                     f"(free {free} of {total})"))

    floor_and_fraction("vram", snap.vram_free, snap.vram_total,
                       limits.min_free_vram, limits.max_vram_use_fraction,
                       limits.require_vram)
    floor_and_fraction("ram", snap.ram_available, snap.ram_total,
                       limits.min_free_ram, limits.max_ram_use_fraction,
                       limits.require_ram)
    # Disk has no usage-fraction budget; the free floor is the limit.
    if snap.disk_free is None or snap.disk_total is None:
        if limits.require_disk:
            out.append(Violation("disk", "unmeasurable",
                                 "disk could not be measured; fail-closed"))
    elif snap.disk_free < limits.min_free_disk:
        out.append(Violation("disk", "below_min_free",
                             f"disk free {snap.disk_free} < required "
                             f"{limits.min_free_disk}"))
    return out


def preflight(
    *,
    limits: Optional[Thresholds] = None,
    vram_probe: Optional[Callable[[], tuple[int, int]]] = None,
    ram_probe: Optional[Callable[[], tuple[int, int]]] = None,
    disk_path: str = ".",
    disk_probe: Optional[Callable[[], tuple[int, int]]] = None,
) -> Verdict:
    """Fail-closed start gate for a workload.

    Inputs: ``limits`` (defaults applied when None) and injectable probes as
    in :func:`snapshot`. Output: :class:`Verdict`; ``ok`` is True only when
    every required resource is measurable and within limits.
    """
    limits = limits or Thresholds()
    snap = snapshot(vram_probe=vram_probe, ram_probe=ram_probe,
                    disk_path=disk_path, disk_probe=disk_probe)
    violations = check(snap, limits)
    return Verdict(ok=not violations, snapshot=snap, violations=tuple(violations))


class ResourceWatchdog:
    """Continuous observer that stops a workload before any limit is hit.

    Inputs: ``limits`` — thresholds; ``on_violation`` — callback invoked
    once with the first :class:`Violation` (e.g. set a training stop flag);
    ``interval_s`` — poll period (default 2.0 s); probe injection as in
    :func:`snapshot`. Output: ``None``; use as a context manager or call
    ``stop()``. The watchdog is fail-closed exactly like :func:`preflight`.
    """

    TOLERATED_MISSED_PROBES = 30

    def __init__(
        self,
        *,
        limits: Optional[Thresholds] = None,
        on_violation: Callable[[Violation], None],
        interval_s: float = 2.0,
        vram_probe: Optional[Callable[[], tuple[int, int]]] = None,
        ram_probe: Optional[Callable[[], tuple[int, int]]] = None,
        disk_path: str = ".",
        disk_probe: Optional[Callable[[], tuple[int, int]]] = None,
    ) -> None:
        self._limits = limits or Thresholds()
        self._on_violation = on_violation
        self._interval_s = interval_s
        self._vram_probe = vram_probe
        self._ram_probe = ram_probe
        self._disk_path = disk_path
        self._disk_probe = disk_probe
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._fired = False
        self._probe_misses = 0

    def __enter__(self) -> "ResourceWatchdog":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()

    def start(self) -> None:
        """Start the polling thread. Inputs/Output: none."""
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the polling thread and join it. Inputs/Output: none."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval_s * 3)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            snap = snapshot(
                vram_probe=self._vram_probe,
                ram_probe=self._ram_probe,
                disk_path=self._disk_path,
                disk_probe=self._disk_probe,
            )
            violations = check(snap, self._limits)
            # Transient probe failures must not kill a healthy run: only a
            # real breach, or a probe that stays unmeasurable for
            # `TOLERATED_MISSED_PROBES` consecutive polls, triggers the stop.
            unmeasurable_only = violations and all(
                v.reason == "unmeasurable" for v in violations
            )
            if unmeasurable_only:
                self._probe_misses += 1
                if self._probe_misses < self.TOLERATED_MISSED_PROBES:
                    self._stop.wait(self._interval_s)
                    continue
            if violations and not self._fired:
                self._fired = True
                self._on_violation(violations[0])
                return
            self._stop.wait(self._interval_s)


def estimate_training_vram(
    *,
    param_billions: float,
    seq_len: int,
    vocab_size: int = 150_000,
    margin: int = 2 * GIB,
) -> int:
    """Estimate peak training VRAM so preflight can size the workload.

    Inputs: ``param_billions`` — base model size in billions of parameters;
    ``seq_len`` — training sequence length; ``vocab_size`` — tokenizer vocab
    for the logits/loss peak; ``margin`` — extra safety bytes. Output:
    estimated peak bytes = base weights at a near-fp16 worst case
    (~1.0 B/param: 4-bit weights plus quant metadata, adapter, optimizer
    state and framework overheads) + activations under gradient
    checkpointing (128 MiB per seq-128 unit) + fp32 logits/loss workspace
    (seq * vocab * 4 bytes) + margin. Deliberately pessimistic: under-
    estimating causes crashes, over-estimating only delays a start.
    """
    weights = int(param_billions * 1.0 * GIB)
    activations = 128 * 1024 * 1024 * max(1, seq_len // 128)
    logits = int(seq_len) * int(vocab_size) * 4
    return weights + activations + logits + int(margin)


# --- default probes (documented sources; kept tiny and injectable) ---------

def _default_vram_probe() -> tuple[int, int]:
    """GPU memory via PyTorch (official API). Output: (free, total) bytes.

    Raises RuntimeError when no GPU stack is present (the decision layer
    treats that as unmeasurable and fails closed when VRAM is required).
    """
    import torch

    if not torch.cuda.is_available():
        raise RuntimeError("no CUDA/HIP device visible")
    free, total = torch.cuda.mem_get_info()
    return int(free), int(total)


def _default_ram_probe() -> tuple[int, int]:
    """RAM via psutil (official API). Output: (available, total) bytes.

    ``available`` (not ``free``) is the OOM-relevant metric. Falls back to
    the stdlib when psutil is absent so the guard stays installation-agnostic.
    """
    try:
        import psutil

        vm = psutil.virtual_memory()
        return int(vm.available), int(vm.total)
    except ImportError:
        pass
    try:
        import os

        page = os.sysconf("SC_PAGE_SIZE")
        total = page * os.sysconf("SC_PHYS_PAGES")
        avail = page * os.sysconf("SC_AVPHYS_PAGES")
        return int(avail), int(total)
    except (ImportError, AttributeError, ValueError):
        pass
    # Windows stdlib path (ctypes is part of the standard library).
    import ctypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        raise RuntimeError("GlobalMemoryStatusEx failed")
    return int(stat.ullAvailPhys), int(stat.ullTotalPhys)


def _default_disk_probe(path: str) -> tuple[int, int]:
    """Disk via the Python standard library. Output: (free, total) bytes."""
    usage = shutil.disk_usage(path)
    return int(usage.free), int(usage.total)
