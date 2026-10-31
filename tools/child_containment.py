"""Windows child-process containment for owned tool runs (Rejection Rejector).

Ported from strmt7/FlitzZip ``mcp/flitzzip_mcp.py`` (MIT, FlitzZip
contributors): the ``CREATE_SUSPENDED`` acquisition, ``admit_child_memory_bytes``
admission, ``resume_owned_child`` resumption and ``ChildContainment`` job-object
containment, byte-faithful. This module provides only the containment surface
the crawler tool chain needs; the hosting MCP server is FlitzZip product code
and is intentionally not ported.

Inputs: a suspended ``subprocess.Popen`` child and an admitted memory budget;
Output: a ``ChildContainment`` handle whose ``close()`` releases or reaps the
owned process tree.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import threading
import time
from ctypes import wintypes

MIB = 1024 * 1024
CREATE_SUSPENDED = 0x00000004
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
PROTOCOL_VERSION = "2026-07-28"
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "flitzzip-mcp", "version": "0.2.0"}
CAPABILITIES = {"tools": {"listChanged": False}}
META_PREFIX = "io.modelcontextprotocol/"
RESPONSE_LOCK = threading.Lock()
COMMANDS = {
    "verification_plan": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/verification_plan.ps1",
        "-IncludeUntracked",
        "-Checkpoint",
        "intermediate",
    ],
    "verify_changes": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/verify_changes.ps1",
        "-IncludeUntracked",
        "-Checkpoint",
        "intermediate",
    ],
    "lint": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/lint.ps1",
        "-CppMode",
        "Changed",
        "-IncludeUntracked",
    ],
    "wait_relevant_workflows": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/wait_relevant_workflows.ps1",
        "-Mode",
        "opportunistic",
    ],
    "wait_relevant_workflows_opportunistic": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/wait_relevant_workflows.ps1",
        "-Mode",
        "opportunistic",
    ],
    "check_long_running_workflows": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/wait_relevant_workflows.ps1",
        "-Mode",
        "opportunistic",
        "-IncludeLongRunning",
    ],
    "wait_final_commit_workflows": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/wait_relevant_workflows.ps1",
        "-Mode",
        "final",
        "-FinalCommit",
        "-Full",
    ],
    "defer_relevant_workflows": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/wait_relevant_workflows.ps1",
        "-Mode",
        "opportunistic",
    ],
    "build": ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools/build.ps1"],
    "build_hip": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/build.ps1",
        "-EnableHip",
    ],
    "test": ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "tools/test.ps1"],
    "security_scan": [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "tools/security_scan.ps1",
    ],
}


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class _JobObjectBasicAccountingInformation(ctypes.Structure):
    """Typed Windows accounting result used to confirm complete owned-tree shutdown."""

    _fields_ = [
        ("total_user_time", ctypes.c_longlong),
        ("total_kernel_time", ctypes.c_longlong),
        ("period_user_time", ctypes.c_longlong),
        ("period_kernel_time", ctypes.c_longlong),
        ("total_page_fault_count", wintypes.DWORD),
        ("total_processes", wintypes.DWORD),
        ("active_processes", wintypes.DWORD),
        ("total_terminated_processes", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", _JobObjectBasicLimitInformation),
        ("io_info", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


class _MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD),
        ("memory_load", wintypes.DWORD),
        ("total_physical", ctypes.c_ulonglong),
        ("available_physical", ctypes.c_ulonglong),
        ("total_page_file", ctypes.c_ulonglong),
        ("available_page_file", ctypes.c_ulonglong),
        ("total_virtual", ctypes.c_ulonglong),
        ("available_virtual", ctypes.c_ulonglong),
        ("available_extended_virtual", ctypes.c_ulonglong),
    ]


class _ThreadEntry(ctypes.Structure):
    size: int
    usage: int
    thread_id: int
    process_id: int
    base_priority: int
    delta_priority: int
    flags: int

    _fields_ = [
        ("size", wintypes.DWORD),
        ("usage", wintypes.DWORD),
        ("thread_id", wintypes.DWORD),
        ("process_id", wintypes.DWORD),
        ("base_priority", wintypes.LONG),
        ("delta_priority", wintypes.LONG),
        ("flags", wintypes.DWORD),
    ]


def resolve_memory_budget_mib(available_mib: int, required_mib: int = 2048) -> int:
    """Purpose: Mirror the shared PowerShell RAM admission policy with integer arithmetic.
    Inputs: available_mib is free physical RAM; required_mib is the positive minimum safe job budget.
    Outputs: Returns at most half free RAM while retaining 2 GiB; raises on unknown or insufficient capacity.
    """
    if type(available_mib) is not int or available_mib < 0 or type(required_mib) is not int or required_mib <= 0:
        raise ValueError("RAM admission requires nonnegative available and positive required integer MiB")
    budget = max(0, available_mib - max(2048, (available_mib + 1) // 2))
    if budget < required_mib:
        raise RuntimeError(
            f"Insufficient available RAM for local work: {available_mib} MiB available, "
            f"{budget} MiB admitted, {required_mib} MiB required."
        )
    return budget


def admit_child_memory_bytes(requested_bytes: int | None = None) -> int:
    """Purpose: Sample current Windows RAM before launching an owned command tree.
    Inputs: Optional smaller positive internal test budget; callers cannot exceed ordinary shared-policy admission.
    Outputs: Returns job committed-memory ceiling; raises before launch if counters, capacity, or platform fail.
    """
    if os.name != "nt":
        raise RuntimeError("FlitzZip command execution requires Windows aggregate job-memory containment")
    if requested_bytes is not None and (type(requested_bytes) is not int or requested_bytes <= 0):
        raise ValueError("requested job memory must be a positive integer byte count")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(_MemoryStatus)]
    kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
    status = _MemoryStatus(length=ctypes.sizeof(_MemoryStatus))
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise OSError(ctypes.get_last_error(), "available physical RAM query failed")
    budget_bytes = resolve_memory_budget_mib(status.available_physical // MIB) * MIB
    if requested_bytes is not None and requested_bytes > budget_bytes:
        raise ValueError("requested job memory exceeds current shared-policy RAM admission")
    return budget_bytes if requested_bytes is None else requested_bytes


def resume_owned_child(process: subprocess.Popen[bytes]) -> None:
    """Purpose: Resume only the primary thread of our newly created, contained suspended Windows child.
    Inputs: process retains its live process handle; no child code has executed yet.
    Outputs: Resumes one verified owned thread or raises; never resumes a thread not verified as owned.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = kernel32.Thread32First.argtypes
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessIdOfThread.restype = wintypes.DWORD
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "owned child thread snapshot failed")
    try:
        entry = _ThreadEntry(size=ctypes.sizeof(_ThreadEntry))
        found = kernel32.Thread32First(snapshot, ctypes.byref(entry))
        thread_ids = []
        while found:
            if entry.process_id == process.pid:
                thread_ids.append(entry.thread_id)
            entry.size = ctypes.sizeof(_ThreadEntry)
            found = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:
            raise OSError(ctypes.get_last_error(), "owned child thread enumeration failed")
        if len(thread_ids) != 1 or process.poll() is not None:
            raise RuntimeError("suspended child must have exactly one live owned thread")
        # Query ownership through the opened handle as well as the read-only snapshot.
        thread = kernel32.OpenThread(0x00000802, False, thread_ids[0])
        if not thread:
            raise OSError(ctypes.get_last_error(), "owned child thread open failed")
        try:
            if kernel32.GetProcessIdOfThread(thread) != process.pid:
                raise RuntimeError("suspended child thread ownership changed")
            if kernel32.ResumeThread(thread) != 1:
                raise RuntimeError("owned child primary thread did not have one initial suspend count")
        finally:
            kernel32.CloseHandle(thread)
    finally:
        kernel32.CloseHandle(snapshot)


class ChildContainment:
    """Own process-tree containment for one allowlisted child command."""

    def __init__(self, process: subprocess.Popen[bytes], memory_limit_bytes: int) -> None:
        """Purpose: Put a suspended child in a verified memory-limited, kill-on-close Windows job.
        Inputs: process is our newly created suspended child; memory_limit_bytes is RAM-admitted committed memory.
        Outputs: Stores containment or raises; the launch owner must terminate and reap on failure before resuming.
        """
        self._handle: int | None = None
        self._kernel32: object | None = None
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateJobObjectW(None, None)
        information = _JobObjectExtendedLimitInformation()
        information.basic_limit_information.limit_flags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_JOB_MEMORY
        )
        information.job_memory_limit = memory_limit_bytes
        configured = handle and kernel32.SetInformationJobObject(
            handle,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )
        actual = _JobObjectExtendedLimitInformation()
        queried = configured and kernel32.QueryInformationJobObject(
            handle, 9, ctypes.byref(actual), ctypes.sizeof(actual), None
        )
        verified = (
            queried
            and actual.basic_limit_information.limit_flags == information.basic_limit_information.limit_flags
            and actual.job_memory_limit == memory_limit_bytes
        )
        assigned = verified and kernel32.AssignProcessToJobObject(handle, wintypes.HANDLE(process._handle))
        if not assigned:
            error = ctypes.get_last_error()
            if handle:
                kernel32.CloseHandle(handle)
            raise RuntimeError(f"child process containment failed ({error})")
        self._handle = handle
        self._kernel32 = kernel32

    def terminate(self, process: subprocess.Popen[bytes]) -> None:
        """Purpose: Terminate the contained child and every descendant.
        Inputs: process is the root child associated with this containment object.
        Outputs: Requests hard tree termination and falls back to killing the root process.
        """
        if self._handle is not None and self._kernel32 is not None:
            self._kernel32.TerminateJobObject(self._handle, 1)
        if process.poll() is None:
            process.kill()

    def close(self) -> None:
        """Purpose: Terminate and drain the owned process tree before releasing containment.
        Inputs: None.
        Outputs: Confirms zero active processes within five seconds, or raises; always closes the job exactly once.
        """
        if self._handle is not None and self._kernel32 is not None:
            try:
                if not self._kernel32.TerminateJobObject(self._handle, 1):
                    raise RuntimeError(f"owned job termination failed ({ctypes.get_last_error()})")
                deadline = time.monotonic() + 5
                while True:
                    accounting = _JobObjectBasicAccountingInformation()
                    if not self._kernel32.QueryInformationJobObject(
                        self._handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
                    ):
                        raise RuntimeError(f"owned job shutdown query failed ({ctypes.get_last_error()})")
                    if accounting.active_processes == 0:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("owned process tree did not finish termination within five seconds")
                    time.sleep(0.01)
            finally:
                self._kernel32.CloseHandle(self._handle)
                self._handle = None
