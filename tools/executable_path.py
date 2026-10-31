"""Resolve native development commands without implicit current-directory lookup."""

from __future__ import annotations

import os
from pathlib import Path


def _native_program(command: str) -> Path:
    """Purpose: Admit a native program name without performing PATH lookup.
    Inputs: Absolute filename or basename. Outputs: Validated path; ValueError for relative paths/Windows scripts.
    """
    if not command or command in {".", ".."} or "\0" in command:
        raise ValueError("Executable name must be nonempty and contain no NUL")
    program = Path(command)
    if not program.is_absolute() and (program.name != command or program.drive or program.root):
        raise ValueError("Executable must be an absolute path or a basename")
    if os.name == "nt":
        if not program.suffix:
            program = program.with_suffix(".exe")
        elif program.suffix.lower() not in {".exe", ".com"}:
            raise ValueError("Windows commands must select a native executable, not a command script")
    return program


def executable_path(command: str, *, search_path: str | None = None) -> str:
    """Purpose: Resolve an explicitly selected native program before process creation.
    Inputs: Absolute filename or basename, and optional PATH; only absolute search directories count.
    Outputs: Absolute executable filename, or ValueError/OSError; never selects a Windows command script.
    """
    program = _native_program(command)
    if program.is_absolute():
        candidates = [program]
    else:
        path = os.environ.get("PATH", os.defpath) if search_path is None else search_path
        directories = (Path(entry) for entry in path.split(os.pathsep) if entry)
        candidates = [directory / program for directory in directories if directory.is_absolute()]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.F_OK | os.X_OK):
            return str(candidate)
    raise FileNotFoundError(f"Native executable is unavailable in absolute PATH directories: {command}")
