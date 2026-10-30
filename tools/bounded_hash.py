"""Bounded streaming file hashing shared by the offline validators.

why (security review finding 10): whole-file reads let a crafted evidence
artifact force memory proportional to its size, and receipt-controlled
artifact lists had no count or aggregate budget. This helper hashes
incrementally under hard budgets and rejects files replaced between
validation and read, so both validators share one bounded implementation.

Inputs: module constants define the budgets. Output: `bounded_sha256` and
`HashBudgetError` for the validator tools.
"""

import hashlib
import os
import stat as stat_module
from pathlib import Path

#: Streaming block size; keeps validator memory flat regardless of file size.
CHUNK_BYTES = 64 * 1024

#: Hard per-artifact byte budget (declared sizes are never trusted).
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

#: Hard aggregate byte budget across every artifact in one receipt.
MAX_AGGREGATE_BYTES = 256 * 1024 * 1024

#: Hard artifact-count budget per receipt.
MAX_ARTIFACT_COUNT = 256


class HashBudgetError(ValueError):
    """A declared artifact exceeded a size, identity or budget check."""


def bounded_sha256(path: Path, max_bytes: int = MAX_ARTIFACT_BYTES) -> str:
    """Hash one regular file incrementally under a hard byte budget.

    why (security review finding 10): the digest is computed from an opened
    descriptor in bounded chunks, and the pre/post identity comparison fails
    closed if the file is replaced or resized while being hashed.

    Inputs: `path` -- the file to hash; `max_bytes` -- per-file byte budget.
    Output: `str` -- lowercase hex SHA-256; raises `HashBudgetError` when the
    file is not regular, exceeds the budget, or changes while hashing, and
    propagates `OSError` for I/O failures.
    """
    before = path.stat()
    if not stat_module.S_ISREG(before.st_mode):
        raise HashBudgetError("not a regular file")
    if before.st_size > max_bytes:
        raise HashBudgetError("artifact exceeds per-file budget")
    digest = hashlib.sha256()
    total = 0
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK_BYTES), b""):
            total += len(block)
            if total > max_bytes:
                raise HashBudgetError("artifact exceeds per-file budget")
            digest.update(block)
        after = os.fstat(handle.fileno())
    if (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) != (
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ):
        raise HashBudgetError("artifact changed while hashing")
    return digest.hexdigest()
