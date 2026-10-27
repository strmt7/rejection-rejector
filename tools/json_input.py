"""Decode UTF-8 JSON without silently resolving ambiguous or nonfinite input.

Callers own byte budgets and domain/schema validation. This module performs no
I/O. Duplicate-property and nonfinite-number errors do not echo keys or values.
"""

from __future__ import annotations

import json
import math
from typing import NoReturn


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate properties before a dictionary could discard an earlier value."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON object contains duplicate properties")
        result[key] = value
    return result


def _finite_number(text: str) -> float:
    """Reject a syntactically valid JSON number that overflows Python's float range."""
    number = float(text)
    if not math.isfinite(number):
        raise ValueError("JSON numbers must be finite")
    return number


def _reject_constant(_text: str) -> NoReturn:
    """Reject the nonstandard NaN and infinity constants accepted by Python's decoder."""
    raise ValueError("JSON numbers must be finite")


def decode_json(payload: bytes | str) -> object:
    """Decode caller-bounded UTF-8 input; reject ambiguity and nonfinite numbers.

    The caller must still validate the decoded value against its domain schema.
    Invalid encoding, JSON syntax, duplicate properties and nonfinite values raise
    ValueError; excessively nested input may raise RecursionError.
    """
    text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    return json.loads(
        text,
        object_pairs_hook=_unique_fields,
        parse_float=_finite_number,
        parse_constant=_reject_constant,
    )
