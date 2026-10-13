"""Read-only printable-string extraction with exact original file offsets."""
from __future__ import annotations

import re
from pathlib import Path

from .diff import sha256
from .errors import DDTError
from .format import _read_input

# Printable ASCII runs only; DOS text is decoded from these bytes without
# applying relocations or inferring any runtime address.
_PRINTABLE = re.compile(rb"[\x20-\x7e]+")


def extract(path: Path, min_length: int = 4, max_results: int = 4096) -> dict:
    if type(min_length) is not int or min_length < 1:
        raise DDTError("min_length must be a positive integer")
    if type(max_results) is not int or max_results < 0:
        raise DDTError("max_results must be nonnegative")
    data = _read_input(path)
    found = []
    total = 0
    for match in _PRINTABLE.finditer(data):
        run = match.group()
        if len(run) < min_length:
            continue
        total += 1
        if len(found) < max_results:
            found.append({"file_offset": match.start(), "length": len(run),
                          "text": run.decode("ascii")})
    return {"schema": "ddt.strings.v1",
            "source_size": len(data), "sha256": sha256(data),
            "min_length": min_length, "strings": found,
            "total_string_count": total, "strings_truncated": total > len(found),
            "limits": ["Only printable ASCII (0x20-0x7E) runs are reported",
                       "Offsets are original input offsets, not runtime addresses"]}
