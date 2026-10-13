"""Read-only binary and directory comparison; no game-specific schemas."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .errors import DDTError
from .format import MAX_INPUT


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _files(root: Path) -> dict[str, Path]:
    if root.is_symlink():
        raise DDTError("symlinks are unsupported in artifact snapshots")
    if root.is_file():
        return {"<file>": root}
    if not root.is_dir():
        raise DDTError(f"not a regular file or directory: {root}")
    result = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise DDTError(f"symlinks are unsupported: {path}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = path
    return result


def _load(path: Path) -> bytes:
    if path.is_symlink() or path.stat().st_size > MAX_INPUT:
        raise DDTError(f"symlink or input over 64 MiB: {path}")
    return path.read_bytes()


def manifest(root: Path) -> dict:
    entries = _files(root)
    return {"schema": "ddt.artifact-manifest.v1",
            "entries": [{"path": name, "bytes": len(b := _load(path)), "sha256": sha256(b)}
                        for name, path in sorted(entries.items())]}


def _byte_runs(before: bytes, after: bytes, max_runs: int, max_preview: int = 24) -> dict:
    n = max(len(before), len(after))
    total = 0
    stored = []
    i = 0
    while i < n:
        if (before[i:i + 1] if i < len(before) else None) == (after[i:i + 1] if i < len(after) else None):
            i += 1
            continue
        start = i
        i += 1
        while i < n and ((before[i:i + 1] if i < len(before) else None) !=
                         (after[i:i + 1] if i < len(after) else None)):
            i += 1
        total += 1
        if len(stored) < max_runs:
            previous = before[start:i]
            current = after[start:i]
            stored.append({"offset": start, "extent_bytes": i - start,
                           "before_hex": previous[:max_preview].hex(),
                           "after_hex": current[:max_preview].hex(),
                           "preview_truncated": len(previous) > max_preview or len(current) > max_preview})
    return {"runs": stored, "total_run_count": total,
            "runs_truncated": total > len(stored)}


def compare(before_path: Path, after_path: Path, max_runs: int = 128) -> dict:
    if max_runs < 0:
        raise DDTError("max_runs must be nonnegative")
    a = _files(before_path)
    b = _files(after_path)
    if (before_path.is_file()) != (after_path.is_file()):
        raise DDTError("compare a file with a file, or directory with directory")
    results = []
    for name in sorted(a.keys() | b.keys()):
        old = _load(a[name]) if name in a else None
        new = _load(b[name]) if name in b else None
        status = "only_before" if new is None else "only_after" if old is None else "same" if old == new else "changed"
        entry = {"path": name, "status": status,
                 "before_bytes": len(old) if old is not None else None,
                 "after_bytes": len(new) if new is not None else None,
                 "before_sha256": sha256(old) if old is not None else None,
                 "after_sha256": sha256(new) if new is not None else None}
        if status == "changed":
            entry.update(_byte_runs(old, new, max_runs))
        results.append(entry)
    return {"schema": "ddt.binary-comparison.v1",
            "results": results,
            "summary": {key: sum(e["status"] == key for e in results)
                        for key in ("same", "changed", "only_before", "only_after")},
            "limits": ["Byte run previews are bounded, count/total extents are retained",
                       "No inferred semantics or causal association"]}
