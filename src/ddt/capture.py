"""Read-only intake of two captured filesystem snapshots.

This is thin orchestration over the existing manifest and compare primitives: it
records what DDT read and what differs, and never attributes a difference to any
action, emulator, or runtime session.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile

from .diff import compare, manifest
from .errors import DDTError

SCHEMA = "ddt.capture-intake.v1"

_LIMITS = [
    "A receipt records what DDT read; it does not prove the captures came from a "
    "particular application, executable, or runtime session",
    "Differences are reported, not explained: no cause is attributed to any action",
    "Changed-byte previews are bounded; total run counts are preserved",
    "Neither capture directory nor its contents are modified",
]


def _capture_dir(path: str | Path, label: str) -> Path:
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        raise DDTError(f"{label} must be an existing directory (not a symlink): {root}")
    return root


def _inside(candidate: Path, root: Path) -> bool:
    candidate = candidate.resolve()
    root = root.resolve()
    return candidate == root or root in candidate.parents


def _write_receipt(destination: Path, record: dict, before: Path, after: Path) -> None:
    if destination.is_dir():
        raise DDTError(f"--out must be a file path, not a directory: {destination}")
    for root in (before, after):
        if _inside(destination, root):
            raise DDTError(f"--out must not be written inside a capture directory: {destination}")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=destination.name + ".", dir=destination.parent))
    except OSError as exc:
        raise DDTError(f"cannot stage the receipt next to {destination}: {exc}") from exc
    try:
        staged = staging / "receipt.json"
        staged.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(staged, destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def intake(before: str | Path, after: str | Path, *, out: str | Path | None = None,
           note: str | None = None, max_runs: int = 128) -> dict:
    """Compare two captures and return a receipt describing exactly what was read."""
    before_dir = _capture_dir(before, "--before")
    after_dir = _capture_dir(after, "--after")
    if max_runs < 0:
        raise DDTError("max_runs must be nonnegative")
    comparison = compare(before_dir, after_dir, max_runs)
    summary = comparison["summary"]
    record = {
        "schema": SCHEMA,
        "captures": {
            "before": {"path": str(before_dir), "manifest": manifest(before_dir)},
            "after": {"path": str(after_dir), "manifest": manifest(after_dir)},
        },
        "comparison": comparison,
        "counts": {"added": summary["only_after"], "removed": summary["only_before"],
                   "unchanged": summary["same"], "modified": summary["changed"]},
        "user_supplied": None if note is None else {"note": note},
        "limits": list(_LIMITS),
    }
    if out is not None:
        _write_receipt(Path(out), record, before_dir, after_dir)
    return record
