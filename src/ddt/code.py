"""Offline direct caller/callee navigation over an exported Ghidra function.

This is a pure consumer of a ddt.ghidra-function.v1 JSON export. It never runs
Ghidra, re-reads the executable, or writes to the export. It reports only the
direct relationships that a single-function export can support and states its
coverage limits explicitly.
"""
from __future__ import annotations

import json
from pathlib import Path

from .errors import DDTError
from .ghidra import SCHEMA

CALLERS_SCHEMA = "ddt.code-callers.v2"
CALLEES_SCHEMA = "ddt.code-callees.v1"


def _load(export: str | Path) -> dict:
    path = Path(export)
    if path.is_symlink() or not path.is_file():
        raise DDTError(f"export must be an ordinary file: {path}")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DDTError(f"unreadable export {path}: {exc}") from exc
    if not isinstance(record, dict):
        raise DDTError(f"export {path} must contain a JSON object")
    schema = record.get("schema")
    if schema != SCHEMA:
        raise DDTError(f"unsupported export schema {schema!r}; expected {SCHEMA!r}")
    if not isinstance(record.get("function"), dict):
        raise DDTError(f"export {path} has no function record")
    return record


def _is_call(reference: dict) -> bool:
    """A Ghidra call reference: flow-typed and named like a call."""
    return bool(reference.get("flow")) and "CALL" in str(reference.get("type", "")).upper()


def _reference(reference: dict) -> dict:
    return {"from": reference.get("from"), "to": reference.get("to"),
            "type": reference.get("type"), "computed": bool(reference.get("computed")),
            "external": bool(reference.get("external"))}


def _source(record: dict) -> dict:
    program = record.get("program") or {}
    function = record["function"] or {}
    return {"program": program.get("name"), "function_entry": function.get("entry"),
            "function_name": function.get("name")}


def _truncation_limit(label: str, truncated) -> str:
    if truncated is None:
        return f"{label} truncation status is unknown (export predates count fields)"
    return f"Export limits may truncate the {label} collection"


def callers(export: str | Path) -> dict:
    """Report call references whose target is this function's entry point."""
    record = _load(export)
    function = record["function"]
    direct, computed, external = [], [], []
    for ref in function.get("incoming_references", []):
        if not isinstance(ref, dict) or not _is_call(ref):
            continue
        entry = _reference(ref)
        if entry["external"]:
            external.append(entry)
        elif entry["computed"]:
            computed.append(entry)
        else:
            direct.append(entry)
    truncated = function.get("incoming_references_truncated")
    limits = ["Incoming references cover only the selected function's entry point",
              "Computed or indirect callers are not proven direct call sites",
              "Caller function names are not available from a single-function export",
              "Indirect or aliased callers may be unresolved and are listed separately",
              _truncation_limit("incoming reference", truncated)]
    return {"schema": CALLERS_SCHEMA, "direction": "callers", "source": _source(record),
            "direct_callers": direct, "computed_callers": computed, "external_callers": external,
            "direct_caller_count": len(direct),
            "references_truncated": truncated, "limits": limits}


def callees(export: str | Path) -> dict:
    """Report direct, computed and external calls made by this function."""
    record = _load(export)
    function = record["function"]
    direct, computed, external = [], [], []
    for ref in function.get("outgoing_references", []):
        if not isinstance(ref, dict) or not _is_call(ref):
            continue
        entry = _reference(ref)
        if entry["external"]:
            external.append(entry)
        elif entry["computed"]:
            computed.append(entry)
        else:
            direct.append(entry)
    unresolved = [{"from": item.get("address"), "text": item.get("text"),
                   "flow_type": item.get("flow_type")}
                  for item in function.get("unresolved_flow", [])
                  if isinstance(item, dict) and "CALL" in str(item.get("flow_type", "")).upper()]
    limits = ["One function is described; this is not whole-program call-graph reconstruction",
              "Computed or indirect calls are not proven direct call targets",
              "A direct call target is a referenced destination address, "
              "not necessarily a verified function entry point",
              "Indirect calls may remain unresolved and are listed separately",
              _truncation_limit("outgoing reference", function.get("outgoing_references_truncated"))]
    return {"schema": CALLEES_SCHEMA, "direction": "callees", "source": _source(record),
            "direct_calls": direct, "computed_calls": computed, "external_calls": external,
            "unresolved_calls": unresolved, "direct_call_count": len(direct),
            "references_truncated": function.get("outgoing_references_truncated"),
            "unresolved_truncated": function.get("unresolved_flow_truncated"),
            "limits": limits}
