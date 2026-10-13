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
READERS_SCHEMA = "ddt.code-readers.v1"
WRITERS_SCHEMA = "ddt.code-writers.v1"

# Exact Ghidra reference-type names used only when an export predates the
# explicit read/write flags. No substring matching, so nothing is misclassified.
_LEGACY_READ_TYPES = frozenset({"READ", "READ_WRITE", "READ_IND", "READ_WRITE_IND"})
_LEGACY_WRITE_TYPES = frozenset({"WRITE", "READ_WRITE", "WRITE_IND", "READ_WRITE_IND"})


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


def _access(reference: dict) -> tuple[bool, bool, bool]:
    """(reads, writes, classified): explicit flags when present, else exact type names."""
    if "read" in reference or "write" in reference:
        return bool(reference.get("read")), bool(reference.get("write")), True
    name = str(reference.get("type") or "").upper()
    return name in _LEGACY_READ_TYPES, name in _LEGACY_WRITE_TYPES, name in _LEGACY_READ_TYPES | _LEGACY_WRITE_TYPES


def _access_query(export: str | Path, address: str, want: str, schema: str, direction: str) -> dict:
    if not isinstance(address, str) or not address:
        raise DDTError("address must be a non-empty Ghidra address string")
    record = _load(export)
    function = record["function"]
    refs = [ref for ref in function.get("outgoing_references", []) if isinstance(ref, dict)]
    # Older exports may lack the explicit flags entirely; say so rather than guess.
    legacy = not any("read" in ref or "write" in ref for ref in refs)
    direct, computed, unclassified = [], [], 0
    for ref in refs:
        # Match the Ghidra address text exactly, so a different address or a
        # different address space can never be equated with the request.
        if ref.get("to") != address or ref.get("flow"):
            continue
        reads, writes, classified = _access(ref)
        if not classified:
            unclassified += 1
            continue
        if not (reads if want == "read" else writes):
            continue
        entry = {"from": ref.get("from"), "to": ref.get("to"), "type": ref.get("type"),
                 "computed": bool(ref.get("computed")), "memory": bool(ref.get("memory")),
                 "external": bool(ref.get("external"))}
        (computed if entry["computed"] else direct).append(entry)
    truncated = function.get("outgoing_references_truncated")
    limits = ["Only one exported function was searched; other functions were not examined",
              "Computed or indirect matches are listed separately and are not proven "
              "accesses to the exact address",
              "Segment aliases can name the same memory through different addresses",
              "Ghidra's static reference classification is analysis evidence, not proof "
              "of an executed access",
              "Writes through pointers and interprocedural effects are outside scope",
              _truncation_limit("outgoing reference", truncated)]
    if legacy:
        limits.append("This export has no read/write flags; references were classified by "
                      "exact Ghidra reference-type name")
    if unclassified:
        limits.append(f"{unclassified} matching reference(s) could not be classified as a read or write")
    return {"schema": schema, "direction": direction, "address": address,
            "source": _source(record), "direct": direct, "computed": computed,
            "direct_count": len(direct), "computed_count": len(computed),
            "unclassified_count": unclassified, "references_truncated": truncated,
            "limits": limits}


def readers(export: str | Path, address: str) -> dict:
    """Report instructions with direct Ghidra references reading the given address."""
    return _access_query(export, address, "read", READERS_SCHEMA, "readers")


def writers(export: str | Path, address: str) -> dict:
    """Report instructions with direct Ghidra references writing the given address."""
    return _access_query(export, address, "write", WRITERS_SCHEMA, "writers")
