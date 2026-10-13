"""Correlate a Ghidra instruction address with a candidate DOS runtime address.

The chain of evidence is: original executable file (SHA-256) -> a Ghidra
function export carrying original source-file offsets -> an observed program
entry context from DOSBox-X. Ghidra's address space is never equated with the
guest's segment:offset space; the runtime address is derived from the observed
entry context and is reported as conditional, never as verified execution.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .errors import DDTError
from .format import COM, MZ, _read_input, inspect

SCHEMA = "ddt.address-correlation.v1"
GHIDRA_SCHEMA = "ddt.ghidra-function.v1"
STEPS_SCHEMA = "ddt.dosbox-steps.v1"

_LIMITATIONS = [
    "The derived runtime address is conditional on the supplied entry observation having come "
    "from launching this exact executable; DDT cannot independently prove that link",
    "Ghidra memory bytes can differ from original file bytes where a loader applied relocations "
    "or patches; the original file-offset provenance is unaffected",
    "This is not observed runtime execution: no guest memory was read, so byte equality at the "
    "derived address was not verified",
    "A canonical segment:offset is one representation of the location, not necessarily the alias "
    "the running program uses",
    "Not applicable to overlays, protected-mode DOS extenders, uninitialized storage without an "
    "original file offset, or self-modified/decompressed code",
]

_UKNOWN = [
    "whether guest memory at the derived address actually holds the original instruction bytes",
]


def _load_json(path: str | Path, schema: str, label: str) -> dict:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise DDTError(f"{label} must be an ordinary file: {source}")
    try:
        record = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DDTError(f"unreadable {label} {source}: {exc}") from exc
    if not isinstance(record, dict) or record.get("schema") != schema:
        raise DDTError(f"{label} {source} is not a {schema} record")
    return record


def _segment_offset(text: str, label: str) -> int:
    try:
        value = int(text, 16)
    except (TypeError, ValueError) as exc:
        raise DDTError(f"{label} is not a hexadecimal value: {text!r}") from exc
    if not 0 <= value <= 0xFFFF:
        raise DDTError(f"{label} does not fit in 16 bits: {text!r}")
    return value


def correlate(binary: str | Path, fmt: str, export: str | Path, instruction: str,
              entry_observation: str | Path) -> dict:
    """Derive a candidate real-mode runtime address for one exported instruction."""
    if fmt not in ("com", "mz"):
        raise DDTError(f"format must be 'com' or 'mz': {fmt!r}")
    source = Path(binary)
    data = _read_input(source)
    target = inspect(source, fmt)
    if fmt == "com" and not isinstance(target, COM):
        raise DDTError("the selected binary is not a COM image")
    if fmt == "mz" and not isinstance(target, MZ):
        raise DDTError("the selected binary is not an MZ image")
    local_sha = hashlib.sha256(data).hexdigest()

    ghidra = _load_json(export, GHIDRA_SCHEMA, "Ghidra export")
    program = ghidra.get("program") or {}
    export_sha = program.get("executable_sha256")
    if not export_sha:
        raise DDTError("the Ghidra export does not record an executable SHA-256; "
                       "executable identity is unresolved")
    if export_sha.lower() != local_sha:
        raise DDTError(f"executable identity mismatch: the Ghidra export was made from "
                       f"{export_sha} but {source} is {local_sha}")

    function = ghidra.get("function") or {}
    chosen = next((item for item in function.get("instructions", [])
                   if item.get("address") == instruction), None)
    if chosen is None:
        raise DDTError(f"instruction {instruction} is not present in the Ghidra export")
    file_offset = chosen.get("source_file_offset")
    if not chosen.get("mapping_known") or file_offset is None:
        raise DDTError(f"instruction {instruction} has no original source-file offset in the "
                       f"Ghidra export; the mapping is unresolved")
    if chosen.get("source_file") and chosen["source_file"].lower() != source.name.lower():
        raise DDTError(f"instruction {instruction} maps to {chosen['source_file']!r}, not "
                       f"{source.name!r}; executable identity is unresolved")

    observation = _load_json(entry_observation, STEPS_SCHEMA, "entry observation")
    initial = observation.get("initial") or {}
    cs_ip = initial.get("cs_ip")
    if not cs_ip or ":" not in cs_ip:
        raise DDTError("the entry observation does not record an initial CS:IP")
    segment_text, offset_text = cs_ip.split(":", 1)
    entry_cs = _segment_offset(segment_text, "observed entry CS")
    entry_ip = _segment_offset(offset_text, "observed entry IP")

    checks = {"identity_sha256_match": True, "instruction_found": True,
              "source_offset_known": True}
    arithmetic: list[str] = []
    mapping: dict = {"original_file_offset": file_offset}

    if fmt == "com":
        if entry_ip != 0x100:
            raise DDTError(f"COM entry must be observed at IP=0100, not {entry_ip:04X}; "
                           "the entry observation is not a COM program start")
        if not 0 <= file_offset < target.source_size:
            raise DDTError(f"source file offset {file_offset} is outside the COM image "
                           f"(0..{target.source_size - 1})")
        runtime_offset = 0x100 + file_offset
        arithmetic = ["COM images load with file offset 0 at runtime offset 0100",
                      f"runtime offset = 0100 + {file_offset:04X} = {runtime_offset:04X}",
                      f"runtime segment = observed entry CS {entry_cs:04X}"]
        mapping.update({"runtime_segment": f"{entry_cs:04X}",
                        "runtime_offset": f"{runtime_offset:04X}",
                        "runtime_cs_ip": f"{entry_cs:04X}:{runtime_offset:04X}"})
        checks["entry_ip_is_0100"] = True
        checks["within_source_image"] = True
    else:
        if entry_ip != target.entry_ip:
            raise DDTError(f"MZ entry IP mismatch: header says {target.entry_ip:04X}, the "
                           f"observation says {entry_ip:04X}")
        load_segment = (entry_cs - target.entry_cs) & 0xFFFF
        module_offset = file_offset - target.header_bytes
        if not 0 <= module_offset < target.image_bytes:
            raise DDTError(f"source file offset {file_offset} is outside the initialized MZ load "
                           f"module ({target.header_bytes}.."
                           f"{target.header_bytes + target.image_bytes - 1})")
        physical = load_segment * 16 + module_offset
        if physical > 0xFFFFF:
            raise DDTError(f"the derived physical address {physical:#x} needs an address wrap or "
                           "A20 assumption; refusing to guess")
        arithmetic = [
            f"header entry CS = {target.entry_cs:04X}, observed entry CS = {entry_cs:04X}",
            f"load segment = {entry_cs:04X} - {target.entry_cs:04X} = {load_segment:04X}",
            f"module image offset = {file_offset} - {target.header_bytes} = {module_offset}",
            f"physical = {load_segment:04X}*16 + {module_offset:04X} = {physical:05X}",
            f"canonical segment:offset = {physical >> 4:04X}:{physical & 0xF:04X}",
        ]
        mapping.update({"module_image_offset": module_offset,
                        "load_segment": f"{load_segment:04X}",
                        "canonical_runtime_cs_ip": f"{physical >> 4:04X}:{physical & 0xF:04X}",
                        "runtime_cs_ip": f"{(physical >> 4) & 0xFFFF:04X}:{physical & 0xF:04X}"})
        checks.update({"entry_ip_matches_header": True, "within_initialized_image": True,
                       "no_address_wraparound": True})

    return {
        "schema": SCHEMA,
        "binary": {"path": str(source), "format": "dos-com" if fmt == "com" else "dos-mz",
                   "sha256": local_sha, "size": len(data)},
        "ghidra": {"program": program.get("name"), "executable_sha256": export_sha,
                   "identity_matches": True},
        "instruction": {"ghidra_address": instruction, "source_file": chosen.get("source_file"),
                        "source_file_offset": file_offset, "bytes": chosen.get("bytes"),
                        "text": chosen.get("text")},
        "entry_observation": {"source": str(entry_observation), "cs_ip": cs_ip,
                              "segment": f"{entry_cs:04X}", "ip": f"{entry_ip:04X}",
                              "registers": initial.get("registers")},
        "mapping": mapping,
        "arithmetic": arithmetic,
        "status": "conditional",
        "checks": checks,
        "unknowns": list(_UKNOWN),
        "limitations": list(_LIMITATIONS),
    }
