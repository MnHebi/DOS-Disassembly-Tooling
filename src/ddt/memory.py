"""Offline comparison of observed guest memory with original and Ghidra bytes.

Consumes an ``ddt.address-correlation.v1`` record, a ``ddt.dosbox-memory.v1``
observation and the original executable, and reports which of the three byte
sequences agree. It never infers a cause for a disagreement.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .correlate import _load_json
from .dosbox import MEMORY_SCHEMA
from .errors import DDTError
from .format import _read_input, parse_mz

SCHEMA = "ddt.memory-comparison.v1"
CORRELATION_SCHEMA = "ddt.address-correlation.v1"
MAX_DIFFERENCES = 64

_LIMITATIONS = [
    "The comparison reports evidence, not a cause: differences between the sources can come from "
    "relocations, loader activity, runtime modification, differing analysis images or other sources",
    "Byte equality does not establish that a particular emulator session produced the observation; "
    "that relationship is supplied by the operator",
    "The comparison checks that the receipt is internally consistent; it does not authenticate the "
    "running executable's identity, the origin of the supplied JSON, or the absence of memory-read "
    "side effects, and it cannot prove the debugger was genuinely paused",
    "No percentage confidence score is implied",
]


def _hex_bytes(value, length: int, label: str, *, required: bool) -> str | None:
    if value is None:
        if required:
            raise DDTError(f"{label} are missing from the observation")
        return None
    if (not isinstance(value, str) or len(value) != length * 2
            or any(c not in "0123456789abcdefABCDEF" for c in value)):
        raise DDTError(f"{label} is not {length} bytes of hexadecimal: {value!r}")
    return value.upper()


def _cs_ip(value, label: str) -> str:
    """Validate a segment:offset observation and normalize it to SSSS:OOOO."""
    parts = value.split(":") if isinstance(value, str) else []
    if len(parts) != 2:
        raise DDTError(f"{label} is not a segment:offset value: {value!r}")
    for part in parts:
        if not part or len(part) > 4 or any(c not in "0123456789abcdefABCDEF" for c in part):
            raise DDTError(f"{label} is not a valid 16-bit segment:offset value: {value!r}")
    return f"{int(parts[0], 16):04X}:{int(parts[1], 16):04X}"


def compare(correlation: str | Path, observation: str | Path, binary: str | Path) -> dict:
    """Compare runtime, Ghidra and original-executable bytes for one instruction."""
    record = _load_json(correlation, CORRELATION_SCHEMA, "correlation record")
    obs = _load_json(observation, MEMORY_SCHEMA, "memory observation")
    source = Path(binary)
    data = _read_input(source)
    sha256 = hashlib.sha256(data).hexdigest()

    fmt = (record.get("binary") or {}).get("format")
    if fmt not in ("dos-com", "dos-mz"):
        raise DDTError(f"the correlation does not record a supported format: {fmt!r}")
    if record["binary"].get("sha256") != sha256:
        raise DDTError(f"executable identity mismatch: the correlation is for "
                       f"{record['binary'].get('sha256')} but {source} is {sha256}")
    if fmt == "dos-mz":
        parse_mz(data)  # validate the MZ the correlation was derived from

    instruction = record.get("instruction") or {}
    mapping = record.get("mapping") or {}
    offset = instruction.get("source_file_offset")
    length = mapping.get("instruction_length")
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise DDTError(f"the correlation has an invalid original file offset: {offset!r}")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise DDTError(f"the correlation has an invalid instruction length: {length!r}")
    if offset + length > len(data):
        raise DDTError(f"the original file does not contain the full instruction extent "
                       f"{offset}..{offset + length}")

    request = obs.get("request") or {}
    derived = mapping.get("runtime_cs_ip")
    if request.get("cs_ip") != derived:
        raise DDTError(f"the observation is for {request.get('cs_ip')!r}, but the correlation "
                       f"derives {derived!r}; segment aliases are not treated as equivalent")
    if request.get("length") != length:
        raise DDTError(f"the observation covers {request.get('length')!r} bytes, but the "
                       f"correlation's instruction is {length} bytes")
    for field in ("read_success", "cs_ip_unchanged"):
        if obs.get(field) is not True:
            raise DDTError(f"the memory observation does not record {field}=true "
                           f"({obs.get(field)!r}); refusing to compare")
    initial = _cs_ip((obs.get("initial") or {}).get("cs_ip"), "the observation's initial CS:IP")
    final = _cs_ip((obs.get("final") or {}).get("cs_ip"), "the observation's final CS:IP")
    if initial != final:
        raise DDTError(f"the memory observation's CS:IP changed ({initial} -> {final}) but "
                       f"cs_ip_unchanged is true")
    runtime_hex = _hex_bytes(obs.get("bytes_hex"), length, "the observed bytes", required=True)
    ghidra_hex = _hex_bytes(instruction.get("bytes"), length, "the Ghidra instruction bytes",
                            required=False)

    original = data[offset:offset + length]
    runtime = bytes.fromhex(runtime_hex)
    ghidra = bytes.fromhex(ghidra_hex) if ghidra_hex is not None else None

    def equal(left: bytes | None, right: bytes | None) -> bool | None:
        return None if left is None or right is None else left == right

    results = {"runtime_equals_original": equal(runtime, original),
               "runtime_equals_ghidra": equal(runtime, ghidra),
               "ghidra_equals_original": equal(ghidra, original)}
    differences = []
    for index in range(length):
        values = {"index": index, "original": f"{original[index]:02X}",
                  "runtime": f"{runtime[index]:02X}",
                  "ghidra": f"{ghidra[index]:02X}" if ghidra is not None else None}
        byte_values = {values["original"], values["runtime"]}
        if values["ghidra"] is not None:
            byte_values.add(values["ghidra"])
        if len(byte_values) > 1:
            differences.append(values)

    module_offset = mapping.get("module_image_offset") if fmt == "dos-mz" else offset
    overlaps = []
    if fmt == "dos-mz":
        for rel_offset, rel_segment in parse_mz(data).relocations:
            image_offset = rel_segment * 16 + rel_offset
            if image_offset < module_offset + length and image_offset + 2 > module_offset:
                overlaps.append({"image_offset": image_offset, "segment_relative": rel_segment,
                                 "offset": rel_offset,
                                 "overlap": [max(image_offset, module_offset),
                                             min(image_offset + 2, module_offset + length)]})

    unknowns = []
    if ghidra is None:
        unknowns.append("Ghidra's recorded instruction bytes were unavailable")
    if record.get("status") != "conditional":
        unknowns.append(f"the correlation status was {record.get('status')!r}")
    return {
        "schema": SCHEMA,
        "binary": {"path": str(source), "format": fmt, "sha256": sha256, "size": len(data)},
        "correlation": {"schema": record["schema"],
                        "ghidra_address": instruction.get("ghidra_address"),
                        "original_file_offset": offset, "instruction_length": length,
                        "derived_runtime_cs_ip": derived, "status": record.get("status")},
        "observation": {"source": str(observation), "schema": obs["schema"],
                        "address": request.get("cs_ip"), "length": request.get("length"),
                        "cs_ip_unchanged": obs.get("cs_ip_unchanged")},
        "bytes": {"original_hex": original.hex().upper(), "ghidra_hex": ghidra_hex,
                  "runtime_hex": runtime_hex},
        "results": results,
        "differences": differences[:MAX_DIFFERENCES],
        "differences_truncated": len(differences) > MAX_DIFFERENCES,
        "relocation_overlaps": overlaps,
        "checks": {"identity_sha256_match": True, "address_matches_correlation": True,
                   "length_matches_correlation": True, "extent_within_original_file": True},
        "unknowns": unknowns,
        "limitations": list(_LIMITATIONS),
    }
