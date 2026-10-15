"""Offline comparison of observed guest memory with original and Ghidra bytes.

Consumes an ``ddt.address-correlation.v1`` record, a ``ddt.dosbox-memory.v1``
observation and the original executable, and reports which of the three byte
sequences agree. It never infers a cause for a disagreement.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .correlate import _load_json
from .dosbox import MAX_MEMORY_BYTES, MEMORY_SCHEMA, _write_json
from .errors import DDTError
from .format import _read_input, parse_mz

SCHEMA = "ddt.memory-comparison.v1"
REFERENCE_SCHEMA = "ddt.memory-reference-comparison.v1"
CORRELATION_SCHEMA = "ddt.address-correlation.v1"
MAX_DIFFERENCES = 64

_REFERENCE_LIMITATIONS = [
    "The reference offset is an operator-supplied original-file byte offset: DDT neither derives, "
    "verifies nor repairs the intended correspondence between the two byte ranges",
    "A byte match (or mismatch) is verified for the two supplied sequences only; it does not "
    "establish executable identity, load history, that those instructions executed, unpacking "
    "causality, or any source-file mapping into a packed executable",
    "Relocations, loader activity or runtime modification can legitimately make a correct runtime "
    "range differ from the reference bytes; DDT reports the difference and never adjusts the "
    "operator's offset",
]

_REFERENCE_UNESTABLISHED = [
    "executable identity",
    "load history",
    "that the observed region executed as those instructions",
    "unpacking causality",
    "a source-file mapping into the packed executable",
]

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


def _hex16(value, label: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 4
            or any(c not in "0123456789abcdefABCDEF" for c in value)):
        raise DDTError(f"{label} is not a 16-bit hexadecimal value: {value!r}")
    return f"{int(value, 16):04X}"


def _observed_cs_ip(container, label: str) -> str:
    if not isinstance(container, dict):
        raise DDTError(f"the observation's {label} register container is not an object: "
                       f"{container!r}")
    return _cs_ip(container.get("cs_ip"), f"the observation's {label} CS:IP")


def _validated_observation(record: dict) -> tuple[str, int, str]:
    """Strictly validate a ddt.dosbox-memory.v1 receipt; return (address, length, bytes_hex)."""
    request = record.get("request")
    response = record.get("response")
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise DDTError("the memory observation has no request/response record")
    address = _cs_ip(request.get("cs_ip"), "the observation's requested address")
    declared = f"{_hex16(request.get('segment'), 'the requested segment')}:" \
               f"{_hex16(request.get('offset'), 'the requested offset')}"
    if declared != address:
        raise DDTError(f"the observation's requested address {address} does not match its "
                       f"segment:offset fields {declared}")
    length = request.get("length")
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= MAX_MEMORY_BYTES:
        raise DDTError(f"the observation length is not an integer in 1..{MAX_MEMORY_BYTES}: "
                       f"{length!r}")
    # MEMREAD's own bounds, so a receipt can never describe a read the command refuses.
    segment_value, offset_value = (int(part, 16) for part in address.split(":"))
    if offset_value + length > 0x10000:
        raise DDTError(f"the observed range {address} + {length} bytes crosses a 64 KiB segment "
                       f"boundary")
    if segment_value * 16 + offset_value + length > 0xA0000:
        raise DDTError(f"the observed range {address} + {length} bytes extends beyond conventional "
                       f"RAM below A0000h")
    for field in ("read_success", "cs_ip_unchanged"):
        if record.get(field) is not True:
            raise DDTError(f"the memory observation does not record {field}=true "
                           f"({record.get(field)!r}); refusing to compare")
    if _cs_ip(response.get("address"), "the observation's response address") != address:
        raise DDTError(f"the observation's response address {response.get('address')!r} does not "
                       f"match the requested {address}")
    if type(response.get("length")) is not int or response["length"] != length:
        raise DDTError(f"the observation's response length {response.get('length')!r} does not "
                       f"match the requested {length}")
    if type(record.get("byte_count")) is not int or record["byte_count"] != length:
        raise DDTError(f"the observation's byte_count {record.get('byte_count')!r} does not match "
                       f"the requested {length}")
    initial = _observed_cs_ip(record.get("initial"), "initial")
    final = _observed_cs_ip(record.get("final"), "final")
    if initial != final:
        raise DDTError(f"the memory observation's CS:IP changed ({initial} -> {final}) but "
                       f"cs_ip_unchanged is true")
    return address, length, _hex_bytes(record.get("bytes_hex"), length, "the observed bytes",
                                       required=True)


def compare_reference(observation: str | Path, reference_binary: str | Path,
                      reference_offset: int, *, out: str | Path | None = None) -> dict:
    """Compare an observed runtime region with an operator-selected reference file range."""
    record = _load_json(observation, MEMORY_SCHEMA, "memory observation")
    address, length, runtime_hex = _validated_observation(record)
    if not isinstance(reference_offset, int) or isinstance(reference_offset, bool) \
            or reference_offset < 0:
        raise DDTError(f"the reference offset must be a nonnegative integer: {reference_offset!r}")
    reference = Path(reference_binary)
    data = _read_input(reference)
    sha256 = hashlib.sha256(data).hexdigest()
    if reference_offset + length > len(data):
        raise DDTError(f"the reference file is only {len(data)} bytes; the requested range "
                       f"{reference_offset}..{reference_offset + length} does not fit")
    reference_bytes = data[reference_offset:reference_offset + length]
    runtime = bytes.fromhex(runtime_hex)
    differences = [{"relative_offset": index,
                    "reference_file_offset": reference_offset + index,
                    "runtime": f"{runtime[index]:02X}",
                    "reference": f"{reference_bytes[index]:02X}"}
                   for index in range(length) if runtime[index] != reference_bytes[index]]
    result = {
        "schema": REFERENCE_SCHEMA,
        "provenance": {"correspondence": "operator_supplied",
                       "note": "the reference offset was supplied by the operator; DDT neither "
                               "derived nor verified the intended correspondence"},
        "observation": {"source": str(observation), "schema": record["schema"], "address": address,
                        "length": length, "bytes_hex": runtime_hex,
                        "read_success": record["read_success"],
                        "cs_ip_unchanged": record["cs_ip_unchanged"]},
        "reference": {"path": str(reference), "sha256": sha256, "size": len(data),
                      "file_offset": reference_offset,
                      "bytes_hex": reference_bytes.hex().upper()},
        "results": {"runtime_equals_reference": runtime == reference_bytes},
        "differences": differences[:MAX_DIFFERENCES],
        "difference_count": len(differences),
        "differences_truncated": len(differences) > MAX_DIFFERENCES,
        "checks": {"observation_schema": True, "read_success": True, "cs_ip_unchanged": True,
                   "addresses_consistent": True, "lengths_consistent": True,
                   "reference_extent_within_file": True},
        "verified": (["the two supplied byte sequences are equal"] if not differences
                     else ["the two supplied byte sequences differ at the listed offsets"]),
        "operator_assertion": ["the runtime region and the reference file range are intended to "
                               "correspond"],
        "not_established": list(_REFERENCE_UNESTABLISHED),
        "limitations": list(_REFERENCE_LIMITATIONS),
    }
    if out is not None:
        destination = Path(out)
        for label, source in (("the observation", Path(observation)),
                              ("the reference binary", Path(reference_binary))):
            if destination.resolve() == source.resolve():
                raise DDTError(f"--out must not overwrite {label}: {destination}")
        _write_json(destination, result)
    return result


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
