"""Read-only identification of DOS executable containers and packaging markers.

This classifies structure only: it never loads, unpacks, relocates, or executes
anything, and a byte-pattern match is reported as a candidate, never as proof.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct

from .errors import DDTError
from .format import MAX_COM_SIZE, _read_input, _secondary_header, parse_mz

SCHEMA = "ddt.identify.v1"
COFF_MACHINE_I386 = 0x014C
MAX_COFF_SECTIONS = 96
LZEXE_OFFSET = 0x1C
LZEXE_SIGNATURES = {b"LZ09": "LZEXE v0.90", b"LZ91": "LZEXE v0.91"}
UPX_OFFSET = 85
UPX_MARKER = b"UPX"
GO32_MARKER = b"go32stub"

_LIMITS = [
    "Identification is structural; a signature match is a candidate, not proof",
    "No loading, unpacking, relocation, or execution is performed",
    "Appended bytes are an unknown-purpose region unless a recognised structure begins there",
    "NE, LE, LX, PE and packed images are recognised but not supported for loading or analysis",
    "An LE/LX image is not asserted to be a specific DOS extender application",
]


def _finding(kind: str, classification: str, supported: bool, **extra) -> dict:
    entry = {"kind": kind, "classification": classification, "supported": supported}
    entry.update(extra)
    return entry


def _coff_image(data: bytes, offset: int) -> dict | None:
    """Validate an i386 COFF file header and section table at offset, or return None."""
    if offset < 0 or offset + 20 > len(data):
        return None
    machine, sections, _stamp, _symbols, _nsyms, optional_size, _chars = \
        struct.unpack_from("<HHIIIHH", data, offset)
    if machine != COFF_MACHINE_I386 or not 1 <= sections <= MAX_COFF_SECTIONS:
        return None
    table_end = offset + 20 + optional_size + sections * 40
    if table_end > len(data):
        return None
    return {"offset": offset, "machine": "i386", "sections": sections,
            "size_of_optional_header": optional_size, "section_table_end": table_end}


def _secondary_finding(data: bytes) -> dict | None:
    secondary = _secondary_header(data)
    if secondary is None:
        return None
    kind, offset = secondary
    return _finding(kind, "identified", False, offset=offset,
                    basis="signature at the outer MZ e_lfanew pointer",
                    relationship="secondary header of the outer MZ executable")


def _packer_findings(data: bytes) -> list[dict]:
    findings = []
    if data[:2] in (b"MZ", b"ZM"):
        signature = data[LZEXE_OFFSET:LZEXE_OFFSET + 4]
        if signature in LZEXE_SIGNATURES:
            findings.append(_finding(
                "lzexe", "candidate", False, offset=LZEXE_OFFSET,
                basis=f"{signature.decode('ascii')} marker at file offset 0x1c "
                      "(fixed 32-byte LZEXE MZ header layout)"))
        if data[UPX_OFFSET:UPX_OFFSET + len(UPX_MARKER)] == UPX_MARKER:
            findings.append(_finding(
                "upx", "candidate", False, offset=UPX_OFFSET,
                basis="UPX marker at file offset 85 (file magic rule; verified against "
                      "a genuine UPX 5.2.1 dos/exe output)"))
    return findings


def identify(path: str | Path, fmt: str = "auto") -> dict:
    source = Path(path)
    data = _read_input(source)
    if fmt not in ("auto", "mz", "com"):
        raise DDTError("unknown format selection")

    findings: list[dict] = []
    mz = None
    mz_error = None
    secondary = None

    if fmt == "com":
        if not 1 <= len(data) <= MAX_COM_SIZE:
            raise DDTError("COM image must contain 1..65280 bytes")
        outer = "dos-com"
        findings.append(_finding("dos-com", "identified", True, offset=0, length=len(data)))
    else:
        secondary = _secondary_header(data)
        try:
            mz = parse_mz(data)
        except DDTError as exc:
            mz_error = str(exc)
        if mz is not None:
            outer = "dos-mz"
            findings.append(_finding("dos-mz", "identified", True, offset=0,
                                     length=mz.declared_file_bytes))
        elif secondary is not None:
            outer = "dos-mz"
            findings.append(_finding("dos-mz", "candidate", False, offset=0, basis=mz_error))
        else:
            outer = "unknown"
            findings.append(_finding("unknown", "unknown", False, basis=mz_error))

    if secondary is not None:
        findings.append(_secondary_finding(data))

    coff = None
    anchors = [0] if mz is None else [0, mz.declared_file_bytes]
    for anchor in dict.fromkeys(anchors):
        if anchor < 0 or anchor >= len(data):
            continue
        coff = _coff_image(data, anchor)
        if coff is not None:
            findings.append(_finding(
                "i386-coff", "identified", False, offset=anchor,
                basis="bounds-validated i386 COFF file header and section table",
                loader_identity="unknown"))
            break
    if coff is not None and coff["offset"] == 0 and outer == "unknown":
        outer = "i386-coff"

    if mz is not None and data[mz.header_bytes:mz.header_bytes + len(GO32_MARKER)] == GO32_MARKER:
        findings.append(_finding(
            "go32-stub", "candidate", False, offset=mz.header_bytes,
            basis="go32stub marker at the MZ load-image start (DJGPP go32 v2 stub layout)",
            loader_identity="unknown"))

    findings.extend(_packer_findings(data))

    appended = None
    if mz is not None and mz.overlay_bytes > 0:
        start = mz.declared_file_bytes
        recognized = None
        if secondary is not None and secondary[1] == start:
            recognized = secondary[0]
        elif coff is not None and coff["offset"] == start:
            recognized = "i386-coff"
        appended = {"start": start, "length": mz.overlay_bytes,
                    "recognized_structure": recognized, "purpose": "unknown"}

    return {"schema": SCHEMA, "source": {"name": source.name, "size": len(data),
                                         "sha256": hashlib.sha256(data).hexdigest()},
            "outer_format": outer, "findings": findings,
            "mz": None if mz is None else mz.to_dict(),
            "appended": appended, "limits": list(_LIMITS)}
