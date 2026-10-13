"""Strict DOS MZ/COM inventory. Does not execute, disassemble or unpack binaries."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

from .errors import DDTError

MAX_INPUT = 64 * 1024 * 1024
MAX_COM_SIZE = 65280


def _read_input(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise DDTError("input must be an ordinary file, not a symlink")
    if path.stat().st_size > MAX_INPUT:
        raise DDTError("input exceeds current 64 MiB safety limit")
    return path.read_bytes()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_SECONDARY_MIN_HEADER = {"ne": 0x40, "le": 0x14, "lx": 0x14, "pe": 24}
_LE_CPU_TYPES = frozenset({1, 2, 3, 4, 0x20, 0x21, 0x40, 0x41, 0x42})
_LE_OS_TYPES = (1, 2, 3, 4, 5)


def _secondary_kind(data: bytes) -> tuple[str, int] | None:
    """Return (kind, file_offset) when a secondary signature sits at e_lfanew."""
    if len(data) < 64 or data[:2] not in (b"MZ", b"ZM"):
        return None
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if 64 <= offset <= len(data) - 2 and data[offset:offset + 2] in (b"NE", b"LE", b"LX"):
        return data[offset:offset + 2].decode("ascii").lower(), offset
    if 64 <= offset <= len(data) - 4 and data[offset:offset + 4] == b"PE\x00\x00":
        return "pe", offset
    return None


def _classify_ne(data: bytes, offset: int) -> tuple[str, str]:
    segments = struct.unpack_from("<H", data, offset + 0x1C)[0]
    table = struct.unpack_from("<H", data, offset + 0x22)[0]
    if segments < 1:
        return "candidate", "NE signature with no declared segments"
    if table < 0x40 or offset + table + segments * 8 > len(data):
        return "candidate", "NE segment table is out of bounds"
    return "identified", "NE header with an in-bounds segment table"


def _classify_le_lx(data: bytes, offset: int, kind: str) -> tuple[str, str]:
    label = kind.upper()
    if struct.unpack_from("<H", data, offset + 2)[0] != 0:
        return "candidate", f"{label} signature without the little-endian marker"
    cpu = struct.unpack_from("<H", data, offset + 8)[0]
    os_type = struct.unpack_from("<H", data, offset + 0x0A)[0]
    if cpu in _LE_CPU_TYPES and os_type in _LE_OS_TYPES:
        return "identified", f"{label} header with documented CPU and OS fields"
    return "candidate", f"{label} signature with undocumented CPU or OS fields"


def _classify_pe(data: bytes, offset: int) -> tuple[str, str]:
    sections = struct.unpack_from("<H", data, offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, offset + 20)[0]
    magic = struct.unpack_from("<H", data, offset + 24)[0]
    if optional_size <= 95 or magic not in (0x10B, 0x20B):
        return "candidate", "PE signature without a recognised Windows COFF optional header"
    if sections < 1 or offset + 24 + optional_size + sections * 40 > len(data):
        return "candidate", "PE section table is out of bounds"
    return "identified", "PE header with a recognised optional header and in-bounds section table"


def secondary_status(data: bytes) -> dict | None:
    """Classify a secondary executable header reached through e_lfanew.

    Returns ``{kind, offset, classification, basis}`` or None when no secondary
    signature is present. A signature alone is never treated as an established
    header: insufficient or inconsistent structures stay ``unknown``/``candidate``.
    """
    found = _secondary_kind(data)
    if found is None:
        return None
    kind, offset = found
    if offset + _SECONDARY_MIN_HEADER[kind] > len(data):
        return {"kind": kind, "offset": offset, "classification": "unknown",
                "basis": f"{kind.upper()} signature with insufficient header bytes"}
    if kind == "ne":
        classification, basis = _classify_ne(data, offset)
    elif kind == "pe":
        classification, basis = _classify_pe(data, offset)
    else:
        classification, basis = _classify_le_lx(data, offset, kind)
    return {"kind": kind, "offset": offset, "classification": classification, "basis": basis}


def _secondary_header(data: bytes) -> tuple[str, int] | None:
    """Return (kind, file_offset) only when a secondary header is structurally established."""
    status = secondary_status(data)
    if status is not None and status["classification"] == "identified":
        return status["kind"], status["offset"]
    return None


@dataclass(frozen=True)
class MZ:
    source_size: int
    sha256: str
    header_bytes: int
    declared_file_bytes: int
    image_bytes: int
    overlay_bytes: int
    entry_cs: int
    entry_ip: int
    initial_ss: int
    initial_sp: int
    min_extra_paragraphs: int
    max_extra_paragraphs: int
    relocation_table_offset: int
    relocations: tuple[tuple[int, int], ...]

    def to_dict(self) -> dict:
        return {
            "format": "dos-mz", "source_size": self.source_size,
            "sha256": self.sha256, "header_bytes": self.header_bytes,
            "declared_file_bytes": self.declared_file_bytes,
            "initialized_image_bytes": self.image_bytes,
            "overlay_bytes": self.overlay_bytes,
            "entry": {"cs_relative": self.entry_cs, "ip": self.entry_ip},
            "initial_stack": {"ss_relative": self.initial_ss, "sp": self.initial_sp},
            "allocation": {"min_extra_paragraphs": self.min_extra_paragraphs, "max_extra_paragraphs": self.max_extra_paragraphs},
            "relocation_table_offset": self.relocation_table_offset,
            "relocations": [
                {"segment_relative": seg, "offset": off,
                 "image_offset": seg * 16 + off,
                 "within_initialized_image": (seg * 16 + off + 2 <= self.image_bytes)}
                for off, seg in self.relocations
            ],
            "limits": ["No DOS loader execution or runtime segment observation",
                       "Relocations listed, not applied to original bytes",
                       "Overlay is not an initialized MZ load module"],
        }

    def image_to_file(self, offset: int) -> int:
        if not 0 <= offset < self.image_bytes:
            raise DDTError("address is outside initialized MZ load module")
        return self.header_bytes + offset


@dataclass(frozen=True)
class COM:
    source_size: int
    sha256: str

    def to_dict(self) -> dict:
        return {
            "format": "dos-com", "source_size": self.source_size,
            "sha256": self.sha256, "entry_offset": 0x100,
            "loaded_offset_start": 0x100,
            "loaded_offset_end_exclusive": 0x100 + self.source_size,
            "limits": ["Headerless COM interpretation explicitly selected",
                       "PSP, runtime segment and stack contents not observed"],
        }

    def segment_offset_to_file(self, segment: int, offset: int) -> int:
        if segment != 0:
            raise DDTError("COM file mapping uses relative segment 0 (actual runtime segment unknown)")
        if not 0x100 <= offset < 0x100 + self.source_size:
            raise DDTError("address is outside initialized COM image")
        return offset - 0x100


def parse_mz(data: bytes) -> MZ:
    """Validate and parse a DOS MZ image; raise DDTError when it is not a clean MZ."""
    if len(data) < 28 or data[:2] not in (b"MZ", b"ZM"):
        raise DDTError("MZ header missing; select --format com explicitly for COM images")
    fields = struct.unpack_from("<14H", data)
    (_, last_page, pages, reloc_count, paras, minalloc, maxalloc,
     ss, sp, _checksum, ip, cs, rel_off, _overlay_no) = fields
    if pages < 1 or last_page >= 512 or paras < 2:
        raise DDTError("invalid DOS MZ page counts or header paragraph count")
    declared = (pages - 1) * 512 + (last_page if last_page else 512)
    header = paras * 16
    if declared < header or declared > len(data) or header > len(data):
        raise DDTError("declared MZ file size/header inconsistent with input")
    if rel_off > header or reloc_count * 4 > header - rel_off:
        raise DDTError("MZ relocation table exceeds DOS header")
    relocations = tuple(struct.unpack_from("<HH", data, rel_off + i * 4) for i in range(reloc_count))
    return MZ(len(data), _digest(data), header, declared, declared - header,
              len(data) - declared, cs, ip, ss, sp, minalloc, maxalloc,
              rel_off, relocations)


def inspect(path: Path, fmt: str = "auto") -> MZ | COM:
    data = _read_input(path)
    if fmt not in ("auto", "mz", "com"):
        raise DDTError("unknown format selection")
    if fmt == "com":
        if not 1 <= len(data) <= MAX_COM_SIZE:
            raise DDTError("COM image must contain 1..65280 bytes")
        return COM(len(data), _digest(data))
    secondary = _secondary_header(data)
    if secondary is not None:
        kind, _ = secondary
        raise DDTError("PE executable, not supported as a real-mode DOS MZ target" if kind == "pe"
                       else "NE/LE/LX executable, not supported as a real-mode DOS MZ target")
    return parse_mz(data)


def map_address(target: MZ | COM, segment: int, offset: int) -> dict:
    if not (0 <= segment <= 0xFFFF and 0 <= offset <= 0xFFFF):
        raise DDTError("16-bit segment and offset must each fit in 0..65535")
    if isinstance(target, COM):
        file_offset = target.segment_offset_to_file(segment, offset)
        return {"format": "dos-com", "relative_segment": segment,
                "offset": offset, "file_offset": file_offset,
                "note": "Relative COM image mapping; runtime segment and PSP are not observed"}
    image_offset = segment * 16 + offset
    file_offset = target.image_to_file(image_offset)
    return {"format": "dos-mz", "relative_segment": segment,
            "offset": offset, "module_image_offset": image_offset,
            "file_offset": file_offset,
            "note": "Relative to MZ load module, NOT an observed runtime segmented address"}
