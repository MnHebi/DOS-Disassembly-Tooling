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


def inspect(path: Path, fmt: str = "auto") -> MZ | COM:
    data = _read_input(path)
    if fmt not in ("auto", "mz", "com"):
        raise DDTError("unknown format selection")
    if fmt == "com":
        if not 1 <= len(data) <= MAX_COM_SIZE:
            raise DDTError("COM image must contain 1..65280 bytes")
        return COM(len(data), _digest(data))
    if len(data) < 28 or data[:2] not in (b"MZ", b"ZM"):
        raise DDTError("MZ header missing; select --format com explicitly for COM images")
    if len(data) >= 64:
        candidate = struct.unpack_from("<I", data, 0x3c)[0]
        if 64 <= candidate <= len(data) - 2 and data[candidate:candidate + 2] in (b"NE", b"LE", b"LX"):
            raise DDTError("NE/LE/LX executable, not supported as a real-mode DOS MZ target")
        if 64 <= candidate <= len(data) - 4 and data[candidate:candidate + 4] == b"PE\x00\x00":
            raise DDTError("PE executable, not supported as a real-mode DOS MZ target")
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
