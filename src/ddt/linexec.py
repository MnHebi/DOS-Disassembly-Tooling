"""Read-only structural inspection of an LE (linear executable) DOS image.

Only the validated LE header, object table and object page map are reported.
Nothing is loaded, relocated, decompressed or executed, and an original-file
offset is never presented as a runtime ``segment:offset`` address.
"""
from __future__ import annotations

import struct
from pathlib import Path

from .errors import DDTError
from .format import _LE_CPU_TYPES, _LE_OS_TYPES, _digest, _read_input

SCHEMA = "ddt.le-header.v1"
LE_HEADER_BYTES = 0xB0
OBJECT_RECORD_BYTES = 24
PAGE_MAP_ENTRY_BYTES = 4
MIN_PAGE_SIZE = 0x200
MAX_PAGES = 65536
MAX_OBJECTS = 4096

_LIMITS = [
    "LE header, object table and object page map only; no load, relocation, "
    "decompression or execution is performed",
    "Offsets are original-file offsets, never runtime segment:offset addresses",
    "The LE/LX OS type field is not a reliable identifier of a specific DOS extender",
    "LX headers are recognised by ddt identify but are not inspected here",
    "The entry file offset is a page-map derivation, not an observed runtime address",
]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _header_offset(data: bytes) -> int:
    if len(data) < 0x40 or data[:2] not in (b"MZ", b"ZM"):
        raise DDTError("LE inspection requires a DOS MZ image hosting the LE header")
    offset = _u32(data, 0x3C)
    if not 0x40 <= offset <= len(data) - 2:
        raise DDTError("MZ e_lfanew does not point inside the file")
    signature = data[offset:offset + 2]
    if signature == b"LX":
        raise DDTError("LX linear executables are recognised but not inspected (no verified fixture)")
    if signature != b"LE":
        raise DDTError("no LE header at the MZ e_lfanew offset")
    return offset


def _page_map_entry(data: bytes, offset: int) -> tuple[int, int]:
    """Decode one LE page-map entry: a 24-bit big-endian page number plus flags."""
    raw = _u32(data, offset)
    page = ((raw & 0xFF) << 16) | (((raw >> 8) & 0xFF) << 8) | ((raw >> 16) & 0xFF)
    return page, (raw >> 24) & 0xFF


def _file_page_offset(data_pages_offset: int, page_size: int, page_number: int) -> int:
    return data_pages_offset + (page_number - 1) * page_size


def _file_page_bytes(page_number: int, page_count: int, page_size: int, last_page_size: int) -> int:
    """Bytes occupied in the file by file page ``page_number`` (the last one may be short)."""
    return last_page_size if page_number == page_count else page_size


def inspect_le(path: str | Path) -> dict:
    data = _read_input(Path(path))
    le = _header_offset(data)
    if le + LE_HEADER_BYTES > len(data):
        raise DDTError("LE header extends past the end of the file")
    if any(data[le + 2:le + 8]):
        raise DDTError("LE byte order, word order or format level is not the documented zero")
    cpu_type = _u16(data, le + 0x08)
    os_type = _u16(data, le + 0x0A)
    if cpu_type not in _LE_CPU_TYPES:
        raise DDTError(f"LE header declares an undocumented CPU type 0x{cpu_type:04X}")
    if os_type not in _LE_OS_TYPES:
        raise DDTError(f"LE header declares an undocumented OS type 0x{os_type:04X}")
    page_size = _u32(data, le + 0x28)
    if page_size < MIN_PAGE_SIZE or page_size & (page_size - 1):
        raise DDTError("LE page size must be a power of two of at least 512 bytes")
    page_count = _u32(data, le + 0x14)
    if not 1 <= page_count <= MAX_PAGES:
        raise DDTError("LE module page count is outside the supported range")
    last_page_size = _u32(data, le + 0x2C)
    if not 1 <= last_page_size <= page_size:
        raise DDTError("LE last page size is inconsistent with the page size")
    object_table_offset = _u32(data, le + 0x40)
    object_count = _u32(data, le + 0x44)
    if not 1 <= object_count <= MAX_OBJECTS:
        raise DDTError("LE object count is outside the supported range")
    if le + object_table_offset + object_count * OBJECT_RECORD_BYTES > len(data):
        raise DDTError("LE object table extends past the end of the file")
    page_map_offset = _u32(data, le + 0x48)
    if le + page_map_offset + page_count * PAGE_MAP_ENTRY_BYTES > len(data):
        raise DDTError("LE object page map extends past the end of the file")
    data_pages_offset = _u32(data, le + 0x80)
    if data_pages_offset > len(data):
        raise DDTError("LE data pages offset is past the end of the file")
    objects = []
    for index in range(object_count):
        size, reloc, flags, map_index, pages, _reserved = struct.unpack_from(
            "<6I", data, le + object_table_offset + index * OBJECT_RECORD_BYTES)
        if map_index < 1 or pages < 1:
            raise DDTError(f"LE object {index + 1} has an empty page map range")
        if map_index - 1 + pages > page_count:
            raise DDTError(f"LE object {index + 1} page range exceeds the module page map")
        object_pages = []
        for page_index in range(pages):
            page_number, page_flags = _page_map_entry(
                data, le + page_map_offset + (map_index - 1 + page_index) * PAGE_MAP_ENTRY_BYTES)
            file_offset = None
            if page_number:
                if page_number > page_count:
                    raise DDTError(f"LE page map references page {page_number} beyond the module")
                file_offset = _file_page_offset(data_pages_offset, page_size, page_number)
                if file_offset + _file_page_bytes(page_number, page_count, page_size,
                                                  last_page_size) > len(data):
                    raise DDTError(f"LE page {page_number} lies past the end of the file")
            object_pages.append({"page_number": page_number, "flags": page_flags,
                                 "file_offset": file_offset})
        objects.append({"index": index + 1, "virtual_size": size, "relocation_base": reloc,
                        "flags": flags, "page_map_index": map_index, "page_count": pages,
                        "pages": object_pages})
    entry_object = _u32(data, le + 0x18)
    entry_offset = _u32(data, le + 0x1C)
    stack_object = _u32(data, le + 0x20)
    stack_offset = _u32(data, le + 0x24)
    auto_data_object = _u32(data, le + 0x94)
    if not 1 <= entry_object <= object_count:
        raise DDTError("LE entry object number is outside the object table")
    if not 1 <= stack_object <= object_count:
        raise DDTError("LE stack object number is outside the object table")
    if auto_data_object > object_count:
        raise DDTError("LE automatic data object number is outside the object table")
    entry = objects[entry_object - 1]
    entry_page_index = entry_offset // page_size
    if entry_offset >= entry["virtual_size"] or entry_page_index >= entry["page_count"]:
        raise DDTError("LE entry offset is outside the entry object's mapped pages")
    entry_page = entry["pages"][entry_page_index]
    entry_file_offset = None
    if entry_page["page_number"]:
        entry_file_offset = _file_page_offset(data_pages_offset, page_size,
                                              entry_page["page_number"]) + entry_offset % page_size
    return {
        "schema": SCHEMA,
        "source_size": len(data),
        "sha256": _digest(data),
        "container": {
            "outer_format": "dos-mz",
            "mz_stub_bytes": le,
            "le_header_offset": le,
            "le_header_bytes": LE_HEADER_BYTES,
            "signature": "LE",
        },
        "header": {
            "byte_order": data[le + 2],
            "word_order": data[le + 3],
            "cpu_type": cpu_type,
            "os_type": os_type,
            "module_version": _u32(data, le + 0x0C),
            "module_flags": _u32(data, le + 0x10),
            "page_count": page_count,
            "page_size": page_size,
            "last_page_size": last_page_size,
            "entry_object": entry_object,
            "entry_offset": entry_offset,
            "stack_object": stack_object,
            "stack_offset": stack_offset,
            "object_table_offset": object_table_offset,
            "object_count": object_count,
            "page_map_offset": page_map_offset,
            "data_pages_offset": data_pages_offset,
            "preload_page_count": _u32(data, le + 0x84),
            "auto_data_object": auto_data_object,
            "stack_size": _u32(data, le + 0xAC),
        },
        "objects": objects,
        "entry": {
            "object": entry_object,
            "offset": entry_offset,
            "file_offset": entry_file_offset,
            "mapped_to_file": entry_file_offset is not None,
        },
        "limits": _LIMITS,
    }
