"""Read-only structural inspection and bounded byte extraction for LE images.

Only the validated LE header, object table and object page map are used.
Nothing is loaded, relocated, decompressed or executed, and an original-file
offset is never presented as a runtime ``segment:offset`` address.
"""
from __future__ import annotations

import struct
from pathlib import Path

from .errors import DDTError
from .format import _LE_CPU_TYPES, _LE_OS_TYPES, _digest, _read_input

HEADER_SCHEMA = "ddt.le-header.v1"
BYTES_SCHEMA = "ddt.le-bytes.v1"
FIXUPS_SCHEMA = "ddt.le-fixups.v1"
LE_HEADER_BYTES = 0xB0
OBJECT_RECORD_BYTES = 24
PAGE_MAP_ENTRY_BYTES = 4
FIXUP_PAGE_ENTRY_BYTES = 4
MIN_FIXUP_RECORD_BYTES = 4
MIN_PAGE_SIZE = 0x200
MAX_PAGES = 65536
MAX_OBJECTS = 4096
MAX_EXTRACT_BYTES = 256

# LE page-map flag values (`bld/watcom/h/exeflat.h`: PAGE_VALID .. PAGE_RANGE) with the
# names OpenWatcom's `wdump` prints. Only PAGE_VALID pages hold an ordinary file image.
_PAGE_TYPES = {0: "valid", 1: "iterated", 2: "invalid", 3: "zeroed", 4: "range",
               5: "compressed", 6: "unknown", 7: "unknown", 8: "m3-packed"}

# LE fixup record fields (`bld/watcom/h/exeflat.h`, decoded as OpenWatcom's wdump does).
_SOURCE_TYPES = {0x00: "byte", 0x01: "undefined", 0x02: "segment", 0x03: "pointer32",
                 0x05: "offset16", 0x06: "pointer48", 0x07: "offset32",
                 0x08: "self_relative_offset32"}
_TARGET_TYPES = {0x00: "internal", 0x01: "import_ordinal", 0x02: "import_name",
                 0x03: "internal_via_entry"}
_SFLAG_LIST = 0x20
_TARGET_MASK = 0x03
_TFLAG_OFF_32BIT = 0x10
_TFLAG_OBJ_MOD_16BIT = 0x40

_HEADER_LIMITS = [
    "LE header, object table and object page map only; no load, relocation, "
    "decompression or execution is performed",
    "Offsets are original-file offsets, never runtime segment:offset addresses",
    "The LE/LX OS type field is not a reliable identifier of a specific DOS extender",
    "LX headers are recognised by ddt identify but are not inspected here",
    "A file offset is reported only for an ordinary file-backed (PAGE_VALID) page; "
    "iterated, zeroed, range, compressed and invalid pages have no direct file image",
    "The entry file offset is a page-map derivation, not an observed runtime address; "
    "the reported stack object and offset are raw header values, not verified file offsets",
]

_BYTES_LIMITS = [
    "Original-file byte extraction only: nothing is loaded, relocated, decompressed "
    "or executed, and memory is never written back into the executable",
    "The derived file offset is not a runtime address; the LE page map does not "
    "describe the loaded image's segment:offset form",
    "Only an ordinary file-backed (PAGE_VALID) page is extractable, and only within "
    "the bytes that actually exist in the file",
]

_FIXUP_LIMITS = [
    "Fixup records are encoded loader requests, not observed runtime state: DDT never "
    "applies them and never reports the value a loader would write",
    "A record's own file offset is not the file offset of the value it describes; "
    "source_file_offset is",
    "Only internal-reference records are decoded; any other record form stops decoding at "
    "its file offset and is reported as undecoded rather than guessed at",
    "The declared fixup-section size is reported but not used for bounds; the fixup page "
    "table's final entry bounds the record table and is checked against the file",
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


def _page_type(flags: int) -> str:
    return _PAGE_TYPES.get(flags, "unknown")


def _file_page_offset(data_pages_offset: int, page_size: int, page_number: int) -> int:
    return data_pages_offset + (page_number - 1) * page_size


def _file_page_bytes(page_number: int, page_count: int, page_size: int, last_page_size: int) -> int:
    """Bytes the page occupies in the file (the declared last page may be short)."""
    return last_page_size if page_number == page_count else page_size


def _parse(data: bytes) -> dict:
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
            kind = _page_type(page_flags)
            file_offset = None
            file_bytes = None
            if kind == "valid" and page_number:
                if page_number > page_count:
                    raise DDTError(f"LE page map references page {page_number} beyond the module")
                file_offset = _file_page_offset(data_pages_offset, page_size, page_number)
                file_bytes = _file_page_bytes(page_number, page_count, page_size, last_page_size)
                if file_offset + file_bytes > len(data):
                    raise DDTError(f"LE page {page_number} lies past the end of the file")
            object_pages.append({"page_number": page_number, "flags": page_flags,
                                 "page_type": kind, "file_offset": file_offset,
                                 "file_bytes": file_bytes})
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
    if entry_page["file_offset"] is not None:
        within = entry_offset % page_size
        if within < entry_page["file_bytes"]:
            entry_file_offset = entry_page["file_offset"] + within
    return {
        "schema": HEADER_SCHEMA,
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
            "page_type": entry_page["page_type"],
            "file_offset": entry_file_offset,
            "mapped_to_file": entry_file_offset is not None,
        },
        "limits": _HEADER_LIMITS,
    }


def inspect_le(path: str | Path) -> dict:
    """Validate and report an LE container's header, objects and page map."""
    return _parse(_read_input(Path(path)))


def extract_le_bytes(path: str | Path, object_index: int, offset: int, length: int) -> dict:
    """Extract bytes from one ordinary file-backed LE page; nothing is loaded."""
    if isinstance(object_index, bool) or not isinstance(object_index, int) or object_index < 1:
        raise DDTError("the LE object index must be a positive 1-based integer")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise DDTError("the LE object-relative offset must be a nonnegative integer")
    if isinstance(length, bool) or not isinstance(length, int) or not 1 <= length <= MAX_EXTRACT_BYTES:
        raise DDTError(f"the LE extraction length must be 1..{MAX_EXTRACT_BYTES} bytes")
    source = Path(path)
    data = _read_input(source)
    record = _parse(data)
    header = record["header"]
    if object_index > header["object_count"]:
        raise DDTError(f"LE object index {object_index} is outside the object table")
    target = record["objects"][object_index - 1]
    if offset >= target["virtual_size"]:
        raise DDTError(f"LE object-relative offset {offset} is outside object "
                       f"{object_index}'s virtual size")
    if offset + length > target["virtual_size"]:
        raise DDTError(f"the requested bytes extend past object {object_index}'s virtual size "
                       f"({target['virtual_size']} bytes)")
    page_size = header["page_size"]
    page_index = offset // page_size
    if (offset + length - 1) // page_size != page_index:
        raise DDTError("the requested LE bytes span more than one object page")
    if page_index >= target["page_count"]:
        raise DDTError(f"LE object-relative offset {offset} is outside object "
                       f"{object_index}'s mapped pages")
    page = target["pages"][page_index]
    if page["file_offset"] is None:
        raise DDTError(f"LE object {object_index} page {page_index + 1} is "
                       f"'{page['page_type']}' and has no direct file image")
    within = offset % page_size
    if within + length > page["file_bytes"]:
        raise DDTError(f"the requested bytes extend past the page's initialized file extent "
                       f"({page['file_bytes']} bytes)")
    file_offset = page["file_offset"] + within
    if file_offset + length > len(data):
        raise DDTError("the requested bytes extend past the end of the file")
    return {
        "schema": BYTES_SCHEMA,
        "source": {"path": str(source), "size": len(data), "sha256": record["sha256"]},
        "object": object_index,
        "object_offset": offset,
        "length": length,
        "page_map_index": target["page_map_index"] + page_index,
        "page_number": page["page_number"],
        "page_flags": page["flags"],
        "page_type": page["page_type"],
        "object_page_bytes": page["file_bytes"],
        "file_offset": file_offset,
        "bytes_hex": data[file_offset:file_offset + length].hex().upper(),
        "limits": _BYTES_LIMITS,
    }


def _fixup_page_owner(record: dict, page: int) -> tuple[dict, int] | None:
    for obj in record["objects"]:
        first = obj["page_map_index"] - 1
        if first <= page < first + obj["page_count"]:
            return obj, page - first
    return None


class _UnsupportedFixup(Exception):
    """A well-formed fixup record form this milestone does not decode."""


def _decode_fixup(data: bytes, cursor: int, end: int) -> dict:
    """Decode one internal-reference LE fixup record; return it with its end offset."""
    def need(position: int, width: int) -> None:
        if position + width > end:
            raise DDTError(f"the LE fixup record at file offset {cursor} is truncated")

    need(cursor, MIN_FIXUP_RECORD_BYTES)
    source_flags = data[cursor]
    flags = data[cursor + 1]
    if source_flags & _SFLAG_LIST:
        raise _UnsupportedFixup("list-form fixup records are not decoded")
    if flags & _TARGET_MASK:
        raise _UnsupportedFixup(f"{_TARGET_TYPES[flags & _TARGET_MASK]} fixup records are "
                                "not decoded")
    source_type = source_flags & 0x0F
    if source_type not in _SOURCE_TYPES:
        raise _UnsupportedFixup(f"fixup source type 0x{source_type:02X} is not decoded")
    source_offset = _u16(data, cursor + 2)
    position = cursor + 4
    if flags & _TFLAG_OBJ_MOD_16BIT:
        need(position, 2)
        target_object = _u16(data, position)
        position += 2
    else:
        need(position, 1)
        target_object = data[position]
        position += 1
    target_offset = None
    target_width = None
    if source_type != 0x02:                      # a segment fixup carries no target offset
        target_width = 4 if flags & _TFLAG_OFF_32BIT else 2
        need(position, target_width)
        target_offset = _u32(data, position) if target_width == 4 else _u16(data, position)
        position += target_width
    return {
        "file_offset": cursor,
        "bytes_hex": data[cursor:position].hex().upper(),
        "source_type": source_type,
        "source_type_name": _SOURCE_TYPES[source_type],
        "source_flags": source_flags,
        "source_offset": source_offset,
        "target_type": "internal",
        "target_object": target_object,
        "target_offset": target_offset,
        "target_offset_width": target_width,
        "target_object_16bit": bool(flags & _TFLAG_OBJ_MOD_16BIT),
    }, position
def inspect_le_fixups(path: str | Path, page: int) -> dict:
    """Report the validated fixup records of one logical LE page."""
    if isinstance(page, bool) or not isinstance(page, int) or page < 0:
        raise DDTError("the LE page index must be a nonnegative integer")
    source = Path(path)
    data = _read_input(source)
    record = _parse(data)
    le = record["container"]["le_header_offset"]
    header = record["header"]
    page_count = header["page_count"]
    if page >= page_count:
        raise DDTError(f"LE page index {page} is outside the module's {page_count} pages")
    section_size = _u32(data, le + 0x30)
    page_table_offset = _u32(data, le + 0x68)
    record_table_offset = _u32(data, le + 0x6C)
    if not page_table_offset:
        raise DDTError("the LE header declares no fixup page table")
    if page_table_offset > record_table_offset:
        raise DDTError("the LE fixup page table starts after the fixup record table")
    if record_table_offset - page_table_offset < (page_count + 1) * FIXUP_PAGE_ENTRY_BYTES:
        raise DDTError("the LE fixup page table is too small for the module's pages")
    record_table = le + record_table_offset
    if record_table > len(data):
        raise DDTError("the LE fixup record table offset is past the end of the file")
    offsets = [_u32(data, le + page_table_offset + index * FIXUP_PAGE_ENTRY_BYTES)
               for index in range(page_count + 1)]
    if any(later < earlier for earlier, later in zip(offsets, offsets[1:])):
        raise DDTError("the LE fixup page table entries are not monotonic")
    if record_table + offsets[-1] > len(data):
        raise DDTError("the LE fixup record table extends past the end of the file")
    start = record_table + offsets[page]
    end = record_table + offsets[page + 1]
    owner = _fixup_page_owner(record, page)
    page_entry = owner[0]["pages"][owner[1]] if owner else None
    page_file_offset = page_entry["file_offset"] if page_entry else None
    page_file_bytes = page_entry["file_bytes"] if page_entry else None
    records = []
    undecoded = None
    cursor = start
    while cursor < end:
        try:
            decoded, cursor = _decode_fixup(data, cursor, end)
        except _UnsupportedFixup as exc:
            undecoded = {"file_offset": cursor, "record_bytes": end - cursor, "reason": str(exc)}
            break
        within = False
        if page_file_offset is not None and decoded["source_offset"] < page_file_bytes:
            within = True
            decoded["source_file_offset"] = page_file_offset + decoded["source_offset"]
        else:
            decoded["source_file_offset"] = None
        decoded["source_within_page"] = within
        records.append(decoded)
    return {
        "schema": FIXUPS_SCHEMA,
        "source": {"path": str(source), "size": len(data), "sha256": record["sha256"]},
        "fixup_tables": {
            "section_size": section_size,
            "page_table_offset": page_table_offset,
            "record_table_offset": record_table_offset,
            "page_table_file_offset": le + page_table_offset,
            "record_table_file_offset": record_table,
            "record_table_file_end": record_table + offsets[-1],
            "page_entry_count": page_count + 1,
        },
        "page": {
            "index": page,
            "index_convention": "zero-based logical page index, matching the fixup page "
                                "table entries",
            "object": owner[0]["index"] if owner else None,
            "object_page": owner[1] if owner else None,
            "page_map_index": owner[0]["page_map_index"] + owner[1] if owner else None,
            "page_number": page_entry["page_number"] if page_entry else None,
            "page_type": page_entry["page_type"] if page_entry else None,
            "page_file_offset": page_file_offset,
            "page_file_bytes": page_file_bytes,
            "record_table_offset": offsets[page],
            "record_table_end": offsets[page + 1],
        },
        "records": records,
        "record_count": len(records),
        "undecoded": undecoded,
        "limits": _FIXUP_LIMITS,
    }
