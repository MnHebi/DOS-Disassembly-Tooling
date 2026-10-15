from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from ddt.errors import DDTError
from ddt.linexec import inspect_le

LE_OFFSET = 0x40
LE_HEADER_BYTES = 0xB0
OBJECT_RECORD_BYTES = 24
PAGE_MAP_ENTRY_BYTES = 4


def _le_image(*, signature=b"LE", cpu=2, os_type=1, page_size=0x1000, page_count=2,
              last_page_size=0x40, object_table_offset=LE_HEADER_BYTES,
              page_map_offset=LE_HEADER_BYTES + OBJECT_RECORD_BYTES, data_pages_offset=0x110,
              entry_object=1, entry_offset=0x40, pages=(1, 2), virtual_size=0x80,
              object_page_count=2, order_bytes=b"\x00\x00\x00\x00\x00\x00") -> bytes:
    """Build a minimal MZ-hosted LE image from literal, hand-chosen field values."""
    data_pages_end = data_pages_offset + (page_count - 1) * page_size + last_page_size
    data = bytearray(max(data_pages_end, LE_OFFSET + 0xB0 + OBJECT_RECORD_BYTES))
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, LE_OFFSET)
    header = bytearray(LE_HEADER_BYTES)
    header[0:2] = signature
    header[2:8] = order_bytes
    struct.pack_into("<H", header, 0x08, cpu)
    struct.pack_into("<H", header, 0x0A, os_type)
    struct.pack_into("<I", header, 0x10, 0x200)          # module flags
    struct.pack_into("<I", header, 0x14, page_count)
    struct.pack_into("<I", header, 0x18, entry_object)
    struct.pack_into("<I", header, 0x1C, entry_offset)
    struct.pack_into("<I", header, 0x20, 1)              # stack object
    struct.pack_into("<I", header, 0x24, 0x100)          # stack offset
    struct.pack_into("<I", header, 0x28, page_size)
    struct.pack_into("<I", header, 0x2C, last_page_size)
    struct.pack_into("<I", header, 0x40, object_table_offset)
    struct.pack_into("<I", header, 0x44, 1)              # one object
    struct.pack_into("<I", header, 0x48, page_map_offset)
    struct.pack_into("<I", header, 0x80, data_pages_offset)
    struct.pack_into("<I", header, 0xAC, 0x10000)        # stack size
    data[LE_OFFSET:LE_OFFSET + LE_HEADER_BYTES] = header
    struct.pack_into("<6I", data, LE_OFFSET + object_table_offset,
                     virtual_size, 0x10000, 0x2045, 1, object_page_count, 0)
    for index, page_number in enumerate(pages):
        raw = ((page_number & 0xFF) << 16) | (((page_number >> 8) & 0xFF) << 8) | (page_number >> 16)
        struct.pack_into("<I", data, LE_OFFSET + page_map_offset + index * PAGE_MAP_ENTRY_BYTES,
                         raw)
    return bytes(data)


def _patched(image: bytes, header_offset: int, value: int) -> bytes:
    data = bytearray(image)
    struct.pack_into("<I", data, LE_OFFSET + header_offset, value)
    return bytes(data)


def _write(tmp_path, data: bytes):
    path = tmp_path / "linear.exe"
    path.write_bytes(data)
    return path


def test_parses_documented_le_fields_and_file_extents(tmp_path):
    image = _le_image()
    record = inspect_le(_write(tmp_path, image))
    assert record["schema"] == "ddt.le-header.v1"
    assert record["source_size"] == len(image)
    assert record["container"] == {"outer_format": "dos-mz", "mz_stub_bytes": LE_OFFSET,
                                   "le_header_offset": LE_OFFSET, "le_header_bytes": LE_HEADER_BYTES,
                                   "signature": "LE"}
    assert record["header"] == {
        "byte_order": 0, "word_order": 0, "cpu_type": 2, "os_type": 1, "module_version": 0,
        "module_flags": 0x200, "page_count": 2, "page_size": 0x1000, "last_page_size": 0x40,
        "entry_object": 1, "entry_offset": 0x40, "stack_object": 1, "stack_offset": 0x100,
        "object_table_offset": LE_HEADER_BYTES, "object_count": 1,
        "page_map_offset": LE_HEADER_BYTES + OBJECT_RECORD_BYTES,
        "data_pages_offset": 0x110, "preload_page_count": 0, "auto_data_object": 0,
        "stack_size": 0x10000}
    assert record["objects"] == [{
        "index": 1, "virtual_size": 0x80, "relocation_base": 0x10000, "flags": 0x2045,
        "page_map_index": 1, "page_count": 2,
        "pages": [{"page_number": 1, "flags": 0, "file_offset": 0x110},
                  {"page_number": 2, "flags": 0, "file_offset": 0x1110}]}]
    assert "never runtime segment:offset addresses" in " ".join(record["limits"])


def test_entry_resolves_to_original_file_offset(tmp_path):
    record = inspect_le(_write(tmp_path, _le_image(entry_offset=0x44)))
    assert record["entry"] == {"object": 1, "offset": 0x44, "file_offset": 0x154,
                               "mapped_to_file": True}


def test_rejects_last_page_extending_past_the_file(tmp_path):
    image = _le_image()
    with pytest.raises(DDTError, match="page 2 lies past the end"):
        inspect_le(_write(tmp_path, _patched(image, 0x2C, 0x41)))


def test_rejects_lx_and_non_le_containers(tmp_path):
    with pytest.raises(DDTError, match="LX linear executables"):
        inspect_le(_write(tmp_path, _le_image(signature=b"LX")))
    with pytest.raises(DDTError, match="no LE header"):
        inspect_le(_write(tmp_path, _le_image(signature=b"NE")))
    with pytest.raises(DDTError, match="requires a DOS MZ image"):
        inspect_le(_write(tmp_path, b"LE" + bytes(0x200)))


def test_rejects_big_endian_or_nonstandard_order_marker(tmp_path):
    with pytest.raises(DDTError, match="byte order, word order or format level"):
        inspect_le(_write(tmp_path, _le_image(order_bytes=b"\x01\x00\x00\x00\x00\x00")))


def test_rejects_undocumented_cpu_os_and_page_size(tmp_path):
    with pytest.raises(DDTError, match="undocumented CPU type"):
        inspect_le(_write(tmp_path, _le_image(cpu=0x7777)))
    with pytest.raises(DDTError, match="undocumented OS type"):
        inspect_le(_write(tmp_path, _le_image(os_type=0x7777)))
    with pytest.raises(DDTError, match="power of two"):
        inspect_le(_write(tmp_path, _le_image(page_size=0x1234)))
    with pytest.raises(DDTError, match="last page size"):
        inspect_le(_write(tmp_path, _le_image(last_page_size=0x2000)))


def test_rejects_tables_and_page_map_out_of_bounds(tmp_path):
    image = _le_image()
    with pytest.raises(DDTError, match="object table extends past"):
        inspect_le(_write(tmp_path, _patched(image, 0x40, 0x9000)))
    with pytest.raises(DDTError, match="page map extends past"):
        inspect_le(_write(tmp_path, _patched(image, 0x48, 0x9000)))
    with pytest.raises(DDTError, match="data pages offset is past"):
        inspect_le(_write(tmp_path, _patched(image, 0x80, 0x9000)))


def test_rejects_page_referencing_beyond_the_module(tmp_path):
    with pytest.raises(DDTError, match="references page 9 beyond the module"):
        inspect_le(_write(tmp_path, _le_image(pages=(1, 9))))


def test_rejects_object_and_entry_inconsistencies(tmp_path):
    with pytest.raises(DDTError, match="page range exceeds the module page map"):
        inspect_le(_write(tmp_path, _le_image(object_page_count=9)))
    with pytest.raises(DDTError, match="entry object number"):
        inspect_le(_write(tmp_path, _le_image(entry_object=3)))
    with pytest.raises(DDTError, match="entry offset is outside"):
        inspect_le(_write(tmp_path, _le_image(entry_offset=0x4000)))
    with pytest.raises(DDTError, match="entry offset is outside"):
        inspect_le(_write(tmp_path, _le_image(virtual_size=0x40, entry_offset=0x50)))


def _dev_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_cli_reports_le_header_schema(tmp_path):
    path = _write(tmp_path, _le_image())
    proc = subprocess.run([sys.executable, "-m", "ddt", "le-header", str(path), "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "ddt.le-header.v1"
    assert payload["entry"]["file_offset"] == 0x150
