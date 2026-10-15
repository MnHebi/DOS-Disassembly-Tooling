from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from ddt.errors import DDTError
from ddt.linexec import extract_le_bytes, inspect_le

LE_OFFSET = 0x40
LE_HEADER_BYTES = 0xB0
OBJECT_RECORD_BYTES = 24
PAGE_MAP_ENTRY_BYTES = 4
DATA_PAGES_OFFSET = 0x110


def _encode_page(page_number: int, flags: int = 0) -> int:
    # 24-bit big-endian page number in the low three bytes, flags in the fourth.
    encoded = ((page_number & 0xFF) << 16) | (((page_number >> 8) & 0xFF) << 8) | (page_number >> 16)
    return (encoded & 0x00FFFFFF) | (flags << 24)


def _le_image(*, signature=b"LE", cpu=2, os_type=1, page_size=0x1000, page_count=2,
              last_page_size=0x40, object_table_offset=LE_HEADER_BYTES,
              page_map_offset=LE_HEADER_BYTES + OBJECT_RECORD_BYTES,
              data_pages_offset=DATA_PAGES_OFFSET, entry_object=1, entry_offset=0x40,
              pages=(1, 2), page_flags=(0, 0), virtual_size=0x80, object_page_count=2,
              order_bytes=b"\x00\x00\x00\x00\x00\x00") -> bytes:
    """Build a minimal MZ-hosted LE image from literal, hand-chosen field values."""
    data_pages_end = data_pages_offset + (page_count - 1) * page_size + last_page_size
    data = bytearray(max(data_pages_end, LE_OFFSET + LE_HEADER_BYTES + object_table_offset))
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
        flags = page_flags[index] if index < len(page_flags) else 0
        struct.pack_into("<I", data, LE_OFFSET + page_map_offset + index * PAGE_MAP_ENTRY_BYTES,
                         _encode_page(page_number, flags))
    for offset in range(data_pages_offset, len(data)):
        data[offset] = (offset * 3 + 1) & 0xFF
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
        "data_pages_offset": DATA_PAGES_OFFSET, "preload_page_count": 0, "auto_data_object": 0,
        "stack_size": 0x10000}
    assert record["objects"] == [{
        "index": 1, "virtual_size": 0x80, "relocation_base": 0x10000, "flags": 0x2045,
        "page_map_index": 1, "page_count": 2,
        "pages": [{"page_number": 1, "flags": 0, "page_type": "valid",
                   "file_offset": 0x110, "file_bytes": 0x1000},
                  {"page_number": 2, "flags": 0, "page_type": "valid",
                   "file_offset": 0x1110, "file_bytes": 0x40}]}]
    assert "no direct file image" in " ".join(record["limits"])


def test_entry_resolves_to_original_file_offset(tmp_path):
    record = inspect_le(_write(tmp_path, _le_image(entry_offset=0x44)))
    assert record["entry"] == {"object": 1, "offset": 0x44, "page_type": "valid",
                               "file_offset": 0x154, "mapped_to_file": True}


@pytest.mark.parametrize("flags,kind", [(1, "iterated"), (2, "invalid"), (3, "zeroed"),
                                        (4, "range"), (5, "compressed")])
def test_nonphysical_page_types_keep_raw_number_and_get_no_file_offset(tmp_path, flags, kind):
    record = inspect_le(_write(tmp_path, _le_image(page_flags=(0, flags))))
    page = record["objects"][0]["pages"][1]
    assert page["page_type"] == kind
    assert page["page_number"] == 2      # raw entry preserved, not interpreted as a page
    assert page["file_offset"] is None
    assert page["file_bytes"] is None


def test_non_file_backed_entry_is_not_given_a_file_offset(tmp_path):
    record = inspect_le(_write(tmp_path, _le_image(entry_offset=0x1040, virtual_size=0x2000,
                                                   page_flags=(0, 3))))
    assert record["entry"]["page_type"] == "zeroed"
    assert record["entry"]["file_offset"] is None
    assert record["entry"]["mapped_to_file"] is False


def test_short_final_page_tail_has_no_file_offset(tmp_path):
    # 0x1020 is inside the object and inside its mapped last page, but past the 0x40
    # bytes that page actually occupies in the file.
    record = inspect_le(_write(tmp_path, _le_image(entry_offset=0x1020, virtual_size=0x2000)))
    assert record["entry"]["mapped_to_file"] is True
    record = inspect_le(_write(tmp_path, _le_image(entry_offset=0x1060, virtual_size=0x2000)))
    assert record["entry"]["page_type"] == "valid"
    assert record["entry"]["file_offset"] is None
    assert record["entry"]["mapped_to_file"] is False


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


def test_extracts_bytes_from_an_ordinary_page(tmp_path):
    image = _le_image(virtual_size=0x2000)
    record = extract_le_bytes(_write(tmp_path, image), 1, 0x40, 4)
    assert record["schema"] == "ddt.le-bytes.v1"
    assert record["file_offset"] == 0x150
    assert record["bytes_hex"] == bytes((0x150 + i) * 3 + 1 & 0xFF for i in range(4)).hex().upper()
    assert record["page_map_index"] == 1
    assert record["page_number"] == 1
    assert record["page_type"] == "valid"
    assert record["object_page_bytes"] == 0x1000
    assert record["length"] == 4


def test_extracts_from_the_short_final_page(tmp_path):
    record = extract_le_bytes(_write(tmp_path, _le_image(virtual_size=0x2000)), 1, 0x1020, 0x10)
    assert record["file_offset"] == 0x1130
    assert record["page_number"] == 2
    assert record["object_page_bytes"] == 0x40


def test_extraction_rejects_bounds_and_unsupported_pages(tmp_path):
    ordinary = _write(tmp_path, _le_image(virtual_size=0x2000))
    with pytest.raises(DDTError, match="span more than one object page"):
        extract_le_bytes(ordinary, 1, 0xFF8, 16)
    with pytest.raises(DDTError, match="initialized file extent"):
        extract_le_bytes(ordinary, 1, 0x1035, 0x10)     # last page holds only 0x40 bytes
    with pytest.raises(DDTError, match="outside object 1's mapped pages"):
        extract_le_bytes(_write(tmp_path, _le_image(virtual_size=0x3000)), 1, 0x2000, 1)
    with pytest.raises(DDTError, match="outside object 1's virtual size"):
        extract_le_bytes(_write(tmp_path, _le_image()), 1, 0x80, 1)
    with pytest.raises(DDTError, match="outside the object table"):
        extract_le_bytes(ordinary, 2, 0, 1)
    with pytest.raises(DDTError, match="1\\.\\.256"):
        extract_le_bytes(ordinary, 1, 0, 0)
    with pytest.raises(DDTError, match="1\\.\\.256"):
        extract_le_bytes(ordinary, 1, 0, 257)
    with pytest.raises(DDTError, match="1-based integer"):
        extract_le_bytes(ordinary, 0, 0, 1)
    with pytest.raises(DDTError, match="nonnegative integer"):
        extract_le_bytes(ordinary, 1, -1, 1)


@pytest.mark.parametrize("flags,kind", [(1, "iterated"), (3, "zeroed"), (4, "range")])
def test_extraction_refuses_non_file_backed_pages(tmp_path, flags, kind):
    path = _write(tmp_path, _le_image(virtual_size=0x2000, page_flags=(flags, 0)))
    with pytest.raises(DDTError, match=f"'{kind}' and has no direct file image"):
        extract_le_bytes(path, 1, 0, 1)


def test_extraction_rejects_a_file_that_no_longer_covers_the_page(tmp_path):
    path = _write(tmp_path, _le_image(virtual_size=0x2000))
    data = bytearray(path.read_bytes())
    del data[-4:]                      # the file no longer covers page 2's full extent
    path.write_bytes(bytes(data))
    with pytest.raises(DDTError, match="past the end of the file"):
        extract_le_bytes(path, 1, 0x1020, 0x10)


def test_extraction_does_not_modify_the_source(tmp_path):
    path = _write(tmp_path, _le_image(virtual_size=0x2000))
    before = path.read_bytes()
    extract_le_bytes(path, 1, 0x40, 4)
    assert path.read_bytes() == before


def _dev_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_cli_reports_le_header_and_bytes_schemas(tmp_path):
    path = _write(tmp_path, _le_image(virtual_size=0x2000))
    header = subprocess.run([sys.executable, "-m", "ddt", "le-header", str(path), "--json"],
                            check=True, capture_output=True, text=True, env=_dev_env())
    payload = json.loads(header.stdout)
    assert payload["schema"] == "ddt.le-header.v1"
    assert payload["entry"]["file_offset"] == 0x150
    extracted = subprocess.run([sys.executable, "-m", "ddt", "le-bytes", str(path),
                                "--object", "1", "--offset", "0x40", "--length", "4", "--json"],
                               check=True, capture_output=True, text=True, env=_dev_env())
    payload = json.loads(extracted.stdout)
    assert payload["schema"] == "ddt.le-bytes.v1"
    assert payload["file_offset"] == 0x150
    assert payload["bytes_hex"] == bytes((0x150 + i) * 3 + 1 & 0xFF for i in range(4)).hex().upper()
