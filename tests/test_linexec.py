from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from ddt.errors import DDTError
from ddt.linexec import extract_le_bytes, inspect_le, inspect_le_fixups

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


def _record(source: int, flags: int, source_offset: int, object_index: int | None = None,
            target_offset: int | None = None) -> bytes:
    """Encode one synthetic LE fixup record (no list form)."""
    body = bytes([source, flags]) + struct.pack("<H", source_offset)
    if object_index is not None:
        body += (struct.pack("<H", object_index) if flags & 0x40 else bytes([object_index]))
    if (source & 0x0F) != 0x02 and target_offset is not None:
        body += struct.pack("<I" if flags & 0x10 else "<H", target_offset)
    return body


def _with_fixups(image: bytes, records_by_page: list[bytes]) -> bytes:
    """Append a fixup page table and record table, then point the LE header at them."""
    page_count = struct.unpack_from("<I", image, LE_OFFSET + 0x14)[0]
    table_position = len(image)
    blob = bytearray()
    offsets = []
    for raw in records_by_page:
        offsets.append(len(blob))
        blob += raw
    offsets.append(len(blob))
    while len(offsets) < page_count + 1:
        offsets.append(len(blob))
    table = b"".join(struct.pack("<I", offset) for offset in offsets)
    data = bytearray(image) + table + bytes(blob)
    struct.pack_into("<I", data, LE_OFFSET + 0x30, len(table) + len(blob))
    struct.pack_into("<I", data, LE_OFFSET + 0x68, table_position - LE_OFFSET)
    struct.pack_into("<I", data, LE_OFFSET + 0x6C, table_position + len(table) - LE_OFFSET)
    return bytes(data)


def _patched_u32(image: bytes, offset: int, value: int) -> bytes:
    data = bytearray(image)
    struct.pack_into("<I", data, offset, value)
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


def test_extraction_respects_the_object_virtual_extent(tmp_path):
    # Object virtual size 0x80 while its physical page holds a full 0x1000 bytes of file
    # data, so the page alone would otherwise let a request run past the object.
    path = _write(tmp_path, _le_image())
    with pytest.raises(DDTError, match="past object 1's virtual size \\(128 bytes\\)"):
        extract_le_bytes(path, 1, 0x7F, 2)
    assert extract_le_bytes(path, 1, 0x7E, 2)["file_offset"] == 0x18E
    assert extract_le_bytes(path, 1, 0x7E, 2)["bytes_hex"] == \
        bytes((0x18E + i) * 3 + 1 & 0xFF for i in range(2)).hex().upper()
    assert extract_le_bytes(path, 1, 0x7F, 1)["file_offset"] == 0x18F


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


def test_fixups_decode_internal_records_per_logical_page(tmp_path):
    first = _record(0x07, 0x00, 0x1B, object_index=2, target_offset=0x0004)
    second = _record(0x07, 0x00, 0x2F, object_index=2, target_offset=0x00E4)
    third = _record(0x07, 0x00, 0x12, object_index=1, target_offset=0x012E)
    path = _write(tmp_path, _with_fixups(_le_image(virtual_size=0x2000), [first + second, third]))

    first_page = inspect_le_fixups(path, 0)
    assert first_page["schema"] == "ddt.le-fixups.v1"
    assert first_page["page"]["object"] == 1
    assert first_page["page"]["object_page"] == 0
    assert first_page["page"]["page_map_index"] == 1
    assert first_page["page"]["page_file_offset"] == DATA_PAGES_OFFSET
    assert first_page["page"]["record_table_offset"] == 0
    assert first_page["page"]["record_table_end"] == 14
    assert first_page["record_count"] == 2
    assert first_page["undecoded"] is None
    assert [record["bytes_hex"] for record in first_page["records"]] == \
        ["07001B00020400", "07002F0002E400"]
    assert [record["source_offset"] for record in first_page["records"]] == [0x1B, 0x2F]
    assert [record["source_file_offset"] for record in first_page["records"]] == \
        [DATA_PAGES_OFFSET + 0x1B, DATA_PAGES_OFFSET + 0x2F]
    assert [record["target_offset"] for record in first_page["records"]] == [4, 0xE4]
    assert first_page["records"][0] == {
        "file_offset": first_page["records"][0]["file_offset"], "bytes_hex": "07001B00020400",
        "source_type": 7, "source_type_name": "offset32", "source_flags": 0x07,
        "source_offset": 0x1B, "source_file_offset": DATA_PAGES_OFFSET + 0x1B,
        "source_within_page": True, "target_type": "internal", "target_object": 2,
        "target_offset": 4, "target_offset_width": 2, "target_object_16bit": False}

    second_page = inspect_le_fixups(path, 1)
    assert second_page["page"]["object"] == 1
    assert second_page["page"]["object_page"] == 1
    assert second_page["record_count"] == 1
    assert second_page["records"][0]["bytes_hex"] == "07001200012E01"
    assert second_page["records"][0]["target_offset"] == 0x12E


def test_fixups_report_a_page_without_records(tmp_path):
    path = _write(tmp_path, _with_fixups(_le_image(virtual_size=0x2000),
                                         [_record(0x07, 0x00, 1, 2, 3)]))
    record = inspect_le_fixups(path, 1)
    assert record["record_count"] == 0
    assert record["records"] == []
    assert record["undecoded"] is None
    assert record["page"]["record_table_offset"] == record["page"]["record_table_end"]


def test_fixups_decode_object_and_offset_width_variants(tmp_path):
    wide = _record(0x07, 0x50, 0x20, object_index=0x0102, target_offset=0x00000123)
    path = _write(tmp_path, _with_fixups(_le_image(virtual_size=0x2000), [wide]))
    record = inspect_le_fixups(path, 0)["records"][0]
    assert record["bytes_hex"] == "07502000020123010000"
    assert record["target_object"] == 0x0102
    assert record["target_object_16bit"] is True
    assert record["target_offset"] == 0x123
    assert record["target_offset_width"] == 4


def test_fixups_segment_source_carries_no_target_offset(tmp_path):
    segment = _record(0x02, 0x00, 0x10, object_index=3)
    path = _write(tmp_path, _with_fixups(_le_image(virtual_size=0x2000), [segment]))
    record = inspect_le_fixups(path, 0)["records"][0]
    assert record["source_type_name"] == "segment"
    assert record["target_object"] == 3
    assert record["target_offset"] is None
    assert record["target_offset_width"] is None


def test_fixups_report_a_source_outside_the_page(tmp_path):
    outside = _record(0x07, 0x00, 0xFFFF, object_index=2, target_offset=0x012D)
    path = _write(tmp_path, _with_fixups(_le_image(virtual_size=0x2000), [outside]))
    record = inspect_le_fixups(path, 0)["records"][0]
    assert record["source_offset"] == 0xFFFF
    assert record["source_file_offset"] is None
    assert record["source_within_page"] is False


def test_fixups_stop_at_an_unsupported_record_form(tmp_path):
    decoded = _record(0x07, 0x00, 0x1B, object_index=2, target_offset=4)
    unsupported = _record(0x07, 0x01, 0x2F, object_index=2, target_offset=0x100)
    path = _write(tmp_path, _with_fixups(_le_image(virtual_size=0x2000), [decoded + unsupported]))
    record = inspect_le_fixups(path, 0)
    assert record["record_count"] == 1
    assert record["undecoded"]["file_offset"] == record["records"][0]["file_offset"] + 7
    assert record["undecoded"]["record_bytes"] == 7
    assert "import_ordinal" in record["undecoded"]["reason"]


def test_fixups_reject_malformed_tables_and_extents(tmp_path):
    base = _with_fixups(_le_image(virtual_size=0x2000),
                        [_record(0x07, 0x00, 0x1B, 2, 4)])
    table_position = len(_le_image(virtual_size=0x2000))
    with pytest.raises(DDTError, match="is truncated"):
        inspect_le_fixups(_write(tmp_path, _with_fixups(
            _le_image(virtual_size=0x2000), [b"\x07\x00\x1b\x00\x02"])), 0)
    with pytest.raises(DDTError, match="outside the module's 2 pages"):
        inspect_le_fixups(_write(tmp_path, base), 2)
    with pytest.raises(DDTError, match="negative integer"):
        inspect_le_fixups(_write(tmp_path, base), -1)
    with pytest.raises(DDTError, match="declares no fixup page table"):
        inspect_le_fixups(_write(tmp_path, _patched(base, 0x68, 0)), 0)
    with pytest.raises(DDTError, match="too small for the module's pages"):
        inspect_le_fixups(_write(tmp_path, _patched_u32(
            base, LE_OFFSET + 0x6C, table_position - LE_OFFSET + 4)), 0)
    with pytest.raises(DDTError, match="record table offset is past the end"):
        inspect_le_fixups(_write(tmp_path, _patched(base, 0x6C, 0x9000)), 0)
    with pytest.raises(DDTError, match="record table extends past the end"):
        inspect_le_fixups(_write(tmp_path, _patched_u32(
            base, table_position + 8, 0x9000)), 0)
    with pytest.raises(DDTError, match="not monotonic"):
        inspect_le_fixups(_write(tmp_path, _patched_u32(base, table_position, 0x40)), 0)


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


def test_cli_reports_le_fixups_schema(tmp_path):
    path = _write(tmp_path, _with_fixups(_le_image(virtual_size=0x2000),
                                         [_record(0x07, 0x00, 0x1B, 2, 4)]))
    proc = subprocess.run([sys.executable, "-m", "ddt", "le-fixups", str(path),
                           "--page", "0", "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "ddt.le-fixups.v1"
    assert payload["record_count"] == 1
    assert payload["records"][0]["target_offset"] == 4
