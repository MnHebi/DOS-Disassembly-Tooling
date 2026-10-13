import struct

import pytest

from ddt.errors import DDTError
from ddt.format import COM, MZ, inspect, map_address


def test_synthetic_mz_mapping_and_overlay(sample_mz):
    target = inspect(sample_mz)
    assert isinstance(target, MZ)
    record = target.to_dict()
    assert record["header_bytes"] == 64
    assert record["initialized_image_bytes"] == 64
    assert record["overlay_bytes"] == 16
    assert record["relocations"][0]["image_offset"] == 2
    assert record["relocations"][0]["within_initialized_image"] is True
    assert map_address(target, 0, 0)["file_offset"] == 64
    assert map_address(target, 1, 0)["file_offset"] == 80
    with pytest.raises(DDTError, match="outside"):
        map_address(target, 4, 0)


def test_mz_rejects_bad_relocation_table(sample_mz):
    data = bytearray(sample_mz.read_bytes())
    struct.pack_into("<H", data, 6, 200)
    sample_mz.write_bytes(data)
    with pytest.raises(DDTError, match="relocation"):
        inspect(sample_mz)


def test_pe_does_not_get_passed_off_as_dos(sample_mz):
    data = bytearray(sample_mz.read_bytes())
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = b"PE\x00\x00"
    sample_mz.write_bytes(data)
    with pytest.raises(DDTError, match="PE executable"):
        inspect(sample_mz)


def test_explicit_com(tmp_path):
    target = tmp_path / "x.com"
    target.write_bytes(b"\x90\xCD\x20")
    with pytest.raises(DDTError, match="explicitly"):
        inspect(target)
    result = inspect(target, "com")
    assert isinstance(result, COM)
    assert map_address(result, 0, 0x101)["file_offset"] == 1
    with pytest.raises(DDTError):
        map_address(result, 1, 0x100)


def test_com_rejects_empty(tmp_path):
    target = tmp_path / "empty.com"
    target.write_bytes(b"")
    with pytest.raises(DDTError):
        inspect(target, "com")
