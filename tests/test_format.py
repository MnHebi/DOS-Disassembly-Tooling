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


def test_bare_pe_signature_is_not_an_established_header(tmp_path):
    data = bytearray(144)
    struct.pack_into("<14H", data, 0, 0x5A4D, 128, 1, 0, 4, 0, 0xFFFF, 0, 0xFFFE, 0, 0, 0, 0x1C, 0)
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = b"PE\x00\x00"
    path = tmp_path / "stub.exe"
    path.write_bytes(bytes(data))
    # A signature alone does not establish a PE header, so the MZ target stands.
    assert inspect(path).to_dict()["format"] == "dos-mz"


def test_valid_pe_header_is_rejected(tmp_path):
    base = bytearray(64 + 16)
    struct.pack_into("<14H", base, 0, 0x5A4D, 80, 1, 0, 4, 0, 0xFFFF, 0, 0xFFFE, 0, 0, 0, 0x1C, 0)
    pe = bytearray(24 + 224 + 40)
    pe[0:4] = b"PE\x00\x00"
    struct.pack_into("<H", pe, 6, 1)
    struct.pack_into("<H", pe, 20, 224)
    struct.pack_into("<H", pe, 24, 0x10B)
    data = base + pe
    struct.pack_into("<I", data, 0x3C, len(base))
    path = tmp_path / "pe.exe"
    path.write_bytes(bytes(data))
    with pytest.raises(DDTError, match="PE executable"):
        inspect(path)


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
