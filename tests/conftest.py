from __future__ import annotations

import struct
import pytest


@pytest.fixture
def sample_mz(tmp_path):
    # Self-generated DOS MZ fixture. No copyrighted binary material.
    data = bytearray(144)
    struct.pack_into("<14H", data, 0,
                     0x5A4D, 128, 1, 1, 4, 0, 0xFFFF,
                     0, 0xFFFE, 0, 0, 0, 0x1C, 0)
    struct.pack_into("<HH", data, 0x1C, 2, 0)  # original-image relocation word
    for i in range(64, 128):
        data[i] = (i * 7) & 0xFF
    data[128:] = b"OVERLAY_EXAMPLE!"  # exactly 16 bytes
    path = tmp_path / "synthetic.exe"
    path.write_bytes(data)
    return path
