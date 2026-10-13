import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from ddt import identify as identify_mod
from ddt.errors import DDTError
from ddt.format import inspect


def _mz(image: bytes, *, cparhdr: int = 4, appended: bytes = b"", lfanew: int | None = None) -> bytes:
    header_size = cparhdr * 16
    declared = header_size + len(image)
    header = bytearray(header_size)
    struct.pack_into("<14H", header, 0, 0x5A4D, declared % 512 or 512,
                     (declared + 511) // 512, 0, cparhdr, 0, 0xFFFF, 0, 0xFFFE, 0, 0, 0, 0x1C, 0)
    if lfanew is not None:
        struct.pack_into("<I", header, 0x3C, lfanew)
    return bytes(header) + image + appended


def _coff_image(*, machine=0x014C, sections=1, optional_size=0, body=b"\x90" * 8) -> bytes:
    header = struct.pack("<HHIIIHH", machine, sections, 0, 0, 0, optional_size, 0)
    return header + b"\x00" * (optional_size + sections * 40) + body


def _write(tmp_path, data: bytes, name="sample.bin") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _kinds(record) -> list[str]:
    return [f["kind"] for f in record["findings"]]


def test_plain_mz_is_identified(tmp_path):
    record = identify_mod.identify(_write(tmp_path, _mz(b"\x90" * 16)))
    assert record["schema"] == "ddt.identify.v1"
    assert record["outer_format"] == "dos-mz"
    assert record["mz"]["header_bytes"] == 64
    assert _kinds(record) == ["dos-mz"]
    assert record["appended"] is None


def test_com_requires_explicit_selection(tmp_path):
    path = _write(tmp_path, b"\xB4\x09\xBA\x00\x01\xCD\x21", name="prog.com")
    record = identify_mod.identify(path, "com")
    assert record["outer_format"] == "dos-com"
    assert _kinds(record) == ["dos-com"]


@pytest.mark.parametrize("signature,kind", [(b"NE", "ne"), (b"LE", "le"), (b"LX", "lx"),
                                            (b"PE\x00\x00", "pe")])
def test_secondary_headers_are_recognized_unsupported(tmp_path, signature, kind):
    base = _mz(b"\x90" * 16)
    offset = len(base)
    data = base + signature + b"\x00" * 64
    data = data[:0x3C] + struct.pack("<I", offset) + data[0x40:]
    record = identify_mod.identify(_write(tmp_path, data))
    header = next(f for f in record["findings"] if f["kind"] == kind)
    assert header["classification"] == "identified"
    assert header["supported"] is False
    assert header["offset"] == offset
    assert record["appended"]["recognized_structure"] == kind
    # inspect still refuses these as conventional DOS MZ targets.
    with pytest.raises(DDTError):
        inspect(_write(tmp_path, data, name="secondary.exe"))


def test_out_of_bounds_or_incidental_signature_is_not_secondary(tmp_path):
    beyond = _mz(b"\x90" * 16, lfanew=0x100000)
    assert "ne" not in _kinds(identify_mod.identify(_write(tmp_path, beyond)))
    # "NE" present inside the load image but not at e_lfanew.
    incidental = _mz(b"\x90" * 4 + b"NE" + b"\x90" * 10)
    assert "ne" not in _kinds(identify_mod.identify(_write(tmp_path, incidental)))


def test_truncated_secondary_pointer_is_not_detected(tmp_path):
    base = _mz(b"\x90" * 16)
    data = base + b"\x90" * 8
    data = data[:0x3C] + struct.pack("<I", len(data) - 1) + data[0x40:]
    assert "ne" not in _kinds(identify_mod.identify(_write(tmp_path, data)))


def test_appended_data_is_reported_without_semantics(tmp_path):
    record = identify_mod.identify(_write(tmp_path, _mz(b"\x90" * 16, appended=b"APPENDED!!")))
    assert record["appended"] == {"start": 80, "length": 10,
                                  "recognized_structure": None, "purpose": "unknown"}


def test_lzexe_candidate_and_negative(tmp_path):
    image = b"\x90" * 16
    positive = bytearray(_mz(image, cparhdr=2))
    positive[0x1C:0x20] = b"LZ91"
    record = identify_mod.identify(_write(tmp_path, bytes(positive), name="packed.exe"))
    lzexe = next(f for f in record["findings"] if f["kind"] == "lzexe")
    assert lzexe["classification"] == "candidate" and lzexe["supported"] is False
    assert lzexe["offset"] == 0x1C
    assert "LZ91" in lzexe["basis"]
    assert "lzexe" not in _kinds(identify_mod.identify(_write(tmp_path, _mz(image), name="plain.exe")))


def test_upx_candidate_requires_the_documented_offset(tmp_path):
    positive = bytearray(_mz(b"\x90" * 200))
    positive[85:89] = b"UPX!"
    record = identify_mod.identify(_write(tmp_path, bytes(positive), name="upx.exe"))
    upx = next(f for f in record["findings"] if f["kind"] == "upx")
    assert upx["classification"] == "candidate" and upx["offset"] == 85
    # The same marker elsewhere is not a UPX signal.
    misplaced = bytearray(_mz(b"\x90" * 200))
    misplaced[90:94] = b"UPX!"
    assert "upx" not in _kinds(identify_mod.identify(_write(tmp_path, bytes(misplaced), name="mis.exe")))


def test_go32_stub_requires_load_image_start(tmp_path):
    at_start = _mz(b"go32stub for MS-DOS\x00" + b"\x90" * 16)
    record = identify_mod.identify(_write(tmp_path, at_start))
    stub = next(f for f in record["findings"] if f["kind"] == "go32-stub")
    assert stub["classification"] == "candidate" and stub["loader_identity"] == "unknown"
    elsewhere = _mz(b"\x90" * 4 + b"go32stub" + b"\x90" * 16)
    assert "go32-stub" not in _kinds(identify_mod.identify(_write(tmp_path, elsewhere)))


def test_validated_coff_and_false_positive(tmp_path):
    valid = identify_mod.identify(_write(tmp_path, _coff_image(), name="image.coff"))
    assert valid["outer_format"] == "i386-coff"
    coff = next(f for f in valid["findings"] if f["kind"] == "i386-coff")
    assert coff["classification"] == "identified" and coff["loader_identity"] == "unknown"
    # Plausible i386 machine word but a section table that runs past end-of-file.
    misleading = _coff_image(sections=5)[:40]
    rejected = identify_mod.identify(_write(tmp_path, misleading, name="bad.coff"))
    assert rejected["outer_format"] == "unknown"
    assert "i386-coff" not in _kinds(rejected)


def test_unknown_input_and_determinism(tmp_path):
    path = _write(tmp_path, b"not an executable", name="notes.txt")
    assert identify_mod.identify(path)["outer_format"] == "unknown"
    assert identify_mod.identify(path) == identify_mod.identify(path)


def _dev_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_cli_identify_and_inspect_unchanged(tmp_path):
    fixture = _write(tmp_path, _mz(b"\xB8\x00\x4C\xCD\x21"), name="prog.exe")
    proc = subprocess.run([sys.executable, "-m", "ddt", "identify", str(fixture), "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    assert json.loads(proc.stdout)["outer_format"] == "dos-mz"
    # inspect still returns its original MZ record for the same file.
    inspected = subprocess.run([sys.executable, "-m", "ddt", "inspect", str(fixture), "--json"],
                               check=True, capture_output=True, text=True, env=_dev_env())
    assert json.loads(inspected.stdout)["format"] == "dos-mz"
