import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from ddt import memory
from ddt.errors import DDTError

COM = bytes([0xB8, 0x34, 0x12, 0xBB, 0x78, 0x56, 0xEB, 0xF8])


def _mz_bytes(reloc: bool = True) -> bytes:
    image = bytes(range(34))
    size = 64 + len(image)
    header = bytearray(64)
    struct.pack_into("<14H", header, 0, 0x5A4D, size, 1, 1 if reloc else 0, 4, 0, 0xFFFF,
                     0, 0xFFFE, 0, 0, 0, 0x1C, 0)
    if reloc:
        struct.pack_into("<HH", header, 0x1C, 0, 0)  # relocation word at image offset 0
    return bytes(header) + image


def _correlation(data: bytes, fmt: str, *, offset: int, length: int, ghidra_hex,
                 runtime_cs_ip: str, module_offset: int | None = None) -> dict:
    mapping = {"instruction_length": length, "runtime_cs_ip": runtime_cs_ip}
    if module_offset is not None:
        mapping["module_image_offset"] = module_offset
    return {"schema": "ddt.address-correlation.v1",
            "binary": {"format": fmt, "sha256": hashlib.sha256(data).hexdigest()},
            "instruction": {"ghidra_address": "1000:0000", "source_file_offset": offset,
                            "bytes": ghidra_hex},
            "mapping": mapping, "status": "conditional"}


def _observation(cs_ip: str, length: int, hex_bytes: str, *, entry: str = "0813:0100",
                 read_success: object = True, cs_ip_unchanged: object = True,
                 final: str | None = None) -> dict:
    record = {"schema": "ddt.dosbox-memory.v1",
              "request": {"cs_ip": cs_ip, "length": length}, "bytes_hex": hex_bytes,
              "initial": {"cs_ip": entry}, "final": {"cs_ip": final or entry}}
    if read_success is not None:
        record["read_success"] = read_success
    if cs_ip_unchanged is not None:
        record["cs_ip_unchanged"] = cs_ip_unchanged
    return record


def _write(tmp_path, name, payload, binary=False):
    path = tmp_path / name
    if binary:
        path.write_bytes(payload)
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_all_three_sources_agree(tmp_path):
    binary = _write(tmp_path, "loop.com", COM, binary=True)
    correlation = _write(tmp_path, "corr.json",
                         _correlation(COM, "dos-com", offset=3, length=3, ghidra_hex="BB7856",
                                      runtime_cs_ip="0813:0103"))
    observation = _write(tmp_path, "mem.json", _observation("0813:0103", 3, "BB7856"))
    record = memory.compare(correlation, observation, binary)
    assert record["schema"] == "ddt.memory-comparison.v1"
    assert record["results"] == {"runtime_equals_original": True, "runtime_equals_ghidra": True,
                                 "ghidra_equals_original": True}
    assert record["differences"] == [] and record["differences_truncated"] is False
    assert record["bytes"] == {"original_hex": "BB7856", "ghidra_hex": "BB7856",
                               "runtime_hex": "BB7856"}
    assert record["relocation_overlaps"] == [] and record["checks"]["identity_sha256_match"] is True
    assert record["unknowns"] == []


def test_runtime_difference_is_reported_not_normalized(tmp_path):
    binary = _write(tmp_path, "loop.com", COM, binary=True)
    correlation = _write(tmp_path, "corr.json",
                         _correlation(COM, "dos-com", offset=3, length=3, ghidra_hex="BB7856",
                                      runtime_cs_ip="0813:0103"))
    observation = _write(tmp_path, "mem.json", _observation("0813:0103", 3, "BB9956"))
    record = memory.compare(correlation, observation, binary)
    assert record["results"] == {"runtime_equals_original": False, "runtime_equals_ghidra": False,
                                 "ghidra_equals_original": True}
    assert record["differences"] == [{"index": 1, "original": "78", "runtime": "99",
                                      "ghidra": "78"}]
    assert any("not a cause" in limit for limit in record["limitations"])


def test_missing_ghidra_bytes_makes_that_comparison_unknown(tmp_path):
    binary = _write(tmp_path, "loop.com", COM, binary=True)
    correlation = _write(tmp_path, "corr.json",
                         _correlation(COM, "dos-com", offset=3, length=3, ghidra_hex=None,
                                      runtime_cs_ip="0813:0103"))
    observation = _write(tmp_path, "mem.json", _observation("0813:0103", 3, "BB7856"))
    record = memory.compare(correlation, observation, binary)
    assert record["results"]["runtime_equals_ghidra"] is None
    assert record["results"]["ghidra_equals_original"] is None
    assert record["bytes"]["ghidra_hex"] is None
    assert any("unavailable" in entry for entry in record["unknowns"])


def test_mz_relocation_overlap_is_reported(tmp_path):
    data = _mz_bytes()
    binary = _write(tmp_path, "fixture.exe", data, binary=True)
    correlation = _write(tmp_path, "corr.json",
                         _correlation(data, "dos-mz", offset=64, length=3, ghidra_hex="000102",
                                      runtime_cs_ip="0823:0000", module_offset=0))
    observation = _write(tmp_path, "mem.json", _observation("0823:0000", 3, "000102",
                                                            entry="0823:0000"))
    record = memory.compare(correlation, observation, binary)
    assert record["results"] == {"runtime_equals_original": True, "runtime_equals_ghidra": True,
                                 "ghidra_equals_original": True}
    assert record["relocation_overlaps"] == [{"image_offset": 0, "segment_relative": 0, "offset": 0,
                                              "overlap": [0, 2]}]


def test_validation_rejects_mismatched_inputs(tmp_path):
    binary = _write(tmp_path, "loop.com", COM, binary=True)
    good = _write(tmp_path, "corr.json",
                  _correlation(COM, "dos-com", offset=3, length=3, ghidra_hex="BB7856",
                               runtime_cs_ip="0813:0103"))
    other = _write(tmp_path, "other.com", COM + b"\x90", binary=True)
    with pytest.raises(DDTError, match="identity mismatch"):
        memory.compare(good, _write(tmp_path, "m.json", _observation("0813:0103", 3, "BB7856")), other)
    alias = _write(tmp_path, "alias.json", _observation("0103:0003", 3, "BB7856"))
    with pytest.raises(DDTError, match="segment aliases"):
        memory.compare(good, alias, binary)
    wrong_len = _write(tmp_path, "len.json", _observation("0813:0103", 2, "BB78"))
    with pytest.raises(DDTError, match="observation covers 2 bytes"):
        memory.compare(good, wrong_len, binary)
    bad_hex = _write(tmp_path, "hex.json", _observation("0813:0103", 3, "BB78"))
    with pytest.raises(DDTError, match="not 3 bytes of hexadecimal"):
        memory.compare(good, bad_hex, binary)
    short_corr = _write(tmp_path, "short.json",
                        _correlation(COM, "dos-com", offset=6, length=3, ghidra_hex="EBF800",
                                     runtime_cs_ip="0813:0106"))
    with pytest.raises(DDTError, match="does not contain the full instruction extent"):
        memory.compare(short_corr, _write(tmp_path, "m2.json", _observation("0813:0106", 3, "EBF800")),
                       binary)


def test_cli_memory_compare(tmp_path):
    binary = _write(tmp_path, "loop.com", COM, binary=True)
    correlation = _write(tmp_path, "corr.json",
                         _correlation(COM, "dos-com", offset=3, length=3, ghidra_hex="BB7856",
                                      runtime_cs_ip="0813:0103"))
    observation = _write(tmp_path, "mem.json", _observation("0813:0103", 3, "BB7856"))
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-m", "ddt", "memory", "compare",
                           "--correlation", str(correlation), "--observation", str(observation),
                           "--binary", str(binary), "--json"],
                          check=True, capture_output=True, text=True, env=env)
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "ddt.memory-comparison.v1"
    assert payload["results"]["runtime_equals_original"] is True


@pytest.mark.parametrize("kwargs,match", [
    ({"read_success": None}, "read_success"),
    ({"read_success": False}, "read_success"),
    ({"read_success": "true"}, "read_success"),
    ({"cs_ip_unchanged": None}, "cs_ip_unchanged"),
    ({"cs_ip_unchanged": False}, "cs_ip_unchanged"),
    ({"final": "0813:0103"}, "CS:IP changed"),
])
def test_observation_integrity_is_required_before_any_comparison(tmp_path, kwargs, match):
    binary = _write(tmp_path, "loop.com", COM, binary=True)
    correlation = _write(tmp_path, "corr.json",
                         _correlation(COM, "dos-com", offset=3, length=3, ghidra_hex="BB7856",
                                      runtime_cs_ip="0813:0103"))
    observation = _write(tmp_path, "mem.json", _observation("0813:0103", 3, "BB7856", **kwargs))
    with pytest.raises(DDTError, match=match):
        memory.compare(correlation, observation, binary)


def test_missing_or_incomplete_runtime_bytes_are_rejected(tmp_path):
    binary = _write(tmp_path, "loop.com", COM, binary=True)
    correlation = _write(tmp_path, "corr.json",
                         _correlation(COM, "dos-com", offset=3, length=3, ghidra_hex="BB7856",
                                      runtime_cs_ip="0813:0103"))
    missing = _write(tmp_path, "missing.json", _observation("0813:0103", 3, None))
    with pytest.raises(DDTError, match="observed bytes are missing"):
        memory.compare(correlation, missing, binary)
    incomplete = _write(tmp_path, "incomplete.json", _observation("0813:0103", 3, "BB78"))
    with pytest.raises(DDTError, match="not 3 bytes of hexadecimal"):
        memory.compare(correlation, incomplete, binary)
