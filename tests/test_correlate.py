import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from ddt import correlate as correlate_mod
from ddt.errors import DDTError

COM_BYTES = bytes([0xB8, 0x34, 0x12, 0xBB, 0x78, 0x56, 0xEB, 0xF8])


def _mz_bytes() -> bytes:
    image = bytes(range(34))
    size = 64 + len(image)
    header = bytearray(64)
    struct.pack_into("<14H", header, 0, 0x5A4D, size, 1, 0, 4, 0, 0xFFFF, 0, 0xFFFE, 0, 0, 0, 0x1C, 0)
    return bytes(header) + image


def _export(name: str, data: bytes, instructions: list[dict]) -> dict:
    return {"schema": "ddt.ghidra-function.v1",
            "program": {"name": name, "executable_sha256": hashlib.sha256(data).hexdigest()},
            "function": {"entry": instructions[0]["address"], "name": "entry",
                         "instructions": instructions}}


def _instruction(address: str, source_file: str, offset, *, known=True, text="MOV AX,0x1234",
                 length=3, raw_bytes="b83412"):
    return {"address": address, "bytes": raw_bytes, "length": length, "text": text,
            "source_file": source_file, "source_file_offset": offset, "mapping_known": known}


def _steps(cs_ip: str) -> dict:
    return {"schema": "ddt.dosbox-steps.v1",
            "initial": {"cs_ip": cs_ip, "registers": {"CS": cs_ip.split(":")[0],
                                                      "IP": cs_ip.split(":")[1]}}}


def _write(tmp_path, name, payload):
    path = tmp_path / name
    if isinstance(payload, bytes):
        path.write_bytes(payload)
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _com_case(tmp_path):
    binary = _write(tmp_path, "loop.com", COM_BYTES)
    export = _write(tmp_path, "export.json",
                    _export("loop.com", COM_BYTES,
                            [_instruction("1000:0100", "loop.com", 0),
                             _instruction("1000:0103", "loop.com", 3, text="MOV BX,0x5678")]))
    steps = _write(tmp_path, "steps.json", _steps("0813:0100"))
    return binary, export, steps


def test_com_correlation_maps_source_offset_to_runtime():
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        tmp = Path(folder)
        binary, export, steps = _com_case(tmp)
        record = correlate_mod.correlate(binary, "com", export, "1000:0103", steps)
    assert record["schema"] == "ddt.address-correlation.v1"
    assert record["binary"]["format"] == "dos-com"
    assert record["ghidra"]["identity_matches"] is True
    assert record["instruction"] == {"ghidra_address": "1000:0103", "source_file": "loop.com",
                                     "source_file_offset": 3, "bytes": "b83412",
                                     "text": "MOV BX,0x5678"}
    assert record["entry_observation"]["cs_ip"] == "0813:0100"
    assert record["mapping"]["runtime_cs_ip"] == "0813:0103"
    assert record["mapping"]["original_file_offset"] == 3
    assert record["status"] == "conditional"
    assert record["checks"]["entry_ip_is_0100"] is True
    assert any("0100 + 0003" in line for line in record["arithmetic"])
    assert any("not observed runtime execution" in limit for limit in record["limitations"])
    assert record["unknowns"]


def test_com_rejects_bad_entry_identity_and_bounds(tmp_path):
    binary, export, steps = _com_case(tmp_path)
    wrong_entry = _write(tmp_path, "wrong.json", _steps("0813:0103"))
    with pytest.raises(DDTError, match="IP=0100"):
        correlate_mod.correlate(binary, "com", export, "1000:0103", wrong_entry)
    mismatch = _write(tmp_path, "other.com", COM_BYTES + b"\x90")
    with pytest.raises(DDTError, match="identity mismatch"):
        correlate_mod.correlate(mismatch, "com", export, "1000:0103", steps)
    with pytest.raises(DDTError, match="not present in the Ghidra export"):
        correlate_mod.correlate(binary, "com", export, "1000:9999", steps)
    outside = _write(tmp_path, "outside.json",
                     _export("loop.com", COM_BYTES, [_instruction("1000:0000", "loop.com", 99)]))
    with pytest.raises(DDTError, match="outside the COM image"):
        correlate_mod.correlate(binary, "com", outside, "1000:0000", steps)


def test_com_rejects_missing_source_offset_and_missing_identity(tmp_path):
    binary, export, steps = _com_case(tmp_path)
    unknown = _write(tmp_path, "unknown.json",
                     _export("loop.com", COM_BYTES, [_instruction("1000:0100", "loop.com", None,
                                                                  known=False)]))
    with pytest.raises(DDTError, match="no original source-file offset"):
        correlate_mod.correlate(binary, "com", unknown, "1000:0100", steps)
    anonymous = {"schema": "ddt.ghidra-function.v1", "program": {"name": "loop.com"},
                 "function": {"instructions": [{"address": "1000:0100", "mapping_known": True,
                                                "source_file_offset": 0}]}}
    no_sha = _write(tmp_path, "nosha.json", anonymous)
    with pytest.raises(DDTError, match="does not record an executable SHA-256"):
        correlate_mod.correlate(binary, "com", no_sha, "1000:0100", steps)


def _mz_case(tmp_path):
    data = _mz_bytes()
    binary = _write(tmp_path, "fixture.exe", data)
    export = _write(tmp_path, "mz-export.json",
                    _export("fixture.exe", data,
                            [_instruction("1000:0000", "fixture.exe", 64),
                             _instruction("1000:0003", "fixture.exe", 67)]))
    steps = _write(tmp_path, "mz-steps.json", _steps("0813:0000"))
    return binary, export, steps


def test_mz_correlation_derives_load_segment_and_canonical_address(tmp_path):
    binary, export, steps = _mz_case(tmp_path)
    record = correlate_mod.correlate(binary, "mz", export, "1000:0003", steps)
    assert record["binary"]["format"] == "dos-mz"
    assert record["mapping"]["module_image_offset"] == 3
    assert record["mapping"]["load_segment"] == "0813"
    assert record["mapping"]["canonical_runtime_cs_ip"] == "0813:0003"
    assert record["mapping"]["runtime_cs_ip"] == "0813:0003"
    assert record["checks"]["entry_ip_matches_header"] is True
    assert any("load segment = 0813 - 0000 = 0813" in line for line in record["arithmetic"])
    # entry instruction maps to the load-module start
    entry = correlate_mod.correlate(binary, "mz", export, "1000:0000", steps)
    assert entry["mapping"]["module_image_offset"] == 0
    assert entry["mapping"]["canonical_runtime_cs_ip"] == "0813:0000"


def test_mz_negative_cases(tmp_path):
    binary, export, steps = _mz_case(tmp_path)
    wrong_entry = _write(tmp_path, "bad-entry.json", _steps("0813:0003"))
    with pytest.raises(DDTError, match="MZ entry IP mismatch"):
        correlate_mod.correlate(binary, "mz", export, "1000:0003", wrong_entry)
    outside = _write(tmp_path, "outside-mz.json",
                     _export("fixture.exe", _mz_bytes(),
                             [_instruction("1000:0050", "fixture.exe", 200)]))
    with pytest.raises(DDTError, match="outside the initialized MZ load module"):
        correlate_mod.correlate(binary, "mz", outside, "1000:0050", steps)
    wrap = _write(tmp_path, "wrap.json", _steps("FFFF:0000"))
    far_export = _write(tmp_path, "far.json",
                        _export("fixture.exe", _mz_bytes(),
                                [_instruction("1000:0010", "fixture.exe", 80)]))
    with pytest.raises(DDTError, match="A20 assumption"):
        correlate_mod.correlate(binary, "mz", far_export, "1000:0010", wrap)


def test_schema_and_format_validation(tmp_path):
    binary, export, steps = _com_case(tmp_path)
    with pytest.raises(DDTError, match="format must be"):
        correlate_mod.correlate(binary, "auto", export, "1000:0100", steps)
    bad_export = _write(tmp_path, "bad.json", {"schema": "other"})
    with pytest.raises(DDTError, match="is not a ddt.ghidra-function.v1 record"):
        correlate_mod.correlate(binary, "com", bad_export, "1000:0100", steps)
    bad_steps = _write(tmp_path, "bad-steps.json", {"schema": "other"})
    with pytest.raises(DDTError, match="is not a ddt.dosbox-steps.v1 record"):
        correlate_mod.correlate(binary, "com", export, "1000:0100", bad_steps)


def test_cli_correlate(tmp_path):
    binary, export, steps = _com_case(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-m", "ddt", "correlate", "--binary", str(binary),
                           "--format", "com", "--export", str(export),
                           "--instruction", "1000:0103", "--entry-observation", str(steps), "--json"],
                          check=True, capture_output=True, text=True, env=env)
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "ddt.address-correlation.v1"
    assert payload["mapping"]["runtime_cs_ip"] == "0813:0103"


def test_binary_is_read_only_once(tmp_path, monkeypatch):
    binary, export, steps = _com_case(tmp_path)
    reads: list[Path] = []
    original = Path.read_bytes

    def counting(self):
        if self == binary:
            reads.append(self)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", counting)
    record = correlate_mod.correlate(binary, "com", export, "1000:0103", steps)
    assert record["mapping"]["runtime_cs_ip"] == "0813:0103"
    assert len(reads) == 1


def test_instruction_extent_boundaries_and_malformed_evidence(tmp_path):
    binary, export, steps = _com_case(tmp_path)  # 8-byte COM
    boundary = _write(tmp_path, "boundary.json",
                      _export("loop.com", COM_BYTES,
                              [_instruction("1000:0105", "loop.com", 5, raw_bytes="7856eb")]))
    record = correlate_mod.correlate(binary, "com", boundary, "1000:0105", steps)
    assert record["mapping"]["runtime_cs_ip"] == "0813:0105"
    assert record["mapping"]["instruction_extent"] == [5, 8]
    beyond = _write(tmp_path, "beyond.json",
                    _export("loop.com", COM_BYTES,
                            [_instruction("1000:0106", "loop.com", 6, raw_bytes="ebf890")]))
    with pytest.raises(DDTError, match="outside the COM image"):
        correlate_mod.correlate(binary, "com", beyond, "1000:0106", steps)
    for value in (0, -1, None):
        bad = _write(tmp_path, f"len-{value}.json",
                     _export("loop.com", COM_BYTES,
                             [{**_instruction("1000:0103", "loop.com", 3), "length": value}]))
        with pytest.raises(DDTError, match="invalid instruction length"):
            correlate_mod.correlate(binary, "com", bad, "1000:0103", steps)
    bad_offset = _write(tmp_path, "neg-offset.json",
                        _export("loop.com", COM_BYTES,
                                [_instruction("1000:0103", "loop.com", -1)]))
    with pytest.raises(DDTError, match="invalid source file offset"):
        correlate_mod.correlate(binary, "com", bad_offset, "1000:0103", steps)
    bad_bytes = _write(tmp_path, "bad-bytes.json",
                       _export("loop.com", COM_BYTES,
                               [_instruction("1000:0103", "loop.com", 3, length=2)]))
    with pytest.raises(DDTError, match="not 2 bytes of hexadecimal"):
        correlate_mod.correlate(binary, "com", bad_bytes, "1000:0103", steps)


def test_mz_rejects_header_and_overlay_extents(tmp_path):
    image = _mz_bytes() + b"OVERLAY!"
    binary = _write(tmp_path, "fixture.exe", image)
    steps = _write(tmp_path, "steps.json", _steps("0813:0000"))
    in_header = _write(tmp_path, "header.json",
                       _export("fixture.exe", image,
                               [_instruction("1000:0000", "fixture.exe", 60,
                                             length=4, raw_bytes="00000000")]))
    with pytest.raises(DDTError, match="outside the initialized MZ load module"):
        correlate_mod.correlate(binary, "mz", in_header, "1000:0000", steps)
    in_overlay = _write(tmp_path, "overlay.json",
                        _export("fixture.exe", image,
                                [_instruction("1000:0000", "fixture.exe", 100,
                                              length=2, raw_bytes="4f56")]))
    with pytest.raises(DDTError, match="outside the initialized MZ load module"):
        correlate_mod.correlate(binary, "mz", in_overlay, "1000:0000", steps)
