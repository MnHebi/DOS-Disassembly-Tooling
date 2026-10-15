import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ddt import memory
from ddt.errors import DDTError

REFERENCE = bytes(range(256)) * 2          # 512 bytes: byte at offset i == i & 0xFF
RUNTIME_HEX = REFERENCE[64:96].hex().upper()


def _observation(bytes_hex=RUNTIME_HEX, address="0823:0000", entry="0813:0100", **overrides) -> dict:
    segment, offset = address.split(":")
    length = len(bytes_hex) // 2 if bytes_hex else 0
    record = {"schema": "ddt.dosbox-memory.v1",
              "request": {"segment": segment, "offset": offset, "length": length, "cs_ip": address},
              "response": {"address": address, "length": length},
              "bytes_hex": bytes_hex, "byte_count": length,
              "read_success": True, "cs_ip_unchanged": True,
              "initial": {"cs_ip": entry}, "final": {"cs_ip": entry}}
    record.update(overrides)
    return record


def _write(tmp_path, name, payload, binary=False):
    path = tmp_path / name
    if binary:
        path.write_bytes(payload)
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_equal_reference_range(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    observation = _write(tmp_path, "memory.json", _observation())
    result = memory.compare_reference(observation, reference, 64)
    assert result["schema"] == "ddt.memory-reference-comparison.v1"
    assert result["provenance"]["correspondence"] == "operator_supplied"
    assert result["observation"]["address"] == "0823:0000"
    assert result["observation"]["length"] == 32
    assert result["reference"] == {"path": str(reference),
                                   "sha256": hashlib.sha256(REFERENCE).hexdigest(),
                                   "size": len(REFERENCE), "file_offset": 64,
                                   "bytes_hex": REFERENCE[64:96].hex().upper()}
    assert result["results"] == {"runtime_equals_reference": True}
    assert result["differences"] == [] and result["difference_count"] == 0
    assert result["differences_truncated"] is False
    assert result["verified"] == ["the two supplied byte sequences are equal"]
    assert result["operator_assertion"] and "executable identity" in result["not_established"]
    assert any("never adjusts" in limit for limit in result["limitations"])


def test_unequal_range_is_reported_literally(tmp_path):
    altered = bytearray(REFERENCE[64:96])
    altered[3] = 0x5A
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    observation = _write(tmp_path, "memory.json", _observation(altered.hex().upper()))
    result = memory.compare_reference(observation, reference, 64)
    assert result["results"] == {"runtime_equals_reference": False}
    assert result["differences"] == [{"relative_offset": 3, "reference_file_offset": 67,
                                      "runtime": "5A", "reference": f"{REFERENCE[67]:02X}"}]
    assert result["difference_count"] == 1
    assert result["verified"] == ["the two supplied byte sequences differ at the listed offsets"]


def test_wrong_offset_reports_a_mismatch_rather_than_adjusting(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    observation = _write(tmp_path, "memory.json", _observation())
    result = memory.compare_reference(observation, reference, 65)   # deliberately off by one
    assert result["results"]["runtime_equals_reference"] is False
    assert result["reference"]["file_offset"] == 65               # offset is not "repaired"
    assert result["difference_count"] > 0


def test_reference_bounds_and_invalid_offsets(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    observation = _write(tmp_path, "memory.json", _observation())
    with pytest.raises(DDTError, match="does not fit"):
        memory.compare_reference(observation, reference, len(REFERENCE) - 4)
    for offset in (-1, True, "64"):
        with pytest.raises(DDTError, match="nonnegative integer"):
            memory.compare_reference(observation, reference, offset)


def test_truncated_difference_list(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", bytes(256), binary=True)
    observation = _write(tmp_path, "memory.json", _observation("FF" * 256,
                                                              address="0823:0000"))
    result = memory.compare_reference(observation, reference, 0)
    assert result["difference_count"] == 256
    assert len(result["differences"]) == 64 and result["differences_truncated"] is True


@pytest.mark.parametrize("override,match", [
    ({"read_success": False}, "read_success"),
    ({"read_success": None}, "read_success"),
    ({"cs_ip_unchanged": False}, "cs_ip_unchanged"),
    ({"final": {"cs_ip": "0813:0103"}}, "CS:IP changed"),
    ({"response": {"address": "0999:0000", "length": 32}}, "response address"),
    ({"response": {"address": "0823:0000", "length": 16}}, "response length"),
    ({"request": {"segment": "0823", "offset": "0001", "length": 32, "cs_ip": "0823:0000"}},
     "does not match its"),
    ({"byte_count": 31}, "byte_count"),
    ({"bytes_hex": "E8"}, "not 32 bytes of hexadecimal"),
])
def test_inconsistent_observations_are_rejected(tmp_path, override, match):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    record = _observation()
    record.update(override)          # corrupt the receipt without recomputing its length
    observation = _write(tmp_path, "memory.json", record)
    with pytest.raises(DDTError, match=match):
        memory.compare_reference(observation, reference, 64)


def test_missing_observation_and_wrong_schema(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    with pytest.raises(DDTError, match="ordinary file"):
        memory.compare_reference(tmp_path / "absent.json", reference, 0)
    wrong = _write(tmp_path, "other.json", {"schema": "ddt.memory-comparison.v1"})
    with pytest.raises(DDTError, match="is not a ddt.dosbox-memory.v1 record"):
        memory.compare_reference(wrong, reference, 0)


def _dev_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("GHIDRA_HOME", None)
    env.pop("GHIDRA_INSTALL_DIR", None)
    env.pop("DDT_GHIDRA_HOME", None)
    return env


def test_cli_compare_reference_offline(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    observation = _write(tmp_path, "memory.json", _observation())
    out = tmp_path / "comparison.json"
    proc = subprocess.run([sys.executable, "-m", "ddt", "memory", "compare-reference",
                           "--observation", str(observation), "--reference-binary", str(reference),
                           "--reference-offset", "64", "--out", str(out), "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    payload = json.loads(proc.stdout)
    assert payload["results"]["runtime_equals_reference"] is True
    assert payload["reference"]["file_offset"] == 64
    assert json.loads(out.read_text(encoding="utf-8")) == payload
    bad = subprocess.run([sys.executable, "-m", "ddt", "memory", "compare-reference",
                          "--observation", str(observation), "--reference-binary", str(reference),
                          "--reference-offset", "-1", "--json"],
                         capture_output=True, text=True, env=_dev_env())
    assert bad.returncode == 2 and json.loads(bad.stderr)["error_type"] == "DDTError"
    # the existing three-source comparison schema is untouched
    assert memory.SCHEMA == "ddt.memory-comparison.v1"


def test_out_must_not_overwrite_either_input(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    observation = _write(tmp_path, "memory.json", _observation())
    reference_before = reference.read_bytes()
    observation_before = observation.read_bytes()
    with pytest.raises(DDTError, match="must not overwrite the reference binary"):
        memory.compare_reference(observation, reference, 64, out=reference)
    with pytest.raises(DDTError, match="must not overwrite the observation"):
        memory.compare_reference(observation, reference, 64, out=observation)
    assert reference.read_bytes() == reference_before
    assert observation.read_bytes() == observation_before
    # an unrelated existing output is preserved when the request is rejected
    other = tmp_path / "other.json"
    other.write_text("KEEP", encoding="utf-8")
    with pytest.raises(DDTError, match="must not overwrite"):
        memory.compare_reference(observation, reference, 64, out=reference)
    assert other.read_text(encoding="utf-8") == "KEEP"


def test_out_equivalent_paths_and_symlink_aliases_are_rejected(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    observation = _write(tmp_path, "memory.json", _observation())
    equivalent = tmp_path / "sub" / ".." / "ORIG.EXE"
    with pytest.raises(DDTError, match="must not overwrite the reference binary"):
        memory.compare_reference(observation, reference, 64, out=equivalent)
    alias = tmp_path / "alias.exe"
    try:
        alias.symlink_to(reference)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(DDTError, match="must not overwrite the reference binary"):
        memory.compare_reference(observation, reference, 64, out=alias)
    assert reference.read_bytes() == REFERENCE


def test_memread_extent_bounds_are_enforced(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    crossing = _write(tmp_path, "crossing.json",
                      _observation("E8" * 32, address="0823:FFF0"))
    with pytest.raises(DDTError, match="64 KiB segment boundary"):
        memory.compare_reference(crossing, reference, 0)
    beyond = _write(tmp_path, "beyond.json", _observation("E8", address="A000:0000"))
    with pytest.raises(DDTError, match="beyond conventional RAM"):
        memory.compare_reference(beyond, reference, 0)
    # a legitimate range right at the conventional-RAM limit is still accepted
    last = _write(tmp_path, "last.json", _observation("E8", address="9FFF:000F"))
    assert memory.compare_reference(last, reference, 0)["results"]["runtime_equals_reference"] in (True, False)


def test_boolean_lengths_and_malformed_register_containers_are_rejected(tmp_path):
    reference = _write(tmp_path, "ORIG.EXE", REFERENCE, binary=True)
    record = _observation("E8")
    record["response"] = {"address": "0823:0000", "length": True}
    with pytest.raises(DDTError, match="response length"):
        memory.compare_reference(_write(tmp_path, "bool-len.json", record), reference, 0)
    record = _observation("E8")
    record["byte_count"] = True
    with pytest.raises(DDTError, match="byte_count"):
        memory.compare_reference(_write(tmp_path, "bool-count.json", record), reference, 0)
    record = _observation()
    record["initial"] = "0813:0100"
    with pytest.raises(DDTError, match="register container is not an object"):
        memory.compare_reference(_write(tmp_path, "bad-initial.json", record), reference, 64)
    record = _observation()
    record["final"] = 42
    with pytest.raises(DDTError, match="register container is not an object"):
        memory.compare_reference(_write(tmp_path, "bad-final.json", record), reference, 64)
