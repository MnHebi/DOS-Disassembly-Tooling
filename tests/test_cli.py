import json
import os
from pathlib import Path
import subprocess
import sys


def _dev_env():
    env = dict(os.environ)
    source = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = source + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_cli_roundtrip(sample_mz):
    proc = subprocess.run([sys.executable, "-m", "ddt", "inspect", str(sample_mz), "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    assert json.loads(proc.stdout)["format"] == "dos-mz"
    proc = subprocess.run([sys.executable, "-m", "ddt", "address", str(sample_mz),
                           "--segment", "0x0", "--offset", "0x2", "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    assert json.loads(proc.stdout)["file_offset"] == 66


def test_cli_rejects_unsupported(tmp_path):
    source = tmp_path / "bad"
    source.write_bytes(b"hello")
    proc = subprocess.run([sys.executable, "-m", "ddt", "inspect", str(source), "--json"],
                          capture_output=True, text=True, env=_dev_env())
    assert proc.returncode == 2
    assert json.loads(proc.stderr)["error_type"] == "DDTError"


def test_cli_strings(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00Copyright 1995 Example Corp\x00")
    proc = subprocess.run([sys.executable, "-m", "ddt", "strings", str(target), "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    record = json.loads(proc.stdout)
    assert record["strings"][0]["text"] == "Copyright 1995 Example Corp"
    assert record["strings"][0]["file_offset"] == 1
