"""Native/executable smoke test, deliberately not dependent on project fixtures."""
from __future__ import annotations
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def main():
    command = sys.argv[1:]
    if not command:
        raise SystemExit("usage: smoke.py path/to/ddt[.exe]")
    with tempfile.TemporaryDirectory(prefix="ddt-smoke-") as folder:
        root = Path(folder)
        a = root / "original.exe"
        data = bytearray(128)
        struct.pack_into("<14H", data, 0, 0x5A4D, 128, 1, 0, 4, 0, 0xFFFF, 0, 0, 0, 0, 0, 0x1C, 0)
        a.write_bytes(data)
        def call(*args):
            return subprocess.run([*command, *args], check=True, text=True, capture_output=True)
        assert "ddt 0.1.0" in call("--version").stdout
        assert json.loads(call("inspect", str(a), "--json").stdout)["initialized_image_bytes"] == 64
        assert json.loads(call("address", str(a), "--segment", "0", "--offset", "0", "--json").stdout)["file_offset"] == 64
        b = root / "modified.exe"
        data[-1] = 42
        b.write_bytes(data)
        assert json.loads(call("diff", str(a), str(b), "--json").stdout)["summary"]["changed"] == 1
        assert len(json.loads(call("manifest", str(a), "--json").stdout)["entries"]) == 1
    print("DDT native smoke OK")


if __name__ == "__main__":
    main()
