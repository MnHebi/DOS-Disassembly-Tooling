import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

from ddt import dosbox
from ddt.errors import DDTError

STATE = {"AX": "0000", "BX": "0000", "CX": "00FF", "DX": "0813", "SI": "0100", "DI": "FFFE",
         "BP": "0000", "SP": "FFFE", "CS": "0813", "IP": "0100", "DS": "0813", "ES": "0813",
         "SS": "0813"}


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class _FakeMemoryDOSBox(threading.Thread):
    def __init__(self, port, *, advertise=True, mode="ok", drop_on=None, move_final=False):
        super().__init__(daemon=True)
        self.port, self.advertise, self.mode = port, advertise, mode
        self.drop_on, self.move_final = drop_on, move_final
        self.state = dict(STATE)
        self.ev_calls, self.seen = 0, []

    def run(self):
        deadline = time.time() + 3.0
        while True:
            try:
                conn = socket.create_connection(("127.0.0.1", self.port), timeout=2); break
            except OSError:
                if time.time() > deadline:
                    return
                time.sleep(0.05)
        conn.settimeout(5)
        buffer = b""
        try:
            while True:
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    return
                if not data:
                    return
                buffer += data
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    parts = raw.decode().split(" ", 2)
                    rid, command = parts[1], parts[2]
                    self.seen.append(command)
                    if self.drop_on is not None and command.startswith(self.drop_on):
                        return
                    status, lines = self._reply(command)
                    conn.sendall(("\n".join([f"BEGIN {rid} {status}", *lines, f"END {rid}"]) + "\n").encode())
        finally:
            conn.close()

    def _reply(self, command):
        if command == "PING":
            return "OK", ["PONG"]
        if command == "EXEC HELP":
            lines = ["Debugger commands (enter all values in hex or as register):", "-" * 12]
            lines.append("MEMREAD <seg>:<off> <len> - Read 1-256 conventional RAM bytes (external)."
                         if self.advertise
                         else "MEMDUMP - (no MEMREAD command in this build).")
            return "OK", lines
        if command.startswith("EXEC EV "):
            names = command.split()[2:]
            self.ev_calls += 1
            state = dict(self.state)
            if self.move_final and self.ev_calls > 1:
                state["IP"] = "0103"
            return "OK", [f"EV of '{' '.join(names)}' is:", " ".join(state[n] for n in names)]
        if command.startswith("EXEC MEMREAD "):
            _, _, seg_off, length = command.split()
            if self.mode == "err":
                return "ERR", ["DEBUG: MEMREAD cannot read 0813:0100"]
            if self.mode == "malformed":
                return "OK", ["DEBUG: MEMREAD done"]
            if self.mode == "absent":
                return "OK", ["DEBUG: memory operation completed"]
            if self.mode == "bad_address":
                return "OK", ["DEBUG: MEMREAD 0999:0100 LEN=0008 HEX=B83412BB7856EBF8"]
            if self.mode == "bad_length":
                return "OK", ["DEBUG: MEMREAD 0813:0100 LEN=0004 HEX=B83412BB"]
            if self.mode == "junk_suffix":
                return "OK", [f"DEBUG: MEMREAD {seg_off} LEN={length} HEX=B83412BB7856EBF8 junk"]
            if self.mode == "substring":
                return "OK", [f"note: DEBUG: MEMREAD {seg_off} LEN={length} HEX=B83412BB7856EBF8"]
            if self.mode == "duplicate":
                line = f"DEBUG: MEMREAD {seg_off} LEN={length} HEX=B83412BB7856EBF8"
                return "OK", [line, line]
            if self.mode == "conflict":
                return "OK", [f"DEBUG: MEMREAD {seg_off} LEN={length} HEX=B83412BB7856EBF8",
                              "DEBUG: MEMREAD 0999:0100 LEN=0008 HEX=DEADBEEFDEADBEEF"]
            if self.mode == "bad_hex":
                return "OK", [f"DEBUG: MEMREAD {seg_off} LEN={length} HEX=B8341G"]
            if self.mode == "odd_hex":
                return "OK", [f"DEBUG: MEMREAD {seg_off} LEN={length} HEX=B8341"]
            hex_bytes = "B83412" if self.mode == "short_hex" else "B83412BB7856EBF8"
            return "OK", [f"DEBUG: MEMREAD {seg_off} LEN={length} HEX={hex_bytes}"]
        return "ERR", ["*** Debugger command not recognized"]


def _capture(port, peer, **kwargs):
    result, errors = {}, {}

    def target():
        try:
            result["record"] = dosbox.capture_memory(port, segment=0x0813, offset=0x0100,
                                                      length=8, settle=0.0, **kwargs)
        except Exception as exc:  # noqa: BLE001 - captured for assertion
            errors["error"] = exc

    worker = threading.Thread(target=target)
    worker.start()
    peer.start()
    worker.join(timeout=20)
    peer.join(timeout=5)
    return result.get("record"), errors.get("error"), peer


def test_capture_memory_returns_observed_bytes():
    port = _free_port()
    record, error, peer = _capture(port, _FakeMemoryDOSBox(port))
    assert error is None
    assert record["schema"] == "ddt.dosbox-memory.v1"
    assert record["request"] == {"segment": "0813", "offset": "0100", "length": 8,
                                 "cs_ip": "0813:0100", "command": "REQ 4 EXEC MEMREAD 0813:0100 0008"}
    assert record["bytes_hex"] == "B83412BB7856EBF8" and record["byte_count"] == 8
    assert record["response"]["raw"] == ["DEBUG: MEMREAD 0813:0100 LEN=0008 HEX=B83412BB7856EBF8"]
    assert record["capability"]["memread_advertised"] is True
    assert record["capability"]["evidence"] == [
        "MEMREAD <seg>:<off> <len> - Read 1-256 conventional RAM bytes (external)."]
    assert record["initial"] == record["final"] and record["cs_ip_unchanged"] is True
    assert record["read_success"] is True and record["paused_state"] == "unknown"
    assert not any(command == "EXEC RUN" for command in peer.seen)


def test_unsupported_build_never_reads_memory():
    port = _free_port()
    record, error, peer = _capture(port, _FakeMemoryDOSBox(port, advertise=False))
    assert record is None and "does not advertise MEMREAD" in str(error)
    assert not any(command.startswith("EXEC MEMREAD") for command in peer.seen)


@pytest.mark.parametrize("mode,match", [
    ("err", "refused the memory read"),
    ("malformed", "unexpected MEMREAD output"),
    ("absent", "did not report address"),
    ("bad_address", "is for 0999:0100"),
    ("bad_length", "reports 4 bytes"),
    ("short_hex", "returned 3 bytes"),
    ("junk_suffix", "unexpected MEMREAD output"),
    ("substring", "unexpected MEMREAD output"),
    ("bad_hex", "unexpected MEMREAD output"),
    ("odd_hex", "returned 2 bytes"),
    ("duplicate", "reported 2 data records"),
    ("conflict", "reported 2 data records"),
])
def test_malformed_or_mismatched_reads_are_rejected(mode, match):
    port = _free_port()
    record, error, _ = _capture(port, _FakeMemoryDOSBox(port, mode=mode))
    assert record is None and match in str(error)


def test_disconnect_and_moved_cs_ip_are_rejected():
    port = _free_port()
    record, error, _ = _capture(port, _FakeMemoryDOSBox(port, drop_on="EXEC MEMREAD"))
    assert record is None and isinstance(error, DDTError)
    port2 = _free_port()
    record2, error2, _ = _capture(port2, _FakeMemoryDOSBox(port2, move_final=True))
    assert record2 is None and "CS:IP moved during the memory read" in str(error2)


def test_bounds_validation_and_output_preservation(tmp_path):
    for kwargs in ({"segment": 0x10000, "offset": 0, "length": 8},
                   {"segment": 0, "offset": -1, "length": 8},
                   {"segment": 0, "offset": 0, "length": 0},
                   {"segment": 0, "offset": 0, "length": 257},
                   {"segment": 0, "offset": 0, "length": True}):
        with pytest.raises(DDTError):
            dosbox.capture_memory(1, settle=0.0, **kwargs)
    port = _free_port()
    out = tmp_path / "memory.json"
    out.write_text("KEEP", encoding="utf-8")
    record, error, _ = _capture(port, _FakeMemoryDOSBox(port, mode="err"), out=out)
    assert record is None and out.read_text(encoding="utf-8") == "KEEP"


def test_cli_capture_memory(tmp_path):
    port = _free_port()
    peer = _FakeMemoryDOSBox(port)
    peer.start()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    out = tmp_path / "memory.json"
    proc = subprocess.run([sys.executable, "-m", "ddt", "debugger", "capture-memory",
                           "--port", str(port), "--segment", "0x0813", "--offset", "0x0100",
                           "--length", "8", "--settle", "0", "--timeout", "10",
                           "--out", str(out), "--json"],
                          check=True, capture_output=True, text=True, env=env)
    payload = json.loads(proc.stdout)
    assert payload["bytes_hex"] == "B83412BB7856EBF8"
    assert json.loads(out.read_text(encoding="utf-8")) == payload
    peer.join(timeout=5)
