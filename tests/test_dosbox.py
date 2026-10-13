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


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _default_responses(command: str):
    if command == "PING":
        return "OK", ["PONG"]
    if command == "BREAK":
        return "OK", ["***| TYPE HELP (+ENTER) TO GET AN OVERVIEW OF ALL COMMANDS |***"]
    if command.startswith("EXEC EV"):
        return "OK", ["EV of 'AX BX CX DX SI DI BP SP CS IP DS ES SS' is:",
                      "1234 5678 0000 0000 0000 0000 0000 0000 0813 0106 0813 0813 0813"]
    if command == "EXEC CPU":
        return "OK", ["cr0:00000010 cr2:00000000 cr3:00000000  cpl=0",
                      "eflags:00007202 [vm=0 iop1=3 ntl=1]"]
    if command == "EXEC RUN":
        return "OK", ["OK"]
    return "ERR", ["*** Debugger command not recognized"]


class _FakeDOSBox(threading.Thread):
    """Minimal peer that speaks the DOSBox-X debugger line protocol."""

    def __init__(self, port, responses=_default_responses, force_id=None, close_after=None,
                 ready=threading.Event()):
        super().__init__(daemon=True)
        self.port, self.responses, self.force_id = port, responses, force_id
        self.close_after, self.ready = close_after, ready

    def run(self):
        deadline = time.time() + 3.0
        while True:
            try:
                conn = socket.create_connection(("127.0.0.1", self.port), timeout=2)
                break
            except OSError:
                if time.time() > deadline:
                    return
                time.sleep(0.05)
        self.ready.set()
        conn.settimeout(5)
        buffer = b""
        handled = 0
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
                    handled += 1
                    if self.close_after is not None and handled > self.close_after:
                        return
                    status, reply = self.responses(command)
                    send_id = self.force_id or rid
                    payload = [f"BEGIN {send_id} {status}", *reply, f"END {send_id}"]
                    conn.sendall(("\n".join(payload) + "\n").encode())
        finally:
            conn.close()


def _capture(port, responses=_default_responses, force_id=None, close_after=None, **kwargs):
    result = {}
    errors = {}

    def target():
        try:
            result["record"] = dosbox.capture_cpu(port, settle=0.0, **kwargs)
        except Exception as exc:  # noqa: BLE001 - captured for assertion
            errors["error"] = exc

    worker = threading.Thread(target=target)
    worker.start()
    peer = _FakeDOSBox(port, responses, force_id=force_id, close_after=close_after)
    peer.start()
    worker.join(timeout=15)
    peer.join(timeout=5)
    return result.get("record"), errors.get("error")


def test_capture_parses_registers_and_cpu_state():
    port = _free_port()
    record, error = _capture(port)
    assert error is None
    assert record["schema"] == "ddt.dosbox-cpu.v1"
    assert record["endpoint"] == {"host": "127.0.0.1", "port": port}
    assert record["registers"] == {"AX": "1234", "BX": "5678", "CX": "0000", "DX": "0000",
                                   "SI": "0000", "DI": "0000", "BP": "0000", "SP": "0000",
                                   "CS": "0813", "IP": "0106", "DS": "0813", "ES": "0813",
                                   "SS": "0813"}
    assert record["cs_ip"] == "0813:0106"
    assert record["paused_at_capture"] is True and record["resumed"] is True
    assert [c["request"] for c in record["commands"]] == [
        "REQ 1 PING", "REQ 2 BREAK", "REQ 3 EXEC EV " + " ".join(dosbox.REGISTERS),
        "REQ 4 EXEC CPU", "REQ 5 EXEC RUN"]
    assert record["cpu_status_text"][0].startswith("cr0:")
    assert record["limits"]


def test_capture_reports_script_error_status():
    port = _free_port()

    def responses(command):
        return ("ERR", ["*** Debugger command not recognized"]) if command == "EXEC CPU" \
            else _default_responses(command)

    record, error = _capture(port, responses)
    assert record is None
    assert isinstance(error, DDTError) and "refused" in str(error)


def test_capture_rejects_mismatched_request_id():
    port = _free_port()
    record, error = _capture(port, force_id="99")
    assert record is None
    assert isinstance(error, DDTError) and "unexpected response header" in str(error)


def test_capture_times_out_without_a_connection():
    port = _free_port()
    started = time.monotonic()
    with pytest.raises(DDTError, match="no DOSBox-X debugger connection"):
        dosbox.capture_cpu(port, settle=0.0, timeout=0.5)
    assert time.monotonic() - started < 5


def test_capture_detects_closed_connection():
    port = _free_port()
    record, error = _capture(port, close_after=1)
    assert record is None
    assert isinstance(error, DDTError) and "closed" in str(error)


def test_invalid_port_and_non_loopback_guard(tmp_path):
    with pytest.raises(DDTError, match="port must be"):
        dosbox.capture_cpu(0, settle=0.0, timeout=0.1)
    assert dosbox._loopback("127.0.0.1") and dosbox._loopback("::1")
    assert not dosbox._loopback("192.168.1.10") and not dosbox._loopback("0.0.0.0")


def test_capture_writes_receipt_outside_dosbox(tmp_path):
    port = _free_port()
    out = tmp_path / "cpu.json"
    record, error = _capture(port, out=out)
    assert error is None
    assert json.loads(out.read_text(encoding="utf-8")) == record


def test_cli_capture_cpu_with_socket_peer(tmp_path):
    port = _free_port()
    peer = _FakeDOSBox(port)
    peer.start()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-m", "ddt", "debugger", "capture-cpu",
                           "--port", str(port), "--settle", "0", "--timeout", "10", "--json"],
                          check=True, capture_output=True, text=True, env=env)
    payload = json.loads(proc.stdout)
    assert payload["registers"]["AX"] == "1234"
    peer.join(timeout=5)
    # Missing subcommand is a clean CLI failure.
    bad = subprocess.run([sys.executable, "-m", "ddt", "debugger"], capture_output=True, text=True, env=env)
    assert bad.returncode == 2
