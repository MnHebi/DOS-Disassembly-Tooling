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
SEGMENT, OFFSET, LENGTH = 0x0813, 0x0200, 16


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class _FakeStepMemoryDOSBox(threading.Thread):
    def __init__(self, port, *, advertise_mem=True, advertise_stepin=True, memory_writes=None,
                 registers_after=None, ip_advance=3, malformed_before=False, malformed_after=False,
                 malformed_step=False, conflicting_step=False, stepin_err=False, move_before=False,
                 move_after=False, drop_on=None):
        super().__init__(daemon=True)
        self.port = port
        self.advertise_mem, self.advertise_stepin = advertise_mem, advertise_stepin
        self.memory_writes = memory_writes or {}
        self.registers_after = registers_after or {}
        self.ip_advance, self.malformed_before, self.malformed_after = ip_advance, malformed_before, malformed_after
        self.malformed_step, self.conflicting_step = malformed_step, conflicting_step
        self.stepin_err, self.move_before, self.move_after = stepin_err, move_before, move_after
        self.drop_on = drop_on
        self.regs = dict(STATE)
        self.mem = [0] * LENGTH
        self.ev_calls, self.read_calls, self.step_calls, self.seen = 0, 0, 0, []

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

    def _region_hex(self):
        return "".join(f"{value:02X}" for value in self.mem)

    def _reply(self, command):
        if command == "PING":
            return "OK", ["PONG"]
        if command == "EXEC HELP":
            lines = ["Debugger commands (enter all values in hex or as register):", "-" * 12]
            if self.advertise_mem:
                lines.append("MEMREAD <seg>:<off> <len> - Read 1-256 conventional RAM bytes (external).")
            if self.advertise_stepin:
                lines.append("STEPIN                    - Execute exactly one instruction, then stop.")
            return "OK", lines
        if command.startswith("EXEC EV "):
            names = command.split()[2:]
            self.ev_calls += 1
            state = dict(self.regs)
            if (self.move_before and self.ev_calls == 2) or (self.move_after and self.ev_calls == 4):
                state["IP"] = f"{int(state['IP'], 16) + 1:04X}"
            return "OK", [f"EV of '{' '.join(names)}' is:", " ".join(state[n] for n in names)]
        if command.startswith("EXEC MEMREAD "):
            _, _, seg_off, length = command.split()
            self.read_calls += 1
            if self.malformed_before and self.read_calls == 1:
                return "OK", ["DEBUG: MEMREAD done"]
            if self.malformed_after and self.read_calls == 2:
                return "OK", ["DEBUG: MEMREAD done"]
            return "OK", [f"DEBUG: MEMREAD {seg_off} LEN={length} HEX={self._region_hex()}"]
        if command == "EXEC STEPIN":
            self.step_calls += 1
            if self.stepin_err:
                return "ERR", ["DEBUG: STEPIN requires the debugger to be stopped"]
            if self.malformed_step:
                return "OK", ["DEBUG: STEPIN executed"]
            self.regs.update(self.registers_after)
            for index, value in self.memory_writes.items():
                self.mem[index] = value
            self.regs["IP"] = f"{int(self.regs['IP'], 16) + self.ip_advance:04X}"
            ax = "FFFF" if self.conflicting_step else self.regs["AX"]
            return "OK", [f"DEBUG: STEPIN CS:IP={self.regs['CS']}:{self.regs['IP']} "
                          f"AX={ax} BX={self.regs['BX']} CX={self.regs['CX']} DX={self.regs['DX']}"]
        return "ERR", ["*** Debugger command not recognized"]


def _run(port, peer, **kwargs):
    result, errors = {}, {}

    def target():
        try:
            result["record"] = dosbox.capture_step_memory(port, segment=SEGMENT, offset=OFFSET,
                                                           length=LENGTH, settle=0.0, **kwargs)
        except Exception as exc:  # noqa: BLE001 - captured for assertion
            errors["error"] = exc

    worker = threading.Thread(target=target)
    worker.start()
    peer.start()
    worker.join(timeout=30)
    peer.join(timeout=5)
    return result.get("record"), errors.get("error"), peer


def test_changed_byte_across_one_instruction():
    port = _free_port()
    peer = _FakeStepMemoryDOSBox(port, memory_writes={0: 0x5A}, registers_after={"AX": "1234"})
    record, error, _ = _run(port, peer)
    assert error is None
    assert record["schema"] == "ddt.dosbox-step-memory.v1"
    assert record["capability"] == {"checked_with": "EXEC HELP", "memread_advertised": True,
                                    "stepin_advertised": True,
                                    "evidence": ["MEMREAD <seg>:<off> <len> - Read 1-256 "
                                                 "conventional RAM bytes (external).",
                                                 "STEPIN                    - Execute exactly one "
                                                 "instruction, then stop."]}
    assert record["request"]["cs_ip"] == "0813:0200" and record["request"]["length"] == 16
    assert record["memory_before"]["bytes_hex"] == "00" * 16
    assert record["memory_after"]["bytes_hex"] == "5A" + "00" * 15
    assert record["byte_differences"] == [{"relative_offset": 0, "address": "0813:0200",
                                           "before": "00", "after": "5A"}]
    assert record["changed_byte_count"] == 1
    assert record["register_differences"] == {"AX": ["0000", "1234"], "IP": ["0100", "0103"]}
    assert record["step"]["reported"]["cs_ip"] == "0813:0103"
    assert record["checks"]["step_report_matches_registers"] is True


def test_unchanged_region_with_a_register_only_instruction():
    port = _free_port()
    peer = _FakeStepMemoryDOSBox(port, registers_after={"AX": "1234"})
    record, error, _ = _run(port, peer)
    assert error is None
    assert record["byte_differences"] == [] and record["changed_byte_count"] == 0
    assert record["memory_before"]["bytes_hex"] == record["memory_after"]["bytes_hex"]
    assert record["register_differences"] == {"AX": ["0000", "1234"], "IP": ["0100", "0103"]}
    assert all("relative_offset" not in entry for entry in record["byte_differences"])


@pytest.mark.parametrize("missing,message", [("stepin", "does not advertise STEPIN"),
                                             ("memread", "does not advertise MEMREAD")])
def test_absent_capability_fails_before_any_action(missing, message):
    port = _free_port()
    peer = _FakeStepMemoryDOSBox(port, advertise_stepin=missing != "stepin",
                                 advertise_mem=missing != "memread")
    record, error, peer = _run(port, peer)
    assert record is None and message in str(error)
    assert not any(command.startswith(("EXEC MEMREAD", "EXEC STEPIN")) for command in peer.seen)


@pytest.mark.parametrize("mode,match", [
    ({"malformed_before": True}, "unexpected MEMREAD output"),
    ({"malformed_after": True}, "may already have executed"),
    ({"malformed_step": True}, "did not report"),
    ({"conflicting_step": True}, "disagree"),
    ({"move_before": True}, "CS:IP moved during the initial memory read"),
    ({"move_after": True}, "CS:IP moved during the post-step memory read"),
    ({"stepin_err": True}, "refused STEPIN"),
])
def test_failures_are_reported_without_retrying(mode, match):
    port = _free_port()
    peer = _FakeStepMemoryDOSBox(port, **mode)
    record, error, peer = _run(port, peer)
    assert record is None and match in str(error)
    assert peer.step_calls <= 1
    if peer.step_calls == 0:
        assert "may already have executed" not in str(error)
    else:
        assert "may already have executed" in str(error)
        assert "does not retry" in str(error)


def test_disconnect_before_and_after_the_step():
    port = _free_port()
    peer = _FakeStepMemoryDOSBox(port, drop_on="EXEC MEMREAD")
    record, error, _ = _run(port, peer)
    assert record is None and peer.step_calls == 0
    assert "may already have executed" not in str(error)
    port2 = _free_port()
    peer2 = _FakeStepMemoryDOSBox(port2, malformed_after=True)
    record2, error2, peer2 = _run(port2, peer2)
    assert record2 is None and peer2.step_calls == 1
    assert "may already have executed" in str(error2)


def test_bounds_and_output_preservation(tmp_path):
    for kwargs in ({"segment": 0x10000, "offset": 0, "length": 1},
                   {"segment": 0, "offset": 0, "length": 0},
                   {"segment": 0, "offset": 0, "length": 257},
                   {"segment": 0, "offset": 0, "length": True},
                   {"segment": 0xFFFF, "offset": 0xFFFF, "length": 2}):
        with pytest.raises(DDTError):
            dosbox.capture_step_memory(1, settle=0.0, **kwargs)
    port = _free_port()
    out = tmp_path / "step-memory.json"
    out.write_text("KEEP", encoding="utf-8")
    record, error, _ = _run(port, _FakeStepMemoryDOSBox(port, malformed_step=True), out=out)
    assert record is None and out.read_text(encoding="utf-8") == "KEEP"


def test_cli_capture_step_memory(tmp_path):
    port = _free_port()
    peer = _FakeStepMemoryDOSBox(port, memory_writes={0: 0x5A}, registers_after={"AX": "1234"})
    peer.start()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    out = tmp_path / "step-memory.json"
    proc = subprocess.run([sys.executable, "-m", "ddt", "debugger", "capture-step-memory",
                           "--port", str(port), "--segment", "0x0813", "--offset", "0x0200",
                           "--length", "16", "--settle", "0", "--timeout", "10",
                           "--out", str(out), "--json"],
                          check=True, capture_output=True, text=True, env=env)
    payload = json.loads(proc.stdout)
    assert payload["changed_byte_count"] == 1
    assert payload["byte_differences"][0]["after"] == "5A"
    assert json.loads(out.read_text(encoding="utf-8")) == payload
    peer.join(timeout=5)
