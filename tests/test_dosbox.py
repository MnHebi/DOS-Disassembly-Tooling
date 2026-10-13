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
        self.seen: list[str] = []

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
                    self.seen.append(command)
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
    return result.get("record"), errors.get("error"), peer


def test_capture_parses_registers_and_cpu_state():
    port = _free_port()
    record, error, _ = _capture(port)
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

    record, error, _ = _capture(port, responses)
    assert record is None
    assert isinstance(error, DDTError) and "refused" in str(error)


def test_capture_rejects_mismatched_request_id():
    port = _free_port()
    record, error, _ = _capture(port, force_id="99")
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
    record, error, _ = _capture(port, close_after=1)
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
    record, error, _ = _capture(port, out=out)
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


# --- Stage 1: pause/resume recovery ------------------------------------------

def _failing_responses(failing: str, *, error=True):
    def responses(command):
        if error and (command == failing or command.startswith(failing)):
            return "ERR", ["*** Debugger command not recognized"]
        return _default_responses(command)
    return responses


def test_ev_failure_after_break_still_attempts_resume():
    port = _free_port()
    record, error, peer = _capture(port, _failing_responses("EXEC EV"))
    assert record is None
    assert "register query was refused" in str(error)
    assert "resume also failed" not in str(error)
    assert any(command.startswith("EXEC RUN") for command in peer.seen)


def test_cpu_failure_after_break_still_attempts_resume():
    port = _free_port()
    record, error, peer = _capture(port, _failing_responses("EXEC CPU"))
    assert record is None
    assert "CPU status query was refused" in str(error)
    assert any(command.startswith("EXEC RUN") for command in peer.seen)


def test_original_error_preserved_when_recovery_also_fails():
    port = _free_port()
    record, error, _ = _capture(port, _failing_responses("EXEC EV"), close_after=3)
    assert record is None
    assert isinstance(error, DDTError)
    text = str(error)
    assert "register query was refused" in text and "resume also failed" in text


def test_run_failure_is_reported_without_losing_the_capture():
    port = _free_port()
    record, error, _ = _capture(port, _failing_responses("EXEC RUN"))
    assert error is None
    assert record["resumed"] is False and record["left_paused"] is False
    assert any("resumed" in entry for entry in record["unknown"])


def test_leave_paused_skips_resume():
    port = _free_port()
    record, error, peer = _capture(port, leave_paused=True)
    assert error is None
    assert record["left_paused"] is True and record["resumed"] is False
    assert not any(command.startswith("EXEC RUN") for command in peer.seen)


# --- Stage 2: breakpoint capture --------------------------------------------

class _FakeBreakpointDOSBox(threading.Thread):
    def __init__(self, port, *, install_state="0813:0100", stop_state="0813:0103",
                 pre_existing=(), ignore_install=False, install_address=None,
                 refuse_delete=False, fail_bplist_after=None, drop_on=None):
        super().__init__(daemon=True)
        self.port, self.install_state, self.stop_state = port, install_state, stop_state
        self.bps = {}
        for index, entry in enumerate(pre_existing):
            self.bps[f"{index:02d}"] = entry
        self.ignore_install, self.seen, self.cs_ip_calls = ignore_install, [], 0
        self.install_address, self.refuse_delete = install_address, refuse_delete
        self.fail_bplist_after, self.drop_on, self.bplist_calls = fail_bplist_after, drop_on, 0

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
        if command == "BREAK":
            return "OK", ["***| TYPE HELP |***"]
        if command.startswith("EXEC BP "):
            if not self.ignore_install:
                number = f"{len(self.bps):02d}"
                self.bps[number] = f"{number}. BP {self.install_address or command.split()[2]}"
            return "OK", ["DEBUG: Set breakpoint"]
        if command == "EXEC BPLIST":
            self.bplist_calls += 1
            if self.fail_bplist_after is not None and self.bplist_calls > self.fail_bplist_after:
                return "ERR", ["*** BPLIST failed"]
            return "OK", ["Breakpoint list:", "-" * 10, *self.bps.values()]
        if command.startswith("EXEC BPDEL "):
            if self.refuse_delete:
                return "ERR", ["*** Breakpoint deletion refused"]
            self.bps.pop(command.split()[2], None)
            return "OK", ["DEBUG: Breakpoint deletion success."]
        if command == "EXEC RUN":
            return "OK", ["OK"]
        if command == "EXEC EV CS IP":
            self.cs_ip_calls += 1
            state = self.install_state if self.cs_ip_calls == 1 else self.stop_state
            return "OK", ["EV of 'CS IP' is:", state.replace(":", " ")]
        if command.startswith("EXEC EV AX"):
            return "OK", ["EV of 'AX ...' is:",
                          "1234 5678 0000 0000 0000 0000 0000 0000 0813 0103 0813 0813 0813"]
        return "ERR", ["*** Debugger command not recognized"]


def _capture_bp(port, **kwargs):
    result, errors = {}, {}
    peer = kwargs.pop("peer") if "peer" in kwargs else _FakeBreakpointDOSBox(port)

    def target():
        try:
            result["record"] = dosbox.capture_breakpoint(port, segment=0x0813, offset=0x0103,
                                                          settle=0.0, **kwargs)
        except Exception as exc:  # noqa: BLE001 - captured for assertion
            errors["error"] = exc

    worker = threading.Thread(target=target)
    worker.start()
    peer.start()
    worker.join(timeout=20)
    peer.join(timeout=5)
    return result.get("record"), errors.get("error"), peer


def test_breakpoint_hit_is_confirmed_and_cleaned_up():
    port = _free_port()
    record, error, peer = _capture_bp(port, confirm=3)
    assert error is None
    assert record["schema"] == "ddt.dosbox-breakpoint.v2"
    assert record["requested"]["cs_ip"] == "0813:0103"
    assert record["target_ip_observed_stable"] is True
    assert record["breakpoint_hit_verified"] is None and record["stop_reason"] is None
    assert record["paused_state"] == "unknown"
    assert record["observed_stop_cs_ip"] == "0813:0103"
    assert record["confirmation"] == {"count": 3, "polls": ["0813:0103"] * 3}
    assert record["breakpoint"]["number"] == "00"
    assert record["breakpoint"]["address_matches_requested"] is True
    assert record["cleanup"] == {"number": "00", "delete_acknowledged": True,
                                 "final_list_verified": True, "removal_verified": True,
                                 "list_after_delete": []}
    assert record["run_acknowledged"] is True and record["left_paused"] is False
    assert record["registers"]["AX"] == "1234"
    assert record["install_time_cs_ip"] == "0813:0100"
    assert any("no asynchronous breakpoint-hit event" in limit for limit in record["limits"])
    assert any("observational evidence" in limit for limit in record["limits"])


def test_unrelated_user_breakpoint_is_preserved():
    port = _free_port()
    peer = _FakeBreakpointDOSBox(port, pre_existing=["00. BP 0813:0200"])
    record, error, _ = _capture_bp(port, peer=peer, confirm=2)
    assert error is None
    assert record["breakpoint"]["number"] == "01"
    assert record["cleanup"]["list_after_delete"] == ["00. BP 0813:0200"]
    assert record["cleanup"]["removal_verified"] is True


def test_missing_hit_is_reported_and_cleaned_up():
    port = _free_port()
    peer = _FakeBreakpointDOSBox(port, stop_state="0813:0106")
    record, error, _ = _capture_bp(port, peer=peer, confirm=2)
    assert record is None
    assert "was not observed to stop" in str(error)
    assert peer.bps == {}  # DDT removed only its own breakpoint
    assert any(command.startswith("EXEC RUN") for command in peer.seen)


def test_ambiguous_install_is_rejected_and_not_deleted():
    port = _free_port()
    peer = _FakeBreakpointDOSBox(port, ignore_install=True, pre_existing=["00. BP 0813:0200"])
    record, error, _ = _capture_bp(port, peer=peer, confirm=2)
    assert record is None
    assert "could not identify exactly one new breakpoint" in str(error)
    assert not any(command.startswith("EXEC BPDEL") for command in peer.seen)
    assert peer.bps == {"00": "00. BP 0813:0200"}


def test_breakpoint_validation_and_leave_paused():
    with pytest.raises(DDTError, match="segment and offset"):
        dosbox.capture_breakpoint(1, segment=0x10000, offset=0)
    port = _free_port()
    record, error, peer = _capture_bp(port, confirm=2, leave_paused=True)
    assert error is None
    assert record["left_paused"] is True and record["run_acknowledged"] is False


def test_cli_capture_breakpoint(tmp_path):
    port = _free_port()
    peer = _FakeBreakpointDOSBox(port)
    peer.start()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-m", "ddt", "debugger", "capture-breakpoint",
                           "--port", str(port), "--segment", "0x0813", "--offset", "0x0103",
                           "--settle", "0", "--timeout", "10", "--confirm", "2", "--json"],
                          check=True, capture_output=True, text=True, env=env)
    payload = json.loads(proc.stdout)
    assert payload["target_ip_observed_stable"] is True
    assert payload["breakpoint_hit_verified"] is None
    assert payload["observed_stop_cs_ip"] == "0813:0103"
    peer.join(timeout=5)


def test_stable_pointer_is_observational_not_a_verified_hit():
    # Even when the pointer is stable at the target, DDT must not claim a verified stop.
    port = _free_port()
    record, error, _ = _capture_bp(port, confirm=4)
    assert error is None
    assert record["target_ip_observed_stable"] is True
    assert record["breakpoint_hit_verified"] is None
    assert record["stop_reason"] is None and record["paused_state"] == "unknown"
    assert any("tight self-loop" in limit for limit in record["limits"])


def test_breakpoint_owned_at_the_wrong_address_is_not_deleted():
    port = _free_port()
    peer = _FakeBreakpointDOSBox(port, install_address="0813:0999")
    record, error, _ = _capture_bp(port, peer=peer, confirm=2)
    assert record is None
    assert "does not correspond to the requested" in str(error)
    assert "manual" in str(error)
    assert not any(command.startswith("EXEC BPDEL") for command in peer.seen)
    assert peer.bps == {"00": "00. BP 0813:0999"}


def test_failed_final_bplist_is_reported_as_unverified():
    port = _free_port()
    peer = _FakeBreakpointDOSBox(port, fail_bplist_after=2)  # before + after succeed, final fails
    record, error, _ = _capture_bp(port, peer=peer, confirm=2)
    assert error is None
    assert record["cleanup"]["delete_acknowledged"] is True
    assert record["cleanup"]["final_list_verified"] is False
    assert record["cleanup"]["removal_verified"] is False
    assert any("whether the breakpoint DDT installed was removed" in u for u in record["unknown"])


def test_refused_bpdel_leaves_removal_unverified():
    port = _free_port()
    peer = _FakeBreakpointDOSBox(port, refuse_delete=True)
    record, error, _ = _capture_bp(port, peer=peer, confirm=2)
    assert error is None
    assert record["cleanup"]["delete_acknowledged"] is False
    assert record["cleanup"]["removal_verified"] is False
    assert any("BPDEL was refused" in u for u in record["unknown"])
    assert peer.bps == {"00": "00. BP 0813:0103"}  # still installed


def test_connection_loss_during_cleanup_is_unverified():
    port = _free_port()
    peer = _FakeBreakpointDOSBox(port, drop_on="EXEC BPDEL")
    record, error, _ = _capture_bp(port, peer=peer, confirm=2)
    assert error is None
    assert record["cleanup"]["final_list_verified"] is False
    assert record["cleanup"]["removal_verified"] is False
    assert record["run_acknowledged"] is False
    assert any("cleanup" in u for u in record["unknown"])


def test_failed_capture_preserves_existing_output_and_original_error(tmp_path):
    port = _free_port()
    out = tmp_path / "bp.json"
    out.write_text("KEEP-ME", encoding="utf-8")
    peer = _FakeBreakpointDOSBox(port, stop_state="0813:0106")
    record, error, _ = _capture_bp(port, peer=peer, confirm=2, out=out)
    assert record is None
    assert "was not observed to stop" in str(error)
    assert out.read_text(encoding="utf-8") == "KEEP-ME"
    assert peer.bps == {}  # its own breakpoint was still removed during recovery
