"""Read-only CPU-state capture from a DOSBox-X debugger session.

DDT listens on loopback, accepts the single connection that DOSBox-X initiates
when ``[dosbox] mcp_server=<port>`` is set, and drives the documented
line-oriented debugger control protocol (``REQ``/``BEGIN``/``END``). It only
issues PING, BREAK, register/CPU queries, a breakpoint install/list/delete, and a
resume; no other debugger command is exposed.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import time

from .errors import DDTError

SCHEMA = "ddt.dosbox-cpu.v1"
BREAKPOINT_SCHEMA = "ddt.dosbox-breakpoint.v2"
PROTOCOL = "dosbox-x debugger control (line-oriented REQ/BEGIN/END)"
DEFAULT_PORT = 58991
DEFAULT_TIMEOUT = 60.0
DEFAULT_COMMAND_TIMEOUT = 15.0
DEFAULT_CONFIRM = 4
DEFAULT_CONFIRM_WINDOW = 1.6
MAX_RESPONSE_BYTES = 1 << 20
MAX_RESPONSE_LINES = 4096
REGISTERS = ("AX", "BX", "CX", "DX", "SI", "DI", "BP", "SP", "CS", "IP", "DS", "ES", "SS")

_LIMITS = [
    "Register and CPU values are DOSBox-X runtime observations, not Ghidra addresses "
    "or original file offsets; the two are never equated",
    "Only the registers explicitly requested with EV are parsed; other CPU state is raw text",
    "The DOSBox-X build identity is not obtainable over this protocol; pass "
    "--dosbox-version to record it",
    "The listener accepts one loopback client and one pending command at a time",
    "These values are static-analysis-free observations made at the moment of the break",
    "An accepted RUN is an acknowledgement, not proof that emulation actually resumed",
    "DDT cannot tell whether the debugger was already paused before BREAK; --leave-paused "
    "avoids resuming a user's own paused session",
]

_BREAKPOINT_LIMITS = _LIMITS + [
    "DOSBox-X exposes no asynchronous breakpoint-hit event: the control channel only has "
    "PING, BREAK and EXEC, and ControlServer_SendEvent is never called",
    "target_ip_observed_stable only means repeated CS:IP observations matched the requested "
    "address after RUN, without issuing another BREAK; it is observational evidence",
    "breakpoint_hit_verified and stop_reason stay null: the protocol has no hit event or "
    "stopped-state query, so a tight self-loop at the target can look identical",
    "Schema ddt.dosbox-breakpoint.v2 replaces v1: hit_confirmed/resumed/paused_at_capture are "
    "replaced by target_ip_observed_stable, breakpoint_hit_verified and run_acknowledged",
    "Only the address-verified breakpoint DDT installed is deleted; unrelated user breakpoints "
    "are preserved and BPDEL * is never used",
]


def _loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1")


@contextlib.contextmanager
def _accepted_connection(port: int, timeout: float):
    """Bind loopback, accept exactly one DOSBox-X connection, and clean up."""
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise DDTError(f"port must be an integer in 1..65535: {port!r}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("127.0.0.1", port))
    except OSError as exc:
        raise DDTError(f"cannot listen on 127.0.0.1:{port}: {exc}") from exc
    server.listen(1)
    try:
        server.settimeout(timeout)
        try:
            conn, peer = server.accept()
        except socket.timeout as exc:
            raise DDTError(
                f"no DOSBox-X debugger connection on 127.0.0.1:{port} within {timeout:g}s") from exc
        except OSError as exc:
            raise DDTError(f"listener failed on 127.0.0.1:{port}: {exc}") from exc
        try:
            if not _loopback(peer[0]):
                raise DDTError(f"refused non-loopback debugger connection from {peer[0]}")
            yield conn
        finally:
            conn.close()
    finally:
        server.close()


def _request(conn: socket.socket, rid: int, command: str, timeout: float) -> dict:
    try:
        conn.sendall(f"REQ {rid} {command}\n".encode("ascii"))
    except OSError as exc:
        raise DDTError(f"connection error sending request {rid}: {exc}") from exc
    deadline = time.monotonic() + timeout
    lines: list[str] = []
    buffer = b""
    total = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DDTError(f"timed out waiting for a response to request {rid}")
        conn.settimeout(remaining)
        try:
            chunk = conn.recv(4096)
        except socket.timeout as exc:
            raise DDTError(f"timed out waiting for a response to request {rid}") from exc
        except OSError as exc:
            raise DDTError(f"connection error on request {rid}: {exc}") from exc
        if not chunk:
            raise DDTError(f"connection closed while waiting for request {rid}")
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise DDTError(f"response to request {rid} exceeded {MAX_RESPONSE_BYTES} bytes")
        buffer += chunk
        while b"\n" in buffer:
            raw, buffer = buffer.split(b"\n", 1)
            line = raw.decode("utf-8", "replace").rstrip("\r")
            lines.append(line)
            if len(lines) > MAX_RESPONSE_LINES:
                raise DDTError(f"response to request {rid} exceeded {MAX_RESPONSE_LINES} lines")
            if len(lines) == 1 and not (line.startswith(f"BEGIN {rid} ")
                                        and line.rsplit(" ", 1)[-1] in ("OK", "ERR")):
                raise DDTError(f"unexpected response header for request {rid}: {line!r}")
            if line == f"END {rid}":
                return {"request": f"REQ {rid} {command}",
                        "status": "OK" if lines[0].endswith("OK") else "ERR",
                        "raw": lines[1:-1]}


def _parse_registers(raw: list[str]) -> dict[str, str] | None:
    tokens = " ".join(raw[1:]).split() if len(raw) > 1 else []
    if len(tokens) != len(REGISTERS):
        return None
    for token in tokens:
        try:
            int(token, 16)
        except ValueError:
            return None
    return dict(zip(REGISTERS, tokens))


def _hex16(value: int) -> str:
    return f"{value:04X}"


def _observed_state(conn: socket.socket, rid: int, timeout: float) -> tuple[dict, tuple[str, str] | None]:
    """Observe CS:IP; returns (raw response, normalized (segment, offset) or None)."""
    response = _request(conn, rid, "EXEC EV CS IP", timeout)
    if response["status"] != "OK":
        return response, None
    body = [line for line in response["raw"] if not line.startswith("EV of")]
    tokens = " ".join(body).split()
    if len(tokens) != 2:
        return response, None
    try:
        return response, (_hex16(int(tokens[0], 16)), _hex16(int(tokens[1], 16)))
    except ValueError:
        return response, None


def _breakpoint_list(conn: socket.socket, rid: int, timeout: float) -> tuple[dict, list[str]]:
    response = _request(conn, rid, "EXEC BPLIST", timeout)
    if response["status"] != "OK":
        raise DDTError(f"BPLIST was refused: {response['raw']}")
    return response, [line.strip() for line in response["raw"] if " BP " in line]


def _breakpoint_number(entry: str) -> str:
    return entry.split(".", 1)[0].strip()


def _entry_address(entry: str) -> str | None:
    """Normalize the runtime address of a BPLIST entry, or None if unreadable."""
    parts = entry.split(" BP ", 1)
    if len(parts) != 2:
        return None
    try:
        segment, offset = parts[1].strip().split(":", 1)
        return f"{int(segment, 16):04X}:{int(offset, 16):04X}"
    except (ValueError, IndexError):
        return None


def _write_json(destination: Path, record: dict) -> None:
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=destination.name + ".", dir=destination.parent))
    except OSError as exc:
        raise DDTError(f"cannot stage the observation next to {destination}: {exc}") from exc
    try:
        staged = staging / "observation.json"
        staged.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(staged, destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def capture_cpu(port: int = DEFAULT_PORT, *, settle: float = 3.0, timeout: float = DEFAULT_TIMEOUT,
                command_timeout: float = DEFAULT_COMMAND_TIMEOUT, dosbox_version: str | None = None,
                out: str | Path | None = None, leave_paused: bool = False) -> dict:
    """Listen for one DOSBox-X debugger connection and record its CPU state."""
    commands: list[dict] = []
    registers: dict[str, str] | None = None
    cpu_status: list[str] = []
    broke = False
    resumed = False
    recovery_error: str | None = None
    failure: DDTError | None = None
    with _accepted_connection(port, timeout) as conn:
        try:
            commands.append(_request(conn, 1, "PING", command_timeout))
            if commands[-1]["status"] != "OK" or commands[-1]["raw"] != ["PONG"]:
                raise DDTError("DOSBox-X debugger did not answer PING with PONG")
            if settle > 0:
                time.sleep(settle)
            commands.append(_request(conn, 2, "BREAK", command_timeout))
            if commands[-1]["status"] != "OK":
                raise DDTError(f"BREAK was refused: {commands[-1]['raw']}")
            broke = True
            commands.append(_request(conn, 3, "EXEC EV " + " ".join(REGISTERS), command_timeout))
            if commands[-1]["status"] != "OK":
                raise DDTError(f"register query was refused: {commands[-1]['raw']}")
            registers = _parse_registers(commands[-1]["raw"])
            commands.append(_request(conn, 4, "EXEC CPU", command_timeout))
            if commands[-1]["status"] != "OK":
                raise DDTError(f"CPU status query was refused: {commands[-1]['raw']}")
            cpu_status = commands[-1]["raw"]
        except DDTError as exc:
            failure = exc
        finally:
            # Recovery: do not leave an emulator we paused parked in the debugger.
            if broke and not leave_paused:
                try:
                    run = _request(conn, 5, "EXEC RUN", command_timeout)
                except DDTError as exc:
                    recovery_error = str(exc)
                else:
                    commands.append(run)
                    resumed = run["status"] == "OK"
    if failure is not None:
        message = str(failure)
        if recovery_error is not None:
            message += f"; the debugger resume also failed: {recovery_error}"
        raise DDTError(message) from failure

    cs_ip = f"{registers['CS']}:{registers['IP']}" if registers else None
    unknown = ["DOSBox-X build identity (not queried over the protocol)"] if not dosbox_version else []
    if registers is None:
        unknown.append("individual register values (register response was not parseable)")
    if not resumed and not leave_paused:
        unknown.append("whether emulation resumed (the RUN acknowledgement was not received)")
    record = {
        "schema": SCHEMA,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "protocol": PROTOCOL,
        "dosbox_version": dosbox_version,
        "paused_at_capture": True,
        "resumed": resumed,
        "left_paused": leave_paused,
        "commands": commands,
        "registers": registers,
        "register_order": list(REGISTERS) if registers else None,
        "cs_ip": cs_ip,
        "cpu_status_text": cpu_status,
        "observed": ["PING/PONG handshake", "BREAK", "registers from EXEC EV",
                     "CPU status from EXEC CPU"]
                    + ([] if leave_paused else ["resume requested (RUN acknowledgement recorded)"]),
        "unknown": unknown,
        "limits": list(_LIMITS),
    }
    if out is not None:
        _write_json(Path(out), record)
    return record


def capture_breakpoint(port: int = DEFAULT_PORT, *, segment: int, offset: int, settle: float = 3.0,
                       timeout: float = DEFAULT_TIMEOUT, command_timeout: float = DEFAULT_COMMAND_TIMEOUT,
                       confirm: int = DEFAULT_CONFIRM, confirm_window: float = DEFAULT_CONFIRM_WINDOW,
                       dosbox_version: str | None = None, out: str | Path | None = None,
                       leave_paused: bool = False) -> dict:
    """Install one real-mode breakpoint, confirm a stop at it, then clean up.

    DOSBox-X exposes no asynchronous breakpoint-hit event, so the hit is only
    reported when CS:IP is observed pinned to the requested address across
    several differently spaced register queries after resuming.
    """
    if not (isinstance(segment, int) and 0 <= segment <= 0xFFFF
            and isinstance(offset, int) and 0 <= offset <= 0xFFFF):
        raise DDTError(f"segment and offset must each be 0..65535: {segment!r}:{offset!r}")
    if confirm < 2:
        raise DDTError("confirm must be at least 2")
    target = f"{_hex16(segment)}:{_hex16(offset)}"
    commands: list[dict] = []
    broke = False
    resumed = False
    recovery_error: str | None = None
    failure: DDTError | None = None
    owned: str | None = None
    delete_acknowledged = False
    final_list_verified = False
    cleanup_error: str | None = None
    registers: dict[str, str] | None = None
    polls: list[str] = []
    list_before: list[str] = []
    list_after: list[str] = []
    list_final: list[str] = []
    install_time: str | None = None
    rid = 0

    def next_rid() -> int:
        nonlocal rid
        rid += 1
        return rid

    with _accepted_connection(port, timeout) as conn:
        try:
            commands.append(_request(conn, next_rid(), "PING", command_timeout))
            if commands[-1]["status"] != "OK" or commands[-1]["raw"] != ["PONG"]:
                raise DDTError("DOSBox-X debugger did not answer PING with PONG")
            if settle > 0:
                time.sleep(settle)
            commands.append(_request(conn, next_rid(), "BREAK", command_timeout))
            if commands[-1]["status"] != "OK":
                raise DDTError(f"BREAK was refused: {commands[-1]['raw']}")
            broke = True
            response, state = _observed_state(conn, next_rid(), command_timeout)
            commands.append(response)
            install_time = f"{state[0]}:{state[1]}" if state else None
            response, list_before = _breakpoint_list(conn, next_rid(), command_timeout)
            commands.append(response)
            install = _request(conn, next_rid(), f"EXEC BP {target}", command_timeout)
            commands.append(install)
            if install["status"] != "OK":
                raise DDTError(f"breakpoint installation was refused: {install['raw']}")
            response, list_after = _breakpoint_list(conn, next_rid(), command_timeout)
            commands.append(response)
            added = [entry for entry in list_after if entry not in list_before]
            if len(added) != 1:
                raise DDTError(f"could not identify exactly one new breakpoint (found {len(added)}); "
                               "not deleting anything, inspect the debugger's breakpoint table manually")
            if _entry_address(added[0]) != target:
                raise DDTError(f"the new breakpoint {added[0]!r} does not correspond to the requested "
                               f"{target}; not deleting it, inspect the breakpoint table manually")
            owned = _breakpoint_number(added[0])
            run = _request(conn, next_rid(), "EXEC RUN", command_timeout)
            commands.append(run)
            if run["status"] != "OK":
                raise DDTError(f"resume before the breakpoint was refused: {run['raw']}")
            steps = confirm * (confirm + 1) // 2
            for index in range(confirm):
                time.sleep(confirm_window * (index + 1) / steps)
                response, polled = _observed_state(conn, next_rid(), command_timeout)
                commands.append(response)
                if response["status"] != "OK":
                    raise DDTError(f"register query was refused while checking the breakpoint: "
                                   f"{response['raw']}")
                polls.append(f"{polled[0]}:{polled[1]}" if polled else "<unreadable>")
            if any(value != target for value in polls):
                raise DDTError(f"execution was not observed to stop at {target} "
                               f"(observed {polls})")
            reg = _request(conn, next_rid(), "EXEC EV " + " ".join(REGISTERS), command_timeout)
            commands.append(reg)
            registers = _parse_registers(reg["raw"]) if reg["status"] == "OK" else None
        except DDTError as exc:
            failure = exc
        finally:
            # Recovery: remove only the breakpoint DDT installed, then resume.
            if owned is not None:
                try:
                    delete = _request(conn, next_rid(), f"EXEC BPDEL {owned}", command_timeout)
                except DDTError as exc:
                    cleanup_error = str(exc)
                else:
                    commands.append(delete)
                    delete_acknowledged = delete["status"] == "OK"
                    if not delete_acknowledged:
                        cleanup_error = f"BPDEL was refused: {delete['raw']}"
                try:
                    response, list_final = _breakpoint_list(conn, next_rid(), command_timeout)
                    commands.append(response)
                    final_list_verified = True
                except DDTError as exc:
                    cleanup_error = cleanup_error or str(exc)
            if broke and not leave_paused:
                try:
                    run = _request(conn, next_rid(), "EXEC RUN", command_timeout)
                except DDTError as exc:
                    recovery_error = recovery_error or str(exc)
                else:
                    commands.append(run)
                    resumed = run["status"] == "OK"
    if failure is not None:
        message = str(failure)
        recovery = recovery_error or cleanup_error
        if recovery is not None:
            message += f"; the debugger recovery also failed: {recovery}"
        raise DDTError(message) from failure

    removal_verified = (owned is not None and final_list_verified
                        and all(owned != _breakpoint_number(entry) for entry in list_final))
    if owned is not None and final_list_verified and not removal_verified:
        cleanup_error = cleanup_error or "the breakpoint is still present in the final list"
    unknown = ["verified stop reason (the protocol exposes no breakpoint-hit event)"]
    if not dosbox_version:
        unknown.append("DOSBox-X build identity (not queried over the protocol)")
    unknown.append("whether the emulator is paused or running (no stopped-state query exists)")
    if not removal_verified:
        unknown.append("whether the breakpoint DDT installed was removed")
        if cleanup_error:
            unknown.append(f"breakpoint cleanup: {cleanup_error}")
    if not resumed and not leave_paused:
        unknown.append("whether emulation resumed (the RUN acknowledgement was not received)")
    record = {
        "schema": BREAKPOINT_SCHEMA,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "protocol": PROTOCOL,
        "dosbox_version": dosbox_version,
        "requested": {"segment": _hex16(segment), "offset": _hex16(offset), "cs_ip": target},
        "install_time_cs_ip": install_time,
        "breakpoint": {"list_before": list_before, "list_after": list_after, "number": owned,
                       "address_matches_requested": True},
        "target_ip_observed_stable": True,
        "breakpoint_hit_verified": None,
        "observed_stop_cs_ip": polls[-1] if polls else None,
        "stop_reason": None,
        "confirmation": {"count": len(polls), "polls": polls},
        "registers": registers,
        "register_order": list(REGISTERS) if registers else None,
        "paused_state": "unknown",
        "left_paused": leave_paused,
        "run_acknowledged": resumed,
        "cleanup": {"number": owned, "delete_acknowledged": delete_acknowledged,
                    "final_list_verified": final_list_verified,
                    "removal_verified": removal_verified, "list_after_delete": list_final},
        "commands": commands,
        "unknown": unknown,
        "limits": list(_BREAKPOINT_LIMITS),
    }
    if out is not None:
        _write_json(Path(out), record)
    return record
