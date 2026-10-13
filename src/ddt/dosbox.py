"""Read-only CPU-state capture from a DOSBox-X debugger session.

DDT listens on loopback, accepts the single connection that DOSBox-X initiates
when ``[dosbox] mcp_server=<port>`` is set, and drives the documented
line-oriented debugger control protocol (``REQ``/``BEGIN``/``END``). It only
issues PING, BREAK, one register query, one CPU status query, and a resume; no
other debugger command is exposed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import time

from .errors import DDTError

SCHEMA = "ddt.dosbox-cpu.v1"
PROTOCOL = "dosbox-x debugger control (line-oriented REQ/BEGIN/END)"
DEFAULT_PORT = 58991
DEFAULT_TIMEOUT = 60.0
DEFAULT_COMMAND_TIMEOUT = 15.0
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


def _loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1")


def _request(conn: socket.socket, rid: int, command: str, timeout: float) -> dict:
    conn.sendall(f"REQ {rid} {command}\n".encode("ascii"))
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
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise DDTError(f"port must be an integer in 1..65535: {port!r}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("127.0.0.1", port))
    except OSError as exc:
        raise DDTError(f"cannot listen on 127.0.0.1:{port}: {exc}") from exc
    server.listen(1)
    commands: list[dict] = []
    registers: dict[str, str] | None = None
    cpu_status: list[str] = []
    broke = False
    resumed = False
    recovery_error: str | None = None
    failure: DDTError | None = None
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
            try:
                if not _loopback(peer[0]):
                    raise DDTError(f"refused non-loopback debugger connection from {peer[0]}")
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
        finally:
            conn.close()
    finally:
        server.close()
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
