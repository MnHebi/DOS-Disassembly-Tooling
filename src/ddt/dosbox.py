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
import re
import shutil
import socket
import tempfile
import time

from .errors import DDTError

SCHEMA = "ddt.dosbox-cpu.v1"
BREAKPOINT_SCHEMA = "ddt.dosbox-breakpoint.v2"
STEPS_SCHEMA = "ddt.dosbox-steps.v1"
MEMORY_SCHEMA = "ddt.dosbox-memory.v1"
STEP_MEMORY_SCHEMA = "ddt.dosbox-step-memory.v1"
PROTOCOL = "dosbox-x debugger control (line-oriented REQ/BEGIN/END)"
DEFAULT_PORT = 58991
DEFAULT_TIMEOUT = 60.0
DEFAULT_COMMAND_TIMEOUT = 15.0
DEFAULT_CONFIRM = 4
DEFAULT_CONFIRM_WINDOW = 1.6
DEFAULT_STEPS = 1
MAX_STEPS = 64
MAX_MEMORY_BYTES = 256
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
]

_RESUME_LIMITS = [
    "An accepted RUN is an acknowledgement, not proof that emulation actually resumed",
    "DDT cannot tell whether the debugger was already paused before BREAK; --leave-paused "
    "avoids resuming a user's own paused session",
]

_CPU_LIMITS = _LIMITS + [
    "These values are static-analysis-free observations made at the moment of the BREAK",
] + _RESUME_LIMITS

_BREAKPOINT_LIMITS = _LIMITS + _RESUME_LIMITS + [
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

_STEPS_LIMITS = _LIMITS + [
    "Each step is one guest instruction executed by DOSBox-X's DEBUG_Run(1); register values are "
    "runtime observations, not Ghidra addresses, module offsets or original file offsets",
    "No instruction bytes, mnemonics or semantics are inferred from the observed register values",
    "A step may be a jump, call or interrupt, so CS:IP can move non-sequentially and an INT may "
    "enter an interrupt handler instead of returning to the caller",
    "STEPIN is an experimental DOSBox-X capability published in an experimental patch; upstream "
    "DOSBox-X 2026.10.01 does not provide it",
    "The debugger must already be stopped at the intended instruction (for example via DEBUGBOX); "
    "DDT never issues BREAK to establish a starting point",
]

_STEP_LINE = re.compile(
    r"CS:IP=([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4})\s+AX=([0-9A-Fa-f]{1,4})\s+BX=([0-9A-Fa-f]{1,4})")
_MEMREAD_LINE = re.compile(
    r"(?:DEBUG:\s*)?MEMREAD ([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4})\s+LEN=([0-9A-Fa-f]{1,4})"
    r"\s+HEX=([0-9A-Fa-f]+)")

_MEMORY_LIMITS = _LIMITS + [
    "The bytes are DOSBox-X's observation of conventional RAM at the moment of the read; they are "
    "not Ghidra addresses, module offsets or original file offsets",
    "Only real-mode conventional RAM below A0000h is read, and only while the debugger is stopped",
    "MEMREAD is an experimental DOSBox-X capability published in an experimental patch; upstream "
    "DOSBox-X 2026.10.01 does not provide it",
    "A memory capture does not establish the identity of the executable that produced it",
    "The read is read-only: no guest instruction is executed and the observed CS:IP is unchanged",
]

_STEP_MEMORY_LIMITS = _LIMITS + [
    "A changed byte is evidence that the observed RAM differed between the two reads, not proof "
    "that the single stepped instruction was the only possible cause",
    "Zero changed bytes means no difference was observed inside the selected region; it does not "
    "establish that the instruction wrote nothing elsewhere",
    "Register observations cover only the registers DDT reads, not all processor state, flags or "
    "side effects",
    "A stable CS:IP across the memory reads is a consistency observation, not proof that the "
    "debugger is internally paused",
    "No executable identity is claimed from this runtime observation alone",
    "Execution is left stopped in the debugger after the single step",
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
    try:
        # DOSBox-X prints unpadded hex; normalize to fixed-width uppercase so
        # records are stable and CS:IP reads consistently (no value is inferred).
        return {name: f"{int(token, 16):04X}" for name, token in zip(REGISTERS, tokens)}
    except ValueError:
        return None


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


def _advertises(raw_lines: list[str], name: str) -> bool:
    """True only when the debugger HELP lists an entry for exactly this command."""
    for line in raw_lines:
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0] == name and "-" in parts[1]:
            return True
    return False


def _parse_step_line(raw_lines: list[str]) -> dict | None:
    for line in raw_lines:
        match = _STEP_LINE.search(line)
        if match:
            cs, ip, ax, bx = (f"{int(value, 16):04X}" for value in match.groups())
            return {"cs": cs, "ip": ip, "cs_ip": f"{cs}:{ip}", "AX": ax, "BX": bx}
    return None


def _parse_memread_line(raw_lines: list[str], expected_segment: str, expected_offset: str,
                        expected_length: int) -> dict:
    """Return the single MEMREAD data record, or raise a precise DDTError.

    Only one complete data line is accepted; anything else that mentions MEMREAD
    (a prefix/suffix, a duplicate, or a conflicting record) is rejected rather
    than treated as a successful read.
    """
    records, unexpected = [], []
    for line in raw_lines:
        if "MEMREAD" not in line:
            continue
        match = _MEMREAD_LINE.fullmatch(line.strip())
        if match is None:
            unexpected.append(line)
        else:
            records.append(match)
    if unexpected:
        raise DDTError(f"unexpected MEMREAD output: {unexpected[0]!r}")
    if not records:
        raise DDTError(f"the MEMREAD response did not report address, length and bytes "
                       f"({raw_lines!r})")
    if len(records) > 1:
        raise DDTError(f"the MEMREAD response reported {len(records)} data records, not one")
    segment, offset, length, hex_bytes = records[0].groups()
    segment, offset = f"{int(segment, 16):04X}", f"{int(offset, 16):04X}"
    recorded = int(length, 16)
    hex_bytes = hex_bytes.upper()
    if segment != expected_segment or offset != expected_offset:
        raise DDTError(f"the MEMREAD response is for {segment}:{offset}, "
                       f"not {expected_segment}:{expected_offset}")
    if recorded != expected_length:
        raise DDTError(f"the MEMREAD response reports {recorded} bytes, not {expected_length}")
    if len(hex_bytes) != expected_length * 2:
        raise DDTError(f"the MEMREAD response returned {len(hex_bytes) // 2} bytes of hex, "
                       f"not {expected_length}")
    return {"segment": segment, "offset": offset, "length": recorded, "hex": hex_bytes}


def _differences(before: dict | None, after: dict | None) -> dict:
    if not before or not after:
        return {}
    return {name: [before.get(name), after[name]] for name in after if before.get(name) != after[name]}


def _step_failure(index: int, response: dict) -> str:
    text = " ".join(response["raw"])
    if "requires the debugger to be stopped" in text:
        return (f"step {index}: the DOSBox-X debugger is not stopped; start the program with "
                f"DEBUGBOX (or break in) so it is stopped at the intended instruction")
    return f"step {index}: the debugger rejected STEPIN: {response['raw']}"


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
        "limits": list(_CPU_LIMITS),
    }
    if out is not None:
        _write_json(Path(out), record)
    return record


def capture_memory(port: int = DEFAULT_PORT, *, segment: int, offset: int, length: int,
                   settle: float = 3.0, timeout: float = DEFAULT_TIMEOUT,
                   command_timeout: float = DEFAULT_COMMAND_TIMEOUT,
                   dosbox_version: str | None = None, out: str | Path | None = None) -> dict:
    """Read bounded conventional RAM bytes from a stopped DOSBox-X debugger."""
    if not (isinstance(segment, int) and not isinstance(segment, bool) and 0 <= segment <= 0xFFFF
            and isinstance(offset, int) and not isinstance(offset, bool) and 0 <= offset <= 0xFFFF):
        raise DDTError(f"segment and offset must each be 0..65535: {segment!r}:{offset!r}")
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= MAX_MEMORY_BYTES:
        raise DDTError(f"length must be an integer in 1..{MAX_MEMORY_BYTES}: {length!r}")
    requested = f"{_hex16(segment)}:{_hex16(offset)}"
    commands: list[dict] = []
    rid = 0
    initial = final = None

    def next_rid() -> int:
        nonlocal rid
        rid += 1
        return rid

    def observe_registers(conn: socket.socket) -> dict:
        response = _request(conn, next_rid(), "EXEC EV " + " ".join(REGISTERS), command_timeout)
        commands.append(response)
        registers = _parse_registers(response["raw"]) if response["status"] == "OK" else None
        if registers is None:
            raise DDTError(f"could not read the CPU registers: {response['raw']}")
        return {"registers": registers, "cs_ip": f"{registers['CS']}:{registers['IP']}"}

    with _accepted_connection(port, timeout) as conn:
        commands.append(_request(conn, next_rid(), "PING", command_timeout))
        if commands[-1]["status"] != "OK" or commands[-1]["raw"] != ["PONG"]:
            raise DDTError("DOSBox-X debugger did not answer PING with PONG")
        if settle > 0:
            time.sleep(settle)
        help_response = _request(conn, next_rid(), "EXEC HELP", command_timeout)
        commands.append(help_response)
        if help_response["status"] != "OK":
            raise DDTError("could not read the debugger command list to check MEMREAD support "
                           f"(EXEC HELP was refused: {help_response['raw']})")
        advertised = _advertises(help_response["raw"], "MEMREAD")
        capability = {"checked_with": "EXEC HELP", "memread_advertised": advertised,
                      "evidence": [line.strip() for line in help_response["raw"]
                                   if line.strip().split(None, 1)[:1] == ["MEMREAD"]]}
        if not advertised:
            raise DDTError("Connected DOSBox-X debugger does not advertise MEMREAD; use a "
                           "debugger-enabled build with bounded memory observation support.")
        initial = observe_registers(conn)
        read_response = _request(conn, next_rid(),
                                 f"EXEC MEMREAD {requested} {_hex16(length)}", command_timeout)
        commands.append(read_response)
        if read_response["status"] != "OK":
            raise DDTError(f"the debugger refused the memory read: {read_response['raw']}")
        parsed = _parse_memread_line(read_response["raw"], _hex16(segment), _hex16(offset), length)
        final = observe_registers(conn)
        if final["cs_ip"] != initial["cs_ip"]:
            raise DDTError(f"CS:IP moved during the memory read ({initial['cs_ip']} -> "
                           f"{final['cs_ip']}); the observation is not trustworthy")

    unknown = ["whether the read had side effects on emulated hardware (conventional RAM only "
               "was requested)",
               "whether the emulator is paused or running (no stopped-state query exists)"]
    if not dosbox_version:
        unknown.append("DOSBox-X build identity (not queried over the protocol)")
    record = {
        "schema": MEMORY_SCHEMA,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "protocol": PROTOCOL,
        "dosbox_version": dosbox_version,
        "capability": capability,
        "request": {"segment": _hex16(segment), "offset": _hex16(offset), "length": length,
                    "cs_ip": requested, "command": read_response["request"]},
        "response": {"raw": read_response["raw"],
                     "address": f"{parsed['segment']}:{parsed['offset']}",
                     "length": parsed["length"]},
        "bytes_hex": parsed["hex"],
        "byte_count": length,
        "read_success": True,
        "initial": initial,
        "final": final,
        "cs_ip_unchanged": True,
        "paused_state": "unknown",
        "commands": commands,
        "unknown": unknown,
        "limits": list(_MEMORY_LIMITS),
    }
    if out is not None:
        _write_json(Path(out), record)
    return record


def capture_steps(port: int = DEFAULT_PORT, *, count: int = DEFAULT_STEPS, settle: float = 3.0,
                  timeout: float = DEFAULT_TIMEOUT, command_timeout: float = DEFAULT_COMMAND_TIMEOUT,
                  dosbox_version: str | None = None, out: str | Path | None = None,
                  resume: bool = False) -> dict:
    """Step a stopped DOSBox-X program one instruction at a time.

    STEPIN support is detected with the non-executing ``EXEC HELP`` command; DDT
    never executes an instruction just to discover capability.
    """
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_STEPS:
        raise DDTError(f"count must be an integer in 1..{MAX_STEPS}: {count!r}")
    commands: list[dict] = []
    steps: list[dict] = []
    rid = 0
    run_acknowledged = False
    initial: dict | None = None
    previous: dict | None = None

    def next_rid() -> int:
        nonlocal rid
        rid += 1
        return rid

    with _accepted_connection(port, timeout) as conn:
        commands.append(_request(conn, next_rid(), "PING", command_timeout))
        if commands[-1]["status"] != "OK" or commands[-1]["raw"] != ["PONG"]:
            raise DDTError("DOSBox-X debugger did not answer PING with PONG")
        if settle > 0:
            time.sleep(settle)
        help_response = _request(conn, next_rid(), "EXEC HELP", command_timeout)
        commands.append(help_response)
        if help_response["status"] != "OK":
            raise DDTError("could not read the debugger command list to check STEPIN support "
                           f"(EXEC HELP was refused: {help_response['raw']})")
        advertised = _advertises(help_response["raw"], "STEPIN")
        capability = {"checked_with": "EXEC HELP", "stepin_advertised": advertised,
                      "evidence": [line.strip() for line in help_response["raw"]
                                   if line.strip().split(None, 1)[:1] == ["STEPIN"]]}
        if not advertised:
            raise DDTError("Connected DOSBox-X debugger does not advertise STEPIN; use a "
                           "debugger-enabled build with external stepping support.")
        registers_response = _request(conn, next_rid(), "EXEC EV " + " ".join(REGISTERS),
                                      command_timeout)
        commands.append(registers_response)
        initial = (_parse_registers(registers_response["raw"])
                   if registers_response["status"] == "OK" else None)
        if initial is None:
            raise DDTError(f"could not read the initial registers: {registers_response['raw']}")
        previous = initial
        for index in range(1, count + 1):
            step_response = _request(conn, next_rid(), "EXEC STEPIN", command_timeout)
            commands.append(step_response)
            if step_response["status"] != "OK":
                raise DDTError(_step_failure(index, step_response))
            reported = _parse_step_line(step_response["raw"])
            if reported is None:
                raise DDTError(f"step {index}: the STEPIN response did not report the resulting "
                               f"CS:IP/registers ({step_response['raw']!r})")
            after_response = _request(conn, next_rid(), "EXEC EV " + " ".join(REGISTERS),
                                      command_timeout)
            commands.append(after_response)
            after = (_parse_registers(after_response["raw"])
                     if after_response["status"] == "OK" else None)
            if after is None:
                raise DDTError(f"step {index}: the post-step register read was refused: "
                               f"{after_response['raw']}")
            # The synchronous STEPIN report and the register read must agree on the
            # overlapping values; both are normalized to fixed-width hex already.
            if (reported["cs"] != after["CS"] or reported["ip"] != after["IP"]
                    or reported["AX"] != after["AX"] or reported["BX"] != after["BX"]):
                raise DDTError(
                    f"step {index}: the STEPIN response and the register read disagree "
                    f"(STEPIN CS:IP={reported['cs_ip']} AX={reported['AX']} BX={reported['BX']}; "
                    f"EV CS:IP={after['CS']}:{after['IP']} AX={after['AX']} BX={after['BX']})")
            steps.append({"index": index, "request": step_response["request"],
                          "status": step_response["status"], "raw": step_response["raw"],
                          "reported": reported, "registers": after,
                          "cs_ip": f"{after['CS']}:{after['IP']}",
                          "changed": _differences(previous, after)})
            previous = after
        if resume:
            run = _request(conn, next_rid(), "EXEC RUN", command_timeout)
            commands.append(run)
            run_acknowledged = run["status"] == "OK"

    def cs_ip(state: dict | None) -> str | None:
        return f"{state['CS']}:{state['IP']}" if state else None

    limits = list(_STEPS_LIMITS)
    limits.append("RUN was requested after the steps; its acknowledgement does not prove that "
                  "execution actually resumed" if resume
                  else "Execution is left stopped in the debugger after the steps")
    unknown = ["whether the emulator is paused or running (no stopped-state query exists)",
               "instruction bytes, mnemonics and semantics "
               "(only observed register values are recorded)"]
    if not dosbox_version:
        unknown.append("DOSBox-X build identity (not queried over the protocol)")
    if resume and not run_acknowledged:
        unknown.append("whether emulation resumed (the RUN acknowledgement was not received)")
    record = {
        "schema": STEPS_SCHEMA,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "protocol": PROTOCOL,
        "dosbox_version": dosbox_version,
        "capability": capability,
        "requested_count": count,
        "completed_count": len(steps),
        "initial": {"registers": initial, "cs_ip": cs_ip(initial)},
        "steps": steps,
        "final": {"registers": previous, "cs_ip": cs_ip(previous)},
        "resume_requested": resume,
        "run_acknowledged": run_acknowledged,
        "paused_state": "unknown",
        "commands": commands,
        "unknown": unknown,
        "limits": limits,
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


def capture_step_memory(port: int = DEFAULT_PORT, *, segment: int, offset: int, length: int,
                        settle: float = 3.0, timeout: float = DEFAULT_TIMEOUT,
                        command_timeout: float = DEFAULT_COMMAND_TIMEOUT,
                        dosbox_version: str | None = None, out: str | Path | None = None) -> dict:
    """Observe one memory region across exactly one DOS instruction.

    Reuses the existing protocol helpers on a single connection: HELP capability
    detection, register observations, strict MEMREAD parsing and one STEPIN. The
    memory region is an explicit runtime address, not an instruction address.
    """
    if not (isinstance(segment, int) and not isinstance(segment, bool) and 0 <= segment <= 0xFFFF
            and isinstance(offset, int) and not isinstance(offset, bool) and 0 <= offset <= 0xFFFF):
        raise DDTError(f"segment and offset must each be 0..65535: {segment!r}:{offset!r}")
    if not isinstance(length, int) or isinstance(length, bool) or not 1 <= length <= MAX_MEMORY_BYTES:
        raise DDTError(f"length must be an integer in 1..{MAX_MEMORY_BYTES}: {length!r}")
    if offset + length > 0x10000:
        raise DDTError(f"the observed region {offset:#x}..{offset + length:#x} crosses a 64 KiB "
                       f"segment boundary")
    requested = f"{_hex16(segment)}:{_hex16(offset)}"
    commands: list[dict] = []
    rid = 0
    initial = post = final = None
    before = after = before_response = after_response = step_response = reported = None
    step_sent = False

    def next_rid() -> int:
        nonlocal rid
        rid += 1
        return rid

    def ask(conn: socket.socket, command: str) -> dict:
        response = _request(conn, next_rid(), command, command_timeout)
        commands.append(response)
        return response

    def observe(conn: socket.socket, label: str) -> dict:
        response = ask(conn, "EXEC EV " + " ".join(REGISTERS))
        registers = _parse_registers(response["raw"]) if response["status"] == "OK" else None
        if registers is None:
            raise DDTError(f"{label}: could not read the CPU registers: {response['raw']}")
        return {"registers": registers, "cs_ip": f"{registers['CS']}:{registers['IP']}"}

    def read_region(conn: socket.socket, label: str) -> tuple[dict, dict]:
        response = ask(conn, f"EXEC MEMREAD {requested} {_hex16(length)}")
        if response["status"] != "OK":
            raise DDTError(f"{label}: the debugger refused the memory read: {response['raw']}")
        parsed = _parse_memread_line(response["raw"], _hex16(segment), _hex16(offset), length)
        return parsed, response

    with _accepted_connection(port, timeout) as conn:
        ping = ask(conn, "PING")
        if ping["status"] != "OK" or ping["raw"] != ["PONG"]:
            raise DDTError("DOSBox-X debugger did not answer PING with PONG")
        if settle > 0:
            time.sleep(settle)
        help_response = ask(conn, "EXEC HELP")
        if help_response["status"] != "OK":
            raise DDTError("could not read the debugger command list (EXEC HELP was refused: "
                           f"{help_response['raw']})")
        mem_ok = _advertises(help_response["raw"], "MEMREAD")
        step_ok = _advertises(help_response["raw"], "STEPIN")
        capability = {"checked_with": "EXEC HELP", "memread_advertised": mem_ok,
                      "stepin_advertised": step_ok,
                      "evidence": [line.strip() for line in help_response["raw"]
                                   if line.strip().split(None, 1)[:1] in (["MEMREAD"], ["STEPIN"])]}
        if not (mem_ok and step_ok):
            missing = " and ".join(name for name, ok in (("MEMREAD", mem_ok), ("STEPIN", step_ok))
                                   if not ok)
            raise DDTError(f"Connected DOSBox-X debugger does not advertise {missing}; this command "
                           f"needs a debugger-enabled build with both bounded memory observation and "
                           f"external stepping support.")
        initial = observe(conn, "before the initial memory read")
        before, before_response = read_region(conn, "the initial memory read")
        settled = observe(conn, "after the initial memory read")
        if settled["cs_ip"] != initial["cs_ip"]:
            raise DDTError(f"CS:IP moved during the initial memory read ({initial['cs_ip']} -> "
                           f"{settled['cs_ip']}); no instruction was executed")
        # From here the guest instruction may execute; never retry, undo or resume.
        try:
            step_sent = True
            step_response = ask(conn, "EXEC STEPIN")
            if step_response["status"] != "OK":
                raise DDTError(f"the debugger refused STEPIN: {step_response['raw']}")
            reported = _parse_step_line(step_response["raw"])
            if reported is None:
                raise DDTError(f"the STEPIN response did not report the resulting CS:IP/registers "
                               f"({step_response['raw']!r})")
            post = observe(conn, "after the step")
            if (reported["cs"] != post["registers"]["CS"] or reported["ip"] != post["registers"]["IP"]
                    or reported["AX"] != post["registers"]["AX"]
                    or reported["BX"] != post["registers"]["BX"]):
                raise DDTError(f"the STEPIN response and the register read disagree "
                               f"(STEPIN CS:IP={reported['cs_ip']} AX={reported['AX']} BX={reported['BX']}; "
                               f"EV CS:IP={post['cs_ip']} AX={post['registers']['AX']} "
                               f"BX={post['registers']['BX']})")
            after, after_response = read_region(conn, "the post-step memory read")
            final = observe(conn, "after the post-step memory read")
            if final["cs_ip"] != post["cs_ip"]:
                raise DDTError(f"CS:IP moved during the post-step memory read ({post['cs_ip']} -> "
                               f"{final['cs_ip']})")
        except DDTError as exc:
            if step_sent:
                raise DDTError(f"{exc} - the guest instruction may already have executed; DDT does "
                               f"not retry, undo, or resume it") from exc
            raise

    byte_differences = []
    for index in range(length):
        pair = (before["hex"][index * 2:index * 2 + 2], after["hex"][index * 2:index * 2 + 2])
        if pair[0] != pair[1]:
            byte_differences.append({"relative_offset": index,
                                     "address": f"{_hex16(segment)}:{_hex16(offset + index)}",
                                     "before": pair[0], "after": pair[1]})
    unknown = ["whether guest memory outside the selected region changed",
               "whether the emulator is paused or running (no stopped-state query exists)"]
    if not dosbox_version:
        unknown.append("DOSBox-X build identity (not queried over the protocol)")
    record = {
        "schema": STEP_MEMORY_SCHEMA,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "protocol": PROTOCOL,
        "dosbox_version": dosbox_version,
        "capability": capability,
        "request": {"segment": _hex16(segment), "offset": _hex16(offset), "length": length,
                    "cs_ip": requested,
                    "read_command": f"EXEC MEMREAD {requested} {_hex16(length)}"},
        "initial": initial,
        "memory_before": {"address": f"{before['segment']}:{before['offset']}",
                          "length": before["length"], "bytes_hex": before["hex"],
                          "raw": before_response["raw"]},
        "step": {"command": step_response["request"], "response": step_response["raw"],
                 "reported": reported},
        "after_step": post,
        "memory_after": {"address": f"{after['segment']}:{after['offset']}",
                         "length": after["length"], "bytes_hex": after["hex"],
                         "raw": after_response["raw"]},
        "final": final,
        "register_differences": _differences(initial["registers"], post["registers"]),
        "byte_differences": byte_differences,
        "changed_byte_count": len(byte_differences),
        "checks": {"cs_ip_unchanged_during_initial_read": True,
                   "cs_ip_unchanged_during_post_step_read": True,
                   "step_report_matches_registers": True,
                   "execution_left_stopped": True},
        "commands": commands,
        "unknown": unknown,
        "limits": list(_STEP_MEMORY_LIMITS),
    }
    if out is not None:
        _write_json(Path(out), record)
    return record
