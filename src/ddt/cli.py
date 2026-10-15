"""Command line application. Prints deterministic machine-readable records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .capture import intake
from .code import callees, callers, readers, writers
from .correlate import correlate
from .diff import compare, manifest
from .dosbox import (capture_breakpoint, capture_cpu, capture_memory, capture_step_memory,
                     capture_steps)
from .errors import DDTError
from .format import inspect, map_address
from .ghidra import export_function
from .identify import identify
from .linexec import extract_le_bytes, inspect_le
from .memory import compare as compare_memory, compare_reference
from .strings import extract


def _num(s: str) -> int:
    return int(s, 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ddt", description="Read-only DOS reverse-engineering primitives")
    parser.add_argument("--version", action="version", version=f"ddt {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    ins = commands.add_parser("inspect", help="Inspect DOS MZ or explicitly selected COM image")
    ins.add_argument("path", type=Path)
    ins.add_argument("--format", choices=["auto", "mz", "com"], default="auto")
    ins.add_argument("--json", action="store_true", help="Structured JSON (also the default output)")
    addr = commands.add_parser("address", help="Map module-relative segment:offset to original file offset")
    addr.add_argument("path", type=Path)
    addr.add_argument("--format", choices=["auto", "mz", "com"], default="auto")
    addr.add_argument("--segment", required=True, type=_num)
    addr.add_argument("--offset", required=True, type=_num)
    addr.add_argument("--json", action="store_true")
    cmp = commands.add_parser("diff", help="Compare files or directories without interpreting contents")
    cmp.add_argument("before", type=Path)
    cmp.add_argument("after", type=Path)
    cmp.add_argument("--max-runs", type=int, default=128)
    cmp.add_argument("--json", action="store_true")
    man = commands.add_parser("manifest", help="Deterministic hash inventory of file/directory")
    man.add_argument("path", type=Path)
    man.add_argument("--json", action="store_true")
    st = commands.add_parser("strings", help="Extract printable strings with original file offsets")
    st.add_argument("path", type=Path)
    st.add_argument("--min-length", type=int, default=4)
    st.add_argument("--max-results", type=int, default=4096)
    st.add_argument("--json", action="store_true")
    idn = commands.add_parser("identify", help="Identify DOS containers and packaging markers")
    idn.add_argument("path", type=Path)
    idn.add_argument("--format", choices=["auto", "mz", "com"], default="auto")
    idn.add_argument("--json", action="store_true")
    leh = commands.add_parser("le-header",
                              help="Inspect a validated LE header, object table and page map")
    leh.add_argument("path", type=Path)
    leh.add_argument("--json", action="store_true")
    leb = commands.add_parser("le-bytes",
                              help="Extract original-file bytes from one validated LE page")
    leb.add_argument("path", type=Path)
    leb.add_argument("--object", required=True, type=_num, help="1-based LE object index")
    leb.add_argument("--offset", required=True, type=_num, help="Object-relative byte offset")
    leb.add_argument("--length", required=True, type=int, help="Bytes to extract (1..256)")
    leb.add_argument("--json", action="store_true")
    cor = commands.add_parser("correlate",
                              help="Derive a candidate runtime address for an exported instruction")
    cor.add_argument("--binary", required=True, type=Path, help="Original COM or MZ executable")
    cor.add_argument("--format", required=True, choices=["com", "mz"])
    cor.add_argument("--export", required=True, type=Path, help="ddt.ghidra-function.v1 JSON")
    cor.add_argument("--instruction", required=True, help="Ghidra instruction address from the export")
    cor.add_argument("--entry-observation", required=True, type=Path,
                     help="ddt.dosbox-steps.v1 record made at the program entry")
    cor.add_argument("--json", action="store_true")
    cap = commands.add_parser("capture", help="Read-only intake of paired artifact captures")
    cap_sub = cap.add_subparsers(dest="capture_command", required=True)
    ci = cap_sub.add_parser("intake", help="Compare a before/after capture and record a receipt")
    ci.add_argument("--before", required=True, type=Path)
    ci.add_argument("--after", required=True, type=Path)
    ci.add_argument("--out", type=Path, default=None, help="Write the receipt outside both captures")
    ci.add_argument("--note", default=None, help="Operator-supplied note (user metadata, not evidence)")
    ci.add_argument("--max-runs", type=int, default=128)
    ci.add_argument("--json", action="store_true")
    dbg = commands.add_parser("debugger", help="Observe CPU state from a DOSBox-X debugger session")
    dbg_sub = dbg.add_subparsers(dest="debugger_command", required=True)
    dc = dbg_sub.add_parser("capture-cpu", help="Accept one DOSBox-X debugger connection and record CPU state")
    dc.add_argument("--port", type=int, default=58991, help="Loopback port DOSBox-X connects back to")
    dc.add_argument("--out", type=Path, default=None, help="Write the observation JSON here")
    dc.add_argument("--settle", type=float, default=3.0, help="Seconds to wait after connect before BREAK")
    dc.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for the connection")
    dc.add_argument("--dosbox-version", default=None, help="Record an operator-known DOSBox-X version")
    dc.add_argument("--leave-paused", action="store_true",
                    help="Leave the debugger paused instead of resuming the emulator")
    dc.add_argument("--json", action="store_true")
    cb = dbg_sub.add_parser("capture-breakpoint",
                            help="Install one real-mode breakpoint and capture the stop")
    cb.add_argument("--port", type=int, default=58991, help="Loopback port DOSBox-X connects back to")
    cb.add_argument("--segment", required=True, type=_num, help="Real-mode segment (e.g. 0x0813)")
    cb.add_argument("--offset", required=True, type=_num, help="Real-mode offset (e.g. 0x0103)")
    cb.add_argument("--out", type=Path, default=None, help="Write the observation JSON here")
    cb.add_argument("--settle", type=float, default=3.0, help="Seconds to wait after connect")
    cb.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for the connection")
    cb.add_argument("--confirm", type=int, default=4, help="Register polls that must agree on the stop")
    cb.add_argument("--dosbox-version", default=None, help="Record an operator-known DOSBox-X version")
    cb.add_argument("--leave-paused", action="store_true",
                    help="Leave the debugger paused instead of resuming the emulator")
    cb.add_argument("--json", action="store_true")
    cst = dbg_sub.add_parser("capture-steps",
                             help="Step a stopped DOSBox-X program one instruction at a time")
    cst.add_argument("--port", type=int, default=58991, help="Loopback port DOSBox-X connects back to")
    cst.add_argument("--count", type=int, default=1, help="Number of instructions to step (1..64)")
    cst.add_argument("--out", type=Path, default=None, help="Write the observation JSON here")
    cst.add_argument("--settle", type=float, default=3.0, help="Seconds to wait after connect")
    cst.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for the connection")
    cst.add_argument("--dosbox-version", default=None, help="Record an operator-known DOSBox-X version")
    cst.add_argument("--resume", action="store_true",
                     help="Run the emulator after the steps complete (default: leave stopped)")
    cst.add_argument("--json", action="store_true")
    cm = dbg_sub.add_parser("capture-memory",
                            help="Read bounded conventional RAM from a stopped DOSBox-X debugger")
    cm.add_argument("--port", type=int, default=58991, help="Loopback port DOSBox-X connects back to")
    cm.add_argument("--segment", required=True, type=_num, help="Real-mode segment (e.g. 0x0813)")
    cm.add_argument("--offset", required=True, type=_num, help="Real-mode offset (e.g. 0x0100)")
    cm.add_argument("--length", required=True, type=int, help="Bytes to read (1..256)")
    cm.add_argument("--out", type=Path, default=None, help="Write the observation JSON here")
    cm.add_argument("--settle", type=float, default=3.0, help="Seconds to wait after connect")
    cm.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for the connection")
    cm.add_argument("--dosbox-version", default=None, help="Record an operator-known DOSBox-X version")
    cm.add_argument("--json", action="store_true")
    csm = dbg_sub.add_parser("capture-step-memory",
                             help="Observe one memory region across exactly one instruction")
    csm.add_argument("--port", type=int, default=58991, help="Loopback port DOSBox-X connects back to")
    csm.add_argument("--segment", required=True, type=_num, help="Real-mode segment of the region")
    csm.add_argument("--offset", required=True, type=_num, help="Real-mode offset of the region")
    csm.add_argument("--length", required=True, type=int, help="Bytes to observe (1..256)")
    csm.add_argument("--out", type=Path, default=None, help="Write the observation JSON here")
    csm.add_argument("--settle", type=float, default=3.0, help="Seconds to wait after connect")
    csm.add_argument("--timeout", type=float, default=60.0, help="Seconds to wait for the connection")
    csm.add_argument("--dosbox-version", default=None, help="Record an operator-known DOSBox-X version")
    csm.add_argument("--json", action="store_true")
    mem = commands.add_parser("memory", help="Compare observed guest memory with static evidence")
    mem_sub = mem.add_subparsers(dest="memory_command", required=True)
    mc = mem_sub.add_parser("compare", help="Compare original, Ghidra and runtime instruction bytes")
    mc.add_argument("--correlation", required=True, type=Path, help="ddt.address-correlation.v1 JSON")
    mc.add_argument("--observation", required=True, type=Path, help="ddt.dosbox-memory.v1 JSON")
    mc.add_argument("--binary", required=True, type=Path, help="Original COM or MZ executable")
    mc.add_argument("--json", action="store_true")
    mcr = mem_sub.add_parser("compare-reference",
                             help="Compare an observed region with an operator-selected reference range")
    mcr.add_argument("--observation", required=True, type=Path, help="ddt.dosbox-memory.v1 JSON")
    mcr.add_argument("--reference-binary", required=True, type=Path,
                     help="File whose bytes are the reference (never modified)")
    mcr.add_argument("--reference-offset", required=True, type=_num,
                     help="Original-file byte offset of the reference range (not a runtime address)")
    mcr.add_argument("--out", type=Path, default=None, help="Write the comparison JSON here")
    mcr.add_argument("--json", action="store_true")
    gh = commands.add_parser("ghidra", help="Optional read-only Ghidra integration")
    gh_sub = gh.add_subparsers(dest="ghidra_command", required=True)
    gx = gh_sub.add_parser("export", help="Export one analyzed function from an existing Ghidra project")
    gx.add_argument("--project", required=True, type=Path, help="Ghidra .gpr file or its directory")
    gx.add_argument("--program", required=True, help="Program name inside the project")
    gx.add_argument("--function", required=True, help="Ghidra entry address, e.g. 0x1000 or 1000:0000")
    gx.add_argument("--out", required=True, type=Path, help="Destination JSON file")
    gx.add_argument("--ghidra", type=Path, default=None, help="Ghidra install directory or analyzeHeadless launcher")
    gx.add_argument("--java-home", type=Path, default=None, help="JAVA_HOME for the Ghidra launcher")
    gx.add_argument("--timeout", type=int, default=600)
    gx.add_argument("--json", action="store_true")
    code = commands.add_parser("code", help="Query direct function relationships from an exported function")
    code_sub = code.add_subparsers(dest="code_command", required=True)
    for direction, help_text in (("callers", "Direct call references targeting the function entry"),
                                 ("callees", "Direct calls made by the function")):
        sub = code_sub.add_parser(direction, help=help_text)
        sub.add_argument("--export", required=True, type=Path, help="Exported ddt.ghidra-function.v1 JSON")
        sub.add_argument("--json", action="store_true")
    for direction, help_text in (("readers", "Instructions with direct reads of a Ghidra address"),
                                 ("writers", "Instructions with direct writes of a Ghidra address")):
        sub = code_sub.add_parser(direction, help=help_text)
        sub.add_argument("--export", required=True, type=Path, help="Exported ddt.ghidra-function.v1 JSON")
        sub.add_argument("--address", required=True, help="Ghidra address, e.g. 1000:1234")
        sub.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            output = inspect(args.path, args.format).to_dict()
        elif args.command == "address":
            output = map_address(inspect(args.path, args.format), args.segment, args.offset)
        elif args.command == "diff":
            output = compare(args.before, args.after, args.max_runs)
        elif args.command == "strings":
            output = extract(args.path, args.min_length, args.max_results)
        elif args.command == "identify":
            output = identify(args.path, args.format)
        elif args.command == "le-header":
            output = inspect_le(args.path)
        elif args.command == "le-bytes":
            output = extract_le_bytes(args.path, args.object, args.offset, args.length)
        elif args.command == "correlate":
            output = correlate(args.binary, args.format, args.export, args.instruction,
                               args.entry_observation)
        elif args.command == "capture":
            output = intake(args.before, args.after, out=args.out, note=args.note,
                            max_runs=args.max_runs)
        elif args.command == "debugger":
            if args.debugger_command == "capture-cpu":
                output = capture_cpu(args.port, settle=args.settle, timeout=args.timeout,
                                     dosbox_version=args.dosbox_version, out=args.out,
                                     leave_paused=args.leave_paused)
            elif args.debugger_command == "capture-breakpoint":
                output = capture_breakpoint(args.port, segment=args.segment, offset=args.offset,
                                            settle=args.settle, timeout=args.timeout,
                                            confirm=args.confirm, dosbox_version=args.dosbox_version,
                                            out=args.out, leave_paused=args.leave_paused)
            elif args.debugger_command == "capture-memory":
                output = capture_memory(args.port, segment=args.segment, offset=args.offset,
                                        length=args.length, settle=args.settle, timeout=args.timeout,
                                        dosbox_version=args.dosbox_version, out=args.out)
            elif args.debugger_command == "capture-step-memory":
                output = capture_step_memory(args.port, segment=args.segment, offset=args.offset,
                                             length=args.length, settle=args.settle,
                                             timeout=args.timeout,
                                             dosbox_version=args.dosbox_version, out=args.out)
            else:
                output = capture_steps(args.port, count=args.count, settle=args.settle,
                                       timeout=args.timeout, dosbox_version=args.dosbox_version,
                                       out=args.out, resume=args.resume)
        elif args.command == "memory":
            if args.memory_command == "compare":
                output = compare_memory(args.correlation, args.observation, args.binary)
            else:
                output = compare_reference(args.observation, args.reference_binary,
                                           args.reference_offset, out=args.out)
        elif args.command == "ghidra":
            output = export_function(args.project, args.program, args.function, args.out,
                                     ghidra=args.ghidra, java_home=args.java_home, timeout=args.timeout)
        elif args.command == "code":
            if args.code_command == "callers":
                output = callers(args.export)
            elif args.code_command == "callees":
                output = callees(args.export)
            elif args.code_command == "readers":
                output = readers(args.export, args.address)
            else:
                output = writers(args.export, args.address)
        else:
            output = manifest(args.path)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (DDTError, OSError) as ex:
        print(json.dumps({"error": str(ex), "error_type": type(ex).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
