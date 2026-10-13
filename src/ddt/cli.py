"""Command line application. Prints deterministic machine-readable records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .code import callees, callers
from .diff import compare, manifest
from .errors import DDTError
from .format import inspect, map_address
from .ghidra import export_function
from .identify import identify
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
        elif args.command == "ghidra":
            output = export_function(args.project, args.program, args.function, args.out,
                                     ghidra=args.ghidra, java_home=args.java_home, timeout=args.timeout)
        elif args.command == "code":
            output = callers(args.export) if args.code_command == "callers" else callees(args.export)
        else:
            output = manifest(args.path)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (DDTError, OSError) as ex:
        print(json.dumps({"error": str(ex), "error_type": type(ex).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
