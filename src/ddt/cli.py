"""Command line application. Prints deterministic machine-readable records."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .diff import compare, manifest
from .errors import DDTError
from .format import inspect, map_address


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
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            output = inspect(args.path, args.format).to_dict()
        elif args.command == "address":
            output = map_address(inspect(args.path, args.format), args.segment, args.offset)
        elif args.command == "diff":
            output = compare(args.before, args.after, args.max_runs)
        else:
            output = manifest(args.path)
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except (DDTError, OSError) as ex:
        print(json.dumps({"error": str(ex), "error_type": type(ex).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
