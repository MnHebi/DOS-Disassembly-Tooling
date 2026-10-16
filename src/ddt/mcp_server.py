"""Optional read-only MCP server exposing a few DDT operations over stdio.

The server adds no analysis of its own: every tool calls the same functions the
`ddt` CLI calls and returns the same versioned JSON receipts. The MCP SDK is an
optional dependency and is imported lazily, so the core stays dependency-free.
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Annotated, Callable, Literal

# Annotations here are evaluated eagerly on purpose: the MCP SDK resolves the tool
# signatures against this module's globals, so argument descriptions must exist as
# objects at definition time rather than as names in a postponed annotation.

from . import __version__
from .diff import manifest
from .errors import DDTError
from .format import inspect as inspect_format
from .identify import identify
from .linexec import extract_le_bytes, inspect_le, inspect_le_fixups

MAX_RESPONSE_BYTES = 256 * 1024

_INSTALL_HINT = ('the optional MCP dependency is not installed; install it with '
                 'pip install "dos-disassembly-tooling[mcp]"')

_INSTRUCTIONS = (
    "Read-only DOS executable evidence through DDT. Every tool takes a path that must "
    "resolve inside the analysis root this server was started with, and returns the same "
    "versioned JSON receipt the DDT CLI produces, including its limits and unknown fields. "
    "Nothing is loaded, relocated, unpacked or executed, and no file is modified. Keep "
    "original-file offsets, module-relative addresses and runtime addresses distinct; a "
    "refused path is a boundary, not a hint to look elsewhere."
)


def authorized_file(root: Path, requested: str) -> Path:
    """Resolve one requested input and require it to stay inside the authorized root."""
    if not isinstance(requested, str) or not requested.strip():
        raise DDTError("path must be a non-empty string")
    candidate = Path(requested)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise DDTError(f"cannot use {requested!r}: {exc.strerror or exc}") from exc
    if not resolved.is_relative_to(root):
        raise DDTError(f"{requested!r} resolves outside the authorized root {root}")
    if not resolved.is_file():
        raise DDTError(f"{requested!r} is not a regular file")
    return resolved


def bounded(receipt: dict) -> dict:
    """Refuse an oversized receipt instead of truncating it."""
    size = len(json.dumps(receipt, separators=(",", ":")).encode("utf-8"))
    if size > MAX_RESPONSE_BYTES:
        raise DDTError(
            f"the receipt is {size} bytes, over the {MAX_RESPONSE_BYTES}-byte MCP response "
            "limit; narrow the request (for example a smaller length or a single page) "
            "rather than truncating it")
    return receipt


def build_server(root: Path):
    """Create the MCP server for an authorized root. Requires the optional MCP SDK."""
    try:
        from mcp.server.mcpserver import MCPServer
        from mcp.server.mcpserver.exceptions import ToolError
        from mcp.types import ToolAnnotations
        from pydantic import Field
    except ImportError as exc:
        print(f"ddt-mcp: {_INSTALL_HINT} ({exc})", file=sys.stderr)
        raise SystemExit(2) from exc

    server = MCPServer(name="ddt", title="DDT DOS executable evidence", version=__version__,
                       instructions=_INSTRUCTIONS)
    read_only = ToolAnnotations(read_only_hint=True)

    def serve(operation: Callable[[], dict]) -> dict:
        try:
            return bounded(operation())
        except DDTError as exc:
            raise ToolError(str(exc)) from exc

    PathArg = Annotated[str, Field(description="Path to a file inside the authorized "
                                               "analysis root")]
    FormatArg = Literal["auto", "mz", "com"]

    @server.tool(name="ddt_manifest", title="Hash one file",
                 description="SHA-256 hash of one authorized file, as "
                             "ddt.artifact-manifest.v1. Use it to establish input identity "
                             "and to quote provenance in later conclusions.",
                 annotations=read_only)
    def ddt_manifest(path: PathArg) -> dict:
        return serve(lambda: manifest(authorized_file(root, path)))

    @server.tool(name="ddt_identify", title="Identify the container",
                 description="Classify one authorized file: outer container, secondary "
                             "NE/LE/LX/PE headers, embedded COFF candidates, packer markers "
                             "and appended regions, as ddt.identify.v1. A candidate is a "
                             "signature match, not proof.",
                 annotations=read_only)
    def ddt_identify(path: PathArg, format: FormatArg = "auto") -> dict:
        return serve(lambda: identify(authorized_file(root, path), format))

    @server.tool(name="ddt_inspect", title="Inspect COM or MZ structure",
                 description="Validate a real-mode DOS MZ image (or a COM image selected "
                             "with format=com) and report its header, initialized image, "
                             "overlay, entry context and relocation locations. Relocations "
                             "are listed, never applied.",
                 annotations=read_only)
    def ddt_inspect(path: PathArg, format: FormatArg = "auto") -> dict:
        return serve(lambda: inspect_format(authorized_file(root, path), format).to_dict())

    @server.tool(name="ddt_le_header", title="Inspect an LE header",
                 description="Validate an LE (DOS extender) container and report its header "
                             "fields, object table and object page map as ddt.le-header.v1. "
                             "File offsets appear only for ordinary file-backed pages.",
                 annotations=read_only)
    def ddt_le_header(path: PathArg) -> dict:
        return serve(lambda: inspect_le(authorized_file(root, path)))

    @server.tool(name="ddt_le_bytes", title="Extract LE original-file bytes",
                 description="Extract 1-256 original-file bytes from one LE object page "
                             "(object is a 1-based object index, offset is object-relative), "
                             "as ddt.le-bytes.v1. The result is pre-relocation file content, "
                             "not a loaded image.",
                 annotations=read_only)
    def ddt_le_bytes(path: PathArg,
                     object: Annotated[int, Field(description="1-based LE object index")],
                     offset: Annotated[int, Field(description="Object-relative byte offset")],
                     length: Annotated[int,
                                       Field(description="Bytes to extract (1..256)")]) -> dict:
        return serve(lambda: extract_le_bytes(authorized_file(root, path), object, offset,
                                              length))

    @server.tool(name="ddt_le_fixups", title="Inspect LE fixup records",
                 description="Decode one logical LE page's encoded fixup records as "
                             "ddt.le-fixups.v1 (page is a zero-based logical page index). "
                             "These are the executable's requests to a loader: DDT never "
                             "applies them, and undecoded forms are reported as such.",
                 annotations=read_only)
    def ddt_le_fixups(path: PathArg,
                      page: Annotated[int, Field(description="Zero-based logical page "
                                                             "index")]) -> dict:
        return serve(lambda: inspect_le_fixups(authorized_file(root, path), page))

    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ddt-mcp",
        description="Read-only MCP server for a bounded set of DDT operations (stdio transport)")
    parser.add_argument("--root", required=True, type=Path,
                        help="Existing directory; every requested file must resolve inside it")
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).resolve(strict=True)
    except OSError as exc:
        print(f"ddt-mcp: --root {args.root}: {exc.strerror or exc}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"ddt-mcp: --root {args.root} is not a directory", file=sys.stderr)
        return 2
    server = build_server(root)
    print(f"ddt-mcp: read-only tools for {root}", file=sys.stderr)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
