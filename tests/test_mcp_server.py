"""Focused tests for the optional MCP server.

The path and size helpers are always exercised; the protocol tests need the optional
MCP SDK and speak to a real server process over stdio.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import textwrap

import pytest

from ddt import mcp_server
from ddt.diff import manifest
from ddt.errors import DDTError
from ddt.format import inspect as inspect_format
from ddt.linexec import inspect_le
from test_linexec import _le_image, _record, _with_fixups

ROOT_DIR = Path(__file__).resolve().parents[1]
TOOL_NAMES = ["ddt_manifest", "ddt_identify", "ddt_inspect", "ddt_le_header",
              "ddt_le_bytes", "ddt_le_fixups"]


def _sdk():
    return pytest.importorskip("mcp", reason="optional MCP SDK is not installed")


def _mz_bytes() -> bytes:
    data = bytearray(128)
    struct.pack_into("<14H", data, 0, 0x5A4D, 128, 1, 0, 4, 0, 0xFFFF, 0, 0, 0, 0, 0, 0x1C, 0)
    return bytes(data)


def _message(result) -> str:
    return result.content[0].text if result.content else ""


def _payload(result) -> dict:
    assert result.is_error is False, _message(result)
    return json.loads(_message(result))


def _environment() -> dict:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(ROOT_DIR / "src") + (os.pathsep + existing if existing else "")
    return env


def _connect(root: Path):
    mcp = _sdk()
    params = mcp.StdioServerParameters(
        command=sys.executable, args=["-m", "ddt.mcp_server", "--root", str(root)],
        env=_environment())
    return mcp.Client(params, read_timeout_seconds=60)


def _call(root: Path, name: str, arguments: dict):
    async def run():
        async with _connect(root) as client:
            return await client.call_tool(name, arguments)
    return asyncio.run(run())


# --- helpers that never need the optional SDK -------------------------------------------

def test_authorized_file_confines_requests_to_the_root(tmp_path):
    root = tmp_path / "authorized"
    (root / "sub").mkdir(parents=True)
    inside = root / "sub" / "prog.exe"
    inside.write_bytes(b"MZ")
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")

    assert mcp_server.authorized_file(root, "sub/prog.exe") == inside.resolve()
    assert mcp_server.authorized_file(root, str(inside)) == inside.resolve()
    with pytest.raises(DDTError, match="outside the authorized root"):
        mcp_server.authorized_file(root, str(outside))
    with pytest.raises(DDTError, match="outside the authorized root"):
        mcp_server.authorized_file(root, "../outside.exe")
    with pytest.raises(DDTError, match="cannot use"):
        mcp_server.authorized_file(root, "missing.exe")
    with pytest.raises(DDTError, match="not a regular file"):
        mcp_server.authorized_file(root, "sub")
    with pytest.raises(DDTError, match="non-empty string"):
        mcp_server.authorized_file(root, "  ")


def test_authorized_file_rejects_a_symlink_escaping_the_root(tmp_path):
    root = tmp_path / "authorized"
    root.mkdir()
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")
    (root / "link.exe").symlink_to(outside)
    with pytest.raises(DDTError, match="outside the authorized root"):
        mcp_server.authorized_file(root, "link.exe")


def test_response_size_limit_refuses_instead_of_truncating():
    assert mcp_server.bounded({"schema": "x", "value": "y"})["value"] == "y"
    with pytest.raises(DDTError, match="over the .* MCP response limit"):
        mcp_server.bounded({"schema": "x",
                            "value": "a" * (mcp_server.MAX_RESPONSE_BYTES + 1)})


def test_missing_dependency_diagnostic_names_the_extra(tmp_path):
    """A clean interpreter with the SDK unavailable must explain how to install it."""
    script = textwrap.dedent(f"""
        import pathlib, sys
        sys.modules["mcp"] = None                      # simulate an environment without the SDK
        from ddt import mcp_server
        raise SystemExit(mcp_server.main(["--root", {str(tmp_path)!r}]))
        """)
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          env=_environment())
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "dos-disassembly-tooling[mcp]" in proc.stderr
    assert "pip install" in proc.stderr
    assert proc.stdout == ""                      # protocol stream stays clean


def test_cli_rejects_a_missing_or_non_directory_root(tmp_path):
    assert mcp_server.main(["--root", str(tmp_path / "missing")]) == 2
    file_root = tmp_path / "prog.exe"
    file_root.write_bytes(b"MZ")
    assert mcp_server.main(["--root", str(file_root)]) == 2


# --- protocol tests over stdio ----------------------------------------------------------

def test_protocol_initialization_and_tool_discovery(tmp_path):
    _sdk()
    (tmp_path / "prog.exe").write_bytes(b"MZ")

    async def run():
        async with _connect(tmp_path) as client:
            return client.protocol_version, client.server_info, (await client.list_tools()).tools

    version, info, tools = asyncio.run(run())
    assert version
    assert info.name == "ddt" and info.version
    assert [tool.name for tool in tools] == TOOL_NAMES
    for tool in tools:
        assert tool.annotations.read_only_hint is True
        assert tool.description and len(tool.description) > 60
    schemas = {tool.name: tool.input_schema for tool in tools}
    assert schemas["ddt_manifest"]["properties"]["path"]["description"]
    assert schemas["ddt_identify"]["properties"]["format"]["enum"] == ["auto", "mz", "com"]
    assert schemas["ddt_le_bytes"]["required"] == ["path", "object", "offset", "length"]
    for name in ("object", "offset", "length"):
        assert schemas["ddt_le_bytes"]["properties"][name]["description"]
    assert schemas["ddt_le_fixups"]["properties"]["page"]["description"]


def test_tool_results_match_the_core_implementation(tmp_path):
    _sdk()
    target = tmp_path / "linear.exe"
    target.write_bytes(_with_fixups(_le_image(virtual_size=0x2000),
                                    [_record(0x07, 0x00, 0x1B, 2, 4)]))
    plain = tmp_path / "plain.exe"
    plain.write_bytes(_mz_bytes())

    hashed = _payload(_call(tmp_path, "ddt_manifest", {"path": "linear.exe"}))
    assert hashed == manifest(target)
    assert hashed["entries"][0]["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()

    assert _payload(_call(tmp_path, "ddt_le_header", {"path": "linear.exe"})) == \
        inspect_le(target)

    extracted = _payload(_call(tmp_path, "ddt_le_bytes", {
        "path": "linear.exe", "object": 1, "offset": 0x40, "length": 4}))
    assert extracted["schema"] == "ddt.le-bytes.v1"
    assert extracted["file_offset"] == 0x150

    fixups = _payload(_call(tmp_path, "ddt_le_fixups", {"path": "linear.exe", "page": 0}))
    assert fixups["schema"] == "ddt.le-fixups.v1"
    assert fixups["records"][0]["target_offset"] == 4

    identification = _payload(_call(tmp_path, "ddt_identify", {"path": "linear.exe"}))
    assert identification["outer_format"] == "dos-mz"
    assert {finding["kind"]: finding["classification"]
            for finding in identification["findings"]}["le"] == "identified"

    assert _payload(_call(tmp_path, "ddt_inspect", {"path": "plain.exe"})) == \
        inspect_format(plain).to_dict()
    refused = _call(tmp_path, "ddt_inspect", {"path": "linear.exe"})
    assert refused.is_error is True and "not supported" in _message(refused)


def test_tool_refuses_paths_and_inputs_outside_the_contract(tmp_path):
    _sdk()
    root = tmp_path / "authorized"
    root.mkdir()
    inside = root / "prog.exe"
    inside.write_bytes(b"MZ")
    outside = tmp_path / "outside.exe"
    outside.write_bytes(b"MZ")
    (root / "link.exe").symlink_to(outside)

    escaped = _call(root, "ddt_manifest", {"path": str(outside)})
    assert escaped.is_error is True and "outside the authorized root" in _message(escaped)
    traversed = _call(root, "ddt_manifest", {"path": "../outside.exe"})
    assert traversed.is_error is True and "outside the authorized root" in _message(traversed)
    linked = _call(root, "ddt_manifest", {"path": "link.exe"})
    assert linked.is_error is True and "outside the authorized root" in _message(linked)
    missing = _call(root, "ddt_identify", {"path": "nope.exe"})
    assert missing.is_error is True and "cannot use" in _message(missing)
    directory = _call(root, "ddt_manifest", {"path": "."})
    assert directory.is_error is True and "not a regular file" in _message(directory)
    unsupported = _call(root, "ddt_le_header", {"path": "prog.exe"})
    assert unsupported.is_error is True and "LE" in _message(unsupported)

    assert inside.read_bytes() == b"MZ"          # nothing was modified
    assert sorted(path.name for path in root.iterdir()) == ["link.exe", "prog.exe"]


def test_tool_refuses_an_oversized_receipt(tmp_path):
    _sdk()
    records = b"".join(_record(0x07, 0x00, index % 0x1000, 2, index % 0x100)
                       for index in range(3000))
    (tmp_path / "wide.exe").write_bytes(
        _with_fixups(_le_image(virtual_size=0x2000), [records]))

    result = _call(tmp_path, "ddt_le_fixups", {"path": "wide.exe", "page": 0})
    assert result.is_error is True
    message = _message(result)
    assert "MCP response limit" in message
    assert str(mcp_server.MAX_RESPONSE_BYTES) in message
    assert "narrow the request" in message


def test_invalid_arguments_and_unknown_tools_are_reported(tmp_path):
    _sdk()
    (tmp_path / "prog.exe").write_bytes(b"MZ")

    wrong_type = _call(tmp_path, "ddt_le_bytes",
                       {"path": "prog.exe", "object": 1, "offset": "0x40", "length": 4})
    assert wrong_type.is_error is True and "offset" in _message(wrong_type)

    missing = _call(tmp_path, "ddt_le_bytes",
                    {"path": "prog.exe", "object": 1, "offset": 4})
    assert missing.is_error is True and "length" in _message(missing)

    unknown = _call(tmp_path, "ddt_nope", {})
    assert unknown.is_error is True and "Unknown tool" in _message(unknown)


def test_server_starts_and_stops_cleanly_for_each_session(tmp_path):
    _sdk()
    (tmp_path / "prog.exe").write_bytes(b"MZ")

    async def two_sessions():
        versions = []
        for _ in range(2):
            async with _connect(tmp_path) as client:
                versions.append(client.protocol_version)
                assert (await client.list_tools()).tools
                assert (await client.call_tool(
                    "ddt_manifest", {"path": "prog.exe"})).is_error is False
        return versions

    versions = asyncio.run(two_sessions())
    assert len(versions) == 2 and all(versions)
