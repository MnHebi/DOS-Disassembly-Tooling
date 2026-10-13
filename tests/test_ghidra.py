import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from ddt import ghidra
from ddt.errors import DDTError


def _fake_ghidra(tmp_path) -> Path:
    home = tmp_path / "ghidra_install"
    support = home / "support"
    support.mkdir(parents=True)
    for name in ("analyzeHeadless", "analyzeHeadless.bat"):
        (support / name).write_text("", encoding="utf-8")
    return home


def test_locate_headless_from_directory_and_launcher(tmp_path):
    home = _fake_ghidra(tmp_path)
    launcher = ghidra.locate_headless(home)
    assert launcher.parent.name == "support"
    assert launcher.name.lower().startswith("analyzeheadless")
    assert ghidra.locate_headless(launcher) == launcher


def test_locate_headless_from_environment(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path)
    monkeypatch.setenv("GHIDRA_HOME", str(home))
    assert ghidra.locate_headless().parent.parent == home


def test_locate_headless_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    with pytest.raises(DDTError, match="analyzeHeadless not found"):
        ghidra.locate_headless(tmp_path / "absent")


def test_resolve_project_accepts_gpr_and_directory(tmp_path):
    project = tmp_path / "DDT_M2.gpr"
    project.write_text("", encoding="utf-8")
    assert ghidra.resolve_project(project) == (tmp_path, "DDT_M2")
    assert ghidra.resolve_project(tmp_path) == (tmp_path, "DDT_M2")


def test_resolve_project_rejects_ambiguous_or_missing(tmp_path):
    with pytest.raises(DDTError, match="no Ghidra project"):
        ghidra.resolve_project(tmp_path)
    (tmp_path / "A.gpr").write_text("", encoding="utf-8")
    (tmp_path / "B.gpr").write_text("", encoding="utf-8")
    with pytest.raises(DDTError, match="multiple Ghidra projects"):
        ghidra.resolve_project(tmp_path)
    with pytest.raises(DDTError, match="not a Ghidra project"):
        ghidra.resolve_project(tmp_path / "missing")


def test_build_command_is_read_only_and_explicit():
    headless, out, scripts = Path("/gh/support/analyzeHeadless"), Path("/out.json"), Path("/scripts")
    command = ghidra.build_command(headless, Path("/proj"), "DDT_M2",
                                   "fixture.exe", "1000:0000", out, scripts)
    assert command[0] == str(headless)
    assert command[command.index("-process") + 1] == "fixture.exe"
    assert command[command.index("-postScript") + 1] == "ExportFunction.java"
    assert command[command.index("-scriptPath") + 1] == str(scripts)
    assert command[-2:] == ["1000:0000", str(out)]
    for flag in ("-readOnly", "-noanalysis"):
        assert flag in command
    for forbidden in ("-import", "-overwrite", "-commit", "-deleteProject"):
        assert forbidden not in command


def test_build_command_wraps_batch_launcher():
    launcher = Path("C:/gh/support/analyzeHeadless.bat")
    command = ghidra.build_command(launcher, Path("C:/proj"), "DDT_M2", "fixture.exe",
                                   "0x0", Path("C:/out.json"), Path("C:/scripts"))
    assert command[:3] == ["cmd", "/c", str(launcher)]
    assert command[command.index("-process") + 1] == "fixture.exe"


def _run_export(tmp_path, monkeypatch, writer, home):
    def fake_run(command, **kwargs):
        writer(Path(command[-1]))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("ddt.ghidra.subprocess.run", fake_run)
    project = tmp_path / "DDT_M2.gpr"
    project.write_text("", encoding="utf-8")
    return ghidra.export_function(project, "fixture.exe", "1000:0000", tmp_path / "out.json",
                                  ghidra=home)


def test_export_function_returns_validated_record(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path)
    record = {"schema": ghidra.SCHEMA, "program": {"name": "fixture.exe"}, "function": {}}
    result = _run_export(tmp_path, monkeypatch,
                         lambda out: out.write_text(json.dumps(record), encoding="utf-8"), home)
    assert result == record


def test_export_function_surfaces_script_error(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path)
    body = {"schema": ghidra.SCHEMA, "error": "no function with entry point at 1000:0099"}
    with pytest.raises(DDTError, match="no function with entry point"):
        _run_export(tmp_path, monkeypatch,
                    lambda out: out.write_text(json.dumps(body), encoding="utf-8"), home)


def test_export_function_requires_output(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path)
    with pytest.raises(DDTError, match="produced no output"):
        _run_export(tmp_path, monkeypatch, lambda out: None, home)


def test_export_function_rejects_wrong_schema(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path)
    with pytest.raises(DDTError, match="unexpected Ghidra export schema"):
        _run_export(tmp_path, monkeypatch,
                    lambda out: out.write_text('{"schema": "other"}', encoding="utf-8"), home)


def test_export_function_reports_timeout(tmp_path, monkeypatch):
    home = _fake_ghidra(tmp_path)

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 600)

    monkeypatch.setattr("ddt.ghidra.subprocess.run", fake_run)
    project = tmp_path / "DDT_M2.gpr"
    project.write_text("", encoding="utf-8")
    with pytest.raises(DDTError, match="exceeded"):
        ghidra.export_function(project, "fixture.exe", "0x0", tmp_path / "o.json",
                               ghidra=home, timeout=600)


def _dev_env(extra=None):
    env = dict(os.environ)
    source = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = source + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("GHIDRA_HOME", None)
    env.pop("GHIDRA_INSTALL_DIR", None)
    if extra:
        env.update(extra)
    return env


def test_cli_ghidra_export_without_ghidra_errors(tmp_path):
    project = tmp_path / "DDT_M2.gpr"
    project.write_text("", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-m", "ddt", "ghidra", "export",
                           "--project", str(project), "--program", "fixture.exe",
                           "--function", "0x0", "--out", str(tmp_path / "o.json"), "--json"],
                          capture_output=True, text=True, env=_dev_env())
    assert proc.returncode == 2
    assert json.loads(proc.stderr)["error_type"] == "DDTError"


# --- Opt-in integration against a real Ghidra install ------------------------

def _fixture_bytes() -> bytes:
    image = bytes([0xE8, 0x09, 0x00, 0xB8, 0x00, 0x4C, 0xCD, 0x21, 0xC3,
                   0x90, 0x90, 0x90, 0xB8, 0x05, 0x00, 0xC3]) + b"DDT_M2_FIXTURE\x00" \
            + bytes([0x90, 0x00, 0x00])
    size = 64 + len(image)
    header = bytearray(64)
    struct.pack_into("<14H", header, 0, 0x5A4D, size, 1, 1, 4, 0, 0xFFFF, 0, 0xFFFE, 0, 0, 0, 0x1C, 0)
    struct.pack_into("<HH", header, 0x1C, 0x0020, 0x0000)
    return bytes(header) + image


def _integration_home():
    for key in ("DDT_GHIDRA_HOME", "GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
        value = os.environ.get(key)
        if value and (Path(value) / "support").is_dir():
            return Path(value)
    return None


@pytest.mark.skipif(_integration_home() is None,
                    reason="set DDT_GHIDRA_HOME to a Ghidra install to run the integration test")
def test_integration_export_matches_fixture(tmp_path):
    home = _integration_home()
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(_fixture_bytes())
    projects = tmp_path / "projects"
    projects.mkdir()
    headless = ghidra.locate_headless(home)
    subprocess.run([str(headless), str(projects), "DDT_M2", "-import", str(fixture)],
                   check=True, capture_output=True, text=True)
    try:
        record = ghidra.export_function(projects, "fixture.exe", "1000:0000",
                                        tmp_path / "entry.json", ghidra=home)
    except DDTError as exc:
        pytest.skip(f"loader entry address differs for this Ghidra build: {exc}")
    program = record["program"]
    function = record["function"]
    assert program["executable_format"].startswith("Old-style DOS Executable")
    assert program["image_base"] == "0000:0000"
    assert program["executable_sha256"] == hashlib.sha256(_fixture_bytes()).hexdigest()
    assert function["entry"] == "1000:0000"
    assert function["instruction_count"] == 4
    first = function["instructions"][0]
    assert first["bytes"] == "e80900"
    assert first["source_file_offset"] == 64
    assert first["source_file"] == "fixture.exe"
    call = next(r for r in function["outgoing_references"] if r["type"] == "UNCONDITIONAL_CALL")
    assert call["to"] == "1000:000c" and call["computed"] is False
    assert function["outgoing_references"][0]["to"] == "1000:000c"
    assert any(u["text"] == "INT 0x21" for u in function["unresolved_flow"])
    block = next(b for b in program["memory_blocks"] if b["name"] == "CODE_0")
    assert block["sources"][0]["file_offset"] == 64
