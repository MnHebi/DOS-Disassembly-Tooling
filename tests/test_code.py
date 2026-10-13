import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ddt import code
from ddt.errors import DDTError


def _ref(source, target, type_, flow=True, computed=False, external=False):
    return {"from": source, "to": target, "type": type_, "computed": computed,
            "flow": flow, "external": external, "memory": True, "offset": False}


def _record(entry="1000:0000", incoming=(), outgoing=(), unresolved=(), **extra):
    function = {"entry": entry, "name": "FUN_1000_0000",
                "incoming_references": list(incoming),
                "outgoing_references": list(outgoing),
                "unresolved_flow": list(unresolved)}
    function.update(extra)
    return {"schema": "ddt.ghidra-function.v1", "program": {"name": "fixture.exe"},
            "function": function}


def _write(tmp_path, record, name="export.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def test_callers_separate_direct_computed_and_external(tmp_path):
    record = _record(incoming=[
        _ref("Entry Point", "1000:0000", "EXTERNAL", flow=False),
        _ref("1000:0010", "1000:0000", "CONDITIONAL_CALL"),
        _ref("1000:0020", "1000:0000", "COMPUTED_CALL", computed=True),
        _ref("1000:0030", "EXT:0001", "UNCONDITIONAL_CALL", external=True),
    ])
    result = code.callers(_write(tmp_path, record))
    assert result["schema"] == "ddt.code-callers.v2"
    assert [c["from"] for c in result["direct_callers"]] == ["1000:0010"]
    assert [c["from"] for c in result["computed_callers"]] == ["1000:0020"]
    assert [c["from"] for c in result["external_callers"]] == ["1000:0030"]
    assert result["direct_caller_count"] == 1
    assert any("not proven direct" in limit for limit in result["limits"])
    assert any("entry point" in limit for limit in result["limits"])


def test_callees_classify_calls_and_ignore_non_calls(tmp_path):
    record = _record(outgoing=[
        _ref("1000:0000", "1000:000c", "UNCONDITIONAL_CALL"),
        _ref("1000:0000", "1000:fffc", "WRITE", flow=False),
        _ref("1000:0003", "1000:0020", "UNCONDITIONAL_JUMP"),
        _ref("1000:0005", "1000:0025", "COMPUTED_CALL", computed=True),
        _ref("1000:0008", "EXT:0001", "UNCONDITIONAL_CALL", external=True),
    ], unresolved=[
        {"address": "1000:0006", "text": "INT 0x21", "flow_type": "COMPUTED_CALL"},
        {"address": "1000:0009", "text": "JMP AX", "flow_type": "COMPUTED_JUMP"},
    ])
    result = code.callees(_write(tmp_path, record))
    assert [c["to"] for c in result["direct_calls"]] == ["1000:000c"]
    assert [c["to"] for c in result["computed_calls"]] == ["1000:0025"]
    assert [c["to"] for c in result["external_calls"]] == ["EXT:0001"]
    assert result["external_calls"][0]["external"] is True
    assert [c["text"] for c in result["unresolved_calls"]] == ["INT 0x21"]
    assert result["direct_call_count"] == 1
    assert any("not proven direct" in limit for limit in result["limits"])
    assert any("referenced destination address" in limit for limit in result["limits"])


def test_truncation_indicators_are_preserved(tmp_path):
    record = _record(
        incoming=[_ref("1000:0010", "1000:0000", "UNCONDITIONAL_CALL")],
        outgoing=[_ref("1000:0000", "1000:000c", "UNCONDITIONAL_CALL")],
        incoming_reference_count=10, incoming_references_truncated=False,
        outgoing_reference_count=5000, outgoing_references_truncated=True,
        unresolved_flow_count=1, unresolved_flow_truncated=False)
    path = _write(tmp_path, record)
    assert code.callers(path)["references_truncated"] is False
    callees = code.callees(path)
    assert callees["references_truncated"] is True
    assert callees["unresolved_truncated"] is False


def test_missing_truncation_fields_report_unknown(tmp_path):
    record = _record(outgoing=[_ref("1000:0000", "1000:000c", "UNCONDITIONAL_CALL")])
    result = code.callees(_write(tmp_path, record))
    assert result["references_truncated"] is None
    assert any("unknown" in limit for limit in result["limits"])


def test_missing_and_malformed_exports_error(tmp_path):
    with pytest.raises(DDTError, match="ordinary file"):
        code.callers(tmp_path / "absent.json")
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(DDTError, match="unreadable export"):
        code.callers(broken)


def test_unsupported_schema_and_shape_are_rejected(tmp_path):
    with pytest.raises(DDTError, match="unsupported export schema"):
        code.callers(_write(tmp_path, {"schema": "ddt.ghidra-function.v2", "function": {}}))
    with pytest.raises(DDTError, match="no function record"):
        code.callers(_write(tmp_path, {"schema": "ddt.ghidra-function.v1"}))


def test_queries_are_deterministic(tmp_path):
    record = _record(outgoing=[_ref("1000:0000", "1000:000c", "UNCONDITIONAL_CALL")])
    path = _write(tmp_path, record)
    assert code.callees(path) == code.callees(path)


def _dev_env():
    env = dict(os.environ)
    source = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = source + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("GHIDRA_HOME", None)
    env.pop("GHIDRA_INSTALL_DIR", None)
    return env


def test_cli_code_navigation_runs_without_ghidra(tmp_path):
    record = _record(outgoing=[_ref("1000:0000", "1000:000c", "UNCONDITIONAL_CALL")])
    path = _write(tmp_path, record)
    proc = subprocess.run([sys.executable, "-m", "ddt", "code", "callees",
                           "--export", str(path), "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "ddt.code-callees.v1"
    assert payload["direct_calls"][0]["to"] == "1000:000c"
