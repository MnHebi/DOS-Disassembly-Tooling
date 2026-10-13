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


# --- Memory readers / writers ------------------------------------------------

ADDRESS = "1000:1234"


def _mem(source, target, type_, *, flow=False, computed=False, external=False,
         read=None, write=None):
    entry = {"from": source, "to": target, "type": type_, "computed": computed,
             "flow": flow, "external": external, "memory": True, "offset": False}
    if read is not None:
        entry["read"] = read
    if write is not None:
        entry["write"] = write
    return entry


def test_readers_and_writers_classify_memory_access(tmp_path):
    record = _record(outgoing=[
        _mem("1000:0000", ADDRESS, "READ", read=True, write=False),
        _mem("1000:0003", ADDRESS, "WRITE", read=False, write=True),
        _mem("1000:0006", ADDRESS, "READ_WRITE", read=True, write=True),
        _mem("1000:0009", ADDRESS, "DATA", read=False, write=False),
        _mem("1000:000c", ADDRESS, "UNCONDITIONAL_CALL", flow=True),
    ])
    path = _write(tmp_path, record)
    finders = code.readers(path, ADDRESS)
    writers = code.writers(path, ADDRESS)
    assert finders["schema"] == "ddt.code-readers.v1"
    assert writers["schema"] == "ddt.code-writers.v1"
    assert [e["from"] for e in finders["direct"]] == ["1000:0000", "1000:0006"]
    assert [e["from"] for e in writers["direct"]] == ["1000:0003", "1000:0006"]
    assert writers["direct_count"] == 2
    assert finders["address"] == ADDRESS and finders["source"]["function_entry"] == "1000:0000"
    # A read/write reference must appear in both directions.
    assert "1000:0006" in {e["from"] for e in finders["direct"]} \
        and "1000:0006" in {e["from"] for e in writers["direct"]}


def test_computed_accesses_are_not_proven_direct(tmp_path):
    record = _record(outgoing=[_mem("1000:0000", ADDRESS, "READ", read=True, write=False, computed=True)])
    result = code.readers(_write(tmp_path, record), ADDRESS)
    assert result["direct"] == []
    assert [e["from"] for e in result["computed"]] == ["1000:0000"]
    assert result["computed_count"] == 1
    assert any("not proven" in limit for limit in result["limits"])


def test_address_and_space_must_match_exactly(tmp_path):
    record = _record(outgoing=[
        _mem("1000:0000", ADDRESS, "READ", read=True, write=False),
        _mem("1000:0003", "1000:9999", "READ", read=True, write=False),
        _mem("1000:0006", "OTHER::00001234", "READ", read=True, write=False),
    ])
    result = code.readers(_write(tmp_path, record), ADDRESS)
    assert [e["from"] for e in result["direct"]] == ["1000:0000"]


def test_legacy_exports_classified_by_exact_type_name(tmp_path):
    record = _record(outgoing=[
        _mem("1000:0000", ADDRESS, "READ"),
        _mem("1000:0003", ADDRESS, "WRITE"),
        _mem("1000:0006", ADDRESS, "DATA"),
    ])
    result = code.readers(_write(tmp_path, record), ADDRESS)
    assert [e["from"] for e in result["direct"]] == ["1000:0000"]
    assert result["unclassified_count"] == 1
    assert any("exact Ghidra reference-type name" in limit for limit in result["limits"])


def test_truncation_is_reported_for_access_queries(tmp_path):
    record = _record(outgoing=[_mem("1000:0000", ADDRESS, "READ", read=True, write=False)],
                     outgoing_reference_count=5000, outgoing_references_truncated=True)
    result = code.writers(_write(tmp_path, record), ADDRESS)
    assert result["direct"] == []
    assert result["references_truncated"] is True


def test_access_queries_reject_bad_inputs(tmp_path):
    with pytest.raises(DDTError, match="unsupported export schema"):
        code.readers(_write(tmp_path, {"schema": "other", "function": {}}), ADDRESS)
    with pytest.raises(DDTError, match="address"):
        code.writers(_write(tmp_path, _record()), "")


def test_cli_access_queries_without_ghidra(tmp_path):
    record = _record(outgoing=[_mem("1000:0000", ADDRESS, "READ", read=True, write=False)])
    path = _write(tmp_path, record)
    proc = subprocess.run([sys.executable, "-m", "ddt", "code", "readers", "--export", str(path),
                           "--address", ADDRESS, "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    payload = json.loads(proc.stdout)
    assert payload["schema"] == "ddt.code-readers.v1"
    assert payload["direct"][0]["from"] == "1000:0000"
