import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from ddt.capture import intake
from ddt.errors import DDTError


def _snapshot(tmp_path, name, files: dict[str, bytes]) -> Path:
    root = tmp_path / name
    root.mkdir()
    for relative, data in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root


def _digest(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def _dev_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_identical_captures(tmp_path):
    before = _snapshot(tmp_path, "before", {"SAVE.DAT": b"\x01\x02\x03", "sub/x.bin": b"abc"})
    after = _snapshot(tmp_path, "after", {"SAVE.DAT": b"\x01\x02\x03", "sub/x.bin": b"abc"})
    record = intake(before, after)
    assert record["schema"] == "ddt.capture-intake.v1"
    assert record["counts"] == {"added": 0, "removed": 0, "unchanged": 2, "modified": 0}
    assert record["captures"]["before"]["manifest"] == record["captures"]["after"]["manifest"]
    # Independent hash check of a literal fixture byte string.
    entry = next(e for e in record["captures"]["before"]["manifest"]["entries"]
                 if e["path"] == "SAVE.DAT")
    assert entry == {"path": "SAVE.DAT", "bytes": 3,
                     "sha256": hashlib.sha256(b"\x01\x02\x03").hexdigest()}


def test_each_capture_file_is_read_once_and_hashes_agree(tmp_path, monkeypatch):
    before = _snapshot(tmp_path, "before", {"f.dat": b"ABCD", "sub/g.dat": b"gg", "gone.dat": b"x"})
    after = _snapshot(tmp_path, "after", {"f.dat": b"AXCD", "sub/g.dat": b"gg", "new.dat": b"z"})
    tracked = {before / name for name in ("f.dat", "sub/g.dat", "gone.dat")} \
        | {after / name for name in ("f.dat", "sub/g.dat", "new.dat")}
    reads: dict[Path, int] = {}
    original = Path.read_bytes

    def counting(path):
        reads[path] = reads.get(path, 0) + 1
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", counting)
    record = intake(before, after)
    assert all(reads.get(path, 0) == 1 for path in tracked)
    rows = {row["path"]: row for row in record["comparison"]["results"]}
    for side in ("before", "after"):
        manifest = record["captures"][side]["manifest"]
        assert manifest["schema"] == "ddt.artifact-manifest.v1"
        for entry in manifest["entries"]:
            assert entry["sha256"] == rows[entry["path"]][f"{side}_sha256"]
            assert entry["bytes"] == rows[entry["path"]][f"{side}_bytes"]
    assert {e["path"] for e in record["captures"]["before"]["manifest"]["entries"]} \
        == {"f.dat", "sub/g.dat", "gone.dat"}
    assert {e["path"] for e in record["captures"]["after"]["manifest"]["entries"]} \
        == {"f.dat", "sub/g.dat", "new.dat"}


def test_single_changed_byte(tmp_path):
    before = _snapshot(tmp_path, "before", {"f.dat": b"ABCD"})
    after = _snapshot(tmp_path, "after", {"f.dat": b"AXCD"})
    record = intake(before, after)
    assert record["counts"]["modified"] == 1
    changed = next(r for r in record["comparison"]["results"] if r["path"] == "f.dat")
    assert changed["status"] == "changed"
    assert changed["before_sha256"] == hashlib.sha256(b"ABCD").hexdigest()
    assert changed["after_sha256"] == hashlib.sha256(b"AXCD").hexdigest()
    assert changed["runs"] == [{"offset": 1, "extent_bytes": 1, "before_hex": "42",
                                 "after_hex": "58", "preview_truncated": False}]
    assert changed["total_run_count"] == 1


def test_multiple_disjoint_runs(tmp_path):
    before = _snapshot(tmp_path, "before", {"f.dat": b"A\x00B\x00C"})
    after = _snapshot(tmp_path, "after", {"f.dat": b"X\x00Y\x00Z"})
    changed = next(r for r in intake(before, after)["comparison"]["results"] if r["path"] == "f.dat")
    assert [run["offset"] for run in changed["runs"]] == [0, 2, 4]
    assert changed["total_run_count"] == 3


def test_added_and_removed_files(tmp_path):
    before = _snapshot(tmp_path, "before", {"gone.dat": b"x", "stay.dat": b"y"})
    after = _snapshot(tmp_path, "after", {"new.dat": b"z", "stay.dat": b"y"})
    record = intake(before, after)
    assert record["counts"] == {"added": 1, "removed": 1, "unchanged": 1, "modified": 0}
    statuses = {r["path"]: r["status"] for r in record["comparison"]["results"]}
    assert statuses == {"gone.dat": "only_before", "new.dat": "only_after", "stay.dat": "same"}


def test_zero_length_files(tmp_path):
    before = _snapshot(tmp_path, "before", {"empty.dat": b""})
    after = _snapshot(tmp_path, "after", {"empty.dat": b"", "fresh.dat": b""})
    record = intake(before, after)
    assert record["counts"] == {"added": 1, "removed": 0, "unchanged": 1, "modified": 0}
    entry = next(e for e in record["captures"]["after"]["manifest"]["entries"]
                 if e["path"] == "empty.dat")
    assert entry["bytes"] == 0 and entry["sha256"] == hashlib.sha256(b"").hexdigest()


def test_bounded_previews_keep_total_counts(tmp_path):
    before = _snapshot(tmp_path, "before", {"f.dat": b"A\x00B\x00C"})
    after = _snapshot(tmp_path, "after", {"f.dat": b"X\x00Y\x00Z"})
    changed = next(r for r in intake(before, after, max_runs=1)["comparison"]["results"]
                   if r["path"] == "f.dat")
    assert len(changed["runs"]) == 1
    assert changed["total_run_count"] == 3
    assert changed["runs_truncated"] is True


def test_missing_or_nondirectory_inputs(tmp_path):
    real = _snapshot(tmp_path, "before", {"f": b"x"})
    with pytest.raises(DDTError, match="--before must be an existing directory"):
        intake(tmp_path / "absent", real)
    file_path = tmp_path / "file.txt"
    file_path.write_bytes(b"x")
    with pytest.raises(DDTError, match="--after must be an existing directory"):
        intake(real, file_path)


def test_symbolic_links_are_rejected(tmp_path):
    before = _snapshot(tmp_path, "before", {"f": b"x"})
    after = _snapshot(tmp_path, "after", {"f": b"x"})
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"data")
    try:
        (after / "link.bin").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(DDTError, match="symlink"):
        intake(before, after)
    link_dir = tmp_path / "linkdir"
    link_dir.symlink_to(after, target_is_directory=True)
    with pytest.raises(DDTError, match="not a symlink"):
        intake(before, link_dir)


def test_receipt_must_not_be_inside_a_capture(tmp_path):
    before = _snapshot(tmp_path, "before", {"f": b"x"})
    after = _snapshot(tmp_path, "after", {"f": b"x"})
    with pytest.raises(DDTError, match="must not be written inside a capture directory"):
        intake(before, after, out=before / "receipt.json")
    with pytest.raises(DDTError, match="must not be written inside a capture directory"):
        intake(before, after, out=after / "nested" / "receipt.json")


def test_captures_are_never_modified(tmp_path):
    before = _snapshot(tmp_path, "before", {"f": b"ABCD", "sub/g": b"gg"})
    after = _snapshot(tmp_path, "after", {"f": b"AXCD"})
    before_digest, after_digest = _digest(before), _digest(after)
    receipt = tmp_path / "receipt.json"
    intake(before, after, out=receipt)
    assert _digest(before) == before_digest
    assert _digest(after) == after_digest
    assert receipt.is_file()
    assert json.loads(receipt.read_text(encoding="utf-8"))["schema"] == "ddt.capture-intake.v1"


def test_deterministic_results(tmp_path):
    before = _snapshot(tmp_path, "before", {"f": b"ABCD"})
    after = _snapshot(tmp_path, "after", {"f": b"AXCD", "n": b""})
    assert intake(before, after) == intake(before, after)


def test_malformed_parameters(tmp_path):
    before = _snapshot(tmp_path, "before", {"f": b"x"})
    after = _snapshot(tmp_path, "after", {"f": b"x"})
    with pytest.raises(DDTError, match="max_runs"):
        intake(before, after, max_runs=-1)
    with pytest.raises(DDTError, match="must be a file path"):
        intake(before, after, out=tmp_path)


def test_cli_intake(tmp_path):
    before = _snapshot(tmp_path, "before", {"SAVE.DAT": b"\x00\x01"})
    after = _snapshot(tmp_path, "after", {"SAVE.DAT": b"\x00\x02"})
    receipt = tmp_path / "reports" / "capture-receipt.json"
    proc = subprocess.run([sys.executable, "-m", "ddt", "capture", "intake",
                           "--before", str(before), "--after", str(after),
                           "--out", str(receipt), "--note", "pressed key", "--json"],
                          check=True, capture_output=True, text=True, env=_dev_env())
    payload = json.loads(proc.stdout)
    assert payload["counts"]["modified"] == 1
    assert payload["user_supplied"] == {"note": "pressed key"}
    assert json.loads(receipt.read_text(encoding="utf-8")) == payload
    # Missing parameter is a clean CLI failure, not a traceback.
    bad = subprocess.run([sys.executable, "-m", "ddt", "capture", "intake",
                          "--after", str(after), "--json"],
                         capture_output=True, text=True, env=_dev_env())
    assert bad.returncode == 2
