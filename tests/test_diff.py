from ddt.diff import compare, manifest


def test_changed_and_unchanged_files(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    (a / "SAVE.DAT").write_bytes(b"\x01\x02\x03\x04")
    (b / "SAVE.DAT").write_bytes(b"\x01\x05\x03\x06")
    (a / "same").write_bytes(b"abc")
    (b / "same").write_bytes(b"abc")
    (b / "new").write_bytes(b"a")
    result = compare(a, b)
    assert result["summary"] == {"same": 1, "changed": 1, "only_before": 0, "only_after": 1}
    record = next(x for x in result["results"] if x["path"] == "SAVE.DAT")
    assert [x["offset"] for x in record["runs"]] == [1, 3]
    assert record["runs"][0]["before_hex"] == "02"
    assert record["runs"][0]["after_hex"] == "05"
    assert record["total_run_count"] == 2
    assert record["runs_truncated"] is False


def test_output_capped_without_understating_changes(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"A\x00B\x00C")
    b.write_bytes(b"X\x00Y\x00Z")
    entry = compare(a, b, max_runs=1)["results"][0]
    assert len(entry["runs"]) == 1
    assert entry["total_run_count"] == 3
    assert entry["runs_truncated"] is True


def test_manifest_is_stable(tmp_path):
    (tmp_path / "b").write_bytes(b"bb")
    (tmp_path / "a").write_bytes(b"aa")
    result = manifest(tmp_path)
    assert [row["path"] for row in result["entries"]] == ["a", "b"]
    assert manifest(tmp_path) == result
