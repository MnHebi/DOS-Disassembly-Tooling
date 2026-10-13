import pytest

from ddt.errors import DDTError
from ddt.strings import extract


def test_extracts_runs_with_exact_offsets(tmp_path):
    blob = b"\x00\x01Hello world\x00\xffAB\x00longer string here"
    target = tmp_path / "sample.bin"
    target.write_bytes(blob)
    result = extract(target, min_length=4)
    assert result["schema"] == "ddt.strings.v1"
    assert [s["text"] for s in result["strings"]] == ["Hello world", "longer string here"]
    assert result["strings"][0]["file_offset"] == 2
    assert result["strings"][0]["length"] == 11
    assert result["strings"][1]["file_offset"] == len(blob) - len("longer string here")
    assert result["total_string_count"] == 2
    assert result["strings_truncated"] is False
    assert result["source_size"] == len(blob)


def test_min_length_filters_short_runs(tmp_path):
    target = tmp_path / "s.bin"
    target.write_bytes(b"AB\x00ABCD\x00")
    assert [s["text"] for s in extract(target, min_length=4)["strings"]] == ["ABCD"]
    assert [s["text"] for s in extract(target, min_length=2)["strings"]] == ["AB", "ABCD"]


def test_max_results_bounds_output_without_understating(tmp_path):
    target = tmp_path / "many.bin"
    target.write_bytes(b"\x00".join(b"STR%02d" % i for i in range(5)))
    result = extract(target, min_length=3, max_results=2)
    assert len(result["strings"]) == 2
    assert result["total_string_count"] == 5
    assert result["strings_truncated"] is True


def test_rejects_invalid_bounds(tmp_path):
    target = tmp_path / "s.bin"
    target.write_bytes(b"ABCD")
    with pytest.raises(DDTError):
        extract(target, min_length=0)
    with pytest.raises(DDTError):
        extract(target, max_results=-1)


def test_rejects_non_file(tmp_path):
    with pytest.raises(DDTError):
        extract(tmp_path / "missing.bin")
