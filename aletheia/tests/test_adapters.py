"""Tests for adapters base."""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aletheia.adapters.base import check_binary, load_jsonl, ScanResult, run_command


def test_scan_result_defaults():
    sr = ScanResult(engine="test", success=False, exit_code=-1)
    assert sr.engine == "test"
    assert sr.stdout == ""
    assert sr.stderr == ""
    assert sr.raw_findings == []
    assert sr.error == ""
    assert sr.duration_sec == 0.0
    assert sr.artifact_path == ""


def test_check_binary_known():
    # "which" should find 'ls' or 'echo'
    assert check_binary("echo")
    assert check_binary("ls")


def test_check_binary_unknown():
    assert not check_binary("this-binary-should-not-exist-xyzzy")


def test_load_jsonl_missing(tmp_path):
    p = tmp_path / "missing.jsonl"
    assert load_jsonl(p) == []


def test_load_jsonl_valid(tmp_path):
    p = tmp_path / "test.jsonl"
    p.write_text('{"a": 1}\n{"b": 2}\n')
    items = load_jsonl(p)
    assert len(items) == 2
    assert items[0]["a"] == 1
    assert items[1]["b"] == 2


def test_load_jsonl_skips_malformed(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"a": 1}\nnotjson\n{"c": 3}\n')
    items = load_jsonl(p)
    assert len(items) == 2


def test_run_command_basic():
    code, out, err = run_command(["echo", "hello"])
    assert code == 0
    assert "hello" in out


def test_run_command_not_found():
    code, out, err = run_command(["nonexistent-tool-xyz"])
    assert code == -2


def test_run_command_timeout():
    code, out, err = run_command(["sleep", "10"], timeout=1)
    assert code == -1
    assert "TIMEOUT" in err