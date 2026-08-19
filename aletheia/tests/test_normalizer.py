"""Tests for normalizer."""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aletheia.normalizer import normalize_slither, normalize_semgrep, normalize_mythril, normalize_fuzzing
from aletheia.adapters.base import ScanResult


def test_normalize_slither_empty():
    assert normalize_slither([]) == []


def test_normalize_slither_items():
    raw = [{
        "finding_id": "pp-abc",
        "detector": "slither:test",
        "title": "Test",
        "description": "desc",
        "pattern_id": "TAX-01",
        "severity": "High",
        "confidence": "high",
        "location": {"file": "a.sol", "line_start": 1, "line_end": 1, "contract": "C", "function": "f"},
        "evidence": [],
    }]
    findings = normalize_slither(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == "slither"
    assert f.detector == "slither:test"
    assert f.severity == "high"


def test_normalize_semgrep():
    raw = [{
        "check_id": "solidity.reentrancy",
        "path": "a.sol",
        "start": {"line": 10},
        "end": {"line": 12},
        "extra": {
            "message": "Reentrancy vulnerability",
            "severity": "HIGH",
            "cwe_id": "CWE-841",
        },
    }]
    findings = normalize_semgrep(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == "semgrep"
    assert f.detector == "solidity.reentrancy"
    assert "Reentrancy" in f.description
    assert f.severity == "high"


def test_normalize_mythril():
    raw = [{
        "title": "SWC-100",
        "description": "Function can be called by anyone",
        "severity": "High",
        "contract": "C",
        "function": "f",
        "contract_file": "a.sol",
        "lineno": 42,
        "swc-id": "SWC-100",
    }]
    findings = normalize_mythril(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == "mythril"
    assert f.severity == "high"
    assert f.source_location.line_start == 42


def test_normalize_fuzzing():
    raw = [{"message": "FOUND: assertion failed in sequence", "description": "revert"}]
    findings = normalize_fuzzing("medusa", raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == "medusa"
    assert f.severity == "high"  # "assertion" triggers high
    assert f.status == "needs-verification"


def test_normalize_scan_result():
    from aletheia.normalizer import normalize_scan_result
    sr = ScanResult(
        engine="semgrep",
        success=True,
        exit_code=0,
        raw_findings=[{
            "check_id": "test",
            "path": "a.sol",
            "start": {"line": 1},
            "end": {"line": 1},
            "extra": {"message": "x", "severity": "MEDIUM"},
        }],
    )
    findings = normalize_scan_result(sr)
    assert len(findings) == 1
    assert findings[0].engine == "semgrep"