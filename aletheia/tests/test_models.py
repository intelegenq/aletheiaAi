"""Tests for AletheiaAI."""

from __future__ import annotations
import os
import sys
from pathlib import Path

# ensure import works
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aletheia.models import Finding, SourceLocation, to_dict, from_slither_normalized


def test_finding_auto_id():
    f = Finding(
        engine="slither", detector="test",
        source_location=SourceLocation(file="test.sol", line_start=10),
    )
    assert f.finding_id.startswith("al-")
    assert len(f.finding_id) == 19  # al- + 16 hex


def test_finding_status_default():
    f = Finding(engine="slither", detector="test")
    assert f.status == "candidate"


def test_finding_fingerprint_default():
    f = Finding(engine="slither", detector="test", description="issue")
    assert f.fingerprint == f.finding_id


def test_from_slither_normalized():
    n = {
        "finding_id": "pp-1234",
        "detector": "slither:uninitialized-storage",
        "title": "Uninitialized Storage",
        "description": "test.sol#10 variable never initialized",
        "pattern_id": "TAX-87",
        "severity": "High",
        "confidence": "high",
        "location": {
            "file": "test.sol",
            "line_start": 10,
            "line_end": 10,
            "contract": "MyContract",
            "function": "myFunc",
        },
        "evidence": ["line 10"],
    }
    f = from_slither_normalized(n)
    assert f.engine == "slither"
    assert f.detector == "slither:uninitialized-storage"
    assert f.description == "test.sol#10 variable never initialized"
    assert f.severity == "high"
    assert f.source_location.file == "test.sol"
    assert f.source_location.contract == "MyContract"


def test_to_dict_roundtrip():
    f = Finding(
        engine="slither", detector="test", title="test finding",
        severity="high", status="candidate",
        source_location=SourceLocation(file="a.sol", line_start=1),
    )
    d = to_dict(f)
    assert d["engine"] == "slither"
    assert d["source_location"]["file"] == "a.sol"
    assert d["status"] == "candidate"
    assert d["finding_id"] == f.finding_id