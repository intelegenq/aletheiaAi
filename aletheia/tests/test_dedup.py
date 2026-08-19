"""Tests for dedup and ranking."""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aletheia.dedup import deduplicate, rank_findings, dedup_key
from aletheia.models import Finding, SourceLocation


def test_dedup_empty():
    assert deduplicate([]) == []


def test_dedup_single():
    f = Finding(engine="slither", detector="test", description="x",
                source_location=SourceLocation(file="a.sol", line_start=1))
    out = deduplicate([f])
    assert len(out) == 1
    assert out[0].finding_id == f.finding_id


def test_dedup_merge_same():
    """Two findings with same detector/file/contract/function should merge."""
    f1 = Finding(engine="slither", detector="uninitialized-storage", description="x",
                 source_location=SourceLocation(file="a.sol", line_start=10, contract="C", function="f"))
    f2 = Finding(engine="mythril", detector="uninitialized-storage", description="x",
                 source_location=SourceLocation(file="a.sol", line_start=10, contract="C", function="f"))
    out = deduplicate([f1, f2])
    assert len(out) == 1
    assert "slither" in out[0].corroborating_engines
    assert "mythril" in out[0].corroborating_engines


def test_dedup_merge_keeps_highest_severity():
    f1 = Finding(engine="slither", detector="test", description="x", severity="high",
                 source_location=SourceLocation(file="a.sol", line_start=10, contract="C", function="f"))
    f2 = Finding(engine="mythril", detector="test", description="x", severity="medium",
                 source_location=SourceLocation(file="a.sol", line_start=10, contract="C", function="f"))
    out = deduplicate([f1, f2])
    assert len(out) == 1
    assert out[0].severity == "high"


def test_dedup_not_same():
    """Different files should not merge."""
    f1 = Finding(engine="slither", detector="test", description="x",
                 source_location=SourceLocation(file="a.sol", line_start=10))
    f2 = Finding(engine="slither", detector="test", description="x",
                 source_location=SourceLocation(file="b.sol", line_start=10))
    out = deduplicate([f1, f2])
    assert len(out) == 2


def test_rank_order():
    f1 = Finding(engine="slither", detector="test", severity="high", confidence="high",
                 source_location=SourceLocation(file="a.sol", line_start=10))
    f2 = Finding(engine="slither", detector="test", severity="low", confidence="low",
                 source_location=SourceLocation(file="a.sol", line_start=20))
    f3 = Finding(engine="slither", detector="test", severity="medium", confidence="medium",
                 source_location=SourceLocation(file="a.sol", line_start=30))
    ranked = rank_findings([f2, f3, f1])
    # highest first
    assert ranked[0].severity == "high"
    assert ranked[-1].severity == "low"


def test_rank_corroboration_boost():
    f1 = Finding(engine="slither", detector="test", severity="medium", confidence="medium",
                 source_location=SourceLocation(file="a.sol", line_start=10),
                 corroborating_engines=["slither", "mythril"])
    f2 = Finding(engine="slither", detector="test", severity="medium", confidence="medium",
                 source_location=SourceLocation(file="a.sol", line_start=20),
                 corroborating_engines=["slither"])
    ranked = rank_findings([f2, f1])
    assert ranked[0].corroborating_engines == ["slither", "mythril"]