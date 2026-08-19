"""Deduplication — combines findings from multiple engines with same root cause.

Uses existing dedup from agent_adapter where available.
"""

from __future__ import annotations
import json
from collections import defaultdict
from typing import Any

from .models import Finding, to_dict


def dedup_key(f: Finding) -> str:
    """Generate a stable dedup key for a finding."""
    if f.dedup_key:
        return f.dedup_key
    return json.dumps({
        "detector": f.detector,
        "file": f.source_location.file,
        "contract": f.source_location.contract,
        "function": f.source_location.function,
    }, sort_keys=True)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings, merging corroborating engines.

    Two findings are considered the same if they share the same dedup_key.
    The merged finding keeps the highest severity, best confidence, and lists
    all engines that found it.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[dedup_key(f)].append(f)

    merged = []
    for key, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        # merge multiple findings
        best = sorted(group, key=lambda x: _severity_rank(x.severity), reverse=True)[0]
        # make a copy
        import copy
        merged_f = copy.deepcopy(best)
        merged_f.corroborating_engines = list(dict.fromkeys(
            f.engine for f in group if f.engine
        ))
        # keep the best confidence
        merged_f.confidence = max(
            (f.confidence for f in group),
            key=lambda x: _confidence_rank(x)
        )
        merged.append(merged_f)

    return merged


def _severity_rank(s: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "unknown": 0}.get(s, 0)


def _confidence_rank(c: str) -> int:
    return {"high": 3, "medium": 2, "low": 1, "unknown": 0}.get(c, 0)


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Preliminary ranking by severity, confidence, corroboration, location.

    Returns sorted list (highest priority first).
    """
    def score(f: Finding) -> int:
        s = _severity_rank(f.severity) * 100
        s += _confidence_rank(f.confidence) * 20
        s += len(f.corroborating_engines) * 10
        if f.source_location.file:
            s += 5
        if f.trace or f.test_sequence:
            s += 5
        if f.status == "needs-verification":
            s -= 10
        return s

    return sorted(findings, key=score, reverse=True)