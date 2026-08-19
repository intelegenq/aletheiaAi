"""Root-cause extraction and cross-engine correlation.

A root cause is identified by (contract, function, state variable, vuln class),
all resolved against REAL analysis data — never by title similarity.
"""

from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from .models import Finding
from .analysis_wiring import AnalysisOutcome


@dataclass
class RootCause:
    root_cause_id: str = ""
    contract: str = ""
    function: str = ""          # canonical name from analysis
    state_variables: list[str] = field(default_factory=list)
    vulnerability_class: str = ""
    operation: str = ""         # e.g. "state-write"
    resolved: bool = False      # True only when mapped to a real analysis function


# Prefixes fuzz harnesses add around the real target function.
_HARNESS_PREFIXES = ("attack_", "test_", "echidna_", "invariant_", "fuzz_", "check_")


def _candidate_tokens(f: Finding) -> list[str]:
    """Text fragments that may name the target function (trace first, then title)."""
    parts: list[str] = []
    for t in (f.trace or []):
        parts.append(str(t))
    for e in (f.evidence or []):
        parts.append(str(e))
    if f.test_sequence:
        parts.append(str(f.test_sequence))
    parts.append(f.title or "")
    parts.append(f.description or "")
    return parts


def resolve_function(f: Finding, analysis: Optional[AnalysisOutcome]) -> tuple[str, str]:
    """Resolve a finding to a canonical (contract, function) from REAL analysis.

    Returns ("", "") when it cannot be resolved — callers must then treat
    access-control and reachability as unknown.
    """
    if analysis is None or not analysis.ok:
        return "", ""

    # 1. Exact source-location mapping (static engines).
    loc_func = (f.source_location.function or "").split("(")[0]
    loc_contract = f.source_location.contract or ""
    if loc_func:
        for canonical in analysis.all_functions:
            c, _, rest = canonical.partition(".")
            name = rest.split("(")[0]
            if name == loc_func and (not loc_contract or c == loc_contract):
                return c, canonical

    # 2. Name mentioned in trace/evidence/title — must exist in the analysis,
    #    so this is grounded in the contract's real ABI, not free-text guessing.
    blob = " ".join(_candidate_tokens(f))
    if not blob:
        return "", ""
    blob_lower = blob.lower()

    best: tuple[int, str, str] = (0, "", "")
    for canonical in analysis.all_functions:
        c, _, rest = canonical.partition(".")
        name = rest.split("(")[0]
        if not name or name.startswith("_"):
            # internal helpers are matched only via the explicit path above
            continue
        n_lower = name.lower()
        hit = False
        # direct mention, e.g. "VulnerableVault.setOwner(address)" or "calldata=setOwner(address)"
        if re.search(rf"\b{re.escape(n_lower)}\s*\(", blob_lower):
            hit = True
        # harness wrapper, e.g. attack_setOwner / test_unauthorized_setOwner
        if not hit:
            for pref in _HARNESS_PREFIXES:
                if re.search(rf"{pref}[a-z0-9_]*{re.escape(n_lower)}", blob_lower):
                    hit = True
                    break
        if hit and len(name) > best[0]:
            best = (len(name), c, canonical)

    if best[2]:
        return best[1], best[2]
    return "", ""


def build_root_cause(
    f: Finding,
    analysis: Optional[AnalysisOutcome],
) -> RootCause:
    """Build the root cause for a finding using real analysis facts."""
    contract, canonical = resolve_function(f, analysis)

    state_vars: list[str] = []
    if analysis is not None and canonical:
        state_vars = list(analysis.state_writes.get(canonical, []))

    vclass = f.vulnerability_class or ""
    # Normalize the class so the same root cause from different engines matches.
    if state_vars:
        operation = "state-write"
    else:
        operation = "unknown"

    if canonical:
        # Class is derived from what the code actually does, not the engine label.
        norm_class = f"state-write:{','.join(sorted(state_vars))}" if state_vars else (vclass or "unclassified")
        raw = f"{contract}|{canonical}|{','.join(sorted(state_vars))}|{norm_class}"
        rid = "rc-" + hashlib.sha256(raw.encode()).hexdigest()[:16]
        return RootCause(
            root_cause_id=rid,
            contract=contract,
            function=canonical,
            state_variables=state_vars,
            vulnerability_class=norm_class,
            operation=operation,
            resolved=True,
        )

    # Unresolved: keep the finding separate, keyed by its own identity so it is
    # never merged with an unrelated finding.
    raw = f"unresolved|{f.engine}|{f.detector}|{f.finding_id}"
    return RootCause(
        root_cause_id="rc-" + hashlib.sha256(raw.encode()).hexdigest()[:16],
        contract=f.source_location.contract or "",
        function=f.source_location.function or "",
        vulnerability_class=vclass or "unclassified",
        operation="unknown",
        resolved=False,
    )


_TITLE_BY_STATE_VAR = {
    "owner": "Unauthorized owner takeover",
    "paused": "Unauthorized pause state change",
    "balances": "Unauthorized balance modification",
}


def correlate(
    findings: list[Finding],
    analysis: Optional[AnalysisOutcome],
) -> tuple[list[Finding], dict[str, dict]]:
    """Merge findings that share a resolved root cause.

    Returns (merged_findings, root_cause_map). Unresolved findings are never
    merged with each other.
    """
    groups: dict[str, list[Finding]] = {}
    rc_by_id: dict[str, RootCause] = {}

    for f in findings:
        rc = build_root_cause(f, analysis)
        rc_by_id[rc.root_cause_id] = rc
        groups.setdefault(rc.root_cause_id, []).append(f)

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "unknown": 0}
    merged: list[Finding] = []
    rc_map: dict[str, dict] = {}

    for rid, group in groups.items():
        rc = rc_by_id[rid]
        # Primary = highest severity, dynamic evidence preferred as tie-break.
        def _key(x: Finding):
            dyn = 1 if x.engine in ("foundry", "medusa", "echidna") else 0
            return (severity_rank.get(x.severity.lower(), 0), dyn, len(x.trace or []))

        primary = max(group, key=_key)

        engines: list[str] = []
        evidence: list[str] = []
        trace: list[str] = []
        for g in group:
            for e in [g.engine, *(g.corroborating_engines or [])]:
                if e and e not in engines:
                    engines.append(e)
            for ev in (g.evidence or []):
                if ev not in evidence:
                    evidence.append(str(ev))
            for tr in (g.trace or []):
                if tr not in trace:
                    trace.append(str(tr))

        primary.corroborating_engines = engines
        primary.evidence = evidence
        primary.trace = trace
        primary.exploitability_metadata = dict(primary.exploitability_metadata or {})
        primary.exploitability_metadata.update({
            "root_cause_id": rid,
            "root_cause_resolved": rc.resolved,
            "root_cause_function": rc.function,
            "root_cause_state_variables": rc.state_variables,
            "evidence_count": len(group),
            "merged_finding_ids": [g.finding_id for g in group],
        })

        # Give merged multi-engine findings a root-cause title.
        if rc.resolved and len(group) > 1:
            for var, title in _TITLE_BY_STATE_VAR.items():
                if var in rc.state_variables:
                    primary.title = title
                    break

        rc_map[rid] = {
            "root_cause_id": rid,
            "title": primary.title,
            "contract": rc.contract,
            "function": rc.function,
            "state_variables": rc.state_variables,
            "vulnerability_class": rc.vulnerability_class,
            "operation": rc.operation,
            "resolved": rc.resolved,
            "corroborating_engines": engines,
            "evidence_count": len(group),
            "finding_ids": [g.finding_id for g in group],
            "primary_finding_id": primary.finding_id,
        }
        merged.append(primary)

    return merged, rc_map