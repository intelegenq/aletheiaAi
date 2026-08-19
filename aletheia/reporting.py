"""Evidence-backed report generation for report-ready triage results.

The reporter is deliberately downstream of conviction and triage.  It never
promotes findings, invents impact amounts, or rewrites raw evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

from .models import Finding
from .triage import is_report_ready
from .triage_model import TriageResult


PLATFORMS = ("default", "immunefi", "hackenproof", "yeswehack")
REQUIRED_REPORT_FIELDS = {
    "finding_id", "root_cause_id", "title", "severity", "priority", "confidence",
    "summary", "root_cause", "impact", "affected_assets", "affected_users",
    "prerequisites", "attack_steps", "evidence", "source", "remediation",
    "scope_status", "policy",
}


@dataclass
class ReportFinding:
    finding_id: str
    root_cause_id: str
    title: str
    severity: str
    priority: str
    confidence: str
    summary: str
    root_cause: str
    impact: dict[str, Any]
    affected_assets: list[str]
    affected_users: list[str]
    prerequisites: dict[str, Any]
    attack_steps: list[str]
    evidence: list[str]
    corroborating_engines: list[str]
    duplicate_status: str
    duplicate_notice: str
    poc_artifacts: list[str]
    raw_artifact_references: list[str]
    source: dict[str, Any]
    remediation: str
    scope_status: str
    policy: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _finding_map(findings: Iterable[Finding]) -> dict[str, Finding]:
    return {f.finding_id: f for f in findings}


def _source(f: Finding | None) -> dict[str, Any]:
    if f is None:
        return {}
    loc = f.source_location
    return {
        "file": loc.file,
        "line_start": loc.line_start,
        "line_end": loc.line_end,
        "contract": loc.contract,
        "function": loc.function,
    }


def _steps(f: Finding | None) -> list[str]:
    if f is None:
        return []
    return [*f.trace] if f.trace else ([f.test_sequence] if f.test_sequence else [])


def _root_cause(f: Finding | None, t: TriageResult) -> str:
    if f is None:
        return "Root cause evidence is unavailable in this run."
    parts = [f.description.strip(), f"Vulnerability class: {f.vulnerability_class}".strip()]
    if f.source_location.function:
        parts.append(f"Affected function: {f.source_location.function}")
    return " ".join(p for p in parts if p)


def build_report_finding(
    finding: Finding,
    triage: TriageResult,
    *,
    policy: str = "default",
) -> ReportFinding:
    """Convert one already-gated triage result to a report schema."""
    return ReportFinding(
        finding_id=triage.finding_id,
        root_cause_id=triage.root_cause_id,
        title=finding.title or "Verified security finding",
        severity=triage.severity,
        priority=triage.priority,
        confidence=triage.confidence,
        summary=finding.description or finding.title,
        root_cause=_root_cause(finding, triage),
        impact=triage.impact.to_dict() if hasattr(triage.impact, "to_dict") else asdict(triage.impact),
        affected_assets=list(triage.affected_assets or triage.impact.affected_assets),
        affected_users=list(triage.affected_users),
        prerequisites=asdict(triage.attacker_prerequisites),
        attack_steps=_steps(finding),
        evidence=[*finding.evidence, *finding.trace],
        corroborating_engines=list(finding.corroborating_engines),
        duplicate_status=triage.duplicate_status,
        duplicate_notice=(
            "Evidence from multiple engines was merged under the same root cause; impact is counted once."
            if triage.duplicate_status == "merged" else ""
        ),
        poc_artifacts=[a for a in getattr(triage, "verification_artifacts", []) if a],
        raw_artifact_references=[finding.raw_artifact_reference] if finding.raw_artifact_reference else [],
        source=_source(finding),
        remediation="Restrict the affected state-changing operation to the intended authorization boundary and add a regression test.",
        scope_status=triage.scope_status,
        policy=policy,
    )


def generate_reports(
    findings: list[Finding],
    triage_results: list[TriageResult],
    output_dir: str | Path,
    *,
    policy: str = "default",
    platform: str = "default",
) -> list[ReportFinding]:
    """Write report JSON and Markdown for strictly report-ready findings."""
    if platform not in PLATFORMS:
        raise ValueError(f"unsupported report platform: {platform}")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    fmap = _finding_map(findings)
    reports = [
        build_report_finding(fmap[t.finding_id], t, policy=policy)
        for t in triage_results
        if is_report_ready(t) and t.finding_id in fmap
    ]
    verification_root = out / "verification"
    for report in reports:
        finding_dir = verification_root / report.finding_id
        if finding_dir.is_dir():
            report.poc_artifacts = [str(p) for p in sorted(finding_dir.iterdir()) if p.is_file()]
    payload = {"schema_version": "aletheia.report.v1", "platform": platform, "policy": policy,
               "count": len(reports), "findings": [r.to_dict() for r in reports]}
    validate_report_payload(payload)
    (out / "report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out / f"{platform}.md").write_text(render_markdown(reports, platform=platform), encoding="utf-8")
    return reports


def validate_report_payload(payload: dict[str, Any]) -> None:
    """Reject malformed or unsafe report payloads before writing them."""
    if payload.get("schema_version") != "aletheia.report.v1":
        raise ValueError("unsupported report schema")
    if payload.get("platform") not in PLATFORMS:
        raise ValueError("unsupported report platform")
    findings = payload.get("findings")
    if not isinstance(findings, list) or payload.get("count") != len(findings):
        raise ValueError("report count does not match findings")
    for item in findings:
        missing = REQUIRED_REPORT_FIELDS - set(item)
        if missing:
            raise ValueError(f"report finding missing fields: {sorted(missing)}")
        if item["severity"] == "unknown" or item["confidence"] not in {"medium", "high"}:
            raise ValueError("unsafe finding passed report serialization gate")
        if item["scope_status"] != "in-scope":
            raise ValueError("out-of-scope finding passed report serialization gate")


def render_markdown(reports: list[ReportFinding], *, platform: str = "default") -> str:
    lines = [f"# AletheiaAI Security Report ({platform})", ""]
    if not reports:
        return "\n".join(lines + ["No report-ready findings.", ""])
    for i, r in enumerate(reports, 1):
        lines += [f"## {i}. {r.title}", "", f"- Severity: `{r.severity}`", f"- Priority: `{r.priority}`",
                  f"- Confidence: `{r.confidence}`", f"- Finding ID: `{r.finding_id}`", "",
                  "### Summary", "", r.summary or "No summary provided.", "",
                  "### Root Cause", "", r.root_cause, "",
                  "### Impact", "", json.dumps(r.impact, indent=2), "",
                  "### Attacker Prerequisites", "", json.dumps(r.prerequisites, indent=2), "",
                  "### Attack Steps", ""]
        lines += [f"{n}. {step}" for n, step in enumerate(r.attack_steps, 1)] or ["No attack sequence recorded."]
        evidence_lines = [f"- {e}" for e in r.evidence] or ["- No additional evidence recorded."]
        lines += ["", "### Evidence", "", *evidence_lines,
                  "", "### Source", "", f"`{r.source.get('file', '')}:{r.source.get('line_start', '')}`",
                  "", "### Remediation", "", r.remediation, ""]
    return "\n".join(lines)
