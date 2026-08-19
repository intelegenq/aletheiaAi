"""AletheiaAI unified finding model."""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class SourceLocation:
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    contract: Optional[str] = None
    function: Optional[str] = None


@dataclass
class Finding:
    # identity
    finding_id: str = ""
    fingerprint: str = ""

    # classification
    engine: str = ""           # slither, semgrep, mythril, medusa, echidna, foundry
    detector: str = ""          # rule name / check name
    title: str = ""
    description: str = ""
    vulnerability_class: str = ""

    # severity & confidence
    severity: str = "unknown"   # critical, high, medium, low, informational
    confidence: str = "unknown" # high, medium, low

    # status
    status: str = "candidate"   # candidate, needs-verification, verified, false-positive

    # location
    source_location: SourceLocation = field(default_factory=SourceLocation)

    # evidence & trace
    evidence: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    test_sequence: Optional[str] = None  # failing test / invariant / tx

    # exploitability
    exploitability_metadata: dict[str, Any] = field(default_factory=dict)

    # scope
    scope_status: str = "unknown"  # in-scope, out-of-scope, unknown

    # provenance
    raw_artifact_reference: str = ""
    corroborating_engines: list[str] = field(default_factory=list)

    # cross-engine dedup
    dedup_key: str = ""

    # v2 non-EVM context. Empty defaults preserve every legacy EVM artifact.
    chain_family: str = "evm"
    ecosystem: str = "evm"
    language: str = "solidity"
    runtime: str = ""
    rule_id: str = ""
    universal_taxonomy_id: str = ""
    chain_pattern_id: str = ""
    semantic_evidence: list[dict[str, Any]] = field(default_factory=list)
    trust_boundary: str = ""
    attacker_control: str = "unknown"
    asset_model: str = ""
    cross_chain_context: dict[str, Any] = field(default_factory=dict)
    verification_status: str = "candidate"
    verification_requirements: list[str] = field(default_factory=list)
    false_positive_conditions: list[str] = field(default_factory=list)
    reproduction_status: str = "not-attempted"

    def __post_init__(self):
        if not self.finding_id:
            raw = json.dumps({
                "chain": self.chain_family, "ecosystem": self.ecosystem,
                "engine": self.engine,
                "detector": self.detector,
                "file": self.source_location.file,
                "contract": self.source_location.contract,
                "function": self.source_location.function,
                "line_start": self.source_location.line_start,
                "description": self.description[:200],
            }, sort_keys=True)
            self.finding_id = "al-" + hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.fingerprint:
            self.fingerprint = self.finding_id
        if not self.dedup_key:
            key = {
                "chain": self.chain_family, "ecosystem": self.ecosystem,
                "detector": self.detector,
                "file": self.source_location.file,
                "contract": self.source_location.contract,
                "function": self.source_location.function,
            }
            key["semantic_sink"] = self.chain_pattern_id
            key["cross_chain_route"] = self.cross_chain_context.get("route", "")
            # Dynamic engines (foundry/medusa/echidna) often have no source
            # location — the failing test/property name is the identity.
            if not self.source_location.file:
                key["title"] = self.title
            self.dedup_key = json.dumps(key, sort_keys=True)


def to_dict(f: Finding) -> dict:
    d = asdict(f)
    return d


def from_slither_normalized(n: dict, engine: str = "slither") -> Finding:
    """Convert agent_adapter normalized dict to Finding."""
    loc = n.get("location") or {}
    return Finding(
        finding_id=n.get("finding_id", ""),
        engine=engine,
        detector=n.get("detector", "slither:unknown"),
        title=n.get("title", ""),
        description=n.get("description", ""),
        vulnerability_class=n.get("pattern_id", n.get("taxonomy_id", "")),
        severity=n.get("severity", "unknown").lower(),
        confidence=n.get("confidence", "medium").lower(),
        status="candidate",
        source_location=SourceLocation(
            file=loc.get("file", ""),
            line_start=loc.get("line_start", 0),
            line_end=loc.get("line_end", 0),
            contract=loc.get("contract"),
            function=loc.get("function"),
        ),
        evidence=n.get("evidence", []),
        raw_artifact_reference=n.get("finding_id", ""),
    )


def from_unified_dict(d: dict) -> Finding:
    """Convert unified output dict back to Finding."""
    loc = d.get("location") or {}
    return Finding(
        finding_id=d.get("finding_id", ""),
        engine=d.get("tool", "unknown"),
        detector=d.get("rule_id", ""),
        title=d.get("title", ""),
        description=d.get("message", ""),
        vulnerability_class=d.get("category", d.get("rule_id", "")),
        severity=d.get("severity", "unknown").lower(),
        confidence=d.get("confidence", "unknown").lower(),
        status=d.get("verification_status", "candidate"),
        source_location=SourceLocation(
            file=loc.get("file", ""),
            line_start=loc.get("line_start", 0),
            line_end=loc.get("line_end", 0),
            contract=loc.get("contract"),
            function=loc.get("function"),
        ),
        evidence=d.get("evidence", []),
        raw_artifact_reference=d.get("finding_id", ""),
        corroborating_engines=d.get("corroborating_engines", []),
        chain_family=d.get("chain_family", "evm"), ecosystem=d.get("ecosystem", "evm"),
        language=d.get("language", "solidity"), runtime=d.get("runtime", ""),
        rule_id=d.get("rule_id", d.get("detector", "")),
        universal_taxonomy_id=d.get("universal_taxonomy_id", ""),
        chain_pattern_id=d.get("chain_pattern_id", ""),
        semantic_evidence=d.get("semantic_evidence", []), trust_boundary=d.get("trust_boundary", ""),
        attacker_control=d.get("attacker_control", "unknown"), asset_model=d.get("asset_model", ""),
        cross_chain_context=d.get("cross_chain_context", {}),
        verification_status=d.get("verification_status", d.get("status", "candidate")),
        verification_requirements=d.get("verification_requirements", []),
        false_positive_conditions=d.get("false_positive_conditions", []),
        reproduction_status=d.get("reproduction_status", "not-attempted"),
    )


def to_aletheia_unified(findings: list[Finding]) -> dict:
    """Serialize findings to AletheiaAI unified format."""
    items = []
    for f in findings:
        items.append(to_dict(f))
    return {
        "schema_version": "aletheia.unified-finding.v2",
        "count": len(items),
        "findings": items,
    }


def to_sarif(findings: list[Finding]) -> dict:
    """Serialize findings to SARIF 2.1."""
    results = []
    rules = {}
    for f in findings:
        rid = f.detector
        rules.setdefault(rid, {
            "id": rid,
            "name": f.title or rid,
            "shortDescription": {"text": f.title or rid},
            "help": {"text": f.description[:500]},
        })
        result = {
            "ruleId": rid,
            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f.severity, "warning"),
            "message": {"text": f.description[:500]},
            "fingerprints": {"aletheiaFindingId": f.finding_id},
            "properties": {
                "engine": f.engine,
                "confidence": f.confidence,
                "status": f.status,
                "scope_status": f.scope_status,
                "vulnerability_class": f.vulnerability_class,
                "chain_family": f.chain_family, "ecosystem": f.ecosystem,
                "verification_status": f.verification_status,
                "corroborating_engines": f.corroborating_engines,
            },
        }
        if f.source_location.file:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.source_location.file},
                    "region": {
                        "startLine": f.source_location.line_start or 1,
                        "endLine": f.source_location.line_end or (f.source_location.line_start or 1),
                    },
                }
            }]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AletheiaAI", "rules": list(rules.values())}},
            "results": results,
        }],
    }
