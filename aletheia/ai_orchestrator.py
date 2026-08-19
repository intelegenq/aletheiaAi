"""AI orchestration layer for evidence-first audit planning.

The planner is provider-neutral and deterministic by default. It can later be
backed by an LLM, but model suggestions remain hypotheses until scanner,
analysis, and verification evidence supports them.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .intake import BuildContext, intake
from .knowledge import KnowledgeBase
from .spec_compiler import compile_catalog, compile_selected
from .models import Finding


@dataclass
class ProjectContext:
    root: str
    build_system: str
    language: str
    solc_version: str
    contracts: list[str]
    test_files: list[str]
    source_signals: list[str] = field(default_factory=list)
    protocol_signals: dict[str, list[str]] = field(default_factory=dict)
    source_hash: str = ""
    chain: str = "unknown"
    chain_confidence: str = "low"


@dataclass
class ProtocolClassification:
    category: str
    confidence: str
    signals: list[str]
    alternatives: list[str] = field(default_factory=list)


@dataclass
class VulnerabilityHypothesis:
    hypothesis_id: str
    vulnerability_class: str
    title: str
    rationale: str
    signals: list[str]
    recommended_engines: list[str]
    priority: str = "normal"
    status: str = "candidate"


@dataclass
class VerificationPlan:
    finding_id: str
    actions: list[str]
    required_evidence: list[str]
    blockers: list[str] = field(default_factory=list)


@dataclass
class ScannerPlan:
    engines: list[str]
    rationale: dict[str, str]
    skipped: dict[str, str] = field(default_factory=dict)


@dataclass
class AIExecutionPlan:
    schema_version: str = "aletheia.ai-plan.v1"
    target: str = ""
    context: ProjectContext | None = None
    classifications: list[ProtocolClassification] = field(default_factory=list)
    hypotheses: list[VulnerabilityHypothesis] = field(default_factory=list)
    scanner_plan: ScannerPlan | None = None
    verification_plans: list[VerificationPlan] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    kb: dict[str, Any] = field(default_factory=dict)
    spec_selections: list[dict[str, Any]] = field(default_factory=list)
    spec_execution_plan: list[dict[str, Any]] = field(default_factory=list)
    spec_catalog: dict[str, Any] = field(default_factory=dict)
    planner: str = "deterministic-evidence-first"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _hash_sources(ctx: BuildContext) -> str:
    digest = hashlib.sha256()
    source_files = getattr(ctx, "sol_files", []) or getattr(ctx, "contracts", [])
    for path in sorted(source_files):
        try:
            digest.update(str(path.relative_to(ctx.root)).encode())
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()


def build_project_context(ctx: BuildContext) -> ProjectContext:
    """Create a compact, reproducible context; source is never sent anywhere."""
    signals: set[str] = set()
    protocol_signals: dict[str, list[str]] = {}
    text_parts: list[str] = []
    for path in ctx.contracts:
        try:
            text_parts.append(path.read_text(encoding="utf-8", errors="ignore")[:200_000])
        except OSError:
            continue
    corpus = "\n".join(text_parts).lower()
    terms = {
        "lending": ["borrow", "liquidat", "collateral", "interest", "healthfactor"],
        "dex": ["swap", "addliquidity", "removeliquidity", "router", "pair"],
        "bridge": ["bridge", "crosschain", "message", "relay", "mintwrapped"],
        "oracle": ["oracle", "pricefeed", "latestanswer", "twap", " Chainlink".lower()],
        "governance": ["proposal", "quorum", "vote", "timelock", "delegate"],
        "token": ["erc20", "erc721", "erc1155", "transferfrom", "balanceof"],
        "upgradeable": ["proxy", "delegatecall", "upgradeTo".lower(), "implementation"],
    }
    for category, needles in terms.items():
        hits = [needle for needle in needles if needle in corpus]
        if hits:
            signals.add(category)
            protocol_signals[category] = hits
    return ProjectContext(
        root=str(ctx.root),
        build_system="foundry" if ctx.foundry else "solidity",
        language=ctx.chain.language if getattr(ctx, "chain", None) else "solidity",
        solc_version=ctx.solc_version,
        contracts=[str(p.relative_to(ctx.root)) for p in ctx.contracts],
        test_files=[str(p.relative_to(ctx.root)) for p in ctx.test_files],
        source_signals=sorted(signals),
        protocol_signals=protocol_signals,
        source_hash=_hash_sources(ctx),
        chain=ctx.chain.primary if getattr(ctx, "chain", None) else "evm",
        chain_confidence=ctx.chain.confidence if getattr(ctx, "chain", None) else "high",
    )


def classify_project(context: ProjectContext) -> list[ProtocolClassification]:
    categories = context.source_signals
    if not categories:
        return [ProtocolClassification("generic-evm", "low", [], ["token", "governance"])]
    ranked = sorted(categories, key=lambda c: len(context.protocol_signals.get(c, [])), reverse=True)
    result = []
    for category in ranked[:4]:
        count = len(context.protocol_signals.get(category, []))
        confidence = "high" if count >= 3 else "medium"
        alternatives = [c for c in ranked if c != category][:2]
        result.append(ProtocolClassification(category, confidence, context.protocol_signals[category], alternatives))
    return result


PACKS: dict[str, list[tuple[str, str, list[str]]]] = {
    "generic-evm": [
        ("access-control", "Check state-changing external functions for effective authorization.", ["slither", "foundry"]),
        ("reentrancy", "Check external calls and state updates for reentrant paths.", ["slither", "foundry", "medusa"]),
        ("arithmetic-accounting", "Check arithmetic, accounting invariants, and token value conservation.", ["slither", "foundry"]),
    ],
    "lending": [
        ("oracle-manipulation", "Lending signals require price freshness, decimals, and trusted update analysis.", ["slither", "foundry", "medusa"]),
        ("liquidation-accounting", "Check collateral, debt, liquidation threshold, and bad-debt invariants.", ["slither", "foundry", "medusa", "echidna"]),
        ("access-control", "Check privileged risk-parameter and reserve mutations.", ["slither", "foundry"]),
    ],
    "dex": [
        ("price-manipulation", "AMM and swap paths require slippage, reserve, and oracle consistency checks.", ["slither", "foundry", "medusa"]),
        ("reentrancy", "Liquidity and callback paths require reentrancy analysis.", ["slither", "foundry", "medusa"]),
        ("arithmetic-accounting", "Check share, reserve, fee, and invariant arithmetic.", ["slither", "foundry", "echidna"]),
    ],
    "bridge": [
        ("message-authentication", "Cross-chain message execution requires origin, replay, and signer validation.", ["slither", "foundry", "medusa"]),
        ("access-control", "Check mint, unlock, and configuration authorization.", ["slither", "foundry"]),
        ("replay-protection", "Check nonce, domain, and message uniqueness invariants.", ["slither", "foundry", "echidna"]),
    ],
    "oracle": [
        ("oracle-manipulation", "Check source trust, freshness, decimals, and fallback behavior.", ["slither", "foundry", "medusa"]),
    ],
    "governance": [
        ("governance-takeover", "Check voting power, quorum, delegation, and execution delay.", ["slither", "foundry", "echidna"]),
        ("access-control", "Check proposal and timelock administrative boundaries.", ["slither", "foundry"]),
    ],
    "token": [
        ("token-accounting", "Check transfer, allowance, mint, burn, and balance conservation.", ["slither", "foundry", "echidna"]),
        ("access-control", "Check mint, burn, pause, and role management.", ["slither", "foundry"]),
    ],
    "upgradeable": [
        ("upgrade-control", "Check implementation, initializer, proxy, and upgrade authorization.", ["slither", "foundry"]),
    ],
}


def build_hypotheses(classifications: Iterable[ProtocolClassification]) -> list[VulnerabilityHypothesis]:
    hypotheses: list[VulnerabilityHypothesis] = []
    seen: set[str] = set()
    for classification in classifications:
        for vuln_class, rationale, engines in PACKS.get(classification.category, PACKS["generic-evm"]):
            if vuln_class in seen:
                continue
            seen.add(vuln_class)
            raw = f"{classification.category}:{vuln_class}"
            hypotheses.append(VulnerabilityHypothesis(
                hypothesis_id="hyp-" + hashlib.sha256(raw.encode()).hexdigest()[:12],
                vulnerability_class=vuln_class,
                title=f"Investigate {vuln_class.replace('-', ' ')}",
                rationale=rationale,
                signals=classification.signals,
                recommended_engines=engines,
                priority="high" if classification.confidence == "high" else "normal",
            ))
    return hypotheses


def build_scanner_plan(hypotheses: Iterable[VulnerabilityHypothesis], available: Iterable[str]) -> ScannerPlan:
    available_set = set(available)
    rationale: dict[str, str] = {}
    requested = {engine for h in hypotheses for engine in h.recommended_engines}
    requested.update({"slither"})
    engines = sorted(requested & available_set)
    skipped = {engine: "not available in adapter registry" for engine in sorted(requested - available_set)}
    for engine in engines:
        matched = [h.vulnerability_class for h in hypotheses if engine in h.recommended_engines]
        rationale[engine] = "Selected for hypotheses: " + ", ".join(matched)
    return ScannerPlan(engines=engines, rationale=rationale, skipped=skipped)


def build_verification_plan(finding: Finding) -> VerificationPlan:
    actions = ["resolve source function", "confirm access-control verdict", "confirm call-path reachability"]
    required = ["source location", "analysis evidence", "reproducible or corroborating evidence"]
    if finding.engine in {"foundry", "medusa", "echidna"}:
        actions.append("preserve dynamic trace and reproduce locally")
    if finding.vulnerability_class in {"reentrancy", "price-manipulation", "oracle-manipulation"}:
        actions.append("check state/invariant preconditions")
    return VerificationPlan(finding_id=finding.finding_id, actions=actions, required_evidence=required)


def create_plan(target: str, *, available_engines: Iterable[str], context: BuildContext | None = None,
                knowledge_base: KnowledgeBase | None = None) -> AIExecutionPlan:
    ctx = context or intake(target, with_build=False)
    project = build_project_context(ctx)
    classifications = classify_project(project)
    hypotheses = build_hypotheses(classifications)
    scanner_plan = build_scanner_plan(hypotheses, available_engines)
    limitations = []
    if not project.source_signals:
        limitations.append("Protocol category is uncertain; generic EVM pack selected")
    if not project.solc_version:
        limitations.append("Solidity compiler version could not be detected")
    kb = knowledge_base or KnowledgeBase()
    spec_selections = [spec.to_dict() for spec in kb.select_specs(
        [c.category for c in classifications]
    )] if kb.status.available else []
    compiled_catalog = compile_catalog(kb, available_engines=available_engines) if kb.status.available else []
    compiled_selected = compile_selected(
        kb, [c.category for c in classifications], available_engines=available_engines
    ) if kb.status.available else []
    if kb.status.available:
        limitations.extend(kb.status.limitations)
        if not kb.status.universal_specs_available:
            limitations.append("Universal spec catalog is not present; routing uses implemented detector specs only")
    else:
        limitations.append("Knowledge base unavailable; built-in hypotheses remain authoritative")
    return AIExecutionPlan(
        target=str(ctx.root), context=project, classifications=classifications,
        hypotheses=hypotheses, scanner_plan=scanner_plan,
        assumptions=["Hypotheses are candidates, not security verdicts", "Static signals require verification"],
        limitations=limitations, kb=kb.summary(), spec_selections=spec_selections,
        spec_execution_plan=[item.to_dict() for item in compiled_selected],
        spec_catalog={
            "count": len(compiled_catalog),
            "execution_modes": {
                mode: sum(item.execution_mode == mode for item in compiled_catalog)
                for mode in ("detector", "analysis_task", "manual_review")
            },
            "warnings": sum(len(item.warnings) for item in compiled_catalog),
        },
    )


def save_plan(plan: AIExecutionPlan, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(plan.to_dict(), indent=2), encoding="utf-8")
    return destination


def read_evidence(run_dir: str | Path) -> dict[str, Any]:
    """Read artifacts without changing verdicts or raw findings."""
    root = Path(run_dir)
    result: dict[str, Any] = {"findings": [], "conviction": [], "triage": [], "artifacts": []}
    for name, key in (("findings.json", "findings"), ("conviction.json", "conviction"), ("triage.json", "triage")):
        path = root / name
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                result[key] = payload
            elif isinstance(payload, dict):
                result[key] = payload.get("findings", payload.get("results", []))
            else:
                result[key] = []
    manifest = root / "artifact_manifest.json"
    if manifest.is_file():
        result["artifacts"] = json.loads(manifest.read_text(encoding="utf-8")).get("artifacts", [])
    return result


def resolve_contradictions(findings: list[Finding], conviction: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Report contradictions for human/LLM planning; never overwrite verdicts."""
    conviction = conviction or {}
    by_id = {item.get("finding_id"): item for item in conviction.get("results", [])} if isinstance(conviction, dict) else {}
    contradictions = []
    for finding in findings:
        cr = by_id.get(finding.finding_id, {})
        if finding.engine in {"foundry", "medusa", "echidna"} and cr.get("verdict") == "rejected":
            contradictions.append({"finding_id": finding.finding_id, "kind": "dynamic-rejected", "action": "manual-review", "reason": "dynamic evidence exists but conviction rejected it"})
        if cr.get("access_control_verdict") == "restricted" and cr.get("verdict") == "verified":
            contradictions.append({"finding_id": finding.finding_id, "kind": "guarded-verified", "action": "recheck-root-cause", "reason": "verified result conflicts with effective access-control guard"})
    return contradictions
