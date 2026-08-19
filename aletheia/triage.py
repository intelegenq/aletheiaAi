"""Triage Engine — converts conviction results into structured triage results.

Triage is a read-only layer: it adds attacker prerequisites, exploitability
scoring, asset impact classification, scope-aware priority, and severity
policy application. It never modifies raw findings.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .models import Finding
from .conviction import ConvictionResult, DYNAMIC_ENGINES
from .triage_model import (
    TriageResult, AttackerPrerequisites, ExploitabilityFactors,
    ExploitabilityScore, AssetImpact,
)
from .severity_policy import apply_policy, SEVERITY_RANK
from .rootcause import correlate


# ---------------- Scope helpers ----------------


def _init_scope(
    f: Finding,
    config: Optional[dict] = None,
    rc_contract: str = "",
    rc_function: str = "",
) -> tuple[str, str]:
    """Determine scope status from finding metadata + optional config.

    Config can define protocol-specific in-scope contracts and vulnerability classes.
    When no scope config is provided, scope is uncertain — it must NOT default
    to in-scope (a safety-critical finding could slip into report-ready without
    program confirmation).

    `rc_contract` / `rc_function` come from the resolved root cause and are used
    when the finding itself has no source pointer (dynamic engines).
    """
    if f.scope_status == "in-scope":
        return "in-scope", "Finding metadata marks as in-scope"
    if f.scope_status == "out-of-scope":
        return "out-of-scope", "Finding metadata marks as out-of-scope"

    scope_config = (config or {}).get("scope", {})
    allow_contracts = scope_config.get("contracts", [])
    allow_classes = scope_config.get("vulnerability_classes", [])
    allow_functions = scope_config.get("functions", [])
    exclude_contracts = scope_config.get("exclude_contracts", [])
    exclude_functions = scope_config.get("exclude_functions", [])

    if allow_contracts or allow_classes or allow_functions or exclude_contracts or exclude_functions:
        # Prefer the finding's own pointer; fall back to the resolved root cause
        # (dynamic engines carry no source location of their own).
        contract = f.source_location.contract or rc_contract or ""
        func = (f.source_location.function or rc_function or "").split("(")[0]
        # Root-cause functions are canonical ("Contract.func(args)") — strip the prefix.
        if "." in func:
            func = func.rsplit(".", 1)[-1]
        vclass = f.vulnerability_class or ""

        # Explicit exclusions first → out-of-scope.
        if exclude_contracts and contract in exclude_contracts:
            return "out-of-scope", f"Contract '{contract}' excluded by scope configuration"
        if exclude_functions and func in exclude_functions:
            return "out-of-scope", f"Function '{func}' excluded by scope configuration"

        reasons = []
        in_scope = True
        if allow_contracts and contract not in allow_contracts:
            reasons.append(f"contract '{contract}' not in scope list")
            in_scope = False
        if allow_functions and func and func not in allow_functions:
            reasons.append(f"function '{func}' not in scope list")
            in_scope = False
        if allow_classes and vclass and vclass not in allow_classes:
            reasons.append(f"class '{vclass}' not in scope list")
            in_scope = False
        if in_scope:
            return "in-scope", "Contract and vulnerability class match configured target scope"
        return "uncertain", "; ".join(reasons)

    return "uncertain", "No program scope configuration was provided"


# ---------------- Attacker prerequisites ----------------


def _analyze_prerequisites(f: Finding, cr: ConvictionResult) -> AttackerPrerequisites:
    """Determine attacker prerequisites from conviction evidence.

    Tri-state booleans: True / False / "unknown". A finding whose access-control
    or reachability could not be determined gets "unknown" for every prerequisite,
    never a silent False (which would be misread as "safe").
    """
    ap = AttackerPrerequisites()
    ac = cr.access_control_verdict
    cp = cr.call_path_verdict
    expl = cr.exploitability or {}
    has_dynamic = bool(cr.evidence_summary.get("has_dynamic_evidence"))
    engine = f.engine

    # --- permissionless + privileged role: derive only from confirmed AC ---
    if ac == "ungated":
        ap.permissionless = True
        ap.requires_privileged_role = False
    elif ac == "restricted":
        ap.permissionless = False
        ap.requires_privileged_role = True
        ap.privileged_role = (
            cr.analysis.get("access_control", {}).get("modifier_name", "").replace("only", "")
            or "owner"
        )
    elif ac == "partially-restricted":
        # Guard present but not proven effective — privilege requirement unclear.
        ap.permissionless = "unknown"
        ap.requires_privileged_role = "unknown"
        ap.unknown.append("access-control")
    else:  # ac == "unknown"
        ap.permissionless = "unknown"
        ap.requires_privileged_role = "unknown"
        ap.unknown.append("access-control")

    # --- reachability ---
    if cp == "unknown":
        ap.unknown.append("reachability")
    elif cp == "unreachable":
        # Proven unreachable: not permissionless regardless of AC.
        ap.permissionless = False
        ap.unknown.append("reachability")

    # --- multiple transactions ---
    if has_dynamic and f.trace:
        # A multi-step trace is evidence of multiple transactions; a single
        # step does not prove it is single-tx for dynamic fuzz sequences.
        ap.requires_multiple_transactions = len(f.trace) > 1
    else:
        ap.requires_multiple_transactions = "unknown"

    # --- special state ---
    # Only a failed dynamic reproduction gives evidence either way; without
    # that we cannot know if a special state is required.
    if has_dynamic and isinstance(expl.get("requires_special_state"), bool):
        ap.requires_special_state = expl.get("requires_special_state")
    else:
        ap.requires_special_state = "unknown"

    # --- flash loan / external dependency / market condition ---
    # Not detectable with current analysis — stay unknown.
    ap.requires_flash_loan = "unknown"
    ap.requires_external_dependency = "unknown"
    ap.requires_market_condition = "unknown"
    ap.requires_compromised_key = "unknown"

    # --- capital requirement ---
    if ap.permissionless is True:
        ap.capital_required = "none"
    else:
        ap.capital_required = "unknown"

    return ap


# ---------------- Exploitability scoring ----------------


def _score_exploitability(cr: ConvictionResult) -> ExploitabilityScore:
    """Deterministic exploitability score from conviction evidence.

    Factors (each 0.0-1.0). Unknown evidence is scored 0.0 AND recorded in
    `missing_information`: the score is NOT secretly a "safe" verdict, and the
    label becomes `insufficient-evidence` when key factors are unknown.
    """
    cp = cr.call_path_verdict
    ac = cr.access_control_verdict
    has_dynamic = bool(cr.evidence_summary.get("has_dynamic_evidence"))
    expl = cr.exploitability or {}

    fac = ExploitabilityFactors()
    missing: list[str] = []

    # Reachable
    if cp == "reachable":
        fac.reachable = 1.0
    elif cp == "restricted-reachable":
        fac.reachable = 0.8
    elif cp == "unreachable":
        fac.reachable = 0.0
    else:  # unknown
        fac.reachable = 0.0
        missing.append("reachability")

    # Reproducible
    if has_dynamic and expl.get("reproducible") is True:
        fac.reproducible = 1.0
    elif has_dynamic:
        fac.reproducible = 0.75
    else:
        fac.reproducible = 0.0
        missing.append("reproducibility")

    # Permissionless
    if ac == "ungated":
        fac.permissionless = 1.0
    elif ac == "restricted":
        fac.permissionless = 0.0
    elif ac == "partially-restricted":
        fac.permissionless = 0.3
    else:  # unknown
        fac.permissionless = 0.0
        missing.append("permissionless")

    # Special state
    req_state = expl.get("requires_special_state")
    if req_state is False:
        fac.special_state_required = 1.0
    elif req_state is True:
        fac.special_state_required = 0.0
    else:  # unknown
        fac.special_state_required = 0.0
        missing.append("special_state")

    # Dynamic corroboration
    if has_dynamic:
        fac.dynamic_corroboration = 1.0
    else:
        fac.dynamic_corroboration = 0.0

    # Weighted: reachable(0.25) + reproducible(0.20) + permissionless(0.25)
    # + state(0.10) + dynamic(0.20)
    score = (
        fac.reachable * 0.25
        + fac.reproducible * 0.20
        + fac.permissionless * 0.25
        + fac.special_state_required * 0.10
        + fac.dynamic_corroboration * 0.20
    )
    score = round(min(score, 1.0), 2)

    # Label. Unknown key factors must never masquerade as "not-exploitable".
    if "reachability" in missing or "permissionless" in missing:
        label = "insufficient-evidence"
    elif score >= 0.90:
        label = "directly-reproducible"
    elif score >= 0.75:
        label = "reproducible"
    elif score >= 0.50:
        label = "plausible"
    elif score >= 0.20:
        label = "theoretical"
    else:
        label = "not-exploitable"

    return ExploitabilityScore(
        score=score,
        label=label,
        factors=fac,
        missing_information=missing,
    )


# ---------------- Asset impact ----------------


def _assess_impact(cr: ConvictionResult, rc: Any) -> AssetImpact:
    """Classify asset impact from conviction evidence.

    Never fabricates quantified amounts. Uses potential/unknown conservatively.
    """
    imp = AssetImpact()
    expl = cr.exploitability or {}
    state_vars = rc.state_variables if hasattr(rc, "state_variables") else []

    # Determine affected assets from state variables
    assets = []
    for var in state_vars:
        var_lower = var.lower()
        if "owner" in var_lower:
            assets.append("admin/ownership state")
            imp.privilege_takeover = True
        elif "balance" in var_lower or "amount" in var_lower:
            assets.append("ERC20/token balance")
            imp.direct_funds_loss = "potential"
        elif "supply" in var_lower or "total" in var_lower:
            assets.append("shares")
        elif "config" in var_lower or "param" in var_lower or "fee" in var_lower:
            assets.append("protocol configuration")
        elif "debt" in var_lower or "account" in var_lower:
            assets.append("debt/accounting units")
        elif "paused" in var_lower or "lock" in var_lower:
            assets.append("availability/service")
            imp.availability_impact = True
        else:
            assets.append("admin/ownership state")
    if not assets:
        assets.append("unknown")

    imp.affected_assets = assets

    # Impact classification
    ac = cr.access_control_verdict
    cp = cr.call_path_verdict
    has_dynamic = bool(cr.evidence_summary.get("has_dynamic_evidence"))

    if ac == "ungated" and cp == "reachable" and has_dynamic:
        imp.state_corruption = True
        if "admin/ownership state" in assets:
            imp.privilege_takeover = True
        imp.permanent_loss = True
        imp.impact = "potential"
    elif ac == "restricted":
        imp.impact = "none"
        imp.direct_funds_loss = "none"
    elif ac == "unknown" or cp == "unknown":
        imp.impact = "unknown"
    else:
        imp.impact = "potential"

    # direct_funds_loss: only "potential" or "unknown" — never "quantified" without evidence
    if imp.direct_funds_loss == "unknown":
        if "balance" in str(assets) or "user funds" in str(assets):
            imp.direct_funds_loss = "potential"

    return imp


# ---------------- Priority ----------------


def _assign_priority(t: TriageResult) -> TriageResult:
    """Assign triage priority separate from severity.

    Considers severity, exploitability, scope, confidence, and impact.
    Returns the modified TriageResult (not the priority string).

    Unknown / incomplete findings get `needs-review`, NOT p4-informational.
    p4-informational is reserved for findings proven to have NO security impact.
    """
    sev = t.severity
    ex = t.exploitability.score
    scope = t.scope_status
    conf = t.confidence
    imp = t.impact
    verdict = getattr(t, "_conviction_verdict", "")

    # Out-of-scope is a non-priority by policy.
    if scope == "out-of-scope":
        t.priority = "p4-informational"
        t.rationale.append("Out of scope — no priority")
        return t

    # Unknown / incomplete evidence → needs-review, never informational/lower.
    perm_unknown = (t.attacker_prerequisites.permissionless == "unknown")
    prereq_missing = (
        "access-control" in t.attacker_prerequisites.unknown
        or "reachability" in t.attacker_prerequisites.unknown
    )
    if (
        sev == "unknown"
        or verdict in ("needs-review", "needs-dynamic-validation")
        or conf == "unknown"
        or perm_unknown
        or prereq_missing
    ):
        t.priority = "needs-review"
        t.rationale.append("Needs review: evidence insufficient to rank")
        return t

    # Uncertainty in scope is a review blocker.
    if scope == "uncertain":
        t.priority = "needs-review"
        t.rationale.append("Scope uncertain — requires manual scope confirmation")
        return t

    # P0: verified + permissionless + reproducible + direct asset loss
    if (
        sev in ("critical", "high")
        and ex >= 0.75
        and t.attacker_prerequisites.permissionless is True
        and imp.direct_funds_loss in ("potential", "quantified")
        and conf in ("high", "medium")
    ):
        t.priority = "p0-critical"
        t.rationale.append("P0: Permissionless exploit with direct asset loss potential")
    # P1: high severity, reproducible, serious impact
    elif sev in ("critical", "high") and ex >= 0.50 and conf in ("high", "medium"):
        t.priority = "p1-high"
        t.rationale.append("P1: High severity with confirmed exploit path")
    # P2: medium severity, some exploitability
    elif sev in ("medium",) and ex >= 0.25:
        t.priority = "p2-medium"
        t.rationale.append("P2: Medium severity with partial exploitability")
    # P3: low impact or hard prerequisites
    elif sev in ("low",):
        t.priority = "p3-low"
        t.rationale.append("P3: Low impact or difficult prerequisites")
    # P4: informational — ONLY for findings with no security impact
    elif sev == "informational":
        t.priority = "p4-informational"
        t.rationale.append("P4: No direct security impact")
    # Fallback for anything not matched above
    else:
        t.priority = "needs-review"
        t.rationale.append("Evidence insufficient to assign priority")

    return t


# ---------------- Main triage pipeline ----------------


def run_triage(
    findings: list[Finding],
    conviction_results: dict[str, ConvictionResult],
    root_cause_map: dict[str, dict],
    config: Optional[dict] = None,
    policy_name: str = "default",
    verbose: bool = True,
) -> list[TriageResult]:
    """Run the full triage pipeline on conviction results.

    Returns a list of TriageResults, one per root cause (findings sharing
    a root cause produce one triage result).
    """
    if verbose:
        print(f"[aletheia] triage: {len(conviction_results)} conviction results")

    # Group findings by root cause
    root_cause_findings: dict[str, list[Finding]] = {}
    for f in findings:
        rc_meta = f.exploitability_metadata or {}
        rid = rc_meta.get("root_cause_id", "")
        if rid:
            root_cause_findings.setdefault(rid, []).append(f)
        else:
            root_cause_findings.setdefault("", []).append(f)

    # Build root cause info lookup
    rc_info: dict[str, dict] = {}
    for rid, info in root_cause_map.items():
        rc_info[rid] = info

    results: list[TriageResult] = []
    rid_counter: dict[str, int] = {}

    for rid, group in root_cause_findings.items():
        if not group:
            continue

        # If multiple findings share a root cause, merge them into one triage result.
        # The primary finding is the most severe one.
        severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "unknown": 0}

        def _sort_key(f: Finding):
            cr = conviction_results.get(f.finding_id)
            return (severity_rank.get(cr.verdict == "verified" and cr.score or 0, 0))

        primary = max(group, key=lambda f: (conviction_results.get(f.finding_id).score if conviction_results.get(f.finding_id) else 0, len(f.trace or [])))
        cr = conviction_results.get(primary.finding_id)
        if cr is None:
            continue

        # Count engines contributing
        engines = []
        for g in group:
            for e in [g.engine, *(g.corroborating_engines or [])]:
                if e and e not in engines:
                    engines.append(e)

        # Root cause detail — needed for both scope matching and asset impact
        from .rootcause import build_root_cause, RootCause
        rc_info = root_cause_map.get(rid, {})
        if rc_info.get("state_variables") or rc_info.get("function"):
            root_cause = RootCause(
                root_cause_id=rid,
                contract=rc_info.get("contract", ""),
                function=rc_info.get("function", ""),
                state_variables=rc_info.get("state_variables", []),
            )
        else:
            root_cause = build_root_cause(primary, None)

        # Determine scope (falls back to the resolved root cause for dynamic engines)
        scope, scope_reason = _init_scope(
            primary, config,
            rc_contract=root_cause.contract,
            rc_function=root_cause.function,
        )

        # Attacker prerequisites
        ap = _analyze_prerequisites(primary, cr)

        # Exploitability score
        ex_score = _score_exploitability(cr)

        # Asset impact
        imp = _assess_impact(cr, root_cause)

        # Build TriageResult
        rc_meta = root_cause_map.get(rid, {})
        all_finding_ids = rc_meta.get("finding_ids", [g.finding_id for g in group])
        is_merged = len(group) > 1 or len(all_finding_ids) > 1
        merged_from = [fid for fid in all_finding_ids if fid != primary.finding_id]
        if not merged_from and len(group) > 1:
            merged_from = [g.finding_id for g in group if g.finding_id != primary.finding_id]

        t = TriageResult(
            finding_id=primary.finding_id,
            root_cause_id=rid,
            scope_status=scope,
            scope_reason=scope_reason,
            exploitability=ex_score,
            impact=imp,
            attacker_prerequisites=ap,
            affected_assets=imp.affected_assets,
            confidence=cr.confidence,
            duplicate_status="merged" if is_merged else "unique",
            evidence_merged_from=merged_from,
            rationale=[
                f"Root cause: {rid}",
                f"Engines: {', '.join(engines)} ({len(all_finding_ids)} evidence sources)",
                f"Conviction verdict: {cr.verdict} (score={cr.score})",
            ],
        )

        # Store conviction verdict for the policy engine
        t._conviction_verdict = cr.verdict

        # Apply severity policy
        t = apply_policy(t, policy_name)

        # Assign priority
        t = _assign_priority(t)

        # Record missing information (blockers for report-ready gate)
        missing = []
        if cr.access_control_verdict == "unknown":
            missing.append("access-control analysis")
        if cr.call_path_verdict == "unknown":
            missing.append("reachability analysis")
        if ap.unknown:
            missing.append(f"attacker prerequisites: {', '.join(ap.unknown)}")
        for factor in ex_score.missing_information:
            missing.append(f"exploitability factor: {factor}")
        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for m in missing:
            if m not in seen:
                seen.add(m)
                deduped.append(m)
        t.missing_information = deduped

        results.append(t)

    if verbose:
        counts = {}
        for t in results:
            counts[t.priority] = counts.get(t.priority, 0) + 1
        for p in sorted(counts):
            print(f"  {p}: {counts[p]}")
        print(f"  total triage results: {len(results)}")

    return results


# Missing-information entries that BLOCK report-ready. Factors like
# special_state / flash_loan are not currently derivable by any analysis, so
# their absence is expected and must not permanently block every finding.
BLOCKING_MISSING_INFO = (
    "access-control analysis",
    "reachability analysis",
    "exploitability factor: reachability",
    "exploitability factor: permissionless",
)


def missing_blockers(t: TriageResult) -> list[str]:
    """Return only the missing-information entries that block report-ready."""
    blockers = []
    for m in t.missing_information:
        if m in BLOCKING_MISSING_INFO:
            blockers.append(m)
        elif m.startswith("attacker prerequisites:") and (
            "access-control" in m or "reachability" in m
        ):
            blockers.append(m)
    return blockers


def is_report_ready(t: TriageResult) -> bool:
    """Strict report-ready gate. ALL conditions must hold:

    - verdict = verified
    - scope_status = in-scope
    - severity != unknown
    - confidence in (medium, high)
    - priority != needs-review
    - permissionless != unknown
    - no BLOCKING missing information (access-control / reachability)
    """
    if getattr(t, "_conviction_verdict", "") != "verified":
        return False
    if t.scope_status != "in-scope":
        return False
    if t.severity == "unknown":
        return False
    if t.confidence not in ("medium", "high"):
        return False
    if t.priority == "needs-review":
        return False
    if t.attacker_prerequisites.permissionless == "unknown":
        return False
    if missing_blockers(t):
        return False
    return True


def bucket_triage_results(results: list[TriageResult]) -> tuple[list[dict], list[dict], list[dict]]:
    """Split triage results into (report_ready, needs_review, out_of_scope) dicts."""
    report_ready: list[dict] = []
    needs_review: list[dict] = []
    out_of_scope: list[dict] = []
    for t in results:
        if t.scope_status == "out-of-scope":
            out_of_scope.append(t.to_dict())
        elif is_report_ready(t):
            report_ready.append(t.to_dict())
        else:
            needs_review.append(t.to_dict())
    return report_ready, needs_review, out_of_scope


def run_triage_from_run(
    run_dir: Path,
    config: Optional[dict] = None,
    policy_name: str = "default",
    verbose: bool = True,
) -> list[TriageResult]:
    """Re-run triage from a previous scan's artifacts."""
    from .verify import load_findings_from_run

    findings = load_findings_from_run(run_dir)
    if not findings:
        raise ValueError(f"No findings found in {run_dir}")

    conviction_path = run_dir / "conviction.json"
    if not conviction_path.is_file():
        raise ValueError(f"No conviction.json found in {run_dir}")

    import json
    conviction_data = json.loads(conviction_path.read_text(encoding="utf-8"))

    # Rebuild conviction results
    from .conviction import ConvictionResult
    from .models import Finding, SourceLocation

    conviction_results: dict[str, ConvictionResult] = {}
    for r in conviction_data.get("results", []):
        try:
            cr = ConvictionResult(**r)
        except Exception:
            cr = ConvictionResult(
                finding_id=r.get("finding_id", ""),
                verdict=r.get("verdict", "needs-review"),
                score=r.get("score", 0.0),
                reasons=r.get("reasons", []),
            )
        conviction_results[cr.finding_id] = cr

    # Rebuild root cause map
    root_cause_map = {}
    for rc in conviction_data.get("root_causes", []):
        root_cause_map[rc["root_cause_id"]] = rc

    # If root_cause_map lacks finding_ids, populate from results
    for r in conviction_data.get("results", []):
        rid = r.get("exploitability_metadata", {}).get("root_cause_id", "")
        if rid and rid in root_cause_map:
            fids = root_cause_map[rid].get("finding_ids", [])
            if not fids:
                root_cause_map[rid]["finding_ids"] = [r.get("finding_id", "")]
            elif r.get("finding_id", "") not in fids:
                root_cause_map[rid]["finding_ids"] = fids + [r.get("finding_id", "")]

    # Load target dir from manifest
    target_dir = ""
    manifest_path = run_dir / "run_manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            target_dir = manifest.get("target", "")
        except Exception:
            pass

    return run_triage(
        findings=findings,
        conviction_results=conviction_results,
        root_cause_map=root_cause_map,
        config=config,
        policy_name=policy_name,
        verbose=verbose,
    )