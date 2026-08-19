"""Conviction & Verification Engine — evidence-based verdicts.

Access control and reachability come from REAL Slither analysis
(AccessControlIndex / ReachabilityIndex / StateIndex / CallIndex) via
analysis_wiring. Titles, detector names and test names are NEVER used as
primary evidence for a vulnerability.
"""

from __future__ import annotations
import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from .models import Finding
from .analysis_wiring import AnalysisOutcome, load_analysis
from .rootcause import build_root_cause

DYNAMIC_ENGINES = ("foundry", "medusa", "echidna")
STATIC_ENGINES = ("slither", "semgrep")
SYMBOLIC_ENGINES = ("mythril",)


@dataclass
class ConvictionResult:
    """Result of running conviction checks on a finding."""
    finding_id: str = ""
    verdict: str = "needs-review"  # verified, rejected, needs-review, needs-dynamic-validation
    confidence: str = "medium"     # high, medium, low
    score: float = 0.0

    # structured checks
    source_verified: bool = False
    access_control_verdict: str = "unknown"  # ungated, restricted, partially-restricted, unknown
    call_path_verdict: str = "unknown"       # reachable, unreachable, restricted-reachable, unknown
    exploitability: dict[str, Any] = field(default_factory=dict)

    # analysis-derived detail
    analysis: dict[str, Any] = field(default_factory=dict)
    root_cause_id: str = ""

    # evidence
    evidence_summary: dict[str, Any] = field(default_factory=dict)
    corroborating_engines: list[str] = field(default_factory=list)

    # reasons
    reasons: list[str] = field(default_factory=list)
    rejected_because: list[str] = field(default_factory=list)
    verification_artifacts: list[str] = field(default_factory=list)

    # checks executed
    checks_run: list[str] = field(default_factory=list)
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class ConvictionEngine:
    """Evidence-based conviction over real static analysis + engine evidence."""

    def __init__(
        self,
        findings: list[Finding] | dict,
        target_dir: str = "",
        config: Optional[dict] = None,
        analysis: Optional[AnalysisOutcome] = None,
    ):
        if isinstance(findings, dict):
            self.findings = findings
        else:
            self.findings = {f.finding_id: f for f in findings if hasattr(f, "finding_id")}
        self.target_dir = target_dir
        self.config = config or {}
        self.results: dict[str, ConvictionResult] = {}
        self.analysis = analysis  # may be None → verdicts stay unknown

    # ---------------- analysis loading ----------------

    def ensure_analysis(self) -> Optional[AnalysisOutcome]:
        """Load real analysis for the target if not already provided."""
        if self.analysis is not None:
            return self.analysis
        if not self.target_dir:
            return None
        target_root = self.target_dir
        if target_root and not os.path.exists(target_root):
            # Archived manifests can contain the producer's absolute target
            # path. Resolve an unambiguous directory with the same basename
            # below the current workspace before giving up on real analysis.
            wanted = os.path.basename(os.path.normpath(target_root))
            matches = []
            for root, dirs, _files in os.walk(os.getcwd()):
                for name in dirs:
                    if name == wanted:
                        candidate = os.path.join(root, name)
                        if any(os.path.isdir(os.path.join(candidate, sub)) for sub in ("contracts", "src")):
                            matches.append(candidate)
            if len(matches) == 1:
                target_root = matches[0]
        candidates = []
        for sub in ("contracts", "src"):
            d = os.path.join(target_root, sub)
            if os.path.isdir(d):
                for root, _dirs, files in os.walk(d):
                    for name in sorted(files):
                        if name.endswith(".sol"):
                            candidates.append(os.path.join(root, name))
            if candidates:
                break
        if not candidates and os.path.isfile(target_root) and target_root.endswith(".sol"):
            candidates = [target_root]
        if not candidates:
            return None
        outcome = load_analysis(candidates[0])
        self.analysis = outcome if outcome.ok else None
        return self.analysis

    # ---------------- main entry ----------------

    def evaluate(self, finding_id: str) -> ConvictionResult:
        f = self.findings.get(finding_id)
        if f is None or not hasattr(f, "finding_id"):
            return ConvictionResult(finding_id=finding_id, verdict="rejected",
                                    reasons=["Finding not found in context"])

        analysis = self.ensure_analysis()
        result = ConvictionResult(finding_id=finding_id)

        # --- resolve to a real function via analysis ---
        rc = build_root_cause(f, analysis)
        result.root_cause_id = rc.root_cause_id
        canonical = rc.function if rc.resolved else ""
        result.analysis = {
            "analysis_available": analysis is not None and analysis.ok,
            "function_resolved": rc.resolved,
            "canonical_function": canonical,
            "state_variables": rc.state_variables,
        }

        # --- 1. source verification ---
        result.checks_run.append("source_verification")
        src_ok, src_reason, src_precision = self._verify_source(f, canonical, analysis)
        result.source_verified = src_ok
        result.analysis["source_mapping"] = src_precision
        (result.checks_passed if src_ok else result.checks_failed).append("source_verification")
        result.reasons.append(src_reason)

        # --- 2. access control (REAL) ---
        result.checks_run.append("access_control_verdict")
        ac_verdict, ac_reasons, ac_detail = self._real_access_control(canonical, analysis)
        result.access_control_verdict = ac_verdict
        result.analysis["access_control"] = ac_detail
        result.reasons.extend(ac_reasons)
        if ac_verdict == "unknown":
            result.checks_failed.append("access_control_verdict")
        else:
            result.checks_passed.append("access_control_verdict")

        # --- 3. reachability (REAL) ---
        result.checks_run.append("call_path_reachability")
        cp_verdict, cp_reasons, cp_detail = self._real_reachability(canonical, analysis, ac_verdict)
        result.call_path_verdict = cp_verdict
        result.analysis["reachability"] = cp_detail
        result.reasons.extend(cp_reasons)
        if cp_verdict == "unknown":
            result.checks_failed.append("call_path_reachability")
        else:
            result.checks_passed.append("call_path_reachability")

        # --- 4. evidence correlation ---
        result.checks_run.append("evidence_correlation")
        result.evidence_summary, result.corroborating_engines = self._correlate_evidence(f)
        result.evidence_summary["source_verified"] = result.source_verified
        result.evidence_summary["access_control_verified"] = ac_verdict != "unknown"
        result.evidence_summary["call_path_verified"] = cp_verdict != "unknown"
        result.checks_passed.append("evidence_correlation")

        # --- 5. exploitability ---
        result.checks_run.append("exploitability")
        result.exploitability = self._assess_exploitability(f, result, rc, analysis)
        result.checks_passed.append("exploitability")

        # --- 6. verdict ---
        result = self._determine_verdict(result, f, rc)
        self.results[finding_id] = result
        return result

    def evaluate_all(self) -> list[ConvictionResult]:
        for fid in list(self.findings):
            self.evaluate(fid)
        return list(self.results.values())

    # ---------------- checks ----------------

    def _verify_source(
        self, f: Finding, canonical: str, analysis: Optional[AnalysisOutcome]
    ) -> tuple[bool, str, str]:
        """Validate the source pointer. Returns (ok, reason, precision)."""
        # Precise path: a real file + in-range line.
        if f.source_location.file:
            src_path = f.source_location.file
            if not src_path.startswith("/") and self.target_dir:
                src_path = os.path.join(self.target_dir, src_path)
            # Findings produced on another machine may retain that machine's
            # absolute workspace prefix. Resolve the path by its relative
            # suffix inside the current target, without trusting the stale
            # absolute location.
            target_base = self.target_dir if os.path.isdir(self.target_dir) else os.getcwd()
            if not os.path.isfile(src_path) and target_base and os.path.isabs(src_path):
                marker = "/contracts/"
                if marker in src_path:
                    candidate = os.path.join(target_base, src_path.split(marker, 1)[1])
                    if os.path.isfile(candidate):
                        src_path = candidate
                elif "/src/" in src_path:
                    candidate = os.path.join(target_base, src_path.split("/src/", 1)[1])
                    if os.path.isfile(candidate):
                        src_path = candidate
                if not os.path.isfile(src_path):
                    # Last resort for archived artifacts whose target root also
                    # moved: locate the same contracts/<file> suffix below the
                    # current working tree. Ambiguous matches are rejected.
                    suffix = src_path.replace("\\", "/").split("/contracts/", 1)[-1]
                    matches = []
                    for root, _dirs, files in os.walk(target_base):
                        if suffix.split("/")[-1] in files and root.replace("\\", "/").endswith("/contracts"):
                            matches.append(os.path.join(root, suffix.split("/")[-1]))
                    if len(matches) == 1:
                        src_path = matches[0]
            if not os.path.isfile(src_path):
                return False, f"Source file not found: {src_path}", "invalid"
            try:
                with open(src_path, encoding="utf-8", errors="replace") as fh:
                    total = sum(1 for _ in fh)
            except Exception as e:
                return False, f"Source unreadable: {e}", "invalid"
            if f.source_location.line_start and f.source_location.line_start > total:
                return False, (
                    f"Line {f.source_location.line_start} exceeds file length ({total}) — stale finding"
                ), "stale"
            return True, f"Source location valid: {f.source_location.file}:{f.source_location.line_start}", "precise"

        # No file: acceptable only when the function was resolved in the real
        # compilation unit (dynamic engines have no source pointer of their own).
        if canonical:
            return True, (
                f"No source pointer; function resolved in compilation unit as {canonical}"
            ), "approximate"

        return False, "No source location and function could not be resolved in analysis", "invalid"

    def _real_access_control(
        self, canonical: str, analysis: Optional[AnalysisOutcome]
    ) -> tuple[str, list[str], dict]:
        """Access-control verdict from AccessControlIndex only."""
        if analysis is None or not analysis.ok:
            return "unknown", ["Access control unknown: static analysis unavailable"], {}
        if not canonical:
            return "unknown", ["Access control unknown: finding not mapped to a analyzed function"], {}

        ac = analysis.access_control.get(canonical)
        if not ac:
            return "unknown", [f"Access control unknown: {canonical} absent from analysis"], {}

        kind = ac.get("kind", "none")
        effective = bool(ac.get("effective"))
        has_ac = bool(ac.get("has_access_control"))
        modifier = ac.get("modifier_name", "")
        writes = analysis.state_writes.get(canonical, [])
        detail = {
            "kind": kind,
            "effective": effective,
            "has_access_control": has_ac,
            "modifier_name": modifier,
            "is_inherited": bool(ac.get("is_inherited")),
            "guard_found": has_ac,
            "protected_operation": canonical,
            "state_writes": writes,
        }

        if has_ac and effective:
            return "restricted", [
                f"AccessControlIndex: effective guard on {canonical}"
                + (f" via {modifier}" if modifier else "")
            ], detail
        if has_ac and not effective:
            return "partially-restricted", [
                f"AccessControlIndex: guard present on {canonical} but not proven effective"
                + (f" ({modifier})" if modifier else "")
            ], detail
        # No guard at all. Only meaningful as "ungated" when the function
        # actually mutates state — otherwise there is nothing to gate.
        if writes:
            return "ungated", [
                f"AccessControlIndex: no guard on {canonical}, writes state {writes}"
            ], detail
        return "unknown", [
            f"AccessControlIndex: no guard on {canonical} but no state write detected"
        ], detail

    def _real_reachability(
        self, canonical: str, analysis: Optional[AnalysisOutcome], ac_verdict: str
    ) -> tuple[str, list[str], dict]:
        """Reachability verdict from ReachabilityIndex/CallIndex only.

        Default is unknown — never assume reachable.
        """
        if analysis is None or not analysis.ok:
            return "unknown", ["Reachability unknown: call-graph analysis unavailable"], {}
        if not canonical:
            return "unknown", ["Reachability unknown: finding not mapped to a analyzed function"], {}

        rc = analysis.reachability.get(canonical)
        if not rc:
            return "unknown", [f"Reachability unknown: {canonical} absent from call graph"], {}

        reachable = bool(rc.get("reachable"))
        entry = bool(rc.get("entry_point"))
        callers = analysis.callers.get(canonical, [])
        detail = {
            "reachability": "reachable" if reachable else "unreachable",
            "entry_point": canonical if entry else "",
            "callers": callers,
            "cfg_verified": True,
            "call_path": self._build_call_path(canonical, entry, callers, analysis),
        }

        if not reachable:
            return "unreachable", [
                f"ReachabilityIndex: {canonical} not reachable from any external entry point"
            ], detail

        if entry:
            if ac_verdict == "restricted":
                return "restricted-reachable", [
                    f"ReachabilityIndex: {canonical} is an external entry point but guarded"
                ], detail
            return "reachable", [
                f"ReachabilityIndex: {canonical} is an external entry point"
            ], detail

        # Internal function reached only through callers.
        guarded_callers = []
        open_callers = []
        for c in callers:
            cac = analysis.access_control.get(c, {})
            if cac.get("has_access_control") and cac.get("effective"):
                guarded_callers.append(c)
            else:
                open_callers.append(c)
        if callers and not open_callers:
            return "restricted-reachable", [
                f"ReachabilityIndex: {canonical} reachable only via guarded callers {guarded_callers}"
            ], detail
        if open_callers:
            return "reachable", [
                f"ReachabilityIndex: {canonical} reachable via unguarded callers {open_callers}"
            ], detail
        return "unknown", [f"Reachability unknown: no caller path resolved for {canonical}"], detail

    def _build_call_path(
        self, canonical: str, entry: bool, callers: list[str], analysis: AnalysisOutcome
    ) -> list[str]:
        path = ["external caller"]
        if not entry and callers:
            path.append(callers[0])
        path.append(canonical)
        writes = analysis.state_writes.get(canonical, [])
        if writes:
            path.append(f"{','.join(writes)} storage write")
        return path

    def _correlate_evidence(self, f: Finding) -> tuple[dict[str, Any], list[str]]:
        engines = [f.engine, *(f.corroborating_engines or [])]
        unique = [e for e in dict.fromkeys(engines) if e]
        static = [e for e in unique if e in STATIC_ENGINES]
        symbolic = [e for e in unique if e in SYMBOLIC_ENGINES]
        dynamic = [e for e in unique if e in DYNAMIC_ENGINES]
        meta = f.exploitability_metadata or {}
        summary = {
            "static_engines": static,
            "symbolic_engines": symbolic,
            "dynamic_engines": dynamic,
            "has_trace": bool(f.trace or f.evidence),
            "has_test_sequence": bool(f.test_sequence),
            "has_dynamic_evidence": bool(dynamic),
            "evidence_count": meta.get("evidence_count", 1),
            "root_cause_id": meta.get("root_cause_id", ""),
        }
        return summary, unique

    def _assess_exploitability(
        self,
        f: Finding,
        result: ConvictionResult,
        rc,
        analysis: Optional[AnalysisOutcome],
    ) -> dict[str, Any]:
        cp = result.call_path_verdict
        ac = result.access_control_verdict

        if cp == "reachable":
            reachable: Any = True
        elif cp == "unreachable":
            reachable = False
        elif cp == "restricted-reachable":
            reachable = True
        else:
            reachable = "unknown"

        has_dynamic = bool(result.evidence_summary.get("has_dynamic_evidence"))
        if has_dynamic:
            reproducible: Any = True
        elif result.evidence_summary.get("static_engines") or result.evidence_summary.get("symbolic_engines"):
            reproducible = "unknown"
        else:
            reproducible = "unknown"

        if ac == "restricted":
            requires_priv: Any = True
        elif ac == "ungated":
            requires_priv = False
        else:
            requires_priv = "unknown"

        # Asset impact: none / unknown / potential / quantified.
        state_vars = rc.state_variables if rc else []
        asset_impact = "unknown"
        if ac == "restricted":
            # A guarded operation is not an unprivileged asset risk.
            asset_impact = "none"
        elif state_vars and ac == "ungated" and cp in ("reachable",):
            asset_impact = "potential"
        elif not state_vars and rc and rc.resolved:
            asset_impact = "none"

        return {
            "reachable": reachable,
            "reproducible": reproducible,
            "requires_privileges": requires_priv,
            "requires_special_state": "unknown",
            "asset_impact": asset_impact,
            "state_variables": state_vars,
        }

    # ---------------- verdict ----------------

    def _determine_verdict(self, result: ConvictionResult, f: Finding, rc) -> ConvictionResult:
        ac = result.access_control_verdict
        cp = result.call_path_verdict
        has_dynamic = bool(result.evidence_summary.get("has_dynamic_evidence"))
        has_trace = bool(result.evidence_summary.get("has_trace"))
        engine_count = len(result.corroborating_engines)

        # ---- rejection: needs concrete proof ----
        rejected: list[str] = []
        if not result.source_verified:
            # Dynamic engines (foundry/medusa/echidna) can lack source pointers
            # when the analysis doesn't index test-only functions. This is a
            # limitation of the analysis, not proof the finding is wrong.
            if f.engine in DYNAMIC_ENGINES:
                result.verdict = "needs-review"
                result.confidence = "low"
                result.reasons.append(
                    f"Dynamic finding ({f.engine}) could not be mapped to an analyzed function — "
                    "manual review of the test failure is required"
                )
                result.score = 0.1
                return result
            rejected.append("Source location invalid or finding could not be mapped to code")
        if cp == "unreachable":
            rejected.append("Function proven unreachable from external call paths")
        if ac == "restricted" and cp in ("reachable", "restricted-reachable", "unknown"):
            guard = result.analysis.get("access_control", {}).get("modifier_name", "")
            rejected.append(
                "Effective access-control guard confirmed by AccessControlIndex"
                + (f" ({guard})" if guard else "")
            )
        if rejected:
            result.verdict = "rejected"
            result.rejected_because = rejected
            result.confidence = "high" if result.analysis.get("analysis_available") else "medium"
            result.score = 0.0
            return result

        # ---- unknown analysis can never be verified ----
        if ac == "unknown" or cp == "unknown":
            result.verdict = "needs-review"
            result.confidence = "low"
            missing = [n for n, v in (("access-control", ac), ("reachability", cp)) if v == "unknown"]
            result.reasons.append(
                f"Cannot verify: {' and '.join(missing)} unknown — manual review required"
            )
            result.score = 0.2 if has_dynamic else 0.1
            return result

        # ---- scoring on real evidence ----
        score = 0.0
        reasons: list[str] = []

        if result.source_verified:
            score += 0.10
            reasons.append("Source verified against compilation unit")

        if ac == "ungated":
            score += 0.30
            reasons.append("AccessControlIndex: no effective guard on the state-changing operation")
        elif ac == "partially-restricted":
            score += 0.10
            reasons.append("AccessControlIndex: guard present but not proven effective")

        if cp == "reachable":
            score += 0.25
            reasons.append("ReachabilityIndex: operation reachable from an external entry point")
        elif cp == "restricted-reachable":
            score += 0.05
            reasons.append("ReachabilityIndex: reachable only through restricted callers")

        if has_dynamic:
            score += 0.25
            reasons.append("Dynamic engine reproduced the unauthorized state change")
        if has_trace:
            score += 0.05
            reasons.append("Trace / transaction sequence captured")
        if engine_count > 1:
            score += 0.05
            reasons.append(f"Corroborated by {engine_count} engines: {', '.join(result.corroborating_engines)}")

        score = min(round(score, 2), 1.0)
        result.score = score
        result.reasons.extend(reasons)

        vuln_proven = ac in ("ungated", "partially-restricted")
        path_ok = cp in ("reachable", "restricted-reachable")

        if vuln_proven and path_ok and has_dynamic and score >= 0.60:
            result.verdict = "verified"
            result.confidence = "high" if score >= 0.80 else "medium"
        elif vuln_proven and path_ok and not has_dynamic:
            result.verdict = "needs-dynamic-validation"
            result.confidence = "medium"
            result.reasons.append("Static evidence strong but no runtime proof yet")
        else:
            result.verdict = "needs-review"
            result.confidence = "medium" if score >= 0.4 else "low"
            result.reasons.append("Evidence incomplete or conflicting — manual review required")
        return result


def run_conviction(
    findings: list[Finding],
    target_dir: str = "",
    config: Optional[dict] = None,
    analysis: Optional[AnalysisOutcome] = None,
) -> dict[str, ConvictionResult]:
    engine = ConvictionEngine(findings, target_dir=target_dir, config=config, analysis=analysis)
    results = engine.evaluate_all()
    return {r.finding_id: r for r in results}
