"""Triage & Severity Engine — comprehensive tests.

Covers: attacker prerequisites, exploitability scoring, asset impact,
scope-aware triage, root-cause duplicate handling, severity policies,
priority assignment, and report-ready filtering.
"""

from __future__ import annotations
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

import pytest

# Ensure path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from aletheia.models import Finding, SourceLocation
from aletheia.conviction import ConvictionResult, DYNAMIC_ENGINES, STATIC_ENGINES
from aletheia.triage_model import (
    TriageResult, AttackerPrerequisites, ExploitabilityScore,
    ExploitabilityFactors, AssetImpact,
)
from aletheia.severity_policy import apply_policy, POLICIES, SEVERITY_RANK
from aletheia.triage import (
    _analyze_prerequisites, _score_exploitability, _assess_impact,
    _assign_priority, _init_scope, run_triage,
)


# ---------------- helpers ----------------

def make_cr(
    fid: str = "test-1",
    verdict: str = "verified",
    score: float = 1.0,
    confidence: str = "high",
    ac: str = "ungated",
    cp: str = "reachable",
    has_dynamic: bool = True,
    reproducible: bool = True,
    requires_priv: bool = False,
    analysis: dict = None,
) -> ConvictionResult:
    return ConvictionResult(
        finding_id=fid,
        verdict=verdict,
        confidence=confidence,
        score=score,
        source_verified=True,
        access_control_verdict=ac,
        call_path_verdict=cp,
        exploitability={
            "reproducible": reproducible,
            "requires_privileges": requires_priv,
        },
        evidence_summary={
            "has_dynamic_evidence": has_dynamic,
            "has_trace": True,
        },
        analysis=analysis or {"access_control": {"modifier_name": ""}},
    )


def make_finding(
    fid: str = "test-1",
    engine: str = "foundry",
    contract: str = "VulnerableVault",
    func: str = "setOwner",
    title: str = "Unauthorized setOwner",
    scope: str = "",
) -> Finding:
    f = Finding(
        finding_id=fid,
        engine=engine,
        title=title,
        source_location=SourceLocation(contract=contract, function=func),
    )
    f.corroborating_engines = []
    f.trace = ["attacker called setOwner(0xdead)"]
    if scope:
        f.scope_status = scope
    return f


# ================ 1. Attacker prerequisites ================

def test_prereq_permissionless():
    """Verified + ungated + reachable + dynamic → permissionless=True."""
    f = make_finding()
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=True)
    ap = _analyze_prerequisites(f, cr)
    assert ap.permissionless is True
    assert ap.requires_privileged_role is False
    assert ap.capital_required == "none"


def test_prereq_restricted():
    """Restricted AC → requires_privileged_role=True, permissionless=False."""
    f = make_finding()
    cr = make_cr(verdict="rejected", score=0.0, ac="restricted",
                 cp="restricted-reachable", has_dynamic=False,
                 analysis={"access_control": {"modifier_name": "onlyOwner"}})
    ap = _analyze_prerequisites(f, cr)
    assert ap.requires_privileged_role is True
    assert ap.permissionless is False
    assert "Owner" in ap.privileged_role or "owner" in ap.privileged_role


def test_prereq_unknown_not_permissionless():
    """Unknown AC/CP → permissionless stays "unknown", never False."""
    f = make_finding()
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False, verdict="needs-review")
    ap = _analyze_prerequisites(f, cr)
    assert ap.permissionless == "unknown"
    assert "access-control" in ap.unknown
    assert "reachability" in ap.unknown


def test_prereq_partially_restricted():
    """Partially-restricted → permissionless unknown (guard not proven effective)."""
    f = make_finding()
    cr = make_cr(ac="partially-restricted", cp="reachable", has_dynamic=True)
    ap = _analyze_prerequisites(f, cr)
    assert ap.permissionless == "unknown"


# ================ 2. Exploitability scoring ================

def test_score_directly_reproducible():
    """All factors maxed → score >= 0.90, label=directly-reproducible."""
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=True, reproducible=True,
                 requires_priv=False)
    ex = _score_exploitability(cr)
    assert ex.score >= 0.90
    assert ex.label == "directly-reproducible"
    assert ex.factors.reachable == 1.0
    assert ex.factors.permissionless == 1.0


def test_score_restricted_low():
    """Restricted finding → low score."""
    cr = make_cr(ac="restricted", cp="restricted-reachable", has_dynamic=False)
    ex = _score_exploitability(cr)
    assert ex.score < 0.50
    assert ex.factors.permissionless == 0.0


def test_score_unknown_zero():
    """Unknown AC/CP → factors are 0, score is low."""
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False)
    ex = _score_exploitability(cr)
    assert ex.score < 0.25
    assert ex.factors.reachable == 0.0
    assert ex.factors.permissionless == 0.0


def test_score_deterministic():
    """Same input → same score (deterministic)."""
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=True)
    s1 = _score_exploitability(cr).score
    s2 = _score_exploitability(cr).score
    assert s1 == s2


def test_score_factors_stored():
    """Factors are stored individually, not just final score."""
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=True)
    ex = _score_exploitability(cr)
    assert hasattr(ex, "factors")
    assert isinstance(ex.factors, ExploitabilityFactors)
    assert ex.factors.reachable == 1.0
    assert ex.factors.dynamic_corroboration == 1.0


# ================ 3. Asset impact ================

def test_impact_ownership_takeover():
    """State var 'owner' → privilege_takeover, admin/ownership state."""
    from aletheia.rootcause import RootCause
    rc = RootCause(state_variables=["owner"])
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=True)
    imp = _assess_impact(cr, rc)
    assert "admin/ownership state" in imp.affected_assets
    assert imp.privilege_takeover is True
    assert imp.impact in ("potential", "quantified")


def test_impact_balances_potential():
    """State var 'balances' → potential funds loss, never quantified."""
    from aletheia.rootcause import RootCause
    rc = RootCause(state_variables=["balances"])
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=True)
    imp = _assess_impact(cr, rc)
    assert "ERC20/token balance" in imp.affected_assets
    assert imp.direct_funds_loss == "potential"
    assert imp.quantified_amount == ""


def test_impact_restricted_none():
    """Restricted finding → impact=none."""
    from aletheia.rootcause import RootCause
    rc = RootCause(state_variables=["owner"])
    cr = make_cr(ac="restricted", cp="restricted-reachable", has_dynamic=False)
    imp = _assess_impact(cr, rc)
    assert imp.impact == "none"


def test_impact_unknown():
    """Unknown AC/CP → impact=unknown."""
    from aletheia.rootcause import RootCause
    rc = RootCause(state_variables=[])
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False)
    imp = _assess_impact(cr, rc)
    assert imp.impact == "unknown"


def test_impact_no_fabricated_quantified():
    """Never produce 'quantified' without real evidence."""
    from aletheia.rootcause import RootCause
    rc = RootCause(state_variables=["balances"])
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=True)
    imp = _assess_impact(cr, rc)
    assert imp.impact != "quantified"
    assert imp.direct_funds_loss != "quantified"
    assert imp.quantified_amount == ""


# ================ 4. Scope-aware triage ================

def test_scope_in_scope():
    f = make_finding()
    f.scope_status = "in-scope"
    scope, reason = _init_scope(f, None)
    assert scope == "in-scope"


def test_scope_out_of_scope():
    f = make_finding()
    f.scope_status = "out-of-scope"
    scope, reason = _init_scope(f, None)
    assert scope == "out-of-scope"


def test_scope_uncertain_no_config():
    f = make_finding()
    f.scope_status = "unknown"
    scope, reason = _init_scope(f, None)
    assert scope == "uncertain"


def test_scope_config_matches():
    f = make_finding()
    f.scope_status = "unknown"
    f.source_location.contract = "VulnerableVault"
    f.vulnerability_class = "access-control"
    config = {"scope": {"contracts": ["VulnerableVault"], "vulnerability_classes": ["access-control"]}}
    scope, reason = _init_scope(f, config)
    assert scope == "in-scope"


def test_scope_config_no_match():
    f = make_finding()
    f.scope_status = "unknown"
    f.source_location.contract = "OtherContract"
    config = {"scope": {"contracts": ["VulnerableVault"]}}
    scope, reason = _init_scope(f, config)
    assert scope == "uncertain"


# ================ 5. Root-cause duplicate handling ================

def test_duplicate_one_triage_result():
    """Multiple findings sharing root cause → one triage result."""
    f1 = make_finding("f1", engine="foundry")
    f2 = make_finding("f2", engine="medusa")
    f3 = make_finding("f3", engine="echidna")
    # All share same root_cause_id
    for f in (f1, f2, f3):
        f.exploitability_metadata = {"root_cause_id": "rc-shared"}
    cr1 = make_cr("f1", ac="ungated", cp="reachable", has_dynamic=True)
    cr2 = make_cr("f2", ac="ungated", cp="reachable", has_dynamic=True)
    cr3 = make_cr("f3", ac="ungated", cp="reachable", has_dynamic=True)
    conviction_results = {"f1": cr1, "f2": cr2, "f3": cr3}
    root_cause_map = {"rc-shared": {"root_cause_id": "rc-shared", "title": "Owner takeover"}}
    results = run_triage(
        findings=[f1, f2, f3],
        conviction_results=conviction_results,
        root_cause_map=root_cause_map,
        config={},
        policy_name="default",
        verbose=False,
    )
    assert len(results) == 1
    assert results[0].duplicate_status == "merged"
    assert len(results[0].evidence_merged_from) == 2  # 2 non-primary


def test_different_root_causes_separate():
    """Different functions/state → separate triage results."""
    f1 = make_finding("f1", func="setOwner")
    f2 = make_finding("f2", func="withdrawFrom")
    f1.exploitability_metadata = {"root_cause_id": "rc-1"}
    f2.exploitability_metadata = {"root_cause_id": "rc-2"}
    cr1 = make_cr("f1")
    cr2 = make_cr("f2")
    results = run_triage(
        findings=[f1, f2],
        conviction_results={"f1": cr1, "f2": cr2},
        root_cause_map={"rc-1": {}, "rc-2": {}},
        verbose=False,
    )
    assert len(results) == 2
    assert results[0].root_cause_id != results[1].root_cause_id


# ================ 6. Severity policy ================

def test_policy_default_critical():
    """Default policy: verified+permissionless+direct_loss+reproducible+dynamic → critical."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
    t.exploitability.factors.reproducible = 1.0
    t.exploitability.factors.dynamic_corroboration = 1.0
    t = apply_policy(t, "default")
    assert t.severity == "critical"


def test_policy_immunefi():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
    t.exploitability.factors.reproducible = 1.0
    t.exploitability.factors.dynamic_corroboration = 1.0
    t = apply_policy(t, "immunefi")
    assert t.severity == "critical"


def test_policy_hackenproof():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.exploitability = ExploitabilityScore(score=0.80)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
    t.exploitability.factors.reproducible = 1.0
    t = apply_policy(t, "hackenproof")
    assert t.severity == "critical"


def test_policy_yeswehack():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
    t.exploitability.factors.reproducible = 1.0
    t = apply_policy(t, "yeswehack")
    assert t.severity == "critical"


def test_policy_unverified_capped():
    """Unverified → never high/critical."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "needs-review"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
    for policy in ("default", "immunefi", "hackenproof", "yeswehack"):
        t_copy = TriageResult(finding_id="t1")
        t_copy._conviction_verdict = "needs-review"
        t_copy.exploitability = ExploitabilityScore(score=0.95)
        t_copy.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
        t_copy.impact = AssetImpact(direct_funds_loss="potential")
        t_copy = apply_policy(t_copy, policy)
        assert t_copy.severity not in ("high", "critical"), f"{policy}: {t_copy.severity}"


def test_policy_secure_not_critical():
    """Secure/guarded finding → never high/critical."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "rejected"
    t.exploitability = ExploitabilityScore(score=0.0)
    t.attacker_prerequisites = AttackerPrerequisites(requires_privileged_role=True)
    t.impact = AssetImpact(impact="none", direct_funds_loss="none")
    for policy in ("default", "immunefi", "hackenproof", "yeswehack"):
        t_copy = TriageResult(finding_id="t1")
        t_copy._conviction_verdict = "rejected"
        t_copy.exploitability = ExploitabilityScore(score=0.0)
        t_copy.attacker_prerequisites = AttackerPrerequisites(requires_privileged_role=True)
        t_copy.impact = AssetImpact(impact="none", direct_funds_loss="none")
        t_copy = apply_policy(t_copy, policy)
        assert t_copy.severity not in ("high", "critical"), f"{policy}: {t_copy.severity}"


# ================ 7. Priority ================

def test_priority_p0_critical():
    """Verified + permissionless + reproducible + direct loss → P0."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "critical"
    t.confidence = "high"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
    t.scope_status = "in-scope"
    t = _assign_priority(t)
    assert t.priority == "p0-critical"


def test_priority_p1_high():
    """Verified + serious impact, not permissionless → P1."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "high"
    t.confidence = "high"
    t.exploitability = ExploitabilityScore(score=0.60)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=False)
    t.impact = AssetImpact(privilege_takeover=True, impact="potential")
    t.scope_status = "in-scope"
    t = _assign_priority(t)
    assert t.priority == "p1-high"


def test_priority_p2_medium():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "medium"
    t.confidence = "medium"
    t.exploitability = ExploitabilityScore(score=0.40)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=False)
    t.impact = AssetImpact(impact="potential")
    t.scope_status = "in-scope"
    t = _assign_priority(t)
    assert t.priority == "p2-medium"


def test_priority_p3_low():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "low"
    t.confidence = "low"
    t.exploitability = ExploitabilityScore(score=0.15)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=False)
    t.impact = AssetImpact(impact="potential")
    t.scope_status = "in-scope"
    t = _assign_priority(t)
    assert t.priority == "p3-low"


def test_priority_out_of_scope():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "critical"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.scope_status = "out-of-scope"
    t = _assign_priority(t)
    assert t.priority == "p4-informational"


def test_priority_uncertain_capped():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "critical"
    t.confidence = "high"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.impact = AssetImpact(direct_funds_loss="potential")
    t.scope_status = "uncertain"
    t = _assign_priority(t)
    assert t.priority == "needs-review"


def test_priority_different_from_severity():
    """Priority ≠ severity — two findings same severity can have different priority."""
    t1 = TriageResult(finding_id="t1")
    t1._conviction_verdict = "verified"
    t1.severity = "high"
    t1.confidence = "high"
    t1.exploitability = ExploitabilityScore(score=0.95)
    t1.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t1.impact = AssetImpact(direct_funds_loss="potential")
    t1.scope_status = "in-scope"
    _assign_priority(t1)

    t2 = TriageResult(finding_id="t2")
    t2._conviction_verdict = "verified"
    t2.severity = "high"
    t2.confidence = "high"
    t2.exploitability = ExploitabilityScore(score=0.55)
    t2.attacker_prerequisites = AttackerPrerequisites(requires_privileged_role=True)
    t2.impact = AssetImpact(impact="potential")
    t2.scope_status = "in-scope"
    _assign_priority(t2)

    assert t1.severity == t2.severity  # same severity
    assert t1.priority != t2.priority   # different priority


# ================ 8. Report-ready filtering ================

def test_report_ready_verified_in_scope():
    """Verified + in-scope + severity != unknown → report-ready."""
    f = make_finding("f1", scope="in-scope")
    f.scope_status = "in-scope"
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", ac="ungated", cp="reachable", has_dynamic=True)
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    assert len(results) == 1
    t = results[0]
    assert t._conviction_verdict == "verified"
    assert t.scope_status == "in-scope"
    assert t.severity != "unknown"


def test_needs_review_not_report_ready():
    """needs-review → severity unknown → not report-ready."""
    f = make_finding("f1")
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", verdict="needs-review", ac="unknown", cp="unknown",
                 has_dynamic=False, score=0.1)
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    assert len(results) == 1
    t = results[0]
    assert t._conviction_verdict == "needs-review"
    assert t.severity == "unknown"


def test_out_of_scope_not_report_ready():
    """Out-of-scope → never report-ready."""
    f = make_finding("f1", scope="out-of-scope")
    f.scope_status = "out-of-scope"
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", ac="ungated", cp="reachable", has_dynamic=True)
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    assert len(results) == 1
    t = results[0]
    assert t.scope_status == "out-of-scope"


def test_secure_guarded_not_high_critical():
    """Secure/guarded finding → severity not high/critical."""
    f = make_finding("f1")
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", verdict="rejected", ac="restricted",
                 cp="restricted-reachable", has_dynamic=False, score=0.0,
                 analysis={"access_control": {"modifier_name": "onlyOwner"}})
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    t = results[0]
    assert t.severity not in ("high", "critical")


def test_unknown_impact_not_quantified():
    """Unknown impact → never quantified."""
    f = make_finding("f1")
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", verdict="needs-review", ac="unknown", cp="unknown",
                 has_dynamic=False, score=0.1)
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    t = results[0]
    assert t.impact.impact != "quantified"
    assert t.impact.direct_funds_loss != "quantified"


def test_unverified_not_critical_report_ready():
    """Unverified finding → never critical/high in report-ready output."""
    f = make_finding("f1")
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", verdict="needs-dynamic-validation", ac="ungated",
                 cp="reachable", has_dynamic=False, score=0.4)
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    t = results[0]
    assert t._conviction_verdict != "verified"
    assert t.severity not in ("high", "critical")


def test_no_fabricated_quantified():
    """No nominal amounts without evidence."""
    f = make_finding("f1")
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", ac="ungated", cp="reachable", has_dynamic=True)
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    t = results[0]
    assert t.impact.quantified_amount == ""
    assert t.impact.impact in ("potential", "unknown", "none")


def test_dynamic_trace_not_auto_critical():
    """Dynamic trace alone → not automatically critical."""
    f = make_finding("f1")
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    # Has dynamic evidence but restricted AC
    cr = make_cr("f1", verdict="verified", ac="restricted",
                 cp="restricted-reachable", has_dynamic=True, score=0.3)
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    t = results[0]
    assert t.severity not in ("critical",)


def test_missing_information_recorded():
    """Unknown AC/CP → missing_information populated."""
    f = make_finding("f1")
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", verdict="needs-review", ac="unknown", cp="unknown",
                 has_dynamic=False, score=0.1)
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    t = results[0]
    assert len(t.missing_information) > 0
    assert any("access-control" in m for m in t.missing_information)


def test_triage_result_to_dict_valid():
    """TriageResult.to_dict() produces valid dict."""
    t = TriageResult(finding_id="t1", root_cause_id="rc-1")
    d = t.to_dict()
    assert isinstance(d, dict)
    assert d["finding_id"] == "t1"
    assert "exploitability" in d
    assert "attacker_prerequisites" in d
    assert "impact" in d


def test_all_policies_available():
    """All 4 policies are registered."""
    assert "default" in POLICIES
    assert "immunefi" in POLICIES
    assert "hackenproof" in POLICIES
    assert "yeswehack" in POLICIES
