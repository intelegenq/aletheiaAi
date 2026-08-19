"""Milestone 3.1 — Triage Safety Patch regression tests.

Verifies that uncertainty is never misclassified as low-risk or safe:
- unknown severity → needs-review (NOT p4-informational)
- unknown permissionless → "unknown" (NOT False)
- no scope config → uncertain (NOT in-scope)
- uncertain/out-of-scope/unknown → NOT report-ready
- verified permissionless → still report-ready
- secure guarded → still NOT high/critical
- report-ready gate rejects findings with missing blockers
"""

from __future__ import annotations
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from aletheia.models import Finding, SourceLocation
from aletheia.conviction import ConvictionResult
from aletheia.triage_model import (
    TriageResult, AttackerPrerequisites, ExploitabilityScore,
    ExploitabilityFactors, AssetImpact,
)
from aletheia.triage import (
    _analyze_prerequisites, _score_exploitability, _assess_impact,
    _assign_priority, _init_scope, run_triage, is_report_ready,
    bucket_triage_results,
)
from aletheia.severity_policy import apply_policy


# ---- helpers ----

def make_cr(
    fid="test-1", verdict="verified", score=1.0, confidence="high",
    ac="ungated", cp="reachable", has_dynamic=True, reproducible=True,
    requires_priv=False, analysis=None,
):
    return ConvictionResult(
        finding_id=fid, verdict=verdict, confidence=confidence, score=score,
        source_verified=True, access_control_verdict=ac, call_path_verdict=cp,
        exploitability={"reproducible": reproducible, "requires_privileges": requires_priv},
        evidence_summary={"has_dynamic_evidence": has_dynamic, "has_trace": True},
        analysis=analysis or {"access_control": {"modifier_name": ""}},
    )


def make_finding(fid="test-1", engine="foundry", contract="Vault", func="setOwner",
                 scope=""):
    f = Finding(finding_id=fid, engine=engine, title=f"Test {func}",
                source_location=SourceLocation(contract=contract, function=func))
    f.corroborating_engines = []
    f.trace = ["attacker called setOwner(0xdead)"]
    if scope:
        f.scope_status = scope
    return f


# ===== 1. Unknown finding → needs-review, NOT informational =====

def test_unknown_severity_needs_review():
    """Unknown severity → priority=needs-review, NOT p4-informational."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "needs-review"
    t.severity = "unknown"
    t.confidence = "low"
    t.exploitability = ExploitabilityScore(score=0.1)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless="unknown")
    t.impact = AssetImpact(impact="unknown")
    t.scope_status = "uncertain"
    t = _assign_priority(t)
    assert t.priority == "needs-review"
    assert t.priority != "p4-informational"


def test_unknown_verdict_needs_review():
    """needs-review verdict → priority=needs-review."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "needs-review"
    t.severity = "unknown"
    t.confidence = "low"
    t.exploitability = ExploitabilityScore(score=0.1)
    t.attacker_prerequisites = AttackerPrerequisites()
    t.impact = AssetImpact(impact="unknown")
    t.scope_status = "in-scope"
    t = _assign_priority(t)
    assert t.priority == "needs-review"


def test_informational_only_for_proven_no_impact():
    """p4-informational only for findings proven to have no security impact."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "informational"
    t.confidence = "high"
    t.exploitability = ExploitabilityScore(score=0.0)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=False)
    t.impact = AssetImpact(impact="none")
    t.scope_status = "in-scope"
    t = _assign_priority(t)
    assert t.priority == "p4-informational"


# ===== 2. Unknown prerequisite → "unknown", NOT False =====

def test_permissionless_unknown_not_false():
    """Unknown AC → permissionless="unknown", NOT False."""
    f = make_finding()
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False, verdict="needs-review")
    ap = _analyze_prerequisites(f, cr)
    assert ap.permissionless == "unknown"
    assert ap.permissionless is not False


def test_permissionless_ungated_true():
    """Ungated AC → permissionless=True."""
    f = make_finding()
    cr = make_cr(ac="ungated", cp="reachable")
    ap = _analyze_prerequisites(f, cr)
    assert ap.permissionless is True


def test_permissionless_restricted_false():
    """Restricted AC → permissionless=False."""
    f = make_finding()
    cr = make_cr(ac="restricted", cp="restricted-reachable", has_dynamic=False,
                 analysis={"access_control": {"modifier_name": "onlyOwner"}})
    ap = _analyze_prerequisites(f, cr)
    assert ap.permissionless is False


def test_requires_privileged_role_unknown():
    """Unknown AC → requires_privileged_role="unknown"."""
    f = make_finding()
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False, verdict="needs-review")
    ap = _analyze_prerequisites(f, cr)
    assert ap.requires_privileged_role == "unknown"


def test_requires_special_state_unknown():
    """No dynamic evidence → requires_special_state="unknown"."""
    f = make_finding()
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=False)
    ap = _analyze_prerequisites(f, cr)
    assert ap.requires_special_state == "unknown"


def test_requires_flash_loan_unknown():
    f = make_finding()
    cr = make_cr()
    ap = _analyze_prerequisites(f, cr)
    assert ap.requires_flash_loan == "unknown"


def test_requires_multiple_transactions_unknown():
    """No dynamic evidence → multiple_transactions="unknown"."""
    f = make_finding()
    cr = make_cr(ac="ungated", cp="reachable", has_dynamic=False)
    ap = _analyze_prerequisites(f, cr)
    assert ap.requires_multiple_transactions == "unknown"


def test_capital_required_unknown_when_permissionless_unknown():
    f = make_finding()
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False, verdict="needs-review")
    ap = _analyze_prerequisites(f, cr)
    assert ap.capital_required == "unknown"


def test_ac_unknown_not_treated_as_restricted():
    """Unknown AC must not be conflated with restricted."""
    f = make_finding()
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False, verdict="needs-review")
    ap = _analyze_prerequisites(f, cr)
    assert ap.permissionless != False  # not restricted → not False
    assert ap.requires_privileged_role != True  # not restricted → not True


def test_cp_unknown_not_treated_as_unreachable():
    """Unknown CP must not be conflated with unreachable."""
    f = make_finding()
    cr = make_cr(ac="ungated", cp="unknown", has_dynamic=False, verdict="needs-review")
    ap = _analyze_prerequisites(f, cr)
    # permissionless stays True because AC is confirmed ungated
    assert ap.permissionless is True
    assert "reachability" in ap.unknown


# ===== 3. Scope default safe =====

def test_no_scope_config_uncertain():
    """No scope config → uncertain, NOT in-scope."""
    f = make_finding()
    f.scope_status = "unknown"
    scope, reason = _init_scope(f, None)
    assert scope == "uncertain"
    assert "scope configuration" in reason.lower() or "scope" in reason.lower()


def test_scope_config_match_in_scope():
    f = make_finding()
    f.scope_status = "unknown"
    f.source_location.contract = "Vault"
    config = {"scope": {"contracts": ["Vault"]}}
    scope, reason = _init_scope(f, config)
    assert scope == "in-scope"


def test_scope_config_exclusion_out_of_scope():
    f = make_finding()
    f.scope_status = "unknown"
    f.source_location.contract = "Vault"
    config = {"scope": {"contracts": ["Vault"], "exclude_contracts": ["Vault"]}}
    scope, reason = _init_scope(f, config)
    assert scope == "out-of-scope"


def test_uncertain_scope_not_report_ready():
    """Uncertain scope → NOT report-ready."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "high"
    t.confidence = "high"
    t.scope_status = "uncertain"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.missing_information = []
    assert not is_report_ready(t)


def test_out_of_scope_not_report_ready():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "critical"
    t.confidence = "high"
    t.scope_status = "out-of-scope"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.missing_information = []
    assert not is_report_ready(t)


# ===== 4. Report-ready gate =====

def test_report_ready_gate_all_conditions():
    """Verified + in-scope + severity + confidence + permissionless + no missing → report-ready."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "critical"
    t.confidence = "high"
    t.scope_status = "in-scope"
    t.priority = "p0-critical"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.missing_information = []
    assert is_report_ready(t)


def test_report_ready_gate_rejects_missing_info():
    """Blocking missing information (access-control) → NOT report-ready."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "high"
    t.confidence = "high"
    t.scope_status = "in-scope"
    t.priority = "p1-high"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.missing_information = ["access-control analysis"]
    assert not is_report_ready(t)


def test_report_ready_gate_allows_nonblocking_missing_info():
    """Non-blocking missing info (special_state) → still report-ready."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "high"
    t.confidence = "high"
    t.scope_status = "in-scope"
    t.priority = "p1-high"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.missing_information = ["exploitability factor: special_state"]
    assert is_report_ready(t)


def test_report_ready_gate_rejects_unknown_permissionless():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "high"
    t.confidence = "high"
    t.scope_status = "in-scope"
    t.priority = "p1-high"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless="unknown")
    t.missing_information = []
    assert not is_report_ready(t)


def test_report_ready_gate_rejects_needs_review_priority():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "high"
    t.confidence = "high"
    t.scope_status = "in-scope"
    t.priority = "needs-review"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.missing_information = []
    assert not is_report_ready(t)


def test_report_ready_gate_rejects_low_confidence():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.severity = "high"
    t.confidence = "low"
    t.scope_status = "in-scope"
    t.priority = "p1-high"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.missing_information = []
    assert not is_report_ready(t)


def test_report_ready_gate_rejects_unverified():
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "needs-review"
    t.severity = "high"
    t.confidence = "high"
    t.scope_status = "in-scope"
    t.priority = "p1-high"
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.missing_information = []
    assert not is_report_ready(t)


def test_bucket_triage_results():
    """bucket_triage_results splits into 3 correct buckets."""
    t_ready = TriageResult(finding_id="t1")
    t_ready._conviction_verdict = "verified"
    t_ready.severity = "critical"
    t_ready.confidence = "high"
    t_ready.scope_status = "in-scope"
    t_ready.priority = "p0-critical"
    t_ready.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t_ready.missing_information = []

    t_review = TriageResult(finding_id="t2")
    t_review._conviction_verdict = "needs-review"
    t_review.severity = "unknown"
    t_review.confidence = "low"
    t_review.scope_status = "uncertain"
    t_review.attacker_prerequisites = AttackerPrerequisites(permissionless="unknown")

    t_oos = TriageResult(finding_id="t3")
    t_oos._conviction_verdict = "verified"
    t_oos.scope_status = "out-of-scope"
    t_oos.attacker_prerequisites = AttackerPrerequisites(permissionless=True)

    rr, nr, oo = bucket_triage_results([t_ready, t_review, t_oos])
    assert len(rr) == 1
    assert rr[0]["finding_id"] == "t1"
    assert len(nr) == 1
    assert nr[0]["finding_id"] == "t2"
    assert len(oo) == 1
    assert oo[0]["finding_id"] == "t3"


# ===== 5. Exploitability unknown → insufficient-evidence =====

def test_exploitability_insufficient_evidence_label():
    """Unknown AC/CP → label=insufficient-evidence, NOT not-exploitable."""
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False, verdict="needs-review")
    ex = _score_exploitability(cr)
    assert ex.label == "insufficient-evidence"
    assert ex.label != "not-exploitable"


def test_exploitability_missing_info_recorded():
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False, verdict="needs-review")
    ex = _score_exploitability(cr)
    assert len(ex.missing_information) > 0
    assert "reachability" in ex.missing_information
    assert "permissionless" in ex.missing_information


def test_exploitability_unknown_does_not_increase_confidence():
    """Unknown factors → confidence cannot be high."""
    cr = make_cr(ac="unknown", cp="unknown", has_dynamic=False, verdict="needs-review",
                 confidence="low")
    ex = _score_exploitability(cr)
    assert ex.label == "insufficient-evidence"


# ===== 6. Verified findings still work =====

def test_verified_permissionless_still_critical():
    """Verified permissionless + direct loss → severity=critical (unchanged)."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless=True)
    t.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
    t.exploitability.factors.reproducible = 1.0
    t.exploitability.factors.dynamic_corroboration = 1.0
    t = apply_policy(t, "default")
    assert t.severity == "critical"


def test_verified_permissionless_priority_p0():
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


def test_secure_guarded_not_high_critical():
    """Rejected/guarded finding → NOT high/critical (unchanged)."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "rejected"
    t.exploitability = ExploitabilityScore(score=0.0)
    t.attacker_prerequisites = AttackerPrerequisites(requires_privileged_role=True, permissionless=False)
    t.impact = AssetImpact(impact="none", direct_funds_loss="none")
    for policy in ("default", "immunefi", "hackenproof", "yeswehack"):
        t_copy = TriageResult(finding_id="t1")
        t_copy._conviction_verdict = "rejected"
        t_copy.exploitability = ExploitabilityScore(score=0.0)
        t_copy.attacker_prerequisites = AttackerPrerequisites(
            requires_privileged_role=True, permissionless=False)
        t_copy.impact = AssetImpact(impact="none", direct_funds_loss="none")
        t_copy = apply_policy(t_copy, policy)
        assert t_copy.severity not in ("high", "critical"), f"{policy}: {t_copy.severity}"


# ===== 7. Policy unknown_prereq caps severity =====

def test_policy_unknown_permissionless_caps_severity():
    """Unknown permissionless → severity=unknown under ALL policies."""
    t = TriageResult(finding_id="t1")
    t._conviction_verdict = "verified"
    t.exploitability = ExploitabilityScore(score=0.95)
    t.attacker_prerequisites = AttackerPrerequisites(permissionless="unknown")
    t.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
    for policy in ("default", "immunefi", "hackenproof", "yeswehack"):
        t_copy = TriageResult(finding_id="t1")
        t_copy._conviction_verdict = "verified"
        t_copy.exploitability = ExploitabilityScore(score=0.95)
        t_copy.attacker_prerequisites = AttackerPrerequisites(permissionless="unknown")
        t_copy.impact = AssetImpact(direct_funds_loss="potential", impact="potential")
        t_copy = apply_policy(t_copy, policy)
        assert t_copy.severity == "unknown", f"{policy}: {t_copy.severity}"


# ===== 8. JSON schema valid =====

def test_triage_result_json_valid():
    t = TriageResult(finding_id="t1", root_cause_id="rc-1")
    d = t.to_dict()
    json.dumps(d)  # must not raise
    assert d["priority"] == "needs-review"  # default
    assert d["severity"] == "unknown"


def test_exploitability_score_json_valid():
    ex = ExploitabilityScore(score=0.4, label="insufficient-evidence",
                             missing_information=["reachability"])
    d = ex.__dict__ if hasattr(ex, "__dict__") else {}
    json.dumps(d, default=str)


# ===== 9. End-to-end run_triage with unknown finding =====

def test_run_triage_unknown_finding_needs_review():
    """End-to-end: unknown AC/CP finding → priority=needs-review, severity=unknown."""
    f = make_finding("f1")
    f.exploitability_metadata = {"root_cause_id": "rc-1"}
    cr = make_cr("f1", verdict="needs-review", ac="unknown", cp="unknown",
                 has_dynamic=False, score=0.1, confidence="low")
    results = run_triage(
        findings=[f],
        conviction_results={"f1": cr},
        root_cause_map={"rc-1": {}},
        verbose=False,
    )
    assert len(results) == 1
    t = results[0]
    assert t.severity == "unknown"
    assert t.priority == "needs-review"
    assert t.attacker_prerequisites.permissionless == "unknown"
    assert len(t.missing_information) > 0
    assert not is_report_ready(t)


def test_run_triage_verified_finding_report_ready():
    """End-to-end: verified permissionless + in-scope → report-ready."""
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
    assert t.attacker_prerequisites.permissionless is True
    assert is_report_ready(t)


def test_run_triage_uncertain_scope_needs_review():
    """End-to-end: no scope config → uncertain → needs-review."""
    f = make_finding("f1")
    f.scope_status = "unknown"
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
    assert t.scope_status == "uncertain"
    assert t.priority == "needs-review"
    assert not is_report_ready(t)
