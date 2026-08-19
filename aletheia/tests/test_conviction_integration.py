"""Integration tests — real analysis wiring into the Conviction Engine.

Uses the vulnerable and secure fixtures. Access control and reachability
verdicts come from AccessControlIndex / ReachabilityIndex — NOT heuristics.
"""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from aletheia.models import Finding, SourceLocation
from aletheia.analysis_wiring import load_analysis
from aletheia.conviction import ConvictionEngine
from aletheia.rootcause import correlate, resolve_function

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
VULN_SOL = str(FIXTURES / "dynamic_test" / "contracts" / "VulnerableVault.sol")
SECURE_SOL = str(FIXTURES / "secure_fixture" / "contracts" / "SecureVault.sol")
VULN_DIR = str(FIXTURES / "dynamic_test")
SECURE_DIR = str(FIXTURES / "secure_fixture")


@pytest.fixture(scope="module")
def vuln_analysis():
    o = load_analysis(VULN_SOL)
    assert o.ok, o.error
    return o


@pytest.fixture(scope="module")
def secure_analysis():
    o = load_analysis(SECURE_SOL)
    assert o.ok, o.error
    return o


def make_finding(fid, engine="slither", func="", contract="", title="",
                 file="", line=0, trace=None, evidence=None, vclass="",
                 meta=None):
    return Finding(
        finding_id=fid, engine=engine, detector=f"{engine}:finding",
        title=title or f"finding {fid}", description="desc",
        vulnerability_class=vclass, severity="high", confidence="medium",
        status="candidate",
        source_location=SourceLocation(file=file, line_start=line, line_end=line,
                                       contract=contract, function=func),
        trace=trace or [], evidence=evidence or [],
        exploitability_metadata=meta or {},
    )


# ---------------- real access-control ----------------

def test_ac_index_vulnerable_setowner_ungated(vuln_analysis):
    """AccessControlIndex says setOwner is unguarded."""
    ac = vuln_analysis.access_control.get("VulnerableVault.setOwner(address)")
    assert ac is not None
    assert ac["kind"] == "none"
    assert ac["effective"] is False


def test_ac_index_secure_setowner_restricted(secure_analysis):
    """AccessControlIndex says SecureVault.setOwner is guarded by onlyOwner."""
    ac = secure_analysis.access_control.get("SecureVault.setOwner(address)")
    assert ac is not None
    assert ac["kind"] == "only_owner"
    assert ac["effective"] is True
    assert ac["modifier_name"] == "onlyOwner"


def test_ac_index_secure_withdraw_ungated_view(secure_analysis):
    """deposit is a state-changing function with no guard (correct: anyone may deposit)."""
    ac = secure_analysis.access_control.get("SecureVault.deposit()")
    assert ac is not None
    assert ac["kind"] == "none"


def test_reachability_vulnerable_setowner_true(vuln_analysis):
    """setOwner is an external entry point."""
    rc = vuln_analysis.reachability.get("VulnerableVault.setOwner(address)")
    assert rc is not None
    assert rc["reachable"] is True
    assert rc["entry_point"] is True


def test_reachability_secure_internal_ownsurgery(secure_analysis):
    """_internalOwnerSurgery is not an entry point (internal-only)."""
    rc = secure_analysis.reachability.get("SecureVault._internalOwnerSurgery(address)")
    assert rc is not None
    assert rc["entry_point"] is False
    # It IS reachable through guarded publicOwnerChange.
    assert rc["reachable"] is True


# ---------------- conviction over vulnerable fixture ----------------

@pytest.mark.parametrize("finding_id,engine,title,trace,evidence", [
    ("fv-1", "foundry", "[FAIL] test_unauthorized_setOwner()",
     ["attacker setOwner(0xdeadbeef)"],
     ["Foundry failing test"]),
    ("fv-2", "echidna", "echidna_owner_unchanged: failed!💥",
     ["callsequence: attack_setOwner(0x0)"],
     ["Echidna property failure"]),
    ("fv-3", "medusa", "[FAILED] Assertion Test: setOwner(address)",
     ["setOwner(address)(0x0)"],
     ["Medusa assertion failure"]),
])
def test_vulnerable_fixture_verified(vuln_analysis, finding_id, engine, title, trace, evidence):
    """All dynamic-engine setOwner findings on the vulnerable fixture → verified."""
    f = make_finding(finding_id, engine=engine, func="setOwner",
                     contract="VulnerableVault", title=title,
                     trace=trace, evidence=evidence)
    engine = ConvictionEngine({f.finding_id: f}, analysis=vuln_analysis)
    cr = engine.evaluate(f.finding_id)
    assert cr.verdict == "verified", f"{finding_id}: {cr.verdict} reasons={cr.reasons}"
    assert cr.access_control_verdict == "ungated"
    assert cr.call_path_verdict == "reachable"


def test_vulnerable_static_without_dynamic(vuln_analysis):
    """Static finding on vulnerable setOwner but NO runtime proof → needs-dynamic-validation."""
    f = make_finding("fv-4", engine="slither", func="setOwner",
                     contract="VulnerableVault", title="unguarded setOwner")
    engine = ConvictionEngine({f.finding_id: f}, analysis=vuln_analysis)
    cr = engine.evaluate(f.finding_id)
    assert cr.verdict == "needs-dynamic-validation", f"got {cr.verdict} reasons={cr.reasons}"
    assert cr.access_control_verdict == "ungated"
    assert cr.call_path_verdict == "reachable"


# ---------------- conviction over secure fixture ----------------

@pytest.mark.parametrize("fid,func", [
    ("sf-1", "setOwner"),
    ("sf-2", "withdrawFrom"),
    ("sf-3", "setPaused"),
])
def test_secure_guarded_functions_rejected(secure_analysis, fid, func):
    """Guarded functions on the secure fixture must be rejected."""
    f = make_finding(fid, engine="slither", func=func, contract="SecureVault",
                     title=f"possible unauthorized {func}")
    engine = ConvictionEngine({f.finding_id: f}, analysis=secure_analysis)
    cr = engine.evaluate(f.finding_id)
    assert cr.verdict == "rejected", f"{fid}: {cr.verdict} reasons={cr.reasons}"
    assert cr.access_control_verdict == "restricted"
    assert any("guard" in r or "AccessControlIndex" in r for r in cr.rejected_because), cr.rejected_because


def test_secure_withdraw_not_rejected(secure_analysis):
    """withdraw is unguarded but only affects caller's own balance → not verified."""
    f = make_finding("sf-4", engine="slither", func="withdraw", contract="SecureVault",
                     title="withdraw reentrancy risk")
    engine = ConvictionEngine({f.finding_id: f}, analysis=secure_analysis)
    cr = engine.evaluate(f.finding_id)
    # deposit/withdraw write balances but only caller's own → asset impact not
    # cross-user; verdict must NOT be verified; not rejected either (no proof).
    assert cr.verdict != "verified", f"got {cr.verdict}"
    assert cr.access_control_verdict == "ungated"
    assert cr.call_path_verdict == "reachable"


def test_secure_internal_surgery_not_verified(secure_analysis):
    """_internalOwnerSurgery is internal-only with a guard on the entry path."""
    f = make_finding("sf-5", engine="slither", func="_internalOwnerSurgery",
                     contract="SecureVault", title="owner write in internal fn")
    engine = ConvictionEngine({f.finding_id: f}, analysis=secure_analysis)
    cr = engine.evaluate(f.finding_id)
    # Resolves as reachable only through guarded publicOwnerChange → restricted-reachable.
    assert cr.verdict != "verified"
    assert cr.call_path_verdict == "restricted-reachable"


# ---------------- cross-engine root-cause correlation ----------------

def test_cross_engine_correlation_merges_setowner(vuln_analysis):
    """Foundry + Medusa + Echidna + Slither findings → ONE root cause."""
    foundry = make_finding("cc-1", engine="foundry", func="setOwner", contract="VulnerableVault",
                           title="[FAIL] test_unauthorized_setOwner()",
                           trace=["attacker setOwner(0x1)"])
    medusa = make_finding("cc-2", engine="medusa", func="setOwner", contract="VulnerableVault",
                          title="[FAILED] setOwner(address)",
                          trace=["setOwner(address)(0x0)"])
    echidna = make_finding("cc-3", engine="echidna", func="setOwner", contract="VulnerableVault",
                           title="echidna_owner_unchanged failed",
                           trace=["attack_setOwner(0x0)"])
    slither = make_finding("cc-4", engine="slither", func="setOwner", contract="VulnerableVault",
                           title="unguarded setOwner", file=VULN_SOL, line=25)

    merged, rc_map = correlate([foundry, medusa, echidna, slither], vuln_analysis)
    assert len(merged) == 1, f"Expected 1 root cause, got {len(merged)}"
    rc = rc_map[merged[0].exploitability_metadata["root_cause_id"]]
    assert rc["evidence_count"] == 4
    assert set(rc["corroborating_engines"]) == {"foundry", "medusa", "echidna", "slither"}
    assert rc["function"] == "VulnerableVault.setOwner(address)"
    assert rc["resolved"] is True


def test_correlation_does_not_merge_different_functions(vuln_analysis):
    """setOwner vs withdrawFrom are different root causes."""
    a = make_finding("nc-1", engine="foundry", func="setOwner", contract="VulnerableVault",
                     title="test_unauthorized_setOwner",
                     trace=["setOwner(0x1)"])
    b = make_finding("nc-2", engine="medusa", func="withdrawFrom", contract="VulnerableVault",
                     title="withdrawFrom unauthorized",
                     trace=["withdrawFrom(0x2, 100)"])
    merged, _ = correlate([a, b], vuln_analysis)
    assert len(merged) == 2


def test_no_default_reachable(vuln_analysis):
    """Static finding mapped to a real function gets a real verdict, never a blind default."""
    f = make_finding("nd-1", engine="slither", func="setOwner", contract="VulnerableVault",
                     title="something", file=VULN_SOL, line=25)
    engine = ConvictionEngine({f.finding_id: f}, analysis=vuln_analysis)
    cr = engine.evaluate(f.finding_id)
    assert cr.call_path_verdict != "unknown"  # resolved by real analysis
    assert cr.call_path_verdict in ("reachable", "unreachable", "restricted-reachable")

    # Without analysis the verdict must NEVER be reachable.
    f2 = make_finding("nd-2", engine="slither", func="setOwner", contract="VulnerableVault",
                      title="something", file=VULN_SOL, line=25)
    engine2 = ConvictionEngine({f2.finding_id: f2})  # no analysis
    cr2 = engine2.evaluate(f2.finding_id)
    assert cr2.call_path_verdict == "unknown"
    assert cr2.verdict != "verified"


def test_vulnerable_full_pipeline_verified(vuln_analysis):
    """Slither+Foundry+Echidna merged finding on vulnerable fixture → verified."""
    s = make_finding("pipe-1", engine="slither", func="setOwner", contract="VulnerableVault",
                     title="slither unguarded write", file=VULN_SOL, line=25)
    f = make_finding("pipe-2", engine="foundry", func="setOwner", contract="VulnerableVault",
                     title="[FAIL] test_unauthorized_setOwner",
                     trace=["attacker setOwner(0xdeadbeef)"])
    e = make_finding("pipe-3", engine="echidna", func="setOwner", contract="VulnerableVault",
                     title="echidna_owner_unchanged failed",
                     trace=["attack_setOwner(0x0)"])
    merged, _ = correlate([s, f, e], vuln_analysis)
    assert len(merged) == 1
    engine = ConvictionEngine(merged, analysis=vuln_analysis)
    cr = engine.evaluate(merged[0].finding_id)
    assert cr.verdict == "verified"
    assert cr.score >= 0.8
    assert cr.confidence == "high"
    assert cr.exploitability["asset_impact"] in ("potential",)
    assert "dynamic" in cr.evidence_summary["dynamic_engines"] or cr.evidence_summary["has_dynamic_evidence"]


def test_secure_fixture_scanned_finds_nothing_verified(secure_analysis):
    """A 'finding' on every secure function: NONE may be verified."""
    for func in ("setOwner", "withdrawFrom", "setPaused", "publicOwnerChange", "withdraw", "deposit"):
        f = make_finding(f"sec-{func}", engine="slither", func=func, contract="SecureVault",
                         title=f"finding on {func}")
        engine = ConvictionEngine({f.finding_id: f}, analysis=secure_analysis)
        cr = engine.evaluate(f.finding_id)
        assert cr.verdict != "verified", f"{func} must not be verified, got {cr.verdict}"