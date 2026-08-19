"""Conviction engine tests — source verification, AC verdict, call-path, correlation, exploitability, FP rejection."""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aletheia.models import Finding, SourceLocation
from aletheia.conviction import ConvictionEngine, ConvictionResult


def make_finding(fid: str, engine: str = "slither", func: str = "setOwner",
                 file: str = "contracts/VulnerableVault.sol", line: int = 25,
                 title: str = "", vuln_class: str = "",
                 trace: list[str] = None, evidence: list[str] = None,
                 meta: dict = None, status: str = "candidate",
                 contract: str = "VulnerableVault") -> Finding:
    return Finding(
        finding_id=fid,
        engine=engine,
        detector=f"{engine}:finding",
        title=title or f"Something wrong in {func}",
        description=f"Finding in {func}",
        vulnerability_class=vuln_class,
        severity="high",
        confidence="medium",
        status=status,
        source_location=SourceLocation(
            file=file, line_start=line, line_end=line,
            contract=contract, function=func,
        ),
        trace=trace or [],
        evidence=evidence or [],
        exploitability_metadata=meta or {},
    )


def test_source_verification_valid():
    """Source location points to a real file."""
    f = make_finding("al-001", file="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test/contracts/VulnerableVault.sol", line=25)
    engine = ConvictionEngine({f.finding_id: f}, target_dir="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test")
    cr = engine.evaluate(f.finding_id)
    assert cr.source_verified, f"Source should be valid: {cr.reasons}"


def test_source_verification_invalid():
    """Source file does not exist."""
    f = make_finding("al-002", file="/nonexistent/contract.sol", line=1)
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    assert not cr.source_verified
    assert "not found" in " ".join(cr.reasons).lower()


def test_source_verification_line_overflow():
    """Line number exceeds file length."""
    f = make_finding("al-003", file="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test/contracts/VulnerableVault.sol", line=9999)
    engine = ConvictionEngine({f.finding_id: f}, target_dir="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test")
    cr = engine.evaluate(f.finding_id)
    assert not cr.source_verified


def test_ac_ungated_dynamic():
    """Dynamic engine finding without real analysis → unknown (no heuristic guessing)."""
    f = make_finding("al-004", engine="foundry", func="test_unauthorized_setOwner",
                      title="[FAIL] test_unauthorized_setOwner()",
                      trace=["attacker called setOwner(0xdead)"])
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    # Without real analysis, AC verdict must be unknown — never guess from title
    assert cr.access_control_verdict == "unknown", f"Expected unknown got {cr.access_control_verdict}"
    assert cr.verdict != "verified"


def test_ac_ungated_medusa():
    """Medusa finding without real analysis → unknown."""
    f = make_finding("al-005", engine="medusa",
                      title="[FAILED] Assertion Test: VulnerableVault.setOwner(address)",
                      trace=["1) VulnerableVault.setOwner(address)(0x0)"])
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    assert cr.access_control_verdict == "unknown", f"Expected unknown got {cr.access_control_verdict}"


def test_ac_restricted_static():
    """Static finding without real analysis → unknown (heuristic from title removed)."""
    f = make_finding("al-006", engine="slither", func="setOwner",
                      title="Potential privilege escalation: onlyOwner not enforced")
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    # Engine no longer uses title heuristics — must be unknown without analysis
    assert cr.access_control_verdict == "unknown", f"Expected unknown got {cr.access_control_verdict}"


def test_ac_unknown_no_match():
    """Finding without real analysis → unknown."""
    f = make_finding("al-007", engine="slither", func="deposit", title="Unchecked math")
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    assert cr.access_control_verdict == "unknown", f"Expected unknown got {cr.access_control_verdict}"


def test_call_path_reachable_dynamic():
    """Dynamic engine finding without real analysis → unknown (no default reachable)."""
    f = make_finding("al-008", engine="foundry", trace=["call sequence"])
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    assert cr.call_path_verdict == "unknown", f"Expected unknown got {cr.call_path_verdict}"
    assert cr.verdict != "verified"


def test_call_path_reachable_static_with_func():
    """Static finding without real analysis → unknown (no default reachable)."""
    f = make_finding("al-009", engine="slither", func="withdrawFrom")
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    assert cr.call_path_verdict == "unknown", f"Expected unknown got {cr.call_path_verdict}"


def test_evidence_correlation():
    """Cross-engine evidence correlation works."""
    f = make_finding("al-010", engine="foundry")
    f.corroborating_engines = ["medusa", "echidna"]
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    assert "foundry" in cr.corroborating_engines
    assert "medusa" in cr.corroborating_engines
    assert cr.evidence_summary["has_dynamic_evidence"]


def test_exploitability_assessment_owner():
    """setOwner finding without real analysis → asset_impact = unknown."""
    f = make_finding("al-011", engine="foundry", func="setOwner",
                      trace=["call sequence"])
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    # Without real analysis, no state variables known → unknown
    assert cr.exploitability["asset_impact"] == "unknown"


def test_verified_finding():
    """A finding with all evidence should be verified."""
    f = make_finding("al-012", engine="foundry", func="setOwner",
                      file="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test/contracts/VulnerableVault.sol",
                      line=25, trace=["attacker called setOwner(0x0)"],
                      title="[FAIL] test_unauthorized_setOwner()")
    f.corroborating_engines = ["medusa", "echidna"]
    engine = ConvictionEngine({f.finding_id: f}, target_dir="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test")
    cr = engine.evaluate(f.finding_id)
    assert cr.verdict == "verified", f"Expected verified got {cr.verdict} (score={cr.score})"
    assert cr.score >= 0.6


def test_rejected_unreachable():
    """Finding with explicit unreachable metadata AND no analysis → needs-review (unknown)."""
    f = make_finding("al-013", engine="slither", func="internalOnly",
                      file="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test/contracts/VulnerableVault.sol",
                      line=10,
                      meta={"reachability": "unreachable"})
    engine = ConvictionEngine({f.finding_id: f}, target_dir="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test")
    cr = engine.evaluate(f.finding_id)
    # Real analysis wins over metadata: without an analysis outcome the engine
    # must not trust freeform metadata — verdict stays needs-review.
    assert cr.verdict in ("needs-review", "needs-dynamic-validation"), f"Got {cr.verdict}"


def test_rejected_invalid_source():
    """Static finding with invalid source should be rejected."""
    f = make_finding("al-014", engine="slither", file="/dev/null/nope.sol", line=1)
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    assert cr.verdict == "rejected", f"Expected rejected got {cr.verdict}"
    assert "source" in " ".join(cr.rejected_because).lower()


def test_dynamic_unresolved_not_rejected():
    """Dynamic finding (echidna) that can't be mapped → needs-review, NOT rejected."""
    f = make_finding("al-099", engine="echidna", func="echidna_vault_not_empty",
                     file="", title="echidna_vault_not_empty: failed!",
                     vuln_class="", meta={})
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    assert cr.verdict == "needs-review", f"Expected needs-review got {cr.verdict}"
    assert "rejected" not in cr.verdict
    assert "could not be mapped" in " ".join(cr.reasons).lower()
    # Also test medusa and foundry
    for eng in ("medusa", "foundry"):
        f2 = make_finding(f"al-0{eng}1", engine=eng, func="test_foo",
                         file="", title="[FAIL] test_foo()", vuln_class="", meta={})
        cr2 = ConvictionEngine({f2.finding_id: f2}).evaluate(f2.finding_id)
        assert cr2.verdict == "needs-review", f"{eng}: expected needs-review got {cr2.verdict}"


def test_rejected_restricted():
    """Finding with effective AC guard on REAL analysis → rejected."""
    from aletheia.tests.test_conviction_integration import SECURE_SOL
    # Use the integration fixtures so this uses the real analysis
    f = make_finding("al-015", engine="slither", func="setOwner",
                      contract="SecureVault",
                      file=SECURE_SOL, line=24,
                      title="OnlyOwner pattern not enforced in setOwner")
    from aletheia.analysis_wiring import load_analysis
    analysis = load_analysis(SECURE_SOL)
    assert analysis.ok
    engine = ConvictionEngine({f.finding_id: f}, analysis=analysis)
    cr = engine.evaluate(f.finding_id)
    # Real analysis: SecureVault.setOwner has effective onlyOwner → rejected
    assert cr.verdict == "rejected", f"Expected rejected got {cr.verdict}"


def test_needs_review_low_evidence():
    """Finding with only static evidence and no trace should be needs-review or needs-dynamic."""
    f = make_finding("al-016", engine="slither", func="deposit",
                      title="Unchecked return value",
                      file="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test/contracts/VulnerableVault.sol",
                      line=15)
    engine = ConvictionEngine({f.finding_id: f}, target_dir="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test")
    cr = engine.evaluate(f.finding_id)
    assert cr.verdict in ("needs-review", "needs-dynamic-validation"), f"Got {cr.verdict}"


def test_verdict_confidence_high():
    """High-scoring finding should have high confidence."""
    f = make_finding("al-017", engine="foundry", func="withdrawFrom",
                      file="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test/contracts/VulnerableVault.sol",
                      line=30, trace=["attacker drained vault"],
                      title="[FAIL] test_withdrawFrom_onlySelf()")
    f.corroborating_engines = ["slither"]
    engine = ConvictionEngine({f.finding_id: f}, target_dir="/mnt/data/aletheiaAI/aletheia/tests/fixtures/dynamic_test")
    cr = engine.evaluate(f.finding_id)
    assert cr.verdict == "verified"
    assert cr.confidence == "high"


def test_checks_run_and_passed():
    """All 5 core checks should have run."""
    f = make_finding("al-018", engine="foundry", func="setOwner",
                      trace=["call sequence"])
    engine = ConvictionEngine({f.finding_id: f})
    cr = engine.evaluate(f.finding_id)
    for check in ["source_verification", "access_control_verdict", "call_path_reachability", "evidence_correlation", "exploitability"]:
        assert check in cr.checks_run, f"Check {check} not in checks_run"


def test_fork_simulation_skipped():
    """Fork simulation should be skipped by default."""
    from aletheia.fork_sim import ForkSimulator
    sim = ForkSimulator({})
    assert not sim.available()
    result = sim.run()
    assert result.status == "skipped"
    assert "RPC" in result.reason or "unavailable" in result.reason