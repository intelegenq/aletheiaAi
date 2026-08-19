"""Test: generated test compilation and reproduction.

Verifies that the generated Foundry test can compile and reproduce the finding.
"""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from aletheia.models import Finding, SourceLocation
from aletheia.analysis_wiring import load_analysis
from aletheia.testgen import generate_test, run_generated_test

TARGET_DIR = str(Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "dynamic_test")
VULN_SOL = TARGET_DIR + "/contracts/VulnerableVault.sol"


@pytest.fixture(scope="module")
def analysis():
    o = load_analysis(VULN_SOL)
    assert o.ok, o.error
    return o


def test_generated_test_compile_and_reproduce(analysis, tmp_path):
    """Generated test must compile and FAIL (reproducing the vulnerability)."""
    f = Finding(
        finding_id="testgen-1", engine="medusa", detector="medusa:finding",
        title="[FAILED] setOwner(address)", description="x",
        vulnerability_class="ownership-takeover", severity="high", confidence="medium",
        status="verified",
        source_location=SourceLocation(file="", line_start=0, line_end=0, contract=None, function=None),
        trace=["setOwner(0x0)"], evidence=["seq"], exploitability_metadata={},
    )
    r = generate_test(f, Path(tmp_path), target_dir=TARGET_DIR, analysis=analysis)
    assert r.get("generated"), f"not generated: {r.get('reason')}"
    tr = run_generated_test(r["test_path"], TARGET_DIR)
    assert tr.get("ran"), f"did not run: {tr.get('stderr')}"
    # Test must FAIL (reproduce the bug: unauthorized setOwner succeeds)
    assert tr.get("passed") is False, f"test passed unexpectedly: {tr.get('stdout')[-200:]}"


def test_generated_test_compile_for_guarded_rejects(tmp_path):
    """Generated test for a finding without analysis should be unsupported."""
    f = Finding(
        finding_id="testgen-2", engine="slither", detector="slither:finding",
        title="something", description="x",
        vulnerability_class="access-control-bypass", severity="high", confidence="medium",
        status="candidate",
        source_location=SourceLocation(file="", line_start=0, line_end=0, contract=None, function=None),
        trace=[], evidence=[], exploitability_metadata={},
    )
    r = generate_test(f, Path(tmp_path), target_dir=TARGET_DIR)  # no analysis
    assert r.get("generated") is False, "should not generate without analysis"
    assert "unsupported" in r.get("reason", "").lower()


def test_no_default_reachable(analysis):
    """Static finding without path evidence on a function that HAS analysis gets real verdict."""
    f = Finding(
        finding_id="nd-1", engine="slither", detector="slither:finding",
        title="unchecked something", description="x",
        vulnerability_class="", severity="high", confidence="medium",
        status="candidate",
        source_location=SourceLocation(
            file=VULN_SOL, line_start=25, line_end=25, contract="VulnerableVault", function="setOwner",
        ),
        trace=[], evidence=[], exploitability_metadata={},
    )
    from aletheia.conviction import ConvictionEngine
    engine = ConvictionEngine({f.finding_id: f}, analysis=analysis)
    cr = engine.evaluate(f.finding_id)
    # With analysis, verdict must be a real one — not unknown, not blindly reachable
    assert cr.call_path_verdict != "unknown", f"should resolve: {cr.reasons}"
    assert cr.call_path_verdict in ("reachable", "unreachable", "restricted-reachable")
    # Without dynamic evidence, cannot be verified
    assert cr.verdict != "verified", f"static only cant verify: {cr.verdict}"

    # Without analysis, verdict must be needs-review
    engine2 = ConvictionEngine({f.finding_id: f})
    cr2 = engine2.evaluate(f.finding_id)
    assert cr2.call_path_verdict == "unknown", "no analysis = unknown"
    assert cr2.verdict == "needs-review", f"no analysis = needs-review, got {cr2.verdict}"