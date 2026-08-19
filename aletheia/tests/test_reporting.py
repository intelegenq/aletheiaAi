from pathlib import Path

from aletheia.models import Finding, SourceLocation
from aletheia.reporting import generate_reports
from aletheia.triage import is_report_ready
from aletheia.triage_model import (
    AssetImpact, AttackerPrerequisites, ExploitabilityScore, TriageResult,
)


def _finding(fid="f-1"):
    return Finding(
        finding_id=fid,
        engine="foundry",
        title="Unauthorized owner takeover",
        description="An unprivileged caller can replace the owner.",
        vulnerability_class="access-control",
        source_location=SourceLocation(
            file="contracts/Vault.sol", line_start=24, line_end=24,
            contract="Vault", function="setOwner(address)",
        ),
        trace=["attacker calls setOwner(attacker)"],
        evidence=["Foundry test fails for unauthorized caller"],
    )


def _triage(fid="f-1", ready=True):
    t = TriageResult(
        finding_id=fid,
        root_cause_id="rc-1",
        priority="p1-high" if ready else "needs-review",
        severity="high" if ready else "unknown",
        confidence="high" if ready else "low",
        exploitability=ExploitabilityScore(score=1.0 if ready else 0.2),
        impact=AssetImpact(impact="potential", affected_assets=["admin/ownership state"], privilege_takeover=True),
        attacker_prerequisites=AttackerPrerequisites(permissionless=True),
        affected_assets=["admin/ownership state"],
        scope_status="in-scope" if ready else "uncertain",
    )
    t._conviction_verdict = "verified" if ready else "needs-review"
    return t


def test_report_only_contains_strictly_ready_findings(tmp_path: Path):
    reports = generate_reports([_finding()], [_triage(), _triage(ready=False)], tmp_path)
    assert len(reports) == 1
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "default.md").is_file()
    assert "Unauthorized owner takeover" in (tmp_path / "default.md").read_text()


def test_report_schema_does_not_fabricate_quantified_amount(tmp_path: Path):
    generate_reports([_finding()], [_triage()], tmp_path)
    text = (tmp_path / "report.json").read_text()
    assert '"quantified_amount": ""' in text
    assert '"impact": "quantified"' not in text
