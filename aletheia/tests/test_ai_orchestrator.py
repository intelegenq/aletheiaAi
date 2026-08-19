from __future__ import annotations

import json
from pathlib import Path

from aletheia.ai_orchestrator import (
    build_hypotheses, build_project_context, build_scanner_plan,
    classify_project, create_plan, read_evidence, resolve_contradictions,
)
from aletheia.intake import intake
from aletheia.models import Finding, SourceLocation


FIXTURE = Path(__file__).parent / "fixtures" / "dynamic_test"


def test_context_and_classification_are_deterministic():
    context = build_project_context(intake(str(FIXTURE), with_build=False, solc_switch=False))
    classifications = classify_project(context)
    assert context.language == "solidity"
    assert context.source_hash
    assert classifications
    assert any(c.category in {"token", "generic-evm"} for c in classifications)


def test_hypotheses_route_to_available_engines_only():
    context = build_project_context(intake(str(FIXTURE), with_build=False, solc_switch=False))
    hypotheses = build_hypotheses(classify_project(context))
    plan = build_scanner_plan(hypotheses, ["slither", "foundry"])
    assert "slither" in plan.engines
    assert all(engine in {"slither", "foundry"} for engine in plan.engines)
    assert all(h.hypothesis_id.startswith("hyp-") for h in hypotheses)


def test_full_plan_has_safe_assumptions_and_limitations():
    plan = create_plan(str(FIXTURE), available_engines=["slither", "foundry", "medusa"])
    payload = plan.to_dict()
    assert payload["schema_version"] == "aletheia.ai-plan.v1"
    assert "Hypotheses are candidates, not security verdicts" in payload["assumptions"]
    assert payload["scanner_plan"]["engines"]


def test_evidence_reader_does_not_require_all_artifacts(tmp_path: Path):
    (tmp_path / "findings.json").write_text(json.dumps({"findings": []}))
    evidence = read_evidence(tmp_path)
    assert evidence["findings"] == []
    assert evidence["conviction"] == []


def test_contradiction_resolver_reports_without_changing_finding():
    finding = Finding(
        finding_id="f-1", engine="foundry", title="dynamic", status="candidate",
        source_location=SourceLocation(file="Vault.sol", line_start=1),
    )
    contradictions = resolve_contradictions(
        [finding], {"results": [{"finding_id": "f-1", "verdict": "rejected"}]}
    )
    assert contradictions[0]["action"] == "manual-review"
    assert finding.status == "candidate"
