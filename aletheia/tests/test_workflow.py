from __future__ import annotations

import json
from pathlib import Path

from aletheia.workflow import AuditWorkflow, WorkflowState, PhaseState, PHASES


def test_checkpoint_is_atomic_and_resume_skips_completed(tmp_path: Path):
    run_dir = tmp_path / "run"
    workflow = AuditWorkflow("target", run_dir=run_dir)
    calls = []

    assert workflow.run_phase("scan", lambda: calls.append("scan") or True)
    assert workflow.run_phase("verify", lambda: calls.append("verify") or True)
    for name in ("ai_plan", "triage", "ai_review", "report"):
        workflow.state.phases[name].status = "completed"
    workflow._save()
    assert workflow.run(resume=True)
    assert calls == ["scan", "verify"]
    state = json.loads((run_dir / "workflow.json").read_text())
    assert state["phases"]["scan"]["status"] == "completed"
    assert state["phases"]["scan"]["attempts"] == 1
    assert (run_dir / "artifact_manifest.json").is_file()


def test_failed_phase_can_retry_and_records_attempts(tmp_path: Path):
    workflow = AuditWorkflow("target", run_dir=tmp_path / "run")
    attempts = {"n": 0}

    def flaky():
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("temporary failure")
        return True

    assert not workflow.run_phase("scan", flaky)
    assert workflow.state.phases["scan"].status == "failed"
    assert workflow.run_phase("scan", flaky)
    assert workflow.state.phases["scan"].attempts == 2
    assert workflow.state.phases["scan"].status == "completed"


def test_budget_pauses_before_phase(tmp_path: Path):
    workflow = AuditWorkflow("target", run_dir=tmp_path / "run", budget_seconds=1)
    workflow.state.created_at = "2000-01-01T00:00:00+00:00"
    assert not workflow.run_phase("scan", lambda: True)
    assert workflow.state.status == "paused"
    assert workflow.state.phases["scan"].status == "paused"


def test_state_roundtrip_preserves_all_phases(tmp_path: Path):
    workflow = AuditWorkflow("target", run_dir=tmp_path / "run")
    restored = WorkflowState.from_dict(json.loads((tmp_path / "run" / "workflow.json").read_text()))
    assert set(restored.phases) == set(PHASES)
    assert all(isinstance(value, PhaseState) for value in restored.phases.values())
