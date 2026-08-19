"""Durable audit workflow orchestration.

This module owns workflow state and recovery. Existing scanner, verification,
triage, and reporting engines remain the source of truth for their phases.
State writes are atomic so an interrupted process leaves the previous
checkpoint usable for resume.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


PHASES = ("ai_plan", "scan", "verify", "triage", "ai_review", "report")
TERMINAL = {"completed", "failed", "paused"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    os.replace(temp, path)


def _run_id(target: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    digest = hashlib.sha256(os.path.abspath(target).encode()).hexdigest()[:8]
    return f"{stamp}-{digest}"


@dataclass
class PhaseState:
    name: str
    status: str = "pending"
    attempts: int = 0
    started_at: str = ""
    completed_at: str = ""
    duration_sec: float = 0.0
    error: str = ""
    outputs: list[str] = field(default_factory=list)


@dataclass
class WorkflowState:
    schema_version: str = "aletheia.workflow.v1"
    run_id: str = ""
    target: str = ""
    run_dir: str = ""
    status: str = "created"
    current_phase: str = ""
    created_at: str = ""
    updated_at: str = ""
    budget_seconds: int = 0
    elapsed_seconds: float = 0.0
    policy: str = "default"
    platform: str = "default"
    options: dict[str, Any] = field(default_factory=dict)
    phases: dict[str, PhaseState] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["phases"] = {name: asdict(phase) for name, phase in self.phases.items()}
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkflowState":
        phases = {
            name: PhaseState(**value)
            for name, value in (data.get("phases") or {}).items()
        }
        for name in PHASES:
            phases.setdefault(name, PhaseState(name=name))
        fields = {k: data[k] for k in cls.__dataclass_fields__ if k != "phases" and k in data}
        return cls(phases=phases, **fields)


class WorkflowError(RuntimeError):
    pass


class AuditWorkflow:
    """Run a resumable scan → verify → triage → report workflow."""

    def __init__(
        self,
        target: str,
        *,
        run_dir: str | Path | None = None,
        run_id: str | None = None,
        policy: str = "default",
        platform: str = "default",
        budget_seconds: int = 0,
        options: dict[str, Any] | None = None,
    ):
        self.target = str(Path(target).resolve())
        self.run_id = run_id or _run_id(self.target)
        self.run_dir = Path(run_dir) if run_dir else Path("artifacts") / self.run_id
        self.state_path = self.run_dir / "workflow.json"
        self.manifest_path = self.run_dir / "artifact_manifest.json"
        self.policy = policy
        self.platform = platform
        self.budget_seconds = max(0, int(budget_seconds or 0))
        self.options = options or {}
        self.state = self._load_or_create()

    def _load_or_create(self) -> WorkflowState:
        if self.state_path.is_file():
            state = WorkflowState.from_dict(json.loads(self.state_path.read_text(encoding="utf-8")))
            if state.target and state.target != self.target:
                raise WorkflowError("run directory belongs to a different target")
            return state
        now = _now()
        state = WorkflowState(
            run_id=self.run_id, target=self.target, run_dir=str(self.run_dir),
            created_at=now, updated_at=now, budget_seconds=self.budget_seconds,
            policy=self.policy, platform=self.platform, options=self.options,
            phases={name: PhaseState(name=name) for name in PHASES},
        )
        self._save(state)
        return state

    def _save(self, state: WorkflowState | None = None) -> None:
        state = state or self.state
        state.updated_at = _now()
        _atomic_json(self.state_path, state.to_dict())

    def _elapsed(self) -> float:
        return max(0.0, time.time() - datetime.fromisoformat(self.state.created_at).timestamp())

    def _budget_exceeded(self) -> bool:
        return bool(self.state.budget_seconds and self._elapsed() >= self.state.budget_seconds)

    def _refresh_manifest(self) -> None:
        files = []
        if self.run_dir.exists():
            for path in sorted(self.run_dir.rglob("*")):
                if path.is_file() and path.name not in {"workflow.json", "artifact_manifest.json"}:
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    files.append({"path": str(path.relative_to(self.run_dir)), "bytes": path.stat().st_size, "sha256": digest})
        _atomic_json(self.manifest_path, {
            "schema_version": "aletheia.artifact-manifest.v1",
            "run_id": self.state.run_id,
            "updated_at": _now(),
            "artifacts": files,
        })

    def _phase_outputs(self) -> list[str]:
        if not self.run_dir.exists():
            return []
        return [str(p.relative_to(self.run_dir)) for p in sorted(self.run_dir.rglob("*")) if p.is_file()]

    def run_phase(self, name: str, action: Callable[[], Any], *, force: bool = False) -> bool:
        if name not in PHASES:
            raise WorkflowError(f"unknown workflow phase: {name}")
        phase = self.state.phases[name]
        if phase.status == "completed" and not force:
            return True
        if self._budget_exceeded():
            self.state.status = "paused"
            self.state.current_phase = name
            phase.status = "paused"
            phase.error = "workflow budget exhausted before phase started"
            self._save()
            return False

        self.run_dir.mkdir(parents=True, exist_ok=True)
        phase.status = "running"
        phase.attempts += 1
        phase.started_at = _now()
        phase.error = ""
        self.state.status = "running"
        self.state.current_phase = name
        self._save()
        started = time.time()
        try:
            result = action()
            if result is False:
                raise WorkflowError(f"phase {name} returned failure")
            phase.status = "completed"
            phase.completed_at = _now()
            phase.duration_sec = round(time.time() - started, 3)
            phase.outputs = self._phase_outputs()
            self._refresh_manifest()
            self._save()
            return True
        except Exception as exc:
            phase.status = "failed"
            phase.duration_sec = round(time.time() - started, 3)
            phase.error = str(exc)
            self.state.errors.append(f"{name}: {exc}")
            self.state.status = "failed"
            self._refresh_manifest()
            self._save()
            return False

    def run(self, *, resume: bool = True, retry_failed: bool = True) -> bool:
        """Execute remaining phases. Returns true only when all phases complete."""
        actions = {
            "ai_plan": self._ai_plan,
            "scan": self._scan,
            "verify": self._verify,
            "triage": self._triage,
            "ai_review": self._ai_review,
            "report": self._report,
        }
        for name in PHASES:
            phase = self.state.phases[name]
            if phase.status == "completed" and resume:
                continue
            if phase.status == "failed" and not retry_failed:
                return False
            if not self.run_phase(name, actions[name], force=not resume):
                return False
        self.state.status = "completed"
        self.state.current_phase = ""
        self.state.elapsed_seconds = round(self._elapsed(), 3)
        self._save()
        self._refresh_manifest()
        return all(self.state.phases[name].status == "completed" for name in PHASES)

    def _scan(self) -> bool:
        from .orchestrator import run_scan
        scanners = self.options.get("scanners", "all")
        if self.options.get("ai_routing", True) and scanners == "all":
            plan_path = self.run_dir / "ai_plan.json"
            if plan_path.is_file():
                plan = json.loads(plan_path.read_text(encoding="utf-8"))
                routed = (plan.get("scanner_plan") or {}).get("engines") or []
                if routed:
                    scanners = ",".join(routed)
        args = argparse.Namespace(
            target=self.target,
            scanners=scanners,
            no_build=bool(self.options.get("no_build", False)),
            output=str(self.run_dir),
            timeout=int(self.options.get("timeout", 600)),
            json=False, sarif=bool(self.options.get("sarif", False)),
            verify=False, triage=False, report=False,
            platform=self.platform, policy=self.policy,
            generate_tests=False, generate_poc=False,
        )
        return run_scan(args)

    def _ai_plan(self) -> bool:
        from .adapters.registry import ADAPTERS
        from .ai_orchestrator import create_plan, save_plan
        from .knowledge import KnowledgeBase
        available = []
        for engine in ADAPTERS:
            if shutil.which(engine):
                available.append(engine)
                continue
            if engine == "slither":
                venv_slither = Path(sys.executable).parent / "slither"
                if venv_slither.is_file():
                    available.append(engine)
        # Keep the planner honest: an adapter can exist in code while its
        # executable is absent from this runtime. Such engines are skipped and
        # can be enabled automatically on the next run after installation.
        plan = create_plan(self.target, available_engines=available, knowledge_base=KnowledgeBase())
        save_plan(plan, self.run_dir / "ai_plan.json")
        from .spec_compiler import compile_catalog
        catalog = compile_catalog(KnowledgeBase(), available_engines=available)
        (self.run_dir / "spec_execution_catalog.json").write_text(
            json.dumps([item.to_dict() for item in catalog], indent=2), encoding="utf-8"
        )
        return True

    def _verify(self) -> bool:
        from .verify import load_findings_from_run, run_verification
        findings = load_findings_from_run(self.run_dir)
        if not (self.run_dir / "findings.json").is_file():
            raise WorkflowError("scan did not produce findings.json")
        manifest = json.loads((self.run_dir / "run_manifest.json").read_text(encoding="utf-8"))
        result = run_verification(
            findings=findings, run_dir=self.run_dir, target_dir=manifest.get("target", self.target),
            generate_tests=bool(self.options.get("generate_tests", False)),
            generate_pocs=bool(self.options.get("generate_poc", False)),
            fork_config={
                "rpc_url": os.environ.get("ALETHEIA_RPC_URL", ""),
                "chain_id": os.environ.get("ALETHEIA_CHAIN_ID", ""),
                "block_number": os.environ.get("ALETHEIA_FORK_BLOCK", ""),
            }, verbose=True,
        )
        # Keep the result available for the next phase and for resume.
        (self.run_dir / "workflow_verification.json").write_text(
            json.dumps({"finding_ids": [f.finding_id for f in result.get("findings", [])]}, indent=2), encoding="utf-8"
        )
        return True

    def _triage(self) -> bool:
        from .triage import run_triage_from_run, bucket_triage_results
        from .verify import load_findings_from_run
        if not load_findings_from_run(self.run_dir):
            for name in ("triage.json", "report-ready-findings.json", "needs-review.json", "out-of-scope.json"):
                (self.run_dir / name).write_text("[]\n", encoding="utf-8")
            return True
        results = run_triage_from_run(self.run_dir, policy_name=self.policy, verbose=True)
        (self.run_dir / "triage.json").write_text(json.dumps([t.to_dict() for t in results], indent=2, default=str), encoding="utf-8")
        report_ready, needs_review, out_of_scope = bucket_triage_results(results)
        (self.run_dir / "report-ready-findings.json").write_text(json.dumps(report_ready, indent=2, default=str), encoding="utf-8")
        (self.run_dir / "needs-review.json").write_text(json.dumps(needs_review, indent=2, default=str), encoding="utf-8")
        (self.run_dir / "out-of-scope.json").write_text(json.dumps(out_of_scope, indent=2, default=str), encoding="utf-8")
        return True

    def _report(self) -> bool:
        from .reporting import generate_reports
        from .verify import load_findings_from_run
        from .triage import run_triage_from_run
        findings = load_findings_from_run(self.run_dir)
        if not findings:
            generate_reports([], [], self.run_dir, policy=self.policy, platform=self.platform)
            return True
        results = run_triage_from_run(self.run_dir, policy_name=self.policy, verbose=False)
        generate_reports(findings, results, self.run_dir, policy=self.policy, platform=self.platform)
        return True

    def _ai_review(self) -> bool:
        from .ai_orchestrator import build_verification_plan, read_evidence, resolve_contradictions
        from .verify import load_findings_from_run
        findings = load_findings_from_run(self.run_dir)
        conviction_payload = {}
        conviction_path = self.run_dir / "conviction.json"
        if conviction_path.is_file():
            conviction_payload = json.loads(conviction_path.read_text(encoding="utf-8"))
        evidence = read_evidence(self.run_dir)
        review = {
            "schema_version": "aletheia.ai-review.v1",
            "verification_plans": [asdict(build_verification_plan(f)) for f in findings],
            "contradictions": resolve_contradictions(findings, conviction_payload),
            "evidence_counts": {
                "findings": len(evidence.get("findings", [])),
                "conviction": len(evidence.get("conviction", [])),
                "triage": len(evidence.get("triage", [])),
                "artifacts": len(evidence.get("artifacts", [])),
            },
            "verdict_authority": "conviction-and-triage-artifacts; AI review cannot promote findings",
        }
        (self.run_dir / "ai_review.json").write_text(json.dumps(review, indent=2), encoding="utf-8")
        return True


def resume_audit(run_dir: str | Path, *, retry_failed: bool = True) -> bool:
    """Resume a persisted workflow from its checkpoint."""
    path = Path(run_dir) / "workflow.json"
    if not path.is_file():
        raise WorkflowError(f"workflow checkpoint not found: {path}")
    state = WorkflowState.from_dict(json.loads(path.read_text(encoding="utf-8")))
    workflow = AuditWorkflow(
        state.target, run_dir=state.run_dir, run_id=state.run_id,
        policy=state.policy, platform=state.platform,
        budget_seconds=state.budget_seconds, options=state.options,
    )
    return workflow.run(resume=True, retry_failed=retry_failed)
