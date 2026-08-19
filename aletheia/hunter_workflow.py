"""Local-only end-to-end hunter orchestration; never submits externally."""
from __future__ import annotations
from pathlib import Path
import json, time
from . import programs
from .attack_surface import write
from .hunter import plan, fuse
from .orchestrator import run_scan

def hunt(program_id:str,target:str,output:str|None=None)->dict:
    program=programs.load(program_id); scope,evidence=programs.explain(program,target)
    if scope != "in-scope": return {"status":"blocked","reason":"target is not explicitly in scope","scope_status":scope,"scope_evidence":evidence}
    out=Path(output or Path("artifacts")/f"hunt-{int(time.time())}"); out.mkdir(parents=True,exist_ok=True)
    (out/"scope_snapshot.json").write_text(json.dumps(program.to_dict(),indent=2,sort_keys=True),encoding="utf-8")
    surface=write(target,out); plan(target,out)
    class Args: pass
    a=Args(); a.target=target; a.scanners="all"; a.timeout=600; a.no_build=True; a.output=str(out); a.json=False; a.sarif=True; a.verify=False; a.triage=False; a.report=False; a.platform="default"; a.policy=program.policy.severity_policy; a.generate_tests=False; a.generate_poc=False; a.chain=""; a.ecosystem=""
    scanned=run_scan(a); fusion=fuse(out) if (out/"findings.json").is_file() else {"findings":[]}
    return {"status":"completed" if scanned else "failed","run_dir":str(out),"scope_status":scope,"scope_evidence":evidence,"candidate_count":len(fusion.get("findings",[])),"auto_submission":False}
def status(run_dir:str)->dict:
    root=Path(run_dir); return {"run_dir":str(root),"artifacts":[p.name for p in sorted(root.iterdir()) if p.is_file()]}
def queue(run_dir:str)->dict:
    path=Path(run_dir)/"needs_human_review.json"; return json.loads(path.read_text()) if path.exists() else {"items":[]}
def explain(run_dir:str,finding_id:str)->dict:
    path=Path(run_dir)/"finding_fusion.json"; data=json.loads(path.read_text()) if path.exists() else {"findings":[]}; return next((x for x in data["findings"] if x["finding_id"]==finding_id),{"finding_id":finding_id,"status":"not-found"})
