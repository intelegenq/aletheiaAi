from __future__ import annotations
import json
from pathlib import Path
from .verify import load_findings_from_run
def lint(run_dir:str|Path)->dict:
    root=Path(run_dir); findings={f.finding_id:f for f in load_findings_from_run(root)}; report=root/"report.json"; errors=[]
    if not report.exists(): return {"ok":False,"errors":["report.json missing"]}
    for item in json.loads(report.read_text()).get("findings",[]):
        f=findings.get(item.get("finding_id"));
        if not f or f.status!="verified" or f.verification_status!="verified": errors.append(f"{item.get('finding_id')}: not verified")
        elif not f.source_location.file or not f.semantic_evidence: errors.append(f"{f.finding_id}: missing source/semantic evidence")
        elif f.scope_status!="in-scope": errors.append(f"{f.finding_id}: scope is not in-scope")
        elif not f.evidence: errors.append(f"{f.finding_id}: reproduction/evidence missing")
        if "TODO" in json.dumps(item) or "unknown" in json.dumps(item).lower(): errors.append(f"{item.get('finding_id')}: placeholder claim")
    return {"ok":not errors,"errors":errors}
