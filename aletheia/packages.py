"""Submission-package rendering; deliberately no network submission capability."""
from __future__ import annotations
from pathlib import Path
import json
from .report_lint import lint
def build(run_dir:str|Path,platform:str="generic") -> dict:
    root=Path(run_dir); check=lint(root)
    if not check["ok"]: raise ValueError("report lint failed: "+"; ".join(check["errors"]))
    report=json.loads((root/"report.json").read_text()); out=root/"package"/platform; out.mkdir(parents=True,exist_ok=True)
    (out/"report.json").write_text(json.dumps(report,indent=2,sort_keys=True),encoding="utf-8")
    (out/"report.md").write_text(f"# {platform} security submission package\n\nLocal evidence only; no auto-submission.\n",encoding="utf-8")
    for name,body in {"reproduction.md":"Local reproduction evidence is indexed in report.json.\n","scope_proof.md":"Scope evidence is required by lint.\n","technical_timeline.md":"Static analysis -> local verification -> review.\n","limitations.md":"Claims are limited to recorded evidence.\n"}.items(): (out/name).write_text(body,encoding="utf-8")
    (out/"evidence_index.json").write_text(json.dumps({"findings":[x.get("finding_id") for x in report.get("findings",[])]},indent=2),encoding="utf-8")
    return {"path":str(out),"platform":platform,"auto_submission":False}
