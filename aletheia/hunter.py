"""Bounded planning, fusion, and local-only reproduction contracts."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from pathlib import Path
import json, os, subprocess, time
from .attack_surface import build
from .verify import load_findings_from_run

@dataclass
class StructuredCompletion: hypotheses:list=field(default_factory=list); priority_targets:list=field(default_factory=list); required_semantic_checks:list=field(default_factory=list); candidate_invariants:list=field(default_factory=list); proposed_tests:list=field(default_factory=list); contradictory_evidence:list=field(default_factory=list); unknowns:list=field(default_factory=list); reasoning_summary:list=field(default_factory=list)
class LLMProvider:
    def complete(self, payload:dict)->dict: raise NotImplementedError
class DeterministicPlanner(LLMProvider):
    def complete(self,payload):
        surface=payload.get("attack_surface",{}); return asdict(StructuredCompletion(priority_targets=[x.get("name","") for x in surface.get("entry_points",[])][:20],required_semantic_checks=[x.get("kind","") for x in surface.get("trust_boundaries",[])][:20],unknowns=["No LLM provider configured; hypotheses are rule-derived."],reasoning_summary=["Deterministic evidence-first fallback."]))
def validate_completion(data:dict)->StructuredCompletion:
    allowed=set(StructuredCompletion.__dataclass_fields__)
    if set(data)-allowed or any(not isinstance(data.get(k,[]),list) for k in allowed): raise ValueError("invalid structured planner response")
    return StructuredCompletion(**{k:data.get(k,[]) for k in allowed})
def plan(target:str|Path, output:str|Path) -> dict:
    surface=build(target); provider=DeterministicPlanner(); raw=provider.complete({"target_identity":str(target),"chain":surface["chain_family"],"ecosystem":surface["ecosystem"],"attack_surface":surface,"redaction":"no credentials/source dump"}); result=asdict(validate_completion(raw)); result.update({"schema_version":"aletheia.audit-plan.v1","provider":"deterministic","attack_surface":surface,"limitations":["Planner cannot create findings or alter verdicts."]}); out=Path(output); out.mkdir(parents=True,exist_ok=True); (out/"audit_plan.json").write_text(json.dumps(result,indent=2,sort_keys=True),encoding="utf-8"); return result
@dataclass
class InvariantCandidate: name:str; source_references:list[str]; rationale:str
@dataclass
class TestPlan: finding_id:str; ecosystem:str; sandbox:str; command:list[str]; limitations:list[str]
@dataclass
class ReproductionPlan: finding_id:str; sandbox:str="local-only"; command:list[str]=field(default_factory=list); limitations:list[str]=field(default_factory=list)
def reproduction_plan(run_dir:str|Path,finding_id:str)->dict:
    f=next((x for x in load_findings_from_run(Path(run_dir)) if x.finding_id==finding_id),None)
    if not f: raise ValueError("finding not found")
    plan=ReproductionPlan(finding_id,f"{f.ecosystem}-local-sandbox",[],["No command is run unless a local chain-native harness is configured.","No production or broadcast action is permitted."])
    path=Path(run_dir)/"reproduction"/finding_id; path.mkdir(parents=True,exist_ok=True); (path/"plan.json").write_text(json.dumps(asdict(plan),indent=2,sort_keys=True),encoding="utf-8"); return asdict(plan)
def fuse(run_dir:str|Path)->dict:
    findings=load_findings_from_run(Path(run_dir)); items=[]
    for f in findings:
        items.append({"finding_id":f.finding_id,"source_confidence":"partial" if f.source_location.file else "unknown","semantic_confidence":"partial" if f.semantic_evidence else "unknown","attacker_control_confidence":f.attacker_control,"reachability_confidence":"unknown","impact_confidence":"unknown","reproduction_confidence":"none","scope_confidence":f.scope_status,"false_positive_risk":"high" if f.status in {"candidate","needs-review"} else "unknown","overall_priority":"needs-human-review","verification_status":f.verification_status})
    data={"schema_version":"aletheia.finding-fusion.v1","findings":items,"contradictions":[],"needs_human_review":[x["finding_id"] for x in items if x["verification_status"]!="verified"]}; out=Path(run_dir)
    for name,value in {"evidence_graph.json":data,"finding_fusion.json":data,"priority_queue.json":items,"contradictions.json":[],"needs_human_review.json":data["needs_human_review"]}.items(): (out/name).write_text(json.dumps(value,indent=2,sort_keys=True),encoding="utf-8")
    return data
