"""Local, evidence-backed bug bounty program and scope registry."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from pathlib import Path
import hashlib, json, re
from .targeting import compute_identity

@dataclass
class ProgramPolicy: name:str="default"; severity_policy:str="default"; submission_requirements:list[str]=field(default_factory=list)
@dataclass
class ScopeRule: pattern:str; status:str="in-scope"; evidence:str=""
@dataclass
class ExclusionRule: pattern:str; reason:str
@dataclass
class ScopeAsset:
    program_name:str; platform:str; asset_identifier:str; repository:str=""; chain_family:str="unknown"; ecosystem:str="unknown"; branch:str="main"; commit_sha:str=""; in_scope_status:str="uncertain"; scope_evidence:str=""; exclusions:list[ExclusionRule]=field(default_factory=list); severity_policy:str="default"; submission_requirements:list[str]=field(default_factory=list); source_provenance:dict=field(default_factory=dict)
@dataclass
class AssetRepository: locator:str; commit_sha:str=""; provenance:dict=field(default_factory=dict)
@dataclass
class AuditTarget: program_id:str; locator:str; identity:dict; scope_status:str; scope_evidence:str
@dataclass
class BugBountyProgram:
    program_id:str; name:str; platform:str="generic"; policy:ProgramPolicy=field(default_factory=ProgramPolicy); rules:list[ScopeRule]=field(default_factory=list); assets:list[ScopeAsset]=field(default_factory=list)
    def to_dict(self):
        return {"program_id":self.program_id,"name":self.name,"platform":self.platform,"policy":asdict(self.policy),"rules":[asdict(x) for x in self.rules],"assets":[asdict(x) for x in self.assets]}

def _root() -> Path:
    root=Path(".aletheia/programs"); root.mkdir(parents=True, exist_ok=True); return root
def save(program:BugBountyProgram) -> Path:
    path=_root()/f"{program.program_id}.json"; path.write_text(json.dumps(program.to_dict(),indent=2,sort_keys=True),encoding="utf-8"); return path
def load(program_id:str) -> BugBountyProgram:
    raw=json.loads((_root()/f"{program_id}.json").read_text(encoding="utf-8")); policy=ProgramPolicy(**raw.get("policy",{})); rules=[ScopeRule(**x) for x in raw.get("rules",[])]; assets=[]
    for x in raw.get("assets",[]): x["exclusions"]=[ExclusionRule(**e) for e in x.get("exclusions",[])]; assets.append(ScopeAsset(**x))
    return BugBountyProgram(raw["program_id"],raw["name"],raw.get("platform","generic"),policy,rules,assets)
def import_program(source:str) -> BugBountyProgram:
    path=Path(source)
    text=path.read_text(encoding="utf-8") if path.is_file() else source
    try: raw=json.loads(text)
    except json.JSONDecodeError:
        name=next((line.lstrip("# ").strip() for line in text.splitlines() if line.lstrip().startswith("#")),"Imported program")
        rules=[ScopeRule(line.strip("- "),"in-scope",f"markdown:{i+1}") for i,line in enumerate(text.splitlines()) if "github.com" in line or line.strip().startswith(("./","contracts/","src/"))]
        raw={"name":name,"rules":[asdict(x) for x in rules]}
    pid=raw.get("program_id") or "program-"+hashlib.sha256(text.encode()).hexdigest()[:12]
    program=BugBountyProgram(pid,raw.get("name",pid),raw.get("platform","generic"),ProgramPolicy(**raw.get("policy",{})),[ScopeRule(**x) for x in raw.get("rules",[])])
    save(program); return program
def explain(program:BugBountyProgram, target:str) -> tuple[str,str]:
    for rule in program.rules:
        if rule.pattern and (rule.pattern in target or re.search(rule.pattern,target,re.I)):
            return rule.status, rule.evidence or f"scope rule matched: {rule.pattern}"
    return "uncertain","no program-specific scope rule matched"
def add_target(program_id:str, locator:str) -> AuditTarget:
    program=load(program_id); status,evidence=explain(program,locator); identity=compute_identity(locator).to_dict() if Path(locator).is_dir() else {"locator":locator}
    program.assets.append(ScopeAsset(program.name,program.platform,locator,locator,commit_sha=identity.get("content_sha256","")[:16],in_scope_status=status,scope_evidence=evidence,source_provenance=identity)); save(program)
    return AuditTarget(program_id,locator,identity,status,evidence)
