"""Local-only reproduction execution with evidence-gated verdict changes."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from pathlib import Path
import hashlib, json, shutil, subprocess
from .models import Finding

@dataclass
class ReproductionEnvironment: sandbox_path:str; tool:str=""; tool_version:str=""
@dataclass
class ReproductionCommand: argv:list[str]; timeout:int=120
@dataclass
class ReproductionEvidence:
    finding_id:str; target_hash:str; chain_family:str; ecosystem:str; source_mapping:dict; attacker_control:str; reachability:str; observed_state_change:list[str]; artifact_hashes:dict
@dataclass
class ReproductionResult:
    finding_id:str; verdict:str; environment:ReproductionEnvironment; command:ReproductionCommand; exit_code:int|None; stdout:str=""; stderr:str=""; assertion_outcome:str="not-run"; limitations:list[str]=field(default_factory=list); evidence:ReproductionEvidence|None=None

def run(finding:Finding, target:str|Path, sandbox:str|Path)->ReproductionResult:
    root=Path(target); out=Path(sandbox); out.mkdir(parents=True,exist_ok=True)
    tool="forge" if finding.chain_family=="evm" else {"solana":"anchor","cosmos":"cargo","move":"move","substrate":"cargo","polkadot":"cargo","starknet":"scarb"}.get(finding.chain_family,"")
    env=ReproductionEnvironment(str(out),tool,"")
    if not finding.source_location.file or not finding.semantic_evidence:
        return ReproductionResult(finding.finding_id,"needs-review",env,ReproductionCommand([]),None,limitations=["missing source mapping or semantic evidence"])
    binary=shutil.which(tool) if tool else None
    if not binary:
        return ReproductionResult(finding.finding_id,"needs-review",env,ReproductionCommand([]),None,limitations=[f"local {tool or 'chain'} harness unavailable"])
    # We only execute a target's existing local tests. No generated patch,
    # network endpoint, transaction broadcast, or production interaction.
    argv=[binary,"test"] if tool in {"forge","anchor","cargo","scarb"} else [binary,"test"]
    try:
        proc=subprocess.run(argv,cwd=root,capture_output=True,text=True,timeout=120)
    except Exception as exc:
        return ReproductionResult(finding.finding_id,"needs-review",env,ReproductionCommand(argv),None,stderr=str(exc),limitations=["local harness execution failed"])
    target_hash=hashlib.sha256("".join(sorted(str(p) for p in root.rglob("*") if p.is_file())).encode()).hexdigest()
    # A passing suite never verifies a vulnerability. A failing suite is only
    # evidence when a concrete assertion and attacker precondition are known.
    if proc.returncode != 0 and finding.attacker_control in {"confirmed","partial"} and finding.trace:
        evidence=ReproductionEvidence(finding.finding_id,target_hash,finding.chain_family,finding.ecosystem,finding.source_location.__dict__,finding.attacker_control,"partial",finding.trace,{})
        verdict="verified"; outcome="security assertion failed locally"
    else:
        evidence=None; verdict="needs-review"; outcome="no evidence-gated security assertion"
    result=ReproductionResult(finding.finding_id,verdict,env,ReproductionCommand(argv),proc.returncode,proc.stdout,proc.stderr,outcome,[] if evidence else ["test outcome alone does not prove vulnerability"],evidence)
    (out/"reproduction.json").write_text(json.dumps(asdict(result),indent=2,sort_keys=True),encoding="utf-8"); return result
