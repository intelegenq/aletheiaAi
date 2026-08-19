"""Deterministic source-span attack surface artifacts."""
from __future__ import annotations
import json
from pathlib import Path
from .plugin_api import plugin_for_target
from .syntax import parse

def build(target:str|Path) -> dict:
    root=Path(target); plugin, desc=plugin_for_target(root); entries=[]; facts=[]
    if plugin and desc:
        bundle=plugin.collect_semantic_facts(desc); facts=bundle.to_dict()["facts"]
        for fact in bundle.facts:
            if fact.kind in {"entry","dispatch","packet","transact","caller","cpi"}: entries.append({"name":fact.attributes.get("node",fact.kind),"source":{"file":fact.file,"line":fact.line},"kind":fact.kind})
        chain,ecosystem=desc.chain_family,desc.ecosystem
    else:
        chain,ecosystem="evm","evm"
        for path in sorted(root.rglob("*.sol")):
            for node in parse(path.read_text(encoding="utf-8",errors="ignore")).nodes_of("function"):
                entries.append({"name":node.name,"source":{"file":str(path.relative_to(root)),"line":node.start_line},"kind":"function"})
    signals={"bridge":["packet","xcm","ibc","bridge"],"dex":["swap","pool"],"lending":["borrow","collateral"],"vault":["vault","deposit","withdraw"],"governance":["vote","proposal"],"oracle":["oracle","price"]}
    hay=" ".join([str(x) for x in facts]+[x["name"] for x in entries]).lower(); matched=[k for k,v in signals.items() if any(t in hay for t in v)]
    classification={"primary":matched[0] if matched else "generic","confidence":"low","signals":matched,"alternatives":matched[1:]}
    return {"schema_version":"aletheia.attack-surface.v1","chain_family":chain,"ecosystem":ecosystem,"entry_points":entries,"privileged_entry_points":[],"state_mutation_sinks":facts,"asset_movement_sinks":[x for x in facts if x["kind"] in {"asset","funds","coin"}],"external_calls":[x for x in facts if x["kind"] in {"cpi","call","dispatcher","transact"}],"cross_chain_flows":[x for x in facts if x["kind"] in {"packet","channel","location","transact"}],"trust_boundaries":[x for x in facts if x["kind"] in {"origin","signer","caller","authority"}],"protocol_classification":classification}
def write(target:str|Path, output:str|Path) -> dict:
    data=build(target); out=Path(output); out.mkdir(parents=True,exist_ok=True)
    mappings={"attack_surface.json":data,"trust_boundaries.json":data["trust_boundaries"],"entrypoint_graph.json":data["entry_points"],"asset_flow_graph.json":data["asset_movement_sinks"],"cross_chain_flow_graph.json":data["cross_chain_flows"],"protocol_classification.json":data["protocol_classification"]}
    for name,value in mappings.items(): (out/name).write_text(json.dumps(value,indent=2,sort_keys=True),encoding="utf-8")
    return data
