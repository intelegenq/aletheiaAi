"""Deterministic local knowledge ingestion; historical data is never proof."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from pathlib import Path
import csv, hashlib, json
from datetime import datetime, timezone

@dataclass
class KnowledgeSource: name:str; path:str; license:str; content_hash:str; imported_at:str
@dataclass
class KnowledgeRecord:
    record_id:str; source:KnowledgeSource; title:str=""; chain_family:str="unknown"; ecosystem:str="unknown"; protocol_domain:str="generic"; taxonomy:str=""; root_cause_shape:str=""; preconditions:list[str]=field(default_factory=list); impact_shape:str=""; mitigation_shape:str=""; scope_metadata:dict=field(default_factory=dict); confidence:str="low"; text:str=""
def _db():
    p=Path(".aletheia/knowledge.jsonl"); p.parent.mkdir(parents=True,exist_ok=True); return p
def _rows(path:Path):
    text=path.read_text(encoding="utf-8",errors="replace")
    if path.suffix.lower()==".jsonl": return [json.loads(x) for x in text.splitlines() if x.strip()]
    if path.suffix.lower()==".json":
        data=json.loads(text); return data if isinstance(data,list) else data.get("findings",data.get("records",[data]))
    if path.suffix.lower()==".csv": return list(csv.DictReader(text.splitlines()))
    if path.suffix.lower()==".sarif":
        data=json.loads(text); return [{"title":r.get("message",{}).get("text",""),"taxonomy":r.get("ruleId","")} for run in data.get("runs",[]) for r in run.get("results",[])]
    return [{"title":path.stem,"text":text}]
def validate(path:str)->dict:
    try: rows=_rows(Path(path)); return {"valid":True,"records":len(rows)}
    except Exception as e: return {"valid":False,"error":str(e)}
def import_path(path:str,source_name:str,license_id:str)->dict:
    paths=[p for p in Path(path).rglob("*") if p.is_file()] if Path(path).is_dir() else [Path(path)]; added=[]; seen={json.loads(x)["record_id"] for x in _db().read_text(encoding="utf-8").splitlines() if x.strip()} if _db().exists() else set()
    for item in paths:
        raw=item.read_bytes(); digest=hashlib.sha256(raw).hexdigest(); source=KnowledgeSource(source_name,str(item),license_id,digest,datetime.now(timezone.utc).isoformat())
        for index,row in enumerate(_rows(item)):
            rid="kr-"+hashlib.sha256((digest+str(index)).encode()).hexdigest()[:16]
            if rid in seen: continue
            record=KnowledgeRecord(rid,source,str(row.get("title",row.get("name",""))),str(row.get("chain_family","unknown")),str(row.get("ecosystem","unknown")),str(row.get("protocol_domain","generic")),str(row.get("taxonomy",row.get("rule_id",""))),str(row.get("root_cause_shape",row.get("description","")))[:500],list(row.get("preconditions",[]) if isinstance(row.get("preconditions",[]),list) else []),str(row.get("impact_shape","")),str(row.get("mitigation_shape","")),dict(row.get("scope_metadata",{})),str(row.get("confidence","low")),str(row.get("text",row.get("description",""))))
            with _db().open("a",encoding="utf-8") as fh: fh.write(json.dumps(asdict(record),sort_keys=True)+"\n")
            added.append(rid)
    return {"imported":len(added),"record_ids":added}
def records(): return [json.loads(x) for x in _db().read_text(encoding="utf-8").splitlines() if x.strip()] if _db().exists() else []
def search(query:str,chain:str="",domain:str=""):
    words=set(query.lower().split()); out=[]
    for r in records():
        if chain and r["chain_family"]!=chain: continue
        if domain and r["protocol_domain"]!=domain: continue
        hay=json.dumps(r).lower(); score=sum(w in hay for w in words)
        if score: out.append((score,r))
    return [r for _,r in sorted(out,key=lambda x:(-x[0],x[1]["record_id"]))]
