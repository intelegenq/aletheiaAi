import json
from aletheia import knowledge_ingestion as k
def test_import_search_and_provenance(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source=tmp_path/"cases.json"; source.write_text(json.dumps([{"title":"Unchecked account","chain_family":"solana","protocol_domain":"vault","taxonomy":"authorization-bypass","description":"account authority"}]))
    assert k.validate(str(source))["valid"]
    assert k.import_path(str(source),"local","CC0-1.0")["imported"] == 1
    result=k.search("authority",chain="solana",domain="vault")
    assert result and result[0]["source"]["license"] == "CC0-1.0"
    assert k.import_path(str(source),"local","CC0-1.0")["imported"] == 0
