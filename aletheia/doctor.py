"""Safe local setup and actionable dependency diagnosis."""
from __future__ import annotations
from pathlib import Path
import shutil, sys
def doctor():
    tools={name:shutil.which(name) for name in ("forge","slither","semgrep","echidna","cargo","scarb")}
    return {"schema_version":"aletheia.doctor.v1","python":sys.version.split()[0],"tools":tools,"affected_capabilities":{"evm":"full Slither analysis requires optional slither-vulndb analyses package","non_evm":"syntax-aware scanners work; native reproduction tools are optional"},"actions":["Run `aletheia setup` to create only local state directories.","Install optional tools using their official package managers; no credentials are required."]}
def setup():
    root=Path(".aletheia"); (root/"programs").mkdir(parents=True,exist_ok=True); (root/"runs").mkdir(parents=True,exist_ok=True)
    return {"status":"ready","path":str(root.resolve()),"credentials_written":False,"note":"External analysis/tool packages are intentionally not downloaded automatically."}
