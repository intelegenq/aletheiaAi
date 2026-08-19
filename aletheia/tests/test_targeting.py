from __future__ import annotations

import json
from pathlib import Path

from aletheia.targeting import compute_identity, load_scope, parse_scope_text, resolve_target


def test_scope_parser_is_conservative():
    scope = parse_scope_text("In Scope:\n- contracts/Vault.sol\nOut of Scope:\n- test/\n")
    assert scope.in_scope == ["contracts/Vault.sol"]
    assert scope.out_of_scope == ["test/"]


def test_identity_is_reproducible_and_scope_aware(tmp_path: Path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts/Vault.sol").write_text("contract Vault {}")
    (tmp_path / "scope.json").write_text(json.dumps({"in_scope": ["contracts/Vault.sol"]}))
    first = compute_identity(tmp_path)
    second = compute_identity(tmp_path)
    assert first.content_sha256 == second.content_sha256
    assert first.file_count == 2
    assert first.scope.in_scope == ["contracts/Vault.sol"]


def test_local_target_resolution(tmp_path: Path):
    source = tmp_path / "Main.sol"
    source.write_text("contract Main {}")
    resolved, identity = resolve_target(str(tmp_path))
    assert resolved == tmp_path.resolve()
    assert identity.file_count == 1
