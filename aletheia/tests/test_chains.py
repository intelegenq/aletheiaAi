from __future__ import annotations

from pathlib import Path

from aletheia.chains import classify_target, route_chain
from aletheia.intake import intake


def test_classify_evm_and_solana(tmp_path: Path):
    (tmp_path / "foundry.toml").write_text("[profile.default]\nsolc='0.8.20'\n")
    sol = tmp_path / "Vault.sol"
    sol.write_text("pragma solidity 0.8.20; contract Vault {}")
    target = classify_target(tmp_path, [sol])
    assert target.primary == "evm"
    assert target.supported
    assert "slither" in target.engines

    solana = tmp_path / "Anchor.toml"
    solana.write_text("[programs.localnet]\n")
    rust = tmp_path / "lib.rs"
    rust.write_text("pub fn entry() {}")
    target = classify_target(tmp_path, [solana, rust])
    assert target.primary == "solana"
    assert not target.supported


def test_move_intake_is_supported_as_deferred_target(tmp_path: Path):
    (tmp_path / "Move.toml").write_text("[package]\nname='demo'\n")
    source = tmp_path / "sources" / "main.move"
    source.parent.mkdir()
    source.write_text("module demo::main {}")
    ctx = intake(str(tmp_path), with_build=False, solc_switch=False)
    assert not ctx.error
    assert ctx.chain.primary == "move"
    assert ctx.contracts == [source]


def test_chain_routing_is_explicit():
    assert route_chain("evm", ["slither"])["supported"]
    unsupported = route_chain("solana", ["slither"])
    assert not unsupported["supported"]
    assert unsupported["engines"] == []
