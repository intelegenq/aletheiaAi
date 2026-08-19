from pathlib import Path
import json
import pytest
from aletheia.plugin_api import plugin_for_target
from aletheia.models import to_sarif
from aletheia.verify import run_verification

CASES = {
 "solana_anchor": ("Anchor.toml", "src/lib.rs", "use anchor_lang::prelude::*; #[derive(Accounts)] pub struct Accounts<'info> { pub user: Signer<'info>, pub vault: UncheckedAccount<'info> }"),
 "cosmwasm": ("Cargo.toml", "src/lib.rs", "use cosmwasm_std::*; pub fn execute(info: MessageInfo) { let _ = info.funds; }"),
 "cosmos_ibc": ("Cargo.toml", "src/lib.rs", "fn on_recv_packet(packet: Packet) { let _ = packet.sequence; }"),
 "substrate_frame": ("Cargo.toml", "src/lib.rs", "use frame_support::*; #[pallet::call] fn go(origin: OriginFor<T>) { ensure_signed(origin); }"),
 "parachain_xcm": ("Cargo.toml", "src/lib.rs", "use xcm::latest::prelude::*; fn x() { let _ = MultiLocation::here(); }"),
 "move_aptos": ("Move.toml", "sources/a.move", "module x::a { use aptos_framework::coin; public entry fun a(s: &signer) {} }"),
 "move_sui": ("Move.toml", "sources/a.move", "module x::a { use sui::object::UID; public entry fun a(ctx: &mut TxContext) {} }"),
 "ink": ("Cargo.toml", "src/lib.rs", "#[ink::contract] mod x { #[ink(storage)] struct X {} }"),
 "cairo": ("Scarb.toml", "src/lib.cairo", "#[starknet::contract] mod x { #[storage] struct Storage {} }")}

@pytest.mark.parametrize("ecosystem", CASES)
def test_plugins_are_syntax_aware_and_conservative(tmp_path, ecosystem):
    marker, source, body=CASES[ecosystem]; (tmp_path/marker).write_text("[package]\n")
    path=tmp_path/source; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(body)
    plugin, target=plugin_for_target(tmp_path); assert plugin and target and target.ecosystem == ecosystem
    facts=plugin.collect_semantic_facts(target); assert facts.facts and all(f.attributes.get("syntax_aware") for f in facts.facts)
    findings=plugin.scan(target, facts, plugin.available_rules()); assert findings
    assert all(f.status == "candidate" and f.source_location.file and f.semantic_evidence for f in findings)
    assert all(item["properties"]["verification_status"] == "candidate" for item in to_sarif(findings)["runs"][0]["results"])

def test_non_evm_verification_never_uses_evm_pipeline(tmp_path, monkeypatch):
    marker, source, body=CASES["solana_anchor"]; (tmp_path/marker).write_text("[package]\n")
    path=tmp_path/source; path.parent.mkdir(parents=True); path.write_text(body)
    plugin,target=plugin_for_target(tmp_path); findings=plugin.scan(target, plugin.collect_semantic_facts(target), plugin.available_rules())
    monkeypatch.setattr("aletheia.verify._load_target_analysis", lambda *_: (_ for _ in ()).throw(AssertionError("EVM analysis invoked")))
    result=run_verification(findings[:1], tmp_path/"out", str(tmp_path), verbose=False)
    assert result["needs_review"] and json.loads((tmp_path/"out"/"chain-verification.json").read_text())["results"][0]["verdict"] == "needs-review"
