"""Honest chain capability registry."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from .plugin_api import plugins

VALID_CHAIN_STATUSES = ("supported", "candidate-only", "partial", "experimental", "deferred", "disabled")

@dataclass(frozen=True)
class Capability:
    chain_family: str
    ecosystem: str
    status: str
    engine: str
    rule_count: int
    verifier_state: str
    def to_dict(self): return asdict(self)

def registry() -> list[Capability]:
    import aletheia.non_evm  # register built-ins
    values=[Capability("evm", "evm", "supported", "slither/foundry", 0, "evm conviction")]
    for plugin in plugins():
        values.append(Capability(plugin.chain_family, plugin.ecosystem, "candidate-only", f"{plugin.ecosystem}-semantic", len(plugin.available_rules()), "source/evidence gate; no reproduction"))
    return values
