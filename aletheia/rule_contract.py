"""Rules are chain mappings, never executable universal keyword lists."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    title: str
    taxonomy_id: str
    chain_pattern_id: str
    required_facts: tuple[str, ...]
    false_positive_conditions: tuple[str, ...] = ()
    verification_requirements: tuple[str, ...] = ("source mapping", "semantic evidence")
    severity: str = "medium"

    def to_dict(self) -> dict:
        return asdict(self)
