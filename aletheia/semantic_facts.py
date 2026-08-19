"""Portable semantic facts. Facts retain their source instead of claiming proof."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SemanticFact:
    kind: str
    value: str
    file: str
    line: int
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class SemanticFactBundle:
    schema_version: str = "aletheia.semantic-facts.v1"
    chain_family: str = "unknown"
    ecosystem: str = "unknown"
    facts: list[SemanticFact] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def find(self, kind: str) -> list[SemanticFact]:
        return [fact for fact in self.facts if fact.kind == kind]

    def to_dict(self) -> dict:
        return {"schema_version": self.schema_version, "chain_family": self.chain_family,
                "ecosystem": self.ecosystem, "facts": [asdict(f) for f in self.facts],
                "limitations": self.limitations}
