"""Evidence contract shared by scanners and verifiers."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    kind: str
    summary: str
    source_mapping: dict[str, Any]
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
