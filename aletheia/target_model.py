"""Chain-aware target descriptors used by the plugin runtime."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class TargetDescriptor:
    root: Path
    chain_family: str
    ecosystem: str
    language: str
    runtime: str = ""
    confidence: str = "low"
    signals: tuple[str, ...] = ()
    files: tuple[Path, ...] = ()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["root"] = str(self.root)
        data["files"] = [str(item) for item in self.files]
        return data
