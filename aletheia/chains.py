"""Chain detection and capability routing for multi-chain audit targets."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ChainCapability:
    chain: str
    languages: tuple[str, ...]
    source_extensions: tuple[str, ...]
    build_markers: tuple[str, ...]
    engines: tuple[str, ...]
    enabled: bool = False

    def to_dict(self):
        return asdict(self)


CHAIN_CAPABILITIES = {
    "evm": ChainCapability("evm", ("solidity",), (".sol",), ("foundry.toml", "hardhat.config.js", "hardhat.config.ts"), ("slither", "foundry", "medusa", "echidna"), True),
    "solana": ChainCapability("solana", ("rust", "typescript"), (".rs", ".ts"), ("Anchor.toml", "Cargo.toml"), (), False),
    "move": ChainCapability("move", ("move",), (".move",), ("Move.toml",), (), False),
    "rust": ChainCapability("rust", ("rust",), (".rs",), ("Cargo.toml",), (), False),
}


@dataclass
class ChainTarget:
    primary: str = "unknown"
    candidates: list[str] = field(default_factory=list)
    language: str = "unknown"
    confidence: str = "low"
    signals: list[str] = field(default_factory=list)
    supported: bool = False
    engines: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def classify_target(root: Path, files: Iterable[Path]) -> ChainTarget:
    paths = list(files)
    names = {p.name for p in paths} | {p.name for p in root.iterdir()} if root.exists() else {p.name for p in paths}
    suffixes = {p.suffix.lower() for p in paths}
    signals: list[str] = []
    scores = {key: 0 for key in CHAIN_CAPABILITIES}
    if ".sol" in suffixes:
        scores["evm"] += 5; signals.append("solidity source")
    if "foundry.toml" in names or any(n.startswith("hardhat.config") for n in names):
        scores["evm"] += 4; signals.append("EVM build marker")
    if ".move" in suffixes or "Move.toml" in names:
        scores["move"] += 5; signals.append("Move source/build marker")
    if ".rs" in suffixes or "Cargo.toml" in names:
        scores["rust"] += 2; signals.append("Rust source/build marker")
    if "Anchor.toml" in names or any("anchor" in str(p).lower() for p in paths if p.suffix in {".json", ".toml", ".ts"}):
        scores["solana"] += 5; signals.append("Solana/Anchor marker")
    ranked = sorted(scores, key=lambda key: (-scores[key], key))
    primary = ranked[0] if scores[ranked[0]] else "unknown"
    top = scores.get(primary, 0)
    confidence = "high" if top >= 5 else "medium" if top >= 2 else "low"
    cap = CHAIN_CAPABILITIES.get(primary)
    candidates = [key for key in ranked if scores[key] and key != primary]
    return ChainTarget(primary, candidates, (cap.languages[0] if cap else "unknown"), confidence, signals, bool(cap and cap.enabled), list(cap.engines) if cap else [])


def route_chain(chain: str, available_engines: Iterable[str] = ()) -> dict:
    cap = CHAIN_CAPABILITIES.get(chain)
    available = set(available_engines)
    if not cap:
        return {"chain": chain, "supported": False, "engines": [], "reason": "unknown chain"}
    selected = sorted(set(cap.engines) & available)
    return {"chain": chain, "supported": cap.enabled, "engines": selected,
            "reason": "no chain adapter enabled" if not cap.enabled else ("no installed engine" if not selected else "")}
