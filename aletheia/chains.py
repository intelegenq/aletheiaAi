"""Chain detection and capability routing for multi-chain audit targets."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable
from .plugin_api import plugin_for_target


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
    ecosystem: str = "unknown"
    chain_status: str = "deferred"

    def to_dict(self):
        return asdict(self)


def classify_target(root: Path, files: Iterable[Path]) -> ChainTarget:
    # A plugin needs both a project marker and ecosystem identifiers; extension
    # matching alone is deliberately insufficient.
    import aletheia.non_evm
    plugin, target = plugin_for_target(root)
    if plugin and target:
        return ChainTarget(target.chain_family, [], target.language, target.confidence,
                           list(target.signals), True, [f"{target.ecosystem}-semantic"],
                           target.ecosystem, "candidate-only")
    paths = list(files)
    names = {p.name for p in paths} | {p.name for p in root.iterdir()} if root.exists() else {p.name for p in paths}
    suffixes = {p.suffix.lower() for p in paths}
    signals: list[str] = []
    if "Anchor.toml" in names:
        return ChainTarget("solana", [], "rust", "medium", ["Anchor project marker; semantic identifiers absent"], False, [], "unknown", "deferred")
    if ".move" in suffixes or "Move.toml" in names:
        return ChainTarget("move", [], "move", "medium", ["Move source/build marker; ecosystem deferred"], False, [], "unknown", "deferred")
    if ".rs" in suffixes or "Cargo.toml" in names:
        return ChainTarget("rust", [], "rust", "low", ["Rust source/build marker; ecosystem deferred"], False, [], "unknown", "deferred")
    scores = {key: 0 for key in CHAIN_CAPABILITIES}
    if ".sol" in suffixes:
        scores["evm"] += 5; signals.append("solidity source")
    if "foundry.toml" in names or any(n.startswith("hardhat.config") for n in names):
        scores["evm"] += 4; signals.append("EVM build marker")
    ranked = sorted(scores, key=lambda key: (-scores[key], key))
    primary = ranked[0] if scores[ranked[0]] else "unknown"
    top = scores.get(primary, 0)
    confidence = "high" if top >= 5 else "medium" if top >= 2 else "low"
    cap = CHAIN_CAPABILITIES.get(primary)
    candidates = [key for key in ranked if scores[key] and key != primary]
    return ChainTarget(primary, candidates, (cap.languages[0] if cap else "unknown"), confidence, signals, bool(cap and cap.enabled), list(cap.engines) if cap else [], primary if cap else "unknown", "supported" if cap and cap.enabled else "deferred")


def route_chain(chain: str, available_engines: Iterable[str] = ()) -> dict:
    cap = CHAIN_CAPABILITIES.get(chain)
    available = set(available_engines)
    if not cap:
        return {"chain": chain, "supported": False, "status": "deferred", "engines": [], "reason": "unknown chain"}
    selected = sorted(set(cap.engines) & available)
    return {"chain": chain, "supported": cap.enabled, "status": "supported" if cap.enabled else "deferred", "engines": selected,
            "reason": "no chain adapter enabled" if not cap.enabled else ("no installed engine" if not selected else "")}
