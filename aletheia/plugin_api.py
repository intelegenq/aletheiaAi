"""Explicit plugin API and deterministic in-process registry."""
from __future__ import annotations
from pathlib import Path
from typing import Protocol
from .target_model import TargetDescriptor
from .semantic_facts import SemanticFactBundle
from .rule_contract import RuleDefinition
from .verification_contract import VerificationCapabilities, ReproductionCapabilities, VerificationResult


class ChainPlugin(Protocol):
    chain_family: str
    ecosystems: tuple[str, ...]
    def detect_target(self, root: Path) -> TargetDescriptor | None: ...
    def collect_semantic_facts(self, target: TargetDescriptor) -> SemanticFactBundle: ...
    def available_rules(self) -> list[RuleDefinition]: ...
    def scan(self, target: TargetDescriptor, facts: SemanticFactBundle, rules: list[RuleDefinition]): ...
    def verifier_capabilities(self) -> VerificationCapabilities: ...
    def verify(self, finding, target, facts, evidence) -> VerificationResult: ...
    def reproduction_capabilities(self) -> ReproductionCapabilities: ...


_PLUGINS: list[ChainPlugin] = []
def register(plugin: ChainPlugin) -> ChainPlugin:
    _PLUGINS.append(plugin); return plugin
def plugins() -> tuple[ChainPlugin, ...]: return tuple(_PLUGINS)
def plugin_for_target(root: Path) -> tuple[ChainPlugin | None, TargetDescriptor | None]:
    # Lazy import keeps the core contract dependency-free while making the
    # built-in registry available to API callers.
    if not _PLUGINS:
        import aletheia.non_evm
    for plugin in _PLUGINS:
        target = plugin.detect_target(root)
        if target is not None: return plugin, target
    return None, None
