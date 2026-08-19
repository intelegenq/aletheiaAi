"""Verifier output contract. Candidate scanners cannot promote a finding."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class VerificationCapabilities:
    available: bool = True
    local_reproduction: bool = False
    semantic_checks: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReproductionCapabilities:
    available: bool = False
    methods: tuple[str, ...] = ()


@dataclass
class VerificationResult:
    finding_id: str
    chain_family: str
    ecosystem: str = ""
    verdict: str = "needs-review"
    source_mapping: dict = field(default_factory=dict)
    semantic_checks: list[str] = field(default_factory=list)
    attacker_control: str = "unknown"
    reachability: str = "unknown"
    impact_evidence: list[dict] = field(default_factory=list)
    reproduction_evidence: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class ChainVerifier(Protocol):
    def verify(self, finding, target, facts, evidence) -> VerificationResult: ...
