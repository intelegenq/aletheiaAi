"""Triage data model — structured assessment layered on conviction results.

Triage never modifies raw evidence; it adds structured judgment on top of
findings that already passed conviction.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class AttackerPrerequisites:
    """Who/what an attacker needs to exploit a finding.

    Boolean fields are tri-state: True / False / "unknown". A value of
    "unknown" means there is NO evidence to conclude either way — it must
    never be silently treated as False (safe) or True.
    """

    permissionless: Any = "unknown"          # true / false / "unknown"
    requires_privileged_role: Any = "unknown"  # true / false / "unknown"
    privileged_role: str = ""             # which role (owner, admin, ...)
    requires_compromised_key: Any = "unknown"
    requires_flash_loan: Any = "unknown"
    requires_special_state: Any = "unknown"
    special_state: str = ""
    requires_external_dependency: Any = "unknown"
    requires_market_condition: Any = "unknown"
    requires_multiple_transactions: Any = "unknown"
    capital_required: str = "unknown"     # none, minimal, significant, unknown
    unknown: list[str] = field(default_factory=list)  # factors we could not determine


@dataclass
class ExploitabilityFactors:
    reachable: float = 0.0
    reproducible: float = 0.0
    permissionless: float = 0.0
    special_state_required: float = 0.0
    dynamic_corroboration: float = 0.0


@dataclass
class ExploitabilityScore:
    score: float = 0.0
    label: str = "unknown"                # insufficient-evidence, not-exploitable, theoretical, plausible, reproducible, directly-reproducible
    factors: ExploitabilityFactors = field(default_factory=ExploitabilityFactors)
    missing_information: list[str] = field(default_factory=list)  # factor names that are unknown


@dataclass
class AssetImpact:
    impact: str = "unknown"               # none, unknown, potential, quantified
    affected_assets: list[str] = field(default_factory=list)
    direct_funds_loss: str = "unknown"    # none, potential, quantified, unknown
    indirect_funds_loss: str = "unknown"
    temporary_loss: bool = False
    permanent_loss: bool = False
    state_corruption: bool = False
    availability_impact: bool = False
    privilege_takeover: bool = False
    quantified_amount: str = ""           # only set when real balance/state evidence exists


@dataclass
class TriageResult:
    finding_id: str = ""
    root_cause_id: str = ""
    priority: str = "needs-review"        # p0-critical .. p4-informational, needs-review
    severity: str = "unknown"             # critical, high, medium, low, informational, unknown
    confidence: str = "unknown"           # high, medium, low, unknown
    exploitability: ExploitabilityScore = field(default_factory=ExploitabilityScore)
    impact: AssetImpact = field(default_factory=AssetImpact)
    attacker_prerequisites: AttackerPrerequisites = field(default_factory=AttackerPrerequisites)
    affected_assets: list[str] = field(default_factory=list)
    affected_users: list[str] = field(default_factory=list)  # all-users, protocol-owner, single-user, ...
    scope_status: str = "unknown"         # in-scope, out-of-scope, uncertain
    scope_reason: str = ""
    duplicate_status: str = "unique"      # unique, duplicate, merged
    duplicated_into: str = ""             # root_cause_id when merged
    evidence_merged_from: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)