"""Severity policy engine — configurable severity mapping profiles.

Supported policies: default, immunefi, hackenproof, yeswehack.
Policies map evidence → severity via rules, never by detector name alone.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional

from .triage_model import TriageResult, AssetImpact, ExploitabilityScore, AttackerPrerequisites


SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "unknown": 0}


@dataclass
class PolicyProfile:
    name: str
    description: str
    # severity thresholds
    critical_reqs: list[str] = field(default_factory=list)
    high_reqs: list[str] = field(default_factory=list)
    medium_reqs: list[str] = field(default_factory=list)
    low_reqs: list[str] = field(default_factory=list)


# ---------------- policy profiles ----------------

DEFAULT_POLICY = PolicyProfile(
    name="default",
    description="General-purpose severity mapping for bug bounty triage",
)

IMMUNEFI_POLICY = PolicyProfile(
    name="immunefi",
    description="Immunefi-style: smart contract critical = direct theft of funds or permanent freeze",
)

HACKENPROOF_POLICY = PolicyProfile(
    name="hackenproof",
    description="HackenProof-style: critical = direct financial loss, high = privilege escalation",
)

YESWEHACK_POLICY = PolicyProfile(
    name="yeswehack",
    description="YesWeHack-style: critical = direct loss of funds/user data, high = major privilege issue",
)


POLICIES: dict[str, PolicyProfile] = {
    "default": DEFAULT_POLICY,
    "immunefi": IMMUNEFI_POLICY,
    "hackenproof": HACKENPROOF_POLICY,
    "yeswehack": YESWEHACK_POLICY,
}


# ---------------- policy engine ----------------

def _maxed_factors(_t: TriageResult) -> bool:
    """True when all exploitability factors are maxed (not unknown)."""
    f = _t.exploitability.factors
    return all(x > 0.9 for x in (f.reachable, f.reproducible, f.permissionless))


def apply_policy(t: TriageResult, policy_name: str = "default") -> TriageResult:
    """Map a TriageResult to a severity using the given policy profile.

    Rules:
    - verified + permissionless/low-priv + direct asset loss + reproducible → critical
    - verified + major privilege takeover / permanent state corruption → high
    - verified + limited impact / special prereq / restricted role → medium
    - confirmed but limited impact / hard prereqs → low
    - no direct security impact → informational
    - evidence insufficient → unknown
    Never high/critical when conviction is needs-review / needs-dynamic-validation.
    """
    policy = POLICIES.get(policy_name, DEFAULT_POLICY)
    sev = "unknown"

    # Hard cap: unverified findings can never be high/critical.
    verdict = getattr(t, "_conviction_verdict", "")
    if verdict in ("needs-review", "needs-dynamic-validation", "rejected"):
        t.severity = "unknown"
        t.confidence = "low"
        t.rationale.append(
            f"Severity capped: conviction verdict '{verdict}' is not verified — evidence insufficient"
        )
        return t

    ex = t.exploitability.score
    priv = t.attacker_prerequisites
    imp = t.impact

    # Tri-state: "unknown" is truthy in Python but MUST NOT count as permissionless.
    permissionless = priv.permissionless is True
    perm_unknown = priv.permissionless == "unknown"
    direct_loss = imp.direct_funds_loss in ("potential", "quantified")
    takeover = imp.privilege_takeover
    corrupt = imp.state_corruption
    avail = imp.availability_impact
    repro = t.exploitability.factors.reproducible >= 0.75
    dynamic = t.exploitability.factors.dynamic_corroboration >= 0.75

    # Unknown prerequisites block high/critical under every policy.
    if perm_unknown:
        t.severity = "unknown"
        t.rationale.append(
            "Severity capped: permissionless requirement is unknown — insufficient evidence"
        )
        return t

    if policy_name == "immunefi":
        # Immunefi: critical = direct theft of user/protocol funds (potential counts only
        # when reproducible), permanent freeze, or governance takeover.
        if verdict == "verified" and permissionless and direct_loss and repro and dynamic:
            sev = "critical"
        elif verdict == "verified" and (takeover and repro) :
            sev = "high"
        elif verdict == "verified" and (corrupt or direct_loss) :
            sev = "medium"
        else:
            sev = "unknown"
    elif policy_name == "hackenproof":
        # HackenProof: critical = direct financial loss, high = privilege escalation.
        if verdict == "verified" and direct_loss and repro:
            sev = "critical"
        elif verdict == "verified" and takeover:
            sev = "high"
        elif verdict == "verified" and (corrupt or avail):
            sev = "medium"
        else:
            sev = "unknown"
    elif policy_name == "yeswehack":
        # YesWeHack: critical = direct loss, high = major privilege, medium = limited.
        if verdict == "verified" and direct_loss and permissionless and repro:
            sev = "critical"
        elif verdict == "verified" and takeover:
            sev = "high"
        elif verdict == "verified" and (corrupt or avail or direct_loss):
            sev = "medium"
        else:
            sev = "unknown"
    else:
        # default policy
        if verdict == "verified" and permissionless and direct_loss and repro and dynamic:
            sev = "critical"
        elif verdict == "verified" and (takeover or corrupt):
            sev = "high"
        elif verdict == "verified" and (direct_loss or avail):
            sev = "medium"
        elif verdict == "verified":
            sev = "low"
        else:
            sev = "unknown"

    t.severity = sev
    if sev != "unknown":
        t.confidence = "high" if t.confidence in ("high", "medium") else t.confidence
    t.rationale.append(f"Policy '{policy_name}': severity mapped to {sev}")
    return t