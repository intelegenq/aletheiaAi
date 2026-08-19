"""Real analysis wiring — Slither compilation unit → AccessControlIndex, ReachabilityIndex,
CallIndex, StateIndex, CFGAnalysis via the pack's AnalysisFacts facade.

This is the evidence backbone for the Conviction Engine.
"""

from __future__ import annotations
import os
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# The pack location is configurable for both local and external installations.
PACK_ROOT = os.environ.get(
    "ALETHEIA_PACK_ROOT",
    str(__import__("pathlib").Path(__file__).resolve().parent.parent / "slither-vulndb"),
)


@dataclass
class AnalysisOutcome:
    """Result of real analysis for a target."""

    ok: bool = False
    error: str = ""
    contracts: list[str] = field(default_factory=list)
    # canonical function name -> access-control verdict
    access_control: dict[str, dict] = field(default_factory=dict)
    # canonical function name -> reachability verdict
    reachability: dict[str, dict] = field(default_factory=dict)
    # canonical function name -> state writes
    state_writes: dict[str, list[str]] = field(default_factory=dict)
    # canonical function name -> callers
    callers: dict[str, list[str]] = field(default_factory=dict)
    # canonical function name -> external entry?
    entry_points: list[str] = field(default_factory=list)
    # canonical function name -> caller canonical names
    all_functions: list[str] = field(default_factory=list)


def load_analysis(
    target: str,
    framework: Optional[str] = None,
) -> AnalysisOutcome:
    """Run real Slither-based analysis against a target directory or .sol file.

    Returns data structures the Conviction Engine can query. Never raises —
    returns AnalysisOutcome(ok=False) with the error message.
    """
    outcome = AnalysisOutcome()
    try:
        import sys
        sys.path.insert(0, PACK_ROOT)
        from slither import Slither
        from analyses.analysis_facts import AnalysisFacts
        from analyses.feature_gates import FeatureGates

        # The pack's gates skip contracts flagged is_test — our fixtures are
        # compiled under Foundry which marks everything is_test. Skip only
        # interfaces/libraries, but analyze test-looking contracts.
        gates = FeatureGates(skip_test_contracts=False)

        sl = Slither(target)
        cu = sl.compilation_units[0]
        # AnalysisFacts is a per-compilation-unit singleton; clear the registry so
        # our gates are the ones actually used instead of a cached default set.
        AnalysisFacts.clear_registry()
        facts = AnalysisFacts(cu, gates=gates)

        ac_index = facts.access_control
        rc_index = facts.reachability
        ci_index = facts.call_index
        st_index = facts.state_index

        for contract in cu.contracts:
            outcome.contracts.append(contract.name)

        # Force computation
        _ = ac_index.results
        _ = rc_index.reachable

        # Build maps
        for contract in cu.contracts:
            for func in contract.functions:
                if getattr(func, "is_constructor", False):
                    continue
                canonical = getattr(func, "canonical_name", func.name)

                # --- access control ---
                try:
                    ac = ac_index.get_access_control(func)
                    acv = ac.kind.value if hasattr(ac, "kind") else "unknown"
                    outcome.access_control[canonical] = {
                        "kind": acv,
                        "has_access_control": bool(getattr(ac, "has_access_control", False)),
                        "effective": bool(getattr(ac, "is_effective", False)),
                        "modifier_name": getattr(ac, "modifier_name", ""),
                        "is_inherited": bool(getattr(ac, "is_inherited", False)),
                        "details": getattr(ac, "details", ""),
                    }
                except Exception as e:
                    outcome.access_control[canonical] = {
                        "kind": "unknown", "error": str(e)[:120],
                    }

                # --- reachability ---
                try:
                    is_reachable = rc_index.is_externally_reachable(func)
                    entry = rc_index.is_entry_point(func)
                    outcome.reachability[canonical] = {
                        "reachable": bool(is_reachable),
                        "entry_point": bool(entry),
                    }
                except Exception as e:
                    outcome.reachability[canonical] = {
                        "reachable": False, "error": str(e)[:120],
                    }

                # --- state writes ---
                try:
                    writes = st_index.get_all_writes(func)
                    outcome.state_writes[canonical] = sorted(writes)
                except Exception as e:
                    outcome.state_writes[canonical] = []

                # --- callers ---
                try:
                    callers = rc_index.get_callers(func)
                    outcome.callers[canonical] = sorted(callers)
                except Exception as e:
                    outcome.callers[canonical] = []

                outcome.all_functions.append(canonical)

        outcome.entry_points = sorted(rc_index.entry_points)
        outcome.ok = True
        return outcome
    except Exception as e:
        logger.debug("analysis load failed", exc_info=True)
        outcome.error = str(e)[:300]
        return outcome


def map_function_to_canonical(
    outcome: AnalysisOutcome,
    contract: Optional[str],
    function: str,
) -> Optional[str]:
    """Map a finding's contract+function to a canonical name in the analysis.

    Tries several forms because finding locations may be imprecise.
    """
    if not function:
        return None
    fn = function.split("(")[0]

    candidates = []
    if contract:
        candidates.append(f"{contract}.{fn}()")
        candidates.append(f"{contract}.{fn}")
    candidates.append(f"{fn}()")
    candidates.append(fn)

    for cand in candidates:
        if cand in outcome.access_control or cand in outcome.reachability:
            return cand
        # prefix match for functions with args
        for canonical in outcome.all_functions:
            if canonical.startswith(cand.rstrip("()") + "("):
                return canonical
    return None
