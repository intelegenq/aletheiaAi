"""Compile universal analysis specs into executable audit actions.

Compilation is intentionally conservative: implemented detector contracts are
 runnable, candidate contracts become analysis tasks, and manual contracts are
 never silently promoted to scanners.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable

from .knowledge import KnowledgeBase, UniversalSpec


class SpecCompilationError(ValueError):
    pass


@dataclass
class CompiledSpec:
    spec_id: str
    pattern_id: str
    detector_id: str
    title: str
    execution_mode: str
    status: str
    required_primitives: list[str] = field(default_factory=list)
    engines: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    coverage_status: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def compile_spec(spec: UniversalSpec, *, available_engines: Iterable[str] = ()) -> CompiledSpec:
    """Compile one spec without changing its security status."""
    if not spec.spec_id or not spec.pattern_id:
        raise SpecCompilationError("spec requires spec_id and pattern_id")
    primitives = sorted(set(spec.required_primitives))
    unknown = [p for p in primitives if p not in {
        "arithmetic_ops", "ast_traversal", "call_graph", "callee_resolution",
        "cfg_reachability", "contract_hierarchy", "cross_function_analysis",
        "data_dependency", "data_flow", "deployment_topology", "economic_incentive",
        "economic_invariant", "effective_access_control", "external_calls",
        "external_reachability", "foundry_fork", "function_signature",
        "low_level_calls", "manual_review", "market_simulation", "message_validation",
        "modifier_check", "onchain_data", "onchain_state", "oracle_source",
        "path_analysis", "protocol_state", "range_constraints", "slithir_ops",
        "state_writes", "static_signals", "storage_reads_writes", "taint_tracking",
    }]
    available = set(available_engines)
    engines = sorted(set(spec.recommended_engines))
    runnable = sorted(set(engines) & available)
    warnings: list[str] = []
    if unknown:
        warnings.append("unknown primitives require adapter-specific handling: " + ", ".join(unknown))
    if spec.status == "implemented":
        mode = "detector"
        actions = ["run_detector", "normalize_candidate", "correlate_knowledge"]
        if engines and not runnable:
            warnings.append("no recommended engine is available in this runtime")
    elif spec.status == "manual":
        mode = "manual_review"
        actions = ["collect_source_context", "request_human_review"]
    else:
        mode = "analysis_task"
        actions = ["collect_analysis_facts", "evaluate_primitives", "retain_as_candidate"]
    return CompiledSpec(
        spec_id=spec.spec_id, pattern_id=spec.pattern_id, detector_id=spec.detector_id,
        title=spec.title, execution_mode=mode, status=spec.status,
        required_primitives=primitives, engines=runnable, actions=actions,
        coverage_status=spec.coverage_status, warnings=warnings,
    )


def compile_catalog(kb: KnowledgeBase, *, available_engines: Iterable[str] = ()) -> list[CompiledSpec]:
    specs = kb.universal_specs()
    if not specs:
        raise SpecCompilationError("universal spec catalog is empty")
    compiled = [compile_spec(spec, available_engines=available_engines) for spec in specs]
    ids = [item.spec_id for item in compiled]
    if len(ids) != len(set(ids)):
        raise SpecCompilationError("universal spec IDs are not unique")
    return compiled


def compile_selected(kb: KnowledgeBase, categories: Iterable[str], *, limit: int = 12,
                     available_engines: Iterable[str] = ()) -> list[CompiledSpec]:
    return [compile_spec(spec, available_engines=available_engines)
            for spec in kb.select_specs(categories, limit=limit)]
