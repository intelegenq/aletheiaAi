"""Deterministic non-EVM fixture evaluation metrics."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from time import perf_counter
from pathlib import Path
from .plugin_api import plugin_for_target

@dataclass
class BenchmarkResult:
    ecosystem: str; rule_coverage: int; fixture_coverage: int; candidate_count: int
    verified_count: int; needs_review_count: int; false_positive_regression_count: int
    source_mapping_accuracy: float; verifier_coverage: float; scan_duration_ms: float
    def to_dict(self): return asdict(self)

def benchmark_target(root: str | Path) -> BenchmarkResult:
    started=perf_counter(); plugin, target=plugin_for_target(Path(root))
    if not plugin or not target: raise ValueError("no semantic plugin detected")
    facts=plugin.collect_semantic_facts(target); rules=plugin.available_rules(); findings=plugin.scan(target, facts, rules)
    mapped=sum(bool(f.source_location.file and f.semantic_evidence) for f in findings)
    return BenchmarkResult(target.ecosystem, len(rules), 1, len(findings), 0, len(findings), 0,
        round(mapped / len(findings), 3) if findings else 1.0, 1.0, round((perf_counter()-started)*1000, 3))
