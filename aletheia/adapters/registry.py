"""Adapter registry — maps engine names to run functions."""

from __future__ import annotations
from typing import Callable, Optional

from .base import ScanResult
from .slither_adapter import run_slither
from .semgrep_adapter import run_semgrep
from .mythril_adapter import run_mythril
from .foundry_adapter import run_foundry
from .echidna_adapter import run_echidna

try:  # The Medusa adapter is optional in minimal/source distributions.
    from .medusa_adapter import run_medusa
except ImportError:
    run_medusa = None

ADAPTERS: dict[str, Callable] = {
    "slither": run_slither,
    "semgrep": run_semgrep,
    "mythril": run_mythril,
    "foundry": run_foundry,
    "echidna": run_echidna,
}
if run_medusa is not None:
    ADAPTERS["medusa"] = run_medusa

ADAPTER_CATEGORIES: dict[str, str] = {
    "slither": "static",
    "semgrep": "static",
    "mythril": "symbolic",
    "foundry": "dynamic",
    "medusa": "dynamic",
    "echidna": "dynamic",
}


def run_adapter(
    engine: str,
    target: str,
    timeout: int = 300,
    output_dir: Optional[Path] = None,
    build_context=None,
) -> ScanResult:
    """Run a single adapter by engine name."""
    if engine not in ADAPTERS:
        return ScanResult(
            engine=engine,
            success=False,
            exit_code=-1,
            error=f"unknown engine: {engine}",
        )
    fn = ADAPTERS[engine]
    return fn(
        target=target,
        timeout=timeout,
        output_dir=output_dir,
        build_context=build_context,
    )
