"""Fork simulation — interface that skips gracefully when RPC config is unavailable."""

from __future__ import annotations
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class ForkSimulationResult:
    status: str = "skipped"  # skipped, running, done, failed
    reason: str = ""
    chain_id: Optional[int] = None
    block_number: Optional[int] = None
    rpc_url: str = ""
    evidence: list[str] = field(default_factory=list)


class ForkSimulator:
    """Runs fork simulation only if RPC config is available."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.rpc_url = self.config.get("rpc_url", os.environ.get("ALETHEIA_RPC_URL", ""))
        self.chain_id = self.config.get("chain_id")
        self.block_number = self.config.get("block_number")

    def available(self) -> bool:
        """True only if we have enough config to fork (RPC URL + chain id)."""
        return bool(self.rpc_url) and bool(self.chain_id)

    def run(self, finding_id: str = "") -> ForkSimulationResult:
        """Attempt fork simulation. Skips cleanly if config missing."""
        if not self.rpc_url:
            return ForkSimulationResult(
                status="skipped",
                reason="fork configuration unavailable (no RPC URL)",
            )
        if not self.chain_id:
            return ForkSimulationResult(
                status="skipped",
                reason="fork configuration unavailable (no chain ID)",
            )

        # For now: fork simulation requires anvil + rpc — if tools missing, skip.
        anvil = os.environ.get("ALETHEIA_ANVIL_BIN") or shutil.which("anvil")
        if not anvil:
            return ForkSimulationResult(
                status="skipped",
                reason="fork simulation unavailable (anvil not found)",
                rpc_url=self.rpc_url,
                chain_id=self.chain_id,
            )

        # Fork is available — but this milestone only requires the interface.
        # Actual fork workflow lands in a later milestone.
        return ForkSimulationResult(
            status="skipped",
            reason="fork simulation interface ready; activated in a later milestone",
            rpc_url=self.rpc_url,
            chain_id=self.chain_id,
            block_number=self.block_number,
        )
