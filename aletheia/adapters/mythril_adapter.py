"""Mythril adapter — symbolic analysis."""

from __future__ import annotations
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from .base import ScanResult


def run_mythril(
    target: str,
    timeout: int = 300,
    output_dir: Optional[Path] = None,
    build_context=None,
) -> ScanResult:
    """Run mythril symbolic analysis on compiled bytecode or contract dir."""
    t0 = time.time()
    out_path = (output_dir / "mythril_findings.json") if output_dir else Path("/tmp/mythril_findings.json")

    # Try to find a compiled artifact first
    artifact = _find_artifact(target, build_context)
    if artifact:
        cmd = ["mythril", "analyze", "-o", "json", "--max-depth", "20", "-a", artifact]
    else:
        # Run myth on source directory (may find compilation artifacts)
        cmd = ["mythril", "analyze", "-o", "json", "--max-depth", "20", "-d", target]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        code = r.returncode
        stdout, stderr = r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return ScanResult(engine="mythril", success=False, exit_code=-1, error=f"TIMEOUT after {timeout}s", duration_sec=time.time() - t0)
    except FileNotFoundError:
        return ScanResult(engine="mythril", success=False, exit_code=-2, error="mythril not found")
    except Exception as e:
        return ScanResult(engine="mythril", success=False, exit_code=-3, error=str(e), duration_sec=time.time() - t0)

    dur = time.time() - t0
    findings = []
    if stdout.strip():
        try:
            payload = json.loads(stdout)
            findings = payload if isinstance(payload, list) else payload.get("issues", [])
        except json.JSONDecodeError:
            pass

    error = ""
    if code not in (0, 1):
        error = stderr.strip() or f"exit {code}"

    return ScanResult(
        engine="mythril",
        success=code in (0, 1),
        exit_code=code,
        stdout=stdout,
        stderr=stderr,
        raw_findings=findings,
        error=error,
        duration_sec=dur,
        artifact_path=str(out_path) if out_path.exists() else "",
    )


def _find_artifact(target: str, build_context) -> Optional[str]:
    """Find bytecode artifact from Foundry build output."""
    root = Path(target)
    candidates = []
    if (root / "out").exists():
        for out_file in (root / "out").rglob("*.json"):
            if out_file.name.startswith("."):
                continue
            candidates.append(out_file)
    if candidates:
        # return the largest artifact (likely has bytecode)
        candidates.sort(key=lambda p: p.stat().st_size, reverse=True)
        return str(candidates[0])
    return None