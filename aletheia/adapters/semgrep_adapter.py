"""Semgrep adapter — static analysis."""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

from .base import ScanResult


def run_semgrep(
    target: str,
    timeout: int = 300,
    output_dir: Optional[Path] = None,
    rules: str = "",
    build_context=None,
) -> ScanResult:
    """Run semgrep on Solidity files."""
    import subprocess, time
    t0 = time.time()

    out_path = (output_dir / "semgrep_findings.json") if output_dir else Path("/tmp/semgrep_findings.json")
    cmd = ["semgrep", "--json", "--output", str(out_path)]
    if rules:
        cmd.extend(["--config", rules])
    else:
        cmd.extend(["--config", "auto"])
    cmd.extend(["--lang", "solidity"])
    cmd.append(target)

    env = dict(os.environ)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        code = r.returncode
    except subprocess.TimeoutExpired:
        return ScanResult(engine="semgrep", success=False, exit_code=-1, error=f"TIMEOUT after {timeout}s", duration_sec=time.time() - t0)
    except FileNotFoundError:
        return ScanResult(engine="semgrep", success=False, exit_code=-2, error="semgrep not found")
    except Exception as e:
        return ScanResult(engine="semgrep", success=False, exit_code=-3, error=str(e), duration_sec=time.time() - t0)

    dur = time.time() - t0
    findings = []
    if out_path.exists():
        try:
            payload = json.loads(out_path.read_text())
            findings = payload.get("results", [])
        except Exception:
            findings = []

    error = ""
    if code not in (0, 1):
        error = r.stderr.strip() if r.stderr else f"exit {code}"

    return ScanResult(
        engine="semgrep",
        success=code in (0, 1),
        exit_code=code,
        stdout=r.stdout or "",
        stderr=r.stderr or "",
        raw_findings=findings,
        error=error,
        duration_sec=dur,
        artifact_path=str(out_path) if out_path.exists() else "",
    )