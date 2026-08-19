"""Foundry adapter — forge test runner."""

from __future__ import annotations
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from .base import ScanResult

FOUNDRY_BIN = os.environ.get("ALETHEIA_FOUNDRY_BIN", "/root/.foundry/bin")


def run_foundry(
    target: str,
    timeout: int = 600,
    output_dir: Optional[Path] = None,
    build_context=None,
    extra_args: Optional[list[str]] = None,
) -> ScanResult:
    """Run forge test on target project."""
    t0 = time.time()
    out_path = (output_dir / "foundry_test_output.txt") if output_dir else Path("/tmp/foundry_test_output.txt")

    env = dict(os.environ)
    env["PATH"] = f"{FOUNDRY_BIN}:{env.get('PATH', '')}"

    cmd = ["forge", "test", "-vvv"]
    if extra_args:
        cmd.extend(extra_args)

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=target, env=env,
        )
        code = r.returncode
        stdout, stderr = r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return ScanResult(engine="foundry", success=False, exit_code=-1, error=f"TIMEOUT after {timeout}s", duration_sec=time.time() - t0)
    except FileNotFoundError:
        return ScanResult(engine="foundry", success=False, exit_code=-2, error="forge not found")
    except Exception as e:
        return ScanResult(engine="foundry", success=False, exit_code=-3, error=str(e), duration_sec=time.time() - t0)

    dur = time.time() - t0

    # Parse failing tests from the "Failing tests:" summary block.
    # Forge emits either:
    #   [FAIL] test_name() (gas: N)
    #   [FAIL: assertion failed]\n\t[Sequence] ...\n invariant_name() (runs: ...)
    findings = []
    lines = stdout.split("\n")
    import re

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("[FAIL"):
            continue

        # unit test form: [FAIL] name() (gas: N)  /  [FAIL: reason] name() (gas: N)
        m = re.match(r"\[FAIL[^\]]*\]\s+(\S+\([^)]*\))", stripped)
        test_name = m.group(1) if m else ""
        trace: list[str] = []

        # invariant form: name appears on a later line after the [Sequence] block
        if not test_name:
            j = idx + 1
            while j < len(lines) and j < idx + 40:
                nxt = lines[j].strip()
                if nxt.startswith("[Sequence]") or nxt.startswith("sender="):
                    trace.append(nxt)
                    j += 1
                    continue
                m2 = re.match(r"(\S+\([^)]*\))\s+\(runs:", nxt)
                if m2:
                    test_name = m2.group(1)
                    break
                if nxt.startswith("[FAIL") or nxt.startswith("Encountered"):
                    break
                j += 1

        if not test_name:
            test_name = stripped

        findings.append({
            "engine": "foundry",
            "test": test_name,
            "description": f"Failing test: {test_name} — {stripped}",
            "status": "failed",
            "trace": trace,
            "sequence": trace,
        })

    if out_path.parent.exists():
        out_path.write_text(stdout)

    error = ""
    if code not in (0, 1):
        error = stderr.strip() or f"exit {code}"

    return ScanResult(
        engine="foundry",
        success=code in (0, 1),
        exit_code=code,
        stdout=stdout,
        stderr=stderr,
        raw_findings=findings,
        error=error,
        duration_sec=dur,
        artifact_path=str(out_path) if out_path.exists() else "",
    )