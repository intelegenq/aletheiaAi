"""Echidna adapter — property-based fuzzing."""

from __future__ import annotations
import json
import os
import subprocess
import shutil
import time
from pathlib import Path
from typing import Optional

from .base import ScanResult

FOUNDRY_BIN = os.environ.get("ALETHEIA_FOUNDRY_BIN", "")


def run_echidna(
    target: str,
    timeout: int = 600,
    output_dir: Optional[Path] = None,
    build_context=None,
    contract: Optional[str] = None,
    config: Optional[Path] = None,
) -> ScanResult:
    """Run echidna fuzzer. Needs a compiled contract or test contract."""
    t0 = time.time()
    out_path = (output_dir / "echidna_findings.json") if output_dir else Path("/tmp/echidna_findings.json")

    env = dict(os.environ)
    env["PATH"] = f"{FOUNDRY_BIN}:{env.get('PATH', '')}"

    binary = os.environ.get("ALETHEIA_ECHIDNA_BIN") or shutil.which("echidna")
    if not binary:
        return ScanResult(engine="echidna", success=False, exit_code=-2, error="echidna not found",
                           duration_sec=time.time() - t0)
    cmd = [binary]
    # find the main test contract file
    test_contract = _find_echidna_test(target, contract)
    if test_contract:
        cmd.append(test_contract)
        # Echidna needs --contract to pick the right contract when a file
        # pulls in multiple contracts via imports.
        contract_name = contract or Path(test_contract).stem
        cmd.extend(["--contract", contract_name])
    else:
        # just run on the whole directory
        cmd.append(target)

    if config and config.exists():
        cmd.append("--config")
        cmd.append(str(config))

    # default mode is property testing (detects echidna_* functions)
    # --test-mode assertion would only check assert() statements
    cmd.extend(["--timeout", str(timeout)])

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 60,
            cwd=target, env=env,
        )
        code = r.returncode
        stdout, stderr = r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return ScanResult(engine="echidna", success=False, exit_code=-1, error=f"TIMEOUT after {timeout}s", duration_sec=time.time() - t0)
    except FileNotFoundError:
        return ScanResult(engine="echidna", success=False, exit_code=-2, error="echidna not found")
    except Exception as e:
        return ScanResult(engine="echidna", success=False, exit_code=-3, error=str(e), duration_sec=time.time() - t0)

    dur = time.time() - t0

    findings = []
    # Parse echidna text output for failing properties
    lines = stdout.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if "failed" in line.lower() and ":" in line:
            prop_name = line.split(":")[0].strip()
            finding = {
                "engine": "echidna",
                "property": prop_name,
                "message": line.strip(),
                "description": f"Echidna property failed: {prop_name}",
                "status": "failed",
            }
            # capture call sequence until next property or blank
            seq = []
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("echidna_"):
                if "Call sequence:" in lines[j] or "Call sequence" in lines[j]:
                    k = j + 1
                    while k < len(lines) and lines[k].strip() and not lines[k].startswith("Traces"):
                        seq.append(lines[k].strip())
                        k += 1
                    j = k
                else:
                    j += 1
            finding["sequence"] = seq
            finding["trace"] = seq
            findings.append(finding)
            i = j
        else:
            i += 1

    # If no findings parsed but output has "failed!" marker
    if not findings and "failed!" in stdout:
        for line in lines:
            if "failed!" in line:
                prop_name = line.split(":")[0].strip()
                findings.append({
                    "engine": "echidna",
                    "property": prop_name,
                    "message": line.strip(),
                    "description": f"Echidna property failed: {prop_name}",
                    "status": "failed",
                })

    error = ""
    if code not in (0, 1):
        error = stderr.strip() or f"exit {code}"

    return ScanResult(
        engine="echidna",
        success=code in (0, 1),
        exit_code=code,
        stdout=stdout,
        stderr=stderr,
        raw_findings=findings,
        error=error,
        duration_sec=dur,
        artifact_path=str(out_path) if out_path.exists() else "",
    )


def _find_echidna_test(target: str, contract: Optional[str] = None) -> Optional[str]:
    """Find a compiled Echidna test contract."""
    root = Path(target)
    if contract:
        # check if contract is a .sol file
        path = root / contract
        if path.exists():
            return str(path)
        # check with .sol extension
        path = root / f"{contract}.sol"
        if path.exists():
            return str(path)
        return str(root / contract)

    # Prefer a dedicated echidna/ directory, then test dirs.
    for d in ["echidna", "test", "tests", ""]:
        dpath = root / d if d else root
        if not dpath.exists():
            continue
        for f in dpath.rglob("*.sol"):
            if "Echidna" in f.name or "echidna" in f.name:
                return str(f)

    # fall back to any test-looking contract
    for d in ["test", "tests"]:
        dpath = root / d
        if not dpath.exists():
            continue
        for f in dpath.rglob("*.sol"):
            if f.name.startswith(("Test", "test")):
                return str(f)
        sols = list(dpath.rglob("*.sol"))
        if sols:
            return str(sols[0])
    return None
