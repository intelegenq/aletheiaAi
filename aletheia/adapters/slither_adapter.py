"""Slither adapter — runs the slither-vulndb pattern pack."""

from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import Optional

from .base import ScanResult, load_jsonl

PACK_ROOT = Path(os.environ.get(
    "ALETHEIA_PACK_ROOT",
    str(Path(__file__).resolve().parents[2] / "slither-vulndb"),
))
VENV_PYTHON = os.environ.get("ALETHEIA_SLITHER_PY", "")
if not VENV_PYTHON:
    # Try sys.executable first; if it can't import slither, fall back to python3.12
    import shutil
    for candidate in (sys.executable, "python3.12", "python3.11"):
        if candidate and shutil.which(candidate):
            import subprocess
            try:
                r = subprocess.run([candidate, "-c", "from slither import Slither"], capture_output=True, timeout=10)
                if r.returncode == 0:
                    VENV_PYTHON = candidate
                    break
            except Exception:
                continue
    if not VENV_PYTHON:
        VENV_PYTHON = sys.executable
FOUNDRY_BIN = os.environ.get("ALETHEIA_FOUNDRY_BIN", "")


def run_slither(
    target: str,
    timeout: int = 600,
    output_dir: Optional[Path] = None,
    build_context=None,
) -> ScanResult:
    """Run slither pattern pack via agent_adapter.py."""
    env = dict(os.environ)
    # The adapter may be launched with an absolute virtualenv interpreter while
    # its bin directory is absent from PATH. The pattern pack invokes the
    # `slither` executable internally, so expose the interpreter's bin dir.
    # Keep the symlink path itself: resolving it can move from the project
    # virtualenv back to the runtime interpreter and hide `.venv/bin/slither`.
    python_bin = str(Path(VENV_PYTHON).parent.resolve())
    env["PATH"] = f"{python_bin}:{FOUNDRY_BIN}:{env.get('PATH', '')}"
    if build_context and build_context.solc_version:
        env["SOLC_VERSION"] = build_context.solc_version

    out_path = (output_dir / "slither_findings.json") if output_dir else Path("/tmp/slither_findings.json")

    cmd = [
        VENV_PYTHON,
        str(PACK_ROOT / "agent_adapter.py"),
        target,
        "--format", "json",
        "--output", str(out_path),
    ]

    import time
    t0 = time.time()
    code, stdout, stderr = _run(cmd, timeout, env)
    dur = time.time() - t0

    findings = []
    if out_path.exists():
        try:
            payload = __import__("json").loads(out_path.read_text())
            findings = payload.get("results") or payload.get("findings") or []
        except Exception:
            findings = []
    elif "pp-" in stdout or "sl-" in stdout:
        findings = load_jsonl(out_path)

    error = ""
    if code not in (0, 1):
        error = stderr.strip() or f"exit {code}"

    return ScanResult(
        engine="slither",
        success=code in (0, 1),
        exit_code=code,
        stdout=stdout,
        stderr=stderr,
        raw_findings=findings,
        error=error,
        duration_sec=dur,
        artifact_path=str(out_path) if out_path.exists() else "",
    )


def _run(cmd, timeout, env):
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"
