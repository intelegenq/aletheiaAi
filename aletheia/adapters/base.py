"""Base scanner adapter interface."""

from __future__ import annotations
import subprocess
import sys
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class ScanResult:
    """Raw output from a single scanner engine."""
    engine: str
    success: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    raw_findings: list[dict] = field(default_factory=list)
    error: str = ""
    duration_sec: float = 0.0
    artifact_path: str = ""


def run_command(
    cmd: list[str],
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> tuple[int, str, str]:
    """Run a subprocess; returns (exit_code, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return -2, "", f"command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def check_binary(name: str) -> bool:
    """Check if a binary is available via which."""
    r = subprocess.run(["which", name], capture_output=True, text=True, timeout=10)
    return r.returncode == 0


def load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file, skipping malformed lines."""
    items = []
    if not path.exists():
        return items
    text = path.read_text(errors="replace")
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items