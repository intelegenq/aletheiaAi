"""Project intake: detect build system, Solidity version, contracts, compile."""

from __future__ import annotations
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from .chains import ChainTarget, classify_target


@dataclass
class BuildContext:
    """Describes a target project for scanning."""
    root: Path
    foundry: bool = False
    foundry_toml: Optional[Path] = None
    solc_version: str = ""
    contracts: list[Path] = field(default_factory=list)
    test_files: list[Path] = field(default_factory=list)
    sol_files: list[Path] = field(default_factory=list)
    has_build_artifact: bool = False
    build_status: str = "not-built"  # not-built, ok, failed
    build_log: str = ""
    error: str = ""
    chain: ChainTarget = field(default_factory=ChainTarget)

    def to_dict(self) -> dict:
        return {
            "root": str(self.root),
            "foundry": self.foundry,
            "foundry_toml": str(self.foundry_toml) if self.foundry_toml else None,
            "solc_version": self.solc_version,
            "contracts": [str(p) for p in self.contracts],
            "test_files": [str(p) for p in self.test_files],
            "sol_files": [str(p) for p in self.sol_files],
            "has_build_artifact": self.has_build_artifact,
            "build_status": self.build_status,
            "build_log": self.build_log,
            "error": self.error,
            "chain": self.chain.to_dict(),
        }


def detect_foundry(root: Path) -> tuple[bool, Optional[Path]]:
    toml = root / "foundry.toml"
    return toml.exists(), toml if toml.exists() else None


def detect_solc_version(root: Path) -> str:
    """Detect solc version from foundry.toml or first .sol pragma."""
    toml = root / "foundry.toml"
    if toml.exists():
        text = toml.read_text()
        m = re.search(r'(?:solc|solc_version)\s*=\s*["\']?([\d.]+)', text, re.IGNORECASE)
        if m:
            return m.group(1)
    # read pragma from first .sol
    sol_files = list(root.rglob("*.sol"))
    for f in sol_files[:50]:
        if "node_modules" in str(f):
            continue
        try:
            text = f.read_text(errors="ignore")
            m = re.search(r'pragma\s+solidity\s+[~^]?\s*([\d.]+)', text)
            if m:
                return m.group(1)
        except Exception:
            continue
    return ""


def find_sol_files(root: Path) -> list[Path]:
    sols = list(root.rglob("*.sol"))
    return [f for f in sols if "node_modules" not in str(f)]


def classify_contracts(
    root: Path, sol_files: list[Path]
) -> tuple[list[Path], list[Path], list[Path]]:
    contracts = []
    tests = []
    libs = []
    for f in sol_files:
        rel = str(f.relative_to(root))
        if rel.replace("\\", "/").startswith(("test/", "tests/", "script/", "scripts/")):
            tests.append(f)
        elif "forge-std" in rel or "ds-test" in rel or "node_modules" in rel:
            libs.append(f)
        else:
            contracts.append(f)
    return contracts, tests, libs


def solc_use_version(version: str) -> tuple[bool, str]:
    """Switch solc version with solc-select if available."""
    try:
        which = subprocess.run(
            ["which", "solc-select"], capture_output=True, text=True, timeout=10
        )
        if which.returncode == 0 and version:
            r = subprocess.run(
                ["solc-select", "use", version],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                return True, f"solc-select switched to {version}"
            else:
                return False, f"solc-select failed: {r.stderr.strip()}"
        return False, "solc-select not available"
    except Exception as e:
        return False, str(e)


def build_foundry(root: Path) -> tuple[bool, str]:
    """Run forge build."""
    try:
        r = subprocess.run(
            ["forge", "build"],
            cwd=root,
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode == 0:
            return True, r.stdout[-500:] if r.stdout else "build ok"
        return False, r.stderr[-500:] if r.stderr else f"exit {r.returncode}"
    except subprocess.TimeoutExpired:
        return False, "forge build timeout (300s)"
    except FileNotFoundError:
        return False, "forge not found in PATH"
    except Exception as e:
        return False, str(e)


def intake(path: str, with_build: bool = True, solc_switch: bool = True) -> BuildContext:
    """Analyze a local project path and return build context."""
    root = Path(path).resolve()
    ctx = BuildContext(root=root)

    if not root.exists():
        ctx.error = f"path does not exist: {path}"
        return ctx
    if not root.is_dir():
        ctx.error = f"not a directory: {path}"
        return ctx

    # detect foundry
    ctx.foundry, ctx.foundry_toml = detect_foundry(root)

    # find all recognized source files
    ctx.sol_files = find_sol_files(root)
    all_source_files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".sol", ".move", ".rs", ".ts"} and "node_modules" not in str(p)]
    ctx.chain = classify_target(root, all_source_files)
    if not all_source_files:
        # Keep the legacy phrase for callers/tests while covering all
        # supported source types in the explanation.
        ctx.error = "no .sol files or recognized source files found"
        return ctx

    # classify
    if ctx.sol_files:
        ctx.contracts, ctx.test_files, _ = classify_contracts(root, ctx.sol_files)
    else:
        ctx.contracts = [p for p in all_source_files if p.name not in {"test.rs", "tests.rs"}]
        ctx.test_files = [p for p in all_source_files if p.name.startswith("test")]

    # detect solc version
    ctx.solc_version = detect_solc_version(root)

    # switch solc version
    if solc_switch and ctx.solc_version:
        solc_use_version(ctx.solc_version)

    # build
    if with_build and ctx.foundry:
        ok, log = build_foundry(root)
        ctx.build_status = "ok" if ok else "failed"
        ctx.build_log = log
        ctx.has_build_artifact = ok and (root / "out").exists()

    if not ctx.build_log:
        ctx.build_status = "skipped"

    return ctx
