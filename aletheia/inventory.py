"""Inventory — show available tools and adapters."""

from __future__ import annotations
import subprocess
import sys
from pathlib import Path


def check_bin(name: str) -> bool:
    try:
        r = subprocess.run(["which", name], capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


def get_version(name: str) -> str:
    try:
        r = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()[:60] or r.stderr.strip()[:60]
    except Exception:
        return ""


def show_inventory() -> int:
    print("=" * 60)
    print("ALETHEIA AI — TOOL INVENTORY")
    print("=" * 60)
    print()

    tools = [
        ("forge", "Foundry build/test"),
        ("slither", "Static analysis"),
        ("myth", "Mythril symbolic"),
        ("semgrep", "Semgrep pattern"),
        ("medusa", "Medusa fuzzer"),
        ("echidna", "Echidna fuzzer"),
    ]

    for cmd, desc in tools:
        installed = check_bin(cmd)
        if cmd == "slither" and not installed:
            try:
                import importlib.util
                installed = importlib.util.find_spec("slither") is not None
            except Exception:
                installed = False
        status = "✅" if installed else "❌"
        ver = f" ({get_version(cmd)})" if installed else ""
        print(f"  {status} {cmd:15s} — {desc}{ver}")

    print()
    print("Available adapters:")
    from aletheia.adapters.registry import ADAPTERS
    for name in sorted(ADAPTERS):
        print(f"  • {name}")

    from aletheia.adapters.registry import ADAPTER_CATEGORIES
    print()
    print("Scanner categories:")
    for name, cat in sorted(ADAPTER_CATEGORIES.items()):
        print(f"  • {name:15s} → {cat}")

    # Check slither pack
    import os
    pack = Path(os.environ.get("ALETHEIA_PACK_ROOT", str(Path(__file__).resolve().parent.parent / "slither-vulndb")))
    if pack.exists():
        print(f"\n  ✅ Slither vulndb pack: {pack}")
        from aletheia.adapters.slither_adapter import PACK_ROOT
        detectors = list(pack.glob("detectors/*.py"))
        native = list(pack.glob("registry/*.json"))
        print(f"     Custom detectors: {len([d for d in detectors if not d.name.startswith('_')])}")
        print(f"     Registry files: {len(native)}")
    else:
        print(f"\n  ❌ Slither vulndb pack not found ({pack})")

    print()
    return 0
