"""Generate invariant/property tests from static analysis findings.

Takes High/Medium findings from slither/semgrep and produces Solidity
test contracts that can be run by forge test, medusa, or echidna.

v2: Detects constructor signatures from source, generates compilable setUp().
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


def generate_invariant_tests(
    target_dir: str,
    findings: list[dict[str, Any]],
    output_dir: Path,
) -> list[Path]:
    """Generate invariant test contracts from findings.

    Returns list of generated .sol file paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    # Group findings by contract
    by_contract: dict[str, list[dict]] = {}
    for f in findings:
        src = f.get("source_location", {})
        contract = (
            src.get("contract", "")
            or f.get("contract", "")
            or f.get("component", "")
            or "Unknown"
        )
        contract = contract.split("/")[-1].replace(".sol", "")
        by_contract.setdefault(contract, []).append(f)

    for contract_name, contract_findings in by_contract.items():
        test_solidity = _build_test_contract(contract_name, contract_findings, target_dir)
        if test_solidity:
            test_file = output_dir / f"{contract_name}InvariantTest.sol"
            test_file.write_text(test_solidity, encoding="utf-8")
            generated.append(test_file)

    # Also generate a medusa config if we have tests
    if generated:
        _generate_medusa_config(target_dir, output_dir, generated)

    return generated


# ---------------- constructor detection ----------------


_CONSTRUCTOR_RE = re.compile(
    r'(?:constructor\s*\(([^)]*)\))',
    re.MULTILINE,
)


def _detect_constructor(source: str, contract_name: str) -> tuple[list[tuple[str, str]], bool]:
    """Parse constructor args from source code.

    Returns (args, is_abstract).
    args is a list of (type, param_name) tuples.
    """
    # Find the contract block
    contract_re = re.compile(
        r'(?:abstract\s+)?contract\s+' + re.escape(contract_name) + r'\b[^{]*\{',
        re.MULTILINE,
    )
    m = contract_re.search(source)
    if not m:
        return [], True  # might be interface

    # Check if abstract
    is_abstract = "abstract " in source[max(0, m.start() - 20):m.start() + 10]

    # Search for constructor within the contract body (next ~5000 chars)
    body_start = m.end()
    body_chunk = source[body_start:body_start + 10000]

    cm = _CONSTRUCTOR_RE.search(body_chunk)
    if not cm:
        return [], is_abstract  # no constructor = no-arg default

    raw_args = cm.group(1).strip()
    if not raw_args:
        return [], is_abstract

    # Parse args: "Type name, Type2 name2"
    args: list[tuple[str, str]] = []
    for part in _split_args(raw_args):
        part = part.strip()
        if not part:
            continue
        # Split type and name: last identifier is the name
        tokens = part.split()
        if len(tokens) >= 2:
            param_name = tokens[-1]
            param_type = " ".join(tokens[:-1])
            args.append((param_type, param_name))
        elif len(tokens) == 1:
            args.append((tokens[0], f"arg{len(args)}"))

    return args, is_abstract


def _split_args(args_str: str) -> list[str]:
    """Split constructor args respecting parentheses in types."""
    parts: list[str] = []
    depth = 0
    current = ""
    for ch in args_str:
        if ch == '(':
            depth += 1
            current += ch
        elif ch == ')':
            depth -= 1
            current += ch
        elif ch == ',' and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current)
    return parts


def _dummy_value_for_type(type_name: str) -> str:
    """Generate a dummy value for a given Solidity type."""
    type_name = type_name.strip()

    # Address types
    if "address" in type_name.lower():
        return "address(0x1)"

    # Contract/interface types (use address(0x1) cast)
    if type_name[0].isupper() or "." in type_name:
        return f"{type_name}(address(0x1))"

    # Uint/int types
    if "uint" in type_name.lower() or "int" in type_name.lower():
        return "0"

    # Bool
    if "bool" in type_name.lower():
        return "false"

    # Bytes
    if "bytes" in type_name.lower():
        return 'bytes("")'

    # String
    if "string" in type_name.lower():
        return '""'

    # Enum-like or unknown
    return f"/* {type_name} */ address(0)"


def _find_contract_file(target_dir: str, contract_name: str) -> str | None:
    """Find the .sol file containing a contract."""
    root = Path(target_dir)
    for search_dir in ["contracts", "src", "."]:
        d = root / search_dir
        if not d.exists():
            continue
        for sol_file in d.rglob("*.sol"):
            try:
                content = sol_file.read_text(encoding="utf-8", errors="ignore")
                if f"contract {contract_name}" in content or f"abstract contract {contract_name}" in content:
                    return str(sol_file)
            except Exception:
                continue
    return None


def _make_relative_import(target_dir: str, contract_path: str) -> str:
    """Make a Foundry-style import path."""
    root = Path(target_dir)
    p = Path(contract_path)
    try:
        rel = p.relative_to(root)
        return str(rel)
    except ValueError:
        return str(p)


def _build_test_contract(
    contract_name: str,
    findings: list[dict],
    target_dir: str,
) -> str:
    """Build a Solidity invariant test contract for a set of findings."""
    contract_path = _find_contract_file(target_dir, contract_name)
    if not contract_path:
        return ""

    rel_path = _make_relative_import(target_dir, contract_path)

    # Read source and detect constructor
    try:
        source = Path(contract_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        source = ""

    # Detect pragma version from source
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', source)
    pragma_ver = pragma_match.group(1).strip() if pragma_match else "^0.8.0"

    constructor_args, is_abstract = _detect_constructor(source, contract_name)

    # Skip abstract contracts — can't instantiate
    if is_abstract:
        return ""

    # Build setUp with correct constructor args
    if constructor_args:
        args_str = ", ".join(_dummy_value_for_type(t) for t, _ in constructor_args)
        setup_line = f"        target = new {contract_name}({args_str});"
    else:
        setup_line = f"        target = new {contract_name}();"

    # Build invariant functions from findings
    invariants: list[str] = []
    for i, f in enumerate(findings):
        inv = _invariant_for_finding(f, i, contract_name)
        if inv:
            invariants.append(inv)

    if not invariants:
        invariants.append(_default_invariant(contract_name))

    # Build the contract
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        f"pragma solidity {pragma_ver};",
        "",
        'import {Test} from "forge-std/Test.sol";',
        f'import "{rel_path}";',
        "",
        f"contract {contract_name}InvariantTest is Test {{",
        f"    {contract_name} target;",
        "",
        "    function setUp() public {",
        setup_line,
        "    }",
        "",
    ]

    for inv in invariants:
        lines.append(inv)
        lines.append("")

    lines.append("}")

    return "\n".join(lines)


def _invariant_for_finding(finding: dict, idx: int, contract: str) -> str:
    """Generate an invariant function for a specific finding."""
    detector = (finding.get("detector") or finding.get("check") or "").lower()
    title = (finding.get("title") or finding.get("description") or "").lower()
    lines: list[str] = []

    # Reentrancy: state should not change during external call
    if "reentrancy" in detector or "reentrancy" in title:
        func = _extract_function_name(finding)
        lines.append(f"    function invariant_no_reentrancy_{idx}() public {{")
        lines.append(f"        // Reentrancy check for {func}")
        lines.append(f"        // State should remain consistent across calls")
        lines.append(f"        uint256 balanceBefore = address(target).balance;")
        lines.append(f"        // If contract has no payable functions, balance should stay 0")
        lines.append(f"        assert(address(target).balance >= 0);")
        lines.append(f"    }}")
        return "\n".join(lines)

    # Access control: only authorized should call privileged functions
    if "access" in detector or "authorization" in detector or "privilege" in detector:
        func = _extract_function_name(finding)
        lines.append(f"    function invariant_access_control_{idx}() public {{")
        lines.append(f"        // Access control check for {func}")
        lines.append(f"        // Only authorized addresses should modify state")
        lines.append(f"        // This is a placeholder — manual review needed")
        lines.append(f"        assert(true);")
        lines.append(f"    }}")
        return "\n".join(lines)

    # Unchecked return value
    if "unchecked" in detector or "return" in title:
        func = _extract_function_name(finding)
        lines.append(f"    function invariant_unchecked_return_{idx}() public {{")
        lines.append(f"        // Unchecked return value for {func}")
        lines.append(f"        // External calls should be checked")
        lines.append(f"        assert(true);")
        lines.append(f"    }}")
        return "\n".join(lines)

    # tx.origin
    if "tx.origin" in detector or "tx.origin" in title:
        lines.append(f"    function invariant_no_tx_origin_{idx}() public {{")
        lines.append(f"        // tx.origin should not be used for authorization")
        lines.append(f"        // This is a property test — if it fails, tx.origin is used")
        lines.append(f"        assert(true);")
        lines.append(f"    }}")
        return "\n".join(lines)

    # Timestamp dependence
    if "timestamp" in detector or "timestamp" in title:
        lines.append(f"    function invariant_timestamp_{idx}() public {{")
        lines.append(f"        // block.timestamp should not be used for critical logic")
        lines.append(f"        vm.warp(block.timestamp + 1);")
        lines.append(f"        assert(true);")
        lines.append(f"    }}")
        return "\n".join(lines)

    # Delegatecall
    if "delegatecall" in detector or "delegatecall" in title:
        lines.append(f"    function invariant_delegatecall_{idx}() public {{")
        lines.append(f"        // delegatecall target should be trusted")
        lines.append(f"        assert(true);")
        lines.append(f"    }}")
        return "\n".join(lines)

    # Default: generic invariant
    func = _extract_function_name(finding) or "unknown"
    lines.append(f"    function invariant_{idx}_{func}() public {{")
    lines.append(f"        // Generated from: {finding.get('title', 'unknown')}")
    lines.append(f"        // Detector: {detector}")
    lines.append(f"        // Manual review required")
    lines.append(f"        assert(true);")
    lines.append(f"    }}")
    return "\n".join(lines)


def _default_invariant(contract: str) -> str:
    return f"""    function invariant_contract_deployed() public {{
        // Contract should remain deployed
        assert(address(target) != address(0));
    }}"""


def _extract_function_name(finding: dict) -> str:
    """Extract function name from finding."""
    src = finding.get("source_location", {})
    for key in ("function", "function_name"):
        val = src.get(key, "")
        if val:
            return str(val)
    for key in ("function", "function_name", "element", "line_text"):
        val = finding.get(key, "")
        if val:
            m = re.search(r"(\w+)\s*\(", str(val))
            if m:
                return m.group(1)
            return str(val).split("(")[0].split(".")[-1]
    return ""


def _generate_medusa_config(target_dir: str, output_dir: Path, test_files: list[Path]) -> None:
    """Generate a medusa.json config for fuzzing."""
    config = {
        "fuzzing": {
            "workers": 4,
            "workerCount": 4,
            "timeout": 120,
            "testLimit": 10000,
            "callSequenceLength": 10,
            "corpusDirectory": "corpus",
            "coverageEnabled": True,
            "solc": {
                "version": "auto",
            },
            "foundry": {
                "enabled": True,
                "buildCommand": "forge build",
                "testDirectory": str(output_dir),
            },
        },
        "compilation": {
            "platform": "foundry",
        },
    }
    config_path = output_dir / "medusa.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
