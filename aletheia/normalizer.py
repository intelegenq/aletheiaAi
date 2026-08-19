"""Finding normalizer — converts raw adapter output to AletheiaAI Finding."""

from __future__ import annotations
from pathlib import Path
from typing import Any, Optional

from .adapters.base import ScanResult
from .models import Finding, SourceLocation, from_slither_normalized


def normalize_slither(raw_findings: list[dict], engine: str = "slither") -> list[Finding]:
    """Normalize Slither findings via agent_adapter's normalized format."""
    from .models import from_slither_normalized
    results = []
    for f in raw_findings:
        try:
            results.append(from_slither_normalized(f, engine=engine))
        except Exception:
            # try unified format
            try:
                from .models import from_unified_dict
                results.append(from_unified_dict(f))
            except Exception:
                continue
    return results


def normalize_semgrep(raw_findings: list[dict]) -> list[Finding]:
    """Normalize Semgrep results to AletheiaAI Finding."""
    results = []
    for f in raw_findings:
        path = f.get("path", f.get("location", {}).get("file", ""))
        start = f.get("start", {}).get("line", 0)
        end = f.get("end", {}).get("line", start)
        loc = SourceLocation(file=path, line_start=start, line_end=end)

        extra = f.get("extra", {})
        finding = Finding(
            engine="semgrep",
            detector=extra.get("check_id", f.get("check_id", "semgrep:rule")),
            title=extra.get("message", "Semgrep finding"),
            description=extra.get("message", ""),
            vulnerability_class=extra.get("cwe_id", "semgrep"),
            severity=extra.get("severity", "medium").lower(),
            confidence="medium",
            source_location=loc,
            status="candidate",
        )
        results.append(finding)
    return results


def normalize_mythril(raw_findings: list[dict]) -> list[Finding]:
    """Normalize Mythril results to AletheiaAI Finding."""
    results = []
    for f in raw_findings:
        loc = SourceLocation(
            file=f.get("contract_file", f.get("filename", "")),
            line_start=f.get("lineno", 0),
            contract=f.get("contract", ""),
            function=f.get("function", ""),
        )
        severity = f.get("severity", "Medium").lower()
        finding = Finding(
            engine="mythril",
            detector=f.get("swc-id", f.get("title", "mythril:unknown")),
            title=f.get("title", ""),
            description=f.get("description", f.get("head", "")),
            vulnerability_class=f.get("swc-id", str(f.get("swcID", ""))),
            severity=severity,
            confidence="medium",
            source_location=loc,
            status="candidate",
        )
        results.append(finding)
    return results


def normalize_foundry(raw_findings: list[dict]) -> list[Finding]:
    """Normalize Foundry test failures to AletheiaAI Finding."""
    results = []
    for f in raw_findings:
        test_name = f.get("test", "Unknown")
        finding = Finding(
            engine="foundry",
            detector="foundry:failing-test",
            title=test_name,
            description=f.get("description", test_name),
            vulnerability_class="foundry-test",
            severity="medium",
            confidence="high",
            status="needs-verification",
            evidence=list(f.get("trace", [])),
            trace=list(f.get("trace", [])),
        )
        results.append(finding)
    return results


def normalize_fuzzing(engine: str, raw_findings: list[dict]) -> list[Finding]:
    """Normalize fuzzer findings (medusa/echidna)."""
    results = []
    for f in raw_findings:
        finding = Finding(
            engine=engine,
            detector=f"{engine}:finding",
            title=f.get("message", f"{engine} finding"),
            description=f.get("description", f.get("message", "")),
            severity=(
                "high" if any(w in str(f).lower()
                for w in ["critical", "high", "assertion", "revert"])
                else "medium"
            ),
            confidence="medium",
            status="needs-verification",
            trace=f.get("sequence", f.get("tx", [])),
            test_sequence=f.get("test_sequence", ""),
        )
        results.append(finding)
    return results


def normalize_scan_result(sr: ScanResult) -> list[Finding]:
    """Route a ScanResult to the appropriate normalizer."""
    engine = sr.engine
    raw = sr.raw_findings

    if engine == "slither":
        return normalize_slither(raw)
    elif engine == "semgrep":
        return normalize_semgrep(raw)
    elif engine == "mythril":
        return normalize_mythril(raw)
    elif engine == "foundry":
        return normalize_foundry(raw)
    elif engine in ("medusa", "echidna"):
        return normalize_fuzzing(engine, raw)
    return []