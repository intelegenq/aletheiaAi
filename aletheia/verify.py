"""Verification pipeline — runs conviction engine + optional test/PoC generation."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Optional

from .models import Finding, to_dict, to_aletheia_unified, to_sarif
from .conviction import ConvictionEngine, ConvictionResult
from .testgen import generate_test, run_generated_test, generate_poc
from .fork_sim import ForkSimulator
from .analysis_wiring import load_analysis
from .rootcause import correlate


def _load_target_analysis(target_dir: str):
    """Load real Slither analysis for a target project (best effort).

    Passes the project directory to Slither so it compiles the whole Foundry
    project (all contracts, not just one file). Falls back to single-file if
    the target is a .sol file.
    """
    import os
    if not target_dir:
        return None

    # If target is a single .sol file, analyse it directly
    if target_dir.endswith(".sol") and os.path.isfile(target_dir):
        outcome = load_analysis(target_dir)
        return outcome if outcome.ok else None

    # Otherwise pass the project directory — Slither + CryticCompile will
    # auto-detect Foundry/Hardhat and compile all contracts.
    if os.path.isdir(target_dir):
        outcome = load_analysis(target_dir)
        return outcome if outcome.ok else None

    return None


def run_verification(
    findings: list[Finding],
    run_dir: Path,
    target_dir: str = "",
    generate_tests: bool = False,
    generate_pocs: bool = False,
    fork_config: Optional[dict] = None,
    verbose: bool = True,
) -> dict[str, Any]:
    """Run the full conviction & verification pipeline.

    Returns a dict with conviction results, verdict buckets, and artifacts.
    """
    if verbose:
        print(f"[aletheia] verification: {len(findings)} findings")

    # Non-EVM findings must never enter Slither, EVM conviction, Foundry test
    # generation, or fork simulation. Their plugin verifier is conservative.
    non_evm = [f for f in findings if f.chain_family not in {"", "evm"}]
    if non_evm:
        if len(non_evm) != len(findings):
            raise ValueError("mixed EVM/non-EVM verification runs are not supported; split targets by chain")
        import aletheia.non_evm
        from .plugin_api import plugins
        plugin = next((p for p in plugins() if non_evm[0].ecosystem in p.ecosystems), None)
        if plugin is None:
            raise ValueError(f"no verifier plugin for {non_evm[0].ecosystem}")
        facts = None
        if target_dir:
            descriptor = plugin.detect_target(Path(target_dir))
            facts = plugin.collect_semantic_facts(descriptor) if descriptor else None
        run_dir.mkdir(parents=True, exist_ok=True)
        results = {}
        for finding in findings:
            result = plugin.verify(finding, None, facts, [])
            finding.status = result.verdict; finding.verification_status = result.verdict
            results[finding.finding_id] = result
        payload={"schema_version":"aletheia.chain-verification.v1", "count":len(results), "results":[r.to_dict() for r in results.values()]}
        (run_dir / "chain-verification.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        # Triage/workflow consume the established conviction artifact.  This
        # compatibility projection never promotes a chain finding and contains
        # no EVM analysis fields.
        projected = {"schema_version": "aletheia.conviction.v2", "count": len(results), "root_causes": [],
                     "results": [{"finding_id": r.finding_id, "verdict": r.verdict, "score": 0.0,
                                  "reasons": r.limitations + r.semantic_checks, "confidence": "low",
                                  "access_control_verdict": "unknown", "call_path_verdict": "unknown",
                                  "evidence_summary": {"chain_family": r.chain_family, "ecosystem": r.ecosystem},
                                  "exploitability": {}, "verification_artifacts": []} for r in results.values()]}
        (run_dir / "conviction.json").write_text(json.dumps(projected, indent=2, sort_keys=True), encoding="utf-8")
        (run_dir / "verified-findings.json").write_text(json.dumps(to_aletheia_unified([]), indent=2, sort_keys=True), encoding="utf-8")
        (run_dir / "needs-review.json").write_text(json.dumps(to_aletheia_unified(findings), indent=2, sort_keys=True), encoding="utf-8")
        return {"conviction_results": results, "verified": [], "rejected": [], "needs_review": findings,
                "needs_dynamic_validation": [], "findings": findings, "root_cause_map": {}}

    # --- real static analysis (single load, shared by all checks) ---
    analysis = _load_target_analysis(target_dir)
    if verbose:
        if analysis is not None:
            print(f"[aletheia]   analysis: ok — {len(analysis.all_functions)} functions, "
                  f"{len(analysis.entry_points)} entry points")
        else:
            print("[aletheia]   analysis: unavailable — access-control/reachability stay unknown")

    # --- cross-engine root-cause correlation ---
    before = len(findings)
    findings, root_cause_map = correlate(findings, analysis)
    if verbose:
        print(f"[aletheia]   root-cause correlation: {before} -> {len(findings)}")

    engine = ConvictionEngine(findings, target_dir=target_dir, analysis=analysis)
    verification_dir = run_dir / "verification"
    verification_dir.mkdir(parents=True, exist_ok=True)

    # Fork simulation (once per run — config-driven)
    fork = ForkSimulator(fork_config)
    fork_result = fork.run()
    if verbose:
        print(f"[aletheia]   fork simulation: {fork_result.status} — {fork_result.reason}")

    conviction_results: dict[str, ConvictionResult] = {}
    testgen_results: dict[str, dict] = {}
    pocgen_results: dict[str, dict] = {}

    for f in findings:
        # --- conviction ---
        try:
            cr = engine.evaluate(f.finding_id)
        except Exception as e:
            cr = ConvictionResult(
                finding_id=f.finding_id,
                verdict="needs-review",
                reasons=[f"conviction error: {e}"],
                checks_failed=["conviction"],
            )
        conviction_results[f.finding_id] = cr

        # Sync evidence summary flags now that checks ran
        cr.evidence_summary["source_verified"] = cr.source_verified
        cr.evidence_summary["access_control_verified"] = cr.access_control_verdict != "unknown"
        cr.evidence_summary["call_path_verified"] = cr.call_path_verdict != "unknown"

        finding_dir = verification_dir / f.finding_id
        finding_dir.mkdir(parents=True, exist_ok=True)

        # --- test generation (opt-in) ---
        if generate_tests:
            try:
                tg = generate_test(f, finding_dir, target_dir=target_dir, analysis=analysis)
            except Exception as e:
                tg = {"generated": False, "reason": f"testgen error: {e}"}
            testgen_results[f.finding_id] = tg

            if tg.get("generated") and tg.get("test_path"):
                cr.verification_artifacts.append(tg["test_path"])
                # Run the generated test; failures never break the pipeline.
                try:
                    tr = run_generated_test(tg["test_path"], target_dir)
                except Exception as e:
                    tr = {"ran": False, "stderr": str(e)}
                tg["run_result"] = tr
                out_txt = finding_dir / "test_output.txt"
                out_txt.write_text(
                    (tr.get("stdout") or "") + "\n" + (tr.get("stderr") or ""),
                    encoding="utf-8",
                )
                cr.verification_artifacts.append(str(out_txt))
                cr.checks_run.append("generated_test")
                if tr.get("ran"):
                    # A generated security test that FAILS reproduces the bug.
                    if tr.get("passed") is False:
                        cr.checks_passed.append("generated_test")
                        cr.reasons.append("Generated Foundry test reproduces the issue (test failed as expected)")
                    else:
                        cr.checks_failed.append("generated_test")
                        cr.reasons.append("Generated Foundry test passed — issue not reproduced by generated test")
                else:
                    cr.checks_failed.append("generated_test")
                    cr.reasons.append(f"Generated test could not run: {tr.get('stderr','')[:120]}")
            else:
                cr.reasons.append(f"Test generation skipped: {tg.get('reason','unsupported')}")

        # --- PoC generation (opt-in, only for reproducible findings) ---
        if generate_pocs:
            ex = cr.exploitability or {}
            if cr.verdict == "verified" and ex.get("reproducible"):
                try:
                    pg = generate_poc(f, finding_dir, target_dir=target_dir)
                except Exception as e:
                    pg = {"generated": False, "reason": f"pocgen error: {e}"}
            else:
                pg = {
                    "generated": False,
                    "reason": f"PoC skipped: verdict={cr.verdict} reproducible={ex.get('reproducible')}",
                    "local_only": True,
                }
            pocgen_results[f.finding_id] = pg
            if pg.get("generated") and pg.get("poc_path"):
                cr.verification_artifacts.append(pg["poc_path"])

        # --- fork simulation status recorded per finding ---
        cr.checks_run.append("fork_simulation")
        if fork_result.status == "skipped":
            cr.checks_failed.append("fork_simulation")
        else:
            cr.checks_passed.append("fork_simulation")

        # --- write per-finding conviction.json ---
        (finding_dir / "conviction.json").write_text(
            json.dumps(cr.to_dict(), indent=2, default=str), encoding="utf-8"
        )
        if f.trace:
            (finding_dir / "trace.txt").write_text("\n".join(str(t) for t in f.trace), encoding="utf-8")

        # --- promote finding status from the verdict ---
        f.status = cr.verdict

    # --- bucket the findings ---
    verified = [f for f in findings if conviction_results[f.finding_id].verdict == "verified"]
    rejected = [f for f in findings if conviction_results[f.finding_id].verdict == "rejected"]
    needs_review = [f for f in findings if conviction_results[f.finding_id].verdict == "needs-review"]
    needs_dynamic = [
        f for f in findings
        if conviction_results[f.finding_id].verdict == "needs-dynamic-validation"
    ]

    # --- write run-level artifacts ---
    conviction_payload = {
        "schema_version": "aletheia.conviction.v2",
        "count": len(conviction_results),
        "analysis": {
            "available": analysis is not None,
            "functions": len(analysis.all_functions) if analysis else 0,
            "entry_points": len(analysis.entry_points) if analysis else 0,
            "contracts": analysis.contracts if analysis else [],
        },
        "root_causes": list(root_cause_map.values()),
        "fork_simulation": {
            "status": fork_result.status,
            "reason": fork_result.reason,
            "chain_id": fork_result.chain_id,
            "block_number": fork_result.block_number,
        },
        "testgen": {
            fid: {
                "generated": t.get("generated"),
                "reason": t.get("reason", ""),
                "template": t.get("template", ""),
                "test_path": t.get("test_path", ""),
                "run": {
                    "ran": (t.get("run_result") or {}).get("ran"),
                    "passed": (t.get("run_result") or {}).get("passed"),
                    "exit_code": (t.get("run_result") or {}).get("exit_code"),
                    "stderr": ((t.get("run_result") or {}).get("stderr") or "")[:300],
                },
            }
            for fid, t in testgen_results.items()
        },
        "summary": {
            "verified": len(verified),
            "rejected": len(rejected),
            "needs_review": len(needs_review),
            "needs_dynamic_validation": len(needs_dynamic),
        },
        "results": [cr.to_dict() for cr in conviction_results.values()],
    }
    (run_dir / "conviction.json").write_text(
        json.dumps(conviction_payload, indent=2, default=str), encoding="utf-8"
    )
    (run_dir / "verified-findings.json").write_text(
        json.dumps(to_aletheia_unified(verified), indent=2, default=str), encoding="utf-8"
    )
    (run_dir / "rejected-findings.json").write_text(
        json.dumps(to_aletheia_unified(rejected), indent=2, default=str), encoding="utf-8"
    )
    (run_dir / "needs-review.json").write_text(
        json.dumps(to_aletheia_unified(needs_review + needs_dynamic), indent=2, default=str),
        encoding="utf-8",
    )

    if verbose:
        print(f"[aletheia]   verified: {len(verified)}")
        print(f"[aletheia]   rejected: {len(rejected)}")
        print(f"[aletheia]   needs-review: {len(needs_review)}")
        print(f"[aletheia]   needs-dynamic-validation: {len(needs_dynamic)}")

    return {
        "conviction_results": conviction_results,
        "verified": verified,
        "rejected": rejected,
        "needs_review": needs_review,
        "needs_dynamic_validation": needs_dynamic,
        "fork_simulation": fork_result,
        "testgen": testgen_results,
        "pocgen": pocgen_results,
        "findings": findings,
        "root_cause_map": root_cause_map,
    }


def load_findings_from_run(run_dir: Path) -> list[Finding]:
    """Rehydrate findings from a previous run's findings.json."""
    from .models import SourceLocation

    path = run_dir / "findings.json"
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for d in data.get("findings", []):
        loc = d.get("source_location") or {}
        findings.append(Finding(
            finding_id=d.get("finding_id", ""),
            fingerprint=d.get("fingerprint", ""),
            engine=d.get("engine", ""),
            detector=d.get("detector", ""),
            title=d.get("title", ""),
            description=d.get("description", ""),
            vulnerability_class=d.get("vulnerability_class", ""),
            severity=d.get("severity", "unknown"),
            confidence=d.get("confidence", "unknown"),
            status=d.get("status", "candidate"),
            source_location=SourceLocation(
                file=loc.get("file", ""),
                line_start=loc.get("line_start", 0),
                line_end=loc.get("line_end", 0),
                contract=loc.get("contract"),
                function=loc.get("function"),
            ),
            evidence=list(d.get("evidence") or []),
            trace=list(d.get("trace") or []),
            test_sequence=d.get("test_sequence"),
            exploitability_metadata=dict(d.get("exploitability_metadata") or {}),
            scope_status=d.get("scope_status", "unknown"),
            raw_artifact_reference=d.get("raw_artifact_reference", ""),
            corroborating_engines=list(d.get("corroborating_engines") or []),
            dedup_key=d.get("dedup_key", ""),
            chain_family=d.get("chain_family", "evm"), ecosystem=d.get("ecosystem", "evm"),
            language=d.get("language", "solidity"), runtime=d.get("runtime", ""),
            rule_id=d.get("rule_id", d.get("detector", "")), universal_taxonomy_id=d.get("universal_taxonomy_id", ""),
            chain_pattern_id=d.get("chain_pattern_id", ""), semantic_evidence=list(d.get("semantic_evidence") or []),
            trust_boundary=d.get("trust_boundary", ""), attacker_control=d.get("attacker_control", "unknown"), asset_model=d.get("asset_model", ""),
            cross_chain_context=dict(d.get("cross_chain_context") or {}), verification_status=d.get("verification_status", d.get("status", "candidate")),
            verification_requirements=list(d.get("verification_requirements") or []), false_positive_conditions=list(d.get("false_positive_conditions") or []),
            reproduction_status=d.get("reproduction_status", "not-attempted"),
        ))
    return findings
