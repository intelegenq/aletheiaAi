"""AletheiaAI scan orchestrator — runs intake → build → scanners → normalize → dedup → rank → report."""

from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from .intake import intake
from .adapters.registry import ADAPTERS, ADAPTER_CATEGORIES, run_adapter
from .adapters.base import ScanResult
from .normalizer import normalize_scan_result
from .dedup import deduplicate, rank_findings
from .models import Finding, to_dict, to_aletheia_unified, to_sarif
from .artifacts import ArtifactStore


def run_scan(args) -> bool:
    """Execute full scan pipeline."""
    target = args.target
    scanners_str = args.scanners or "all"
    timeout = args.timeout or 600
    no_build = getattr(args, "no_build", False)
    output_dir_arg = getattr(args, "output", "")
    emit_json = getattr(args, "json", False)
    emit_sarif = getattr(args, "sarif", False)
    do_verify = getattr(args, "verify", False)
    do_report = getattr(args, "report", False)
    report_platform = getattr(args, "platform", "default")
    gen_tests = getattr(args, "generate_tests", False)
    gen_pocs = getattr(args, "generate_poc", False)

    # --- 1. Intake ---
    print(f"[aletheia] intake: {target}")
    ctx = intake(target, with_build=not no_build)
    if ctx.error:
        print(f"[aletheia] ERROR: {ctx.error}")
        return False
    print(f"[aletheia]   chain={ctx.chain.primary} confidence={ctx.chain.confidence} foundry={ctx.foundry} solc={ctx.solc_version} contracts={len(ctx.contracts)} tests={len(ctx.test_files)}")
    print(f"[aletheia]   build={ctx.build_status}")

    if ctx.chain.primary != "evm":
        output_dir = Path(getattr(args, "output", "") or (Path(os.environ.get("ALETHEIA_RESULTS_DIR", "artifacts")) / str(int(time.time()))))
        output_dir.mkdir(parents=True, exist_ok=True)
        store = ArtifactStore()
        store.base_dir = output_dir
        store.init()
        manifest = {
            "run_id": store.run_id, "target": target, "build_context": ctx.to_dict(),
            "scanners": [], "chain_status": {"chain": ctx.chain.primary, "supported": False, "reason": "no enabled adapter for this chain"},
            "results": {"total_findings": 0, "by_severity": {}, "by_engine": {}, "by_status": {}}, "engine_results": {},
        }
        store.save_run(manifest)
        (output_dir / "findings.json").write_text(json.dumps(to_aletheia_unified([]), indent=2), encoding="utf-8")
        print(f"[aletheia] chain {ctx.chain.primary}: no adapter enabled; scan deferred without false findings")
        return True

    # --- 2. Resolve scanners ---
    selected = _resolve_scanners(scanners_str, ctx)
    if not selected:
        print("[aletheia] ERROR: no scanners selected")
        return False
    print(f"[aletheia] scanners: {', '.join(selected)}")

    # --- 3. Init artifact store ---
    store = ArtifactStore()
    run_dir = output_dir_arg if output_dir_arg else str(store.init())
    output_dir = Path(run_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    # All phase artifacts must share the requested run directory. Previously
    # ArtifactStore kept its auto-generated default while findings.json used
    # --output, leaving resume/verify without run_manifest.json.
    store.base_dir = output_dir
    store.init()
    print(f"[aletheia] output: {output_dir}")

    # --- 4. Run each scanner ---
    scan_results: list[ScanResult] = []
    all_findings: list[Finding] = []

    for engine in selected:
        print(f"[aletheia]   running {engine}...")
        t0 = time.time()

        sr = run_adapter(
            engine=engine,
            target=target,
            timeout=timeout,
            output_dir=output_dir,
            build_context=ctx,
        )

        dur = time.time() - t0
        status = "OK" if sr.success else "FAIL"
        print(f"[aletheia]   {engine}: {status} ({dur:.1f}s, exit={sr.exit_code}, findings={len(sr.raw_findings)})")

        # save raw artifact
        if sr.stdout:
            store.save_artifact(engine, sr.stdout, "stdout.txt")
        if sr.stderr:
            store.save_artifact(engine, sr.stderr, "stderr.txt")
        if sr.raw_findings:
            store.save_json(engine, sr.raw_findings, "raw_findings.json")

        scan_results.append(sr)

        # normalize
        try:
            normalized = normalize_scan_result(sr)
            for f in normalized:
                if not f.engine:
                    f.engine = engine
            all_findings.extend(normalized)
            print(f"[aletheia]   {engine}: normalized {len(normalized)} findings")
        except Exception as e:
            print(f"[aletheia]   {engine}: normalize failed: {e}")

    # --- 5. Deduplicate ---
    before = len(all_findings)
    deduped = deduplicate(all_findings)
    print(f"[aletheia] dedup: {before} -> {len(deduped)}")

    # --- 6. Rank ---
    ranked = rank_findings(deduped)

    # --- 7. Verification (opt-in) ---
    if do_verify:
        from .verify import run_verification
        fork_config = {
            "rpc_url": os.environ.get("ALETHEIA_RPC_URL", ""),
            "chain_id": os.environ.get("ALETHEIA_CHAIN_ID", ""),
            "block_number": os.environ.get("ALETHEIA_FORK_BLOCK", ""),
        }
        vres = run_verification(
            findings=ranked,
            run_dir=output_dir,
            target_dir=target,
            generate_tests=gen_tests,
            generate_pocs=gen_pocs,
            fork_config=fork_config,
            verbose=True,
        )
        # statuses are promoted on the finding objects; re-serialize below

    # --- 8. Triage (opt-in, after verification) ---
    do_triage = getattr(args, "triage", False)
    triage_policy = getattr(args, "policy", "default")
    triage_results = []
    if do_verify and do_triage:
        from .triage import run_triage
        triage_results = run_triage(
            findings=vres.get("findings", ranked),
            conviction_results=vres.get("conviction_results", {}),
            root_cause_map=vres.get("root_cause_map", {}),
            config={},
            policy_name=triage_policy,
            verbose=True,
        )
        # Write triage artifacts
        (output_dir / "triage.json").write_text(
            json.dumps([t.to_dict() for t in triage_results], indent=2, default=str),
            encoding="utf-8",
        )
        # Write severity/priority
        sev_data = []
        pri_data = []
        for t in triage_results:
            sev_data.append({
                "finding_id": t.finding_id,
                "severity": t.severity,
                "confidence": t.confidence,
            })
            pri_data.append({
                "finding_id": t.finding_id,
                "priority": t.priority,
                "rationale": t.rationale,
                "missing_information": t.missing_information,
            })
        (output_dir / "severity.json").write_text(
            json.dumps(sev_data, indent=2, default=str), encoding="utf-8",
        )
        (output_dir / "priority.json").write_text(
            json.dumps(pri_data, indent=2, default=str), encoding="utf-8",
        )

        # Strict report-ready gate; everything else goes to needs-review / out-of-scope
        from .triage import bucket_triage_results
        report_ready, needs_review_t, out_of_scope_t = bucket_triage_results(triage_results)
        (output_dir / "report-ready-findings.json").write_text(
            json.dumps(report_ready, indent=2, default=str), encoding="utf-8",
        )
        (output_dir / "needs-review.json").write_text(
            json.dumps(needs_review_t, indent=2, default=str), encoding="utf-8",
        )
        (output_dir / "out-of-scope.json").write_text(
            json.dumps(out_of_scope_t, indent=2, default=str), encoding="utf-8",
        )
        print(
            f"[aletheia] triage: {len(triage_results)} results — "
            f"{len(report_ready)} report-ready, {len(needs_review_t)} needs-review, "
            f"{len(out_of_scope_t)} out-of-scope"
        )

        if do_report:
            from .reporting import generate_reports
            reports = generate_reports(
                findings=vres.get("findings", ranked),
                triage_results=triage_results,
                output_dir=output_dir,
                policy=triage_policy,
                platform=report_platform,
            )
            print(f"[aletheia] report: {len(reports)} report-ready findings ({report_platform})")

    # --- 9. Output ---
    # Build run manifest
    manifest = {
        "run_id": store.run_id,
        "target": target,
        "build_context": ctx.to_dict(),
        "scanners": selected,
        "results": {
            "total_findings": len(ranked),
            "by_severity": {},
            "by_engine": {},
            "by_status": {},
        },
        "engine_results": {
            sr.engine: {
                "success": sr.success,
                "exit_code": sr.exit_code,
                "finding_count": len(sr.raw_findings),
                "error": sr.error,
                "duration_sec": round(sr.duration_sec, 1),
            }
            for sr in scan_results
        },
    }

    # populate stats
    for f in ranked:
        sev = f.severity.lower()
        manifest["results"]["by_severity"][sev] = manifest["results"]["by_severity"].get(sev, 0) + 1
        eng = f.engine
        manifest["results"]["by_engine"][eng] = manifest["results"]["by_engine"].get(eng, 0) + 1
        st = f.status
        manifest["results"]["by_status"][st] = manifest["results"]["by_status"].get(st, 0) + 1

    store.save_run(manifest)

    # Write unified findings
    unified = to_aletheia_unified(ranked)
    (output_dir / "findings.json").write_text(json.dumps(unified, indent=2, default=str), encoding="utf-8")
    print(f"[aletheia] findings written: {output_dir / 'findings.json'}")

    # Write SARIF if requested
    if emit_sarif:
        sarif = to_sarif(ranked)
        (output_dir / "findings.sarif").write_text(json.dumps(sarif, indent=2, default=str), encoding="utf-8")
        print(f"[aletheia] sarif written: {output_dir / 'findings.sarif'}")

    # emit JSON to stdout
    if emit_json:
        print(json.dumps(unified, indent=2, default=str))

    # Summary
    print()
    print("=" * 60)
    print("ALETHEIA AI — SCAN COMPLETE")
    print("=" * 60)
    print(f"  Run ID:      {store.run_id}")
    print(f"  Target:      {target}")
    print(f"  Scanners:    {', '.join(selected)}")
    print(f"  Findings:    {len(ranked)}")
    print(f"  Output:      {output_dir}")
    print()
    print(f"  By severity:")
    for sev in ["critical", "high", "medium", "low", "informational"]:
        count = manifest["results"]["by_severity"].get(sev, 0)
        if count:
            print(f"    {sev:15s}: {count}")
    print()
    print(f"  By engine:")
    for eng, count in sorted(manifest["results"]["by_engine"].items()):
        print(f"    {eng:15s}: {count}")
    print()
    print(f"  Engine status:")
    for eng, info in manifest["engine_results"].items():
        icon = "✅" if info["success"] else "❌"
        err = f" — {info['error'][:80]}" if info["error"] else ""
        print(f"    {icon} {eng:15s} exit={info['exit_code']} findings={info['finding_count']} {info['duration_sec']}s{err}")

    return True


def _resolve_scanners(scanners_str: str, ctx) -> list[str]:
    """Resolve comma-separated scanner list."""
    if scanners_str == "all":
        return list(ADAPTERS.keys())

    selected = []
    for s in scanners_str.split(","):
        s = s.strip()
        if s in ADAPTERS:
            selected.append(s)
        else:
            print(f"[aletheia] WARNING: unknown scanner '{s}', skipping")
    return selected
