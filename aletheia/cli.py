"""AletheiaAI CLI entry point."""

from __future__ import annotations
import argparse
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="aletheia",
        description="AletheiaAI - bug bounty meta-orchestrator: scan, verify, convict, report",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="run static + fuzz scanning on target")
    p_scan.add_argument("target", help="local project path")
    p_scan.add_argument("--scanners", default="all",
                        help="comma-separated engines: all,slither,semgrep,mythril,foundry,medusa,echidna")
    p_scan.add_argument("--chain", default="", help="require a chain family (for example solana, cosmos, polkadot, move, starknet)")
    p_scan.add_argument("--ecosystem", default="", help="require a specific ecosystem plugin (for example solana_anchor)")
    p_scan.add_argument("--capabilities", action="store_true", help="print chain capability matrix and exit")
    p_scan.add_argument("--no-build", action="store_true",
                        help="skip forge build")
    p_scan.add_argument("--output", default="",
                        help="output directory (default: ./artifacts/<run_id>)")
    p_scan.add_argument("--timeout", type=int, default=600,
                        help="per-engine timeout in seconds")
    p_scan.add_argument("--json", action="store_true",
                        help="output as JSON to stdout")
    p_scan.add_argument("--sarif", action="store_true",
                        help="output as SARIF to stdout")
    p_scan.add_argument("--verify", action="store_true",
                        help="run conviction engine on findings")
    p_scan.add_argument("--triage", action="store_true",
                        help="run triage & severity engine on verified findings")
    p_scan.add_argument("--report", action="store_true",
                        help="generate report after triage")
    p_scan.add_argument("--platform", default="default",
                        choices=["default", "immunefi", "hackenproof", "yeswehack"],
                        help="report format profile")
    p_scan.add_argument("--policy", default="default",
                        choices=["default", "immunefi", "hackenproof", "yeswehack"],
                        help="severity policy profile (default: default)")
    p_scan.add_argument("--generate-tests", action="store_true",
                        help="generate Foundry tests for candidate findings")
    p_scan.add_argument("--generate-poc", action="store_true",
                        help="generate local PoC scripts for verified findings")

    # verify command
    p_verify = sub.add_parser("verify", help="run conviction engine on a previous run")
    p_verify.add_argument("run_dir", help="run directory (e.g. artifacts/20260819T084351)")
    p_verify.add_argument("--generate-tests", action="store_true",
                          help="generate Foundry tests")
    p_verify.add_argument("--generate-poc", action="store_true",
                          help="generate local PoC scripts")

    # triage command
    p_triage = sub.add_parser("triage", help="run triage & severity engine on a previous run")
    p_triage.add_argument("run_dir", help="run directory")
    p_triage.add_argument("--policy", default="default",
                         choices=["default", "immunefi", "hackenproof", "yeswehack"],
                         help="severity policy profile")

    # report command
    p_report = sub.add_parser("report", help="generate reports from a verified triage run")
    p_report.add_argument("run_dir", help="run directory containing findings.json and triage artifacts")
    p_report.add_argument("--policy", default="default",
                          choices=["default", "immunefi", "hackenproof", "yeswehack"],
                          help="report policy profile")
    p_report.add_argument("--platform", default="default",
                          choices=["default", "immunefi", "hackenproof", "yeswehack"],
                          help="report format profile")

    # inventory
    sub.add_parser("inventory", help="show available tools and adapters")
    sub.add_parser("doctor", help="show reproducible dependency diagnostics")
    sub.add_parser("setup", help="prepare safe local directories; never stores credentials")
    p_map=sub.add_parser("map", help="write deterministic attack-surface artifacts"); p_map.add_argument("target"); p_map.add_argument("--output",default="")
    p_plan=sub.add_parser("plan", help="create bounded evidence-first audit plan"); p_plan.add_argument("target"); p_plan.add_argument("--output",default="")
    p_rep=sub.add_parser("reproduce", help="run an existing local-only test harness"); p_rep.add_argument("run_dir"); p_rep.add_argument("--finding",required=True); p_rep.add_argument("--target",default="")
    p_package=sub.add_parser("package",help="render a linted local submission package"); p_package.add_argument("run_dir"); p_package.add_argument("--platform",default="generic",choices=["generic","immunefi","hackenproof","yeswehack","code4rena"])
    p_hunt=sub.add_parser("hunt",help="run local, scope-aware hunter workflow"); p_hunt.add_argument("program_id"); p_hunt.add_argument("target"); p_hunt.add_argument("--output",default="")
    p_status=sub.add_parser("status",help="show a persisted run"); p_status.add_argument("run_dir")
    p_queue=sub.add_parser("queue",help="show human review queue"); p_queue.add_argument("run_dir")
    p_explain=sub.add_parser("explain",help="explain fused evidence"); p_explain.add_argument("run_dir"); p_explain.add_argument("--finding",required=True)
    p_prog=sub.add_parser("program",help="manage local program scope"); ps=p_prog.add_subparsers(dest="program_command"); pi=ps.add_parser("import"); pi.add_argument("source"); pshow=ps.add_parser("show"); pshow.add_argument("program_id"); padd=ps.add_parser("target-add"); padd.add_argument("program_id"); padd.add_argument("locator"); pexpl=ps.add_parser("scope-explain"); pexpl.add_argument("program_id"); pexpl.add_argument("target")
    p_knowledge=sub.add_parser("knowledge",help="import and search local historical knowledge"); ks=p_knowledge.add_subparsers(dest="knowledge_command"); ki=ks.add_parser("import"); ki.add_argument("path"); ki.add_argument("--source-name",required=True); ki.add_argument("--license",required=True); kv=ks.add_parser("validate"); kv.add_argument("path"); kstats=ks.add_parser("stats"); ksearch=ks.add_parser("search"); ksearch.add_argument("query"); ksearch.add_argument("--chain",default=""); ksearch.add_argument("--domain",default="")

    # durable audit workflow
    p_audit = sub.add_parser("audit", help="run durable scan -> verify -> triage -> report workflow")
    p_audit.add_argument("target", help="local project path")
    p_audit.add_argument("--output", default="", help="workflow run directory")
    p_audit.add_argument("--scanners", default="all", help="comma-separated scanner engines")
    p_audit.add_argument("--timeout", type=int, default=600, help="per-engine timeout")
    p_audit.add_argument("--budget-seconds", type=int, default=0, help="whole-workflow budget; 0 means unlimited")
    p_audit.add_argument("--policy", default="default", choices=["default", "immunefi", "hackenproof", "yeswehack"])
    p_audit.add_argument("--platform", default="default", choices=["default", "immunefi", "hackenproof", "yeswehack"])
    p_audit.add_argument("--no-build", action="store_true")
    p_audit.add_argument("--generate-tests", action="store_true")
    p_audit.add_argument("--generate-poc", action="store_true")
    p_audit.add_argument("--no-resume", action="store_true", help="rerun completed phases")
    p_audit.add_argument("--no-ai-routing", action="store_true", help="keep explicit/all scanner selection without AI routing")

    p_resume = sub.add_parser("resume", help="resume a durable audit run")
    p_resume.add_argument("run_dir", help="workflow run directory")
    p_resume.add_argument("--no-retry-failed", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "inventory":
        from aletheia.inventory import show_inventory
        return show_inventory()
    if args.command == "doctor":
        from .doctor import doctor
        print(__import__("json").dumps(doctor(), indent=2)); return 0
    if args.command == "setup":
        from .doctor import setup
        print(__import__("json").dumps(setup(), indent=2)); return 0
    if args.command == "map":
        from .attack_surface import write
        out=args.output or "artifacts/map"; write(args.target,out); print(out); return 0
    if args.command == "plan":
        from .hunter import plan
        out=args.output or "artifacts/plan"; plan(args.target,out); print(out); return 0
    if args.command == "reproduce":
        from .verify import load_findings_from_run
        from .reproduction import run
        finding=next((f for f in load_findings_from_run(Path(args.run_dir)) if f.finding_id==args.finding),None)
        if not finding: print("[aletheia] ERROR: finding not found"); return 1
        target=args.target or __import__("json").loads((Path(args.run_dir)/"run_manifest.json").read_text()).get("target","")
        print(__import__("json").dumps(run(finding,target,Path(args.run_dir)/"reproduction"/finding.finding_id).__dict__,default=str,indent=2)); return 0
    if args.command == "package":
        from .packages import build
        try: print(__import__("json").dumps(build(args.run_dir,args.platform),indent=2)); return 0
        except ValueError as exc: print(f"[aletheia] ERROR: {exc}"); return 1
    if args.command == "hunt":
        from .hunter_workflow import hunt
        print(__import__("json").dumps(hunt(args.program_id,args.target,args.output or None),indent=2)); return 0
    if args.command == "status":
        from .hunter_workflow import status
        print(__import__("json").dumps(status(args.run_dir),indent=2)); return 0
    if args.command == "queue":
        from .hunter_workflow import queue
        print(__import__("json").dumps(queue(args.run_dir),indent=2)); return 0
    if args.command == "explain":
        from .hunter_workflow import explain
        print(__import__("json").dumps(explain(args.run_dir,args.finding),indent=2)); return 0
    if args.command == "program":
        from . import programs
        if args.program_command == "import": print(__import__("json").dumps(programs.import_program(args.source).to_dict(),indent=2)); return 0
        if args.program_command == "show": print(__import__("json").dumps(programs.load(args.program_id).to_dict(),indent=2)); return 0
        if args.program_command == "target-add": print(__import__("json").dumps(programs.add_target(args.program_id,args.locator).__dict__,indent=2)); return 0
        if args.program_command == "scope-explain":
            p=programs.load(args.program_id); print(__import__("json").dumps(dict(zip(("status","evidence"),programs.explain(p,args.target))),indent=2)); return 0
        p_prog.print_help(); return 1
    if args.command == "knowledge":
        from . import knowledge_ingestion as knowledge
        if args.knowledge_command == "import": print(__import__("json").dumps(knowledge.import_path(args.path,args.source_name,args.license),indent=2)); return 0
        if args.knowledge_command == "validate": print(__import__("json").dumps(knowledge.validate(args.path),indent=2)); return 0
        if args.knowledge_command == "stats": print(__import__("json").dumps({"records":len(knowledge.records())},indent=2)); return 0
        if args.knowledge_command == "search": print(__import__("json").dumps(knowledge.search(args.query,args.chain,args.domain),indent=2)); return 0
        p_knowledge.print_help(); return 1

    if args.command == "scan":
        if args.capabilities:
            from aletheia.inventory import show_inventory
            return show_inventory()
        from aletheia.orchestrator import run_scan
        result = run_scan(args)
        return 0 if result else 1

    if args.command == "audit":
        from .workflow import AuditWorkflow
        from .targeting import resolve_target
        try:
            resolved_target, identity = resolve_target(args.target)
        except Exception as exc:
            print(f"[aletheia] ERROR: target resolution failed: {exc}")
            return 1
        workflow = AuditWorkflow(
            str(resolved_target),
            run_dir=args.output or None,
            policy=args.policy,
            platform=args.platform,
            budget_seconds=args.budget_seconds,
            options={
                "scanners": args.scanners,
                "timeout": args.timeout,
                "no_build": args.no_build,
                "generate_tests": args.generate_tests,
                "generate_poc": args.generate_poc,
                "ai_routing": not args.no_ai_routing,
                "source_target": args.target,
                "artifact_identity": identity.to_dict(),
            },
        )
        workflow.run_dir.mkdir(parents=True, exist_ok=True)
        (workflow.run_dir / "artifact_identity.json").write_text(
            __import__("json").dumps(identity.to_dict(), indent=2), encoding="utf-8"
        )
        ok = workflow.run(resume=not args.no_resume, retry_failed=True)
        print(f"[aletheia] audit {workflow.state.status}: {workflow.run_dir}")
        return 0 if ok else 1

    if args.command == "resume":
        from .workflow import resume_audit
        try:
            ok = resume_audit(args.run_dir, retry_failed=not args.no_retry_failed)
        except Exception as exc:
            print(f"[aletheia] ERROR: {exc}")
            return 1
        print(f"[aletheia] resume {'completed' if ok else 'incomplete'}: {args.run_dir}")
        return 0 if ok else 1

    if args.command == "verify":
        from .verify import run_verification, load_findings_from_run
        run_dir = Path(args.run_dir)
        findings = load_findings_from_run(run_dir)
        if not findings:
            print(f"[aletheia] ERROR: no findings found in {run_dir}")
            return 1
        target_dir = ""
        manifest_path = run_dir / "run_manifest.json"
        if manifest_path.is_file():
            try:
                import json
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                target_dir = manifest.get("target", "")
            except Exception:
                pass
        run_verification(
            findings=findings,
            run_dir=run_dir,
            target_dir=target_dir,
            generate_tests=getattr(args, "generate_tests", False),
            generate_pocs=getattr(args, "generate_poc", False),
            fork_config={},
            verbose=True,
        )
        return 0

    if args.command == "triage":
        from .triage import run_triage_from_run, bucket_triage_results
        run_dir = Path(args.run_dir)
        policy = getattr(args, "policy", "default")
        results = run_triage_from_run(run_dir, policy_name=policy, verbose=True)
        import json
        (run_dir / "triage.json").write_text(
            json.dumps([t.to_dict() for t in results], indent=2, default=str),
            encoding="utf-8",
        )
        sev_data = [{"finding_id": t.finding_id, "severity": t.severity, "confidence": t.confidence} for t in results]
        pri_data = [{"finding_id": t.finding_id, "priority": t.priority, "rationale": t.rationale,
                      "missing_information": t.missing_information} for t in results]
        report_ready, needs_review_t, out_of_scope_t = bucket_triage_results(results)
        (run_dir / "severity.json").write_text(json.dumps(sev_data, indent=2, default=str), encoding="utf-8")
        (run_dir / "priority.json").write_text(json.dumps(pri_data, indent=2, default=str), encoding="utf-8")
        (run_dir / "report-ready-findings.json").write_text(json.dumps(report_ready, indent=2, default=str), encoding="utf-8")
        (run_dir / "needs-review.json").write_text(json.dumps(needs_review_t, indent=2, default=str), encoding="utf-8")
        (run_dir / "out-of-scope.json").write_text(json.dumps(out_of_scope_t, indent=2, default=str), encoding="utf-8")
        print(
            f"\n[aletheia] triage complete: {len(results)} results - "
            f"{len(report_ready)} report-ready, {len(needs_review_t)} needs-review, "
            f"{len(out_of_scope_t)} out-of-scope"
        )
        return 0

    if args.command == "report":
        import json
        from .verify import load_findings_from_run
        from .triage import run_triage_from_run
        from .reporting import generate_reports
        run_dir = Path(args.run_dir)
        findings = load_findings_from_run(run_dir)
        if not findings:
            print(f"[aletheia] ERROR: no findings found in {run_dir}")
            return 1
        triage_path = run_dir / "triage.json"
        if not triage_path.is_file():
            print("[aletheia] triage.json missing; running triage first")
            triage = run_triage_from_run(run_dir, policy_name=args.policy, verbose=True)
        else:
            # Recompute from the canonical run artifacts rather than trusting a
            # hand-edited report input; this keeps the report gate evidence-backed.
            triage = run_triage_from_run(run_dir, policy_name=args.policy, verbose=True)
        reports = generate_reports(findings, triage, run_dir, policy=args.policy, platform=args.platform)
        print(f"[aletheia] report complete: {len(reports)} report-ready findings")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
