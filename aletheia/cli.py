"""AletheiaAI CLI entry point."""

from __future__ import annotations
import argparse
import sys
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="aletheia",
        description="AletheiaAI — bug bounty meta-orchestrator: scan, verify, convict, report",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="run static + fuzz scanning on target")
    p_scan.add_argument("target", help="local project path")
    p_scan.add_argument("--scanners", default="all",
                        help="comma-separated engines: all,slither,semgrep,mythril,foundry,medusa,echidna")
    p_scan.add_argument("--no-build", action="store_true",
                        help="skip forge build")
    p_scan.add_argument("--output", default="",
                        help="output directory (default: /mnt/data/results/<run_id>)")
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
    p_scan.add_argument("--policy", default="default",
                        choices=["default", "immunefi", "hackenproof", "yeswehack"],
                        help="severity policy profile (default: default)")
    p_scan.add_argument("--generate-tests", action="store_true",
                        help="generate Foundry tests for candidate findings")
    p_scan.add_argument("--generate-poc", action="store_true",
                        help="generate local PoC scripts for verified findings")

    # verify command
    p_verify = sub.add_parser("verify", help="run conviction engine on a previous run")
    p_verify.add_argument("run_dir", help="run directory (e.g. /mnt/data/results/20260819T084351)")
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

    # inventory
    sub.add_parser("inventory", help="show available tools and adapters")

    args = parser.parse_args(argv)

    if args.command == "inventory":
        from aletheia.inventory import show_inventory
        return show_inventory()

    if args.command == "scan":
        from aletheia.orchestrator import run_scan
        result = run_scan(args)
        return 0 if result else 1

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
            f"\n[aletheia] triage complete: {len(results)} results — "
            f"{len(report_ready)} report-ready, {len(needs_review_t)} needs-review, "
            f"{len(out_of_scope_t)} out-of-scope"
        )
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())