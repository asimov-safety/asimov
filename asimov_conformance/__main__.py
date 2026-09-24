"""Local Asimov draft tooling. No network access or live-agent execution."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .evidence import EvidenceError, build_evidence_manifest, verify_evidence_manifest
from .gate import ReportError, catalog, evaluate_report, load_report
from .render import render_html, render_probe_html
from .probes import run_initial_probes, run_mutation_validation
from .onboarding import doctor, init_project
from .reference_target import ReferenceTarget


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Asimov draft tools; NOT a certification or enforcement service.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("catalog", help="List specified conformance families.")

    rp = sub.add_parser("report", help="Aggregate a local report's supplied findings; does not verify evidence.")
    rp.add_argument("path", type=Path)
    rp.add_argument("--json-output", type=Path)
    rp.add_argument("--html-output", type=Path)

    ep = sub.add_parser("evidence-manifest", help="Hash an evidence directory into a deterministic manifest.")
    ep.add_argument("root", type=Path)
    ep.add_argument("--output", type=Path, required=True)

    vp = sub.add_parser("verify-evidence", help="Verify local files against a draft evidence manifest.")
    vp.add_argument("manifest", type=Path)
    vp.add_argument("root", type=Path)

    pp = sub.add_parser("reference-probes", help="Run the full executable A2 reference harness against the disposable target.")
    pp.add_argument("--json-output", type=Path)
    pp.add_argument("--html-output", type=Path)

    mp = sub.add_parser("reference-mutations", help="Verify that every executable A2 probe fails when its matching reference control is removed.")
    mp.add_argument("--json-output", type=Path)

    ip = sub.add_parser("init", help="Create a cross-platform Asimov deployment scaffold without overwriting existing configuration.")
    ip.add_argument("--output", type=Path, default=Path("asimov.toml"))

    dp = sub.add_parser("doctor", help="Fail-closed readiness check for required probe/control surfaces.")
    dp.add_argument("--level", choices=["A1", "A2", "A3", "A4", "A5"], default="A2")
    dp.add_argument("--json-output", type=Path)

    args = parser.parse_args(argv)


    if args.command == "init":
        try:
            result = init_project(args.output)
        except (OSError, FileExistsError) as exc:
            print(f"INIT ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"Created {result['path']}")
        print(f"Platform: {result['environment']['platform']} | Python: {result['environment']['python']}")
        for row in result['environment']['detected_framework_modules']:
            print(f"Detected module: {row['module']} — {row['description']}")
        return 0

    if args.command == "doctor":
        result = doctor(ReferenceTarget(), args.level)
        if args.json_output is not None:
            args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"ASIMOV DOCTOR — {args.level} — {'READY' if result['ready'] else 'BLOCKED'}")
        print(f"Requirements: {result['requirements']} | blockers: {result['blockers']}")
        for row in result['findings']:
            if row['state'].startswith('BLOCKED'):
                print(f"  {row['requirement_id']}: {row['state']} — {row['remediation']}")
        return 0 if result['ready'] else 2

    if args.command == "catalog":
        data = catalog()
        print(f"ASIMOV {data['version']} — {len(data['requirements'])} SPECIFIED families; live deployment probes are adapter-dependent")
        for r in data["requirements"]:
            print(f"{r['id']}  A{r['minimum_profile']}  {r['automation']:<20}  {r['title']}")
        return 0

    if args.command == "reference-probes":
        result = run_initial_probes()
        if args.json_output is not None:
            args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if args.html_output is not None:
            args.html_output.write_text(render_probe_html(result), encoding="utf-8")
        print(f"ASIMOV {result['spec_version']} — A2 REFERENCE HARNESS")
        for row in result["results"]:
            print(f"{row['requirement_id']}: {row['status']} — {row['summary']}")
        print(f"Selected probes passed: {result['counts']['PASS']}/{len(result['results'])}")
        print("Reference target only; no external deployment conformance claim is made.")
        return 0 if result["selected_all_pass"] else 1

    if args.command == "reference-mutations":
        result = run_mutation_validation()
        if args.json_output is not None:
            args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        for row in result["rows"]:
            verdict = "DETECTED" if row["mutation_detected"] else "MISSED"
            print(f"{row['requirement_id']}: {verdict} ({row['mutation']})")
        print(f"All deliberate control removals detected: {result['all_mutations_detected']}")
        return 0 if result["all_mutations_detected"] else 1

    if args.command == "evidence-manifest":
        try:
            manifest = build_evidence_manifest(args.root)
            args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        except (EvidenceError, OSError) as exc:
            print(f"EVIDENCE ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"Evidence files: {len(manifest['files'])}")
        print(f"Manifest SHA-256: {manifest['manifest_sha256']}")
        print("Integrity only: sign/checkpoint this manifest separately for identity and trusted time.")
        return 0

    if args.command == "verify-evidence":
        try:
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
            errors = verify_evidence_manifest(manifest, args.root)
        except (OSError, json.JSONDecodeError, EvidenceError) as exc:
            print(f"EVIDENCE ERROR: {exc}", file=sys.stderr)
            return 3
        if errors:
            print("EVIDENCE VERIFICATION FAILED")
            for err in errors:
                print(f"  - {err}")
            return 1
        print("EVIDENCE INTEGRITY VERIFIED")
        print(f"Manifest SHA-256: {manifest['manifest_sha256']}")
        print("This verifies file integrity only, not assessor identity, timestamp, completeness, or safety.")
        return 0

    try:
        result = evaluate_report(load_report(args.path))
        if args.json_output is not None:
            if args.json_output.resolve() == args.path.resolve():
                raise ReportError("JSON output must not overwrite the input report")
            args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if args.html_output is not None:
            if args.html_output.resolve() == args.path.resolve():
                raise ReportError("HTML output must not overwrite the input report")
            args.html_output.write_text(render_html(result), encoding="utf-8")
    except (ReportError, OSError) as exc:
        print(f"INVALID REPORT: {exc}", file=sys.stderr)
        return 3

    print(f"ASIMOV {result['spec_version']} — REPORT AGGREGATION ONLY")
    print(f"System: {result['system']['id']} | Mode: {result['assessment_mode']}")
    print(f"Claim status: {result['claim_status']}")
    for level in ("A1", "A2", "A3", "A4", "A5"):
        p = result["profiles"][level]
        print(f"{level}: {p['state']} ({p['mandatory_families']} mandatory families + {p['mandatory_preconditions']} preconditions)")
    print(f"Requested {result['requested_profile']}: {result['reported_outcome']}")
    for unmet in result["profiles"][result["requested_profile"]].get("unmet", [])[:30]:
        print(f"  {unmet['id']}: {unmet['status']}")
    if len(result["profiles"][result["requested_profile"]].get("unmet", [])) > 30:
        print("  ... additional unmet items omitted from console; use JSON/HTML output")
    print("No deployment probed. No evidence identity verified. No certificate issued.")
    state = result["reported_outcome"]
    return 0 if state == "REPORTED_PASS" else 1 if state == "REPORTED_FAIL" else 2


if __name__ == "__main__":
    raise SystemExit(main())
