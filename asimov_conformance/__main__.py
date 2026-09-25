"""Asimov conformance command-line tooling."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .evidence import EvidenceError, build_evidence_manifest, verify_evidence_manifest
from .gate import ReportError, catalog, evaluate_report, load_report
from .render import render_html, render_probe_html, render_summary_html, render_verification_receipt
from .verification import (
    VerificationError,
    build_public_verification_record,
    build_verification_statement,
    embed_public_verification_record,
    sigstore_attest_blob,
    sigstore_sign,
    sigstore_verify,
    verify_package,
    verify_public_report,
    verify_review_attestation,
)
from .probes import run_initial_probes, run_mutation_validation
from .onboarding import doctor, init_project
from .reference_target import ReferenceTarget
from .assessment import (
    AssessmentWorkflowError,
    acknowledge_assessment,
    assessment_status,
    finalize_assessment,
    load_adapter,
    prepare_assessment,
    run_assessment,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Asimov conformance tools for autonomous AI deployments.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("catalog", help="List specified conformance families.")

    rp = sub.add_parser("report", help="Aggregate a local report's supplied findings; does not verify evidence.")
    rp.add_argument("path", type=Path)
    rp.add_argument("--json-output", type=Path)
    rp.add_argument("--html-output", type=Path)
    rp.add_argument("--summary-output", type=Path)

    ep = sub.add_parser("evidence-manifest", help="Hash an evidence directory into a deterministic manifest.")
    ep.add_argument("root", type=Path)
    ep.add_argument("--output", type=Path, required=True)

    vp = sub.add_parser("verify-evidence", help="Verify local files against an evidence manifest.")
    vp.add_argument("manifest", type=Path)
    vp.add_argument("root", type=Path)

    pp = sub.add_parser("reference-probes", help="Run the full executable A5 reference harness against the disposable target.")
    pp.add_argument("--json-output", type=Path)
    pp.add_argument("--html-output", type=Path)

    mp = sub.add_parser("reference-mutations", help="Verify that every executable probe fails when its matching reference control is removed.")
    mp.add_argument("--json-output", type=Path)

    ip = sub.add_parser("init", help="Create a cross-platform Asimov deployment scaffold without overwriting existing configuration.")
    ip.add_argument("--output", type=Path, default=Path("asimov.toml"))

    dp = sub.add_parser("doctor", help="Fail-closed readiness check for required probe/control surfaces.")
    dp.add_argument("--level", choices=["A1", "A2", "A3", "A4", "A5"], default="A2")
    dp.add_argument("--json-output", type=Path)

    pa = sub.add_parser("prepare-assessment", help="Prepare a generic external assessment workspace, human-review plan, and verification plan before probes run.")
    pa.add_argument("--adapter", required=True, help="Adapter as path/to/file.py:Class or package.module:Class")
    pa.add_argument("--adapter-kwargs", default="{}", help="JSON object passed to the adapter constructor")
    pa.add_argument("--level", choices=["A1", "A2", "A3", "A4", "A5"], default="A5")
    pa.add_argument("--assessor", required=True)
    pa.add_argument("--subject-organization", default="", help="Organization responsible for the assessed deployment.")
    pa.add_argument("--assessor-organization", default="", help="Organization performing the assessment/review work.")
    pa.add_argument("--mode", choices=["self_assessment", "independent_assessment"], default="self_assessment")
    pa.add_argument("--output", type=Path, required=True)

    aa = sub.add_parser("acknowledge-assessment", help="Bulk-acknowledge generated pre-run human/review obligations without marking them PASS.")
    aa.add_argument("workspace", type=Path)
    aa.add_argument("--reviewer", required=True)
    aa.add_argument("--reviewer-role", required=True)

    ra = sub.add_parser("run-assessment", help="Run cumulative technical probes after the prepared human/review obligations have been acknowledged.")
    ra.add_argument("workspace", type=Path)
    ra.add_argument("--adapter", required=True, help="Adapter as path/to/file.py:Class or package.module:Class")
    ra.add_argument("--adapter-kwargs", default="{}", help="JSON object passed to the adapter constructor")

    fa = sub.add_parser("finalize-assessment", help="Merge technical and human/review evidence fail-closed and build the full report/verification package.")
    fa.add_argument("workspace", type=Path)

    ast = sub.add_parser("assessment-status", help="Show pre-run and final human/review work still pending in an assessment workspace.")
    ast.add_argument("workspace", type=Path)

    sp = sub.add_parser("verification-statement", help="Bind an assessment, evidence manifest, and rendered reports into a signed-subject statement.")
    sp.add_argument("assessment", type=Path)
    sp.add_argument("--evidence-manifest", type=Path, required=True)
    sp.add_argument("--report", type=Path, action="append", default=[])
    sp.add_argument("--output", type=Path, required=True)

    sr = sub.add_parser("sign-report", help="Sign a finalized public HTML report with Sigstore and embed authenticated provenance into the report.")
    sr.add_argument("report", type=Path)
    sr.add_argument("--statement", type=Path, required=True)
    sr.add_argument("--identity", required=True, help="Exact signer identity expected in the Sigstore certificate, such as an email or workload identity.")
    sr.add_argument("--provider", choices=["google", "github", "microsoft", "github-actions", "custom"], default="google")
    sr.add_argument("--oidc-issuer", help="Required only with --provider custom; otherwise Asimov supplies the standard issuer.")
    sr.add_argument("--bundle", type=Path, help="Bundle output path; defaults to asimov.sigstore.json beside the report.")
    sr.add_argument("--json-export", type=Path, help="Optional export of the embedded public verification record.")
    sr.add_argument("--cosign-bin", default="cosign")
    sr.add_argument("--yes", action="store_true", help="Pass --yes to Cosign for non-interactive confirmation.")

    rv = sub.add_parser("sign-review", help="Sign a completed human review as a Sigstore blob attestation.")
    rv.add_argument("review", type=Path)
    rv.add_argument("--identity", required=True, help="Exact reviewer signing identity expected in the Sigstore certificate.")
    rv.add_argument("--provider", choices=["google", "github", "microsoft", "github-actions", "custom"], default="google")
    rv.add_argument("--oidc-issuer", help="Required only with --provider custom.")
    rv.add_argument("--bundle", type=Path, help="Defaults to <review>.sigstore.json beside the review record.")
    rv.add_argument("--cosign-bin", default="cosign")
    rv.add_argument("--yes", action="store_true", help="Pass --yes to Cosign for non-interactive confirmation.")

    vrv = sub.add_parser("verify-review", help="Verify a human review's Sigstore attestation and declared reviewer identity.")
    vrv.add_argument("review", type=Path)
    vrv.add_argument("--bundle", type=Path)
    vrv.add_argument("--cosign-bin", default="cosign")
    vrv.add_argument("--json-output", type=Path)

    ss = sub.add_parser("sigstore-sign", help="Sign an Asimov verification statement with Cosign/Sigstore.")
    ss.add_argument("statement", type=Path)
    ss.add_argument("--bundle", type=Path, required=True)
    ss.add_argument("--cosign-bin", default="cosign")
    ss.add_argument("--yes", action="store_true", help="Pass --yes to Cosign for non-interactive confirmation.")

    pr = sub.add_parser("public-record", help="Embed/update public verification inside an HTML report and optionally export the JSON record.")
    pr.add_argument("--statement", type=Path, required=True)
    pr.add_argument("--report", type=Path, required=True)
    pr.add_argument("--bundle", type=Path)
    pr.add_argument("--certificate-identity")
    pr.add_argument("--certificate-oidc-issuer")
    pr.add_argument("--output", type=Path, help="Optional JSON export of the embedded public verification record.")

    vr = sub.add_parser("verify-report", help="Verify a public HTML report using its embedded Asimov verification capsule; an optional sidecar may be supplied for compatibility.")
    vr.add_argument("report", type=Path)
    vr.add_argument("record", type=Path, nargs="?")
    vr.add_argument("--cosign-bin", default="cosign")
    vr.add_argument("--json-output", type=Path)

    pv = sub.add_parser("verify-package", help="Verify evidence, report binding, scope binding, and optionally a Sigstore identity/transparency bundle.")
    pv.add_argument("assessment", type=Path)
    pv.add_argument("--evidence-manifest", type=Path, required=True)
    pv.add_argument("--evidence-root", type=Path, required=True)
    pv.add_argument("--statement", type=Path, required=True)
    pv.add_argument("--report", type=Path, action="append", default=[])
    pv.add_argument("--bundle", type=Path)
    pv.add_argument("--certificate-identity")
    pv.add_argument("--certificate-oidc-issuer")
    pv.add_argument("--cosign-bin", default="cosign")
    pv.add_argument("--json-output", type=Path)
    pv.add_argument("--html-output", type=Path)

    args = parser.parse_args(argv)

    if args.command in {"prepare-assessment", "run-assessment"}:
        try:
            adapter_kwargs = json.loads(args.adapter_kwargs)
            if not isinstance(adapter_kwargs, dict):
                raise ValueError("--adapter-kwargs must decode to a JSON object")
            adapter = load_adapter(args.adapter, adapter_kwargs)
            try:
                if args.command == "prepare-assessment":
                    plan = prepare_assessment(
                        adapter,
                        args.level,
                        args.output,
                        assessor=args.assessor,
                        mode=args.mode,
                        adapter_spec=args.adapter,
                        subject_organization=args.subject_organization,
                        assessor_organization=args.assessor_organization,
                    )
                    print(f"ASIMOV ASSESSMENT PREPARED — {plan['requested_profile']}")
                    print(f"System: {plan['system_id']} | Adapter: {plan['adapter_id']}")
                    print(f"Technical families: {len(plan['requirements'])}")
                    print(f"Human/review families: {len(plan['human_review_requirements'])}")
                    print(f"Mandatory preconditions: {len(plan['required_preconditions'])}")
                    print(f"Independent-review families: {len(plan['independent_review_requirements'])}")
                    print(f"Workspace: {args.output}")
                    print("NEXT: read REVIEW-CHECKLIST.md and verification-plan.json, review/edit scope.json, then run acknowledge-assessment. Independent review may remain unassigned until final review; the technical suite can still run.")
                    return 0
                result = run_assessment(adapter, args.workspace)
                print(f"ASIMOV TECHNICAL ASSESSMENT — {result['scope']}")
                for row in result["results"]:
                    print(f"{row['requirement_id']}: {row['status']} — {row['summary']}")
                print(f"Counts: {json.dumps(result['counts'], sort_keys=True)}")
                status = assessment_status(args.workspace)
                print(f"Pending human/review decisions: {len(status['pending_requirement_reviews'])}")
                print(f"Pending preconditions: {len(status['pending_preconditions'])}")
                print("NEXT: complete the generated review records, then run finalize-assessment.")
                return 0
            finally:
                close = getattr(adapter, "close", None)
                if callable(close):
                    close()
        except (AssessmentWorkflowError, OSError, ValueError, ImportError) as exc:
            print(f"ASSESSMENT ERROR: {exc}", file=sys.stderr)
            return 3

    if args.command == "acknowledge-assessment":
        try:
            result = acknowledge_assessment(
                args.workspace,
                reviewer=args.reviewer,
                reviewer_role=args.reviewer_role,
            )
        except (AssessmentWorkflowError, OSError, ValueError) as exc:
            print(f"ASSESSMENT ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"ASIMOV PRE-RUN ACKNOWLEDGEMENT — {result['count']} obligations acknowledged")
        print(result["warning"])
        if result["independent_review_requirements"]:
            print("Independent final review still required for:")
            for rid in result["independent_review_requirements"]:
                print(f"  {rid}")
        print("NEXT: run assessment-status, then run-assessment when Pre-run ready is True.")
        return 0

    if args.command == "assessment-status":
        try:
            status = assessment_status(args.workspace)
        except (AssessmentWorkflowError, OSError, ValueError) as exc:
            print(f"ASSESSMENT ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"ASIMOV ASSESSMENT STATUS — {status['state']} — {status['requested_profile']}")
        print(f"Pre-run ready: {status['pre_run_ready']}")
        for err in status["pre_run_errors"]:
            print(f"  PRE-RUN: {err}")
        print(f"Pending requirement reviews: {len(status['pending_requirement_reviews'])}")
        for rid in status["pending_requirement_reviews"]:
            print(f"  REVIEW: {rid}")
        print(f"Pending preconditions: {len(status['pending_preconditions'])}")
        for name in status["pending_preconditions"]:
            print(f"  PRECONDITION: {name}")
        if status.get("reported_outcome"):
            print(f"Reported outcome: {status['reported_outcome']}")
        return 0 if status["pre_run_ready"] and not status["pending_requirement_reviews"] and not status["pending_preconditions"] else 2

    if args.command == "finalize-assessment":
        try:
            result = finalize_assessment(args.workspace)
        except (AssessmentWorkflowError, ReportError, VerificationError, OSError, ValueError) as exc:
            print(f"ASSESSMENT ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"ASIMOV ASSESSMENT FINALIZED — {result['system']['id']}")
        for level in ("A1", "A2", "A3", "A4", "A5"):
            p = result["profiles"][level]
            print(f"{level}: {p['state']} ({p['mandatory_families']} families + {p['mandatory_preconditions']} preconditions)")
        print(f"Requested {result['requested_profile']}: {result['reported_outcome']}")
        print(f"Full report: {args.workspace / 'report.html'}")
        print(f"Summary: {args.workspace / 'summary.html'}")
        print(f"Verification instructions: {args.workspace / 'VERIFICATION-INSTRUCTIONS.md'}")
        print("IMPORTANT: completed human reviews require their own Sigstore attestations before they can contribute PASS/FAIL. Finalization does not invent reviewer identity, independence, package signer identity, external checkpoints, or A5 evidence escrow. Follow VERIFICATION-INSTRUCTIONS.md.")
        state = result["reported_outcome"]
        return 0 if state == "REPORTED_PASS" else 1 if state == "REPORTED_FAIL" else 2

    if args.command == "public-record":
        try:
            record = build_public_verification_record(
                args.statement,
                args.report,
                bundle_path=args.bundle,
                certificate_identity=args.certificate_identity,
                certificate_oidc_issuer=args.certificate_oidc_issuer,
            )
            embed_public_verification_record(args.report, record)
            if args.output is not None:
                args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        except (VerificationError, OSError, ValueError) as exc:
            print(f"PUBLIC VERIFICATION ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"Public verification embedded in: {args.report}")
        if args.output is not None:
            print(f"Optional JSON export written: {args.output}")
        print("The HTML report is now self-contained for public verification and contains no private assessment evidence.")
        if record.get("sigstore") is None:
            print("Provenance is not authenticated yet; add a Sigstore bundle for public signer verification.")
        else:
            print("Sigstore material embedded for public provenance verification.")
        return 0

    if args.command == "verify-report":
        try:
            result = verify_public_report(args.report, args.record, cosign_bin=args.cosign_bin)
            if args.json_output is not None:
                args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        except (VerificationError, OSError, ValueError) as exc:
            print(f"PUBLIC VERIFICATION ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"ASIMOV PUBLIC VERIFY — {result['overall']}")
        print(f"Report integrity: {result['report_integrity']['state']}")
        binding = result["assessment_binding"]
        print(f"Report ID: {binding.get('report_id')}")
        print(f"System: {binding.get('system_id')}")
        print(f"Assessor claim: {binding.get('assessor')}")
        print(f"Requested profile: {binding.get('requested_profile')}")
        print(f"Reported outcome: {binding.get('reported_outcome')}")
        signer = result["provenance"].get("signer_identity")
        signer_state = result["provenance"]["state"]
        if signer_state == "VERIFIED":
            print(f"Who signed this? {signer} — AUTHENTICATED")
            print(f"Identity provider: {result['provenance'].get('oidc_issuer')}")
        elif signer:
            print(f"Who signed this? {signer} — {signer_state}")
        else:
            print("Who signed this? No authenticated signer attached")
        print("Signer authentication does not by itself establish assessor independence or semantic correctness.")
        return 1 if result["overall"] == "FAILED" else 0

    if args.command == "verification-statement":
        try:
            statement = build_verification_statement(
                args.assessment,
                args.evidence_manifest,
                args.report,
            )
            args.output.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
        except (VerificationError, ReportError, OSError, ValueError) as exc:
            print(f"VERIFICATION ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"Created verification statement: {args.output}")
        print(f"Subjects: {len(statement['subject'])}")
        return 0

    if args.command == "sign-report":
        issuers = {
            "google": "https://accounts.google.com",
            "github": "https://github.com/login/oauth",
            "microsoft": "https://login.microsoftonline.com",
            "github-actions": "https://token.actions.githubusercontent.com",
        }
        issuer = args.oidc_issuer if args.provider == "custom" else issuers[args.provider]
        if args.provider == "custom" and not issuer:
            print("SIGN REPORT ERROR: --oidc-issuer is required with --provider custom", file=sys.stderr)
            return 3
        bundle = args.bundle or (args.report.parent / "asimov.sigstore.json")
        print("ASIMOV PUBLIC REPORT SIGNING")
        print(f"Who should sign this? {args.identity}")
        print(f"Identity provider: {args.provider} ({issuer})")
        print("When Cosign opens an authentication flow, authenticate as the exact identity above.")
        try:
            code = sigstore_sign(
                args.statement,
                bundle,
                cosign_bin=args.cosign_bin,
                yes=args.yes,
            )
            if code != 0:
                print(f"SIGSTORE SIGNING FAILED (exit {code})", file=sys.stderr)
                return 1
            verified, detail = sigstore_verify(
                args.statement,
                bundle,
                certificate_identity=args.identity,
                certificate_oidc_issuer=issuer,
                cosign_bin=args.cosign_bin,
            )
            if not verified:
                print("SIGN REPORT ERROR: the new Sigstore signature did not verify against the declared signer identity/issuer.", file=sys.stderr)
                if detail:
                    print(detail, file=sys.stderr)
                return 1
            print("Sigstore signer verification: VERIFIED")
            record = build_public_verification_record(
                args.statement,
                args.report,
                bundle_path=bundle,
                certificate_identity=args.identity,
                certificate_oidc_issuer=issuer,
            )
            embed_public_verification_record(args.report, record)
            if args.json_export is not None:
                args.json_export.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        except (VerificationError, OSError, ValueError) as exc:
            print(f"SIGN REPORT ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"Signed report ready: {args.report}")
        print(f"Sigstore bundle: {bundle}")
        print(f"Authenticated signer expected: {args.identity}")
        print(f"OIDC issuer: {issuer}")
        print("Public verification now requires only the HTML report.")
        print("Anyone can check it with: asimov verify-report " + str(args.report))
        return 0

    if args.command == "sign-review":
        issuers = {
            "google": "https://accounts.google.com",
            "github": "https://github.com/login/oauth",
            "microsoft": "https://login.microsoftonline.com",
            "github-actions": "https://token.actions.githubusercontent.com",
        }
        issuer = args.oidc_issuer if args.provider == "custom" else issuers[args.provider]
        if args.provider == "custom" and not issuer:
            print("SIGN REVIEW ERROR: --oidc-issuer is required with --provider custom", file=sys.stderr)
            return 3
        try:
            record = json.loads(args.review.read_text(encoding="utf-8"))
            if not isinstance(record, dict):
                raise ValueError("review record must be a JSON object")
            if record.get("decision") not in {"PASS", "FAIL", "INCONCLUSIVE"}:
                raise ValueError("review decision must be PASS, FAIL, or INCONCLUSIVE before signing")
            record["signing_identity"] = {
                "type": "sigstore",
                "expected_subject": args.identity,
                "expected_issuer": issuer,
            }
            args.review.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            bundle = args.bundle or args.review.with_suffix(".sigstore.json")
            code = sigstore_attest_blob(
                args.review,
                args.review,
                bundle,
                cosign_bin=args.cosign_bin,
                yes=args.yes,
            )
            if code != 0:
                print(f"SIGN REVIEW FAILED (exit {code})", file=sys.stderr)
                return 1
            verified = verify_review_attestation(args.review, bundle, cosign_bin=args.cosign_bin)
        except (VerificationError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"SIGN REVIEW ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"ASIMOV REVIEW ATTESTATION — {verified['state']}")
        print(f"Review: {verified.get('item_id')} ({verified.get('review_requirement')})")
        print(f"Authenticated reviewer identity: {verified.get('signer_identity')}")
        print(f"Sigstore bundle: {bundle}")
        return 0 if verified["state"] == "VERIFIED" else 1

    if args.command == "verify-review":
        try:
            result = verify_review_attestation(
                args.review,
                args.bundle,
                cosign_bin=args.cosign_bin,
            )
            if args.json_output is not None:
                args.json_output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        except (VerificationError, OSError, ValueError) as exc:
            print(f"VERIFY REVIEW ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"ASIMOV REVIEW VERIFY — {result['state']}")
        print(f"Review: {result.get('item_id')} ({result.get('review_requirement')})")
        print(f"Authenticated reviewer identity: {result.get('signer_identity')}")
        if result.get("detail"):
            print(result["detail"])
        return 0 if result["state"] == "VERIFIED" else 1

    if args.command == "sigstore-sign":
        try:
            code = sigstore_sign(
                args.statement,
                args.bundle,
                cosign_bin=args.cosign_bin,
                yes=args.yes,
            )
        except (VerificationError, OSError) as exc:
            print(f"SIGSTORE ERROR: {exc}", file=sys.stderr)
            return 3
        if code != 0:
            print(f"SIGSTORE SIGNING FAILED (exit {code})", file=sys.stderr)
            return 1
        print(f"Sigstore bundle written: {args.bundle}")
        return 0

    if args.command == "verify-package":
        try:
            receipt = verify_package(
                assessment_path=args.assessment,
                evidence_manifest_path=args.evidence_manifest,
                evidence_root=args.evidence_root,
                statement_path=args.statement,
                report_paths=args.report,
                bundle_path=args.bundle,
                certificate_identity=args.certificate_identity,
                certificate_oidc_issuer=args.certificate_oidc_issuer,
                cosign_bin=args.cosign_bin,
            )
            if args.json_output is not None:
                args.json_output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            if args.html_output is not None:
                args.html_output.write_text(render_verification_receipt(receipt), encoding="utf-8")
        except (VerificationError, ReportError, OSError, ValueError) as exc:
            print(f"VERIFICATION ERROR: {exc}", file=sys.stderr)
            return 3
        print(f"ASIMOV VERIFY — {receipt['overall']}")
        for name, check in receipt["checks"].items():
            print(f"  {name}: {check['state']}")
        return 1 if receipt["overall"] == "FAILED" else 0

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
        print(f"ASIMOV {result['spec_version']} — A5 REFERENCE HARNESS")
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
        if args.summary_output is not None:
            if args.summary_output.resolve() == args.path.resolve():
                raise ReportError("Summary output must not overwrite the input report")
            args.summary_output.write_text(render_summary_html(result), encoding="utf-8")
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
