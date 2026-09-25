from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asimov_conformance.evidence import build_evidence_manifest
from asimov_conformance.__main__ import main
from asimov_conformance.verification import (
    build_public_verification_record,
    build_verification_statement,
    verify_package,
    verify_public_report,
    verify_statement_binding,
)


def _assessment(scope_sha: str) -> dict:
    from asimov_conformance.gate import ALL_PRECONDITIONS
    ids = [
        "OBS-001", "OBS-002", "OBS-003", "OBS-004",
        "ACC-001", "ACC-002", "ACC-003", "ACC-004",
    ]
    return {
        "spec_version": "0.2.0",
        "catalog_version": "0.2.0",
        "report_id": "verification-test",
        "created_at": "2026-09-24T18:00:00Z",
        "assessment": {"mode": "self_assessment", "assessor": "test@example.com"},
        "system": {"id": "test-system", "configuration_sha256": "a" * 64},
        "scope_manifest_sha256": scope_sha,
        "requested_profile": "A1",
        "preconditions": {
            name: {"status": "PASS", "reason": "test", "evidence_refs": ["evidence/test"]}
            for name in ALL_PRECONDITIONS[:5]
        },
        "results": [
            {"requirement_id": rid, "status": "PASS", "reason": "test", "evidence_refs": ["evidence/test"]}
            for rid in ids
        ],
        "limitations": ["test fixture"],
    }


class VerificationTests(unittest.TestCase):
    def test_statement_binds_assessment_manifest_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest = build_evidence_manifest(evidence)
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("b" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<h1>report</h1>", encoding="utf-8")

            statement = build_verification_statement(assessment_path, manifest_path, [report_path])
            self.assertEqual(verify_statement_binding(statement, assessment_path, manifest_path, [report_path]), [])

            report_path.write_text("<h1>changed</h1>", encoding="utf-8")
            self.assertIn(
                "artifact subject digests do not match",
                verify_statement_binding(statement, assessment_path, manifest_path, [report_path]),
            )

    def test_package_local_verification_and_sigstore_mock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest = build_evidence_manifest(evidence)
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("c" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("report", encoding="utf-8")
            statement_path = root / "statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )
            local = verify_package(
                assessment_path=assessment_path,
                evidence_manifest_path=manifest_path,
                evidence_root=evidence,
                statement_path=statement_path,
                report_paths=[report_path],
            )
            self.assertEqual(local["overall"], "LOCAL_BINDING_VERIFIED")

            bundle = root / "bundle.sigstore.json"; bundle.write_text("{}", encoding="utf-8")
            with patch("asimov_conformance.verification.sigstore_verify", return_value=(True, "verified")):
                full = verify_package(
                    assessment_path=assessment_path,
                    evidence_manifest_path=manifest_path,
                    evidence_root=evidence,
                    statement_path=statement_path,
                    report_paths=[report_path],
                    bundle_path=bundle,
                    certificate_identity="test@example.com",
                    certificate_oidc_issuer="https://accounts.google.com",
                )
            self.assertEqual(full["overall"], "VERIFIED")


    def test_public_report_sidecar_detects_tampering_and_preserves_statement_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("e" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<h1>public report</h1>", encoding="utf-8")
            statement_path = root / "asimov-statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )

            record = build_public_verification_record(statement_path, report_path)
            record_path = root / "public-verification.json"
            record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            self.assertEqual(record["statement"]["text"], statement_path.read_text(encoding="utf-8"))

            verified = verify_public_report(report_path, record_path)
            self.assertEqual(verified["overall"], "LOCAL_MATCH_ONLY")
            self.assertEqual(verified["report_integrity"]["state"], "VERIFIED")
            self.assertEqual(verified["provenance"]["state"], "UNSIGNED")

            report_path.write_text("<h1>tampered public report</h1>", encoding="utf-8")
            tampered = verify_public_report(report_path, record_path)
            self.assertEqual(tampered["overall"], "FAILED")
            self.assertEqual(tampered["report_integrity"]["state"], "FAILED")

    def test_public_record_cli_and_verify_report_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("f" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("public report", encoding="utf-8")
            statement_path = root / "asimov-statement.json"
            statement_path.write_text(
                json.dumps(build_verification_statement(assessment_path, manifest_path, [report_path]), indent=2) + "\n",
                encoding="utf-8",
            )
            record_path = root / "public-verification.json"
            self.assertEqual(main([
                "public-record",
                "--statement", str(statement_path),
                "--report", str(report_path),
                "--output", str(record_path),
            ]), 0)
            receipt_path = root / "public-receipt.json"
            self.assertEqual(main([
                "verify-report", str(report_path), str(record_path),
                "--json-output", str(receipt_path),
            ]), 0)
            receipt = json.loads(receipt_path.read_text())
            self.assertEqual(receipt["overall"], "LOCAL_MATCH_ONLY")

    def test_cli_statement_and_local_verification_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"; evidence.mkdir()
            (evidence / "event.json").write_text("{}", encoding="utf-8")
            manifest_path = root / "evidence-manifest.json"
            manifest_path.write_text(json.dumps(build_evidence_manifest(evidence), indent=2) + "\n", encoding="utf-8")
            assessment_path = root / "assessment.json"
            assessment_path.write_text(json.dumps(_assessment("d" * 64), indent=2) + "\n", encoding="utf-8")
            report_path = root / "report.html"; report_path.write_text("<h1>shareable report</h1>", encoding="utf-8")
            statement_path = root / "statement.json"
            self.assertEqual(main([
                "verification-statement", str(assessment_path),
                "--evidence-manifest", str(manifest_path),
                "--report", str(report_path),
                "--output", str(statement_path),
            ]), 0)
            receipt_json = root / "receipt.json"
            receipt_html = root / "receipt.html"
            self.assertEqual(main([
                "verify-package", str(assessment_path),
                "--evidence-manifest", str(manifest_path),
                "--evidence-root", str(evidence),
                "--statement", str(statement_path),
                "--report", str(report_path),
                "--json-output", str(receipt_json),
                "--html-output", str(receipt_html),
            ]), 0)
            receipt = json.loads(receipt_json.read_text())
            self.assertEqual(receipt["overall"], "LOCAL_BINDING_VERIFIED")
            self.assertIn("Verification receipt", receipt_html.read_text())

            report_path.write_text("<h1>tampered report</h1>", encoding="utf-8")
            self.assertEqual(main([
                "verify-package", str(assessment_path),
                "--evidence-manifest", str(manifest_path),
                "--evidence-root", str(evidence),
                "--statement", str(statement_path),
                "--report", str(report_path),
            ]), 1)


if __name__ == "__main__":
    unittest.main()
